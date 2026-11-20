# The demo plant

[netbox-ot.packetflow.be](https://netbox-ot.packetflow.be) is a public NetBox with netbox-ot and its companion
plugins, filled with a fictional plant. Log in as **demo** / **demo**. You can change anything: the whole
database is reset every two hours, so do not enter real data.

This page describes what is in it, level by level, and what each part is there to show. Everything comes from
generators, so you can build the same plant in your own NetBox:

| Layer | Generator | Public demo |
|---|---|---|
| The plant: zones, conduits, devices, cabling, flows, services, fieldbus, risk assessments, requirement statuses | `manage.py ot_demo` ([ot_demo.py](../netbox_ot/management/commands/ot_demo.py)) | yes |
| Modules, lifecycle dates, support contracts, licences, purchases, assets, spare parts, more requirement statuses, access paths | Packetflow's `netbox-demo-populate.py` (through the REST API, needs netbox-lifecycle, netbox-inventory and netbox-access-paths) | yes |
| Saved topology views | Packetflow's NetBox role (saved filters for netbox-topology-views) | yes |
| A site from a real capture: the DFRWS 2023 elevator | `manage.py ot_demo --capture` ([demo_capture.py](../netbox_ot/demo_capture.py)) | from 0.8.0 |
| A large plant: 35 zones, about 200 flows, no devices | `manage.py ot_demo --large` ([demo_large.py](../netbox_ot/demo_large.py)) | no |

All names, addresses and serial numbers are invented. The addresses for the MSP and NOC are documentation
ranges (192.0.2.0/24, 198.51.100.0/24).

## Contents

1. [The plant at a glance](#the-plant-at-a-glance)
2. [Level 1: zones and conduits](#level-1-zones-and-conduits)
3. [Level 2: the network](#level-2-the-network)
4. [Level 3: the machine, Line 1](#level-3-the-machine-line-1)
5. [Level 4: the controllers and the field](#level-4-the-controllers-and-the-field)
6. [Who talks to what: the flows](#who-talks-to-what-the-flows)
7. [Remote access](#remote-access)
8. [Monitoring](#monitoring)
9. [Lifecycle, inventory and spare parts](#lifecycle-inventory-and-spare-parts)
10. [Risk assessments and requirements](#risk-assessments-and-requirements)
11. [What is wrong on purpose](#what-is-wrong-on-purpose)
12. [The capture site: DFRWS 2023 elevator](#the-capture-site-dfrws-2023-elevator)
13. [The large plant](#the-large-plant)
14. [Where to look](#where-to-look)

## The plant at a glance

Site **IEC 62443 demo plant**: one production line (*Line 1*) with two PLCs, a safety PLC and a protocol gateway,
a control room with an operator panel and an engineering station, an OT DMZ with a historian and a jump host,
the office, a monitoring proxy, and two outside parties: the MSP that maintains the SCADA servers and the NOC that
receives the alarms. One OT firewall sits between all of them.

| | Count |
|---|---|
| Zones | 8 (6 on site, 2 external) |
| Conduits | 6, all enforced by the firewall |
| Devices | 14 (plus 2 virtual machines) |
| Cables | 13 |
| Flows | 15 |
| Fieldbuses | 1 |
| Modules | 3 |
| Risk assessments | 4 |

## Level 1: zones and conduits

The zones (boxes) by Purdue level, and the conduits (hexagons) between them, with their target security level
(SL-T). The firewall demo-fw-1 enforces every conduit.

```mermaid
flowchart TB
  MSP["IEC 62443 demo MSP<br/>external<br/>192.0.2.0/24"]
  OFF["Office<br/>level 4, enterprise<br/>VLAN 104, 10.61.4.0/24, wireless"]
  NOC["IEC 62443 demo NOC<br/>external<br/>198.51.100.0/24"]
  C_REM{{"Remote maintenance<br/>SL-T 3"}}
  C_OFF{{"Office - DMZ<br/>SL-T 1"}}
  C_NOC{{"Remote monitoring<br/>SL-T 2, outbound only"}}
  DMZ["OT DMZ<br/>level 3.5<br/>VLAN 135, 10.61.35.0/24"]
  MON["OT monitoring<br/>level 3.5<br/>VLAN 136, 10.61.36.0/24"]
  C_DMZ{{"DMZ - OT<br/>SL-T 2"}}
  C_MON{{"Monitoring - Line 1<br/>SL-T 2"}}
  CR["Control room<br/>level 2<br/>VLAN 102, 10.61.2.0/24"]
  C_CR{{"Control room - Line 1<br/>SL-T 2"}}
  subgraph CELLZ["Line 1 cell, level 1"]
    CELL["Line 1 cell<br/>VLAN 101, 10.61.1.0/24<br/>PLCs, gateway, cell switch"]
    SIS["Line 1 safety<br/>safety zone, SL-T 3"]
  end
  MSP --- C_REM --- DMZ
  OFF --- C_OFF --- DMZ
  MON --- C_NOC --> NOC
  DMZ --- C_DMZ
  C_DMZ --- CR
  C_DMZ --- CELL
  CR --- C_CR --- CELL
  MON --- C_MON --- CELL
```

| Zone | Level | Type | Members | Security levels (FR1 to FR7) |
|---|---|---|---|---|
| Line 1 cell | 1 | OT | demo-plc-1, demo-plc-2, demo-gw-1, cell switch | target 2,2,2,1,2,1,2; achieved 2,1,2,1,2,1,2 |
| Line 1 safety | 1 | safety, inside the cell | demo-sis-1 | target 3 on every FR |
| Control room | 2 | OT | demo-hmi-1, demo-es-1, control room switch | target and achieved 2 |
| OT DMZ | 3.5 | DMZ | demo-fw-1, VMs demo-historian and demo-jump-1, DMZ switch | target 2 |
| OT monitoring | 3.5 | DMZ | demo-mon-1 | target and achieved 2 |
| Office | 4 | enterprise | demo-office-laptop, office switch | none set |
| IEC 62443 demo MSP | | external | (a prefix only) | |
| IEC 62443 demo NOC | | external | (a prefix only) | |

The conduits: *Control room - Line 1*, *DMZ - OT* (DMZ, control room and cell), *Office - DMZ*, *Remote
maintenance* (MSP and DMZ), *Monitoring - Line 1* and *Remote monitoring* (monitoring and NOC, outbound only).
demo-fw-1 enforces all six.

## Level 2: the network

What is cabled to what. Every zone has its own switch on its own firewall port, so every conduit passes a
firewall rule. Each switch has eight access ports in its zone's VLAN; port 8 is the uplink.

```mermaid
flowchart TB
  FW["demo-fw-1<br/>OT firewall, FW 7.4.2<br/>10.61.35.1"]
  subgraph CELLSW["Line 1 cell, VLAN 101"]
    SW1["demo01be1-sw001<br/>Line 1 cell switch"]
    PLC1["demo-plc-1<br/>10.61.1.10"]
    PLC2["demo-plc-2<br/>10.61.1.11"]
    GW["demo-gw-1<br/>10.61.1.20"]
    CAM["demo-unzoned-camera<br/>10.61.1.99, in no zone"]
  end
  subgraph SAFE["Line 1 safety"]
    SISP["demo-sis-1<br/>10.61.1.50"]
  end
  subgraph CRSW["Control room, VLAN 102"]
    SW2["demo01be1-sw002<br/>Control room switch"]
    HMI["demo-hmi-1<br/>10.61.2.10"]
    ES["demo-es-1<br/>10.61.2.20"]
  end
  subgraph DMZSW["OT DMZ, VLAN 135"]
    SW3["demo01be1-sw003<br/>OT DMZ switch"]
    HIS["demo-historian (VM)<br/>10.61.35.10"]
    JMP["demo-jump-1 (VM)<br/>10.61.35.20"]
  end
  subgraph OFFSW["Office, VLAN 104"]
    SW4["demo01be1-sw004<br/>Office switch"]
    LAP["demo-office-laptop<br/>10.61.4.30"]
  end
  subgraph MONSEG["Monitoring, VLAN 136"]
    MONP["demo-mon-1<br/>monitoring proxy<br/>10.61.36.10"]
  end
  FW ---|"eth1 - port8"| SW1
  FW ---|"eth2 - port8"| SW2
  FW ---|"eth0 - port8"| SW3
  FW ---|"eth3 - port8"| SW4
  FW ---|"eth4 - eth0"| MONP
  SW1 ---|"port1"| PLC1
  SW1 ---|"port2"| PLC2
  SW1 ---|"port3"| GW
  SW1 ---|"port4"| CAM
  PLC1 ---|"eth1 - eth0, point to point"| SISP
  SW2 ---|"port1"| HMI
  SW2 ---|"port2"| ES
  SW3 -.-|"VMs on this segment"| HIS
  SW3 -.- JMP
  SW4 ---|"port1"| LAP
```

- The historian reads the gateway through a **1:1 NAT** on the firewall: 10.61.35.120 in the DMZ is
  demo-gw-1's 10.61.1.20 (NetBox's own NAT inside/outside on the IP address).
- The safety PLC is not on the cell switch: it has a dedicated link to demo-plc-1's second port.
- The IP camera is cabled to the cell switch but belongs to no zone: a finding (*asset without zone*).
- Cables are coloured per zone, so the topology view shows the zones in the cabling.

## Level 3: the machine, Line 1

*Line 1* is a NetBox location: what sits in the machine's cabinets. It is what the machine drawing draws (the
*Machine drawing* tab of the location), for the technical file of the Machinery Regulation.

```mermaid
flowchart LR
  subgraph LINE1["Location Line 1"]
    direction TB
    SW1["Line 1 cell switch<br/>demo01be1-sw001"]
    PLC1["demo-plc-1<br/>PLC, FW V2.8.3"]
    PLC2["demo-plc-2<br/>PLC, FW V2.6.0"]
    SISP["demo-sis-1<br/>safety PLC, FW V2.8.3"]
    GW["demo-gw-1<br/>protocol gateway, FW 3.2.1"]
    CAM["demo-unzoned-camera<br/>IP camera"]
    BUS[("Line 1 RS-485<br/>Modbus RTU")]
    SW1 --- PLC1
    SW1 --- PLC2
    SW1 --- GW
    SW1 --- CAM
    PLC1 --- SISP
    GW --- BUS
  end
  SW1 ---|"port8 to firewall eth1"| FW["demo-fw-1"]
  FW --- OUT["To and from the machine:<br/>control room (S7comm),<br/>DMZ (OPC UA reverse connect, syslog),<br/>office (Modbus TCP: not allowed; MQTT),<br/>monitoring (SNMP, HTTPS),<br/>MSP (TeamViewer, expired)"]
```

What leaves the machine is every flow from or to *Line 1 cell* (see [the flows](#who-talks-to-what-the-flows));
the drawing lists them under the machine, with the devices, cables, addresses and firmware.

## Level 4: the controllers and the field

Inside the controllers, and below them.

```mermaid
flowchart TB
  subgraph P1["demo-plc-1 (Demo PLC)"]
    direction LR
    P1S1["Slot 1: Demo CPU module<br/>FW V2.8.3, end of support passed"]
    P1S2["Slot 2: Demo communication module<br/>PROFINET / Modbus TCP, FW V1.4.0"]
    P1E0["eth0: cell switch port1"]
    P1E1["eth1: safety PLC"]
  end
  subgraph P2["demo-plc-2 (Demo PLC)"]
    direction LR
    P2S1["Slot 1: Demo CPU module<br/>end of support passed"]
    P2E0["eth0: cell switch port2"]
  end
  subgraph S1["demo-sis-1 (safety PLC)"]
    S1E0["eth0: point to point to demo-plc-1"]
  end
  subgraph G1["demo-gw-1 (gateway)"]
    G1E0["eth0: cell switch port3"]
    G1RS["RS-485 port: Modbus RTU client"]
  end
  P1E1 --- S1E0
  G1RS --- BUS[("Fieldbus Line 1 RS-485<br/>medium RS-485, Modbus RTU, zone Line 1 cell")]
  BUS -.- FIELD["Field devices on the bus:<br/>not modelled in the demo"]
  HMIC["demo-hmi-1: S7comm client"] -->|"S7comm tcp/102"| P1E0
  HMIC -->|"S7comm tcp/102"| P2E0
```

| Controller | Type | Firmware | Industrial services | Modules |
|---|---|---|---|---|
| demo-plc-1 | Demo PLC (SL capability 2,2,2,1,2,1,1) | V2.8.3 | S7comm server, tcp/102 | CPU (slot 1), communication module (slot 2) |
| demo-plc-2 | Demo PLC | V2.6.0, one release behind | S7comm server, tcp/102 | CPU (slot 1) |
| demo-sis-1 | Demo PLC as safety PLC | V2.8.3 | | |
| demo-gw-1 | Demo industrial PC as protocol gateway | 3.2.1 | Modbus RTU client on the RS-485 fieldbus | |
| demo-hmi-1 | Demo HMI panel (SL capability 1) | V15.1 | S7comm client | |

**Sensors and actuators.** The demo stops at the fieldbus: the RS-485 Modbus RTU bus behind the gateway is in
NetBox, with the gateway as its client, but the instruments, drives and I/O on it are not modelled as devices.
The cell's description says what it holds (*PLCs and drives of production line 1*), and the gateway's monitoring
agent sends the values it reads from the bus to the monitoring proxy. The large plant has zones for field
instruments (*Tank farm instruments*, *Packaging sensors*), without devices.

## Who talks to what: the flows

Fifteen flows, as a two-week passive capture on a SPAN port of the OT core switch would show them. Each has a
decision: allowed (*yes*), not allowed (*no*) or not decided yet (*unknown*).

The seven flows into the line, the ones that reach the controllers. Green is allowed, red is not allowed, orange
is not decided yet, grey is allowed but expired.

```mermaid
flowchart LR
  CR["Control room"]
  OFF["Office"]
  DMZ["OT DMZ"]
  MON["OT monitoring"]
  MSP["MSP / supplier"]
  CELL["Line 1 cell<br/>PLCs, gateway"]
  F1["S7comm tcp/102<br/>read, write"]:::yes
  F2["S7comm tcp/102<br/>program, control<br/>engineering station"]:::yes
  F3["Modbus TCP tcp/502<br/>read, write"]:::no
  F4["MQTT tcp/8883 via the DMZ broker<br/>write: recipe changes"]:::open
  F5["OPC UA tcp/4843, reverse connect<br/>read, write: the MES"]:::open
  F6["SNMP udp/161<br/>read: polling"]:::yes
  F7["TeamViewer tcp/5938<br/>remote access, no conduit"]:::expired
  CR --> F1 --> CELL
  CR --> F2 --> CELL
  OFF --> F3 --> CELL
  OFF --> F4 --> CELL
  DMZ --> F5 --> CELL
  MON --> F6 --> CELL
  MSP --> F7 --> CELL
  classDef yes fill:#e8f5e9,stroke:#2e7d32,color:#1b5e20
  classDef no fill:#ffebee,stroke:#c62828,color:#b71c1c
  classDef open fill:#fff3e0,stroke:#ef6c00,color:#e65100
  classDef expired fill:#eeeeee,stroke:#616161,color:#424242,stroke-dasharray: 4 3
```

All fifteen:

| From | To | Protocol, port | Access | Decision | Note |
|---|---|---|---|---|---|
| Control room | Line 1 cell | S7comm tcp/102 | read, write | yes | review in 180 days |
| Control room | Line 1 cell | S7comm tcp/102 | program, control | yes | *Engineering station program* |
| OT DMZ | Control room | OPC UA tcp/4840 | read | yes | |
| Office | Line 1 cell | Modbus TCP tcp/502 | read, write | **no** | the office laptop writing to the line: should not exist |
| Office | Control room | SMB tcp/445 | | undecided | found in the capture, nobody knows why |
| MSP | OT DMZ | RDP tcp/3389 | | yes | remote access; IPsec tunnel, jump host, firewall; expires in 30 days |
| MSP | Line 1 cell | TeamViewer tcp/5938 | | yes, **expired** | the supplier's TeamViewer, expired 10 days ago, no conduit |
| Line 1 cell | OT DMZ | syslog udp/514 | | yes | |
| OT DMZ | Line 1 cell | OPC UA tcp/4843 | read, write | undecided | MES over OPC UA reverse connect: the gateway opens the connection |
| Office | Line 1 cell | MQTT tcp/8883 | write | undecided | recipe changes through the broker in the DMZ, topic `spBv1.0/line1/DCMD/demo-gw-1` |
| OT monitoring | Line 1 cell | SNMP udp/161 | read | yes | SNMPv3, read-only view |
| Line 1 cell | OT monitoring | SNMP udp/162 | | yes | traps from the cell switch |
| Line 1 cell | OT monitoring | HTTPS tcp/443 | | yes | the gateway's monitoring agent |
| OT monitoring | Control room | SNMP udp/161 | read | undecided | SNMPv2c with the default community |
| OT monitoring | NOC | HTTPS tcp/443 | | yes | one outbound connection, through demo-fw-1 |

The *Access map* tab of the site draws these by level, with the flows that change a controller (write, control,
program, or requests nobody could classify) as heavy arrows.

## Remote access

Three ways into the plant, recorded both as flows (above) and as access paths (netbox-access-paths), so the
machine drawing and the access map show who can reach what.

```mermaid
flowchart LR
  ENG["Demo MSP engineer<br/>(Demo MSP team)"] --> T1["IPsec tunnel<br/>IEC 62443 demo MSP IPsec"]
  T1 --> J["demo-jump-1<br/>jump host, OT DMZ"]
  J --> F1["demo-fw-1"]
  F1 --> ESX["demo-es-1<br/>engineering station"]
  TECH["Demo supplier technician"] --> TV["TeamViewer relay<br/>(internet)"]
  TV --> PLCX["demo-plc-1"]
  LEAD["Demo OT security lead"] --> CON["On site: console cable"]
  CON --> FWC["demo-fw-1 console"]
```

| Access path | Holder | Method | Authentication | Status |
|---|---|---|---|---|
| MSP maintenance: engineering station | Demo MSP engineer, Demo MSP team | RDP through the jump host | MFA | active, expires in 30 days |
| Supplier remote support: PLC 1 | Demo supplier technician | vendor remote tool | shared account | still active, expired 10 days ago, review overdue |
| Break-glass: firewall console | Demo OT security lead | console | password in a sealed envelope | break glass |

## Monitoring

The plant is watched from outside without anything outside reaching in: the monitoring proxy has its own firewall
port, polls the line, receives its traps and agent data, and forwards everything to the NOC over one outbound
connection.

```mermaid
flowchart LR
  subgraph PLANT["Plant"]
    CELL["Line 1 cell<br/>cell switch, demo-gw-1"]
    CR["Control room"]
    MONP["demo-mon-1<br/>monitoring proxy"]
    FW["demo-fw-1"]
  end
  NOC["NOC<br/>(external)"]
  MONP -->|"SNMP poll, decided"| CELL
  CELL -->|"traps, agent values"| MONP
  MONP -.->|"SNMPv2c poll, not decided"| CR
  MONP -->|"HTTPS"| FW
  FW -->|"one outbound connection"| NOC
```

## Lifecycle, inventory and spare parts

Added through the API by the populate layer (netbox-lifecycle and netbox-inventory). Dates are relative to the
day the demo was built, so there is always one passed end of support, one within a year and a contract about to
run out.

| Item | End of sale | End of support | Note |
|---|---|---|---|
| Demo PLC (device type) | passed | in about 200 days | phase-out announced |
| Demo HMI panel | passed | **passed** (about 120 days ago) | no security fixes any more |
| Demo CPU module (module type) | passed | **passed** (about 30 days ago) | the PLC racks are supported longer than their CPUs |
| Demo communication module | in about 300 days | in about 4 years | current |
| Demo OT firewall | in about 2 years | in about 7 years | current |
| Demo industrial PC | passed | in about 3 years | |

- **Support contracts:** the firewall's runs out in 90 days (renewal due in 60); the PLCs' expired 40 days ago and
  covers demo-plc-1, demo-plc-2 and demo-sis-1.
- **Licences:** the SCADA runtime on demo-historian; the engineering suite with two seats on demo-es-1.
- **Purchases:** the line build (closed), the firewall and spares (closed), and an open order for replacement CPU
  modules, placed after the end-of-support notice.
- **Assets:** one per device and module, with serial numbers and warranty dates; in the *Spare parts cabinet*: two
  spare PLCs (firmware V2.6.0) and three 24 V DC power supplies; one retired operator panel.

## Risk assessments and requirements

| Assessed | Kind | Status | Unmitigated | Residual | Tolerable |
|---|---|---|---|---|---|
| Line 1 cell | detailed | approved | high | medium | medium |
| Remote maintenance (conduit) | detailed | approved, **review overdue** | critical | **high** | medium |
| Control room | initial | | high | | medium |
| Office | initial | | medium | | |

IEC 62443-3-3 requirement statuses (the plugin ships the identifiers; the texts and levels come from your own copy
of the standard):

| Zone | Met | Compensated | Not met | Not applicable |
|---|---|---|---|---|
| Line 1 cell | SR 5.1 | SR 5.2 | SR 1.13 (the supplier's TeamViewer reaches the PLCs) | |
| Control room | SR 1.1, SR 2.1, SR 7.3 | SR 1.2 | SR 3.2 (no malware protection on the engineering station) | |
| OT DMZ | SR 5.2, SR 6.1 | | | |
| Line 1 safety | SR 5.1 | | | SR 1.13 |

## What is wrong on purpose

The demo is built so that *OT > Consistency checks* and the site's *OT overview* have something to find:

- the office laptop writes Modbus to the line, a flow decided *not allowed*;
- the supplier's TeamViewer to PLC 1 expired 10 days ago, has no conduit, and its access path is still active;
- SMB from the office to the control room, MQTT recipe writes from the office, OPC UA reverse connect from the MES
  and SNMPv2c polling of the control room are not decided;
- the IP camera on the cell switch is in no zone;
- the remote-maintenance conduit's residual risk is above tolerable and its review is overdue;
- the cell's achieved security level is below target on FR 2 (use control);
- the HMI panel and the PLCs' CPU modules are past end of support, the PLC support contract has expired, and
  demo-plc-2 runs older firmware than demo-plc-1;
- SR 1.13 and SR 3.2 are not met.

## The capture site: DFRWS 2023 elevator

From netbox-ot 0.8.0, `ot_demo --capture` adds a second site, **Elevator (DFRWS 2023 capture)**, imported from a
real network trace rather than invented: the [DFRWS 2023 Forensic Challenge "The Troubled
Elevator"](https://github.com/dfrws/dfrws2023-challenge) (DFRWS; Security and Forensics Engineering Lab,
Virginia Commonwealth University; Apache-2.0). The trace went through Malcolm's Zeek and netbox-ot's importer
(see [Malcolm](malcolm.md)); what ships is aggregated requests only, described in
[NOTICE.md](../netbox_ot/data/demo/dfrws-2023-elevator/NOTICE.md). Device names and roles are ours.

```mermaid
flowchart LR
  subgraph SUP["Supervisory, level 2"]
    W121["elevator-station-121<br/>192.168.10.121"]
    W130["elevator-station-130<br/>192.168.10.130"]
    W164["elevator-station-164<br/>192.168.10.164"]
  end
  subgraph CTL["Control, level 1"]
    PLC["elevator-plc-45<br/>192.168.10.45<br/>Modbus tcp/502"]
  end
  W130 -->|"PROGRAM_UNITY x 35,387"| PLC
  W121 -->|"PROGRAM_UNITY x 24,889"| PLC
  W164 -->|"PROGRAM_UNITY x 1,488"| PLC
```

In two hours (29 June 2023, 18:27 to 20:27 UTC) three stations send 61,764 Schneider UMAS requests (Modbus
function 90, *PROGRAM_UNITY*) to the PLC: an engineering channel that can read and change the controller's
program. No table classifies UMAS functions yet, so the flow is **unclassified**, the access map draws it as a
flow that may change the controller, and `ot_check` reports it as an undecided flow into a control zone until
someone decides it. The other hosts in the subnet (DHCP, name resolution) stay in *Elevator cell*.

## The large plant

`ot_demo --large` (not on the public demo) creates a plant of 35 zones and about 200 flows without devices, to
see the access map and the lists at the size of a real site: three production lines, each with a control room,
a cell, robots and a safety zone; utilities (boiler house, compressed air, water treatment); field instrument
zones (tank farm instruments, packaging sensors); MES, site historian, engineering and OT management; four DMZ
zones (historian mirror, remote access, patch and antivirus, MQTT broker); office, ERP, IT management and guest
Wi-Fi; and outside parties (internet, corporate WAN, MSP, robot supplier, boiler supplier).

## Where to look

| To see | Open |
|---|---|
| Where the site stands | the site, tab *OT overview* |
| Who can change the controllers | the site, tab *Access map* |
| The zone register for an audit | the site, tab *Zone register* |
| The machine drawing | location *Line 1*, tab *Machine drawing* |
| Everything the checks find | *OT > Consistency checks* |
| The cabling | *Topology* with the saved views *Demo plant: whole control network*, *PLCs, HMI and how they connect*, *PLCs and their neighbours*, *way in (firewall, gateways, laptops)* |
| End of support and contracts | *Lifecycle > Hardware* and *Support contracts* |
| Assets and spare parts | *Inventory > Assets* |
| Who can get in from outside | *Access paths* |
