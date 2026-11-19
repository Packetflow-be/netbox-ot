# Machine drawing

One drawing and its tables per machine, for the network part of the technical file under the Machinery
Regulation (EU) 2023/1230, which applies from 20 January 2027:

- Annex IV, Part A (c) and (d): drawings and schemes of the machine, its components and circuits, with the
  descriptions needed to understand them;
- Annex III, 1.7.4.2 (e) and (i): drawings and diagrams for use, maintenance and repair, and for installation
  and connection;
- Annex III, 1.1.9: connecting another device, remote ones included, must not lead to a hazardous situation.

The drawing shows the devices of the machine in their zones, the cables between them with port names, the
addresses with their 1:1 NAT, the firmware, and every connection that leaves the machine or comes into it,
with remote access marked. It is built from what NetBox already holds: there is nothing extra to enter.

## Where

- *OT > Reports > Machine drawing*: choose a site, a location, one or more tags, or a mix. All filters apply
  together, so *site Plant + tag M3200* is machine M3200 at that plant. A tag is the usual way to draw one
  machine on a line, or the reference machine of a type.
- The *Machine drawing* tab on a location: the devices in it and in the locations below it. The tab shows
  when the location has devices. A tag filter narrows it down.

*Machine version* is free text printed in the header and in the drawing's title block, for example
"type 3200, revision C". It is not stored: it travels in the link like the other filters.

## What is in scope

| | |
|---|---|
| Devices | The devices you may view that match the filters |
| Zones | Every zone one of those devices is a member of. A device is drawn in one zone frame: a sub-zone before its parent, then the lowest Purdue level. The table lists the other zones |
| Cables | Cables on an interface, front or rear port of a device in scope. A cable to a device out of scope, or to a circuit, *leaves the machine* |
| Flows | Flows with exactly one end in a zone of the scope: the connections to and from the outside. Flows between two zones of the machine are not drawn (they are on the access map) |
| NAT | NetBox's own *NAT (inside)* on an IP address: the outside address points to the inside one. No extra model |
| Firmware | The `ot_firmware_version` custom field on devices and modules |

## The drawing

- **Frames**: one per zone, from the highest Purdue level at the top to the lowest at the bottom, with the
  zone's level, type and SL-T in the title. Devices without a zone are in a dashed frame at the bottom.
- **Devices**: name, manufacturer and model, primary address (`inside ⇄ outside` when NATed), firmware; the
  stripe on the left has the colour of the device role. In each frame the most-cabled device (the switch)
  comes first.
- **Cables**: drawn at right angles through the gaps between the rows and columns, never behind a device, in
  the cable's colour when it has one. Port names run along the cable at both ends (`GigabitEthernet1/0/1`
  becomes `Gi1/0/1`); the full names are in the cable table.
- **Left**: what a cable leaves the machine for (dashed boxes, dashed cables).
- **Right**: the zones that flows go to or come from. One arrow per frame, outside zone and direction, with
  each flow's protocol and ports on it. As on the access map: the colour is the verdict (green allowed, amber
  no decision yet, red not allowed or expired), dashed is remote access, dotted is a connection opened from
  the inside (reverse connect, a broker), and a heavy arrow writes, controls or programs its destination.

The drawing is SVG rendered on the server, so it prints and works without JavaScript; hover a cable or an
arrow for its full description.

## Tables

- **Devices**: role, manufacturer, model, serial, zone, firmware, every address with its NAT, and the
  modules (bay, model, serial, firmware), for a PLC's CPU and I/O cards.
- **Cables**: both ends with their ports, type, status, and whether the cable leaves the machine.
- **Connections to and from the outside**: the columns of the [firewall rule export](firewall-rules.md), for
  the flows that cross the scope, deny rules included. Flows without a verdict are counted below the table:
  decide them first.
- **Access paths into the machine**, when [netbox-access-paths](https://github.com/Packetflow-be/netbox-access-paths)
  is installed: the paths whose target is a device in scope (or its services or addresses), or that run
  through one.

## Export

- *Drawing (SVG)*: the drawing as a file, with its title block (scope, version, date, netbox-ot version).
- *Devices*, *Cables*, *Connections* and *Access paths* as CSV.
- *Print*: the page prints on A3 landscape without the form and the buttons, with the scope, version and date
  at the top. Print to PDF for the technical file.
- JSON: `GET /api/plugins/ot/machine-drawing/?site_id=<id>&location_id=<id>&tag=<slug>&version=<text>` (any
  mix, at least one of site, location or tag; `tag` may repeat). Needs `dcim.view_device`; everything else
  is limited to what you may view.

## Permissions

The page needs `dcim.view_device`. Zones, flows, cables, addresses, modules and access paths appear as far as
you may view them; a device at the other end of a cable that you may not view is shown as *Not visible*.

## Not in scope

Remote-access sessions, work permits and session logs stay in the PAM or bastion, as in netbox-access-paths.
The machine itself must log interventions where the regulation asks for it (Annex III, 1.1.9): the drawing
documents the paths, not their use.
