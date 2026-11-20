# Using netbox-ot with Malcolm

[Malcolm](https://github.com/cisagov/Malcolm) (CISA and Idaho National Laboratory, Apache-2.0) captures and
analyses network traffic: Zeek with CISA's ICSNPP parsers, Suricata, Arkime, OpenSearch, and its own NetBox.
A Hedgehog Linux sensor on a SPAN port or TAP at a site forwards to a central Malcolm.

Malcolm shows what talks to what, and can create devices in NetBox from the traffic it sees. netbox-ot adds what
an OT network needs on top: zones and conduits, which flows are allowed, who can change a controller (the access
map), supplier access paths and the checks. Its importer reads the Zeek logs Malcolm writes, ICSNPP included.

## Status

| Malcolm | Its NetBox | netbox-ot in Malcolm's NetBox |
|---|---|---|
| v26.10.0 (29 October 2026) | 4.6.10 | Does not load: netbox-ot needs NetBox 4.7 |

netbox-ot builds on NetBox 4.7's application services (port mappings), so it does not run on 4.6. Malcolm has
moved to a new NetBox minor release three to four months after it came out (4.5 and 4.6 in 2026); NetBox 4.7
came out on 2 September 2026. CI checks every week which NetBox the latest Malcolm release ships, and builds
Malcolm's NetBox image on NetBox 4.7 with netbox-ot installed the Malcolm way (see [CI](#ci)).

What that build shows (Malcolm v26.10.0, November 2026): Malcolm's NetBox Dockerfile works on NetBox 4.7 with
three version changes: the base image, netbox-initializers v4.7.0, and netbox-healthcheck-plugin 0.4.0 (the
pinned 0.3.0 stops NetBox from starting on Django 6.1). With those, Malcolm's installer installs netbox-ot and
the full test suite passes inside Malcolm's NetBox, beside its own plugins and under its `BASE_PATH`.

Until then, the importer works on Malcolm's Zeek logs with netbox-ot in a NetBox 4.7 of its own (see below).

## Installing it into Malcolm

Once Malcolm ships NetBox 4.7, install netbox-ot like any custom plugin: Malcolm's NetBox container installs
every directory under `./netbox/custom-plugins/` when it starts, adds the plugin to `PLUGINS` and migrates.

```bash
cd ~/Malcolm
curl -sL https://github.com/Packetflow-be/netbox-ot/archive/refs/tags/vX.Y.Z.tar.gz \
  | tar xz -C netbox/custom-plugins
./scripts/restart -s netbox
```

Use a released tag, not `main`. netbox-ot has no Python dependencies beyond NetBox, so nothing goes into
`./netbox/custom-plugins/requirements/` for an offline Malcolm.

Malcolm logs NetBox in through its own authentication. netbox-ot's menu and permissions are NetBox's: give the
Malcolm users or groups that work on zones the netbox-ot permissions (see [Installation](installation.md)).

## Importing Malcolm's Zeek logs

Malcolm keeps the Zeek logs of uploaded PCAPs and live capture under `./zeek-logs/` (`processed/` once
indexed) and prunes them after `LOG_CLEANUP_MINUTES` in `config/filebeat.env` (360 in the example
configuration). Copy them out first, or raise that value for the capture you want to import.

`ot_import` reads one directory of logs. Several captures go into the same directory as `<stream>.<n>.log`,
one `<n>` per capture:

```bash
out=plant-a-logs; mkdir -p "$out"; n=0
find ./zeek-logs/processed -type f \( -name '*.log' -o -name '*.log.gz' \) -printf '%h\n' | sort -u |
while read -r dir; do
  n=$((n + 1))
  for f in "$dir"/*.log "$dir"/*.log.gz; do
    [ -e "$f" ] || continue
    name=$(basename "$f"); stream=${name%%.*}; gz=${name##*.log}
    cp "$f" "$out/$stream.$n.log$gz"
  done
done
```

Then import as in [Zeek logs](zeek.md): into Malcolm's NetBox once netbox-ot runs there,

```bash
docker compose cp plant-a-logs netbox:/tmp/plant-a-logs
docker compose exec netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py \
  ot_import /tmp/plant-a-logs --site plant-a --suggest-zone-map /tmp/zones.csv
```

or into any NetBox 4.7 with netbox-ot until then. Malcolm's NetBox has a default site (`NETBOX_DEFAULT_SITE`,
`Malcolm`); give each plant its own site, and its own VRF if plants share address ranges.

Malcolm's device autopopulation (`NETBOX_AUTO_POPULATE`) and netbox-ot's `--unknown-import` both create devices
for addresses they see. They have not been tested together yet: use one of them per site.

## What Malcolm's Zeek sees

Malcolm's Zeek image carries more parsers than a plain Zeek with ICSNPP, among them an IEC 60870-5-104 parser
(`spicy-iec104`) and a PROFINET plugin. Layer-2 protocols (GOOSE, PROFINET RT/DCP) stay invisible to Zeek. The
bench below records, per Malcolm release, what the importer reads from each protocol and which functions it
cannot classify yet.

## CI

The [Malcolm workflow](../.github/workflows/malcolm.yml) runs on every change and weekly:

- **Malcolm NetBox (as released):** Malcolm's NetBox image of the latest release, netbox-ot copied into its
  custom-plugins directory and installed by Malcolm's own installer, then the demo plant, `ot_check` and the
  full test suite. While Malcolm ships a NetBox older than netbox-ot supports, the job only says so.
- **Malcolm NetBox, built on NetBox 4.7:** the same, with Malcolm's NetBox Dockerfile of that release built on
  the newest NetBox 4.7. Not a gate: it can fail on Malcolm's side.
- **Bench:** public ICS captures run through Malcolm's Zeek image the way Malcolm processes an uploaded PCAP,
  then imported. See [.github/bench/README.md](../.github/bench/README.md) for the captures, their licences
  and how to re-record the expected results.
