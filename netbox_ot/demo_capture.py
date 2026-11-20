"""
The capture demo of `manage.py ot_demo --capture`: a site imported from a real network trace instead of a made-up
plant. The trace is the one of the DFRWS 2023 Forensic Challenge "The Troubled Elevator" (DFRWS; Security and
Forensics Engineering Lab, Virginia Commonwealth University; Apache-2.0). data/demo/dfrws-2023-elevator/ holds what
the importer read from it through Malcolm's Zeek, as observation files (aggregated requests per address pair,
protocol and function; no packets, no payloads), written by the Malcolm bench (.github/bench/, its NOTICE.md says how).

The import only matches existing devices, so the addresses with a level in the bench's zone map get a device first
(the controller at level 1, the stations at level 2); then the observation files go through the importer as
`ot_import --split-all` would take them. Everything belongs to the capture site and the roles, type and manufacturer
named "Capture demo ...", and `--capture --delete` removes exactly that.
"""
import json
from pathlib import Path

SITE_SLUG = 'dfrws-2023-elevator'
SITE_NAME = 'Elevator (DFRWS 2023 capture)'
PREFIX = 'Capture demo'
DATA = Path(__file__).parent / 'data' / 'demo' / SITE_SLUG
TITLE = 'the DFRWS 2023 Forensic Challenge "The Troubled Elevator"'
CREDIT = (
    'Imported from the network trace of the DFRWS 2023 Forensic Challenge "The Troubled Elevator" '
    '(DFRWS; Security and Forensics Engineering (SAFE) Lab, Virginia Commonwealth University), '
    'https://github.com/dfrws/dfrws2023-challenge, licensed under the Apache License 2.0. '
    "Processed with Malcolm's Zeek and CISA's ICSNPP parsers; only aggregated requests per address pair, protocol "
    'and function are kept. Device names and roles are ours, not part of the challenge. '
    'See netbox_ot/data/demo/dfrws-2023-elevator/NOTICE.md.'
)
# Device name and role per Purdue level of the zone map
ROLES = {1: ('plc', 'PLC', 'ff9800'), 2: ('station', 'Workstation', '2196f3')}


def load():
    return {name: json.loads((DATA / f'{name}.json').read_text()) for name in ('assets', 'flows', 'summary')}


def delete_capture():
    from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
    from ipam.models import IPAddress, Service

    from netbox_ot.models import Conduit, Flow, IndustrialService, Zone

    site = Site.objects.filter(slug=SITE_SLUG).first()
    if site:
        zones = Zone.objects.filter(site=site)
        Flow.objects.filter(source_zone__in=zones).delete()
        Flow.objects.filter(destination_zone__in=zones).delete()
        (Conduit.objects.filter(site=site) | Conduit.objects.filter(zones__in=zones)).distinct().delete()
        devices = Device.objects.filter(site=site)
        IndustrialService.objects.filter(device__in=devices).delete()
        Service.objects.filter(parent_object_type__model='device',
                               parent_object_id__in=list(devices.values_list('pk', flat=True))).delete()
        for device in devices:
            device.delete()
        zones.filter(parent__isnull=False).delete()
        zones.delete()
        site.delete()
    IPAddress.objects.filter(description=PREFIX).delete()
    DeviceType.objects.filter(model=f'{PREFIX} host').delete()
    Manufacturer.objects.filter(name=PREFIX).delete()
    DeviceRole.objects.filter(name__startswith=f'{PREFIX} ').delete()


def create_capture(log=print):
    from dcim.models import Device, DeviceRole, DeviceType, Interface, Manufacturer, Site
    from ipam.models import IPAddress

    from netbox_ot.importers.observations import apply_plan, build_plan

    data = load()
    site = Site.objects.create(name=SITE_NAME, slug=SITE_SLUG, description=f'Real capture: {TITLE}', comments=CREDIT)
    manufacturer = Manufacturer.objects.create(name=PREFIX, slug='capture-demo')
    device_type = DeviceType.objects.create(manufacturer=manufacturer, model=f'{PREFIX} host',
                                            slug='capture-demo-host')
    roles = {level: DeviceRole.objects.create(name=f'{PREFIX} {label}', slug=f'capture-demo-{slug}', color=color)
             for level, (slug, label, color) in ROLES.items()}
    for asset in data['assets']:
        # The zone map's levels arrive as text ("1"); the addresses without one get no device
        try:
            level = int(asset.get('purdue_level'))
        except (TypeError, ValueError):
            continue
        if level not in roles:
            continue
        device = Device.objects.create(name=f"elevator-{ROLES[level][0]}-{asset['ip'].rsplit('.', 1)[1]}",
                                       site=site, role=roles[level], device_type=device_type)
        interface = Interface.objects.create(device=device, name='eth0', type='1000base-t')
        ip = IPAddress.objects.create(address=f"{asset['ip']}/24", assigned_object=interface, description=PREFIX)
        device.primary_ip4 = ip
        device.save()
    plan = build_plan(data['assets'], data['flows'], data['summary'], outside_zone='Outside', split_zones=True)
    stats = apply_plan(plan, site, log=log)
    return site, stats
