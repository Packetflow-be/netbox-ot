"""
The machine drawing: one drawing and its tables for one machine (a site, a location, one or more tags, or a mix of
these), for the technical file of the Machinery Regulation (EU) 2023/1230: Annex IV Part A (c) and (d), Annex III
1.7.4.2 (e) and (i), and 1.1.9 for the connections that leave the machine.

What is in scope:

  devices       the devices the viewer may see at the site, in the location (and the locations below it), with
                any of the tags; all given filters apply together.
  zones         every zone one of those devices is a member of. A device is drawn in one zone frame: a sub-zone
                before its parent, then the lowest Purdue level.
  cables        cables on an interface, front or rear port of a device in scope. A cable to a device out of scope
                (or to a circuit) leaves the machine.
  flows         flows with exactly one end in a zone of the scope: the connections to and from the outside.
  NAT           NetBox's own IPAddress.nat_inside: an outside address points to the inside address it maps to.

The layout and the SVG are in machinediagram.py.
"""
import csv
import io
from collections import defaultdict

from django.apps import apps
from django.db.models import Prefetch, Q
from django.utils import timezone
from django.utils.translation import gettext as _
from django.utils.translation import gettext_lazy as _l

from .accessmap import verdict_order
from .customfields import get_firmware_version
from .rules import build_rules, rules_csv

CABLED_MODELS = ('interface', 'frontport', 'rearport')
DEVICE_COLUMNS = (
    'device', 'role', 'manufacturer', 'model', 'serial', 'asset_tag', 'zone', 'other_zones', 'firmware', 'addresses',
    'modules',
)
CABLE_COLUMNS = ('cable', 'a_device', 'a_ports', 'b_device', 'b_ports', 'type', 'status', 'leaves_machine')
ACCESS_PATH_COLUMNS = ('path', 'route', 'origin', 'method', 'target', 'authentication', 'status', 'approved_by',
                       'expires')
# The headers of the connections table, in RULE_COLUMNS order (the CSV keeps the column names)
RULE_LABELS = (
    _l('Rule'), _l('Action'), _l('Source zone'), _l('Source networks'), _l('Destination zone'),
    _l('Destination networks'), _l('Transport'), _l('Ports'), _l('Application'), _l('Connection'), _l('Access'),
    _l('Remote access'), _l('Conduit'), _l('Enforced by'), _l('Valid until'), _l('Decided by'), _l('Decided on'),
    _l('Flow'), _l('Notes'),
)


def _level_key(zone):
    try:
        return float(zone.purdue_level)
    except (TypeError, ValueError):
        return 99.0


def home_zone(zones):
    """The zone frame a device is drawn in: a sub-zone before its parent, then the lowest Purdue level, then name."""
    if not zones:
        return None
    ids = {z.pk for z in zones}
    return sorted(zones, key=lambda z: (z.parent_id not in ids, _level_key(z), z.name))[0]


def _address(ip):
    return str(ip.address.ip)


class Scope:
    """What one drawing covers. Any mix of a site, a location and tags; at least one of them."""

    def __init__(self, site=None, location=None, tags=(), version=''):
        self.site, self.location, self.tags, self.version = site, location, list(tags or ()), (version or '').strip()

    def __bool__(self):
        return bool(self.site or self.location or self.tags)

    @property
    def label(self):
        parts = []
        if self.location is not None:
            parts.append(_('Location {location} ({site})').format(location=self.location, site=self.location.site))
        if self.site is not None and (self.location is None or self.location.site_id != self.site.pk):
            parts.append(_('Site {site}').format(site=self.site))
        if self.tags:
            parts.append(_('Tag {tags}').format(tags=', '.join(t.name for t in self.tags)))
        return ' · '.join(parts)

    @property
    def slug(self):
        parts = [o.slug for o in (self.site, self.location) if o is not None] + [t.slug for t in self.tags]
        if self.version:
            parts.append(''.join(c if c.isalnum() or c in '.-_' else '-' for c in self.version))
        return '-'.join(parts) or 'machine'

    def devices(self, user):
        from dcim.models import Device

        qs = Device.objects.restrict(user, 'view')
        if self.site is not None:
            qs = qs.filter(site=self.site)
        if self.location is not None:
            qs = qs.filter(location__in=self.location.get_descendants(include_self=True))
        if self.tags:
            qs = qs.filter(tags__in=self.tags).distinct()
        return qs


def _modules(device):
    rows = []
    for module in device.modules.all():
        rows.append({
            'bay': module.module_bay.name if module.module_bay_id else '',
            'model': str(module.module_type) if module.module_type_id else '',
            'serial': module.serial,
            'firmware': get_firmware_version(module),
        })
    return rows


def _addresses(user, devices):
    """{device pk: [{'interface', 'address', 'nat': [outside addresses]}]}, the primary address first."""
    from ipam.models import IPAddress

    if not devices:
        return {}
    visible = IPAddress.objects.restrict(user, 'view')
    ips = visible.filter(interface__device__in=devices).prefetch_related(
        'assigned_object', Prefetch('nat_outside', queryset=visible.order_by('address')),
    ).order_by('address')
    primary = {pk for d in devices for pk in (d.primary_ip4_id, d.primary_ip6_id) if pk}
    out = defaultdict(list)
    for ip in ips:
        interface = ip.assigned_object
        out[interface.device_id].append({
            'interface': interface.name,
            'address': _address(ip),
            'primary': ip.pk in primary,
            'nat': [_address(o) for o in ip.nat_outside.all()],
            'pk': ip.pk,
        })
    for rows in out.values():
        rows.sort(key=lambda r: not r['primary'])
    return out


def _cables(user, devices):
    """The cables on a port of a device in scope, each with its two ends and whether it leaves the machine."""
    from django.contrib.contenttypes.models import ContentType

    from dcim.models import Cable, CableTermination, Device

    if not devices:
        return []
    in_scope = {d.pk for d in devices}
    types = [ContentType.objects.get_by_natural_key('dcim', m) for m in CABLED_MODELS]
    on_scope = CableTermination.objects.filter(_device__in=in_scope, termination_type__in=types).values('cable_id')
    cables = list(Cable.objects.restrict(user, 'view').filter(pk__in=on_scope).prefetch_related(
        Prefetch('terminations', queryset=CableTermination.objects.select_related('_device').prefetch_related(
            'termination')),
    ).order_by('pk'))
    peers = {t._device_id for c in cables for t in c.terminations.all() if t._device_id} - in_scope
    visible_peers = set(Device.objects.restrict(user, 'view').filter(pk__in=peers).values_list('pk', flat=True))
    rows = []
    for cable in cables:
        ends = {'A': [], 'B': []}
        for t in cable.terminations.all():
            ends[t.cable_end].append(t)
        sides = []
        for end in ('A', 'B'):
            terms = ends[end]
            device = next((t._device for t in terms if t._device_id), None)
            if device is not None and device.pk not in in_scope and device.pk not in visible_peers:
                sides.append({'device': None, 'name': _('Not visible'), 'ports': '', 'in_scope': False,
                              'url': ''})
                continue
            ports = ', '.join(t.termination.name if hasattr(t.termination, 'name') else str(t.termination)
                              for t in terms if t.termination is not None)
            name = device.name if device is not None else ', '.join(str(t.termination) for t in terms)
            sides.append({
                'device': device,
                'name': name or str(device or ''),
                'ports': ports,
                'in_scope': device is not None and device.pk in in_scope,
                'url': device.get_absolute_url() if device is not None else '',
            })
        a, b = sides
        if not (a['in_scope'] or b['in_scope']):
            continue
        if not a['in_scope']:
            a, b = b, a  # the end in scope first
        rows.append({
            'cable': cable,
            'label': cable.label or f'#{cable.pk}',
            'url': cable.get_absolute_url(),
            'a': a,
            'b': b,
            'type': cable.get_type_display() if cable.type else '',
            'status': cable.get_status_display(),
            'color': cable.color,
            'leaves': not b['in_scope'],
        })
    return rows


def _boundary_flows(user, zone_ids):
    from .models import Flow

    if not zone_ids:
        return Flow.objects.none()
    inside_src, inside_dst = Q(source_zone__in=zone_ids), Q(destination_zone__in=zone_ids)
    return Flow.objects.restrict(user, 'view').filter(
        (inside_src & ~inside_dst) | (~inside_src & inside_dst)
    ).select_related('source_zone__site', 'destination_zone__site', 'broker_zone').annotate(
        verdict_order=verdict_order(),
    ).order_by('verdict_order', 'source_zone__name', 'destination_zone__name', 'name')


def access_paths_installed():
    return apps.is_installed('netbox_access_paths')


def _access_paths(user, devices):
    """Access paths into or through a device in scope (netbox-access-paths), or None when it is not installed."""
    if not access_paths_installed():
        return None
    try:
        from netbox_access_paths.models import AccessPath
        from netbox_access_paths.queries import into_q, through_q
    except ImportError:
        return None
    if not devices:
        return []
    paths = AccessPath.objects.restrict(user, 'view').filter(
        into_q(devices=devices) | through_q('device', devices)
    ).select_related('route', 'tenant', 'approved_by', 'target_type').distinct().order_by('name', 'pk')
    rows = []
    for path in paths:
        target = ''
        if path.target_type_id and path.target_id:
            try:
                target = str(path.target or '')
            except Exception:  # a target that was deleted
                target = ''
        rows.append({
            'path': str(path),
            'url': path.get_absolute_url(),
            'route': str(path.route),
            'origin': path.route.get_origin_display(),
            'method': path.get_method_display(),
            'target': target or path.target_url,
            'authentication': path.get_authentication_display(),
            'status': path.get_status_display(),
            'approved_by': str(path.approved_by or ''),
            'expires': path.expires.isoformat() if path.expires else '',
        })
    return rows


def build_machine(scope, user):
    """Everything the drawing and its tables show, for what the user may see."""
    from dcim.models import Module

    from . import __version__
    from .models import Zone

    zones = Zone.objects.restrict(user, 'view').select_related('site').order_by('purdue_level', 'name')
    devices = list(scope.devices(user).select_related(
        'role', 'device_type__manufacturer', 'primary_ip4', 'primary_ip6', 'site', 'location',
    ).prefetch_related(
        Prefetch('ot_zones', queryset=zones),
        Prefetch('modules', queryset=Module.objects.restrict(user, 'view').select_related(
            'module_bay', 'module_type__manufacturer').order_by('module_bay__name')),
    ).order_by('name', 'pk'))
    addresses = _addresses(user, devices)
    device_rows = []
    for device in devices:
        member_of = list(device.ot_zones.all())
        home = home_zone(member_of)
        rows = addresses.get(device.pk, [])
        primary = next((r for r in rows if r['primary']), rows[0] if rows else None)
        device_rows.append({
            'device': device,
            'name': device.name or str(device),
            'url': device.get_absolute_url(),
            'role': device.role.name if device.role_id else '',
            'role_color': device.role.color if device.role_id else '',
            'manufacturer': device.device_type.manufacturer.name,
            'model': device.device_type.model,
            'serial': device.serial,
            'asset_tag': device.asset_tag or '',
            'zone': home,
            'zones': member_of,
            'other_zones': [z for z in member_of if z != home],
            'firmware': get_firmware_version(device),
            'addresses': rows,
            'primary': primary,
            'modules': _modules(device),
        })
    zone_ids = sorted({z.pk for d in device_rows for z in d['zones']})
    flows_qs = _boundary_flows(user, zone_ids)
    flows = list(flows_qs)
    rules, skipped = build_rules(flows_qs, include_denied=True) if flows else ([], {})
    return {
        'scope': scope,
        'generated': timezone.now(),
        'version': __version__,
        'devices': device_rows,
        'zone_ids': zone_ids,
        'cables': _cables(user, devices),
        'flows': flows,
        'rules': rules,
        'not_exported': dict(skipped),
        'access_paths': _access_paths(user, devices),
    }


#
# Exports
#

def _device_csv_row(d):
    return {
        'device': d['name'],
        'role': d['role'],
        'manufacturer': d['manufacturer'],
        'model': d['model'],
        'serial': d['serial'],
        'asset_tag': d['asset_tag'],
        'zone': d['zone'].name if d['zone'] else '',
        'other_zones': ', '.join(z.name for z in d['other_zones']),
        'firmware': d['firmware'],
        'addresses': '; '.join(
            f"{a['interface']} {a['address']}" + (f" (NAT {', '.join(a['nat'])})" if a['nat'] else '')
            for a in d['addresses']),
        'modules': '; '.join(
            ' '.join(p for p in (m['bay'] + ':' if m['bay'] else '', m['model'],
                                 f"S/N {m['serial']}" if m['serial'] else '',
                                 f"FW {m['firmware']}" if m['firmware'] else '') if p)
            for m in d['modules']),
    }


def _cable_csv_row(c):
    return {
        'cable': c['label'],
        'a_device': c['a']['name'],
        'a_ports': c['a']['ports'],
        'b_device': c['b']['name'],
        'b_ports': c['b']['ports'],
        'type': c['type'],
        'status': c['status'],
        'leaves_machine': 'yes' if c['leaves'] else 'no',
    }


def _csv(columns, rows):
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=columns)
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()


def machine_csv(machine, table):
    """One table as CSV: devices, cables, connections (the firewall rules columns) or access-paths."""
    if table == 'devices':
        return _csv(DEVICE_COLUMNS, [_device_csv_row(d) for d in machine['devices']])
    if table == 'cables':
        return _csv(CABLE_COLUMNS, [_cable_csv_row(c) for c in machine['cables']])
    if table == 'connections':
        return rules_csv(machine['rules'])
    if table == 'access-paths':
        return _csv(ACCESS_PATH_COLUMNS, [{k: r[k] for k in ACCESS_PATH_COLUMNS}
                                          for r in machine['access_paths'] or []])
    raise ValueError(table)


def _flow_json(flow, zone_ids):
    outbound = flow.source_zone_id in zone_ids
    return {
        'id': flow.pk,
        'name': str(flow),
        'direction': 'out' if outbound else 'in',
        'source_zone': flow.source_zone.name,
        'destination_zone': flow.destination_zone.name,
        'outside_zone': (flow.destination_zone if outbound else flow.source_zone).name,
        'protocol': flow.protocol,
        'ports': list(flow.port_mappings),
        'connection': flow.connection,
        'access': list(flow.access),
        'remote_access': flow.remote_access,
        'allowed': 'expired' if flow.is_expired else flow.allowed,
    }


def machine_json(machine):
    scope = machine['scope']
    zone_ids = set(machine['zone_ids'])
    return {
        'scope': {
            'label': scope.label,
            'site': scope.site.pk if scope.site else None,
            'location': scope.location.pk if scope.location else None,
            'tags': [t.slug for t in scope.tags],
            'version': scope.version,
        },
        'generated': machine['generated'].isoformat(),
        'netbox_ot_version': machine['version'],
        'devices': [{**_device_csv_row(d), 'id': d['device'].pk,
                     'addresses': [{k: a[k] for k in ('interface', 'address', 'primary', 'nat')}
                                   for a in d['addresses']],
                     'modules': d['modules'],
                     'other_zones': [z.name for z in d['other_zones']]} for d in machine['devices']],
        'cables': [{**_cable_csv_row(c), 'id': c['cable'].pk, 'leaves_machine': c['leaves']}
                   for c in machine['cables']],
        'flows': [_flow_json(f, zone_ids) for f in machine['flows']],
        'connections': machine['rules'],
        'not_exported': machine['not_exported'],
        'access_paths': machine['access_paths'],
    }
