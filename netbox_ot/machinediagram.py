"""
The machine drawing as a server-rendered SVG, so it prints, downloads and works without JavaScript.

  frames        one per zone, stacked top to bottom from the highest Purdue level down; devices without a zone go
                in a dashed frame at the top, as they are usually IT equipment. All frames share one column grid.
  devices       in each frame the most-cabled first (the switch), then by name; the box shows name, model, primary
                address (with its 1:1 NAT address), firmware, and the role's colour as a stripe.
  cables        drawn orthogonally through the gaps between the rows and the columns, never behind a box; every
                cable has its own lane in a gap, and its port names run along it at both ends.
  left column   what a cable leaves the machine for: devices out of scope, circuits.
  right column  the zones the flows go to or come from, one box each; one arrow per frame, outside zone and
                direction, labelled with each flow's protocol and ports and styled as on the access map (colour =
                verdict, dashed = remote access, dotted = opened from the inside, heavy = changes the destination,
                or may: unclassified requests).
"""
import math
from collections import defaultdict

from django.utils.html import escape
from django.utils.safestring import mark_safe
from django.utils.translation import gettext as _

from .accessdiagram import COLORS, SHADE, SHADES, _short
from .choices import PurdueLevelChoices, ZoneTypeChoices
from .exposure import may_change_flow
from .machine import _level_key

BOX_W, BOX_H = 188, 70
MAX_COLS = 4
GAP = 30            # between two columns, before their lanes
EDGE = 16           # between a frame's border and its outer columns
LANE = 7            # between two cables side by side
PORT = 52           # room for a port name along a cable, below or above a box
TITLE = 30          # a frame's title band
FGAP = 24           # between two frames
PEER_W, PEER_H = 160, 42
OUT_W, OUT_H = 200, 52
FLOW_GAP = 320
PAD = 16
LINE = 12           # one line of a flow label
LABEL_CHARS = 36
CABLE_GREY = '#6c7a89'
ABBREVIATIONS = (('TwentyFiveGigE', 'Twe'), ('HundredGigE', 'Hu'), ('FortyGigabitEthernet', 'Fo'),
                 ('TenGigabitEthernet', 'Te'), ('GigabitEthernet', 'Gi'), ('FastEthernet', 'Fa'),
                 ('Ethernet', 'Eth'))


def _port(name):
    for long, short in ABBREVIATIONS:
        if name.startswith(long):
            name = short + name[len(long):]
            break
    return _short(name, 9)


def _level_label(level):
    return dict(PurdueLevelChoices.CHOICES).get(level, '')


def _verdict(flow):
    return 'expired' if flow.is_expired else flow.allowed


class _Lanes:
    """Lanes of one gap: requests first, then each gets an index, the shortest span the innermost lane."""

    def __init__(self):
        self.requests = []
        self.index = {}

    def ask(self, key, span):
        self.requests.append((span, len(self.requests), key))

    def assign(self):
        for i, (_span, _n, key) in enumerate(sorted(self.requests)):
            self.index[key] = i
        return len(self.requests)

    def __len__(self):
        return len(self.requests)


def _frames(devices):
    """[(zone or None, [device rows])]: devices without a zone first, then from the highest Purdue level down."""
    by_zone = defaultdict(list)
    zones = {}
    for d in devices:
        key = d['zone'].pk if d['zone'] else None
        by_zone[key].append(d)
        zones[key] = d['zone']

    def order(key):
        zone = zones[key]
        if zone is None:
            return (-1, 0, '')
        return (0 if zone.purdue_level else 1, -_level_key(zone), zone.name)

    return [(zones[k], by_zone[k]) for k in sorted(by_zone, key=order)]


def machine_diagram(machine):
    """{'svg': safe string, 'frames', 'devices', 'cables', 'flows'} for build_machine's result; empty svg without
    devices."""
    devices = machine['devices']
    if not devices:
        return {'svg': '', 'frames': 0, 'devices': 0, 'cables': 0, 'flows': 0}
    degree = defaultdict(int)
    for c in machine['cables']:
        for side in (c['a'], c['b']):
            if side['in_scope']:
                degree[side['device'].pk] += 1
    frames = [(zone, sorted(rows, key=lambda d: (-degree[d['device'].pk], d['name'])))
              for zone, rows in _frames(devices)]
    cols = max(1, min(MAX_COLS, max(len(rows) for _z, rows in frames)))

    # Rows of the shared grid
    rows, cell = [], {}
    for fi, (_zone, members) in enumerate(frames):
        count = math.ceil(len(members) / cols)
        for r in range(count):
            chunk = members[r * cols:(r + 1) * cols]
            for c, d in enumerate(chunk):
                cell[d['device'].pk] = (len(rows), c)
            rows.append({'frame': fi, 'first': r == 0, 'last': r == count - 1, 'devices': chunk})
    R = len(rows)

    # Cables: what each needs of the gaps
    channel = [_Lanes() for _ in range(R + 1)]   # channel k lies above row k
    gap = [_Lanes() for _ in range(cols + 1)]    # gap k lies left of column k
    corridor = _Lanes()                          # between the left column and the frames
    bottom, top = defaultdict(list), defaultdict(list)   # exits of a box: (order, route key, port name)
    routes, peers = [], {}
    for n, c in enumerate(machine['cables']):
        a, b = c['a'], c['b']
        key = n
        ra, ca = cell[a['device'].pk]
        if c['leaves']:
            peer_key = ('d', b['device'].pk) if b['device'] is not None else ('o', b['name'])
            peer = peers.setdefault(peer_key, {'name': b['name'], 'url': b['url'], 'ports': [], 'routes': []})
            if b['ports']:
                peer['ports'].append(b['ports'])
            peer['routes'].append(key)
            channel[ra + 1].ask((key, 1), ca + 1)
            corridor.ask(key, -ra)
            bottom[a['device'].pk].append(((-1, n), key, a['ports']))
            routes.append({'key': key, 'kind': 'out', 'a': (ra, ca), 'peer': peer_key, 'cable': c})
            continue
        if a['device'].pk == b['device'].pk:
            continue  # a loop on one device: in the table only
        rb, cb = cell[b['device'].pk]
        if (rb, cb) < (ra, ca):
            a, b, (ra, ca), (rb, cb) = b, a, (rb, cb), (ra, ca)
        route = {'key': key, 'a': (ra, ca), 'b': (rb, cb), 'cable': c}
        bottom[a['device'].pk].append(((cb, n), key, a['ports']))
        if ra == rb:
            route['kind'] = 'same'
            channel[ra + 1].ask((key, 1), abs(cb - ca))
            bottom[b['device'].pk].append(((ca, n), key, b['ports']))
        elif rb == ra + 1:
            route['kind'] = 'down'
            channel[ra + 1].ask((key, 1), abs(cb - ca))
            top[b['device'].pk].append(((ca, n), key, b['ports']))
        else:
            route['kind'] = 'long'
            g = cb if cb >= ca else cb + 1
            route['gap'] = g
            channel[ra + 1].ask((key, 1), abs(g - ca))
            gap[g].ask(key, rb - ra)
            channel[rb].ask((key, 2), abs(cb - g))
            top[b['device'].pk].append(((ca, n), key, b['ports']))
        routes.append(route)
    for lanes in channel + gap + [corridor]:
        lanes.assign()

    # Flows: one arrow per frame, outside zone and direction
    frame_of = {}
    for fi, (zone, members) in enumerate(frames):
        if zone is not None:
            frame_of[zone.pk] = fi
    for fi, (_zone, members) in enumerate(frames):
        for d in members:
            for z in d['zones']:
                frame_of.setdefault(z.pk, fi)
    zone_ids = set(machine['zone_ids'])
    groups = {}
    for flow in machine['flows']:
        outbound = flow.source_zone_id in zone_ids
        inside, other = (flow.source_zone, flow.destination_zone) if outbound else (flow.destination_zone,
                                                                                     flow.source_zone)
        fi = frame_of.get(inside.pk)
        if fi is None:
            continue
        groups.setdefault((fi, other.pk, 'out' if outbound else 'in'),
                          {'frame': fi, 'zone': other, 'out': outbound, 'flows': []})['flows'].append(flow)
    by_frame = defaultdict(list)
    for g in groups.values():
        lines = []
        for f in g['flows']:
            text = ' '.join(p for p in (f.get_protocol_display() if f.protocol else str(f), f.ports_short) if p)
            if f.remote_access:
                text += ' · ' + _('remote')
            lines.append(_short(text, LABEL_CHARS))
        if len(lines) > 4:
            lines = lines[:3] + [_('+{n} more').format(n=len(lines) - 3)]
        g['lines'] = lines
        g['height'] = len(lines) * LINE + 12
        by_frame[g['frame']].append(g)
    for fi in by_frame:
        by_frame[fi].sort(key=lambda g: (-_level_key(g['zone']), g['zone'].name, not g['out']))

    # Horizontal geometry
    def lanes_width(lanes, base):
        return base + (len(lanes) * LANE + 6 if len(lanes) else 0)

    widths = [lanes_width(gap[k], EDGE if k in (0, cols) else GAP) for k in range(cols + 1)]
    corridor_w = lanes_width(corridor, 18) if peers else 0
    grid_left = PAD + (PEER_W + corridor_w if peers else 0)
    gap_start = []
    at = grid_left
    for k in range(cols + 1):
        gap_start.append(at)
        at += widths[k] + (BOX_W if k < cols else 0)
    grid_right = at
    col_x = [gap_start[k] + widths[k] for k in range(cols)]

    def lane_x(start, width, lanes, i):
        return round(start + width / 2 + (i - (len(lanes) - 1) / 2) * LANE, 1)

    # Vertical geometry, channel by channel
    row_y, lane_y, frame_box = [0] * R, [dict() for _ in range(R + 1)], {}
    bottom_used = {cell[pk][0] for pk, exits in bottom.items() if exits}
    top_used = {cell[pk][0] for pk, exits in top.items() if exits}
    y = PAD
    frame_top = 0
    for k in range(R + 1):
        if k > 0:
            y += PORT if (k - 1) in bottom_used else 10
        lanes = channel[k]
        for request, index in lanes.index.items():
            lane_y[k][request] = round(y + 6 + index * LANE, 1)
        y += len(lanes) * LANE + 12 if len(lanes) else 4
        if k > 0 and rows[k - 1]['last']:
            fi = rows[k - 1]['frame']
            need = TITLE + 8 + sum(g['height'] for g in by_frame.get(fi, ()))
            y = max(y + 4, frame_top + need)
            frame_box[fi] = (frame_top, y)
            y += FGAP
        if k < R:
            if rows[k]['first']:
                frame_top = y
                y += TITLE
            y += PORT if k in top_used else 8
            row_y[k] = y
            y += BOX_H
    grid_bottom = y - FGAP

    def box_x(pk):
        return col_x[cell[pk][1]]

    # Where each cable leaves or enters a box
    exit_at = {}
    for exits, edge in ((bottom, 'b'), (top, 't')):
        for pk, items in exits.items():
            items.sort(key=lambda e: e[0])
            step = min(16, (BOX_W - 36) / max(len(items) - 1, 1))
            centre = box_x(pk) + BOX_W / 2
            r = cell[pk][0]
            yy = row_y[r] + BOX_H if edge == 'b' else row_y[r]
            for i, (_o, key, ports) in enumerate(items):
                exit_at.setdefault(key, []).append((round(centre + (i - (len(items) - 1) / 2) * step, 1), yy,
                                                    edge, ports))

    # The left column: what cables leave the machine for, next to the lanes they arrive in
    out = []
    peer_box = {}
    if peers:
        wanted = []
        for peer_key, peer in peers.items():
            ys = [lane_y[next(r['a'][0] + 1 for r in routes if r['key'] == key)][(key, 1)] for key in peer['routes']]
            wanted.append((sum(ys) / len(ys), peer_key))
        at = PAD
        for want, peer_key in sorted(wanted):
            peer = peers[peer_key]
            h = max(PEER_H, len(peer['routes']) * 10 + 20)
            top_y = max(at, want - h / 2)
            peer_box[peer_key] = (top_y, h)
            at = top_y + h + 10
            label = _short(', '.join(_port(p) for p in peer['ports']), 26)
            inner = (f'<rect x="{PAD}" y="{top_y}" width="{PEER_W}" height="{h}" rx="4" class="md-peer"/>'
                     f'<text x="{PAD + 9}" y="{top_y + 17}" class="md-pn">{escape(_short(peer["name"], 22))}</text>'
                     + (f'<text x="{PAD + 9}" y="{top_y + 31}" class="md-ps">{escape(label)}</text>' if label else ''))
            if peer['url']:
                inner = f'<a href="{escape(peer["url"])}">{inner}</a>'
            out.append(f'<g class="md-peer-g"><title>{escape(peer["name"])}</title>{inner}</g>')
    peer_entry = {}
    for peer_key, peer in peers.items():
        top_y, h = peer_box[peer_key]
        keys = sorted(peer['routes'])
        for i, key in enumerate(keys):
            peer_entry[key] = round(top_y + h * (i + 1) / (len(keys) + 1), 1)

    # Cables
    cable_lines, port_labels = [], []
    for route in routes:
        key = route['key']
        c = route['cable']
        ends = exit_at[key]
        (ax, ay, _ae, a_ports) = ends[0]
        ra, ca = route['a']
        if route['kind'] == 'out':
            ly = lane_y[ra + 1][(key, 1)]
            cx = lane_x(PAD + PEER_W, corridor_w, corridor, corridor.index[key])
            py = peer_entry[key]
            points = [(ax, ay), (ax, ly), (cx, ly), (cx, py), (PAD + PEER_W, py)]
        else:
            (bx, by, _be, b_ports) = ends[1]
            rb, _cb = route['b']
            ly = lane_y[ra + 1][(key, 1)]
            if route['kind'] in ('same', 'down'):
                points = [(ax, ay), (ax, ly), (bx, ly), (bx, by)]
            else:
                g = route['gap']
                gx = lane_x(gap_start[g], widths[g], gap[g], gap[g].index[key])
                ly2 = lane_y[rb][(key, 2)]
                points = [(ax, ay), (ax, ly), (gx, ly), (gx, ly2), (bx, ly2), (bx, by)]
        path = 'M' + ' L'.join(f'{px},{py}' for px, py in points)
        colour = f'#{c["color"]}' if c['color'] else CABLE_GREY
        title = escape(f'{c["label"]}: {c["a"]["name"]} {c["a"]["ports"]} - {c["b"]["name"]} {c["b"]["ports"]}'
                       + (f' ({c["type"]})' if c['type'] else ''))
        dash = ' stroke-dasharray="5 3"' if c['leaves'] else ''
        cable_lines.append(f'<g class="md-cable"><title>{title}</title><path d="{path}" class="md-hit"/>'
                           f'<path d="{path}" class="md-cl" stroke="{colour}"{dash}/></g>')
        for (px, py, edge, ports) in ends:
            if not ports:
                continue
            if edge == 'b':
                port_labels.append(f'<text transform="translate({px + 2.5},{py + 4}) rotate(90)" class="md-pt md-halo">'
                                   f'{escape(_port(ports))}</text>')
            else:
                port_labels.append(f'<text transform="translate({px + 2.5},{py - 4}) rotate(90)" '
                                   f'text-anchor="end" class="md-pt md-halo">{escape(_port(ports))}</text>')

    # Frames
    types = dict(ZoneTypeChoices.CHOICES)
    frame_parts, frame_titles = [], []
    for fi, (zone, _members) in enumerate(frames):
        y0, y1 = frame_box[fi]
        w = grid_right - grid_left
        if zone is None:
            frame_parts.append(f'<rect x="{grid_left}" y="{y0}" width="{w}" height="{y1 - y0}" rx="6" '
                               f'class="md-zf md-none"/>')
            frame_titles.append(f'<text x="{grid_left + 12}" y="{y0 + 19}" class="md-zt md-halo">'
                                f'{escape(_("Not in a zone"))}</text>')
            continue
        notes = []
        if zone.purdue_level:
            notes.append(_('level {level}').format(level=zone.purdue_level))
        if zone.zone_type != ZoneTypeChoices.OT:
            notes.append(str(types.get(zone.zone_type, zone.zone_type)).split(' (')[0])
        if zone.sl_target:
            notes.append('SL-T ' + ','.join(str(v) for v in zone.sl_target))
        title = escape(zone.name + (f' ({_level_label(zone.purdue_level)})' if zone.purdue_level else ''))
        frame_parts.append(f'<rect x="{grid_left}" y="{y0}" width="{w}" height="{y1 - y0}" rx="6" class="md-zf"/>')
        frame_titles.append(
            f'<g class="md-frame"><title>{title}</title>'
            f'<a href="{escape(zone.get_absolute_url())}"><text x="{grid_left + 12}" y="{y0 + 19}" '
            f'class="md-zt md-halo">{escape(_short(zone.name, 40))}'
            + (f'<tspan class="md-zs" dx="8">{escape(" · ".join(notes))}</tspan>' if notes else '')
            + '</text></a></g>'
        )

    # Devices
    boxes = []
    for d in devices:
        pk = d['device'].pk
        x0, y0 = box_x(pk), row_y[cell[pk][0]]
        lines = [(_short(d['name'], 24), 'md-dn'), (_short(f'{d["manufacturer"]} {d["model"]}', 30), 'md-ds')]
        if d['primary']:
            ip = d['primary']['address']
            if d['primary']['nat']:
                ip += ' ⇄ ' + d['primary']['nat'][0]
            lines.append((_short(ip, 32), 'md-ds'))
        if d['firmware']:
            lines.append((_short(_('FW {version}').format(version=d['firmware']), 30), 'md-ds'))
        texts = ''.join(f'<text x="{x0 + 12}" y="{y0 + 17 + i * 15}" class="{cls}">{escape(text)}</text>'
                        for i, (text, cls) in enumerate(lines))
        stripe = (f'<rect x="{x0}" y="{y0}" width="5" height="{BOX_H}" fill="#{d["role_color"]}"/>'
                  if d['role_color'] else '')
        title = escape(' · '.join(p for p in (d['name'], d['role'], f'{d["manufacturer"]} {d["model"]}') if p))
        boxes.append(f'<g class="md-dev"><title>{title}</title><a href="{escape(d["url"])}">'
                     f'<rect x="{x0}" y="{y0}" width="{BOX_W}" height="{BOX_H}" rx="4" class="md-box"/>'
                     f'{stripe}{texts}</a></g>')

    # Flows to and from the outside zones
    arrows, labels = [], []
    out_x = grid_right + FLOW_GAP
    slots = {}
    for fi, items in by_frame.items():
        at = frame_box[fi][0] + TITLE + 4
        for g in items:
            slots[id(g)] = round(at + g['height'] - 5, 1)
            at += g['height']
    by_outside = defaultdict(list)
    for g in groups.values():
        by_outside[g['zone'].pk].append(g)
    zone_box = {}
    at = PAD
    for want, zpk in sorted((sum(slots[id(g)] for g in gs) / len(gs), zpk) for zpk, gs in by_outside.items()):
        gs = sorted(by_outside[zpk], key=lambda g: slots[id(g)])
        h = max(OUT_H, len(gs) * 12 + 22)
        top_y = max(at, want - h / 2)
        zone_box[zpk] = (top_y, h)
        at = top_y + h + 12
        for i, g in enumerate(gs):
            g['entry'] = round(top_y + h * (i + 1) / (len(gs) + 1), 1)
        zone = gs[0]['zone']
        notes = []
        if zone.site_id and zone.site_id != getattr(machine['scope'].site, 'pk', None) and zone.site is not None:
            notes.append(zone.site.name)
        if zone.zone_type != ZoneTypeChoices.OT:
            notes.append(str(types.get(zone.zone_type, zone.zone_type)).split(' (')[0])
        if zone.purdue_level:
            notes.append(_('level {level}').format(level=zone.purdue_level))
        note = _short(', '.join(notes), 32)
        out.append(
            f'<g class="md-out-g"><title>{escape(zone.name)}</title><a href="{escape(zone.get_absolute_url())}">'
            f'<rect x="{out_x}" y="{top_y}" width="{OUT_W}" height="{h}" rx="4" class="md-out"/>'
            f'<text x="{out_x + 10}" y="{top_y + 19}" class="md-pn">{escape(_short(zone.name, 26))}</text>'
            + (f'<text x="{out_x + 10}" y="{top_y + 34}" class="md-ps">{escape(note)}</text>' if note else '')
            + '</a></g>'
        )
    for g in groups.values():
        sy, ey = slots[id(g)], g['entry']
        flows = g['flows']
        counts = defaultdict(int)
        for f in flows:
            counts[SHADE[_verdict(f)]] += 1
        shade = next(s for s in SHADES if counts[s])
        remote = any(f.remote_access for f in flows)
        outbound = any(f.is_outbound_only for f in flows)
        pattern = {(True, False): '6 4', (False, True): '2 4', (True, True): '6 3 2 3'}.get((remote, outbound))
        dash = f' stroke-dasharray="{pattern}"' if pattern else ''
        thick = 4.2 if any(may_change_flow(f) for f in flows) else 1.8
        if g['out']:
            path = f'M{grid_right},{sy} C{grid_right + FLOW_GAP * 0.72},{sy} {out_x - 70},{ey} {out_x},{ey}'
        else:
            path = f'M{out_x},{ey} C{out_x - 70},{ey} {grid_right + FLOW_GAP * 0.72},{sy} {grid_right},{sy}'
        title = escape('\n'.join(str(f) for f in flows))
        arrows.append(f'<g class="md-flow"><title>{title}</title><path d="{path}" class="md-hit"/>'
                      f'<path d="{path}" class="md-fl" stroke="{COLORS[shade]}" stroke-width="{thick}"{dash} '
                      f'marker-end="url(#md-arrow-{shade})"/></g>')
        n = len(g['lines'])
        for i, text in enumerate(g['lines']):
            labels.append(f'<text x="{grid_right + 10}" y="{round(sy - 5 - (n - 1 - i) * LINE, 1)}" '
                          f'class="md-lb md-halo">{escape(text)}</text>')

    content_right = (out_x + OUT_W) if groups else grid_right
    content_bottom = max([grid_bottom] + [t + h for t, h in peer_box.values()] + [t + h for t, h in zone_box.values()])

    # Legend and title block
    scope = machine['scope']
    ly0 = content_bottom + 24
    legend = [
        ('cable', _('Cable'), CABLE_GREY, ''),
        ('cable', _('Cable that leaves the machine'), CABLE_GREY, '5 3'),
        ('flow', _('Allowed'), COLORS['green'], ''),
        ('flow', _('No decision yet'), COLORS['amber'], ''),
        ('flow', _('Not allowed, or expired'), COLORS['red'], ''),
        ('flow', _('Remote access'), CABLE_GREY, '6 4'),
        ('flow', _('Opened from the inside (reverse connect, broker)'), CABLE_GREY, '2 4'),
    ]
    legend_parts = [f'<text x="{PAD}" y="{ly0}" class="md-zt">{escape(_("Legend"))}</text>']
    for i, (kind, text, colour, pattern) in enumerate(legend):
        yy = ly0 + 18 + i * 17
        dash = f' stroke-dasharray="{pattern}"' if pattern else ''
        marker = ' marker-end="url(#md-arrow-grey)"' if kind == 'flow' else ''
        legend_parts.append(f'<path d="M{PAD},{yy - 4} L{PAD + 44},{yy - 4}" stroke="{colour}" class="md-cl" '
                            f'stroke-width="{1.8 if kind == "flow" else 1.6}"{dash}{marker}/>'
                            f'<text x="{PAD + 54}" y="{yy}" class="md-ds">{escape(text)}</text>')
    legend_parts.append(f'<text x="{PAD}" y="{ly0 + 18 + len(legend) * 17}" class="md-ds">'
                        f'{escape(_("Heavy arrow: writes, controls or programs the destination, or carries "
                                    "unclassified requests"))}</text>')
    tb_w = 330
    title_lines = [(_('Machine drawing'), 'md-zt'), (_short(scope.label, 52), 'md-ds')]
    if scope.version:
        title_lines.append((_('Version {version}').format(version=_short(scope.version, 40)), 'md-ds'))
    title_lines.append((_('Generated {date} from NetBox, netbox-ot {version}').format(
        date=machine['generated'].strftime('%Y-%m-%d %H:%M'), version=machine['version']), 'md-ds'))
    width = max(content_right + PAD, PAD + 380 + tb_w + PAD)
    tb_x = width - PAD - tb_w
    tb_h = 18 + len(title_lines) * 17
    title_block = (f'<rect x="{tb_x}" y="{ly0 - 14}" width="{tb_w}" height="{tb_h}" rx="4" class="md-tb"/>'
                   + ''.join(f'<text x="{tb_x + 12}" y="{ly0 + 6 + i * 17}" class="{cls}">{escape(text)}</text>'
                             for i, (text, cls) in enumerate(title_lines)))
    height = math.ceil(max(ly0 + 30 + len(legend) * 17, ly0 - 14 + tb_h) + PAD)
    width = math.ceil(width)

    markers = ''.join(
        f'<marker id="md-arrow-{s}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="9" markerHeight="9" '
        f'markerUnits="userSpaceOnUse" orient="auto"><path d="M0,1 L10,5 L0,9 z" fill="{c}"/></marker>'
        for s, c in list(COLORS.items()) + [('grey', CABLE_GREY)]
    )
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        f'style="max-width:{width}px" '
        f'role="img" aria-label="{escape(_("Machine drawing"))}: {escape(scope.label)}" class="md-map">'
        f'<defs>{markers}</defs>'
        '<style>.md-map{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;'
        'color:var(--tblr-body-color,#1d273b)}'
        '.md-map a{color:inherit}.md-map text{fill:currentColor}'
        '.md-halo{paint-order:stroke;stroke:var(--tblr-bg-surface,#fff);stroke-width:4px;stroke-linejoin:round}'
        '.md-zf{fill:rgba(32,107,196,.04);stroke:rgba(32,107,196,.7);stroke-width:1.4}'
        '.md-none{stroke-dasharray:6 4;fill:none;stroke:#8a94a6}'
        '.md-zt{font-size:13px;font-weight:700}.md-zs{font-size:11px;font-weight:400;opacity:.7}'
        '.md-box{fill:var(--tblr-bg-surface,#fff);stroke:#8a94a6;stroke-width:1.2}'
        '.md-dn{font-size:12.5px;font-weight:600}.md-ds{font-size:10.5px;opacity:.8}'
        '.md-pt{font-size:9px;opacity:.85}'
        '.md-cl{fill:none;stroke-width:1.6;stroke-linejoin:round}'
        '.md-hit{fill:none;stroke:transparent;stroke-width:10}'
        '.md-fl{fill:none}.md-lb{font-size:10.5px}'
        '.md-peer{fill:var(--tblr-bg-surface,#fff);stroke:#8a94a6;stroke-dasharray:5 3}'
        '.md-out{fill:var(--tblr-bg-surface,#fff);stroke:rgba(32,107,196,.7);stroke-width:1.4}'
        '.md-pn{font-size:12px;font-weight:600}.md-ps{font-size:10px;opacity:.75}'
        '.md-tb{fill:none;stroke:#8a94a6}'
        '.md-cable:hover .md-cl{stroke-width:3}.md-flow:hover .md-fl{opacity:.75}</style>'
        + ''.join(frame_parts + cable_lines + boxes + arrows + frame_titles + port_labels + labels + out
                  + legend_parts)
        + title_block + '</svg>'
    )
    return {'svg': mark_safe(svg), 'frames': len(frames), 'devices': len(devices),
            'cables': len(routes), 'flows': len(groups), 'width': width, 'height': height}
