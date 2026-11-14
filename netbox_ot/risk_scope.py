"""
What a risk assessment is about: the assets, the ways in and the open findings of its zone or conduit, as they are
now. A risk assessment records a person's judgement; this is the evidence next to it, read live from the model, so
whoever reads or reviews the assessment sees what is at risk and what changed since it was made. It never sets a
risk level.
"""
from django.db.models import Case, IntegerField, Q, Value, When

from . import exposure, lifecycle, sl
from .checks import run_checks
from .choices import FlowAllowedChoices, PurdueLevelChoices
from .customfields import get_purdue_level, get_sl_capability
from .models import Flow, RiskAssessment

# Rows shown per table on the assessment page; the rest is one click away in the filtered list
ROWS_SHOWN = 15


def _key(obj):
    return obj._meta.label_lower, obj.pk


def _new_since(when, assessed_on):
    """True when `when` (a date or datetime) is after the assessment date."""
    if when is None or assessed_on is None:
        return False
    return (when.date() if hasattr(when, 'date') else when) > assessed_on


def _verdict_order():
    # Undecided first (they need a decision), then allowed, then refused
    return Case(
        When(allowed=FlowAllowedChoices.UNKNOWN, then=Value(0)),
        When(allowed=FlowAllowedChoices.YES, then=Value(1)),
        default=Value(2),
        output_field=IntegerField(),
    )


def _flow_rows(flows, assessed_on):
    rows = []
    for flow in flows:
        outside = flow.source_zone is not None and exposure.is_outside_zone(flow.source_zone)
        control = flow.destination_zone is not None and exposure.is_control_zone(flow.destination_zone)
        rows.append({
            'flow': flow,
            'changes': exposure.changes_flow(flow),
            'outside': outside,
            'into_control': control,
            'new': _new_since(flow.first_seen or flow.created, assessed_on),
        })
    return rows


def _asset_rows(assets, assessed_on):
    eos = lifecycle.end_of_support(assets)
    labels = dict(PurdueLevelChoices.CHOICES)
    rows = []
    for asset in assets:
        level = get_purdue_level(asset)
        is_device = asset._meta.label_lower == 'dcim.device'
        capability = get_sl_capability(asset) if is_device else None
        rows.append({
            'asset': asset,
            'role': getattr(asset, 'role', None),
            'level': level,
            'level_label': labels.get(level, level),
            'level_color': PurdueLevelChoices.colors.get(level),
            'capability': sl.short(capability),
            'end_of_support': eos.get(asset.pk) if is_device else None,
            'new': _new_since(asset.created, assessed_on),
        })
    # Most critical (lowest level) first, unknown levels last
    return sorted(rows, key=lambda r: (_level_sort(r['level']), str(r['asset'])))


def _level_sort(level):
    try:
        return float(level)
    except (TypeError, ValueError):
        return 99.0


def _findings(subject, user, keys):
    findings = run_checks(site=subject.site, user=user)
    return [f for f in findings if getattr(f.obj, '_meta', None) and _key(f.obj) in keys]


def _grouped(findings, shown=4):
    """One row per check (the findings come sorted by severity and check): a single finding keeps its message."""
    groups = {}
    for f in findings:
        g = groups.setdefault(f.check, {'check': f.check, 'title': f.title, 'severity': f.severity,
                                        'color': f.color, 'findings': []})
        g['findings'].append(f)
    for g in groups.values():
        g['count'] = len(g['findings'])
        g['shown'] = g['findings'][:shown]
        g['more'] = max(g['count'] - shown, 0)
    return list(groups.values())


def _counts(findings):
    counts = {'error': 0, 'warning': 0, 'info': 0}
    for f in findings:
        counts[f.severity] += 1
    return counts


def _flows(qs, user):
    return qs.restrict(user, 'view').select_related(
        'source_zone', 'destination_zone', 'conduit',
    ).annotate(
        exposure=exposure.exposure_order(), verdict_order=_verdict_order(),
    ).order_by('verdict_order', 'exposure', 'name')


def zone_scope(ra, user):
    zone = ra.zone
    assets = list(zone.devices.restrict(user, 'view').select_related('role', 'device_type')) + list(
        zone.virtual_machines.restrict(user, 'view').select_related('role'))
    asset_rows = _asset_rows(assets, ra.assessed_on)

    ways_in = list(_flows(Flow.objects.filter(destination_zone=zone).exclude(source_zone=zone), user))
    ways_out = _flows(Flow.objects.filter(source_zone=zone).exclude(destination_zone=zone), user).count()
    flow_rows = _flow_rows(ways_in, ra.assessed_on)

    keys = {_key(zone)} | {_key(a) for a in assets}
    keys |= {_key(f) for f in Flow.objects.filter(Q(source_zone=zone) | Q(destination_zone=zone))}
    keys |= {_key(r) for r in RiskAssessment.objects.filter(zone=zone)}
    findings = _findings(zone, user, keys)

    capability = sl.minimum(get_sl_capability(a) for a in assets if a._meta.label_lower == 'dcim.device')
    return _result(
        ra, findings, flow_rows,
        asset_rows=asset_rows,
        ways_out=ways_out,
        sl_target=zone.sl_target_display,
        sl_achieved=zone.sl_achieved_display,
        sl_gap=zone.sl_gap,
        capability=sl.display(capability),
        capability_gap=sl.below(capability, zone.sl_target),
        flows_url_param=f'destination_zone_id={zone.pk}',
    )


def conduit_scope(ra, user):
    conduit = ra.conduit
    zones = list(conduit.zones.restrict(user, 'view').order_by('purdue_level', 'name'))
    enforcing = list(conduit.enforcing_devices.restrict(user, 'view')) + list(
        conduit.enforcing_virtual_machines.restrict(user, 'view'))

    carried = list(_flows(Flow.objects.filter(conduit=conduit), user))
    flow_rows = _flow_rows(carried, ra.assessed_on)

    keys = {_key(conduit)} | {_key(e) for e in enforcing}
    keys |= {_key(f) for f in Flow.objects.filter(conduit=conduit)}
    keys |= {_key(r) for r in RiskAssessment.objects.filter(conduit=conduit)}
    findings = _findings(conduit, user, keys)

    return _result(
        ra, findings, flow_rows,
        zones=zones,
        enforcing=enforcing,
        sl_target=conduit.sl_target_display,
        sl_achieved=conduit.sl_achieved_display,
        sl_gap=conduit.sl_gap,
        flows_url_param=f'conduit_id={conduit.pk}',
    )


def _result(ra, findings, flow_rows, asset_rows=(), **extra):
    asset_rows = list(asset_rows)
    summary = {
        'assets': len(asset_rows),
        'end_of_support': sum(1 for r in asset_rows if r['end_of_support'] and r['end_of_support'].passed),
        'flows': len(flow_rows),
        'remote': sum(1 for r in flow_rows if r['flow'].remote_access),
        'changes': sum(1 for r in flow_rows if r['changes']),
        'outside': sum(1 for r in flow_rows if r['outside']),
        'undecided': sum(1 for r in flow_rows if r['flow'].allowed == FlowAllowedChoices.UNKNOWN),
        'new': sum(1 for r in flow_rows if r['new']) + sum(1 for r in asset_rows if r['new']),
        **_counts(findings),
    }
    return {
        'summary': summary,
        'findings': findings,
        'finding_groups': _grouped(findings),
        'flow_rows': flow_rows[:ROWS_SHOWN],
        'flows_more': max(len(flow_rows) - ROWS_SHOWN, 0),
        'asset_rows': asset_rows[:ROWS_SHOWN],
        'assets_more': max(len(asset_rows) - ROWS_SHOWN, 0),
        **extra,
    }


def assessment_scope(ra, user):
    """The evidence for one risk assessment, for its page (see the module docstring)."""
    if ra.zone_id:
        return {'kind': 'zone', **zone_scope(ra, user)}
    if ra.conduit_id:
        return {'kind': 'conduit', **conduit_scope(ra, user)}
    return None
