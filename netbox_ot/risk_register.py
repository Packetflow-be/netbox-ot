"""
The risk register: every zone and conduit in scope (a tenant, a site, or everything) with where its risk stands,
worst first. It is the overview an asset owner or auditor asks for: what is above the tolerable risk, what has no
approved assessment yet, what is due for review, and what is within tolerable. One structure, rendered as HTML
(printable) and CSV.
"""
import csv
import io
from collections import defaultdict

from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from . import __version__, risk
from .checks import Scope, run_checks
from .choices import RiskAssessmentStatusChoices, RiskLevelChoices, ZoneTypeChoices
from .models import RiskAssessment

# Worst first
ABOVE, UNASSESSED, DUE, WITHIN = 'above', 'unassessed', 'due', 'within'
BUCKETS = {
    ABOVE: (_('Above tolerable'), 'red'),
    UNASSESSED: (_('No approved assessment'), 'orange'),
    DUE: (_('Review due'), 'yellow'),
    WITHIN: (_('Within tolerable'), 'green'),
}
CSV_COLUMNS = (
    'status', 'kind', 'name', 'site', 'tenant', 'purdue_level', 'sl_target', 'assessment', 'assessment_status',
    'step', 'unmitigated_risk', 'residual_risk', 'tolerable_risk', 'next_review', 'ways_in', 'remote_access',
    'errors', 'warnings',
)


def _key(obj):
    return obj._meta.label_lower, obj.pk


def _level_rank(level):
    order = RiskLevelChoices.values()
    return order.index(level) if level in order else -1


def _latest(ras, approved=False):
    if approved:
        ras = [ra for ra in ras if ra.status == RiskAssessmentStatusChoices.APPROVED]
    return max(ras, key=lambda ra: (ra.assessed_on, ra.pk)) if ras else None


def build_risk_register(user=None, site=None, tenant=None):
    """The risk register of a tenant, a site, or everything the user may view (see the module docstring)."""
    scope = Scope(site=site, user=user, tenant=tenant)
    zones = [z for z in scope.zones if z.zone_type != ZoneTypeChoices.EXTERNAL]
    conduits = scope.conduits
    today = timezone.localdate()

    # Every assessment of the subjects in scope, per subject
    assessments = RiskAssessment.objects.filter(Q(zone__in=zones) | Q(conduit__in=conduits)).select_related(
        'zone', 'conduit', 'approved_by')
    if user is not None:
        assessments = assessments.restrict(user, 'view')
    per_subject = defaultdict(list)
    for ra in assessments:
        per_subject[('zone', ra.zone_id) if ra.zone_id else ('conduit', ra.conduit_id)].append(ra)

    # Which subject each object belongs to, to count the findings per subject
    owners = defaultdict(set)
    for zone in zones:
        subject = ('zone', zone.pk)
        owners[_key(zone)].add(subject)
        for member in scope.members(zone):
            owners[_key(member)].add(subject)
    for conduit in conduits:
        subject = ('conduit', conduit.pk)
        owners[_key(conduit)].add(subject)
        for device in list(conduit.enforcing_devices.all()) + list(conduit.enforcing_virtual_machines.all()):
            owners[_key(device)].add(subject)
    flows = list(scope.flows)
    ways_in, remote = defaultdict(int), defaultdict(int)
    for flow in flows:
        if flow.destination_zone_id and flow.source_zone_id != flow.destination_zone_id:
            ways_in[('zone', flow.destination_zone_id)] += 1
            remote[('zone', flow.destination_zone_id)] += bool(flow.remote_access)
        for zone_id in {flow.source_zone_id, flow.destination_zone_id} - {None}:
            owners[_key(flow)].add(('zone', zone_id))
        if flow.conduit_id:
            owners[_key(flow)].add(('conduit', flow.conduit_id))
            ways_in[('conduit', flow.conduit_id)] += 1
            remote[('conduit', flow.conduit_id)] += bool(flow.remote_access)
    for subject, ras in per_subject.items():
        for ra in ras:
            owners[_key(ra)].add(subject)
    findings = defaultdict(lambda: {'error': 0, 'warning': 0, 'info': 0})
    for f in run_checks(site=site, user=user, tenant=tenant):
        if getattr(f.obj, '_meta', None):
            for subject in owners.get(_key(f.obj), ()):
                findings[subject][f.severity] += 1

    rows = []
    for kind, objs in (('zone', zones), ('conduit', conduits)):
        for obj in objs:
            subject = (kind, obj.pk)
            ras = per_subject.get(subject, [])
            approved = _latest(ras, approved=True)
            latest = _latest(ras)
            # A newer draft or reviewed assessment is the one in progress
            in_progress = latest if latest is not None and latest is not approved else None
            shown = approved or in_progress
            if approved is None:
                bucket = UNASSESSED
            elif approved.residual_above_tolerable:
                bucket = ABOVE
            elif approved.next_review and approved.next_review <= today:
                bucket = DUE
            else:
                bucket = WITHIN
            if kind == 'zone':
                tenants = [obj.tenant] if obj.tenant_id else []
            else:
                tenants = sorted({z.tenant for z in obj.zones.all() if z.tenant_id}, key=str)
            rows.append({
                'kind': kind,
                'subject': obj,
                'site': obj.site,
                'tenants': tenants,
                'purdue_level': getattr(obj, 'purdue_level', '') or '',
                'sl_target': obj.sl_target_display,
                'bucket': bucket,
                'bucket_label': BUCKETS[bucket][0],
                'bucket_color': BUCKETS[bucket][1],
                'approved': approved,
                'in_progress': in_progress,
                'assessment': shown,
                'step': risk.current_step(in_progress, [ra for ra in ras if ra is not in_progress])
                if in_progress else (risk.current_step(approved, [ra for ra in ras if ra is not approved])
                                     if approved else ''),
                'unmitigated': shown.unmitigated_risk if shown else '',
                'residual': shown.residual_risk if shown else '',
                'tolerable': shown.tolerable_risk if shown else '',
                'next_review': approved.next_review if approved else None,
                'ways_in': ways_in.get(subject, 0),
                'remote': remote.get(subject, 0),
                'findings': findings.get(subject, {'error': 0, 'warning': 0, 'info': 0}),
            })
    labels = dict(RiskLevelChoices.CHOICES)
    for r in rows:
        # (label, color) of the unmitigated, residual and tolerable risk, for badges
        r['levels'] = [(labels[v], RiskLevelChoices.colors.get(v)) if v else None
                       for v in (r['unmitigated'], r['residual'], r['tolerable'])]
    order = list(BUCKETS)
    rows.sort(key=lambda r: (order.index(r['bucket']), -_level_rank(r['residual'] or r['unmitigated']),
                             -r['remote'], str(r['subject'])))
    counts = {b: sum(1 for r in rows if r['bucket'] == b) for b in BUCKETS}
    return {
        'site': site,
        'tenant': tenant,
        'rows': rows,
        'buckets': [(b, BUCKETS[b][0], BUCKETS[b][1], counts[b]) for b in BUCKETS],
        'generated': timezone.now(),
        'version': __version__,
    }


def risk_register_csv(register):
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    labels = dict(RiskLevelChoices.CHOICES)
    for r in register['rows']:
        ra = r['assessment']
        writer.writerow({
            'status': str(r['bucket_label']),
            'kind': r['kind'],
            'name': str(r['subject']),
            'site': str(r['site'] or ''),
            'tenant': ', '.join(str(t) for t in r['tenants']),
            'purdue_level': r['purdue_level'],
            'sl_target': r['sl_target'],
            'assessment': f'{ra.get_kind_display()} {ra.assessed_on}' if ra else '',
            'assessment_status': ra.get_status_display() if ra else '',
            'step': str(r['step']),
            'unmitigated_risk': str(labels.get(r['unmitigated'], '')),
            'residual_risk': str(labels.get(r['residual'], '')),
            'tolerable_risk': str(labels.get(r['tolerable'], '')),
            'next_review': r['next_review'].isoformat() if r['next_review'] else '',
            'ways_in': r['ways_in'],
            'remote_access': r['remote'],
            'errors': r['findings']['error'],
            'warnings': r['findings']['warning'],
        })
    return out.getvalue()
