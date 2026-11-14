"""
When a flow counts as stale: not seen for `stale_after_days` (plugin setting, default 90) before the newest
observation at its site, not before today. A plant imported from an old capture (or from a capture taken once a
year) would otherwise have every flow stale the day after the import; measured from the site's latest observation,
"stale" means what it should: this path was there before and did not show up in the latest capture.

A flow's site is its destination zone's site (the plant it reaches), else its source zone's. The site's latest
observation is the newest last_seen of any flow from or into a zone of that site, capped at now (a capture clock
that ran ahead). A flow without a site is measured from now.
"""
import datetime

from django.db.models import DateTimeField, ExpressionWrapper, F, OuterRef, Q, Subquery
from django.db.models.functions import Coalesce, Least, Now
from django.utils import timezone

STALE_ANNOTATION = 'site_last_seen'


def _days():
    from .models import stale_after_days
    return datetime.timedelta(days=stale_after_days())


def _newest_at(site):
    """Flows from or into a zone of `site` (a value or an OuterRef), newest observation first."""
    from .models import Flow

    return (Flow.objects.filter(Q(source_zone__site=site) | Q(destination_zone__site=site), last_seen__isnull=False)
            .order_by('-last_seen').values('last_seen')[:1])


def site_last_seen():
    """Expression: the newest last_seen at the outer flow's site, capped at now; now without a site or flows."""
    site = Coalesce(OuterRef('destination_zone__site'), OuterRef('source_zone__site'))
    return Least(Coalesce(Subquery(_newest_at(site), output_field=DateTimeField()), Now()), Now())


def annotate(queryset):
    """The queryset with STALE_ANNOTATION on each flow, so is_stale needs no query of its own."""
    return queryset.annotate(**{STALE_ANNOTATION: site_last_seen()})


def filter_stale(queryset, stale=True):
    """The stale flows of `queryset` (or, with stale=False, the others)."""
    if STALE_ANNOTATION not in queryset.query.annotations:
        queryset = annotate(queryset)
    q = Q(last_seen__lt=ExpressionWrapper(F(STALE_ANNOTATION) - _days(), output_field=DateTimeField()))
    return queryset.filter(q) if stale else queryset.exclude(q)


def site_reference(site_id):
    """The newest last_seen at a site (capped at now), or now: what a flow of that site is measured from."""
    now = timezone.now()
    if site_id is None:
        return now
    newest = _newest_at(site_id).first()
    return min(newest['last_seen'], now) if newest else now


def is_stale(flow):
    if not flow.last_seen:
        return False
    reference = getattr(flow, STALE_ANNOTATION, None)
    if reference is None:
        zone = flow.destination_zone if flow.destination_zone_id else None
        site_id = zone.site_id if zone is not None else None
        if site_id is None and flow.source_zone_id:
            site_id = flow.source_zone.site_id
        reference = site_reference(site_id)
    return flow.last_seen < reference - _days()
