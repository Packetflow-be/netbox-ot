import datetime

from django.core.exceptions import ValidationError
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from dcim.models import Site
from tenancy.models import Contact
from utilities.testing import TestCase

from netbox_ot import risk
from netbox_ot.checks import run_checks
from netbox_ot.filtersets import RiskAssessmentFilterSet
from netbox_ot.models import RiskAssessment, Zone
from netbox_ot.risk_register import ACCEPTED, build_risk_register

TODAY = timezone.localdate()
DAY = datetime.timedelta(days=1)


class RiskAcceptanceTest(TestCase):
    """#46: an explicit, time-bound acceptance of a residual risk above tolerable, and the SL-T it arrives at."""
    user_permissions = (
        'netbox_ot.view_riskassessment', 'netbox_ot.change_riskassessment', 'netbox_ot.view_zone',
        'netbox_ot.change_zone',
    )

    @classmethod
    def setUpTestData(cls):
        cls.site = Site.objects.create(name='Plant', slug='plant')
        cls.zone = Zone.objects.create(name='Cell', slug='cell', site=cls.site, purdue_level='1', sl_target=[1] * 7)
        cls.owner = Contact.objects.create(name='Plant manager')

    def over(self, **kwargs):
        ra = RiskAssessment(zone=self.zone, kind='detailed', assessed_on=TODAY - 10 * DAY, status='approved',
                            approved_on=TODAY - 10 * DAY, approved_by=self.owner, threats='t', countermeasures='c',
                            unmitigated_risk='critical', residual_risk='high', tolerable_risk='medium', **kwargs)
        ra.full_clean()
        ra.save()
        return ra

    def accept(self, ra, until=None):
        ra.risk_accepted_by, ra.risk_accepted_on, ra.risk_acceptance = self.owner, TODAY - DAY, 'Line replaced in Q2'
        ra.risk_accepted_until = until
        ra.full_clean()
        ra.save()
        return ra

    def _check_ids(self):
        return {f.check for f in run_checks(site=self.site)}

    def test_partial_acceptance_is_refused(self):
        ra = self.over()
        ra.risk_accepted_by = self.owner
        with self.assertRaises(ValidationError) as cm:
            ra.full_clean()
        self.assertEqual(set(cm.exception.message_dict), {'risk_accepted_on', 'risk_acceptance'})
        ra.risk_accepted_on, ra.risk_acceptance, ra.risk_accepted_until = TODAY, 'why', TODAY - DAY
        with self.assertRaises(ValidationError) as cm:
            ra.full_clean()
        self.assertIn('risk_accepted_until', cm.exception.message_dict)

    def test_accepted_risk(self):
        ra = self.over()
        self.assertFalse(ra.risk_accepted)
        self.assertIn('residual-above-tolerable', self._check_ids())
        self.assertEqual({s['key']: s['state'] for s in risk.steps(ra)}['residual'], 'attention')
        self.accept(ra, until=TODAY + 90 * DAY)
        self.assertTrue(ra.risk_accepted)
        residual = {s['key']: s for s in risk.steps(ra)}['residual']
        self.assertEqual(residual['state'], 'done')
        self.assertIn('accepted by Plant manager', residual['note'])
        ids = self._check_ids()
        self.assertNotIn('residual-above-tolerable', ids)
        self.assertIn('risk-accepted', ids)
        self.assertEqual(build_risk_register(site=self.site)['rows'][0]['bucket'], ACCEPTED)
        self.assertEqual(list(RiskAssessmentFilterSet({'risk_accepted': True}, RiskAssessment.objects.all()).qs), [ra])

    def test_ended_acceptance(self):
        ra = self.accept(self.over(), until=TODAY - DAY)
        self.assertFalse(ra.risk_accepted)
        self.assertTrue(ra.acceptance_expired)
        findings = [f for f in run_checks(site=self.site) if f.check == 'residual-above-tolerable']
        self.assertIn('acceptance ended', findings[0].message)
        self.assertEqual(list(RiskAssessmentFilterSet({'risk_accepted': True}, RiskAssessment.objects.all()).qs), [])

    def test_sl_target_from_the_assessment(self):
        ra = self.over(sl_target=[2] * 7)
        self.assertTrue(ra.sl_target_differs)
        self.assertIn('sl-target-differs', self._check_ids())
        # A detailed assessment asks for the SL-T it arrives at
        self.assertNotIn('the SL-T it arrives at', {s['key']: s for s in risk.steps(ra)}['detailed']['missing'])

    @override_settings(EXEMPT_VIEW_PERMISSIONS=[])
    def test_page_and_apply(self):
        ra = self.over(sl_target=[2] * 7)
        response = self.client.get(ra.get_absolute_url())
        self.assertHttpStatus(response, 200)
        self.assertContains(response, 'Accept the residual risk')
        self.assertContains(response, 'nobody accepted it')
        self.assertContains(response, 'Set it on Cell')
        url = reverse('plugins:netbox_ot:riskassessment_apply_sl_target', kwargs={'pk': ra.pk})
        response = self.client.post(url)
        self.assertHttpStatus(response, 302)
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.sl_target, [2] * 7)
        self.assertNotIn('sl-target-differs', self._check_ids())

    @override_settings(EXEMPT_VIEW_PERMISSIONS=[])
    def test_apply_needs_change_on_the_zone(self):
        self.remove_permissions('netbox_ot.change_zone')
        ra = self.over(sl_target=[2] * 7)
        response = self.client.get(ra.get_absolute_url())
        self.assertNotContains(response, 'Set it on Cell')
        response = self.client.post(reverse('plugins:netbox_ot:riskassessment_apply_sl_target', kwargs={'pk': ra.pk}))
        self.assertHttpStatus(response, 403)
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.sl_target, [1] * 7)
