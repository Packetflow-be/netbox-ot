import datetime
from io import StringIO

from django.core.management import call_command
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from dcim.models import Site
from tenancy.models import Tenant
from utilities.testing import TestCase

from netbox_ot.checks import run_checks
from netbox_ot.models import Conduit, Flow, RiskAssessment, Zone
from netbox_ot.risk_register import ABOVE, DUE, UNASSESSED, WITHIN, build_risk_register, risk_register_csv

TODAY = timezone.localdate()
LAST_MONTH = TODAY - datetime.timedelta(days=30)


def approved(**kwargs):
    ra = RiskAssessment(assessed_on=LAST_MONTH, status='approved', approved_on=LAST_MONTH, **kwargs)
    ra.save()
    return ra


class RiskRegisterTest(TestCase):
    user_permissions = (
        'netbox_ot.view_riskassessment', 'netbox_ot.view_zone', 'netbox_ot.view_conduit', 'netbox_ot.view_flow',
        'tenancy.view_tenant', 'dcim.view_site',
    )

    @classmethod
    def setUpTestData(cls):
        cls.site = Site.objects.create(name='Plant', slug='plant')
        cls.other_site = Site.objects.create(name='Plant 2', slug='plant-2')
        cls.tenant = Tenant.objects.create(name='Customer', slug='customer')
        cls.other = Tenant.objects.create(name='Other', slug='other')

        def zone(name, site=None, tenant=None, **kwargs):
            return Zone.objects.create(name=name, slug=name.lower(), site=site or cls.site,
                                       tenant=tenant or cls.tenant, **kwargs)

        cls.cell = zone('Cell', purdue_level='1')
        cls.scada = zone('Scada', purdue_level='2')
        cls.mes = zone('Mes', purdue_level='3')
        cls.hmi = zone('Hmi', site=cls.other_site, purdue_level='2')
        cls.foreign = zone('Foreign', tenant=cls.other, purdue_level='1')
        cls.supplier = zone('Supplier', zone_type='external')
        cls.conduit = Conduit.objects.create(name='Supplier - Cell', site=cls.site)
        cls.conduit.zones.set([cls.supplier, cls.cell])
        Flow.objects.create(name='vpn', source_zone=cls.supplier, destination_zone=cls.cell, remote_access=True,
                            access=['write'], conduit=cls.conduit)
        # Cell: residual above tolerable; Mes: approved, review due; Hmi: within tolerable; Scada: only a draft
        approved(zone=cls.cell, kind='detailed', unmitigated_risk='critical', residual_risk='high',
                 tolerable_risk='medium')
        approved(zone=cls.mes, kind='initial', unmitigated_risk='low', tolerable_risk='medium',
                 next_review=TODAY - datetime.timedelta(days=1))
        approved(zone=cls.hmi, kind='initial', unmitigated_risk='low', tolerable_risk='medium',
                 next_review=TODAY + datetime.timedelta(days=300))
        RiskAssessment(zone=cls.scada, kind='initial', assessed_on=TODAY, unmitigated_risk='high',
                       tolerable_risk='medium').save()

    def _rows(self, **kwargs):
        return {str(r['subject']): r for r in build_risk_register(**kwargs)['rows']}

    def test_buckets_worst_first(self):
        register = build_risk_register(tenant=self.tenant)
        names = [str(r['subject']) for r in register['rows']]
        self.assertEqual(names[0], 'Cell')
        rows = self._rows(tenant=self.tenant)
        self.assertEqual(rows['Cell']['bucket'], ABOVE)
        self.assertEqual(rows['Scada']['bucket'], UNASSESSED)
        self.assertEqual(rows['Mes']['bucket'], DUE)
        self.assertEqual(rows['Hmi']['bucket'], WITHIN)
        # The draft is shown as the assessment in progress, with its step
        self.assertIsNone(rows['Scada']['approved'])
        self.assertEqual(rows['Scada']['step'], 'Detailed assessment (ZCR 5)')
        self.assertEqual(dict((b, n) for b, _l, _c, n in register['buckets']),
                         {ABOVE: 1, 'accepted': 0, UNASSESSED: 2, DUE: 1, WITHIN: 1})

    def test_tenant_scope(self):
        rows = self._rows(tenant=self.tenant)
        # External zones are outside the system under consideration; another tenant's zones are not listed
        self.assertNotIn('Supplier', rows)
        self.assertNotIn('Foreign', rows)
        # A conduit joins a zone of the tenant: it is listed, with its flows
        self.assertEqual(rows['Supplier - Cell']['kind'], 'conduit')
        self.assertEqual(rows['Supplier - Cell']['bucket'], UNASSESSED)
        self.assertEqual((rows['Cell']['ways_in'], rows['Cell']['remote']), (1, 1))
        self.assertGreater(rows['Cell']['findings']['error'], 0)  # undecided remote write into a control zone
        # All sites of the tenant, or one site
        self.assertIn('Hmi', rows)
        self.assertNotIn('Hmi', self._rows(tenant=self.tenant, site=self.site))
        self.assertIn('Foreign', self._rows())

    def test_csv(self):
        data = risk_register_csv(build_risk_register(tenant=self.tenant))
        lines = data.strip().splitlines()
        self.assertTrue(lines[0].startswith('status,kind,name,site,tenant'))
        self.assertIn('Above tolerable,zone,Cell,Plant,Customer', lines[1])

    def test_checks_tenant_scope(self):
        objects = {str(f.obj) for f in run_checks(tenant=self.other)}
        self.assertIn('Foreign', objects)
        self.assertNotIn('Cell', objects)
        out = StringIO()
        with self.assertRaises(SystemExit):
            call_command('ot_check', tenant='customer', stdout=out)
        self.assertIn('undecided-into-control', out.getvalue())

    @override_settings(EXEMPT_VIEW_PERMISSIONS=[])
    def test_pages(self):
        url = reverse('plugins:netbox_ot:risk_register')
        response = self.client.get(url, {'tenant_id': self.tenant.pk})
        self.assertHttpStatus(response, 200)
        self.assertContains(response, 'Above tolerable')
        self.assertContains(response, 'Supplier - Cell')
        self.assertNotContains(response, '>Foreign<')
        response = self.client.get(url, {'tenant_id': self.tenant.pk, 'export': 'csv'})
        self.assertEqual(response['Content-Type'], 'text/csv; charset=utf-8')
        self.assertIn('customer-ot-risk-register.csv', response['Content-Disposition'])
        # The tab on the tenant
        response = self.client.get(reverse('tenancy:tenant_ot_risk_register', kwargs={'pk': self.tenant.pk}))
        self.assertHttpStatus(response, 200)
        self.assertContains(response, 'Cell')
        response = self.client.get(reverse('plugins:netbox_ot:checks'), {'tenant_id': self.other.pk})
        self.assertHttpStatus(response, 200)

    def test_step_counts_the_other_assessments(self):
        # An initial assessment above tolerable with a detailed one: past the detailed step, in the list too
        initial = RiskAssessment(zone=self.scada, kind='initial', assessed_on=LAST_MONTH, unmitigated_risk='high',
                                 tolerable_risk='medium')
        initial.save()
        self.assertEqual(initial.current_step, 'Detailed assessment (ZCR 5)')
        RiskAssessment(zone=self.scada, kind='detailed', assessed_on=TODAY, threats='t').save()
        initial.refresh_from_db()
        self.assertEqual(initial.current_step, 'Approval')
