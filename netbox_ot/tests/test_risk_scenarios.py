from django.core.exceptions import ValidationError
from django.test import TestCase as DjangoTestCase
from django.test import override_settings
from django.utils import timezone

from dcim.models import Site
from utilities.testing import (
    APIViewTestCases,
    ChangeLoggedFilterSetTestMixin,
    TestCase,
    ViewTestCases,
    create_tags,
    create_test_device,
)

from netbox_ot import risk
from netbox_ot.checks import run_checks
from netbox_ot.filtersets import RiskScenarioFilterSet
from netbox_ot.models import Conduit, Flow, RiskAssessment, RiskScenario, Zone
from netbox_ot.tests.test_views import PluginURLMixin

TODAY = timezone.localdate()


def plant():
    """A cell with a PLC, a supplier zone, the conduit between them and the supplier's remote maintenance flow."""
    site = Site.objects.create(name='Plant', slug='plant')
    cell = Zone.objects.create(name='Cell', slug='cell', site=site, purdue_level='1')
    supplier = Zone.objects.create(name='Supplier', slug='supplier', site=site, zone_type='external')
    conduit = Conduit.objects.create(name='Supplier - Cell', site=site)
    conduit.zones.set([cell, supplier])
    plc = create_test_device('plc-1', site=site)
    cell.devices.add(plc)
    vpn = Flow.objects.create(name='supplier vpn', source_zone=supplier, destination_zone=cell, remote_access=True,
                              access=['program'], conduit=conduit)
    ra = RiskAssessment.objects.create(zone=cell, kind='detailed', assessed_on=TODAY, tolerable_risk='medium',
                                       unmitigated_risk='high', residual_risk='medium')
    return site, cell, supplier, conduit, plc, vpn, ra


class RiskScenarioModelTest(DjangoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.site, cls.cell, cls.supplier, cls.conduit, cls.plc, cls.vpn, cls.ra = plant()

    def scenario(self, **kwargs):
        return RiskScenario(assessment=self.ra, name='Supplier session reprograms the PLC', **kwargs)

    def test_entry_flow_gives_the_conduit_and_must_reach_the_zone(self):
        s = self.scenario(entry_flow=self.vpn, threat_source='supplier')
        s.full_clean()
        self.assertEqual(s.entry_conduit, self.conduit)
        other = Zone.objects.create(name='Office', slug='office', site=self.site, purdue_level='4')
        stray = Flow.objects.create(name='office to supplier', source_zone=other, destination_zone=self.supplier)
        with self.assertRaises(ValidationError) as cm:
            self.scenario(entry_flow=stray).full_clean()
        self.assertIn('entry_flow', cm.exception.message_dict)

    def test_matrix_gives_the_levels(self):
        s = self.scenario(unmitigated_likelihood=4, unmitigated_impact=5, residual_likelihood=2, residual_impact=5)
        s.full_clean()
        self.assertEqual((s.unmitigated_risk, s.residual_risk), ('critical', 'high'))
        self.assertTrue(s.residual_above_tolerable)
        self.assertEqual(s.tolerable_risk, 'medium')
        # Saved without clean() (the API path): the levels are still stored
        t = RiskScenario(assessment=self.ra, name='Ransomware', unmitigated_likelihood=3, unmitigated_impact=3)
        t.save()
        self.assertEqual(RiskScenario.objects.get(pk=t.pk).unmitigated_risk, 'medium')

    def test_steps_and_worst_of(self):
        # Scenarios carry the threats: the detailed step is done, an unrated scenario is listed as missing
        s = self.scenario(entry_flow=self.vpn, countermeasures='VPN on request, MFA')
        s.save()
        s.targets.set([self.plc])
        steps = {st['key']: st for st in risk.steps(self.ra)}
        self.assertEqual(steps['detailed']['state'], 'done')
        self.assertIn('the unmitigated risk of Supplier session reprograms the PLC', steps['detailed']['missing'])
        self.assertEqual(steps['countermeasures']['state'], 'done')
        # The assessment says residual medium; its scenario says high: the check warns
        s.unmitigated_risk, s.residual_risk = 'critical', 'high'
        s.save()
        self.assertEqual(self.ra.scenario_levels(), ('critical', 'high'))
        self.assertTrue(self.ra.understates_scenarios)
        self.ra.status, self.ra.approved_on = 'approved', TODAY
        self.ra.save()
        findings = [f for f in run_checks(site=self.site) if f.check == 'risk-below-scenarios']
        self.assertEqual(len(findings), 1)
        self.assertIn('lower than its worst threat scenario', findings[0].message)
        self.ra.unmitigated_risk, self.ra.residual_risk = 'critical', 'high'
        self.ra.save()
        self.assertFalse(self.ra.understates_scenarios)

    def test_worst(self):
        self.assertEqual(risk.worst(['low', 'high', '', 'medium']), 'high')
        self.assertEqual(risk.worst(['', None]), '')


class RiskScenarioPageTest(TestCase):
    user_permissions = (
        'netbox_ot.view_riskassessment', 'netbox_ot.view_riskscenario', 'netbox_ot.add_riskscenario',
        'netbox_ot.view_zone', 'netbox_ot.view_flow', 'netbox_ot.view_conduit', 'dcim.view_device',
        'netbox_ot.view_requirementstatus',
    )

    @classmethod
    def setUpTestData(cls):
        cls.site, cls.cell, cls.supplier, cls.conduit, cls.plc, cls.vpn, cls.ra = plant()
        cls.s = RiskScenario.objects.create(assessment=cls.ra, name='Supplier session reprograms the PLC',
                                            threat_source='supplier', entry_flow=cls.vpn, unmitigated_risk='critical',
                                            residual_risk='high', consequence='Line stop')
        cls.s.targets.set([cls.plc])

    @override_settings(EXEMPT_VIEW_PERMISSIONS=[])
    def test_pages(self):
        response = self.client.get(self.s.get_absolute_url())
        self.assertHttpStatus(response, 200)
        self.assertContains(response, 'Way in')
        self.assertContains(response, 'remote access')
        self.assertContains(response, 'changes the controllers')
        self.assertContains(response, 'Target assets')  # the table itself loads by HTMX
        self.assertContains(response, 'Line stop')
        # On the assessment: its scenarios with an Add button, and the worst of them
        response = self.client.get(self.ra.get_absolute_url())
        self.assertHttpStatus(response, 200)
        self.assertContains(response, 'Threat scenarios')
        self.assertContains(response, f'assessment={self.ra.pk}')
        self.assertContains(response, 'unmitigated Critical, residual High')


class RiskScenarioFilterSetTest(DjangoTestCase, ChangeLoggedFilterSetTestMixin):
    queryset = RiskScenario.objects.all()
    filterset = RiskScenarioFilterSet
    ignore_fields = ('vulnerability', 'consequence', 'countermeasures', 'unmitigated_risk', 'residual_risk')

    @classmethod
    def setUpTestData(cls):
        cls.site, cls.cell, cls.supplier, cls.conduit, cls.plc, cls.vpn, cls.ra = plant()
        a = RiskScenario.objects.create(assessment=cls.ra, name='Remote', threat_source='supplier',
                                        entry_flow=cls.vpn, residual_risk='high', vulnerability='shared account')
        a.targets.set([cls.plc])
        RiskScenario.objects.create(assessment=cls.ra, name='USB stick', threat_source='insider',
                                    residual_risk='low')
        other = RiskAssessment.objects.create(conduit=cls.conduit, assessed_on=TODAY, tolerable_risk='high')
        RiskScenario.objects.create(assessment=other, name='Tampered conduit', threat_source='criminal',
                                    residual_risk='high')

    def _count(self, params):
        return self.filterset(params, self.queryset).qs.count()

    def test_filters(self):
        self.assertEqual(self._count({'assessment_id': [self.ra.pk]}), 2)
        self.assertEqual(self._count({'zone_id': [self.cell.pk]}), 2)
        self.assertEqual(self._count({'conduit_id': [self.conduit.pk]}), 1)
        self.assertEqual(self._count({'site_id': [self.site.pk]}), 3)
        self.assertEqual(self._count({'threat_source': ['supplier', 'insider']}), 2)
        self.assertEqual(self._count({'entry_flow_id': [self.vpn.pk]}), 1)
        self.assertEqual(self._count({'entry_conduit_id': [self.conduit.pk]}), 1)
        self.assertEqual(self._count({'device_id': [self.plc.pk]}), 1)
        self.assertEqual(self._count({'remote_access': True}), 1)
        self.assertEqual(self._count({'residual_risk': ['high']}), 2)
        # High is above the cell's tolerable medium, not above the conduit's tolerable high
        self.assertEqual(self._count({'residual_above_tolerable': True}), 1)
        self.assertEqual(self._count({'q': 'shared'}), 1)


class RiskScenarioViewTest(PluginURLMixin, ViewTestCases.PrimaryObjectViewTestCase):
    model = RiskScenario

    @classmethod
    def setUpTestData(cls):
        cls.site, cls.cell, cls.supplier, cls.conduit, cls.plc, cls.vpn, cls.ra = plant()
        for name in ('Remote session', 'USB stick', 'Phishing'):
            RiskScenario.objects.create(assessment=cls.ra, name=name)
        tags = create_tags('Alpha', 'Bravo', 'Charlie')
        cls.form_data = {
            'assessment': cls.ra.pk,
            'name': 'Supplier session reprograms the PLC',
            'threat_source': 'supplier',
            'entry_flow': cls.vpn.pk,
            'targets': [cls.plc.pk],
            'consequence': 'Line stop',
            'unmitigated_risk': 'critical',
            'residual_risk': 'high',
            'tags': [t.pk for t in tags],
        }
        cls.csv_data = (
            'assessment,name,threat_source,targets,residual_risk',
            f'{cls.ra.pk},Scenario 1,insider,plc-1,low',
            f'{cls.ra.pk},Scenario 2,supplier,,high',
            f'{cls.ra.pk},Scenario 3,,,',
        )
        ids = list(RiskScenario.objects.order_by('pk').values_list('pk', flat=True))
        cls.csv_update_data = (
            'id,threat_source,description',
            f'{ids[0]},accident,changed',
            f'{ids[1]},criminal,changed',
            f'{ids[2]},other,changed',
        )
        cls.bulk_edit_data = {'threat_source': 'insider'}


class RiskScenarioAPITest(APIViewTestCases.APIViewTestCase):
    model = RiskScenario
    view_namespace = 'plugins-api:netbox_ot'
    graphql_base_name = 'ot_risk_scenario'
    user_permissions = (
        'netbox_ot.view_riskassessment', 'netbox_ot.view_flow', 'netbox_ot.view_conduit', 'dcim.view_device',
        'netbox_ot.view_requirementstatus',
    )
    brief_fields = ['description', 'display', 'id', 'name', 'url']
    bulk_update_data = {'threat_source': 'insider'}

    @classmethod
    def setUpTestData(cls):
        site, cell, supplier, conduit, plc, vpn, ra = plant()
        for name in ('Remote session', 'USB stick', 'Phishing'):
            RiskScenario.objects.create(assessment=ra, name=name)
        cls.create_data = [
            {'assessment': ra.pk, 'name': 'A', 'threat_source': 'supplier', 'entry_flow': vpn.pk,
             'targets': [plc.pk], 'unmitigated_likelihood': 5, 'unmitigated_impact': 5},
            {'assessment': ra.pk, 'name': 'B', 'residual_risk': 'low'},
            {'assessment': ra.pk, 'name': 'C', 'consequence': 'Line stop', 'entry_conduit': conduit.pk},
        ]


