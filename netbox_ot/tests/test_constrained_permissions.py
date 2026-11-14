"""
Constrained object permissions: a user who may only view site A must not see site B's zones, conduits, flows,
devices or risk assessments in netbox-ot's object pages, reports, report APIs and GraphQL. Everything of site B
carries "secretb" in its name, so a leak is a substring check.

As in NetBox itself, permissions filter the objects a list or API returns, not the references inside a visible
object: the REST API's nested `devices` of a zone or `zones` of a conduit, and the zones column of the conduit
list, show every related object (NetBox's ManyToManyColumn and nested serializers do the same). GraphQL limits
nested lists as well. Those surfaces are only checked for site B's own objects as rows.
"""
import datetime
import json

from django.urls import reverse

from core.models import ObjectType
from dcim.models import Device, Site
from users.models import ObjectPermission
from utilities.testing import TestCase, create_test_device

from netbox_ot.models import Conduit, Flow, RiskAssessment, Zone

MARK = 'secretb'


def _grant(user, model, constraints):
    perm = ObjectPermission.objects.create(
        name=f'view {model._meta.label_lower}', actions=['view'], constraints=constraints)
    perm.object_types.add(ObjectType.objects.get_for_model(model))
    perm.users.add(user)


def _context(body):
    i = body.find(MARK)
    return ' '.join(body[max(0, i - 90):i + 30].split()) if i >= 0 else ''


class ConstrainedPermissionTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.site_a = Site.objects.create(name='Site A', slug='site-a')
        site_b = Site.objects.create(name=f'Site {MARK}', slug=f'site-{MARK}')
        dev_a = create_test_device('plc-a', site=cls.site_a)
        dev_b = create_test_device(f'plc-{MARK}', site=site_b)
        za1 = Zone.objects.create(name='Zone A1', slug='za1', site=cls.site_a, purdue_level='1', zone_type='ot')
        za2 = Zone.objects.create(name='Zone A2', slug='za2', site=cls.site_a, purdue_level='3', zone_type='ot')
        zb = Zone.objects.create(name=f'Zone {MARK}', slug='zb', site=site_b, purdue_level='3', zone_type='ot')
        # A visible zone that also holds a device of site B (a device moved to another site later)
        za1.devices.set([dev_a, dev_b])
        zb.devices.set([dev_b])
        # A visible conduit of site A that also joins site B's zone, one inside site A, and one of site B
        cx = Conduit.objects.create(name='Conduit cross', site=cls.site_a)
        cx.zones.set([za1, zb])
        ca = Conduit.objects.create(name='Conduit A', site=cls.site_a)
        ca.zones.set([za1, za2])
        cb = Conduit.objects.create(name=f'Conduit {MARK}', site=site_b)
        cb.zones.set([zb, za2])
        Flow.objects.create(name='Flow A', source_zone=za2, destination_zone=za1, conduit=ca, protocol='modbus-tcp',
                            port_mappings=['tcp/502'], allowed='yes')
        # Into site A's control zone from site B: not visible (its source zone is site B's), but on a visible conduit
        Flow.objects.create(name=f'Flow {MARK}', source_zone=zb, destination_zone=za1, conduit=cx,
                            protocol='modbus-tcp', port_mappings=['tcp/502'], allowed='no')
        on = datetime.date(2026, 11, 1)
        RiskAssessment.objects.create(zone=za1, kind='initial', status='approved', description='RA A', assessed_on=on)
        RiskAssessment.objects.create(zone=zb, kind='initial', status='approved', description=f'RA {MARK}',
                                      assessed_on=on)

    def setUp(self):
        super().setUp()
        site_a = {'site__slug': 'site-a'}
        _grant(self.user, Site, {'slug': 'site-a'})
        _grant(self.user, Device, site_a)
        _grant(self.user, Zone, site_a)
        _grant(self.user, Conduit, site_a)
        _grant(self.user, Flow, {'source_zone__site__slug': 'site-a', 'destination_zone__site__slug': 'site-a'})
        _grant(self.user, RiskAssessment, {'zone__site__slug': 'site-a'})

    def test_site_b_never_shows(self):
        za1 = Zone.objects.get(slug='za1')
        sid = self.site_a.pk
        urls = {
            'ui zone list': reverse('plugins:netbox_ot:zone_list'),
            'ui flow list': reverse('plugins:netbox_ot:flow_list'),
            'ui risk assessment list': reverse('plugins:netbox_ot:riskassessment_list'),
            'ui zone': za1.get_absolute_url(),
            'ui conduit': Conduit.objects.get(name='Conduit cross').get_absolute_url(),
            'ui device panel': Device.objects.get(name='plc-a').get_absolute_url(),
            'ui site register': reverse('dcim:site_ot_register', args=[sid]),
            'ui site overview': reverse('dcim:site_ot_overview', args=[sid]),
            'ui site access map': reverse('dcim:site_ot_accessmap', args=[sid]),
            'ui access map': reverse('plugins:netbox_ot:accessmap') + f'?site_id={sid}',
            'ui checks': reverse('plugins:netbox_ot:checks') + f'?site_id={sid}',
            'ui risk register': reverse('plugins:netbox_ot:risk_register'),
            'api flows': '/api/plugins/ot/flows/',
            'api risk assessments': '/api/plugins/ot/risk-assessments/',
            'api register': f'/api/plugins/ot/register/?site_id={sid}',
            'api checks': f'/api/plugins/ot/checks/?site_id={sid}',
            'api overview': f'/api/plugins/ot/overview/?site_id={sid}',
            'api access map': f'/api/plugins/ot/access-map/?site_id={sid}&max_level=3',
            'api firewall rules': f'/api/plugins/ot/firewall-rules/?site_id={sid}&include_denied=true',
        }
        leaks = []
        for label, url in urls.items():
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200, label)
            if MARK in (body := response.content.decode()):
                leaks.append(f'{label}: ...{_context(body)}...')
        queries = {
            'graphql zones': '{ ot_zone_list { name devices { name } conduits { name zones { name } flows { name } }'
                             ' flows_in { name } risk_assessments { description } } }',
            'graphql conduits': '{ ot_conduit_list { name zones { name } flows { name } } }',
            'graphql flows': '{ ot_flow_list { name } }',
        }
        for label, query in queries.items():
            response = self.client.post('/graphql/', data=json.dumps({'query': query}), content_type='application/json')
            self.assertEqual(response.status_code, 200, label)
            if MARK in (body := response.content.decode()):
                leaks.append(f'{label}: ...{_context(body)}...')
        self.assertEqual(leaks, [])

    def test_nested_references_list_only_visible_objects(self):
        """The conduit list and the zone/conduit API list no site-B object as a row (nested references may show)."""
        body = self.client.get(reverse('plugins:netbox_ot:conduit_list')).content.decode()
        self.assertNotIn(f'Conduit {MARK}', body)
        for endpoint in ('zones', 'conduits'):
            results = self.client.get(f'/api/plugins/ot/{endpoint}/').json()['results']
            self.assertFalse([r['name'] for r in results if MARK in r['name']], endpoint)

    def test_register_counts_only_visible_flows(self):
        """The cross-site conduit carries a site-B flow the user cannot view: the register does not count it."""
        data = self.client.get(f'/api/plugins/ot/register/?site_id={self.site_a.pk}').json()
        cross = next(c for c in data['conduits'] if c['conduit'] == 'Conduit cross')
        self.assertEqual((cross['flows'], cross['not_allowed'], cross['zones']), (0, 0, 'Zone A1'))
