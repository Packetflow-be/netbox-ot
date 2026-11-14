"""
The smaller items of the field review (issue #35, P3): Zeek's conn-only connections, function classes, remote
access from an external zone, re-import noise, stale flows, firewalls and sites without zones, the access map
badge, and the OT panel on the device page.
"""
import datetime

from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from dcim.models import Interface, Site
from ipam.models import IPAddress
from utilities.testing import TestCase as NetBoxTestCase
from utilities.testing import create_test_device

from netbox_ot.checks import run_checks
from netbox_ot.choices import ZoneTypeChoices
from netbox_ot.importers import functions, zeek
from netbox_ot.importers.observations import apply_plan, build_plan
from netbox_ot.models import Conduit, Flow, Zone
from netbox_ot.overview import build_overview

T0 = 1793520000  # 2026-11-01T08:00:00Z
ZONES = zeek.ZoneMap(networks={'10.10.10.0/24': 'Cell', '10.10.20.0/24': 'Control room'})


def conn(uid, src, dst, port, service=None, state='SF', history='ShADadFf', proto='tcp'):
    return {'ts': T0, 'uid': uid, 'id.orig_h': src, 'id.resp_h': dst, 'id.resp_p': port, 'proto': proto,
            'service': service, 'conn_state': state, 'history': history, 'orig_bytes': 10, 'resp_bytes': 10}


class ConnOnlyFoldTest(SimpleTestCase):

    def _flows(self, logs):
        _assets, flows, _summary = zeek.to_observations(logs, ZONES)
        return {(f['src'], f['dst'], f['proto'], f.get('port'), f.get('func', '')): f['count'] for f in flows}

    def test_cotp_only_connections_join_the_s7comm_flow(self):
        # One connection carries an S7 read; two more to the same PLC port carry COTP only (no S7 request logged)
        logs = {
            'conn': [conn('S1', '10.10.20.5', '10.10.10.10', 102, 'cotp,s7comm'),
                     conn('S2', '10.10.20.5', '10.10.10.10', 102, 'cotp'),
                     conn('S3', '10.10.20.5', '10.10.10.10', 102)],
            's7comm': [{'ts': T0, 'uid': 'S1', 'id.orig_h': '10.10.20.5', 'id.resp_h': '10.10.10.10',
                        'id.resp_p': 102, 'is_orig': True, 'function_name': 'Read Variable'}],
        }
        self.assertEqual(self._flows(logs), {
            ('10.10.20.5', '10.10.10.10', 's7comm', 102, 'Read Variable'): 1,
            ('10.10.20.5', '10.10.10.10', 's7comm', 102, ''): 2,  # no second, unidentified flow
        })
        plan = build_plan(*zeek.to_observations(logs, ZONES))
        self.assertEqual([(f.source, f.destination, f.protocol) for f in plan.flows],
                         [('Control room', 'Cell', 's7comm')])

    def test_a_rare_guess_joins_the_unidentified_majority(self):
        telnet = [conn(f'T{i}', '10.10.20.5', '10.10.10.10', 23) for i in range(20)]
        guessed = [conn(f'G{i}', '10.10.20.5', '10.10.10.10', 23, 'smb') for i in range(2)]
        self.assertEqual(self._flows({'conn': telnet + guessed}), {('10.10.20.5', '10.10.10.10', 'tcp/23', 23, ''): 22})
        # When the identified connections are more than a small share, Zeek's identification stands
        flows = self._flows({'conn': telnet[:5] + guessed})
        self.assertEqual(flows[('10.10.20.5', '10.10.10.10', 'smb', 23, '')], 2)
        self.assertEqual(flows[('10.10.20.5', '10.10.10.10', 'tcp/23', 23, '')], 5)

    def test_s7_user_data_is_named_by_its_subfunction(self):
        logs = {'conn': [conn('U1', '10.10.20.5', '10.10.10.10', 102)],
                's7comm': [{'ts': T0, 'uid': 'U1', 'id.orig_h': '10.10.20.5', 'id.resp_h': '10.10.10.10',
                            'id.resp_p': 102, 'is_orig': True, 'rosctr_name': 'User-Data',
                            'function_name': 'Request: CPU Functions', 'subfunction_name': 'Read SZL'}]}
        self.assertIn(('10.10.20.5', '10.10.10.10', 's7comm', 102, 'Read SZL'), self._flows(logs))


class ClassifyReconnaissanceTest(SimpleTestCase):

    def test_device_identification_reads(self):
        for protocol, func in (('modbus-tcp', 'ENCAP_INTERFACE_TRANSPORT'), ('modbus-tcp', '43'),
                               ('s7comm', 'Read SZL'), ('s7comm', 'CPU Functions'), ('s7comm', 'List blocks')):
            self.assertEqual(functions.classify(protocol, func), functions.READ, (protocol, func))
        self.assertEqual(functions.classify('s7comm', 'Set clock'), functions.WRITE)

    def test_ot_zone_label(self):
        # A level-3 zone without a declared type is OT; the label no longer claims it is a control zone
        self.assertEqual(dict(ZoneTypeChoices.CHOICES)[ZoneTypeChoices.OT], 'OT')


class ImportTest(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.site = Site.objects.create(name='Plant', slug='plant')

    def _apply(self, assets, flows, summary=None):
        lines = []
        stats = apply_plan(build_plan(assets, flows, summary or {}), self.site, log=lines.append)
        return stats, lines

    def test_a_stray_packet_from_outside_is_not_remote_access(self):
        assets = [{'ip': '10.10.10.10', 'zone': 'Cell', 'purdue_level': 1}]
        flows = [{'src': '203.0.113.5', 'dst': '10.10.10.10', 'proto': 'icmp', 'count': 1}]
        self._apply(assets, flows)
        flow = Flow.objects.get()
        self.assertFalse(flow.remote_access)
        self.assertIn('Not marked as remote access', flow.evidence)
        # A session from the same zone is remote access
        flows.append({'src': '203.0.113.5', 'dst': '10.10.10.10', 'proto': 'tcp/22', 'port': 22, 'transport': 'tcp'})
        self._apply(assets, flows)
        flow.refresh_from_db()
        self.assertTrue(flow.remote_access)
        self.assertNotIn('Not marked as remote access', flow.evidence)

    def test_same_input_same_evidence_and_one_line_per_kind(self):
        assets = [{'ip': f'10.10.10.{i}', 'zone': 'Cell', 'purdue_level': 1} for i in range(1, 12)]
        assets.append({'ip': '10.10.20.5', 'zone': 'Control room', 'purdue_level': 2})
        flows = [{'src': '10.10.20.5', 'dst': f'10.10.10.{i}', 'proto': 'tcp/23', 'port': 23, 'transport': 'tcp',
                  'count': 3} for i in range(1, 12)]
        stats, lines = self._apply(assets, flows)
        self.assertEqual(stats['flows created'], 1)
        # The same requests in another order write the same evidence: a re-run changes nothing
        stats, lines = self._apply(assets, list(reversed(flows)))
        self.assertEqual((stats.get('flows updated', 0), stats['flows unchanged']), (0, 1))
        # Addresses without a device or prefix: one line each, not one per host
        missing = [line for line in lines if 'no prefix in NetBox' in line or 'no device or VM' in line]
        self.assertEqual(len(missing), 2)
        self.assertIn('12 address(es): 10.10.10.1, 10.10.10.2', missing[0])
        self.assertIn('and 4 more', missing[0])


class StaleTest(TestCase):
    """An old capture is not stale; a path that did not show up in the latest capture is."""

    @classmethod
    def setUpTestData(cls):
        site = Site.objects.create(name='Plant', slug='plant')
        cls.site = site
        office = Zone.objects.create(name='Office', slug='office', site=site, purdue_level='4')
        cell = Zone.objects.create(name='Cell', slug='cell', site=site, purdue_level='1')
        capture = timezone.now() - datetime.timedelta(days=400)
        cls.latest = Flow.objects.create(name='latest', source_zone=office, destination_zone=cell, last_seen=capture)
        cls.earlier = Flow.objects.create(name='earlier', source_zone=cell, destination_zone=office,
                                          last_seen=capture - datetime.timedelta(days=100))
        cls.recent = Flow.objects.create(name='recent', source_zone=cell, destination_zone=office,
                                         last_seen=capture - datetime.timedelta(days=10))

    def test_measured_from_the_latest_observation_at_the_site(self):
        self.assertEqual({f.obj.name for f in run_checks(site=self.site, checks=['stale-flow'])}, {'earlier'})
        message = run_checks(site=self.site, checks=['stale-flow'])[0].message
        self.assertIn('more than 90 days before the latest observation at its site', message)
        self.assertFalse(Flow.objects.get(pk=self.latest.pk).is_stale)
        self.assertFalse(Flow.objects.get(pk=self.recent.pk).is_stale)
        self.assertTrue(Flow.objects.get(pk=self.earlier.pk).is_stale)
        from netbox_ot.filtersets import FlowFilterSet
        self.assertEqual([f.name for f in FlowFilterSet({'stale': True}, Flow.objects.all()).qs], ['earlier'])
        self.assertEqual(FlowFilterSet({'stale': False}, Flow.objects.all()).qs.count(), 2)
        with override_settings(PLUGINS_CONFIG={'netbox_ot': {'stale_after_days': 120}}):
            self.assertFalse(Flow.objects.get(pk=self.earlier.pk).is_stale)


def device(name, site, ip=None):
    d = create_test_device(name, site=site)
    if ip:
        iface = Interface.objects.create(device=d, name='eth0', type='1000base-t')
        d.primary_ip4 = IPAddress.objects.create(address=f'{ip}/24', assigned_object=iface)
        d.save()
    return d


class ChecksAndStartTest(TestCase):

    def test_a_firewall_enforcing_a_conduit_is_not_in_no_zone(self):
        site = Site.objects.create(name='Plant', slug='plant')
        a = Zone.objects.create(name='A', slug='a', site=site, purdue_level='1')
        b = Zone.objects.create(name='B', slug='b', site=site, purdue_level='3')
        fw = device('fw-1', site, ip='10.9.9.1')
        device('loose-1', site, ip='10.9.9.2')
        conduit = Conduit.objects.create(name='A - B', site=site)
        conduit.zones.set([a, b])
        conduit.enforcing_devices.add(fw)
        self.assertEqual({f.message for f in run_checks(site=site, checks=['asset-without-zone'])},
                         {'loose-1 at Plant is in no zone'})

    def test_a_site_without_zones_says_where_to_start(self):
        site = Site.objects.create(name='New plant', slug='new-plant')
        device('plc-1', site, ip='10.9.9.10')
        device('patch-panel', site)  # no address, no level: not counted
        # The checks of that site already list its networked devices
        self.assertEqual({f.message for f in run_checks(site=site)}, {'plc-1 at New plant is in no zone'})
        overview = build_overview(site)
        self.assertEqual(overview['start']['assets'], 1)
        self.assertIn(f'site={site.pk}', overview['start']['zone_add_url'])
        Zone.objects.create(name='Cell', slug='cell', site=site, purdue_level='1')
        self.assertIsNone(build_overview(site)['start'])


@override_settings(EXEMPT_VIEW_PERMISSIONS=[])
class PagesTest(NetBoxTestCase):
    user_permissions = ('netbox_ot.view_flow', 'netbox_ot.view_zone', 'dcim.view_site', 'dcim.view_device')

    @classmethod
    def setUpTestData(cls):
        cls.site = Site.objects.create(name='Plant', slug='plant')
        cls.office = Zone.objects.create(name='Office', slug='office', site=cls.site, purdue_level='4')
        cls.cell = Zone.objects.create(name='Cell', slug='cell', site=cls.site, purdue_level='1')
        cls.plc = device('plc-1', cls.site, ip='10.1.1.10')
        cls.other = device('plc-2', cls.site, ip='10.1.1.11')
        cls.cell.devices.add(cls.plc, cls.other)
        Flow.objects.create(name='reads plc-1', source_zone=cls.office, destination_zone=cls.cell,
                            evidence='Passively seen: 3 request(s)\nRequest: 10.2.2.5 -> 10.1.1.10 tcp/102 s7comm '
                                     'Read Variable x3 [read]')
        Flow.objects.create(name='reads plc-2', source_zone=cls.office, destination_zone=cls.cell,
                            evidence='Request: 10.2.2.5 -> 10.1.1.11 tcp/102 s7comm Read Variable x3 [read]\n'
                                     'Request: 10.2.2.5 -> 110.1.1.10 tcp/80 http x1 []')
        Flow.objects.create(name='to the office', source_zone=cls.cell, destination_zone=cls.office)

    def test_device_panel_lists_the_flows_it_was_seen_in(self):
        response = self.client.get(self.plc.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn('Flows it was seen in', content)
        self.assertIn('reads plc-1', content)
        self.assertNotIn('reads plc-2', content)  # 110.1.1.10 is not 10.1.1.10
        self.assertIn('All 3 flows of these zones', content)

    def test_access_map_badge_counts_the_table(self):
        response = self.client.get(reverse('dcim:site', kwargs={'pk': self.site.pk}))
        content = response.content.decode()
        self.assertEqual(response.status_code, 200)
        # Two flows go into the level-1 cell; the one into the office is not on the access map
        url = reverse('dcim:site_ot_accessmap', kwargs={'pk': self.site.pk})
        tab = content[content.index(url):][:400]
        self.assertIn('>2<', tab.replace(' ', '').replace('\n', ''))

    def test_overview_of_a_site_without_zones(self):
        site = Site.objects.create(name='New plant', slug='new-plant')
        device('plc-9', site, ip='10.9.9.10')
        response = self.client.get(reverse('dcim:site_ot_overview', kwargs={'pk': site.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertIn('Where to start', response.content.decode())
        self.assertIn('--suggest-zone-map', response.content.decode())
