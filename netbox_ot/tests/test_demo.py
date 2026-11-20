from io import StringIO
from unittest import skipIf

from django.apps import apps
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from dcim.models import Device, Site
from ipam.models import IPAddress, Prefix
from tenancy.models import Contact

from netbox_ot.checks import run_checks
from netbox_ot.models import Conduit, Flow, FlowHop, IndustrialService, RiskAssessment, Zone


class DemoCommandTest(TestCase):

    @skipIf(apps.is_installed('netbox_branching'), 'netbox-branching is installed')
    def test_branch_needs_netbox_branching(self):
        for command in ('ot_demo', 'ot_check', 'ot_rules'):
            with self.assertRaisesRegex(CommandError, 'netbox-branching'):
                call_command(command, '--branch', 'demo', stdout=StringIO(), stderr=StringIO())
        self.assertFalse(Site.objects.filter(slug='iec62443-demo').exists())

    def test_create_and_delete(self):
        call_command('ot_demo', stdout=StringIO())
        site = Site.objects.get(slug='iec62443-demo')
        self.assertEqual(Zone.objects.count(), 8)
        self.assertEqual(Conduit.objects.count(), 6)
        self.assertEqual(Flow.objects.count(), 15)
        remote = Flow.objects.get(name='MSP maintenance RDP')
        self.assertEqual([str(h.hop) for h in remote.hops.all()],
                         ['IEC 62443 demo MSP IPsec', 'demo-jump-1', 'demo-fw-1'])
        self.assertTrue(IndustrialService.objects.filter(service__isnull=False).exists())
        self.assertEqual(RiskAssessment.objects.count(), 4)
        # Firmware versions on the controllers, panel, gateway and firewall; none where nobody recorded one
        firmware = {d.name: d.custom_field_data.get('ot_firmware_version')
                    for d in Device.objects.filter(name__startswith='demo-')}
        self.assertEqual(firmware['demo-plc-1'], 'V2.8.3')
        self.assertEqual(firmware['demo-plc-2'], 'V2.6.0')
        self.assertEqual(sum(1 for v in firmware.values() if v), 6)
        self.assertIsNone(firmware['demo-unzoned-camera'])
        # The demo shows the checks at work, errors included
        found = {f.check for f in run_checks(site=site)}
        self.assertTrue({'expired-access', 'residual-above-tolerable', 'asset-without-zone', 'sl-gap',
                         'capability-below-target', 'flow-without-conduit'} <= found)
        self.assertNotIn('asset-below-zone-level', found)
        # The cabled network: a switch per zone (in its zone), line 1 as a location, a NATed gateway
        from dcim.models import Cable, Location

        from netbox_ot.machine import Scope, build_machine
        from netbox_ot.machinediagram import machine_diagram

        self.assertEqual(Cable.objects.count(), 13)
        sw1 = Device.objects.get(name='demo01be1-sw001')
        self.assertEqual({(i.mode, i.untagged_vlan.vid) for i in sw1.interfaces.all()}, {('access', 101)})
        self.assertEqual(Prefix.objects.get(prefix='10.61.35.0/24').vlan.vid, 135)
        for name, zone in (('demo01be1-sw001', 'Line 1 cell'), ('demo01be1-sw002', 'Control room'),
                           ('demo01be1-sw003', 'OT DMZ'), ('demo01be1-sw004', 'Office')):
            self.assertEqual([z.name for z in Device.objects.get(name=name).ot_zones.all()], [zone])
        line1 = Location.objects.get(site=site, slug='line-1')
        from django.contrib.auth import get_user_model
        admin = get_user_model().objects.create_superuser('demo-admin', 'demo@example.invalid', 'x')
        machine = build_machine(Scope(location=line1), admin)
        self.assertEqual(len(machine['devices']), 6)
        self.assertEqual([c['b']['name'] for c in machine['cables'] if c['leaves']], ['demo-fw-1'])
        gateway = next(d for d in machine['devices'] if d['name'] == 'demo-gw-1')
        self.assertEqual(gateway['primary']['nat'], ['10.61.35.120'])
        self.assertTrue(machine['flows'])
        self.assertEqual(machine_diagram(machine)['frames'], 3)  # no zone, the cell, its safety sub-zone
        # Monitoring: the proxy in its own zone on its own firewall port, the line's monitoring flows on the drawing
        # (polled from the proxy, traps and agent data out to it), the NOC reached over one outbound flow
        proxy = Device.objects.get(name='demo-mon-1')
        self.assertEqual([z.name for z in proxy.ot_zones.all()], ['OT monitoring'])
        self.assertEqual([str(i.link_peers[0].device) for i in proxy.interfaces.all()], ['demo-fw-1'])
        line_monitoring = {(f.source_zone.name, f.destination_zone.name, f.protocol, tuple(f.port_mappings))
                           for f in machine['flows'] if 'OT monitoring' in (f.source_zone.name,
                                                                            f.destination_zone.name)}
        self.assertEqual(line_monitoring, {('OT monitoring', 'Line 1 cell', 'snmp', ('udp/161',)),
                                           ('Line 1 cell', 'OT monitoring', 'snmp', ('udp/162',)),
                                           ('Line 1 cell', 'OT monitoring', 'https', ('tcp/443',))})
        to_noc = Flow.objects.get(name='Monitoring proxy to the NOC')
        self.assertEqual((to_noc.destination_zone.name, to_noc.allowed, to_noc.conduit.name),
                         ('IEC 62443 demo NOC', 'yes', 'Remote monitoring'))
        self.assertFalse(Flow.objects.filter(source_zone__name='IEC 62443 demo NOC').exists())
        self.assertEqual([str(h.hop) for h in to_noc.hops.all()], ['demo-fw-1'])
        with self.assertRaisesRegex(CommandError, 'already exists'):
            call_command('ot_demo', stdout=StringIO())

        call_command('ot_demo', '--delete', stdout=StringIO())
        self.assertFalse(Site.objects.filter(slug='iec62443-demo').exists())
        for model in (Zone, Conduit, Flow, FlowHop, IndustrialService, RiskAssessment):
            self.assertEqual(model.objects.count(), 0, model)
        self.assertFalse(Device.objects.filter(name__startswith='demo').exists())
        self.assertFalse(Cable.objects.exists())
        self.assertFalse(Location.objects.filter(slug='line-1').exists())
        from ipam.models import VLAN
        self.assertFalse(VLAN.objects.filter(description__startswith='IEC 62443 demo').exists())
        self.assertFalse(IPAddress.objects.filter(description='IEC 62443 demo').exists())
        self.assertFalse(Prefix.objects.filter(description__startswith='IEC 62443 demo').exists())
        self.assertFalse(Contact.objects.filter(description='IEC 62443 demo').exists())
        call_command('ot_demo', stdout=StringIO())  # and again

    def test_capture_create_and_delete(self):
        from dcim.models import DeviceRole

        from netbox_ot import demo_capture

        out = StringIO()
        call_command('ot_demo', '--capture', stdout=out)
        self.assertIn('Capture demo created', out.getvalue())
        site = Site.objects.get(slug=demo_capture.SITE_SLUG)
        # The credit travels with the data: on the site itself and in the NOTICE next to the files
        self.assertIn('Apache License 2.0', site.comments)
        self.assertIn('DFRWS', site.comments)
        self.assertTrue((demo_capture.DATA / 'NOTICE.md').exists())
        # One controller at level 1, three stations at level 2, each with its address as primary IP
        devices = Device.objects.filter(site=site)
        self.assertEqual(devices.count(), 4)
        self.assertTrue(all(d.primary_ip4 for d in devices))
        self.assertEqual(devices.filter(role__slug='capture-demo-plc').count(), 1)
        # Split like ot_import --split-all: controller and stations in zones of their own, so the stations' requests
        # to the PLC are a flow on the access map
        self.assertLessEqual({'Elevator cell (control)', 'Elevator cell (supervisory)'},
                             {z.name for z in Zone.objects.filter(site=site)})
        # Their Schneider UMAS programming requests (Modbus FC 90) are in no table: unclassified, so the exposure
        # rules fail closed and the flow is an undecided flow into control
        into_plc = Flow.objects.get(source_zone__name='Elevator cell (supervisory)',
                                    destination_zone__name='Elevator cell (control)', protocol='modbus-tcp')
        self.assertEqual(into_plc.access, ['unclassified'])
        self.assertIn('PROGRAM_UNITY', into_plc.evidence)
        self.assertIn('undecided-into-control', {f.check for f in run_checks(site=site)})
        with self.assertRaisesRegex(CommandError, 'already exists'):
            call_command('ot_demo', '--capture', stdout=StringIO())
        with self.assertRaisesRegex(CommandError, 'one at a time'):
            call_command('ot_demo', '--capture', '--large', stdout=StringIO())

        call_command('ot_demo', '--capture', '--delete', stdout=StringIO())
        self.assertFalse(Site.objects.filter(slug=demo_capture.SITE_SLUG).exists())
        for model in (Zone, Conduit, Flow, IndustrialService):
            self.assertEqual(model.objects.count(), 0, model)
        self.assertFalse(Device.objects.filter(name__startswith='elevator-').exists())
        self.assertFalse(IPAddress.objects.filter(description=demo_capture.PREFIX).exists())
        self.assertFalse(DeviceRole.objects.filter(slug__startswith='capture-demo-').exists())
        call_command('ot_demo', '--capture', stdout=StringIO())  # and again
