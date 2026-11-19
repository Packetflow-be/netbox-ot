import csv
import io
import json
from unittest import skipUnless

from django.apps import apps
from django.urls import reverse

from dcim.models import (
    Cable,
    Device,
    DeviceRole,
    DeviceType,
    Interface,
    Location,
    Manufacturer,
    Module,
    ModuleBay,
    ModuleType,
    Site,
)
from extras.models import Tag
from ipam.models import IPAddress
from utilities.testing import APITestCase, TestCase

from netbox_ot.machine import Scope, build_machine, home_zone, machine_csv, machine_json
from netbox_ot.machinediagram import machine_diagram
from netbox_ot.models import Flow, Zone


def build_plant():
    """
    Machine M3200 in location Line 1 / M3200 of site Plant, every device tagged m3200: a switch, a PLC with an I/O
    module, an HMI, two drives and a 4G router, in three zones. The switch's uplink goes to the core switch in
    another location; the PLC's address is NATed 1:1. Flows: SCADA reads the PLC, SCADA to the HMI (not allowed),
    the PLC reports to the MES by reverse connect, the supplier comes in over the 4G router (no decision yet),
    and the HMI talks to the PLC (inside the machine).
    """
    site = Site.objects.create(name='Plant', slug='plant')
    line = Location.objects.create(name='Line 1', slug='line-1', site=site)
    machine = Location.objects.create(name='M3200', slug='m3200', site=site, parent=line)
    core_room = Location.objects.create(name='Core room', slug='core-room', site=site)
    tag = Tag.objects.create(name='M3200', slug='m3200')
    siemens = Manufacturer.objects.create(name='Siemens', slug='siemens')
    cisco = Manufacturer.objects.create(name='Cisco', slug='cisco')
    insys = Manufacturer.objects.create(name='Insys', slug='insys')

    def dtype(manufacturer, model):
        return DeviceType.objects.create(manufacturer=manufacturer, model=model, slug=model.lower().replace(' ', '-'))

    def role(name, color):
        return DeviceRole.objects.create(name=name, slug=name.lower(), color=color)

    switch_role, plc_role, hmi_role = role('Switch', '2196f3'), role('PLC', 'f44336'), role('HMI', 'ff9800')
    drive_role, router_role = role('Drive', '9c27b0'), role('Router', '607d8b')

    def device(name, devtype, devrole, location, ports, tagged=True, **kwargs):
        d = Device.objects.create(name=name, device_type=devtype, role=devrole, site=site, location=location,
                                  **kwargs)
        for port in ports:
            Interface.objects.create(device=d, name=port, type='1000base-t')
        if tagged:
            d.tags.add(tag)
        return d

    sw = device('sw-m3200', dtype(siemens, 'SCALANCE XC208'), switch_role, machine,
                [f'P{n}' for n in range(1, 9)])
    plc = device('plc-m3200', dtype(siemens, 'S7-1516-3 PN/DP'), plc_role, machine, ['X1 P1'], serial='S C-X4U12345',
                 custom_field_data={'ot_firmware_version': 'V2.9.4'})
    hmi = device('hmi-m3200', dtype(siemens, 'TP1500 Comfort'), hmi_role, machine, ['eth0'])
    drive_type = dtype(siemens, 'G120')
    drv1 = device('drv-m3200-1', drive_type, drive_role, machine, ['X150 P1'])
    drv2 = device('drv-m3200-2', drive_type, drive_role, machine, ['X150 P1'])
    rtr = device('rtr-m3200', dtype(insys, 'MRX5 LTE'), router_role, machine, ['lan1', 'wwan'])
    core = device('core-sw01', dtype(cisco, 'C9300-24T'), switch_role, core_room, ['GigabitEthernet1/0/1'],
                  tagged=False)
    bay = ModuleBay.objects.create(device=plc, name='Slot 2')
    Module.objects.create(device=plc, module_bay=bay, serial='M-001',
                          module_type=ModuleType.objects.create(manufacturer=siemens, model='SM 1231 AI'),
                          custom_field_data={'ot_firmware_version': 'V1.0.1'})

    def port(dev, name):
        return Interface.objects.get(device=dev, name=name)

    def cable(a, b, **kwargs):
        c = Cable(a_terminations=[a], b_terminations=[b], **kwargs)
        c.save()
        return c

    for n, (dev, name) in enumerate(((plc, 'X1 P1'), (hmi, 'eth0'), (drv1, 'X150 P1'), (drv2, 'X150 P1'),
                                     (rtr, 'lan1')), start=1):
        cable(port(sw, f'P{n}'), port(dev, name))
    uplink = cable(port(sw, 'P8'), port(core, 'GigabitEthernet1/0/1'), label='UPLINK-1', color='ffeb3b')

    def ip(dev, name, address, primary=True):
        address = IPAddress.objects.create(address=address, assigned_object=port(dev, name))
        if primary:
            dev.primary_ip4 = address
            dev.save()
        return address

    plc_ip = ip(plc, 'X1 P1', '192.168.32.10/24')
    IPAddress.objects.create(address='10.30.0.10/24', nat_inside=plc_ip)
    ip(hmi, 'eth0', '192.168.32.20/24')
    ip(sw, 'P1', '192.168.32.2/24')

    def zone(name, level, members, **kwargs):
        z = Zone.objects.create(name=name, slug=name.lower().replace(' ', '-'), site=kwargs.pop('site', site),
                                purdue_level=level, **kwargs)
        z.devices.set(members)
        return z

    control = zone('M3200 control', '1', [sw, plc, drv1, drv2], sl_target=[2, 2, 2, 1, 2, 1, 1])
    panel = zone('M3200 HMI', '2', [hmi])
    dmz = zone('M3200 remote', '3.5', [rtr], zone_type='dmz')
    scada = zone('Plant SCADA', '3', [core])
    mes = zone('Plant MES', '3', [])
    supplier = zone('Supplier', '5', [], zone_type='external', site=None)

    def flow(src, dst, name, **kwargs):
        return Flow.objects.create(source_zone=src, destination_zone=dst, name=name, **kwargs)

    flows = {
        'read': flow(scada, control, 'SCADA reads PLC', protocol='s7comm', port_mappings=['tcp/102'],
                     access=['read'], allowed='yes'),
        'vnc': flow(scada, panel, 'SCADA VNC to HMI', protocol='vnc', port_mappings=['tcp/5900'], allowed='no'),
        'mes': flow(control, mes, 'PLC to MES', protocol='opc-ua', port_mappings=['tcp/4840'],
                    connection='reverse-connect', allowed='yes'),
        'vendor': flow(supplier, dmz, 'Supplier VPN', protocol='openvpn', port_mappings=['udp/1194'],
                       remote_access=True),
        'inside': flow(panel, control, 'HMI to PLC', protocol='s7comm', port_mappings=['tcp/102'],
                       access=['write'], allowed='yes'),
    }
    return {
        'site': site, 'line': line, 'machine': machine, 'tag': tag, 'devices': (sw, plc, hmi, drv1, drv2, rtr),
        'core': core, 'uplink': uplink, 'zones': (control, panel, dmz, scada, mes, supplier), 'flows': flows,
    }


class MachinePlant(TestCase):
    user_permissions = (
        'dcim.view_device', 'dcim.view_site', 'dcim.view_location', 'dcim.view_cable', 'dcim.view_module',
        'ipam.view_ipaddress', 'netbox_ot.view_zone', 'netbox_ot.view_flow',
    )

    @classmethod
    def setUpTestData(cls):
        cls.plant = build_plant()

    def machine(self, **scope):
        return build_machine(Scope(**scope), self.user)


class MachineScopeTest(MachinePlant):

    def test_scopes(self):
        names = lambda m: sorted(d['name'] for d in m['devices'])  # noqa: E731
        six = sorted(d.name for d in self.plant['devices'])
        self.assertEqual(names(self.machine(location=self.plant['machine'])), six)
        # A location takes the locations below it; a tag crosses locations; all filters apply together
        self.assertEqual(names(self.machine(location=self.plant['line'])), six)
        self.assertEqual(names(self.machine(tags=[self.plant['tag']])), six)
        self.assertEqual(names(self.machine(site=self.plant['site'])), sorted(six + ['core-sw01']))
        self.assertEqual(names(self.machine(site=self.plant['site'], tags=[self.plant['tag']])), six)
        self.assertFalse(Scope())
        self.assertEqual(Scope(tags=[self.plant['tag']], version='rev C').slug, 'm3200-rev-C')

    def test_home_zone_prefers_sub_zone_then_lowest_level(self):
        control, panel = self.plant['zones'][:2]
        sub = Zone.objects.create(name='Drives', slug='drives', site=self.plant['site'], purdue_level='1',
                                  parent=control)
        self.assertEqual(home_zone([control, sub]), sub)
        self.assertEqual(home_zone([panel, control]), control)
        self.assertIsNone(home_zone([]))

    def test_devices_cables_nat_firmware(self):
        m = self.machine(location=self.plant['machine'])
        plc = next(d for d in m['devices'] if d['name'] == 'plc-m3200')
        self.assertEqual(plc['firmware'], 'V2.9.4')
        self.assertEqual(plc['primary']['address'], '192.168.32.10')
        self.assertEqual(plc['primary']['nat'], ['10.30.0.10'])
        self.assertEqual(plc['modules'][0]['firmware'], 'V1.0.1')
        self.assertEqual(plc['zone'].name, 'M3200 control')
        self.assertEqual(len(m['cables']), 6)
        uplink = next(c for c in m['cables'] if c['leaves'])
        self.assertEqual((uplink['a']['name'], uplink['a']['ports']), ('sw-m3200', 'P8'))
        self.assertEqual((uplink['b']['name'], uplink['b']['ports']), ('core-sw01', 'GigabitEthernet1/0/1'))
        # With the site as scope the core switch is inside and the uplink no longer leaves
        self.assertFalse(any(c['leaves'] for c in self.machine(site=self.plant['site'])['cables']))

    def test_boundary_flows_and_rules(self):
        m = self.machine(tags=[self.plant['tag']])
        self.assertEqual(sorted(f.name for f in m['flows']),
                         ['PLC to MES', 'SCADA VNC to HMI', 'SCADA reads PLC', 'Supplier VPN'])
        # The rules: allowed and denied, not the flow without a verdict; the reverse connect is opened by the MES
        actions = sorted((r['source_zone'], r['destination_zone'], r['action']) for r in m['rules'])
        self.assertEqual(actions, [('Plant MES', 'M3200 control', 'allow'), ('Plant SCADA', 'M3200 HMI', 'deny'),
                                   ('Plant SCADA', 'M3200 control', 'allow')])
        self.assertEqual(m['not_exported'], {'no verdict yet': 1})

    def test_restricted_user_sees_only_what_they_may(self):
        self.user.object_permissions.all().delete()
        self.user.user_permissions.clear()
        self.add_permissions('dcim.view_device')
        m = self.machine(location=self.plant['machine'])
        self.assertEqual(len(m['devices']), 6)
        self.assertEqual((m['cables'], m['flows'], m['zone_ids']), ([], [], []))
        self.assertIsNone(m['devices'][0]['zone'])

    def test_peer_not_visible(self):
        from core.models import ObjectType
        from users.models import ObjectPermission

        self.user.object_permissions.all().delete()
        self.user.user_permissions.clear()
        self.add_permissions('dcim.view_cable', 'dcim.view_module', 'ipam.view_ipaddress')
        perm = ObjectPermission.objects.create(name='machine only', actions=['view'],
                                               constraints={'location': self.plant['machine'].pk})
        perm.object_types.add(ObjectType.objects.get_for_model(Device))
        perm.users.add(self.user)
        m = self.machine(site=self.plant['site'])
        self.assertEqual(len(m['devices']), 6)
        uplink = next(c for c in m['cables'] if c['leaves'])
        self.assertEqual((uplink['b']['name'], uplink['b']['ports']), ('Not visible', ''))


class MachineDiagramTest(MachinePlant):

    def test_diagram(self):
        m = self.machine(tags=[self.plant['tag']], version='type 3200 rev C')
        d = machine_diagram(m)
        self.assertEqual((d['frames'], d['devices'], d['cables'], d['flows']), (3, 6, 6, 4))
        svg = str(d['svg'])
        for text in ('M3200 control', 'plc-m3200', '192.168.32.10 ⇄ 10.30.0.10', 'FW V2.9.4', 'core-sw01',
                     'S7comm TCP/102', 'OpenVPN UDP/1194 · remote', 'Plant MES', 'Supplier', 'type 3200 rev C',
                     'UPLINK-1', 'SL-T 2,2,2,1,2,1,1', '#ffeb3b'):
            self.assertIn(text, svg)
        # The flow inside the machine is not drawn
        self.assertNotIn('HMI to PLC', svg)
        # Remote access dashed, reverse connect dotted
        self.assertIn('stroke-dasharray="6 4"', svg)
        self.assertIn('stroke-dasharray="2 4"', svg)

    def test_frames_from_the_top_level_down(self):
        svg = str(machine_diagram(self.machine(tags=[self.plant['tag']]))['svg'])
        self.assertLess(svg.index('M3200 remote'), svg.index('M3200 HMI'))
        self.assertLess(svg.index('M3200 HMI'), svg.index('M3200 control'))

    def test_empty(self):
        tag = Tag.objects.create(name='Empty', slug='empty')
        self.assertEqual(machine_diagram(self.machine(tags=[tag]))['svg'], '')

    def test_device_without_zone_and_many_devices(self):
        site = self.plant['site']
        dtype = DeviceType.objects.first()
        role = DeviceRole.objects.first()
        for n in range(9):
            Device.objects.create(name=f'io-{n}', device_type=dtype, role=role, site=site,
                                  location=self.plant['machine'])
        d = machine_diagram(self.machine(location=self.plant['machine']))
        self.assertEqual(d['frames'], 4)
        svg = str(d['svg'])
        # Devices without a zone (usually IT equipment) on top, then the zones from the highest level down
        self.assertLess(svg.index('Not in a zone'), svg.index('M3200 remote'))


class MachineExportTest(MachinePlant):

    def test_csv_and_json(self):
        m = self.machine(location=self.plant['machine'], version='rev C')
        devices = list(csv.DictReader(io.StringIO(machine_csv(m, 'devices'))))
        plc = next(r for r in devices if r['device'] == 'plc-m3200')
        self.assertEqual(plc['addresses'], 'X1 P1 192.168.32.10 (NAT 10.30.0.10)')
        self.assertEqual(plc['modules'], 'Slot 2: SM 1231 AI S/N M-001 FW V1.0.1')
        cables = list(csv.DictReader(io.StringIO(machine_csv(m, 'cables'))))
        self.assertEqual([r['leaves_machine'] for r in cables].count('yes'), 1)
        rules = list(csv.DictReader(io.StringIO(machine_csv(m, 'connections'))))
        self.assertEqual(len(rules), 3)
        data = json.loads(json.dumps(machine_json(m)))
        self.assertEqual(data['scope']['version'], 'rev C')
        self.assertEqual(len(data['flows']), 4)
        self.assertEqual({f['direction'] for f in data['flows']}, {'in', 'out'})
        self.assertEqual(data['access_paths'], [] if apps.is_installed('netbox_access_paths') else None)


class MachineViewTest(MachinePlant):

    def setUp(self):
        super().setUp()
        self.add_permissions('extras.view_tag')

    def test_standalone_view(self):
        url = reverse('plugins:netbox_ot:machine_drawing')
        response = self.client.get(url)
        self.assertHttpStatus(response, 200)
        self.assertContains(response, 'Choose a site, a location or one or more tags')
        response = self.client.get(url, {'tag': 'm3200', 'version': 'rev C'})
        self.assertHttpStatus(response, 200)
        self.assertContains(response, 'class="md-map"')
        self.assertContains(response, 'Connections to and from the outside')
        response = self.client.get(url, {'location_id': self.plant['machine'].pk, 'export': 'svg'})
        self.assertEqual(response['Content-Type'], 'image/svg+xml')
        self.assertTrue(response.content.startswith(b'<?xml'))
        response = self.client.get(url, {'location_id': self.plant['machine'].pk, 'export': 'devices'})
        self.assertIn(b'plc-m3200', response.content)
        self.assertIn('m3200-machine-devices.csv', response['Content-Disposition'])
        expected = 200 if apps.is_installed('netbox_access_paths') else 404
        self.assertHttpStatus(self.client.get(url, {'tag': 'm3200', 'export': 'access-paths'}), expected)

    def test_location_tab(self):
        url = reverse('dcim:location_ot_machine', kwargs={'pk': self.plant['machine'].pk})
        response = self.client.get(url, {'version': 'rev C'})
        self.assertHttpStatus(response, 200)
        self.assertContains(response, 'plc-m3200')
        self.assertContains(response, 'rev C')
        response = self.client.get(url, {'export': 'cables'})
        self.assertIn(b'UPLINK-1', response.content)
        # The tab is on the location page; hidden on a location without devices
        page = self.client.get(self.plant['machine'].get_absolute_url())
        self.assertContains(page, url)
        empty = Location.objects.create(name='Spare', slug='spare', site=self.plant['site'])
        empty_tab = reverse('dcim:location_ot_machine', kwargs={'pk': empty.pk})
        self.assertNotContains(self.client.get(empty.get_absolute_url()), empty_tab)

    def test_needs_view_device(self):
        self.user.object_permissions.all().delete()
        self.assertHttpStatus(self.client.get(reverse('plugins:netbox_ot:machine_drawing')), 403)


class MachineAPITest(APITestCase):

    @classmethod
    def setUpTestData(cls):
        cls.plant = build_plant()

    def test_api(self):
        self.add_permissions(*MachinePlant.user_permissions)
        url = reverse('plugins-api:netbox_ot-api:machine_drawing')
        response = self.client.get(url, {'tag': 'm3200'}, **self.header)
        self.assertHttpStatus(response, 200)
        self.assertEqual(len(response.json()['devices']), 6)
        self.assertHttpStatus(self.client.get(url, **self.header), 400)
        self.assertHttpStatus(self.client.get(url, {'tag': 'nope'}, **self.header), 400)
        self.assertHttpStatus(self.client.get(url, {'location_id': 'x'}, **self.header), 400)


@skipUnless(apps.is_installed('netbox_access_paths'), 'netbox-access-paths is not installed')
class MachineAccessPathsTest(MachinePlant):

    def test_access_paths(self):
        from netbox_access_paths.models import AccessPath, AccessRoute

        from tenancy.models import Tenant

        self.add_permissions('netbox_access_paths.view_accesspath')
        tenant = Tenant.objects.create(name='Customer', slug='customer')
        route = AccessRoute.objects.create(name='Office', origin='ztna')
        hmi = self.plant['devices'][2]
        AccessPath.objects.create(tenant=tenant, route=route, method='web', target=hmi)
        AccessPath.objects.create(tenant=tenant, route=route, method='ssh', target=self.plant['core'])
        m = self.machine(location=self.plant['machine'])
        self.assertEqual([p['target'] for p in m['access_paths']], ['hmi-m3200'])
        self.assertIn('hmi-m3200', machine_csv(m, 'access-paths'))
