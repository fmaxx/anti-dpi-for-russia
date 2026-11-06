import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'macos/app'))

import app_paths
import darwin_session
import dependencies
import desktop_integration
import igareck


class CatalogueTests(unittest.TestCase):
    def test_engine_arguments_preserve_every_recipe(self):
        for row in igareck.load_catalogue()['ProfileRows']:
            args = igareck.engine_arguments(Path('/opt/igareck-antidpi'), row, scope='80,443,1000-2000')
            self.assertEqual(args[0], '/opt/igareck-antidpi/engine/macws2')
            self.assertIn('--port=1', args)
            self.assertIn('--filter-tcp=80,443,1000-2000', args)
            self.assertNotIn('--qnum=20000', args)
            self.assertNotIn('--fwmark=0x20000000', args)
            self.assertEqual(args[-len(row['Args']):], row['Args'])

    def test_ports_are_merged(self):
        self.assertEqual(igareck.parse_ports('443,80,1000-2000,80-81'), '80-81,443,1000-2000')
        self.assertEqual(igareck.parse_ports('все'), 'all')


class NetworkTests(unittest.TestCase):
    FIXTURE = '''en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
        ether 11:22:33:44:55:66
        status: inactive
en1: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
        ether aa:bb:cc:dd:ee:ff
        inet 192.168.2.68 netmask 0xffffff00
        status: active
utun4: flags=8051<UP,POINTOPOINT,RUNNING> mtu 1280
        inet 100.1.2.3 --> 100.1.2.3 netmask 0xffffffff
'''

    def test_ifconfig_parser(self):
        items = darwin_session.parse_ifconfig(self.FIXTURE)
        en1 = next(item for item in items if item['name'] == 'en1')
        self.assertEqual(en1['addresses'], ['192.168.2.68'])
        self.assertEqual(en1['mac'], 'aa:bb:cc:dd:ee:ff')
        self.assertTrue(en1['active'])
        self.assertEqual(en1['mtu'], 1500)

    def test_interfaces_exclude_tunnels_and_inactive(self):
        with patch.object(darwin_session, 'run', return_value=Mock(returncode=0, stdout=self.FIXTURE)):
            self.assertEqual([item['name'] for item in darwin_session.interfaces()], ['en1'])

    def test_physical_default_route_is_selected(self):
        output = 'default 198.18.0.1 UGScg utun4\ndefault 192.168.2.1 UGScIg en1\n'
        items = [{'name': 'en1'}]
        with patch.object(darwin_session, 'run', return_value=Mock(returncode=0, stdout=output)):
            self.assertEqual(darwin_session.default_interface(items), 'en1')

    def test_pf_rules_have_isolated_drop_and_observed_inbound(self):
        rules = darwin_session.pf_rules('com.apple/igareck_0123456789ab', 'en1', [
            {'pflog': 'pflog9', 'ports': (10000, 10063)}], ['0.0.0.0/8', '10.0.0.0/8'], '80,443')
        self.assertIn('block out log (all, to pflog9) quick on en1', rules)
        self.assertIn('from any port { 10000:10063 }', rules)
        self.assertIn('port { 80, 443 }', rules)
        self.assertIn('pass in log (all, to pflog9) on en1', rules)
        self.assertNotIn('pass in log (all, to pflog9) quick', rules)
        self.assertIn('flags S/SA no state', rules)
        if sys.platform == 'darwin':
            with tempfile.NamedTemporaryFile('w', suffix='.conf') as config:
                config.write(rules)
                config.flush()
                checked = subprocess.run(['/sbin/pfctl', '-n', '-a', 'com.apple/igareck_0123456789ab',
                                          '-f', config.name], capture_output=True, text=True, timeout=20)
                self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_pf_rejects_unowned_names(self):
        with self.assertRaises(ValueError):
            darwin_session.pf_rules('other', 'en1', [], ['10.0.0.0/8'])
        with self.assertRaises(ValueError):
            darwin_session.pf_rules('com.apple/igareck_0123456789ab', 'en1', [{'pflog': 'pflog0'}], ['10.0.0.0/8'])


class ResourceTests(unittest.TestCase):
    def test_every_resource_exists(self):
        for name in app_paths.FILE_LAYOUT:
            self.assertTrue(app_paths.resource_path(REPO / 'macos/app', name).is_file(), name)

    def test_release_metadata(self):
        release = json.loads((REPO / 'macos/data/release.json').read_text())
        self.assertEqual(release['version'], '1.0')
        self.assertEqual(release['minimum_macos'], '26')
        self.assertEqual(release['recipes'], 484)

    def test_source_cli_without_installation(self):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        for arguments in (['--help'], ['show', '--strategy', '25']):
            result = subprocess.run(['bash', str(REPO / 'macos/START.sh'), *arguments],
                                    env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_shortcut_has_owned_marker_and_absolute_path(self):
        data = desktop_integration.launcher_bytes(Path('/opt/igareck-antidpi'), 'a' * 32, 'start')
        self.assertIn(b'igareck-macos-shortcut-v1', data)
        self.assertIn(b'/opt/igareck-antidpi/START.sh', data)

    def test_ready_dependencies_do_not_invoke_brew(self):
        with patch.object(dependencies, 'missing_dependencies', return_value=[]), \
             patch.object(dependencies.subprocess, 'run') as run:
            dependencies.ensure_dependencies()
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
