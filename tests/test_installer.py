"""Offline regressions for irreversible boundaries; no privileged host mutations."""
from dataclasses import replace
import hashlib
import getpass
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import unittest
import warnings
from unittest.mock import Mock, patch
import urllib.error

from installer import credentials, firewall, host, recovery
from installer.cloudflare import Cloudflare, NoRedirect
from installer.common import SetupError, atomic_write, hidden, read_private, run, write_json
from installer.ledger import Ledger
from installer.model import Paths, Plan, profile_text
from installer.storage import Storage

PLAN = Plan('a' * 32, 'client-test-bucket', 'eth0', '192.168.50.2', '192.168.50.0/24')
MATERIAL = {'crypt_password': 'crypt-password-' + 'x' * 32, 'crypt_salt': 'salt-' + 'y' * 32,
            'smb_password': 'client-test-password'}
S3 = {'access_key_id': 'b' * 32, 'secret_access_key': 'c' * 64}


class Workspace(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.paths = Paths(base=root / 'base', storage=root / 'encrypted', udev=root / 'udev.rules')
        for path in (self.paths.base, self.paths.storage, self.paths.recovery, self.paths.state):
            path.mkdir(mode=0o700)
        self.ledger = Ledger.create(self.paths.ledger, PLAN)

    def tearDown(self):
        self.temp.cleanup()


class InputTests(Workspace):
    def test_hidden_prompts_never_fall_back_to_echoed_input(self):
        def fallback(*args):
            warnings.warn('Echo control unavailable', getpass.GetPassWarning)
            self.fail('An echoed input prompt would have been reached')

        with patch('builtins.open'), patch('installer.common.os.isatty', return_value=True), \
             patch('installer.common.getpass.getpass', side_effect=fallback), self.assertRaises(SetupError):
            hidden('Test password')

    def test_public_network_and_injection_are_refused(self):
        for changes in ({'network': '0.0.0.0/0'}, {'address': '8.8.8.8'}, {'interface': 'eth0\naccept'},
                        {'size_gib': True}, {'bucket': '../other'}, {'network': '192.168.50.1/24'}):
            with self.subTest(changes=changes), self.assertRaises((SetupError, ValueError)):
                replace(PLAN, **changes).validate()
        text = tomllib.loads(profile_text(PLAN, 'd' * 32, self.paths))
        self.assertEqual(text['listen_address'], PLAN.address)
        self.assertEqual(text['encryption']['key_id'], 'd' * 32)

    def test_private_files_refuse_links_and_no_overwrite(self):
        original = self.paths.base / 'input'
        atomic_write(original, b'keep-this')
        with self.assertRaises(SetupError):
            atomic_write(original, b'overwrite')
        link = self.paths.base / 'link'
        link.symlink_to(original)
        with self.assertRaises(SetupError):
            read_private(link)
        link.unlink()
        os.link(original, link)
        with self.assertRaises(SetupError):
            read_private(original)
        self.assertEqual(original.read_bytes(), b'keep-this')

    def test_child_diagnostics_do_not_disclose_secrets(self):
        secret = 'never-include-this-password'
        with self.assertRaises(SetupError) as result:
            run(['python3', '-c', 'import sys; print(sys.stdin.read(), file=sys.stderr); sys.exit(7)'],
                data=secret.encode())
        self.assertNotIn(secret, str(result.exception))

    def test_unrecognized_installation_never_replaced(self):
        with self.assertRaises(SetupError), patch('installer.host.run') as command:
            host.fresh(self.paths)
        command.assert_not_called()


class ApiTests(unittest.TestCase):
    def test_account_scoping_permissions_and_s3_derivation(self):
        requests = []

        def transport(request, timeout):
            requests.append(request)
            if '/permission_groups?' in request.full_url:
                from urllib.parse import parse_qs, urlsplit
                name = parse_qs(urlsplit(request.full_url).query)['name'][0]
                result = [{'name': name, 'id': '1' * 32, 'scopes': ['com.cloudflare.edge.r2.bucket'], 'is_selectable': True}]
            else:
                result = {'id': '2' * 32, 'value': 'z' * 40}
            return io.BytesIO(json.dumps({'success': True, 'result': result}).encode())

        api = Cloudflare(PLAN.account_id, 'bootstrap-secret', transport)
        groups = api.permission_groups()
        result = api.create_object_token(PLAN.bucket, 'gateway-test', groups)
        policy = json.loads(requests[-1].data)['policies']
        self.assertEqual(policy, [{'effect': 'allow', 'permission_groups': groups,
                                  'resources': {f'com.cloudflare.edge.r2.bucket.{PLAN.account_id}_default_{PLAN.bucket}': '*'}}])
        self.assertEqual(result['access_key_id'], '2' * 32)
        self.assertEqual(result['secret_access_key'], hashlib.sha256(b'z' * 40).hexdigest())
        with self.assertRaises(SetupError):
            api.request('GET', '/accounts/' + '9' * 32 + '/tokens')
        api.forget()
        self.assertEqual(api._token, '')

    def test_public_access_and_unselectable_groups_are_refused(self):
        api = Cloudflare(PLAN.account_id, 'test-token')
        with patch.object(api, 'request', side_effect=[{'enabled': True}, {'domains': []}]):
            with self.assertRaises(SetupError):
                api.check_private(PLAN.bucket)
        with patch.object(api, 'request', return_value=[{'name': 'Workers R2 Storage Bucket Item Read',
                  'id': '1' * 32, 'scopes': ['com.cloudflare.edge.r2.bucket'], 'is_selectable': False}]):
            with self.assertRaises(SetupError):
                api.permission_groups()

    def test_http_body_and_redirect_cannot_leak_token(self):
        error = urllib.error.HTTPError('https://api.cloudflare.com', 403, 'secret-in-message', {}, io.BytesIO(b'secret-in-body'))
        api = Cloudflare(PLAN.account_id, 'test-token', Mock(side_effect=error))
        with self.assertRaises(SetupError) as result:
            api.bucket(PLAN.bucket)
        self.assertNotIn('secret', str(result.exception))
        with self.assertRaises(SetupError):
            NoRedirect().redirect_request(None, None, 302, '', {}, 'https://example.invalid')


class CredentialRecoveryTests(Workspace):
    def setUp(self):
        super().setUp()
        write_json(self.paths.recovery / 'material.json', MATERIAL)

    def test_ambiguous_token_creation_is_never_retried(self):
        api = Mock()
        api.bucket.return_value = None
        api.create_object_token.side_effect = SetupError('Lost HTTP response')
        factory = Mock(return_value=api)
        with patch('installer.credentials.hidden', return_value='bootstrap'), self.assertRaises(SetupError):
            credentials.obtain(self.paths, self.ledger, factory=factory)
        self.assertTrue(Ledger.load(self.paths.ledger).get('token_requested'))
        with self.assertRaises(SetupError):
            credentials.obtain(self.paths, Ledger.load(self.paths.ledger), factory=factory)
        api.create_object_token.assert_called_once()
        factory.assert_called_once()
        self.assertEqual(json.loads(read_private(self.paths.recovery / 'material.json')), MATERIAL)
        self.assertNotIn('bootstrap', self.paths.ledger.read_text())

    def test_credentials_saved_before_journal_completion_are_reused(self):
        write_json(self.paths.recovery / 'material.json', {**MATERIAL, **S3}, replace=True)
        self.ledger.set(token_requested=True)
        factory = Mock()
        result = credentials.obtain(self.paths, self.ledger, factory=factory)
        factory.assert_not_called()
        self.assertEqual(result, {**MATERIAL, **S3})

    def test_missing_recorded_keys_never_regenerate(self):
        (self.paths.recovery / 'material.json').unlink()
        self.ledger.set(keys_saved=True)
        with patch('installer.credentials.hidden') as prompt, self.assertRaises(SetupError):
            credentials.obtain(self.paths, self.ledger)
        prompt.assert_not_called()

    def test_manual_token_recovery_preserves_crypt_keys(self):
        self.ledger.set(token_requested=True, token_name='known-ambiguous-token')
        with patch('installer.credentials.confirm') as confirm, patch('installer.credentials.hidden', side_effect=S3.values()):
            result = credentials.obtain(self.paths, self.ledger, import_r2=True)
        self.assertEqual(result, {**MATERIAL, **S3})
        self.assertIn('known-ambiguous-token', confirm.call_args_list[0].args[0])


class StorageRecoveryTests(Workspace):
    def test_image_identity_survives_device_renumbering_but_not_backing_replacement(self):
        self.ledger.set(image_identity={'inode': 1234, 'backing_uuid': 'recorded-filesystem'})
        storage = Storage(self.paths, self.ledger)
        with patch.object(storage, 'backing', return_value={'uuid': 'recorded-filesystem'}):
            storage.check_image_identity(Mock(st_ino=1234, st_dev=253))
            storage.check_image_identity(Mock(st_ino=1234, st_dev=999))
            with self.assertRaises(SetupError):
                storage.check_image_identity(Mock(st_ino=5678, st_dev=999))
        with patch.object(storage, 'backing', return_value={'uuid': 'foreign-filesystem'}), self.assertRaises(SetupError):
            storage.check_image_identity(Mock(st_ino=1234, st_dev=253))

    def test_first_format_installs_desktop_exclusion_before_attaching(self):
        storage = Storage(self.paths, self.ledger)
        events = []
        with patch.object(storage, 'allocate', side_effect=lambda: events.append('allocate')), \
             patch.object(storage, 'udev_rule', side_effect=lambda: events.append('udev')), \
             patch.object(storage, 'attach', side_effect=lambda: events.append('attach') or '/dev/loop99'), \
             patch.object(storage, 'probe', side_effect=[{}, {}]), \
             patch.object(storage, 'open', side_effect=lambda *args: events.append('open')), \
             patch.object(storage, 'mount', side_effect=lambda: events.append('mount')), \
             patch('installer.storage.hidden', return_value='new-test-passphrase'), \
             patch('installer.storage.run', side_effect=lambda args, **kwargs: events.append(args[0])):
            storage.provision()
        self.assertEqual(events, ['allocate', 'udev', 'attach', 'cryptsetup', 'open', 'mkfs.ext4', 'mount'])
        self.assertTrue(Ledger.load(self.paths.ledger).get('luks_format_started'))

    def test_foreign_image_and_wrong_uuid_never_formatted(self):
        atomic_write(self.paths.image, b'important-existing-data')
        storage = Storage(self.paths, self.ledger)
        with patch('installer.storage.run') as command, self.assertRaises(SetupError):
            storage.allocate()
        command.assert_not_called()
        self.assertEqual(self.paths.image.read_bytes(), b'important-existing-data')
        with patch.object(storage, 'allocate'), patch.object(storage, 'udev_rule'), \
             patch.object(storage, 'attach', return_value='/dev/loop99'), \
             patch.object(storage, 'probe', return_value={'TYPE': 'crypto_LUKS', 'UUID': 'foreign'}), \
             patch('installer.storage.run') as command, self.assertRaises(SetupError):
            storage.provision()
        command.assert_not_called()

    def test_existing_volume_resumes_without_formatting_or_new_keys(self):
        storage = Storage(self.paths, self.ledger)
        signatures = [{'TYPE': 'crypto_LUKS', 'UUID': self.ledger.get('luks_uuid')},
                      {'TYPE': 'ext4', 'UUID': self.ledger.get('filesystem_uuid')}]
        with patch.object(storage, 'allocate'), patch.object(storage, 'udev_rule'), \
             patch.object(storage, 'attach', return_value='/dev/loop99'), \
             patch.object(storage, 'probe', side_effect=signatures), patch.object(storage, 'open'), \
             patch.object(storage, 'mount'), patch('installer.storage.run') as command, \
             patch('installer.storage.hidden') as prompt:
            storage.provision()
        command.assert_not_called()
        prompt.assert_not_called()
        self.assertTrue(self.ledger.get('filesystem_ready'))

    def test_ambiguous_format_interruption_stops_before_reformat(self):
        self.ledger.set(luks_format_started=True)
        storage = Storage(self.paths, self.ledger)
        with patch.object(storage, 'allocate'), patch.object(storage, 'udev_rule'), \
             patch.object(storage, 'attach', return_value='/dev/loop99'), \
             patch.object(storage, 'probe', return_value={}), patch('installer.storage.run') as command, \
             self.assertRaises(SetupError):
            storage.provision()
        command.assert_not_called()

    def test_destination_lost_success_is_verified_not_reinitialized(self):
        with patch('installer.host.active', return_value=False), \
             patch('installer.host.as_service', return_value=Mock(returncode=0)) as command:
            host.destination(self.paths, self.ledger)
        command.assert_called_once_with(self.paths, 'verify-destination', check=False)
        self.assertTrue(self.ledger.get('destination_ready'))
        with patch('installer.host.active', return_value=False), \
             patch('installer.host.as_service', return_value=Mock(returncode=1)) as command, \
             self.assertRaises(SetupError):
            host.destination(self.paths, self.ledger)
        command.assert_called_once()


class RecoveryExportTests(Workspace):
    @unittest.skipUnless(shutil.which('gpg') and shutil.which('gpgconf'), 'GPG unavailable')
    def test_real_encrypted_export_roundtrip_and_no_overwrite(self):
        self.ledger.set(profile_ready=True)
        for name in ('profile.toml', 'secrets.toml', 'luks-header.bin', 'storage.json', 'README.txt'):
            atomic_write(self.paths.recovery / name, ('private-' + name).encode())
        output = self.paths.base / 'recovery.tar.gpg'
        password = 'test-only-recovery-passphrase'
        with patch('installer.recovery.hidden', return_value=password):
            recovery.export(self.paths, self.ledger, output)
        self.assertNotIn(b'private-secrets.toml', output.read_bytes())
        with tempfile.TemporaryDirectory(dir=self.temp.name) as home:
            try:
                result = run(['gpg', '--homedir', home, '--batch', '--pinentry-mode', 'loopback',
                              '--passphrase-fd', '0', '--decrypt', output], data=(password + '\n').encode())
                with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
                    self.assertEqual(archive.extractfile('secrets.toml').read(), b'private-secrets.toml')
                    self.assertIn('setup.json', archive.getnames())
            finally:
                run(['gpgconf', '--homedir', home, '--kill', 'gpg-agent'])
        with self.assertRaises(SetupError):
            recovery.export(self.paths, self.ledger, output)

    def test_firewall_never_flushes_other_tables_and_blocks_ipv6_smb(self):
        self.ledger.set(firewall_owned=True)
        with patch('installer.firewall.exists', return_value=True), patch('installer.firewall.run') as command:
            firewall.apply(self.ledger)
        data = command.call_args.kwargs['data'].decode()
        self.assertNotIn('flush ruleset', data)
        self.assertTrue(data.startswith('delete table inet cloudflare_disk_smb\n'))
        self.assertIn('ip saddr 192.168.50.0/24 ip daddr 192.168.50.2 tcp dport 445 accept', data)
        self.assertIn('tcp dport 445 drop', data)


if __name__ == '__main__':
    unittest.main()
