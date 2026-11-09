#!/usr/bin/env python3
"""Exercise the signing entrypoint with private DKMS files and mocked host actions."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / 'packaging/secure-boot.sh'


@unittest.skipUnless(os.geteuid() == 0, 'run as root for isolated bwrap mounts')
class SecureBootTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='milanl-signing-')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        for name in ('config/framework.conf.d', 'keys', 'bin', 'efi'):
            (self.work / name).mkdir(parents=True)
        self.log = self.work / 'calls'
        self.key = self.work / 'keys/custom.key'
        self.cert = self.work / 'keys/custom.der'
        subprocess.run([
            'openssl', 'req', '-new', '-x509', '-nodes', '-days', '1',
            '-subj', '/CN=Synthetic test only', '-newkey', 'rsa:2048',
            '-keyout', str(self.key), '-outform', 'DER', '-out', str(self.cert),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        serial = subprocess.check_output([
            'openssl', 'x509', '-inform', 'DER', '-in', str(self.cert),
            '-noout', '-serial',
        ], text=True)
        self.key_id = serial.strip().split('=', 1)[1]
        (self.work / 'config/framework.conf').write_text('mok_certificate=/wrong/default.der\n')
        (self.work / 'config/framework.conf.d/custom.conf').write_text(
            'mok_signing_key=/var/lib/dkms/custom.key\n'
            'mok_certificate=/var/lib/dkms/custom.der\n')
        self.shim = self.work / 'efi/MokListRT-synthetic'
        self.shim.touch()
        commands = {
            'mokutil': 'printf "mokutil %s\\n" "$*" >> "$CALLS"\n'
                       'if [ "$1" = --test-key ]; then exit "$MOK_STATUS"; fi\n',
            'modinfo': 'printf "modinfo %s\\n" "$*" >> "$CALLS"\n'
                       'printf "%s\\n" "$MODULE_KEY"\n',
            'dkms': 'printf "dkms %s\\n" "$*" >> "$CALLS"\n',
        }
        for name, body in commands.items():
            path = self.work / 'bin' / name
            path.write_text('#!/bin/sh\n' + body)
            path.chmod(0o755)

    def run_script(self, action, **environment):
        env = dict(os.environ, PATH=f'{self.work / "bin"}:/usr/bin',
                   CALLS=str(self.log), MOK_STATUS='0', MODULE_KEY=self.key_id)
        env.update(environment)
        return subprocess.run([
            'bwrap', '--ro-bind', '/', '/', '--bind', str(self.work), str(self.work),
            '--bind', str(self.work / 'config'), '/etc/dkms',
            '--bind', str(self.work / 'keys'), '/var/lib/dkms',
            '--tmpfs', '/sys', '--dir', '/sys/firmware/efi/efivars',
            '--ro-bind', str(self.work / 'efi'), '/sys/firmware/efi/efivars',
            '--dev', '/dev', '--unshare-net', '--unshare-pid',
            '/usr/bin/bash', str(SCRIPT), action,
        ], env=env, capture_output=True, text=True, timeout=10)

    def calls(self):
        return self.log.read_text() if self.log.exists() else ''

    def test_check_uses_configured_certificate_and_checks_both_modules(self):
        result = self.run_script('check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--test-key /var/lib/dkms/custom.der', self.calls())
        self.assertIn('isgx: signed', result.stdout)
        self.assertIn('goodix_milanl_transport: signed', result.stdout)
        self.assertNotIn('--import', self.calls())
        self.assertNotIn('dkms ', self.calls())

    def test_real_sign_file_and_modinfo_match_the_enrolled_certificate(self):
        sign_file = Path('/usr/lib/modules') / os.uname().release / 'build/scripts/sign-file'
        self.assertTrue(sign_file.is_file(), 'target kernel headers are required')
        module = self.work / 'synthetic.ko'
        subprocess.run(['cc', '-x', 'c', '-c', '-o', str(module), '-'],
                       input=b'const char info[] __attribute__((section(".modinfo"))) = "license=GPL";\n',
                       check=True, capture_output=True)
        subprocess.run([str(sign_file), 'sha256', str(self.key), str(self.cert), str(module)],
                       check=True, capture_output=True)
        module_key = subprocess.check_output(['modinfo', '-F', 'sig_key', str(module)], text=True).strip()
        result = self.run_script('check', MODULE_KEY=module_key)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('isgx: signed', result.stdout)

    def test_unenrolled_key_fails_without_import(self):
        result = self.run_script('check', MOK_STATUS='1')
        self.assertEqual(result.returncode, 1)
        self.assertIn('not enrolled', result.stderr)
        self.assertNotIn('--import', self.calls())
        self.assertNotIn('modinfo ', self.calls())

    def test_wrong_module_signer_fails(self):
        result = self.run_script('check', MODULE_KEY='00:11')
        self.assertEqual(result.returncode, 1)
        self.assertIn('not signed with the enrolled DKMS key', result.stderr)

    def test_prepare_uses_dkms_and_keeps_existing_pair(self):
        before = (self.key.read_bytes(), self.cert.read_bytes())
        result = self.run_script('prepare')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), 'dkms generate_mok\n')
        self.assertEqual((self.key.read_bytes(), self.cert.read_bytes()), before)

    def test_prepare_does_not_replace_an_orphaned_key(self):
        self.cert.unlink()
        before = self.key.read_bytes()
        result = self.run_script('prepare')
        self.assertEqual(result.returncode, 1)
        self.assertIn('preserving the existing file', result.stderr)
        self.assertEqual(self.calls(), '')
        self.assertEqual(self.key.read_bytes(), before)

    def test_enroll_is_the_only_importing_action(self):
        result = self.run_script('enroll', MOK_STATUS='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--import /var/lib/dkms/custom.der', self.calls())
        self.assertNotIn('dkms ', self.calls())

    def test_enroll_without_shim_leaves_boot_configuration_alone(self):
        self.shim.unlink()
        result = self.run_script('enroll', MOK_STATUS='1')
        self.assertEqual(result.returncode, 1)
        self.assertIn('no shim MOK list', result.stderr)
        self.assertEqual(self.calls(), '')

    def test_unknown_action_runs_nothing(self):
        result = self.run_script('invalid')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.calls(), '')


if __name__ == '__main__':
    unittest.main()
