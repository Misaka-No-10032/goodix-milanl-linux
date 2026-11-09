#!/usr/bin/env python3
"""Drive an unpacked native engine at its CLI/socket as root; no sensor access."""
import argparse
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import unittest


class PackagedRuntimeTests(unittest.TestCase):
    root = None

    @property
    def binary(self):
        return self.root / 'usr/bin/goodix-milanl-engine'

    def test_native_package_contents_and_service(self):
        with self.binary.open('rb') as binary:
            self.assertEqual(binary.read(4), b'\x7fELF')
        self.assertEqual(self.binary.stat().st_mode & 0o777, 0o755)
        self.assertEqual({p.name for p in (self.root / 'usr/lib/goodix-milanl').iterdir()}, {'oem'})
        units = self.root / 'usr/lib/systemd/system'
        unit = (units / 'goodix-milanl-engine.service').read_text()
        dropin = (units / 'fprintd.service.d/50-goodix-milanl.conf').read_text()
        self.assertIn('ExecStart=/usr/bin/goodix-milanl-engine --socket '
                      '/run/goodix-milanl/engine.sock --assets /usr/lib/goodix-milanl/oem\n', unit)
        self.assertIn('RuntimeDirectory=goodix-milanl\n', unit)
        self.assertIn('StateDirectory=goodix-milanl\n', unit)
        self.assertIn('StateDirectoryMode=0700\n', unit)
        self.assertIn('Type=notify\n', unit)
        self.assertIn('Requires=goodix-milanl-engine.service\n', dropin)
        self.assertIn('After=goodix-milanl-engine.service\n', dropin)
        self.assertIn('Environment=GOODIX_MILANL_ENGINE=/run/goodix-milanl/engine.sock\n', dropin)
        unit_files = {str(path.relative_to(units)) for path in units.rglob('*') if path.is_file()}
        self.assertLessEqual(unit_files, {
            'goodix-milanl-engine.service', 'fprintd.service',
            'fprintd.service.d/50-goodix-milanl.conf',
        })
        signing = self.root / 'usr/bin/goodix-milanl-secure-boot'
        self.assertEqual(signing.stat().st_mode & 0o777, 0o755)
        policy = self.root / 'usr/share/goodix-milanl/selinux'
        for name in ('goodix_milanl.te', 'goodix_milanl.fc', 'install.sh'):
            self.assertTrue((policy / name).is_file())
        licenses = self.root / 'usr/share/licenses/goodix-milanl-engine'
        self.assertTrue((licenses / 'LICENSE-NOTICE').is_file())
        self.assertTrue((self.root / 'usr/share/licenses/goodix-milanl-oem/LICENSE-NOTICE').is_file())
        self.assertTrue((licenses / 'isgx-License.txt').is_file())
        self.assertTrue(list((licenses / 'dependencies').glob('*/LICENSE*')))

    def test_native_cli_help_and_version(self):
        for option in ('--help', '--version'):
            with self.subTest(option=option):
                result = subprocess.run([str(self.binary), option], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(b'goodix-milanl-engine', result.stdout)
                self.assertEqual(result.stderr, b'')
                if option == '--help':
                    self.assertIn(b'/dev/goodix-milanl-raw', result.stdout)

    def test_native_check_does_not_create_a_socket(self):
        with tempfile.TemporaryDirectory(prefix='milanl-check-') as tmp:
            path = Path(tmp) / 'engine.sock'
            result = subprocess.run([
                str(self.binary), '--check', '--socket', str(path),
                '--assets', str(self.root / 'usr/lib/goodix-milanl/oem'),
            ], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 1)  # Isolated /sys has no platform or installed modules.
            self.assertIn(b'OK   OEM assets: nine OEM assets readable', result.stdout)
            self.assertIn(b'FAIL Platform:', result.stdout)
            self.assertNotIn(b'listening', result.stderr)
            self.assertFalse(path.exists())

    def test_native_cli_rejects_invalid_arguments_before_hardware_access(self):
        result = subprocess.run([str(self.binary), '--invalid-option'],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'Usage: goodix-milanl-engine', result.stderr)
        self.assertEqual(result.stdout, b'')

    def test_native_ready_protocol_reconnect_and_shutdown(self):
        with tempfile.TemporaryDirectory(prefix='milanl-package-') as tmp, \
             socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notify:
            work = Path(tmp)
            path = work / 'engine.sock'
            notify.bind(str(work / 'notify'))
            notify.settimeout(5)  # Machine-only test; no human touch/release request.
            process = subprocess.Popen([
                str(self.binary), '--socket', str(path),
                '--assets', str(self.root / 'usr/lib/goodix-milanl/oem'),
            ], cwd=work, env=dict(os.environ, NOTIFY_SOCKET=str(work / 'notify')),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                self.assertEqual(notify.recv(64), b'READY=1')
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                # The second connection must be served after the first one's EOF.
                for _ in range(2):
                    with socket.socket(socket.AF_UNIX) as client:
                        client.settimeout(5)
                        client.connect(str(path))
                        with client.makefile('rb') as response:
                            for request, expected in (
                                (b'\x01\x02\x00\x00\x00', struct.pack('<BIHI', 2, 2, 12, 3)),
                                (b'\x05\x00\x00', b'\x06'),
                                (b'\x02\x00', b'\x08\x02'),
                                (b'\x06', b'\x01'),
                                (b'\x07', b'\x01'),
                            ):
                                client.sendall(struct.pack('<I', len(request)) + request)
                                size, = struct.unpack('<I', response.read(4))
                                self.assertEqual(size, len(expected))
                                self.assertEqual(response.read(size), expected)
                        descriptors = {os.readlink(fd) for fd in Path(f'/proc/{process.pid}/fd').iterdir()}
                        self.assertFalse(descriptors & {'/dev/isgx', '/dev/goodix-milanl-raw'})
                        children = Path(f'/proc/{process.pid}/task/{process.pid}/children').read_text()
                        self.assertEqual(children.strip(), '')
            finally:
                process.terminate()
                try:
                    stdout, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
                    raise
            self.assertEqual(process.returncode, 0, stdout + stderr)
            self.assertEqual(stdout, b'')
            self.assertEqual(stderr, b'goodix-milanl-engine: listening\n')
            self.assertFalse(path.exists())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True, help='private unpacked package root, not /')
    args, unittest_args = parser.parse_known_args()
    if os.geteuid() != 0:
        parser.error('the native service requires root; run this isolated test with sudo')
    PackagedRuntimeTests.root = args.root.resolve()
    unittest.main(argv=[__file__] + unittest_args)
