#!/usr/bin/env python3
"""The SELinux deployment entrypoint must require explicit installation."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


INSTALLER = Path(__file__).resolve().parents[2] / 'packaging/selinux/install.sh'


class SelinuxInstallerTests(unittest.TestCase):
    def test_help_and_invalid_arguments_never_need_host_tools(self):
        with tempfile.TemporaryDirectory() as empty_path:
            for arguments, status in ((['--help'], 0), ([], 2),
                                      (['--unknown'], 2), (['--install', 'extra'], 2)):
                with self.subTest(arguments=arguments):
                    result = subprocess.run(
                        ['/bin/sh', str(INSTALLER), *arguments],
                        env=dict(os.environ, PATH=empty_path), cwd=empty_path,
                        capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertIn('Usage:', result.stdout + result.stderr)
                    self.assertNotIn('not found', result.stderr)


if __name__ == '__main__':
    unittest.main()
