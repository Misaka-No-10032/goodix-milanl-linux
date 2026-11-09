#!/usr/bin/env python3
"""Synthetic download regressions; no network, vendor binaries or hardware."""
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
from urllib.error import URLError


spec = importlib.util.spec_from_file_location(
    'prepare_oem', Path(__file__).resolve().parents[2] / 'tools/prepare-oem.py')
prepare_oem = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare_oem)


class DownloadTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory(prefix='milanl-download-')
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)
        self.addCleanup(os.umask, os.umask(0o077))

    def test_download_verifies_bytes_and_keeps_private_modes(self):
        data = b'synthetic vendor archive'
        url = 'https://vendor.invalid/driver.zip'
        with mock.patch.object(prepare_oem, 'urlopen', return_value=io.BytesIO(data)) as request:
            archive = prepare_oem.download(
                url, self.root / 'download', 'driver.zip', hashlib.sha256(data).hexdigest())
        request.assert_called_once_with(url)
        self.assertEqual(archive.read_bytes(), data)
        self.assertEqual(archive.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)

    def test_either_hash_mismatch_stops_before_extraction(self):
        for bad_input in (0, 1):
            with self.subTest(bad_input=bad_input):
                data = [b'synthetic OEM', b'synthetic Intel']
                digests = [hashlib.sha256(item).hexdigest() for item in data]
                data[bad_input] = b'not the expected archive'
                with (
                    mock.patch.object(sys, 'argv', ['prepare-oem.py', str(self.root / str(bad_input))]),
                    mock.patch.object(prepare_oem, 'OEM_SHA256', digests[0]),
                    mock.patch.object(prepare_oem, 'INTEL_SHA256', digests[1]),
                    mock.patch.object(prepare_oem, 'urlopen',
                                      side_effect=[io.BytesIO(item) for item in data]) as request,
                    mock.patch.object(prepare_oem, 'extract') as extract,
                    redirect_stdout(io.StringIO()),
                    self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'),
                ):
                    prepare_oem.main()
                self.assertEqual(request.call_count, bad_input + 1)
                extract.assert_not_called()

    def test_download_propagates_network_failure(self):
        with (
            mock.patch.object(prepare_oem, 'urlopen', side_effect=URLError('unavailable')),
            self.assertRaises(URLError),
        ):
            prepare_oem.download('https://vendor.invalid/driver.zip',
                                 self.root / 'download', 'driver.zip', '0' * 64)
        self.assertFalse((self.root / 'download/driver.zip').exists())

    def test_existing_output_is_not_overwritten_or_downloaded(self):
        output = self.root / 'existing'
        output.mkdir()
        marker = output / 'keep'
        marker.write_bytes(b'existing input')
        with (
            mock.patch.object(sys, 'argv', ['prepare-oem.py', str(output)]),
            mock.patch.object(prepare_oem, 'urlopen') as request,
            self.assertRaises(FileExistsError),
        ):
            prepare_oem.main()
        request.assert_not_called()
        self.assertEqual(marker.read_bytes(), b'existing input')


if __name__ == '__main__':
    unittest.main()
