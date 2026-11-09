import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.pe_enclave import METADATA_MAGIC, PAGE, PE, verify_css


def synthetic_pe():
    data = bytearray(0x1400)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HH', data, 0x84, 0x8664, 5)
    struct.pack_into('<H', data, 0x94, 0xf0)
    optional = 0x98
    struct.pack_into('<H', data, optional, 0x20b)
    base = 0x180000000
    struct.pack_into('<Q', data, optional + 24, base)
    struct.pack_into('<II', data, optional + 56, 0x6000, 0x400)
    struct.pack_into('<I', data, 0xd8, 0x12345678)
    for index, rva, size in [(0, 0x2000, 0x80), (5, 0x4000, 12), (9, 0x2080, 40)]:
        struct.pack_into('<II', data, optional + 112 + 8 * index, rva, size)
    sections = [
        (b'.text', 0x180, 0x1000, 0x200, 0x400, 0x60000020),
        (b'.rdata', 0x200, 0x2000, 0x200, 0x600, 0x40000040),
        (b'.tls', 0x68, 0x3000, 0x200, 0x800, 0x40000040),
        (b'.reloc', 0x200, 0x4000, 0x200, 0xa00, 0x40000040),
        (b'sgxmeta', 0x754, 0x5000, 0x800, 0xc00, 0x40000040),
    ]
    for index, (name, size, rva, rawsize, rawoff, flags) in enumerate(sections):
        position = optional + 0xf0 + index * 40
        struct.pack_into('<8sIIII', data, position, name, size, rva, rawsize, rawoff)
        struct.pack_into('<I', data, position + 36, flags)
    data[0x400:0x600] = b'\xcc' * 0x200
    struct.pack_into('<IIIII', data, 0x600 + 20, 1, 1, 0x2040, 0x2044, 0x2048)
    struct.pack_into('<IIH', data, 0x640, 0x1000, 0x204a, 0)
    data[0x64a:0x658] = b'enclave_entry\0'
    struct.pack_into('<QQ', data, 0x680, base + 0x3000, base + 0x3068)
    struct.pack_into('<IIHH', data, 0xa00, 0x2000, 12, 0xaff9, 0)
    struct.pack_into('<QQI6I', data, 0xc00, METADATA_MAGIC, 0x100000002,
                     0x754, 1, 1, 2, 1, 0x2000, 0x1000)
    struct.pack_into('<QQ', data, 0xc00 + 52, 4, 0xe7)
    return data


class PEEnclaveTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'synthetic.dll'
        self.data = synthetic_pe()
        self.path.write_bytes(self.data)

    def test_measurement_records_and_layout(self):
        pe = PE(self.path)
        digest, pages = pe.measure()
        self.assertEqual(len(pages), 12)
        self.assertEqual(pe.enclave_size, 0x40000)
        self.assertEqual(pe.tcs_offsets, [0x16000])
        self.assertEqual(len({page[0] for page in pages}), len(pages))
        self.assertTrue(all(len(page[1]) == PAGE for page in pages))
        # Build the measurement stream separately from the implementation's record packing.
        stream = bytearray(b'ECREATE\0' + (1).to_bytes(4, 'little') +
                           (0x40000).to_bytes(8, 'little') + bytes(44))
        for rva, content, flags, measured in pages:
            stream += b'EADD\0\0\0\0' + rva.to_bytes(8, 'little') + flags.to_bytes(8, 'little') + bytes(40)
            if measured:
                for offset in range(0, PAGE, 256):
                    stream += b'EEXTEND\0' + (rva + offset).to_bytes(8, 'little') + bytes(48)
                    stream += content[offset:offset + 256]
        self.assertEqual(digest, hashlib.sha256(stream).digest())
        self.assertEqual(pe.measure()[0], digest)
        self.assertEqual(self.path.read_bytes(), self.data)

    def test_relocation_cross_page_write_permissions(self):
        pages = {rva: flags for rva, _, flags, _ in PE(self.path).measure()[1]}
        self.assertEqual(pages[0x1000], 0x205)
        self.assertEqual(pages[0x2000], 0x203)
        self.assertEqual(pages[0x3000], 0x203)
        self.assertEqual(pages[0x4000], 0x201)

    def test_heap_is_added_without_extend_and_guards_are_absent(self):
        pages = {page[0]: page for page in PE(self.path).measure()[1]}
        self.assertEqual(pages[0x5000][1:], (bytes(PAGE), 0x203, False))
        self.assertNotIn(0x6000, pages)
        self.assertNotIn(0x18000, pages)
        self.assertNotIn(0x2a000, pages)
        self.assertEqual(pages[0x3a000][1], b'\xcc' * PAGE)

    def test_tcs_and_thread_template(self):
        pages = {page[0]: page for page in PE(self.path).measure()[1]}
        tcs = pages[0x16000]
        self.assertEqual(tcs[2], 0x100)
        self.assertEqual(struct.unpack_from('<QIIQ', tcs[1], 16), (0x28000, 0, 2, 0x1000))
        self.assertEqual(struct.unpack_from('<QQII', tcs[1], 48), (0x17000, 0x17000, 0xfff, 0xfff))
        template = pages[0x3000][1]
        self.assertEqual(struct.unpack_from('<Q', template, 8)[0], 0x26000)
        self.assertEqual(struct.unpack_from('<Q', template, 64)[0], 0x5000)
        self.assertEqual(struct.unpack_from('<Q', template, 72)[0], 0x40000)
        self.assertEqual(struct.unpack_from('<I', pages[0][1], 0xd8)[0], 0)

    def test_measured_content_changes_digest(self):
        first = PE(self.path).measure()[0]
        self.data[0x400] = 0x90
        self.path.write_bytes(self.data)
        self.assertNotEqual(PE(self.path).measure()[0], first)

    def test_unextended_heap_content_does_not_change_digest(self):
        pe = PE(self.path)
        digest, pages = pe.measure()
        altered = [(rva, content if measured else b'\xa5' * PAGE, flags, measured)
                   for rva, content, flags, measured in pages]
        with patch.object(pe, 'pages', return_value=iter(altered)):
            self.assertEqual(pe.measure()[0], digest)

    def test_page_package_and_measurement_mismatch(self):
        pe = PE(self.path)
        digest, pages = pe.measure()
        css = bytearray(1808)
        css[960:992] = digest
        pe.css = bytes(css)
        output = Path(self.directory.name) / 'synthetic.pages'
        # Synthetic signatures are deliberately not valid RSA signatures.
        with patch('tools.pe_enclave.verify_css'):
            pe.package(output)
            packed = output.read_bytes()
            self.assertEqual(struct.unpack_from('<8sQIIQQQ', packed),
                             (b'MPESGX01', 0x40000, 1, len(pages), 4, 3, 0x16000))
            self.assertEqual(len(packed), 48 + 1808 + len(pages) * (24 + PAGE))
            self.assertEqual(packed[48:48 + 1808], css)
            with self.assertRaises(ValueError):
                pe.checked_pages(bytes(1808))

    def test_invalid_pe_and_metadata(self):
        for offset, value in [(0, 0), (0x84, 0), (0x98, 0), (0xc00, 0), (0xc08, 0)]:
            data = synthetic_pe()
            data[offset] = value
            self.path.write_bytes(data)
            with self.assertRaises(ValueError):
                PE(self.path)

    def test_invalid_relocation_block(self):
        struct.pack_into('<I', self.data, 0xa04, 6)
        self.path.write_bytes(self.data)
        with self.assertRaises(ValueError):
            PE(self.path).measure()

    def test_invalid_signature(self):
        with self.assertRaises(ValueError):
            verify_css(bytes(1807))
        css = bytearray(1808)
        css[128:512] = b'\xff' * 384
        struct.pack_into('<I', css, 512, 3)
        with self.assertRaisesRegex(ValueError, 'RSA signature'):
            verify_css(css)
        struct.pack_into('<I', css, 512, 65537)
        with self.assertRaisesRegex(ValueError, 'RSA parameters'):
            verify_css(css)


if __name__ == '__main__':
    unittest.main()
