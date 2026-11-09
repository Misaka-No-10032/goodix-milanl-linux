#!/usr/bin/env python3
"""Reconstruct SGX1 Windows PE pages without changing their signed measurement."""
import argparse
import hashlib
import struct
from pathlib import Path

PAGE = 4096
METADATA_MAGIC = 0x86A80294635D0E4C


def verify_css(css):
    if len(css) != 1808:
        raise ValueError("SIGSTRUCT must contain 1808 bytes")
    modulus = int.from_bytes(css[128:512], "little")
    exponent = int.from_bytes(css[512:516], "little")
    signature = int.from_bytes(css[516:900], "little")
    if modulus.bit_length() != 3072 or exponent != 3 or signature >= modulus:
        raise ValueError("unsupported SIGSTRUCT RSA parameters")
    digest = hashlib.sha256(css[:128] + css[900:1028]).digest()
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + digest
    expected = b"\x00\x01" + b"\xff" * (384 - len(digest_info) - 3) + b"\x00" + digest_info
    if pow(signature, exponent, modulus).to_bytes(384, "big") != expected:
        raise ValueError("invalid original SIGSTRUCT RSA signature")


def align(value):
    return (value + PAGE - 1) & -PAGE

class PE:
    def __init__(self, path):
        self.data = bytearray(Path(path).read_bytes())
        if self.data[:2] != b'MZ':
            raise ValueError("not a DOS/PE image")
        self.nt = struct.unpack_from('<I', self.data, 0x3c)[0]
        if self.data[self.nt:self.nt + 6] != b'PE\0\0\x64\x86':
            raise ValueError("not an x86-64 PE image")
        self.opt = self.nt + 24
        if struct.unpack_from('<H', self.data, self.opt)[0] != 0x20b:
            raise ValueError("PE32+ required")
        self.base = struct.unpack_from('<Q', self.data, self.opt + 24)[0]
        count, opt_size = struct.unpack_from('<H12xH', self.data, self.nt + 6)
        self.sections = []
        for n in range(count):
            off = self.opt + opt_size + n * 40
            name, size, rva, rawsize, rawoff = struct.unpack_from('<8sIIII', self.data, off)
            flags = struct.unpack_from('<I', self.data, off + 36)[0]
            self.sections.append((name.rstrip(b'\0'), size, rva, rawsize, rawoff, flags))
        metadata = [x for x in self.sections if x[0] == b'sgxmeta']
        if len(metadata) != 1:
            raise ValueError("exactly one sgxmeta section required")
        self.meta = metadata[0][4]
        magic, version, size = struct.unpack_from('<QQI', self.data, self.meta)
        if (magic, version, size) != (METADATA_MAGIC, 0x100000002, 0x754):
            raise ValueError("unsupported Windows SGX metadata layout")
        self.tcs, self.policy, self.nssa, self.ssa, self.stack, self.heap = struct.unpack_from('<6I', self.data, self.meta + 20)
        if not (1 <= self.tcs <= 64 and self.nssa == 2 and self.ssa == 1 and
                self.stack > 0 and self.stack % PAGE == 0 and self.heap % PAGE == 0):
            raise ValueError("unsupported SGX1 thread layout")
        for name, size, rva, rawsize, rawoff, flags in self.sections:
            if rva % PAGE or rawoff + rawsize > len(self.data) or rawsize > align(size):
                raise ValueError("invalid PE section bounds or alignment")
        self.css = bytes(self.data[self.meta + 68:self.meta + 68 + 1808])
    def directory(self, index):
        return struct.unpack_from('<II', self.data, self.opt + 112 + 8 * index)
    def offset(self, rva):
        for name, size, addr, rawsize, rawoff, flags in self.sections:
            if addr <= rva < addr + max(size, rawsize):
                return rawoff + rva - addr
        if rva < struct.unpack_from('<I', self.data, self.opt + 60)[0]:
            return rva
        raise ValueError(hex(rva))
    def export(self, name):
        off = self.offset(self.directory(0)[0])
        functions = self.offset(struct.unpack_from('<I', self.data, off + 28)[0])
        names = self.offset(struct.unpack_from('<I', self.data, off + 32)[0])
        ordinals = self.offset(struct.unpack_from('<I', self.data, off + 36)[0])
        for i in range(struct.unpack_from('<I', self.data, off + 24)[0]):
            pos = self.offset(struct.unpack_from('<I', self.data, names + 4 * i)[0])
            if self.data[pos:self.data.index(0, pos)] == name:
                n = struct.unpack_from('<H', self.data, ordinals + 2 * i)[0]
                return struct.unpack_from('<I', self.data, functions + 4 * n)[0]
        raise ValueError(name)
    def pages(self):
        image_sections = [x for x in self.sections if x[0] != b'sgxmeta']
        image_end = align(max(x[2] + x[1] for x in image_sections))
        tls = self.offset(self.directory(9)[0])
        tls_start, tls_end = struct.unpack_from('<QQ', self.data, tls)
        tls_size = tls_end - tls_start
        if not 104 <= tls_size <= 0x10000:
            raise ValueError("unsupported Windows SGX TLS template")
        thread_size = PAGE + align(tls_size) + 0x20000 + self.nssa * self.ssa * PAGE + self.stack
        required = image_end + self.heap + 0x10000 + self.tcs * thread_size
        self.enclave_size = 1 << (required - 1).bit_length()
        if self.enclave_size > 1 << 28:
            raise ValueError("enclave exceeds the supported SGX1 enclave size limit")
        td = self.offset(tls_start - self.base)
        stack_end = self.stack + 0x21000 + self.nssa * self.ssa * PAGE + align(tls_size)
        for off, value in [(8, stack_end), (16, stack_end), (24, stack_end - self.stack),
                           (32, align(tls_size) + 0x11000),
                           (40, align(tls_size) + 0x11000 + self.ssa * PAGE - 0xb8),
                           (48, PAGE), (64, image_end), (72, self.enclave_size), (88, 0x1030)]:
            struct.pack_into('<Q', self.data, td + off, value)
        self.data[td + 56] = self.policy
        struct.pack_into('<II', self.data, td + 96, self.ssa, self.heap)
        struct.pack_into('<I', self.data, self.nt + 0x58, 0)
        struct.pack_into('<Q', self.data, self.nt + 0xa8, 0)
        reloc_pages = set()
        reloc, reloc_size = self.directory(5)
        pos = self.offset(reloc)
        end = pos + reloc_size
        while pos < end:
            addr, size = struct.unpack_from('<II', self.data, pos)
            if not size:
                break
            if size < 8 or size % 2 or pos + size > end:
                raise ValueError("invalid relocation block")
            reloc_pages.add(addr // PAGE)
            for off in range(pos + 8, pos + size, 2):
                entry = struct.unpack_from('<H', self.data, off)[0]
                if entry >> 12 == 10 and entry & 0xfff > 0xff8:
                    reloc_pages.add(addr // PAGE + 1)
            pos += size
        headers = struct.unpack_from('<I', self.data, self.opt + 60)[0]
        inputs = [(b'headers', PAGE, 0, headers, 0, 0x40000000)] + image_sections
        self.stats = {'image_end': hex(image_end), 'tls_size': hex(tls_size), 'thread_bytes': hex(thread_size), 'enclave_size': hex(self.enclave_size)}
        for name, size, rva, rawsize, rawoff, flags in inputs:
            secinfo = 0x200 | ((flags >> 30) & 1) | (((flags >> 31) & 1) << 1) | (((flags >> 29) & 1) << 2)
            content = self.data[rawoff:rawoff + rawsize]
            content += bytes(align(size) - len(content))
            for off in range(0, align(size), PAGE):
                address = rva + off
                page_flags = secinfo | (2 if address // PAGE in reloc_pages else 0)
                yield address, bytes(content[off:off + PAGE]), page_flags, True
        for off in range(0, self.heap, PAGE):
            yield image_end + off, bytes(PAGE), 0x203, False
        current = image_end + align(self.heap) + 0x10000
        entry = self.export(b'enclave_entry')
        self.tcs_offsets = []
        for index in range(self.tcs):
            self.tcs_offsets.append(current)
            tcs = bytearray(PAGE)
            struct.pack_into('<Q', tcs, 16, current + 0x11000 + align(tls_size))
            struct.pack_into('<II', tcs, 24, 0, self.nssa)
            struct.pack_into('<Q', tcs, 32, entry)
            struct.pack_into('<QQII', tcs, 48, current + PAGE, current + PAGE, 0xfff, 0xfff)
            yield current, bytes(tcs), 0x100, True
            for off in range(0, align(tls_size), PAGE):
                yield current + PAGE + off, bytes(PAGE), 0x203, True
            ssa_start = current + 0x11000 + align(tls_size)
            for off in range(0, self.nssa * self.ssa * PAGE, PAGE):
                yield ssa_start + off, bytes(PAGE), 0x203, True
            stack_start = ssa_start + self.nssa * self.ssa * PAGE + 0x10000
            for off in range(0, self.stack, PAGE):
                yield stack_start + off, b'\xcc' * PAGE, 0x203, True
            current = stack_start + self.stack

    def measure(self):
        pages = list(self.pages())
        h = hashlib.sha256()
        h.update(struct.pack('<8sIQ44x', b'ECREATE', self.ssa, self.enclave_size))
        for rva, data, flags, extend in pages:
            if len(data) != PAGE or rva % PAGE or rva + PAGE > self.enclave_size:
                raise ValueError("invalid enclave page")
            h.update(struct.pack('<8sQQ40x', b'EADD', rva, flags))
            if extend:
                for off in range(0, PAGE, 256):
                    h.update(struct.pack('<8sQ48x', b'EEXTEND', rva + off))
                    h.update(data[off:off + 256])
        return h.digest(), pages

    def checked_pages(self, css=None):
        digest, pages = self.measure()
        signature = self.css if css is None else css
        verify_css(self.css)
        verify_css(signature)
        if digest != self.css[960:992] or digest != signature[960:992]:
            raise ValueError("reconstructed pages do not match the original signed measurement")
        if len({page[0] for page in pages}) != len(pages):
            raise ValueError("overlapping enclave pages")
        return digest, pages, signature

    def package(self, output, css=None):
        digest, pages, signature = self.checked_pages(css)
        flags = struct.unpack_from('<Q', self.data, self.meta + 52)[0]
        with Path(output).open('wb') as file:
            file.write(struct.pack('<8sQIIQQQ', b'MPESGX01', self.enclave_size, self.ssa,
                                   len(pages), flags, 3, self.tcs_offsets[0]))
            file.write(signature)
            for rva, content, secinfo, extend in pages:
                file.write(struct.pack('<QQII', rva, secinfo, extend, 0))
                file.write(content)
        return digest, len(pages)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('images', nargs='+')
    parser.add_argument('--output', help='private SGX1 page package for one image (vendor licensing applies; do not redistribute)')
    parser.add_argument('--css', help='official production SIGSTRUCT for the same measurement')
    args = parser.parse_args()
    if (args.output or args.css) and len(args.images) != 1:
        parser.error('--output and --css require exactly one image')
    css = Path(args.css).read_bytes() if args.css else None
    for filename in args.images:
        pe = PE(filename)
        digest, pages, _ = pe.checked_pages(css)
        if args.output:
            pe.package(args.output, css)
        print(Path(filename).name, 'pages=', len(pages), 'enclave_bytes=', pe.enclave_size,
              'MRENCLAVE=', digest.hex(), 'original_signature_and_measurement=PASS')


if __name__ == '__main__':
    main()
