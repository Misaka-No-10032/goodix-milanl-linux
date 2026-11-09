#!/usr/bin/env python3
"""Download and prepare pinned OEM assets locally; never run installers or use hardware."""
import argparse
import hashlib
import os
from pathlib import Path
import runpy
import shutil
import subprocess
from urllib.request import urlopen

OEM_URL = (
    'https://consumer-tkbdownload.huawei.com/ctkbfm/servlet/download/downloadServlet/'
    'H4sIAAAAAAAA_z1Qy2rDMBD8F51DWL21PcVP6KGNwSn0ZmRbTUVTOyhyS1P675VLKMsehpndGeab'
    'LBcXDl9nR-4IIxsyzp_TDaoEX_zJPdr3FT7Y6PJ5fuueuybMXe2nowtN8FPs6DaNTGu2V3--nTU2vq5Pc'
    'XAOnTLcGKEG7FFo4FLxkaIStE_q3l_vxyRt97uWKqCCGS7UjgKASPQQnI1-ng5-zZEEKDgIWOkNufjjZOMS1o'
    'RZJktWcQlQlTlnFeM1IkooC6iMoRpZLWWdGZprXWpDS1nVUvNCq6IwqGXy-rAnPz79VxLD4v7y3Spp9-TnF5ZBVFQzAQAA.zip'
)
INTEL_URL = (
    'https://registrationcenter-download.intel.com/akdlm/IRC_NAS/18000/'
    'Intel%20SGX%20PSW%20for%20Windows%20v2.13.100.2.exe'
)
OEM_SHA256 = 'eae4baecf92ed4a33e1ae2720cc458cb6d005297c2b1b97d6d0541650e429123'
INTEL_SHA256 = '2f8d0344d5853bc1a5ea3167e779c8718eeb67b3e855be2e2bb3b1c67b8ad084'
GOODIX_FILES = {
    'gfspi.dll': 'd98e873e02b00d03d90ccdd78ac69624676a6b9c3662ce66dfca220551b675cd',
    'WBDI_Enclave.signed.dll': '8811f32411a236b28c61a0f0d9c134c42357e0dcddd71c2c324873e9219618b4',
    'Engine_Enclave_3.00.20.signed.dll': 'fa0602a1c8c037e014c07093e455128f1596f2efa8580d8ba34bedc1bac742d1',
    'sgx_white_list_cert.bin': 'fd2723344d1acf470fc231a93920bf6c2b9efe18474b3ab9247ec2960e8b9223',
}
INTEL_FILES = {
    'le.signed.dll': '8122bb622d75cc39a689a305bdf9f5c9055eec64ceb4af01d13115caef34e705',
    'le_prod_css.bin': '02366e59874e0698a1b8827a1152bce389a1ff3ff3bed0b52e694fff5404f0c6',
}


def check_hash(path, expected):
    with path.open('rb') as source:
        actual = hashlib.file_digest(source, 'sha256').hexdigest()
    if actual != expected:
        raise ValueError(f'vendor input SHA-256 mismatch: {path.name}')


def download(url, directory, filename, expected):
    directory.mkdir(mode=0o700)
    archive = directory / filename
    with urlopen(url) as response, archive.open('xb') as target:
        shutil.copyfileobj(response, target)
    check_hash(archive, expected)
    return archive


def extract(archive, directory, members):
    directory.mkdir(mode=0o700)
    subprocess.run(['7zz', 'x', '-y', '-o' + str(directory), str(archive), *members],
                   check=True, stdout=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path, help='new private output directory')
    args = parser.parse_args()
    os.umask(0o077)
    work = args.output.resolve()
    work.mkdir(mode=0o700)
    basename = 'MateBook_X_Pro_FingerPrint_1.1.151.18'
    print('OEM_DOWNLOAD: official Huawei driver and Intel SGX PSW', flush=True)
    oem = download(OEM_URL, work / 'download-oem', basename + '.zip', OEM_SHA256)
    intel = download(INTEL_URL, work / 'download-intel',
                     'Intel-SGX-PSW-2.13.100.2.exe', INTEL_SHA256)
    exe = 'FingerPrint_1.1.151.18.exe'
    extract(oem, work / 'outer', [f'{basename}/{basename}.zip'])
    extract(work / 'outer' / basename / (basename + '.zip'), work / 'inner', [exe])
    extract(work / 'inner' / exe, work / 'nsis', [exe])
    extract(work / 'nsis' / exe, work / 'goodix',
            ['source/' + name for name in [*GOODIX_FILES, 'gfspi.inf']])
    intel_prefix = 'Intel SGX PSW for Windows v2.13.100.2/PSW_INF_RS3_and_above'
    intel_license = 'INTEL Software License Agreement 11.2.17.pdf'
    extract(intel, work / 'intel',
            [intel_prefix + '/' + name for name in [*INTEL_FILES, intel_license]])
    goodix = work / 'goodix/source'
    win = work / 'intel' / intel_prefix
    for directory, files in ((goodix, GOODIX_FILES), (win, INTEL_FILES)):
        for name, digest in files.items():
            check_hash(directory / name, digest)
    # Load only the trusted reconstruction code, never Python from an archive.
    repo = Path(__file__).resolve().parents[1]
    pe_class = runpy.run_path(str(repo / 'tools/pe_enclave.py'), run_name='oem_build')['PE']
    assets, licenses = work / 'assets', work / 'licenses'
    assets.mkdir(mode=0o700)
    licenses.mkdir(mode=0o700)
    pe_class(win / 'le.signed.dll').package(assets / 'windows-le.pages',
                                          (win / 'le_prod_css.bin').read_bytes())
    for stem, name in (('goodix', 'WBDI_Enclave.signed.dll'),
                       ('engine', 'Engine_Enclave_3.00.20.signed.dll')):
        pe = pe_class(goodix / name)
        pe.package(assets / (stem + '.pages'))
        (assets / (stem + '-mrenclave.bin')).write_bytes(pe.css[960:992])
        (assets / (stem + '-mrsigner.bin')).write_bytes(hashlib.sha256(pe.css[128:512]).digest())
    shutil.copyfile(goodix / 'sgx_white_list_cert.bin', assets / 'goodix-whitelist.bin')
    shutil.copyfile(goodix / 'gfspi.dll', assets / 'gfspi.dll')
    shutil.copyfile(goodix / 'gfspi.inf', licenses / 'gfspi.inf')
    shutil.copyfile(win / intel_license, licenses / intel_license)
    print(f'OEM_ASSETS_PASS: {assets}; original signatures and measurements verified; local only')


if __name__ == '__main__':
    main()
