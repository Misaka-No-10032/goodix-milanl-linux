// SPDX-License-Identifier: GPL-2.0-only
// Load measured PE pages with their original, unmodified SIGSTRUCTs.
use super::abi;
use crate::{
    Cancellation,
    error::{Error, Result},
};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
};

const HEADER_BYTES: usize = 48 + 1808;
const RECORD_BYTES: usize = 24 + abi::PAGE_BYTES;
const MAX_SIZE: usize = 1 << 28;

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

pub(super) fn read_asset(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    // O_NONBLOCK avoids hanging on an accidental FIFO before checking its type.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(Error::Enclave("invalid enclave asset file"));
    }
    let mut bytes = vec![0; metadata.len() as usize];
    file.read_exact(&mut bytes)?;
    let mut extra = [0];
    if file.read(&mut extra)? != 0 {
        return Err(Error::Enclave("enclave asset changed size"));
    }
    Ok(bytes)
}
pub(super) fn exact_asset<const N: usize>(assets: &Path, name: &str) -> Result<[u8; N]> {
    read_asset(&assets.join(name), N)?
        .try_into()
        .map_err(|_| Error::Enclave("incorrect enclave asset length"))
}

pub(super) struct Package {
    bytes: Vec<u8>,
    pub size: usize,
    pub tcs: usize,
    pub flags: u64,
    pages: usize,
}
impl Package {
    pub fn open(path: &Path, cancel: &dyn Cancellation) -> Result<Self> {
        cancel.check()?;
        let bytes = read_asset(
            path,
            HEADER_BYTES + MAX_SIZE / abi::PAGE_BYTES * RECORD_BYTES,
        )?;
        let package = Self::parse(bytes)?;
        package.verify_measurement(cancel)?;
        Ok(package)
    }
    pub fn parse(bytes: Vec<u8>) -> Result<Self> {
        let bad = || Error::Enclave("malformed MPESGX01 enclave image");
        if bytes.len() < HEADER_BYTES || &bytes[..8] != b"MPESGX01" {
            return Err(bad());
        }
        let size64 = u64_at(&bytes, 8);
        let size = usize::try_from(size64).map_err(|_| bad())?;
        let pages = u32_at(&bytes, 20) as usize;
        let flags = u64_at(&bytes, 24);
        let tcs = usize::try_from(u64_at(&bytes, 40)).map_err(|_| bad())?;
        if !(abi::PAGE_BYTES..=MAX_SIZE).contains(&size) || !size.is_power_of_two()
            || u32_at(&bytes, 16) != 1 || pages == 0 || pages > size / abi::PAGE_BYTES
            || u64_at(&bytes, 32) != 3 || tcs >= size || tcs % abi::PAGE_BYTES != 0
            // The original production LE requires EINITTOKENKEY (0x20).
            || !matches!(flags, 4 | 0x24)
            || bytes.len() != HEADER_BYTES + pages * RECORD_BYTES
        {
            return Err(bad());
        }
        let mut seen = vec![false; size / abi::PAGE_BYTES];
        let mut tcs_found = false;
        for page in bytes[HEADER_BYTES..].chunks_exact(RECORD_BYTES) {
            let rva = u64_at(page, 0);
            let flags = u64_at(page, 8);
            if rva >= size64
                || rva % abi::PAGE_BYTES as u64 != 0
                || u32_at(page, 16) > 1
                || u32_at(page, 20) != 0
                || !(flags == 0x100 || flags & !7 == 0x200)
            {
                return Err(bad());
            }
            let index = rva as usize / abi::PAGE_BYTES;
            if seen[index] {
                return Err(bad());
            }
            seen[index] = true;
            if rva as usize == tcs {
                tcs_found = flags == 0x100;
            }
        }
        if !tcs_found {
            return Err(bad());
        }
        Ok(Self {
            bytes,
            size,
            tcs,
            flags,
            pages,
        })
    }
    pub fn css(&self) -> &[u8] {
        &self.bytes[48..HEADER_BYTES]
    }
    pub fn verify_identity(&self, measurement: &[u8; 32], signer: &[u8; 32]) -> Result<()> {
        if self.css()[960..992] != measurement[..]
            || Sha256::digest(&self.css()[128..512])[..] != signer[..]
        {
            return Err(Error::Enclave(
                "enclave launch identity does not match SIGSTRUCT",
            ));
        }
        Ok(())
    }
    fn verify_measurement(&self, cancel: &dyn Cancellation) -> Result<()> {
        let mut hash = Sha256::new();
        let mut record = [0u8; 64];
        record[..8].copy_from_slice(b"ECREATE\0");
        record[8..12].copy_from_slice(&1u32.to_le_bytes());
        record[12..20].copy_from_slice(&(self.size as u64).to_le_bytes());
        hash.update(record);
        for page in self.bytes[HEADER_BYTES..].chunks_exact(RECORD_BYTES) {
            cancel.check()?;
            record.fill(0);
            record[..8].copy_from_slice(b"EADD\0\0\0\0");
            record[8..24].copy_from_slice(&page[..16]);
            hash.update(record);
            if u32_at(page, 16) == 1 {
                for (index, block) in page[24..].chunks_exact(256).enumerate() {
                    record.fill(0);
                    record[..8].copy_from_slice(b"EEXTEND\0");
                    record[8..16]
                        .copy_from_slice(&(u64_at(page, 0) + index as u64 * 256).to_le_bytes());
                    hash.update(record);
                    hash.update(block);
                }
            }
        }
        if hash.finalize()[..] != self.css()[960..992] {
            return Err(Error::Enclave(
                "enclave pages differ from original signed measurement",
            ));
        }
        Ok(())
    }
    pub fn load(self, token: &[u8], cancel: &dyn Cancellation) -> Result<Image> {
        if token.len() != 304 {
            return Err(Error::Enclave("incorrect launch token length"));
        }
        cancel.check()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/dev/isgx")?;
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                self.size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error().into());
        }
        let image = Image {
            base,
            size: self.size,
            tcs: base as usize + self.tcs,
            file,
        };
        #[repr(C, align(4096))]
        struct Page([u8; abi::PAGE_BYTES]);
        #[repr(C, align(64))]
        struct Secinfo([u64; 8]);
        let mut secs = Page([0; abi::PAGE_BYTES]);
        secs.0[0..8].copy_from_slice(&(self.size as u64).to_le_bytes());
        secs.0[8..16].copy_from_slice(&(base as u64).to_le_bytes());
        secs.0[16..20].copy_from_slice(&1u32.to_le_bytes());
        secs.0[48..56].copy_from_slice(&self.flags.to_le_bytes());
        secs.0[56..64].copy_from_slice(&3u64.to_le_bytes());
        ioctl(
            &image.file,
            abi::CREATE,
            &abi::EnclaveCreate {
                src: secs.0.as_ptr() as u64,
            },
        )?;
        let mut data = Page([0; abi::PAGE_BYTES]);
        let mut secinfo = Secinfo([0; 8]);
        for page in self.bytes[HEADER_BYTES..]
            .chunks_exact(RECORD_BYTES)
            .take(self.pages)
        {
            cancel.check()?;
            data.0.copy_from_slice(&page[24..]);
            secinfo.0[0] = u64_at(page, 8);
            let add = abi::EnclaveAdd {
                addr: base as u64 + u64_at(page, 0),
                src: data.0.as_ptr() as u64,
                secinfo: secinfo.0.as_ptr() as u64,
                mrmask: if u32_at(page, 16) == 1 { 0xffff } else { 0 },
            };
            ioctl(&image.file, abi::ADD, &add)?;
        }
        cancel.check()?;
        ioctl(
            &image.file,
            abi::INIT,
            &abi::EnclaveInit {
                addr: base as u64,
                sigstruct: self.css().as_ptr() as u64,
                einittoken: token.as_ptr() as u64,
            },
        )?;
        cancel.check()?;
        Ok(image)
    }
}
fn ioctl<T>(file: &File, request: libc::c_ulong, value: &T) -> Result<()> {
    let result = unsafe { libc::ioctl(file.as_raw_fd(), request, std::ptr::from_ref(value)) };
    if result < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if result != 0 {
        return Err(Error::Enclave("isgx rejected original enclave image"));
    }
    Ok(())
}
pub(super) struct Image {
    base: *mut libc::c_void,
    size: usize,
    pub tcs: usize,
    file: File,
}
impl Image {
    pub fn release(mut self) -> Result<()> {
        if unsafe { libc::munmap(self.base, self.size) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        self.base = std::ptr::null_mut();
        Ok(())
    }
}
impl Drop for Image {
    fn drop(&mut self) {
        if !self.base.is_null() {
            unsafe { libc::munmap(self.base, self.size) };
        }
    }
}

pub(super) fn cpu_features() -> Result<[u64; 6]> {
    // The crate's Rust 1.85 minimum still declares this intrinsic unsafe.
    #[allow(unused_unsafe)]
    let c = unsafe { std::arch::x86_64::__cpuid_count(1, 0) }.ecx;
    if c & ((1 << 19) | (1 << 20)) != (1 << 19) | (1 << 20) {
        return Err(Error::Enclave("OEM runtime requires SSE4.1 and SSE4.2"));
    }
    let mut features = [0x3ff, 0, 1 << 63, 0, 0, 0];
    for (cpuid, feature) in [(20, 0x400), (25, 0x4000), (1, 0x2000), (30, 0x20000)] {
        if c & (1 << cpuid) != 0 {
            features[0] |= feature;
        }
    }
    Ok(features)
}
