// SPDX-License-Identifier: GPL-2.0-only
// WBDI sealed baselines and the OEM goodix.dat host record.
use super::{Component, Runtime, UNSET, abi, application, packed_crc};
use crate::{
    Secret,
    error::{Error, Result},
};
use abi::{Pointer, buffer, pointer};
use zeroize::Zeroizing;

const FILE: &str = "goodix.dat";
const ID_BYTES: usize = 32;
const FDT_BYTES: usize = 24;
const NAV_BYTES: usize = 0x18c0 + 0x230;
const IMAGE_BYTES: usize = 0x7380 + 0x230;
const NAV_OFFSET: usize = ID_BYTES + FDT_BYTES;
const IMAGE_OFFSET: usize = NAV_OFFSET + NAV_BYTES;
const CRC_OFFSET: usize = IMAGE_OFFSET + IMAGE_BYTES;
const FILE_BYTES: usize = CRC_OFFSET + 4;

#[derive(Default)]
pub(super) struct BaseState {
    pub(super) exists: u32,
    pub(super) valid: u32,
    pub(super) need_update: bool,
    pub(super) identity: Zeroizing<[u8; ID_BYTES]>,
    // Already encoded for the FDT registers, not the raw FDT measurements.
    pub(super) fdt: Zeroizing<[u8; FDT_BYTES]>,
}

impl BaseState {
    fn saved(&mut self, result: Result<()>) {
        if let Err(error) = result {
            eprintln!("baseline: goodix.dat save failed: {error}");
        }
        // OEM save is void: even a short/failed file write marks the engine base.
        self.need_update = true;
    }
}

// Ordinals 11, 12 and 13 have no application-result field.
#[repr(C)]
struct SealedBaseSizes {
    nav: Pointer,
    image: Pointer,
}
#[repr(C)]
struct SealedBases {
    nav: Pointer,
    nav_bytes: u32,
    image: Pointer,
    image_bytes: u32,
}
#[repr(C)]
struct CheckBase {
    result: i32,
    need_update: Pointer,
    valid: Pointer,
}
#[repr(C)]
struct TemperatureClass {
    result: i32,
}

impl Runtime {
    /// The sensor's OEM OTP compatibility path validates this header separately.
    pub fn cached_identity(&self) -> Result<Option<Zeroizing<[u8; ID_BYTES]>>> {
        Ok(optional_file(self.state.read(FILE, ID_BYTES))
            .and_then(|bytes| bytes.as_slice().try_into().ok().map(Zeroizing::new)))
    }

    /// Import an identity/CRC-matched sealed base after WBDI buffer initialization.
    /// The caller supplies the complete, OEM-normalized 32-byte sensor identity.
    pub fn load_base(&mut self, identity: &[u8; ID_BYTES]) -> Result<Option<[u8; FDT_BYTES]>> {
        self.base = BaseState {
            identity: Zeroizing::new(*identity),
            ..BaseState::default()
        };
        self.sealed_base_sizes()?;
        let Some(mut bytes) = optional_file(self.state.read(FILE, FILE_BYTES)) else {
            return Ok(None);
        };
        let Some(fdt) = checked_fdt(&bytes, identity) else {
            return Ok(None);
        };
        let mut request = sealed_bases(&mut bytes);
        self.call(Component::Wbdi, 13, &mut request)?;
        // Ordinal 13 exposes only SGX status, not its internal unseal status.
        self.base.exists = 1;
        *self.base.fdt = fdt;
        Ok(Some(fdt))
    }

    pub fn base_exists(&self) -> bool {
        self.base.exists != 0
    }

    pub fn base_valid(&self) -> bool {
        self.base.valid != 0
    }

    /// Current IMAGE and NAV must already have been consumed via ordinals 5/6.
    pub fn commit_base(&mut self, encoded_fdt: &[u8; FDT_BYTES]) -> Result<()> {
        *self.base.fdt = *encoded_fdt;
        let (mut exists, mut valid, mut changed) = (self.base.exists, self.base.valid, 0u32);
        let mut request = abi::UpdateBase {
            result: UNSET,
            exists: pointer(&mut exists),
            valid: pointer(&mut valid),
            changed: pointer(&mut changed),
        };
        self.call(Component::Wbdi, 26, &mut request)?;
        application(request.result, "WBDI baseline update failed")?;
        self.base.valid = valid;
        if changed != 0 {
            self.save_base()?;
        }
        // Saving does not change exists: only a later file import does that.
        Ok(())
    }

    /// UP/RESET validation: the caller first acquires IMAGE, then NAV, and
    /// consumes both. Ordinal 27 updates those bases; it is not a status query.
    pub fn check_base(&mut self) -> Result<()> {
        let (mut need_update, mut valid) = (0u32, self.base.valid);
        let mut request = CheckBase {
            result: UNSET,
            need_update: pointer(&mut need_update),
            valid: pointer(&mut valid),
        };
        self.call(Component::Wbdi, 27, &mut request)?;
        if !matches!(request.result, 0 | 1) {
            return Err(Error::Enclave("WBDI baseline validation failed"));
        }
        self.base.valid = valid;
        if need_update != 0 {
            self.base.need_update = true;
        }
        if request.result == 1 {
            self.save_base()?;
        }
        Ok(())
    }

    /// Ordinal 25 clears the ring, classifies current IMAGE and then clears it.
    /// It does not consume a queued IMAGE: the caller must invoke ordinal 5 first.
    pub fn classify_temperature(&mut self) -> Result<i32> {
        let mut request = TemperatureClass { result: UNSET };
        self.call(Component::Wbdi, 25, &mut request)?;
        Ok(request.result)
    }

    fn sealed_base_sizes(&mut self) -> Result<()> {
        let (mut nav, mut image) = (0u32, 0u32);
        let mut request = SealedBaseSizes {
            nav: pointer(&mut nav),
            image: pointer(&mut image),
        };
        self.call(Component::Wbdi, 11, &mut request)?;
        if nav as usize != NAV_BYTES || image as usize != IMAGE_BYTES {
            return Err(Error::Enclave("incorrect MilanL sealed baseline sizes"));
        }
        Ok(())
    }

    fn save_base(&mut self) -> Result<()> {
        self.sealed_base_sizes()?;
        let mut bytes = base_file(&self.base.identity, &self.base.fdt);
        let mut request = sealed_bases(&mut bytes);
        self.call(Component::Wbdi, 12, &mut request)?;
        let crc = packed_crc(&bytes[..CRC_OFFSET]);
        bytes[CRC_OFFSET..].copy_from_slice(&crc.to_le_bytes());
        self.base.saved(self.state.write(FILE, &bytes));
        Ok(())
    }
}

fn optional_file(result: Result<Secret>) -> Option<Secret> {
    match result {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            // State still rejects unsafe paths/modes; an unusable cache is not
            // an initialization failure and is never imported into WBDI.
            eprintln!("baseline: goodix.dat unavailable: {error}");
            None
        }
    }
}

fn sealed_bases(bytes: &mut [u8]) -> SealedBases {
    SealedBases {
        nav: buffer(&mut bytes[NAV_OFFSET..IMAGE_OFFSET]),
        nav_bytes: NAV_BYTES as u32,
        image: buffer(&mut bytes[IMAGE_OFFSET..CRC_OFFSET]),
        image_bytes: IMAGE_BYTES as u32,
    }
}

fn base_file(identity: &[u8; ID_BYTES], fdt: &[u8; FDT_BYTES]) -> Secret {
    let mut bytes = Secret::new(vec![0; FILE_BYTES]);
    bytes[..ID_BYTES].copy_from_slice(identity);
    bytes[ID_BYTES..NAV_OFFSET].copy_from_slice(fdt);
    bytes
}

fn checked_fdt(bytes: &[u8], identity: &[u8; ID_BYTES]) -> Option<[u8; FDT_BYTES]> {
    if bytes.len() != FILE_BYTES
        || &bytes[..ID_BYTES] != identity
        || bytes[CRC_OFFSET..] != packed_crc(&bytes[..CRC_OFFSET]).to_le_bytes()
    {
        return None;
    }
    Some(
        bytes[ID_BYTES..NAV_OFFSET]
            .try_into()
            .expect("fixed FDT field"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    fn fixture() -> Secret {
        let mut bytes = base_file(&[0x19; ID_BYTES], &[0x2a; FDT_BYTES]);
        bytes[NAV_OFFSET..IMAGE_OFFSET].fill(0x31);
        bytes[IMAGE_OFFSET..CRC_OFFSET].fill(0x72);
        let crc = packed_crc(&bytes[..CRC_OFFSET]);
        bytes[CRC_OFFSET..].copy_from_slice(&crc.to_le_bytes());
        bytes
    }

    #[test]
    fn oem_baseline_marshalling_layouts() {
        assert_eq!(size_of::<SealedBaseSizes>(), 16);
        assert_eq!(offset_of!(SealedBaseSizes, image), 8);
        assert_eq!(size_of::<SealedBases>(), 32);
        assert_eq!(offset_of!(SealedBases, nav_bytes), 8);
        assert_eq!(offset_of!(SealedBases, image), 16);
        assert_eq!(offset_of!(SealedBases, image_bytes), 24);
        assert_eq!(size_of::<CheckBase>(), 24);
        assert_eq!(offset_of!(CheckBase, need_update), 8);
        assert_eq!(offset_of!(CheckBase, valid), 16);
        assert_eq!(size_of::<TemperatureClass>(), 4);
    }

    #[test]
    fn base_file_layout_preserves_encoded_fdt() {
        let bytes = fixture();
        assert_eq!(NAV_BYTES, 6896);
        assert_eq!(IMAGE_BYTES, 30128);
        assert_eq!(NAV_OFFSET, 56);
        assert_eq!(IMAGE_OFFSET, 6952);
        assert_eq!(CRC_OFFSET, 37080);
        assert_eq!(bytes.len(), 37084);
        assert_eq!(&bytes[..ID_BYTES], &[0x19; ID_BYTES]);
        assert_eq!(&bytes[NAV_OFFSET..IMAGE_OFFSET], &[0x31; NAV_BYTES]);
        assert_eq!(&bytes[IMAGE_OFFSET..CRC_OFFSET], &[0x72; IMAGE_BYTES]);
        // 0x2a2a is already encoded. Import must not halve/encode it a second time.
        assert_eq!(
            checked_fdt(&bytes, &[0x19; ID_BYTES]),
            Some([0x2a; FDT_BYTES])
        );
        assert_eq!(
            &bytes[CRC_OFFSET..],
            &packed_crc(&bytes[..CRC_OFFSET]).to_le_bytes()
        );
    }

    #[test]
    fn import_requires_length_crc_and_all_32_identity_bytes() {
        let bytes = fixture();
        for length in [0, ID_BYTES - 1, NAV_OFFSET, IMAGE_OFFSET, FILE_BYTES - 1] {
            assert!(checked_fdt(&bytes[..length], &[0x19; ID_BYTES]).is_none());
        }
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert!(checked_fdt(&longer, &[0x19; ID_BYTES]).is_none());
        let mut other_identity = [0x19; ID_BYTES];
        other_identity[31] ^= 1;
        assert!(checked_fdt(&bytes, &other_identity).is_none());
        for offset in [0, 31, ID_BYTES, NAV_OFFSET, IMAGE_OFFSET, CRC_OFFSET] {
            let mut corrupt = bytes.to_vec();
            corrupt[offset] ^= 1;
            assert!(checked_fdt(&corrupt, &[0x19; ID_BYTES]).is_none());
        }
    }

    #[test]
    fn file_errors_leave_the_live_base_usable_and_mark_engine_update() {
        use std::io::{Error as IoError, ErrorKind};
        assert!(
            optional_file(Err(Error::Io(IoError::from(ErrorKind::PermissionDenied)))).is_none()
        );
        assert!(optional_file(Err(Error::Device("synthetic unsafe cache"))).is_none());
        assert_eq!(&*optional_file(Ok(Secret::new(vec![42]))).unwrap(), &[42]);
        let mut base = BaseState {
            valid: 1,
            ..BaseState::default()
        };
        base.saved(Err(Error::Io(IoError::from(ErrorKind::WriteZero))));
        assert_eq!((base.exists, base.valid, base.need_update), (0, 1, true));
    }

    #[test]
    fn base_crc_is_mpeg2_and_new_state_is_not_imported() {
        assert_eq!(packed_crc(b"123456789"), 0x0376_e6e7);
        let base = BaseState::default();
        assert_eq!((base.exists, base.valid, base.need_update), (0, 0, false));
        assert_eq!(*base.identity, [0; ID_BYTES]);
        assert_eq!(*base.fdt, [0; FDT_BYTES]);
    }
}
