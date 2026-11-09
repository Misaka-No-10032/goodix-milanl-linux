//! The validated OEM DLL is a data source, never executable code.
use super::packet;
use crate::{
    Secret,
    error::{Error, Result},
};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const DLL_SHA256: [u8; 32] = [
    0xd9, 0x8e, 0x87, 0x3e, 0x02, 0xb0, 0x0d, 0x03, 0xd9, 0x0c, 0xcd, 0xd7, 0x8a, 0xc6, 0x96, 0x24,
    0x67, 0x6a, 0x6b, 0x9c, 0x36, 0x62, 0xce, 0x66, 0xdf, 0xca, 0x22, 0x05, 0x51, 0xb6, 0x75, 0xcd,
];
const CONFIG_OFFSET: usize = 0x92010;

pub(super) fn load(path: &Path) -> Result<Zeroizing<[u8; 256]>> {
    let dll = Secret::new(fs::read(path)?);
    extract(&dll)
}

fn extract(dll: &[u8]) -> Result<Zeroizing<[u8; 256]>> {
    let hash = Sha256::digest(dll);
    if !bool::from(hash[..].ct_eq(&DLL_SHA256)) {
        return Err(Error::Device("unsupported OEM configuration DLL"));
    }
    let source = dll
        .get(CONFIG_OFFSET..CONFIG_OFFSET + 256)
        .ok_or(Error::Device("truncated OEM configuration"))?;
    let mut config = Zeroizing::new([0; 256]);
    config.copy_from_slice(source);
    checksum(&mut config);
    Ok(config)
}

fn checksum(config: &mut [u8; 256]) {
    let sum = config[..254]
        .chunks_exact(2)
        .fold(0xa5a5u16, |sum, word| sum.wrapping_add(packet::word(word)));
    config[254..].copy_from_slice(&sum.wrapping_neg().to_le_bytes());
}

pub(super) fn identity(raw: &[u8; 32], cached: Option<&[u8; 32]>) -> (Zeroizing<[u8; 32]>, bool) {
    if let Some(cached) = cached.filter(|cached| cached[..16] == raw[..16]) {
        let mut identity = Zeroizing::new(*cached);
        if packet::check_otp(&mut identity) {
            return (identity, true);
        }
    }
    let mut identity = Zeroizing::new(*raw);
    let valid = packet::check_otp(&mut identity);
    (identity, valid)
}

fn register(config: &mut [u8; 256], header: usize, address: u16) -> Result<&mut [u8]> {
    let start = usize::from(config[header]);
    let size = usize::from(config[header + 1]);
    if start + size > 254 || size % 4 != 0 {
        return Err(Error::Device("invalid OEM register section"));
    }
    config[start..start + size]
        .chunks_exact_mut(4)
        .find(|register| packet::word(register) == address)
        .ok_or(Error::Device("OEM configuration register missing"))
}

pub(super) fn from_otp(
    config: &mut [u8; 256],
    otp: &[u8; 32],
    valid: bool,
    parameters: &mut [u16; 2],
) -> Result<(u8, u16)> {
    if !valid {
        // Invalid-OTP markers select the existing HAL parameters, not defaults.
        checksum(config);
        return Ok((parameters[0] as u8, parameters[1]));
    }
    if otp[22] == 0 || u16::from(otp[22]) + u16::from(otp[23]) != 255 {
        *parameters = [0, packet::word(&register(config, 9, 0x5c)?[2..])];
        checksum(config);
        // WBDI14 sees zeroes; HAL retains the default table's tcode afterwards.
        return Ok((0, 0));
    }
    let tcode = ((u16::from(otp[22]) >> 4) + 1) * 16;
    let delta = (((u32::from(otp[22] & 15) + 2) * 0x6400 / u32::from(tcode) / 3) >> 4) as u16;
    register(config, 9, 0x5c)?[2..4].copy_from_slice(&tcode.to_le_bytes());
    register(config, 5, 0x82)?[3] = delta as u8;
    *parameters = [delta, tcode];
    checksum(config);
    Ok((delta as u8, tcode))
}

#[derive(Default)]
pub(super) struct DacState {
    value: Zeroizing<u16>,
    pub(super) checked: bool,
}

impl DacState {
    pub(super) fn factory(&mut self, otp: &[u8; 32]) {
        if !self.checked {
            *self.value = (u16::from(otp[0x13] & 0x80) << 8) | u16::from(otp[0x1f]);
        }
    }

    pub(super) fn check(&mut self, read: &[u8]) -> Result<()> {
        if self.checked {
            return Ok(());
        }
        if read.len() != 2 {
            return Err(Error::Device("invalid DAC read length"));
        }
        let word = packet::word(read);
        if word >> 4 != *self.value {
            return Err(Error::Device("OEM raw-OTP DAC comparison failed"));
        }
        *self.value = (*self.value << 4) | (word & 15);
        self.checked = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn otp() -> [u8; 32] {
        let mut otp = std::array::from_fn(|index| index as u8);
        otp[22..24].copy_from_slice(&[0x53, 0xac]);
        otp[30] = packet::crc8(otp[..20].iter().copied().chain([otp[29], otp[31]]));
        otp
    }

    fn config() -> Zeroizing<[u8; 256]> {
        let mut config = Zeroizing::new([0; 256]);
        config[5..7].copy_from_slice(&[0xa1, 4]);
        config[9..11].copy_from_slice(&[0xd5, 4]);
        config[0xa1..0xa5].copy_from_slice(&[0x82, 0, 0x7f, 0x15]);
        config[0xd5..0xd9].copy_from_slice(&[0x5c, 0, 0x80, 0]);
        checksum(&mut config);
        config
    }

    #[test]
    fn otp_config_uses_exact_sections_and_checksum() {
        let mut config = config();
        let mut parameters = [0; 2];
        assert_eq!(
            from_otp(&mut config, &otp(), true, &mut parameters).unwrap(),
            (27, 96)
        );
        assert_eq!(parameters, [27, 96]);
        assert_eq!(&config[0xd7..0xd9], &[0x60, 0]);
        assert_eq!(&config[0xa3..0xa5], &[0x7f, 27]);
        assert_eq!(
            config
                .chunks_exact(2)
                .fold(0u16, |sum, bytes| sum.wrapping_add(packet::word(bytes))),
            0x5a5b
        );
    }

    #[test]
    fn invalid_tcode_pair_retains_oem_defaults() {
        let mut config = config();
        let before = config.clone();
        let mut otp = otp();
        let mut parameters = [27, 96];
        otp[22..24].fill(0);
        assert_eq!(
            from_otp(&mut config, &otp, true, &mut parameters).unwrap(),
            (0, 0)
        );
        assert_eq!(parameters, [0, 128]);
        assert_eq!(*config, *before);
        assert_eq!(
            from_otp(&mut config, &otp, false, &mut parameters).unwrap(),
            (0, 128)
        );
    }

    #[test]
    fn invalid_otp_keeps_existing_hal_parameters_without_modifying_table() {
        let mut parameters = [0; 2];
        assert_eq!(
            from_otp(&mut config(), &otp(), false, &mut parameters).unwrap(),
            (0, 0)
        );
        from_otp(&mut config(), &otp(), true, &mut parameters).unwrap();
        let mut table = config();
        let before = table.clone();
        assert_eq!(
            from_otp(&mut table, &otp(), false, &mut parameters).unwrap(),
            (27, 96)
        );
        assert_eq!(*table, *before);
    }

    #[test]
    fn corrupt_sections_and_unpinned_dll_are_rejected() {
        let mut config = config();
        config[5] = 255;
        assert!(from_otp(&mut config, &otp(), true, &mut [0; 2]).is_err());
        assert!(extract(&[0; 256]).is_err());
    }

    #[test]
    fn cached_identity_requires_matching_prefix_and_valid_oem_checksum() {
        let raw = otp();
        let mut cached = raw;
        cached[31] ^= 0x5a;
        cached[30] = packet::crc8(cached[..20].iter().copied().chain([cached[29], cached[31]]));
        let mut expected = cached;
        expected[26..29].fill(0);
        let (selected, valid) = identity(&raw, Some(&cached));
        assert!(valid);
        assert_eq!(*selected, expected);

        let (raw_identity, _) = identity(&raw, None);
        cached[0] ^= 1;
        cached[30] = packet::crc8(cached[..20].iter().copied().chain([cached[29], cached[31]]));
        assert_eq!(*identity(&raw, Some(&cached)).0, *raw_identity);
        cached[..16].copy_from_slice(&raw[..16]);
        let mut invalid = cached;
        assert!(!packet::check_otp(&mut invalid));
        assert_eq!(*identity(&raw, Some(&cached)).0, *raw_identity);
    }

    #[test]
    fn dac_guard_compares_raw_coarse_field_and_normalizes_only_once() {
        let mut otp = otp();
        otp[0x1f] = 0x27;
        let mut dac = DacState::default();
        dac.factory(&otp);
        for wrong in [&[0x27, 0][..], &[0x22, 0], &[0x78]] {
            assert!(dac.check(wrong).is_err());
            assert!(!dac.checked);
            assert_eq!(*dac.value, 0x27);
        }
        dac.check(&[0x78, 0x02]).unwrap();
        assert!(dac.checked);
        assert_eq!(*dac.value, 0x278);
        otp[0x1f] = 0x55;
        dac.factory(&otp);
        dac.check(&[]).unwrap();
        assert_eq!(*dac.value, 0x278);
    }

    #[test]
    fn dac_high_otp_bit_is_not_reinterpreted_as_a_shifted_register_field() {
        let mut otp = otp();
        otp[0x13] |= 0x80;
        otp[0x1f] = 0x27;
        let mut dac = DacState::default();
        dac.factory(&otp);
        assert_eq!(*dac.value, 0x8027);
        assert!(dac.check(&[0x78, 0x02]).is_err());
        assert!(!dac.checked);
    }
}
