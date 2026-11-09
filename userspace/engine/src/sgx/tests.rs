// SPDX-License-Identifier: GPL-2.0-only
use super::*;
use std::mem::{offset_of, size_of};

#[test]
fn original_c_and_isgx_layouts() {
    assert_eq!(size_of::<abi::EnclaveCreate>(), 8);
    assert_eq!(size_of::<abi::EnclaveAdd>(), 26);
    assert_eq!(size_of::<abi::EnclaveInit>(), 24);
    assert_eq!(abi::CREATE, 0x4008_a400);
    assert_eq!(abi::ADD, 0x401a_a401);
    assert_eq!(abi::INIT, 0x4018_a402);
    assert_eq!(size_of::<abi::Authorization>(), 40);
    assert_eq!(size_of::<abi::Whitelist>(), 24);
    assert_eq!(size_of::<abi::ImageBuffers>(), 40);
    assert_eq!(size_of::<abi::DhOutput>(), 32);
    assert_eq!(size_of::<abi::DhExchange>(), 48);
    assert_eq!(size_of::<abi::ImageCipher>(), 24);
    assert_eq!(size_of::<abi::NavSource>(), 24);
    assert_eq!(offset_of!(abi::NavSource, buffer), 8);
    assert_eq!(offset_of!(abi::NavSource, bytes), 16);
    assert_eq!(size_of::<abi::UpdateBase>(), 32);
    assert_eq!(size_of::<abi::FdtInitialize>(), 24);
    assert_eq!(size_of::<abi::PreprocessorInitialize>(), 48);
    assert_eq!(size_of::<abi::Preprocess>(), 56);
    assert_eq!(size_of::<abi::Attach>(), 96);
    assert_eq!(offset_of!(abi::Attach, settings), 80);
    assert_eq!(size_of::<abi::TemplateCompare>(), 56);
    assert_eq!(offset_of!(abi::TemplateCompare, new_image), 48);
    assert_eq!(offset_of!(abi::TemplateCompare, reserved), 49);
    assert_eq!(size_of::<abi::TemplateUpdate>(), 24);
    assert_eq!(size_of::<abi::OcallCalibration>(), 32);
    assert_eq!(size_of::<abi::OcallReadPmk>(), 32);
    assert_eq!(size_of::<abi::OcallWritePmk>(), 24);
    assert_eq!(size_of::<abi::OcallTls>(), 32);
}
#[test]
fn ocall_stack_bounds_and_unaligned_fields() {
    let mut stack = abi::Stack::new().unwrap();
    let start = stack.start() as usize;
    let unaligned = (start + 1) as abi::Pointer;
    stack.write(unaligned, 0x1234_5678u32).unwrap();
    assert_eq!(stack.read::<u32>(unaligned).unwrap(), 0x1234_5678);
    for address in [0, start - 1, usize::MAX, stack.top()] {
        assert!(stack.read::<u32>(address as abi::Pointer).is_err());
    }
    assert!(
        stack
            .validate((stack.top() - 1) as abi::Pointer, 2)
            .is_err()
    );
    assert!(stack.validate(stack.start(), usize::MAX).is_err());
    assert!(stack.validate(stack.top() as abi::Pointer, 0).is_ok());
    stack.wipe();
    assert_eq!(stack.read::<u32>(unaligned).unwrap(), 0);
}

fn package(pages: usize) -> Vec<u8> {
    let mut data = vec![0u8; 1856 + pages * 4120];
    data[..8].copy_from_slice(b"MPESGX01");
    data[8..16].copy_from_slice(&16384u64.to_le_bytes());
    data[16..20].copy_from_slice(&1u32.to_le_bytes());
    data[20..24].copy_from_slice(&(pages as u32).to_le_bytes());
    data[24..32].copy_from_slice(&4u64.to_le_bytes());
    data[32..40].copy_from_slice(&3u64.to_le_bytes());
    for index in 0..pages {
        let offset = 1856 + index * 4120;
        data[offset..offset + 8].copy_from_slice(&(index as u64 * 4096).to_le_bytes());
        data[offset + 8..offset + 16]
            .copy_from_slice(&(if index == 0 { 0x100u64 } else { 0x203u64 }).to_le_bytes());
        data[offset + 16..offset + 20].copy_from_slice(&1u32.to_le_bytes());
    }
    data
}
#[test]
fn loader_rejects_malformed_packages_before_hardware() {
    let valid = package(2);
    assert!(Package::parse(valid.clone()).is_ok());
    for length in [0, 47, 1855, 1856, valid.len() - 1] {
        assert!(Package::parse(valid[..length].to_vec()).is_err());
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(Package::parse(trailing).is_err());
    for (offset, value) in [
        (0, 0),
        (8, 3),
        (16, 2),
        (20, 0),
        (24, 6),
        (32, 7),
        (40, 1),
        (1856 + 16, 2),
        (1856 + 20, 1),
    ] {
        let mut malformed = valid.clone();
        malformed[offset] = value;
        assert!(Package::parse(malformed).is_err(), "offset {offset}");
    }
    let mut launch = valid.clone();
    launch[24..32].copy_from_slice(&0x24u64.to_le_bytes());
    assert!(Package::parse(launch).is_ok());
    let mut duplicate = valid.clone();
    duplicate[1856 + 4120..1856 + 4120 + 8].fill(0);
    assert!(Package::parse(duplicate).is_err());
    let mut outside = valid.clone();
    outside[1856..1864].copy_from_slice(&16384u64.to_le_bytes());
    assert!(Package::parse(outside).is_err());
    let mut missing_tcs = valid;
    missing_tcs[1864..1872].copy_from_slice(&0x203u64.to_le_bytes());
    assert!(Package::parse(missing_tcs).is_err());
}
#[test]
fn nav_crc_and_exact_unpacker_size() {
    assert_eq!(packed_crc(b"123456789"), 0x0376_e6e7);
    let mut nav = vec![0; NAV_PACKED + 4];
    let crc = packed_crc(&nav[..NAV_PACKED]).to_be_bytes();
    nav[NAV_PACKED..].copy_from_slice(&[crc[2], crc[3], crc[0], crc[1]]);
    assert!(validate_nav(&nav).is_ok());
    assert!(validate_nav(&nav[..nav.len() - 1]).is_err());
    nav[17] ^= 1;
    assert!(validate_nav(&nav).is_err());
    assert!(validate_nav(&[0; 4]).is_err());
}
#[test]
fn original_quality_rules_distinguish_enrollment_from_matching() {
    for enrollment in [false, true] {
        assert!(quality_accepted(0, 0, enrollment));
        assert!(!quality_accepted(0, -2, enrollment));
        for application in [1, -1, 0x8001, 0x8002, 0x8003] {
            assert!(!quality_accepted(application, 0, enrollment));
        }
    }
    assert!(!quality_accepted(0, -1, true));
    assert!(quality_accepted(0, -1, false));
}
