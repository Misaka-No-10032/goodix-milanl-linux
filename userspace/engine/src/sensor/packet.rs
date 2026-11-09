//! MilanL mailbox framing. Packed NAV data stays packed; TLS stays opaque.
use crate::{
    Secret,
    error::{Error, Result},
};
use zeroize::Zeroizing;

pub(super) const RX_BYTES: usize = 0x7000;
pub(super) const TLS_CHUNK: usize = 4092;
pub(super) const NAV_PACKED: usize = 0x1290;
pub(super) const NAV_SOURCE: usize = NAV_PACKED + 4;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Control,
    Tls,
}

pub(super) fn word(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn sum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte))
}

pub(super) fn envelope(frame: &[u8]) -> Result<Kind> {
    if !(4..=RX_BYTES).contains(&frame.len())
        || frame[3] != sum(&frame[..3])
        || usize::from(word(&frame[1..3])) + 4 != frame.len()
    {
        return Err(Error::Device("invalid mailbox envelope"));
    }
    match frame[0] {
        0xa0 if frame.len() >= 8 && usize::from(word(&frame[5..7])) + 7 == frame.len() => {
            Ok(Kind::Control)
        }
        0xb0 if frame.len() > 4 => Ok(Kind::Tls),
        _ => Err(Error::Device(
            "invalid mailbox kind, channel or inner length",
        )),
    }
}

pub(super) fn control(frame: &[u8], command: u8, bytes: Option<usize>) -> Result<&[u8]> {
    if envelope(frame)? != Kind::Control
        || frame[4] != command
        || bytes.is_some_and(|bytes| frame.len() != bytes + 8)
        || sum(&frame[4..]) != 0xaa
    {
        return Err(Error::Device("invalid control response"));
    }
    Ok(&frame[7..frame.len() - 1])
}

pub(super) fn ack(frame: &[u8]) -> Result<Option<u8>> {
    if envelope(frame)? != Kind::Control || frame[4] != 0xb0 {
        return Ok(None);
    }
    let data = control(frame, 0xb0, Some(2))?;
    if data[1] != 1 {
        return Err(Error::Device("MCU rejected command"));
    }
    Ok(Some(data[0]))
}

pub(super) fn command(command: u8, data: &[u8]) -> Secret {
    // Only fixed, private command builders in this module supply these lengths.
    let mut frame = Secret::new(vec![0; data.len() + 8]);
    frame[0] = 0xa0;
    frame[1..3].copy_from_slice(&((data.len() + 4) as u16).to_le_bytes());
    frame[3] = sum(&frame[..3]);
    frame[4] = command;
    frame[5..7].copy_from_slice(&((data.len() + 1) as u16).to_le_bytes());
    frame[7..7 + data.len()].copy_from_slice(data);
    let last = frame.len() - 1;
    frame[last] = 0xaau8.wrapping_sub(sum(&frame[4..last]));
    frame
}

pub(super) fn tls(data: &[u8]) -> Result<Secret> {
    if !(1..=TLS_CHUNK).contains(&data.len()) {
        return Err(Error::Device("invalid TLS transmit length"));
    }
    let mut frame = Secret::new(vec![0; data.len() + 4]);
    frame[0] = 0xb0;
    frame[1..3].copy_from_slice(&(data.len() as u16).to_le_bytes());
    frame[3] = sum(&frame[..3]);
    frame[4..].copy_from_slice(data);
    Ok(frame)
}

pub(super) fn register_request(address: u16, bytes: u16) -> Secret {
    let address = address.to_le_bytes();
    let bytes = bytes.to_le_bytes();
    command(0x82, &[0, address[0], address[1], bytes[0], bytes[1]])
}

pub(super) fn registers(frame: &[u8], bytes: usize) -> Result<Secret> {
    let data = control(frame, 0x82, Some(bytes))?;
    let mut result = Secret::new(data.to_vec());
    for pair in result.chunks_exact_mut(2) {
        pair.swap(0, 1);
    }
    Ok(result)
}

pub(super) fn chip_id(frame: &[u8]) -> Result<u32> {
    let data = registers(frame, 4)?;
    Ok(u32::from_le_bytes([data[1], data[2], data[3], 0]))
}

pub(super) fn crc8(bytes: impl IntoIterator<Item = u8>) -> u8 {
    let mut value = 0u8;
    for byte in bytes {
        value ^= byte;
        for _ in 0..8 {
            value = (value << 1) ^ if value & 0x80 != 0 { 7 } else { 0 };
        }
    }
    value ^ 0xff
}

/// gfspi!OtpCheck (0x18003f9dc), including the legacy format metadata fixup.
/// The caller rejects an entirely zero read before invoking this function.
pub(super) fn check_otp(otp: &mut [u8; 32]) -> bool {
    let legacy = (otp[8..18].iter().all(|byte| *byte == 0) && otp[30] == 0)
        || otp[..20]
            .iter()
            .chain([&otp[29], &otp[31]])
            .fold(0u8, |sum, byte| sum.wrapping_add(*byte))
            == otp[30]
        || crc8(otp[..20].iter().copied().chain([otp[29], otp[31]])) == otp[30];
    if legacy {
        otp[26..29].fill(0);
        return true;
    }
    let suffix = if otp[28] == 0xc0 {
        &otp[28..30]
    } else {
        &otp[26..30]
    };
    if crc8(otp[..20].iter().chain(suffix).copied().chain([otp[31]])) == otp[30] {
        return true;
    }
    // These are host-side diagnostic markers, never writes to sensor OTP.
    otp[10..12].copy_from_slice(&[0x5a, 0xa5]);
    otp[26..29].copy_from_slice(&[0xf1, 0xfb, 9]);
    false
}

pub(super) fn otp(frame: &[u8]) -> Result<Secret> {
    let data = control(frame, 0xa6, Some(32))?;
    if data.iter().all(|byte| *byte == 0) {
        return Err(Error::Device("empty sensor OTP"));
    }
    Ok(Secret::new(data.to_vec()))
}

pub(super) fn tls_state(frame: &[u8]) -> Result<(bool, bool)> {
    let state = control(frame, 0xae, Some(10))?;
    Ok((state[0] & 2 != 0, state[0] & 8 != 0))
}

pub(super) fn fdt(frame: &[u8]) -> Result<(u16, &[u8; 26])> {
    if envelope(frame)? != Kind::Control || frame[4] & 0xf1 != 0x30 {
        return Err(Error::Device("unexpected FDT command"));
    }
    let data = control(frame, frame[4], Some(28))?;
    let touch = data[2..]
        .try_into()
        .map_err(|_| Error::Device("invalid FDT length"))?;
    Ok((word(data), touch))
}

pub(super) fn manual_fdt(frame: &[u8]) -> Result<&[u8; 24]> {
    let (irq, touch) = fdt(frame)?;
    if irq != 0x100 {
        return Err(Error::Device("manual FDT interrupt missing"));
    }
    Ok(touch[2..].try_into().expect("validated FDT size"))
}

pub(super) fn down_base(raw: &[u8; 24]) -> Zeroizing<[u8; 24]> {
    let mut down = Zeroizing::new([0; 24]);
    for (raw, out) in raw.chunks_exact(2).zip(down.chunks_exact_mut(2)) {
        out.copy_from_slice(&(u32::from(word(raw) >> 1).wrapping_mul(0x101) as u16).to_le_bytes());
    }
    down
}

pub(super) fn up_base(touch: &[u8; 26], threshold: u8) -> Zeroizing<[u8; 24]> {
    let flags = word(touch);
    let delta = u32::from(if threshold == 0 { 0x15 } else { threshold });
    let mut base = Zeroizing::new([0; 24]);
    for (i, out) in base.chunks_exact_mut(2).enumerate() {
        let value = u32::from(word(&touch[2 + i * 2..]) >> 1) + delta;
        let mut result = ((value << 8) | value) & 0xffff;
        if flags & (1 << i) == 0 {
            result = ((delta.wrapping_sub(2) << 8) | (result >> 8)) & 0xffff;
        }
        out.copy_from_slice(&(result as u16).to_le_bytes());
    }
    base
}

pub(super) fn fdt_request(command_byte: u8, mode: u8, base: &[u8; 24]) -> Secret {
    let mut data = Zeroizing::new([0; 34]);
    data[..2].copy_from_slice(&[mode, 1]);
    data[2..26].copy_from_slice(base);
    command(command_byte, data.as_slice())
}

pub(super) fn crc32_mpeg(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in data {
        crc ^= u32::from(*byte) << 24;
        for _ in 0..8 {
            crc = (crc << 1)
                ^ if crc & 0x8000_0000 != 0 {
                    0x04c1_1db7
                } else {
                    0
                };
        }
    }
    crc
}

pub(super) fn nav(frame: &[u8]) -> Result<Secret> {
    if envelope(frame)? != Kind::Control
        || frame.len() != NAV_PACKED + 17
        || frame[4] != 0x50
        || frame[frame.len() - 1] != 0x88
    {
        return Err(Error::Device("invalid NAV wire framing"));
    }
    let source = &frame[12..12 + NAV_SOURCE];
    let footer = &source[NAV_PACKED..];
    let expected = u32::from_be_bytes([footer[2], footer[3], footer[0], footer[1]]);
    if crc32_mpeg(&source[..NAV_PACKED]) != expected {
        return Err(Error::Device("invalid packed NAV CRC"));
    }
    Ok(Secret::new(source.to_vec()))
}
