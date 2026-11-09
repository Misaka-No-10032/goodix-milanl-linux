//! Synthetic protocol fixtures only; no raw device, OEM binary or biometric data.
use super::*;

fn ack(target: u8) -> Secret {
    packet::command(0xb0, &[target, 1])
}

fn fdt(irq: u16) -> Secret {
    let mut data = Zeroizing::new([0; 28]);
    data[..2].copy_from_slice(&irq.to_le_bytes());
    data[2..4].copy_from_slice(&0x0fffu16.to_le_bytes());
    for (i, word) in data[4..].chunks_exact_mut(2).enumerate() {
        word.copy_from_slice(&(1200 + i as u16).to_le_bytes());
    }
    packet::command(0x36, data.as_slice())
}

fn nav() -> Secret {
    let mut frame = packet::command(0x50, &vec![0; packet::NAV_PACKED + 9]);
    let crc = packet::crc32_mpeg(&frame[12..12 + packet::NAV_PACKED]).to_be_bytes();
    let end = 12 + packet::NAV_PACKED;
    frame[end..end + 4].copy_from_slice(&[crc[2], crc[3], crc[0], crc[1]]);
    frame[end + 4] = 0x88;
    frame
}

fn exchange(reply: Option<Reply>) -> Exchange {
    Exchange::new(0x36, true, reply, CONTROL_TIMEOUT)
}

#[test]
fn command_frames_match_oem_wire_bytes() {
    assert_eq!(
        packet::register_request(0, 4).as_slice(),
        &[0xa0, 9, 0, 0xa9, 0x82, 6, 0, 0, 0, 0, 4, 0, 0x1e]
    );
    assert_eq!(
        packet::command(0x20, &[1, 0]).as_slice(),
        &[0xa0, 6, 0, 0xa6, 0x20, 3, 0, 1, 0, 0x86]
    );
    assert_eq!(
        packet::command(0x70, &[0x14, 0]).as_slice(),
        &[0xa0, 6, 0, 0xa6, 0x70, 3, 0, 0x14, 0, 0x23]
    );
    assert_eq!(
        packet::command(0xd0, &[0, 0]).as_slice(),
        &[0xa0, 6, 0, 0xa6, 0xd0, 3, 0, 0, 0, 0xd7]
    );
    assert_eq!(
        packet::command(0xd4, &[0, 0]).as_slice(),
        &[0xa0, 6, 0, 0xa6, 0xd4, 3, 0, 0, 0, 0xd3]
    );
    assert_eq!(
        packet::command(0xa2, &[5, 0x14]).as_slice(),
        &[0xa0, 6, 0, 0xa6, 0xa2, 3, 0, 5, 0x14, 0xec]
    );
    assert_eq!(
        packet::command(0x96, &[1, 0]).as_slice(),
        &[0xa0, 6, 0, 0xa6, 0x96, 3, 0, 1, 0, 0x10]
    );
}

#[test]
fn envelope_and_control_validate_both_lengths_checksums_and_channel() {
    let valid = ack(0x36);
    for position in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9] {
        let mut bad = valid.clone();
        bad[position] ^= 1;
        assert!(packet::control(&bad, 0xb0, Some(2)).is_err());
    }
    for length in 0..valid.len() {
        assert!(packet::control(&valid[..length], 0xb0, Some(2)).is_err());
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(packet::envelope(&trailing).is_err());
    assert!(packet::ack(&packet::command(0xb0, &[0x36, 0])).is_err());
    assert!(packet::ack(&packet::command(0xb0, &[0x36, 2])).is_err());
}

#[test]
fn register_pairs_are_swapped_before_chip_and_threshold_decode() {
    let frame = packet::command(0x82, &[5, 0xa2, 0, 0x22]);
    assert_eq!(packet::chip_id(&frame).unwrap(), 0x2205);
    let frame = packet::command(0x82, &[0x2a, 0x7f]);
    let value = packet::registers(&frame, 2).unwrap();
    assert_eq!(value.as_slice(), &[0x7f, 0x2a]);
    assert_eq!(value[1], 0x2a);
    assert!(packet::registers(&frame, 4).is_err());
}

#[test]
fn otp_transport_rejects_empty_reads_but_preserves_bytes_for_oem_validation() {
    let otp: [u8; 32] = std::array::from_fn(|index| index as u8);
    assert_eq!(
        packet::otp(&packet::command(0xa6, &otp))
            .unwrap()
            .as_slice(),
        &otp
    );
    assert!(packet::otp(&packet::command(0xa6, &[0; 32])).is_err());
    assert!(packet::otp(&packet::command(0xa6, &[1; 31])).is_err());
}

#[test]
fn otp_accepts_all_five_oem_formats_and_normalizes_only_legacy_metadata() {
    assert_eq!(packet::crc8(b"123456789".iter().copied()), 0x0b);
    for format in 0..5 {
        let mut otp: [u8; 32] = std::array::from_fn(|index| index as u8);
        match format {
            0 => {
                otp[8..18].fill(0);
                otp[30] = 0;
            }
            1 => {
                otp[30] = otp[..20]
                    .iter()
                    .chain([&otp[29], &otp[31]])
                    .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
            }
            2 => otp[30] = packet::crc8(otp[..20].iter().copied().chain([otp[29], otp[31]])),
            3 => {
                otp[28] = 0xc0;
                otp[30] =
                    packet::crc8(otp[..20].iter().copied().chain([otp[28], otp[29], otp[31]]));
            }
            4 => {
                otp[30] = packet::crc8(
                    otp[..20]
                        .iter()
                        .chain(&otp[26..30])
                        .copied()
                        .chain([otp[31]]),
                );
            }
            _ => unreachable!(),
        }
        let before = otp;
        assert!(packet::check_otp(&mut otp), "format {format}");
        assert_eq!(&otp[..26], &before[..26]);
        assert_eq!(&otp[29..], &before[29..]);
        assert_eq!(
            &otp[26..29],
            if format < 3 { &[0; 3] } else { &before[26..29] }
        );
    }
}

#[test]
fn invalid_otp_sets_host_diagnostic_markers_instead_of_rejecting_initialization() {
    let mut otp: [u8; 32] = std::array::from_fn(|index| index as u8);
    let before = otp;
    assert!(!packet::check_otp(&mut otp));
    assert_eq!(&otp[10..12], &[0x5a, 0xa5]);
    assert_eq!(&otp[26..29], &[0xf1, 0xfb, 9]);
    for index in (0..10).chain(12..26).chain(29..32) {
        assert_eq!(otp[index], before[index]);
    }
}

#[test]
fn authenticated_and_locked_mcu_flags_are_independent() {
    for (flags, expected) in [
        (0, (false, false)),
        (2, (true, false)),
        (0x0a, (true, true)),
        (8, (false, true)),
    ] {
        let mut state = [0; 10];
        state[0] = flags;
        assert_eq!(
            packet::tls_state(&packet::command(0xae, &state)).unwrap(),
            expected
        );
    }
    assert!(packet::tls_state(&packet::command(0xae, &[2; 9])).is_err());
}

#[test]
fn fdt_requires_real_checksum_manual_irq_and_exact_words() {
    let frame = fdt(0x100);
    let raw = packet::manual_fdt(&frame).unwrap();
    assert_eq!(packet::word(raw), 1200);
    for irq in [0x002, 0x200, 0x400] {
        assert!(packet::manual_fdt(&fdt(irq)).is_err());
    }
    let mut corrupted = frame.clone();
    corrupted[11] ^= 1;
    assert!(packet::manual_fdt(&corrupted).is_err());
    let mut sentinel = frame.clone();
    sentinel[35] = 0x88;
    assert!(packet::manual_fdt(&sentinel).is_err());
    let down = packet::down_base(raw);
    for (raw, down) in raw.chunks_exact(2).zip(down.chunks_exact(2)) {
        assert_eq!(
            packet::word(down),
            ((u32::from(packet::word(raw)) >> 1) * 0x101) as u16
        );
    }
    let request = packet::fdt_request(0x36, 0x0d, &down);
    let payload = packet::control(&request, 0x36, Some(34)).unwrap();
    assert_eq!(&payload[..2], &[0x0d, 1]);
    assert_eq!(&payload[26..], &[0; 8]);
    assert_eq!(packet::command(0x36, &[0x0d, 0]).len(), 10);
}

#[test]
fn fdt_up_preserves_touch_flags_and_oem_default_threshold() {
    let mut touch = Zeroizing::new([0; 26]);
    touch[..2].copy_from_slice(&0x0555u16.to_le_bytes());
    for word in touch[2..].chunks_exact_mut(2) {
        word.copy_from_slice(&100u16.to_le_bytes());
    }
    for (threshold, touched, untouched) in [(0, 0x4747, 0x1347), (0x2a, 0x5c5c, 0x285c)] {
        let up = packet::up_base(&touch, threshold);
        for (index, word) in up.chunks_exact(2).enumerate() {
            assert_eq!(
                packet::word(word),
                if index % 2 == 0 { touched } else { untouched }
            );
        }
    }
}

#[test]
fn packed_nav_is_exact_source_including_crc_without_pixel_unpacking() {
    assert_eq!(packet::crc32_mpeg(b"123456789"), 0x0376_e6e7);
    let frame = nav();
    assert_eq!(frame.len(), 4769);
    let source = packet::nav(&frame).unwrap();
    assert_eq!(source.len(), 0x1294);
    assert_eq!(source.as_slice(), &frame[12..4768]);
    for position in [4, 5, 12, 4764, 4768] {
        let mut bad = frame.clone();
        bad[position] ^= 1;
        assert!(packet::nav(&bad).is_err());
    }
    assert!(packet::nav(&frame[..4768]).is_err());
}

#[test]
fn transaction_allows_data_before_ack_but_not_duplicate_or_wrong_packets() {
    let mut optional = OptionalAcks([0; 256]);
    for ack_first in [true, false] {
        let mut exchange = exchange(Some(Reply::ManualFdt));
        let packets = if ack_first {
            [ack(0x36), fdt(0x100)]
        } else {
            [fdt(0x100), ack(0x36)]
        };
        exchange.accept(&packets[0], &mut optional).unwrap();
        assert!(!exchange.complete());
        exchange.accept(&packets[1], &mut optional).unwrap();
        assert!(exchange.complete());
        assert!(exchange.accept(&ack(0x36), &mut optional).is_err());
        assert!(exchange.accept(&fdt(0x100), &mut optional).is_err());
    }
    assert!(
        exchange(Some(Reply::ManualFdt))
            .accept(&ack(0x50), &mut optional)
            .is_err()
    );
    assert!(
        exchange(Some(Reply::ManualFdt))
            .accept(&fdt(0x002), &mut optional)
            .is_err()
    );
    assert!(exchange(None).accept(&fdt(0x100), &mut optional).is_err());
}

#[test]
fn optional_ack_may_arrive_after_its_data_not_after_an_unsent_command() {
    let mut optional = OptionalAcks([0; 256]);
    optional.expect(0xae);
    let mut current = exchange(Some(Reply::ManualFdt));
    current.accept(&ack(0xae), &mut optional).unwrap();
    assert!(!current.complete());
    assert!(current.accept(&ack(0xae), &mut optional).is_err());
    assert!(current.accept(&ack(0xd4), &mut optional).is_err());
}

#[test]
fn ack_timeout_retransmits_once_even_with_early_data_but_never_for_missing_data() {
    let mut optional = OptionalAcks([0; 256]);
    let mut current = exchange(Some(Reply::ManualFdt));
    current.accept(&fdt(0x100), &mut optional).unwrap();
    assert!(current.retry());
    assert!(!current.retry());
    optional.expect(0x36);
    current.accept(&ack(0x36), &mut optional).unwrap();
    assert!(current.complete());
    current.accept(&ack(0x36), &mut optional).unwrap();
    assert!(current.accept(&ack(0x36), &mut optional).is_err());

    let mut current = exchange(Some(Reply::ManualFdt));
    current.accept(&ack(0x36), &mut optional).unwrap();
    assert!(!current.complete());
    assert!(!current.retry());
    let mut optional_only = Exchange::new(
        0xae,
        false,
        Some(Reply::Control(0xae, Some(10))),
        CONTROL_TIMEOUT,
    );
    assert!(!optional_only.retry());
}

#[test]
fn ack_and_data_have_independent_oem_minimum_waits() {
    for timeout in [
        Duration::from_millis(200),
        Duration::from_millis(500),
        Duration::from_secs(2),
    ] {
        let before = Instant::now();
        let mut current = Exchange::new(0x36, true, Some(Reply::ManualFdt), timeout);
        let after = Instant::now();
        assert!(current.deadline >= before + ACK_TIMEOUT);
        assert!(current.deadline <= after + ACK_TIMEOUT);
        let data_timeout = timeout.max(Duration::from_secs(1));
        assert_eq!(current.data_timeout, data_timeout);

        current.deadline = before;
        let before = Instant::now();
        current
            .accept(&ack(0x36), &mut OptionalAcks([0; 256]))
            .unwrap();
        let after = Instant::now();
        assert!(current.deadline >= before + data_timeout);
        assert!(current.deadline <= after + data_timeout);
    }
}

#[test]
fn late_data_requires_an_outstanding_transmitted_reply_and_valid_framing() {
    let mut late = LateReplies([0; 256]);
    let data = packet::command(0xa6, &[1; 32]);
    assert!(!late.accept(&data).unwrap());
    late.expect(0xa6);
    late.expect(0xa6);
    let mut corrupt = data.clone();
    corrupt[7] ^= 1;
    assert!(late.accept(&corrupt).is_err());
    assert!(!late.accept(&packet::command(0xa8, &[0; 4])).unwrap());
    assert!(late.accept(&data).unwrap());
    assert!(late.accept(&data).unwrap());
    assert!(!late.accept(&data).unwrap());

    late.expect(0x50);
    let mut corrupt = nav();
    corrupt[12] ^= 1;
    assert!(late.accept(&corrupt).is_err());
    assert!(late.accept(&nav()).unwrap());
    assert!(!late.accept(&nav()).unwrap());
}

#[test]
fn tls_queue_keeps_duplicates_handles_partial_reads_and_erases_consumed_bytes() {
    let mut queue = TlsQueue::default();
    queue.push(&[1, 2, 3]).unwrap();
    queue.push(&[1, 2, 3]).unwrap();
    let mut output = Zeroizing::new([0; 4]);
    assert_eq!(queue.read(&mut output[..2]), 2);
    assert_eq!(&output[..2], &[1, 2]);
    assert_eq!(queue.frames[0].as_slice(), &[0, 0, 3]);
    assert_eq!(queue.read(output.as_mut_slice()), 4);
    assert_eq!(*output, [3, 1, 2, 3]);
    assert_eq!(queue.bytes, 0);
    assert!(queue.frames.is_empty());
    queue.push(&vec![0; TLS_QUEUE_LIMIT]).unwrap();
    assert!(queue.push(&[0]).is_err());
}

#[test]
fn tls_transmit_chunks_and_image_evidence_allow_multiple_transport_packets() {
    for length in [1, 4092] {
        let data = Secret::new(vec![0x5a; length]);
        let frame = packet::tls(&data).unwrap();
        assert!(packet::envelope(&frame).unwrap() == Kind::Tls);
        assert_eq!(&frame[4..], data.as_slice());
    }
    assert!(packet::tls(&[]).is_err());
    assert!(packet::tls(&[0; 4093]).is_err());
    assert!(ImageEvidence::default().verify().is_err());
    let mut image = ImageEvidence {
        prepared: true,
        requested: true,
        acknowledged: true,
        tls_frames: 2,
    };
    assert!(image.verify().is_ok());
    image.tls_frames = 0;
    assert!(image.verify().is_err());
    image.tls_frames = 1;
    image.acknowledged = false;
    assert!(image.verify().is_err());
}
