//! OEM FDT state and commands. Session owns classification, timers and WBDI calls.
use super::{CONTROL_TIMEOUT, Reply, Sensor, device::Wait, packet};
use crate::{
    Secret,
    error::{Error, Result},
};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const BASELINE_WAIT: Duration = Duration::from_millis(500);
const POST_CAPTURE_WAIT: Duration = Duration::from_millis(200);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TouchEvent {
    Down,
    Up,
    Reset,
    Reverse,
    Wrong,
}

#[derive(Default)]
pub(super) struct TouchState {
    // Both arrays contain encoded register words, never raw FDT measurements.
    down: Zeroizing<[u8; 24]>,
    up: Zeroizing<[u8; 24]>,
    saved_flags: u16,
    pressed: bool,
    threshold: u8,
    pending: VecDeque<Secret>,
}

impl TouchState {
    fn queue(&mut self, frame: &[u8]) -> Result<()> {
        packet::fdt(frame)?;
        self.pending.push_back(Secret::new(frame.to_vec()));
        Ok(())
    }

    fn restore(&mut self, encoded: &[u8; 24]) {
        *self.down = *encoded;
        *self.up = *encoded;
    }

    fn keep_manual(&mut self, frame: &[u8]) -> Result<[u8; 24]> {
        let raw = packet::manual_fdt(frame)?;
        self.down = packet::down_base(raw);
        Ok(*raw)
    }

    fn post_capture(&mut self, frame: &[u8]) -> Result<()> {
        let (irq, measurements) = packet::fdt(frame)?;
        if irq != 0x100 {
            return Err(Error::Device("manual FDT interrupt missing"));
        }
        let mut merged = Zeroizing::new(*measurements);
        let flags = packet::word(&merged[..2]) | self.saved_flags;
        merged[..2].copy_from_slice(&flags.to_le_bytes());
        let candidate = packet::up_base(&merged, self.threshold);
        for (previous, next) in self.up.chunks_exact_mut(2).zip(candidate.chunks_exact(2)) {
            let value = packet::word(previous).min(packet::word(next));
            previous.copy_from_slice(&value.to_le_bytes());
        }
        // Post-capture manual FDT does not update DOWN or replace saved DOWN flags.
        Ok(())
    }

    fn event(&mut self, frame: &[u8]) -> Result<Option<TouchEvent>> {
        let (irq, measurements) = packet::fdt(frame)?;
        let raw = measurements[2..].try_into().expect("validated FDT size");
        let event = match irq {
            0x002 => {
                self.saved_flags = packet::word(measurements);
                self.up = packet::up_base(measurements, self.threshold);
                self.pressed = true;
                TouchEvent::Down
            }
            0x200 => {
                self.down = packet::down_base(raw);
                self.pressed = false;
                TouchEvent::Up
            }
            0x400 => {
                self.pressed = false;
                TouchEvent::Reset
            }
            0x080 | 0x082 => {
                self.down = packet::down_base(raw);
                TouchEvent::Reverse
            }
            0x001 | 0x004 | 0x008 | 0x010 | 0x020 | 0x040 => return Ok(None),
            _ => {
                self.pressed = false;
                TouchEvent::Wrong
            }
        };
        Ok(Some(event))
    }
}

impl Sensor {
    /// Preserve early DOWN/UP packets while a finite command still awaits its ACK.
    pub(super) fn queue_touch(&mut self, frame: &[u8]) -> Result<()> {
        self.touch.queue(frame)
    }

    pub fn has_touch_event(&self) -> bool {
        !self.touch.pending.is_empty()
    }

    pub fn set_touch_threshold(&mut self, threshold: u8) {
        self.touch.threshold = threshold;
    }

    /// goodix.dat contains encoded DOWN words; the OEM restores them to both arrays.
    pub fn restore_fdt(&mut self, encoded: &[u8; 24]) {
        self.touch.restore(encoded);
    }

    pub fn encoded_fdt(&self) -> &[u8; 24] {
        &self.touch.down
    }

    pub fn touch_pressed(&self) -> bool {
        self.touch.pressed
    }

    /// A no-finger classification lets Session clear the logical DOWN state before
    /// temperature baseline work, without replacing either encoded FDT array.
    pub fn clear_touch(&mut self) {
        self.touch.pressed = false;
    }

    pub(super) fn require_released(&self) -> Result<()> {
        if self.touch.pressed {
            return Err(Error::Device("baseline refresh requires FDT-up"));
        }
        Ok(())
    }

    pub fn manual_fdt(&mut self, down: &[u8; 24]) -> Result<[u8; 24]> {
        self.run(|sensor| {
            sensor.require_released()?;
            sensor.drain()?;
            let frame = sensor.exchange(
                &packet::fdt_request(0x36, 0x0d, down),
                true,
                Some(Reply::ManualFdt),
                BASELINE_WAIT,
            )?;
            sensor.touch.keep_manual(&frame)
        })
    }

    /// Run after every classification-1 handoff, even if Engine rejects quality;
    /// Session then calls arm_up. This manual request intentionally permits DOWN.
    pub fn post_capture_fdt(&mut self) -> Result<()> {
        self.run(|sensor| {
            sensor.drain()?;
            let request = packet::fdt_request(0x36, 0x0d, &sensor.touch.down);
            let frame =
                sensor.exchange(&request, true, Some(Reply::ManualFdt), POST_CAPTURE_WAIT)?;
            sensor.touch.post_capture(&frame)
        })
    }

    /// Send/acknowledge DOWN mode; do not wait for a person or re-arm on events.
    pub fn arm_down(&mut self) -> Result<()> {
        self.run(|sensor| {
            let request = packet::fdt_request(0x32, 0x0c, &sensor.touch.down);
            sensor.exchange(&request, true, None, CONTROL_TIMEOUT)?;
            Ok(())
        })
    }

    /// Baseline-update fallback for cold setup and resume: SetMode(3, 1, 0)
    /// arms MCU-default DOWN without sending host base bytes.
    pub fn arm_default_down(&mut self) -> Result<()> {
        self.run(|sensor| {
            sensor.exchange(
                &packet::command(0x32, &[0x0c, 0]),
                true,
                None,
                CONTROL_TIMEOUT,
            )?;
            Ok(())
        })
    }

    /// UP uses the already-maintained array, including post-capture word minima.
    pub fn arm_up(&mut self) -> Result<()> {
        self.run(|sensor| {
            let request = packet::fdt_request(0x34, 0x0e, &sensor.touch.up);
            sensor.exchange(&request, true, None, CONTROL_TIMEOUT)?;
            Ok(())
        })
    }

    /// IRQ 0x400 restores vendor ID register 0x0008; it is not a hard MCU reset.
    pub fn recover_touch_reset(&mut self) -> Result<()> {
        self.run(|sensor| {
            sensor.exchange(
                &packet::command(0x80, &[0, 8, 0, 0x11, 0x11]),
                true,
                None,
                Duration::from_millis(100),
            )?;
            Ok(())
        })
    }

    /// None is an unbounded human wait. A deadline belongs to Session's one-shot
    /// temperature timer, and expires as Ok(None), not a failed sensor session.
    pub fn wait_touch(&mut self, deadline: Option<Instant>) -> Result<Option<TouchEvent>> {
        self.run(|sensor| {
            loop {
                // SUSPEND/cancellation wins even if an event arrived during an ACK.
                sensor.device.check_wait()?;
                if let Some(frame) = sensor.touch.pending.pop_front() {
                    if let Some(event) = sensor.touch.event(&frame)? {
                        return Ok(Some(event));
                    }
                    continue;
                }
                let wait = deadline.map_or(Wait::Human, Wait::HumanUntil);
                let Some(frame) = sensor.device.read(wait, true)? else {
                    return Ok(None);
                };
                if packet::envelope(&frame)? == packet::Kind::Control && frame[4] & 0xf1 == 0x30 {
                    if sensor.late_replies.accept(&frame)? {
                        continue;
                    }
                    if let Some(event) = sensor.touch.event(&frame)? {
                        return Ok(Some(event));
                    }
                } else {
                    // Preserve TLS and consume only explicitly outstanding ACKs.
                    sensor.unsolicited(&frame)?;
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Secret;

    fn fdt(irq: u16, flags: u16, raw: u16) -> Secret {
        let mut data = [0; 28];
        data[..2].copy_from_slice(&irq.to_le_bytes());
        data[2..4].copy_from_slice(&flags.to_le_bytes());
        for word in data[4..].chunks_exact_mut(2) {
            word.copy_from_slice(&raw.to_le_bytes());
        }
        packet::command(0x36, &data)
    }

    #[test]
    fn restored_fdt_is_encoded_and_copied_without_conversion() {
        let mut state = TouchState::default();
        assert!(!state.pressed);
        assert_eq!((state.saved_flags, state.threshold), (0, 0));
        assert_eq!(*state.down, [0; 24]);
        assert_eq!(*state.up, [0; 24]);
        let encoded = [0xff, 0x7e].repeat(12).try_into().unwrap();
        state.restore(&encoded);
        assert_eq!(*state.down, encoded);
        assert_eq!(*state.up, encoded);
    }

    #[test]
    fn ordinary_manual_updates_down_from_raw_but_not_up() {
        let mut state = TouchState::default();
        state.restore(&[0x2a; 24]);
        let raw = state.keep_manual(&fdt(0x100, 0xfff, 100)).unwrap();
        assert_eq!(packet::word(&raw), 100);
        assert_eq!(*state.down, [50; 24]);
        assert_eq!(*state.up, [0x2a; 24]);
        assert!(!state.pressed);
        assert!(state.keep_manual(&fdt(0x002, 0xfff, 100)).is_err());
        assert_eq!(*state.down, [50; 24]);
    }

    #[test]
    fn down_initializes_up_and_postmanual_merges_flags_with_word_minimum() {
        let mut state = TouchState::default();
        state.restore(&[0x2a; 24]);
        assert_eq!(
            state.event(&fdt(0x002, 1, 100)).unwrap(),
            Some(TouchEvent::Down)
        );
        assert!(state.pressed);
        assert_eq!(state.saved_flags, 1);
        assert_eq!(packet::word(&state.up[..2]), 0x4747);
        assert_eq!(packet::word(&state.up[2..4]), 0x1347);
        state.post_capture(&fdt(0x100, 2, 80)).unwrap();
        // Saved bit0 remains touched. For bit1, min(0x1347, 0x3d3d) is
        // 0x1347, not the bytewise-min result 0x133d.
        assert_eq!(packet::word(&state.up[..2]), 0x3d3d);
        assert_eq!(packet::word(&state.up[2..4]), 0x1347);
        assert_eq!(packet::word(&state.up[4..6]), 0x133d);
        assert_eq!(*state.down, [0x2a; 24]);
        assert_eq!(state.saved_flags, 1);
        assert!(state.pressed);
        assert!(state.post_capture(&fdt(0x200, 2, 80)).is_err());
    }

    #[test]
    fn up_and_reverse_refresh_down_but_reset_and_wrong_do_not() {
        let mut state = TouchState::default();
        state.event(&fdt(0x002, 0xfff, 100)).unwrap();
        assert_eq!(
            state.event(&fdt(0x200, 0, 200)).unwrap(),
            Some(TouchEvent::Up)
        );
        assert_eq!(*state.down, [100; 24]);
        assert!(!state.pressed);
        for irq in [0x080, 0x082] {
            state.pressed = true;
            assert_eq!(
                state.event(&fdt(irq, 0, 300)).unwrap(),
                Some(TouchEvent::Reverse)
            );
            assert_eq!(*state.down, [150; 24]);
            assert!(state.pressed);
        }
        for (irq, event) in [(0x400, TouchEvent::Reset), (0x800, TouchEvent::Wrong)] {
            state.pressed = true;
            assert_eq!(state.event(&fdt(irq, 0, 400)).unwrap(), Some(event));
            assert!(!state.pressed);
            assert_eq!(*state.down, [150; 24]);
        }
    }

    #[test]
    fn early_events_are_validated_and_applied_in_fifo_order_only_when_consumed() {
        let mut state = TouchState::default();
        state.queue(&fdt(0x002, 1, 100)).unwrap();
        state.queue(&fdt(0x200, 0, 200)).unwrap();
        assert!(!state.pressed);
        assert_eq!(*state.down, [0; 24]);
        let down = state.pending.pop_front().unwrap();
        assert_eq!(state.event(&down).unwrap(), Some(TouchEvent::Down));
        assert!(state.pressed);
        let up = state.pending.pop_front().unwrap();
        assert_eq!(state.event(&up).unwrap(), Some(TouchEvent::Up));
        assert!(!state.pressed);
        assert_eq!(*state.down, [100; 24]);
        assert!(state.pending.is_empty());
        let mut bad = fdt(0x002, 1, 100);
        bad[11] ^= 1;
        assert!(state.queue(&bad).is_err());
        assert!(state.queue(&packet::command(0xb0, &[0x32, 1])).is_err());
        assert!(state.pending.is_empty());
    }

    #[test]
    fn ignored_irqs_and_bad_packets_do_not_change_touch_state() {
        let mut state = TouchState::default();
        state.restore(&[0x2a; 24]);
        state.event(&fdt(0x002, 1, 100)).unwrap();
        for irq in [0x001, 0x004, 0x008, 0x010, 0x020, 0x040] {
            assert_eq!(state.event(&fdt(irq, 0, 400)).unwrap(), None);
        }
        let mut corrupt = fdt(0x200, 0, 400);
        corrupt[11] ^= 1;
        assert!(state.event(&corrupt).is_err());
        assert!(state.event(&[]).is_err());
        assert!(state.pressed);
        assert_eq!(state.saved_flags, 1);
        assert_eq!(*state.down, [0x2a; 24]);
        assert_eq!(packet::word(&state.up[..2]), 0x4747);
    }
}
