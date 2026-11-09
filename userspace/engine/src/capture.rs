//! OEM no-finger baseline sequencing. Only stability rejection retries a cycle.

use crate::error::{Error, Result};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub trait BaselineIo {
    fn fdt(&mut self, down: &[u8; 24]) -> Result<[u8; 24]>;
    fn navigation(&mut self) -> Result<()>;
    fn threshold(&mut self) -> Result<u8>;
    fn image(&mut self) -> Result<()>;
    fn commit(&mut self, encoded_fdt: &[u8; 24]) -> Result<()>;
    fn checkpoint(&self) -> Result<()> {
        Ok(())
    }
}

pub fn down_base(raw: &[u8; 24]) -> [u8; 24] {
    let mut down = [0; 24];
    for (input, output) in raw.chunks_exact(2).zip(down.chunks_exact_mut(2)) {
        let value = u16::from_le_bytes([input[0], input[1]]) >> 1;
        output.copy_from_slice(&value.wrapping_mul(0x101).to_le_bytes());
    }
    down
}

fn stable(first: &[u8; 24], second: &[u8; 24], delta: u8) -> bool {
    first
        .chunks_exact(2)
        .zip(second.chunks_exact(2))
        .all(|(a, b)| {
            let a = u16::from_le_bytes([a[0], a[1]]);
            let b = u16::from_le_bytes([b[0], b[1]]);
            a.abs_diff(b) <= u16::from(delta)
        })
}

pub fn before(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(Error::Device("hardware transaction timed out"))
    } else {
        Ok(())
    }
}

pub fn build_baseline(
    io: &mut impl BaselineIo,
    initial_down: &[u8; 24],
    exists: bool,
) -> Result<()> {
    let mut down = Zeroizing::new(*initial_down);
    loop {
        io.checkpoint()?;
        let deadline = Instant::now() + Duration::from_secs(12);
        let first = Zeroizing::new(io.fdt(&down)?);
        *down = down_base(&first);
        before(deadline)?;
        io.navigation()?;
        before(deadline)?;
        let second = Zeroizing::new(io.fdt(&down)?);
        *down = down_base(&second);
        before(deadline)?;
        let delta = io.threshold()?;
        before(deadline)?;
        if !stable(&first, &second, delta) {
            if exists {
                return Ok(());
            }
            continue;
        }
        io.image()?;
        before(deadline)?;
        let final_fdt = Zeroizing::new(io.fdt(&down)?);
        *down = down_base(&final_fdt);
        before(deadline)?;
        if !stable(&second, &final_fdt, delta) {
            if exists {
                return Ok(());
            }
            continue;
        }
        io.commit(&down)?;
        return before(deadline);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Fixture {
        values: VecDeque<u16>,
        events: Vec<&'static str>,
        fail_nav: bool,
    }
    impl BaselineIo for Fixture {
        fn fdt(&mut self, _: &[u8; 24]) -> Result<[u8; 24]> {
            self.events.push("fdt");
            let value = self.values.pop_front().expect("unexpected extra FDT");
            let mut raw = [0; 24];
            for word in raw.chunks_exact_mut(2) {
                word.copy_from_slice(&value.to_le_bytes());
            }
            Ok(raw)
        }
        fn navigation(&mut self) -> Result<()> {
            self.events.push("nav");
            if self.fail_nav {
                Err(Error::Device("injected I/O failure"))
            } else {
                Ok(())
            }
        }
        fn threshold(&mut self) -> Result<u8> {
            self.events.push("threshold");
            Ok(5)
        }
        fn image(&mut self) -> Result<()> {
            self.events.push("image");
            Ok(())
        }
        fn commit(&mut self, _: &[u8; 24]) -> Result<()> {
            self.events.push("commit");
            Ok(())
        }
    }
    fn run(values: &[u16]) -> Vec<&'static str> {
        let mut io = Fixture {
            values: values.iter().copied().collect(),
            events: vec![],
            fail_nav: false,
        };
        build_baseline(&mut io, &[0; 24], false).unwrap();
        assert!(io.values.is_empty());
        io.events
    }

    #[test]
    fn one_accepted_cycle_commits_once() {
        assert_eq!(
            run(&[0; 3]),
            ["fdt", "nav", "fdt", "threshold", "image", "fdt", "commit"]
        );
    }
    #[test]
    fn nav_rejection_does_not_capture_or_commit_candidate() {
        let events = run(&[0, 20, 20, 20, 20]);
        assert_eq!(&events[..5], &["fdt", "nav", "fdt", "threshold", "fdt"]);
        assert_eq!(events.iter().filter(|&&e| e == "commit").count(), 1);
        assert_eq!(events.iter().filter(|&&e| e == "image").count(), 1);
    }
    #[test]
    fn image_rejection_restarts_at_first_fdt() {
        let events = run(&[0, 0, 20, 20, 20, 20]);
        assert_eq!(events.iter().filter(|&&e| e == "commit").count(), 1);
        assert_eq!(events.iter().filter(|&&e| e == "image").count(), 2);
        assert_eq!(events[6], "fdt");
    }
    #[test]
    fn unstable_candidates_keep_an_existing_base() {
        for values in [vec![0, 20], vec![0, 0, 20]] {
            let mut io = Fixture {
                values: values.into(),
                events: vec![],
                fail_nav: false,
            };
            build_baseline(&mut io, &[0; 24], true).unwrap();
            assert!(io.values.is_empty());
            assert!(!io.events.contains(&"commit"));
        }
    }
    #[test]
    fn transport_failure_is_not_stability_retry() {
        let mut io = Fixture {
            values: [0].into(),
            events: vec![],
            fail_nav: true,
        };
        assert!(build_baseline(&mut io, &[0; 24], false).is_err());
        assert_eq!(io.events, ["fdt", "nav"]);
    }
    #[test]
    fn fdt_word_arithmetic_matches_oem_overflow_and_delta() {
        let raw = [0xff; 24];
        assert_eq!(down_base(&raw), [0xff, 0x7e].repeat(12).as_slice());
        assert!(stable(&[0; 24], &[0; 24], 0));
        let mut changed = [0; 24];
        changed[0] = 6;
        assert!(!stable(&[0; 24], &changed, 5));
    }
}
