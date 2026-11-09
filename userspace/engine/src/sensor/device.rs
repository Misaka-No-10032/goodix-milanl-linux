use super::packet::RX_BYTES;
use crate::{
    Cancellation, Secret,
    error::{Error, Result},
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, OpenOptionsExt},
    },
    path::Path,
    rc::Rc,
    time::{Duration, Instant},
};

pub(super) enum Wait {
    Now,
    Until(Instant),
    Human,
    HumanUntil(Instant),
}

pub(super) struct Device {
    file: File,
    cancel: Rc<dyn Cancellation>,
}

impl Device {
    pub(super) fn open(path: &Path, cancel: Rc<dyn Cancellation>) -> Result<Self> {
        cancel.check()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(path)?;
        Ok(Self { file, cancel })
    }

    pub(super) fn descriptor(&self) -> std::os::fd::RawFd {
        self.file.as_raw_fd()
    }

    pub(super) fn check(&self) -> Result<()> {
        self.cancel.check()
    }

    pub(super) fn check_wait(&self) -> Result<()> {
        self.cancel.check_wait()
    }

    pub(super) fn sealed_input(&self) -> Result<Secret> {
        self.check()?;
        // kernel/goodix_milanl_uapi.h: _IOR('M', 2, { u32 length; u8 data[2048]; }).
        const IOCTL: libc::c_ulong = (2 << 30) | (2052 << 16) | (b'M' as libc::c_ulong) << 8 | 2;
        let mut buffer = Secret::new(vec![0; 2052]);
        // SAFETY: the kernel writes exactly the ioctl's 2052-byte output struct.
        let result = unsafe { libc::ioctl(self.file.as_raw_fd(), IOCTL, buffer.as_mut_ptr()) };
        if result < 0 {
            return Err(io::Error::last_os_error().into());
        }
        self.check()?;
        let count =
            u32::from_le_bytes(buffer[..4].try_into().expect("fixed ioctl header")) as usize;
        if !(0x230..=2048).contains(&count) {
            return Err(Error::Device("invalid sealed enclave input length"));
        }
        Ok(Secret::new(buffer[4..4 + count].to_vec()))
    }

    pub(super) fn write(&self, frame: &[u8], cancellable: bool) -> Result<()> {
        if cancellable {
            self.check()?;
        }
        // A mailbox write is one command, not a byte stream. Never write_all or
        // retry a short/interrupted write: its device-side effect is unknown.
        let written = (&self.file).write(frame)?;
        if written != frame.len() {
            return Err(Error::Device("short mailbox write; command not retried"));
        }
        Ok(())
    }

    pub(super) fn read(&self, wait: Wait, cancellable: bool) -> Result<Option<Secret>> {
        if !self.poll(wait, cancellable, true)? {
            return Ok(None);
        }
        let mut frame = Secret::new(vec![0; RX_BYTES]);
        // Each packet must start at offset zero. Ordinary read() would revisit
        // the previous packet's file offset in this mailbox driver's ABI.
        let count = self.file.read_at(&mut frame, 0)?;
        if !(4..=RX_BYTES).contains(&count) {
            return Err(Error::Device("invalid mailbox read length"));
        }
        // Vec::truncate does not reallocate; unread capacity is still all zero.
        frame.truncate(count);
        Ok(Some(frame))
    }

    pub(super) fn pause(&self, duration: Duration) -> Result<()> {
        self.poll(Wait::Until(Instant::now() + duration), true, false)?;
        Ok(())
    }

    fn poll(&self, wait: Wait, cancellable: bool, include_device: bool) -> Result<bool> {
        loop {
            if cancellable {
                if matches!(wait, Wait::Human | Wait::HumanUntil(_)) {
                    self.check_wait()?;
                } else {
                    self.check()?;
                }
            }
            let mut descriptors = Vec::new();
            if include_device {
                descriptors.push(libc::pollfd {
                    fd: self.file.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                });
            }
            if cancellable {
                descriptors.extend(
                    self.cancel
                        .descriptors()
                        .into_iter()
                        .map(|fd| libc::pollfd {
                            fd,
                            events: libc::POLLIN,
                            revents: 0,
                        }),
                );
            }
            // A pending SUSPEND can remove the peer from the finite-work poll
            // set. Recheck after constructing it before an unbounded human wait.
            if cancellable && matches!(wait, Wait::Human | Wait::HumanUntil(_)) {
                self.check_wait()?;
            }
            let timeout = match wait {
                Wait::Now => 0,
                Wait::Human => -1,
                Wait::Until(end) | Wait::HumanUntil(end) => {
                    let remaining = end.saturating_duration_since(Instant::now());
                    if remaining.is_zero() && matches!(wait, Wait::Until(_)) {
                        return Ok(false);
                    }
                    remaining
                        .as_nanos()
                        .div_ceil(1_000_000)
                        .min(i32::MAX as u128) as i32
                }
            };
            // SAFETY: poll receives the live vector's pointer and exact length.
            let result = unsafe {
                libc::poll(
                    descriptors.as_mut_ptr(),
                    descriptors.len() as libc::nfds_t,
                    timeout,
                )
            };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            // Cancellation wins when both the sensor and an interruption are ready.
            if cancellable {
                if matches!(wait, Wait::Human | Wait::HumanUntil(_)) {
                    self.check_wait()?;
                } else {
                    self.check()?;
                }
            }
            if result == 0 {
                return Ok(false);
            }
            if include_device {
                let events = descriptors[0].revents;
                if events & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                    return Err(Error::Device("mailbox device unavailable"));
                }
                if events & libc::POLLIN != 0 {
                    return Ok(true);
                }
            }
            if matches!(wait, Wait::Now) {
                return Ok(false);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        os::{
            fd::{OwnedFd, RawFd},
            unix::net::UnixStream,
        },
    };

    struct WakeCancellation {
        input: UnixStream,
        initial: Cell<bool>,
    }

    impl Cancellation for WakeCancellation {
        fn check(&self) -> Result<()> {
            // Model an interruption becoming visible between check() and poll().
            if self.initial.replace(false) {
                return Ok(());
            }
            let mut descriptor = libc::pollfd {
                fd: self.input.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut descriptor, 1, 0) };
            if ready > 0 {
                Err(Error::Cancelled)
            } else {
                Ok(())
            }
        }
        fn descriptors(&self) -> Vec<RawFd> {
            vec![self.input.as_raw_fd()]
        }
    }

    fn simulated_device(cancel: Rc<dyn Cancellation>) -> (Device, UnixStream) {
        let (input, output) = UnixStream::pair().unwrap();
        let descriptor: OwnedFd = input.into();
        (
            Device {
                file: File::from(descriptor),
                cancel,
            },
            output,
        )
    }

    #[test]
    fn human_wait_and_mailbox_pacing_poll_the_cancellation_descriptor() {
        for human in [true, false] {
            let (input, output) = UnixStream::pair().unwrap();
            drop(output); // Synthetic EOF, no sensor or signal handler.
            let cancel = Rc::new(WakeCancellation {
                input,
                initial: Cell::new(true),
            });
            let (device, _output) = simulated_device(cancel);
            let result = if human {
                device.poll(Wait::Human, true, true).map(|_| ())
            } else {
                device.pause(Duration::from_millis(1))
            };
            assert!(matches!(result, Err(Error::Cancelled)));
        }
    }

    struct ForbiddenCancellation;
    impl Cancellation for ForbiddenCancellation {
        fn check(&self) -> Result<()> {
            panic!("cleanup must not check cancellation")
        }
        fn descriptors(&self) -> Vec<RawFd> {
            panic!("cleanup must not poll cancellation")
        }
    }

    #[test]
    fn cleanup_wait_ignores_cancellation_and_still_observes_the_device() {
        let (device, mut output) = simulated_device(Rc::new(ForbiddenCancellation));
        output.write_all(&[1]).unwrap();
        assert!(
            device
                .poll(Wait::Until(Instant::now() + ACK_TEST_TIMEOUT), false, true)
                .unwrap()
        );
    }

    #[test]
    fn expired_human_timer_still_observes_an_already_ready_event() {
        let (device, mut output) = simulated_device(Rc::new(ForbiddenCancellation));
        output.write_all(&[1]).unwrap();
        assert!(
            device
                .poll(Wait::HumanUntil(Instant::now()), false, true)
                .unwrap()
        );
        assert!(
            !device
                .poll(Wait::Until(Instant::now()), false, true)
                .unwrap()
        );
    }

    #[test]
    fn suspend_arriving_while_building_poll_set_interrupts_the_human_wait() {
        struct SuspendOnDescriptors(Cell<bool>);
        impl Cancellation for SuspendOnDescriptors {
            fn check(&self) -> Result<()> {
                Ok(())
            }
            fn check_wait(&self) -> Result<()> {
                if self.0.get() {
                    Err(Error::Suspended)
                } else {
                    Ok(())
                }
            }
            fn descriptors(&self) -> Vec<RawFd> {
                self.0.set(true);
                vec![]
            }
        }
        let (device, _output) = simulated_device(Rc::new(SuspendOnDescriptors(Cell::new(false))));
        assert!(matches!(
            device.poll(Wait::Human, true, true),
            Err(Error::Suspended)
        ));
        // Finite work still completes after the same SUSPEND.
        device.pause(Duration::from_millis(1)).unwrap();
    }

    const ACK_TEST_TIMEOUT: Duration = Duration::from_secs(2);
}
