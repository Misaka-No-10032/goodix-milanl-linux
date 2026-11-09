//! Process shutdown, connection cancellation, and owned kernel-module lifetime.

use std::{
    cell::Cell,
    fs, io,
    mem::{self, size_of},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::net::UnixStream,
    },
    path::{Path, PathBuf},
    process::Command,
    rc::Rc,
};

use crate::{
    Cancellation,
    error::{Error, Result},
};

pub struct Shutdown {
    descriptor: OwnedFd,
    previous_mask: libc::sigset_t,
    requested: Cell<bool>,
}

impl Shutdown {
    pub fn new() -> Result<Self> {
        // The daemon is single-threaded. Blocking termination signals makes
        // cleanup non-interruptible without installing a signal-time destructor.
        unsafe {
            let mut mask: libc::sigset_t = mem::zeroed();
            let mut previous_mask = mem::zeroed();
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGINT);
            libc::sigaddset(&mut mask, libc::SIGTERM);
            let status = libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut previous_mask);
            if status != 0 {
                return Err(io::Error::from_raw_os_error(status).into());
            }
            let fd = libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
            if fd < 0 {
                let error = io::Error::last_os_error();
                libc::pthread_sigmask(libc::SIG_SETMASK, &previous_mask, std::ptr::null_mut());
                return Err(error.into());
            }
            Ok(Self {
                descriptor: OwnedFd::from_raw_fd(fd),
                previous_mask,
                requested: Cell::new(false),
            })
        }
    }

    pub fn check(&self) -> Result<()> {
        loop {
            let mut signal = mem::MaybeUninit::<libc::signalfd_siginfo>::uninit();
            // signalfd writes one fixed-size record; its payload is not needed.
            let count = unsafe {
                libc::read(
                    self.descriptor.as_raw_fd(),
                    signal.as_mut_ptr().cast(),
                    size_of::<libc::signalfd_siginfo>(),
                )
            };
            if count == size_of::<libc::signalfd_siginfo>() as isize {
                self.requested.set(true);
                continue;
            }
            if count < 0 {
                let error = io::Error::last_os_error();
                match error.kind() {
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::WouldBlock => break,
                    _ => return Err(error.into()),
                }
            }
            return Err(Error::Device("invalid shutdown signal record"));
        }
        if self.requested.get() {
            Err(Error::Shutdown)
        } else {
            Ok(())
        }
    }

    pub fn descriptor(&self) -> RawFd {
        self.descriptor.as_raw_fd()
    }
}

impl Drop for Shutdown {
    fn drop(&mut self) {
        let _ = self.check();
        // All hardware and owned modules are closed before this guard is dropped.
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous_mask, std::ptr::null_mut());
        }
    }
}

pub struct RequestControl {
    shutdown: Rc<Shutdown>,
    peer: Rc<UnixStream>,
    in_flight: Cell<bool>,
    cleaning: Cell<bool>,
}

impl RequestControl {
    pub fn new(shutdown: Rc<Shutdown>, peer: Rc<UnixStream>) -> Self {
        Self {
            shutdown,
            peer,
            in_flight: Cell::new(false),
            cleaning: Cell::new(false),
        }
    }

    pub fn set_in_flight(&self, value: bool) {
        self.in_flight.set(value);
    }

    pub fn cleanup(&self) -> CleanupGuard<'_> {
        let previous = self.cleaning.replace(true);
        CleanupGuard {
            control: self,
            previous,
        }
    }
}

pub struct CleanupGuard<'a> {
    control: &'a RequestControl,
    previous: bool,
}

impl Drop for CleanupGuard<'_> {
    fn drop(&mut self) {
        self.control.cleaning.set(self.previous);
    }
}

impl Cancellation for RequestControl {
    fn check_wait(&self) -> Result<()> {
        if self.cleaning.get() {
            return Ok(());
        }
        self.shutdown.check()?;
        let mut descriptor = libc::pollfd {
            fd: self.peer.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            if result == 0 {
                return Ok(());
            }
            if descriptor.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(Error::Cancelled);
            }
            // Leave SUSPEND queued so the server acknowledges it after the
            // interrupted request. Ordinary idle requests are not cancellation.
            const SUSPEND: [u8; 5] = [1, 0, 0, 0, 7];
            let mut frame = [0u8; 5];
            let count = unsafe {
                libc::recv(
                    self.peer.as_raw_fd(),
                    frame.as_mut_ptr().cast(),
                    frame.len(),
                    libc::MSG_PEEK | libc::MSG_DONTWAIT,
                )
            };
            if count < 0 {
                let error = io::Error::last_os_error();
                match error.kind() {
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::WouldBlock => return Ok(()),
                    _ => return Err(error.into()),
                }
            }
            if count == 0 {
                return Err(Error::Cancelled);
            }
            if frame[..count as usize] == SUSPEND[..count as usize] {
                return if count == 5 {
                    Err(Error::Suspended)
                } else {
                    Ok(())
                };
            }
            return if self.in_flight.get() {
                Err(Error::Cancelled)
            } else {
                Ok(())
            };
        }
    }

    fn check(&self) -> Result<()> {
        // Finish finite hardware/enclave work before suspending, so completed
        // merge counters and pending calibration reach their OEM save points.
        match self.check_wait() {
            Err(Error::Suspended) => Ok(()),
            result => result,
        }
    }

    fn descriptors(&self) -> Vec<RawFd> {
        if self.cleaning.get() {
            return vec![];
        }
        let mut result = vec![self.shutdown.descriptor()];
        if self.in_flight.get() && !matches!(self.check_wait(), Err(Error::Suspended)) {
            result.push(self.peer.as_raw_fd());
        }
        result
    }
}

pub fn wait_for(fd: RawFd, events: libc::c_short, shutdown: &Shutdown) -> Result<()> {
    loop {
        shutdown.check()?;
        let mut descriptors = [
            libc::pollfd {
                fd,
                events,
                revents: 0,
            },
            libc::pollfd {
                fd: shutdown.descriptor(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let result = unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, -1) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        shutdown.check()?;
        if descriptors[0].revents & libc::POLLNVAL != 0 {
            return Err(io::Error::from_raw_os_error(libc::EBADF).into());
        }
        if descriptors[0].revents != 0 {
            return Ok(());
        }
    }
}

pub struct Modules {
    isgx: Option<PathBuf>,
    transport: Option<PathBuf>,
    owned: Vec<&'static str>,
}

impl Modules {
    pub fn new(isgx: Option<PathBuf>, transport: Option<PathBuf>) -> Self {
        Self {
            isgx,
            transport,
            owned: vec![],
        }
    }

    pub fn load(&mut self) -> Result<()> {
        for (name, path, parameters) in [
            ("isgx", &self.isgx, &[][..]),
            (
                "goodix_milanl_transport",
                &self.transport,
                &["enable_sealed_input=1", "enable_raw_tx=1"][..],
            ),
        ] {
            if !Path::new("/sys/module").join(name).try_exists()? {
                let mut command = if let Some(path) = path {
                    let mut command = Command::new("insmod");
                    command.arg(path);
                    command
                } else {
                    let mut command = Command::new("modprobe");
                    command.arg(name);
                    command
                };
                if !command.args(parameters).status()?.success() {
                    return Err(Error::Device("kernel module loading failed"));
                }
                self.owned.push(name);
            }
        }
        for parameter in ["enable_sealed_input", "enable_raw_tx"] {
            let value = fs::read_to_string(
                Path::new("/sys/module/goodix_milanl_transport/parameters").join(parameter),
            )?;
            if !matches!(value.trim(), "Y" | "1") {
                return Err(Error::Device("transport input permissions are disabled"));
            }
        }
        Ok(())
    }

    pub fn close(&mut self) -> Result<()> {
        while let Some(name) = self.owned.last() {
            if !Command::new("rmmod").arg(name).status()?.success() {
                return Err(Error::Device("owned kernel module unloading failed"));
            }
            self.owned.pop();
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq)]
pub struct SuspendEpoch {
    success: u64,
    failed: u64,
}

impl SuspendEpoch {
    pub fn read() -> Result<Self> {
        Self::read_from(Path::new("/sys/power/suspend_stats"))
    }

    fn read_from(path: &Path) -> Result<Self> {
        let counter = |name| -> Result<u64> {
            fs::read_to_string(path.join(name))?
                .trim()
                .parse()
                .map_err(|_| Error::Device("invalid Linux suspend counter"))
        };
        Ok(Self {
            success: counter("success")?,
            failed: counter("fail")?,
        })
    }
}

pub fn protect_process() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) < 0 {
            return Err(io::Error::last_os_error().into());
        }
        libc::umask(0o077);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eof_and_pipeline_cancel_but_cleanup_is_not_interrupted() {
        let shutdown = Rc::new(Shutdown::new().unwrap());
        let (server, client) = UnixStream::pair().unwrap();
        let control = RequestControl::new(shutdown, Rc::new(server));
        control.set_in_flight(true);
        control.check().unwrap();
        drop(client);
        assert!(matches!(control.check(), Err(Error::Cancelled)));
        {
            let _guard = control.cleanup();
            control.check().unwrap();
            assert!(control.descriptors().is_empty());
        }
        assert!(matches!(control.check(), Err(Error::Cancelled)));
    }

    #[test]
    fn idle_request_data_is_not_cancellation() {
        use std::io::Write;
        let shutdown = Rc::new(Shutdown::new().unwrap());
        let (server, mut client) = UnixStream::pair().unwrap();
        let control = RequestControl::new(shutdown, Rc::new(server));
        client.write_all(&[1, 0, 0, 0, 6]).unwrap();
        control.check().unwrap();
        control.set_in_flight(true);
        assert!(matches!(control.check(), Err(Error::Cancelled)));
    }

    #[test]
    fn fragmented_suspend_is_left_queued_and_deferred_only_during_finite_work() {
        use std::io::{Read, Write};
        let shutdown = Rc::new(Shutdown::new().unwrap());
        let (server, mut client) = UnixStream::pair().unwrap();
        let peer = Rc::new(server);
        let control = RequestControl::new(shutdown, peer.clone());
        control.set_in_flight(true);
        let suspend = [1, 0, 0, 0, 7];
        for byte in &suspend[..4] {
            client.write_all(&[*byte]).unwrap();
            control.check_wait().unwrap();
            assert!(control.descriptors().contains(&peer.as_raw_fd()));
        }
        client.write_all(&suspend[4..]).unwrap();
        assert!(matches!(control.check_wait(), Err(Error::Suspended)));
        control.check().unwrap();
        assert!(!control.descriptors().contains(&peer.as_raw_fd()));
        let mut queued = [0; 5];
        (&*peer).read_exact(&mut queued).unwrap();
        assert_eq!(queued, suspend);
        control.check_wait().unwrap();
    }

    #[test]
    fn eof_wins_over_a_queued_suspend_and_is_observed_when_idle() {
        use std::io::Write;
        for active in [false, true] {
            let shutdown = Rc::new(Shutdown::new().unwrap());
            let (server, mut client) = UnixStream::pair().unwrap();
            let control = RequestControl::new(shutdown, Rc::new(server));
            control.set_in_flight(active);
            client.write_all(&[1, 0, 0, 0, 7]).unwrap();
            drop(client);
            assert!(matches!(control.check_wait(), Err(Error::Cancelled)));
            assert!(matches!(control.check(), Err(Error::Cancelled)));
        }
    }

    #[test]
    fn failed_suspends_invalidate_sessions_too() {
        let initial = SuspendEpoch {
            success: 2,
            failed: 0,
        };
        assert!(
            initial
                != SuspendEpoch {
                    success: 3,
                    failed: 0
                }
        );
        assert!(
            initial
                != SuspendEpoch {
                    success: 2,
                    failed: 1
                }
        );
    }
}
