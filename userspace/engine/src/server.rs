//! Root-private protocol v2 service. EOF cancels; queued SUSPEND preserves host state.

use crate::{
    Cancellation, Secret,
    error::{Error, Result},
    lifecycle::{RequestControl, Shutdown, wait_for},
    protocol::{ErrorCode, MAX_MESSAGE, Request, Response},
};
use std::{
    env, fs,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, RawFd},
        linux::net::SocketAddrExt,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, PermissionsExt},
            net::{SocketAddr, UnixDatagram, UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    rc::Rc,
    time::Instant,
};

pub struct IdleSource {
    pub descriptor: RawFd,
    pub deadline: Option<Instant>,
}

pub trait Backend {
    fn execute(&mut self, request: Request<'_>) -> Result<Response>;
    fn close(&mut self) -> Result<()>;
    fn idle_source(&self) -> Option<IdleSource> {
        None
    }
    fn on_idle(&mut self) -> Result<()> {
        Ok(())
    }
}

fn wait_request(peer: &UnixStream, shutdown: &Shutdown, backend: &mut impl Backend) -> Result<()> {
    loop {
        shutdown.check()?;
        let source = backend.idle_source();
        let mut descriptors = vec![
            libc::pollfd {
                fd: peer.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: shutdown.descriptor(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if let Some(source) = &source {
            descriptors.push(libc::pollfd {
                fd: source.descriptor,
                events: libc::POLLIN,
                revents: 0,
            });
        }
        let timeout = source
            .as_ref()
            .and_then(|source| source.deadline)
            .map_or(-1, |deadline| {
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_nanos()
                    .div_ceil(1_000_000)
                    .min(i32::MAX as u128) as i32
            });
        let ready =
            unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, timeout) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        shutdown.check()?;
        if descriptors[0].revents != 0 {
            return Ok(());
        }
        if ready == 0
            || descriptors
                .get(2)
                .is_some_and(|descriptor| descriptor.revents != 0)
        {
            match backend.on_idle() {
                // Idle baseline/temperature work has no request response to
                // interrupt. Yield directly to the queued SUSPEND instead.
                Err(Error::Suspended) => return Ok(()),
                result => result?,
            }
        }
    }
}

pub struct Listener {
    socket: Option<UnixListener>,
    path: PathBuf,
    identity: Option<(u64, u64)>,
}

impl Listener {
    pub fn bind(path: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let metadata = fs::metadata(parent)?;
        if !metadata.is_dir()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(Error::Device(
                "socket directory must be private and owned by the service user",
            ));
        }
        // bind must fail on any existing file, including an apparently stale socket.
        let socket = UnixListener::bind(path)?;
        let metadata = fs::symlink_metadata(path)?;
        let listener = Self {
            socket: Some(socket),
            path: path.to_owned(),
            identity: Some((metadata.dev(), metadata.ino())),
        };
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        listener.socket.as_ref().unwrap().set_nonblocking(true)?;
        Ok(listener)
    }

    pub fn accept(&self, shutdown: &Shutdown) -> Result<UnixStream> {
        let socket = self.socket.as_ref().unwrap();
        loop {
            wait_for(socket.as_raw_fd(), libc::POLLIN, shutdown)?;
            match socket.accept() {
                Ok((peer, _)) => {
                    peer.set_nonblocking(true)?;
                    return Ok(peer);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub fn close(&mut self) -> Result<()> {
        self.socket.take();
        let Some(identity) = self.identity.take() else {
            return Ok(());
        };
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if (metadata.dev(), metadata.ino()) != identity {
            return Err(Error::Device(
                "listening socket path was replaced; leaving it untouched",
            ));
        }
        fs::remove_file(&self.path)?;
        Ok(())
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("goodix-milanl-engine: {error}");
        }
    }
}

pub fn notify_ready() -> Result<()> {
    let Some(path) = env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let socket = UnixDatagram::unbound()?;
    let bytes = path.as_bytes();
    if let Some(name) = bytes.strip_prefix(b"@") {
        socket.connect_addr(&SocketAddr::from_abstract_name(name)?)?;
    } else {
        socket.connect(Path::new(&path))?;
    }
    if socket.send(b"READY=1")? != 7 {
        return Err(Error::Device("short systemd readiness message"));
    }
    Ok(())
}

fn read_exact(peer: &UnixStream, shutdown: &Shutdown, mut output: &mut [u8]) -> Result<bool> {
    let mut stream = peer;
    while !output.is_empty() {
        wait_for(peer.as_raw_fd(), libc::POLLIN, shutdown)?;
        match stream.read(output) {
            Ok(0) => return Ok(false),
            Ok(count) => output = &mut output[count..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(true)
}

fn read_frame(peer: &UnixStream, shutdown: &Shutdown) -> Result<Option<Secret>> {
    let mut header = [0; 4];
    if !read_exact(peer, shutdown, &mut header)? {
        return Ok(None);
    }
    let length = u32::from_le_bytes(header) as usize;
    if !(1..=MAX_MESSAGE).contains(&length) {
        return Err(Error::Protocol("frame length out of range"));
    }
    let mut body = Secret::new(vec![0; length]);
    if !read_exact(peer, shutdown, &mut body)? {
        return Err(Error::Protocol("truncated frame"));
    }
    Ok(Some(body))
}

fn write_frame(
    peer: &UnixStream,
    shutdown: &Shutdown,
    control: &RequestControl,
    response: &Response,
) -> Result<()> {
    let body = response.encode()?;
    let header = (body.len() as u32).to_le_bytes();
    let mut stream = peer;
    for mut bytes in [&header[..], &body[..]] {
        while !bytes.is_empty() {
            control.check()?;
            // A queued SUSPEND stays unread until this response is complete.
            // Do not spin on its POLLIN while a large response is backpressured.
            let events = if matches!(control.check_wait(), Err(Error::Suspended)) {
                libc::POLLOUT
            } else {
                libc::POLLOUT | libc::POLLIN
            };
            wait_for(peer.as_raw_fd(), events, shutdown)?;
            control.check()?;
            match stream.write(bytes) {
                Ok(0) => return Err(Error::Cancelled),
                Ok(count) => bytes = &bytes[count..],
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

pub fn serve_connection(
    peer: Rc<UnixStream>,
    shutdown: &Shutdown,
    control: &RequestControl,
    backend: &mut impl Backend,
) -> Result<()> {
    let result = (|| {
        loop {
            control.set_in_flight(false);
            wait_request(&peer, shutdown, backend)?;
            let body = match read_frame(&peer, shutdown) {
                Ok(Some(body)) => body,
                Ok(None) | Err(Error::Protocol(_)) => return Ok(()),
                Err(error) => return Err(error),
            };
            control.set_in_flight(true);
            let outcome = control
                .check_wait()
                .and_then(|()| Request::decode(&body))
                .and_then(|request| backend.execute(request));
            let (response, terminal) = match outcome {
                Ok(response) => (response, false),
                Err(Error::Suspended) => (Response::Interrupted, false),
                Err(Error::Protocol(_)) => (Response::Error(ErrorCode::Protocol), false),
                Err(error @ (Error::Cancelled | Error::Shutdown | Error::Cleanup(_))) => {
                    return Err(error);
                }
                Err(error) => {
                    let code = if matches!(error, Error::Template(_)) {
                        ErrorCode::Data
                    } else {
                        ErrorCode::General
                    };
                    eprintln!("goodix-milanl-engine: {error}");
                    (Response::Error(code), true)
                }
            };
            write_frame(&peer, shutdown, control, &response)?;
            if terminal {
                return Ok(());
            }
        }
    })();
    // A failed teardown is fatal to the listener, never a reusable device state.
    let closed = {
        let _guard = control.cleanup();
        backend.close()
    };
    closed.map_err(|error| Error::Cleanup(Box::new(error)))?;
    match result {
        Err(Error::Cancelled) => Ok(()),
        Err(Error::Io(error))
            if matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
            ) =>
        {
            Ok(())
        }
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };

    struct TestBackend {
        calls: Arc<AtomicUsize>,
        closed: Arc<AtomicUsize>,
        fail_cleanup: bool,
    }
    impl Backend for TestBackend {
        fn execute(&mut self, _: Request<'_>) -> Result<Response> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Response::Hello)
        }
        fn close(&mut self) -> Result<()> {
            self.closed.fetch_add(1, Ordering::SeqCst);
            if self.fail_cleanup {
                Err(Error::Device("test cleanup failure"))
            } else {
                Ok(())
            }
        }
    }

    fn exchange(peer: &mut UnixStream, body: &[u8]) -> Vec<u8> {
        peer.write_all(&(body.len() as u32).to_le_bytes()).unwrap();
        peer.write_all(body).unwrap();
        receive(peer)
    }

    fn receive(peer: &mut UnixStream) -> Vec<u8> {
        let mut length = [0; 4];
        peer.read_exact(&mut length).unwrap();
        let mut response = vec![0; u32::from_le_bytes(length) as usize];
        peer.read_exact(&mut response).unwrap();
        response
    }

    #[test]
    fn malformed_requests_do_not_reach_backend_and_disconnect_closes_once() {
        let (server, mut client) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let mut backend = TestBackend {
            calls: calls.clone(),
            closed: closed.clone(),
            fail_cleanup: false,
        };
        let worker = thread::spawn(move || {
            let shutdown = Rc::new(Shutdown::new().unwrap());
            let peer = Rc::new(server);
            let control = RequestControl::new(shutdown.clone(), peer.clone());
            serve_connection(peer, &shutdown, &control, &mut backend).unwrap();
        });
        assert_eq!(exchange(&mut client, &[2, 42]), [8, 2]);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            exchange(&mut client, &[1, 2, 0, 0, 0]),
            [2, 2, 0, 0, 0, 12, 0, 3, 0, 0, 0]
        );
        drop(client);
        worker.join().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(closed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn queued_suspend_follows_interrupted_or_completed_response_on_the_same_socket() {
        use std::sync::mpsc;
        struct PausingBackend {
            control: Rc<RequestControl>,
            entered: mpsc::Sender<()>,
            proceed: mpsc::Receiver<()>,
            mode: u8,
        }
        impl Backend for PausingBackend {
            fn execute(&mut self, request: Request<'_>) -> Result<Response> {
                match request {
                    Request::EnrollCapture => {
                        self.entered.send(()).unwrap();
                        self.proceed.recv_timeout(Duration::from_secs(3)).unwrap();
                        if self.mode == 0 {
                            self.control.check_wait()?;
                            panic!("human wait must be interrupted");
                        }
                        self.control.check()?;
                        if self.mode == 1 {
                            Ok(Response::EnrollStage(2))
                        } else {
                            Ok(Response::EnrollDone(Secret::new(
                                vec![0x5a; crate::protocol::MAX_BLOB],
                            )))
                        }
                    }
                    Request::Suspend | Request::Resume => Ok(Response::Ok),
                    _ => panic!("unexpected synthetic request"),
                }
            }
            fn close(&mut self) -> Result<()> {
                Ok(())
            }
        }
        for mode in 0..3 {
            let (server, mut client) = UnixStream::pair().unwrap();
            server.set_nonblocking(true).unwrap();
            let send_buffer: libc::c_int = 4096;
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        server.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_SNDBUF,
                        (&send_buffer as *const libc::c_int).cast(),
                        size_of_val(&send_buffer) as _,
                    )
                },
                0
            );
            client
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let (entered_tx, entered_rx) = mpsc::channel();
            let (proceed_tx, proceed_rx) = mpsc::channel();
            let worker = thread::spawn(move || {
                let shutdown = Rc::new(Shutdown::new().unwrap());
                let peer = Rc::new(server);
                let control = Rc::new(RequestControl::new(shutdown.clone(), peer.clone()));
                let mut backend = PausingBackend {
                    control: control.clone(),
                    entered: entered_tx,
                    proceed: proceed_rx,
                    mode,
                };
                serve_connection(peer, &shutdown, &control, &mut backend).unwrap();
            });
            client.write_all(&[1, 0, 0, 0, 3]).unwrap();
            entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            client.write_all(&[1, 0, 0, 0, 7]).unwrap();
            proceed_tx.send(()).unwrap();
            let response = receive(&mut client);
            match mode {
                0 => assert_eq!(response, [9]),
                1 => assert_eq!(response, [3, 2, 0]),
                _ => {
                    assert_eq!(response.len(), crate::protocol::MAX_BLOB + 5);
                    assert_eq!(response[0], 4);
                    assert!(response[5..].iter().all(|byte| *byte == 0x5a));
                }
            }
            assert_eq!(receive(&mut client), [1]);
            assert_eq!(exchange(&mut client, &[8]), [1]);
            drop(client);
            worker.join().unwrap();
        }
    }

    #[test]
    fn idle_events_and_one_shot_timer_run_without_client_requests() {
        use std::sync::mpsc;
        struct IdleBackend {
            input: UnixStream,
            deadline: Option<Instant>,
            events: mpsc::Sender<&'static str>,
        }
        impl Backend for IdleBackend {
            fn execute(&mut self, _: Request<'_>) -> Result<Response> {
                Ok(Response::Hello)
            }
            fn close(&mut self) -> Result<()> {
                Ok(())
            }
            fn idle_source(&self) -> Option<IdleSource> {
                Some(IdleSource {
                    descriptor: self.input.as_raw_fd(),
                    deadline: self.deadline,
                })
            }
            fn on_idle(&mut self) -> Result<()> {
                if self.deadline.is_some() {
                    self.deadline = None;
                    self.events.send("timer").unwrap();
                } else {
                    let mut byte = [0];
                    self.input.read_exact(&mut byte)?;
                    self.events.send("sensor").unwrap();
                }
                Ok(())
            }
        }
        let (server, mut client) = UnixStream::pair().unwrap();
        let (input, mut output) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let (events, received) = mpsc::channel();
        let worker = thread::spawn(move || {
            let shutdown = Rc::new(Shutdown::new().unwrap());
            let peer = Rc::new(server);
            let control = RequestControl::new(shutdown.clone(), peer.clone());
            let mut backend = IdleBackend {
                input,
                deadline: Some(Instant::now()),
                events,
            };
            serve_connection(peer, &shutdown, &control, &mut backend).unwrap();
        });
        assert_eq!(
            received.recv_timeout(Duration::from_secs(3)).unwrap(),
            "timer"
        );
        output.write_all(&[1]).unwrap();
        assert_eq!(
            received.recv_timeout(Duration::from_secs(3)).unwrap(),
            "sensor"
        );
        assert_eq!(
            exchange(&mut client, &[1, 2, 0, 0, 0]),
            [2, 2, 0, 0, 0, 12, 0, 3, 0, 0, 0]
        );
        assert!(received.try_recv().is_err());
        drop(client);
        worker.join().unwrap();
    }

    #[test]
    fn suspend_during_idle_base_work_yields_without_an_unsolicited_response() {
        struct YieldingBackend {
            client: UnixStream,
            control: Rc<RequestControl>,
        }
        impl Backend for YieldingBackend {
            fn execute(&mut self, _: Request<'_>) -> Result<Response> {
                unreachable!()
            }
            fn close(&mut self) -> Result<()> {
                panic!("idle yield must retain the session")
            }
            fn idle_source(&self) -> Option<IdleSource> {
                Some(IdleSource {
                    descriptor: -1,
                    deadline: Some(Instant::now()),
                })
            }
            fn on_idle(&mut self) -> Result<()> {
                self.client.write_all(&[1, 0, 0, 0, 7])?;
                self.control.check()?; // finite work completes first
                self.control.check_wait()
            }
        }
        let (server, client) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        client.set_nonblocking(true).unwrap();
        let shutdown = Rc::new(Shutdown::new().unwrap());
        let peer = Rc::new(server);
        let control = Rc::new(RequestControl::new(shutdown.clone(), peer.clone()));
        let mut backend = YieldingBackend { client, control };
        wait_request(&peer, &shutdown, &mut backend).unwrap();
        assert_eq!(
            read_frame(&peer, &shutdown).unwrap().unwrap().as_slice(),
            &[7]
        );
        let mut byte = [0];
        assert_eq!(
            backend.client.read(&mut byte).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn cleanup_failure_is_not_a_normal_disconnect() {
        let (server, client) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        drop(client);
        let shutdown = Rc::new(Shutdown::new().unwrap());
        let peer = Rc::new(server);
        let control = RequestControl::new(shutdown.clone(), peer.clone());
        let mut backend = TestBackend {
            calls: Arc::new(AtomicUsize::new(0)),
            closed: Arc::new(AtomicUsize::new(0)),
            fail_cleanup: true,
        };
        assert!(matches!(
            serve_connection(peer, &shutdown, &control, &mut backend),
            Err(Error::Cleanup(_))
        ));
    }
}
