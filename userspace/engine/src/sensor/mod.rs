//! Native MilanL control and opaque TLS mailbox transport.
mod config;
mod device;
mod packet;
mod touch;
pub use touch::TouchEvent;

use crate::{
    Cancellation, Secret, TlsIo,
    error::{Error, Result},
};
use device::{Device, Wait};
use packet::Kind;
use std::{
    collections::VecDeque,
    path::Path,
    rc::Rc,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(1);
const ACK_TIMEOUT: Duration = Duration::from_secs(1);
const INIT_ATTEMPTS: usize = 3;
const TLS_QUEUE_LIMIT: usize = 65536;

pub struct SensorInfo {
    pub identity: [u8; 32],
    pub sensor_id: [u8; 16],
    pub threshold: u8,
    pub tcode: u16,
    config: Zeroizing<[u8; 256]>,
}

impl Drop for SensorInfo {
    fn drop(&mut self) {
        self.identity.zeroize();
        self.sensor_id.zeroize();
        self.threshold.zeroize();
        self.tcode.zeroize();
    }
}

#[derive(Default)]
struct TlsQueue {
    frames: VecDeque<Secret>,
    offset: usize,
    bytes: usize,
}

impl TlsQueue {
    fn push(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() || bytes.len() > TLS_QUEUE_LIMIT - self.bytes {
            return Err(Error::Device("MCU TLS pending queue limit exceeded"));
        }
        // No ciphertext deduplication: identical packets still reach TLS authentication.
        self.frames.push_back(Secret::new(bytes.to_vec()));
        self.bytes += bytes.len();
        Ok(())
    }

    fn read(&mut self, output: &mut [u8]) -> usize {
        let mut count = 0;
        while count < output.len() {
            let Some(frame) = self.frames.front_mut() else {
                break;
            };
            let take = (frame.len() - self.offset).min(output.len() - count);
            output[count..count + take].copy_from_slice(&frame[self.offset..self.offset + take]);
            frame[self.offset..self.offset + take].zeroize();
            self.offset += take;
            count += take;
            self.bytes -= take;
            if self.offset == frame.len() {
                self.frames.pop_front();
                self.offset = 0;
            }
        }
        count
    }
}

#[derive(Default)]
struct ImageEvidence {
    prepared: bool,
    requested: bool,
    acknowledged: bool,
    tls_frames: usize,
}

impl ImageEvidence {
    fn verify(&self) -> Result<()> {
        if !self.requested || !self.acknowledged || self.tls_frames == 0 {
            return Err(Error::Device(
                "IMAGE acknowledgement or TLS evidence missing",
            ));
        }
        Ok(())
    }
}

struct OptionalAcks([usize; 256]);

impl OptionalAcks {
    fn expect(&mut self, target: u8) {
        self.0[usize::from(target)] += 1;
    }

    fn accept(&mut self, target: u8) -> Result<()> {
        let count = &mut self.0[usize::from(target)];
        if *count == 0 {
            return Err(Error::Device("unexpected or duplicate MCU acknowledgement"));
        }
        *count -= 1;
        Ok(())
    }
}

struct LateReplies([usize; 256]);

impl LateReplies {
    fn expect(&mut self, target: u8) {
        self.0[usize::from(target)] += 1;
    }

    fn accept(&mut self, frame: &[u8]) -> Result<bool> {
        let target = frame[4];
        let count = &mut self.0[usize::from(target)];
        if *count == 0 {
            return Ok(false);
        }
        if target == 0x50 {
            packet::nav(frame)?;
        } else if target & 0xf1 == 0x30 {
            if packet::fdt(frame)?.0 != 0x100 {
                return Ok(false);
            }
        } else {
            packet::control(frame, target, None)?;
        }
        *count -= 1;
        Ok(true)
    }
}

#[derive(Clone, Copy)]
enum Reply {
    Control(u8, Option<usize>),
    ManualFdt,
    Nav,
}

impl Reply {
    fn decode(self, frame: &[u8]) -> Result<Secret> {
        match self {
            Self::Control(command, length) => {
                packet::control(frame, command, length)?;
            }
            Self::ManualFdt => {
                packet::manual_fdt(frame)?;
            }
            Self::Nav => return packet::nav(frame),
        }
        Ok(Secret::new(frame.to_vec()))
    }
}

struct Exchange {
    target: u8,
    required_ack: bool,
    acknowledged: bool,
    reply: Option<Reply>,
    data: Option<Secret>,
    attempt: u8,
    deadline: Instant,
    data_timeout: Duration,
}

impl Exchange {
    fn new(target: u8, required_ack: bool, reply: Option<Reply>, timeout: Duration) -> Self {
        let data_timeout = timeout.max(CONTROL_TIMEOUT);
        Self {
            target,
            required_ack,
            acknowledged: false,
            reply,
            data: None,
            attempt: 1,
            deadline: Instant::now()
                + if required_ack {
                    ACK_TIMEOUT
                } else {
                    data_timeout
                },
            data_timeout,
        }
    }

    fn retry(&mut self) -> bool {
        if self.required_ack && !self.acknowledged && self.attempt == 1 {
            self.attempt = 2;
            self.deadline = Instant::now() + ACK_TIMEOUT;
            return true;
        }
        false
    }

    fn complete(&self) -> bool {
        (!self.required_ack || self.acknowledged) && (self.reply.is_none() || self.data.is_some())
    }

    fn accept(&mut self, frame: &[u8], optional: &mut OptionalAcks) -> Result<()> {
        if let Some(target) = packet::ack(frame)? {
            if self.required_ack && target == self.target && !self.acknowledged {
                self.acknowledged = true;
                // SpiSendDataToDeviceLock starts its event wait after the ACK wait.
                self.deadline = Instant::now() + self.data_timeout;
            } else {
                optional.accept(target)?;
            }
        } else {
            let reply = self.reply.ok_or(Error::Device("unexpected command data"))?;
            if self.data.is_some() {
                return Err(Error::Device("duplicate command data"));
            }
            self.data = Some(reply.decode(frame)?);
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq)]
enum TlsState {
    Off,
    Handshaking,
    Connected,
}

pub struct Sensor {
    device: Device,
    failed: bool,
    tls: TlsState,
    pending: TlsQueue,
    optional_acks: OptionalAcks,
    late_replies: LateReplies,
    init_prepared: bool,
    otp_parameters: Zeroizing<[u16; 2]>,
    dac: config::DacState,
    image: ImageEvidence,
    touch: touch::TouchState,
}

impl Sensor {
    pub fn open(raw_path: &Path, cancel: Rc<dyn Cancellation>) -> Result<Self> {
        Ok(Self {
            device: Device::open(raw_path, cancel)?,
            failed: false,
            tls: TlsState::Off,
            pending: TlsQueue::default(),
            optional_acks: OptionalAcks([0; 256]),
            late_replies: LateReplies([0; 256]),
            init_prepared: false,
            otp_parameters: Zeroizing::new([0; 2]),
            dac: config::DacState::default(),
            image: ImageEvidence::default(),
            touch: touch::TouchState::default(),
        })
    }

    fn run<T>(&mut self, operation: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let result = self.device.check().and_then(|()| operation(self));
        self.failed = result.is_err();
        result
    }

    pub fn descriptor(&self) -> std::os::fd::RawFd {
        self.device.descriptor()
    }

    pub fn sealed_input(&mut self) -> Result<Secret> {
        self.run(|sensor| sensor.device.sealed_input())
    }

    /// Split at WBDI14: the caller initializes FDT before downloading this table.
    /// Initialization failures remain retryable by the caller's OEM init loop.
    pub fn prepare(
        &mut self,
        dll: &Path,
        cached_identity: Option<&[u8; 32]>,
    ) -> Result<SensorInfo> {
        self.run(|_| Ok(()))?;
        let mut config = config::load(dll)?;
        if !self.init_prepared {
            self.run(|sensor| {
                for _ in 0..2 {
                    match sensor.exchange(
                        &packet::command(0x96, &[1, 0]),
                        true,
                        None,
                        CONTROL_TIMEOUT,
                    ) {
                        Ok(_) => break,
                        Err(error) => sensor.retry_check(&error)?,
                    }
                }
                // OEM HardResetMcu is a no-op returning 1 in this pinned DLL;
                // GetEvkVersion still makes its additional attempt afterwards.
                sensor.retry_init(INIT_ATTEMPTS + 1, false, |sensor| {
                    sensor.exchange(
                        &packet::command(0xa8, &[0, 0]),
                        true,
                        Some(Reply::Control(0xa8, None)),
                        CONTROL_TIMEOUT,
                    )
                })?;
                sensor.reset_idle()?;
                sensor.retry_init(INIT_ATTEMPTS, true, Self::check_chip)?;
                sensor.init_prepared = true;
                Ok(())
            })?;
        }
        // OTP and configuration share the caller's three-attempt loop.
        let otp = match self.read_otp() {
            Ok(otp) => otp,
            Err(error) => {
                self.retry_check(&error)?;
                if let Err(reset_error) = self.reset_sensor() {
                    self.retry_check(&reset_error)?;
                }
                return Err(error);
            }
        };
        let (identity, valid) = config::identity(
            otp.as_slice().try_into().expect("validated OTP size"),
            cached_identity,
        );
        let (threshold, tcode) =
            config::from_otp(&mut config, &identity, valid, &mut self.otp_parameters)?;
        if valid {
            self.dac.factory(&identity);
        }
        let mut info = SensorInfo {
            identity: *identity,
            sensor_id: [0; 16],
            threshold,
            tcode,
            config,
        };
        info.sensor_id.copy_from_slice(&identity[..16]);
        Ok(info)
    }

    pub fn fdt_parameters(&self) -> (u8, u16) {
        (self.otp_parameters[0] as u8, self.otp_parameters[1])
    }

    pub fn initialization_retryable(&self) -> bool {
        self.init_prepared && !self.failed
    }

    pub fn configure(&mut self, info: &SensorInfo) -> Result<()> {
        self.device.check()?;
        self.reset_idle()?;
        let frame = self.exchange(
            &packet::command(0x90, info.config.as_slice()),
            true,
            Some(Reply::Control(0x90, Some(2))),
            CONTROL_TIMEOUT,
        )?;
        if packet::control(&frame, 0x90, Some(2))?[0] != 1 {
            return Err(Error::Device("MCU rejected OEM runtime configuration"));
        }
        Ok(())
    }

    fn retry_check(&self, error: &Error) -> Result<()> {
        match error {
            Error::Cancelled => Err(Error::Cancelled),
            Error::Suspended => Err(Error::Suspended),
            Error::Shutdown => Err(Error::Shutdown),
            _ => self.device.check(),
        }
    }

    fn retry_init<T>(
        &mut self,
        mut attempts: usize,
        reset: bool,
        mut operation: impl FnMut(&mut Self) -> Result<T>,
    ) -> Result<T> {
        loop {
            match operation(self) {
                Ok(value) => return Ok(value),
                Err(error) => {
                    self.retry_check(&error)?;
                    if reset {
                        if let Err(reset_error) = self.reset_sensor() {
                            self.retry_check(&reset_error)?;
                        }
                    }
                    attempts -= 1;
                    if attempts == 0 {
                        return Err(error);
                    }
                }
            }
        }
    }

    fn reset_sensor(&mut self) -> Result<()> {
        self.drain()?;
        self.exchange(
            &packet::command(0xa2, &[5, 0x14]),
            true,
            Some(Reply::Control(0xa2, None)),
            CONTROL_TIMEOUT,
        )?;
        Ok(())
    }

    /// gfspi!0x18004f94c is a reset plus Sleep(1), not SetMode(IDLE).
    fn reset_idle(&mut self) -> Result<()> {
        let result = self.reset_sensor();
        self.device.pause(Duration::from_millis(1))?;
        result
    }

    /// Called only after classification 1, not during initialization.
    pub fn check_dac_once(&mut self) -> Result<()> {
        self.run(|sensor| {
            if sensor.dac.checked {
                return Ok(());
            }
            let first = sensor
                .read_register(0x220, 2, CONTROL_TIMEOUT)
                .and_then(|read| sensor.dac.check(&read));
            if let Err(error) = first {
                sensor.retry_check(&error)?;
                sensor.reset_idle()?;
                let read = sensor.read_register(0x220, 2, CONTROL_TIMEOUT)?;
                sensor.dac.check(&read)?;
            }
            Ok(())
        })
    }

    fn check_chip(&mut self) -> Result<()> {
        self.drain()?;
        let frame = self.exchange(
            &packet::register_request(0, 4),
            true,
            Some(Reply::Control(0x82, Some(4))),
            ACK_TIMEOUT,
        )?;
        if packet::chip_id(&frame)? != 0x2205 {
            return Err(Error::Device("unsupported fingerprint sensor"));
        }
        Ok(())
    }

    fn read_otp(&mut self) -> Result<Secret> {
        self.drain()?;
        let frame = self.exchange(
            &packet::command(0xa6, &[0, 0]),
            true,
            Some(Reply::Control(0xa6, Some(32))),
            ACK_TIMEOUT,
        )?;
        packet::otp(&frame)
    }

    fn read_register(&mut self, address: u16, bytes: u16, timeout: Duration) -> Result<Secret> {
        self.drain()?;
        let frame = self.exchange(
            &packet::register_request(address, bytes),
            true,
            Some(Reply::Control(0x82, Some(usize::from(bytes)))),
            timeout,
        )?;
        packet::registers(&frame, usize::from(bytes))
    }

    pub fn start_tls(&mut self) -> Result<()> {
        self.run(|sensor| {
            if sensor.tls != TlsState::Off {
                return Err(Error::Device("TLS session already started"));
            }
            sensor.tls = TlsState::Handshaking;
            sensor.drain()?;
            sensor.pending = TlsQueue::default();
            sensor.device.write(&packet::command(0xd0, &[0, 0]), true)?;
            sensor.optional_acks.expect(0xd0);
            Ok(())
        })
    }

    /// Failed TLS attempts use D4 before WBDI40/39 and another D0, not IDLE70.
    pub fn unlock_tls(&mut self) -> Result<()> {
        self.device.check()?;
        self.tls = TlsState::Handshaking;
        let result = self.exchange(&packet::command(0xd4, &[0, 0]), true, None, ACK_TIMEOUT);
        self.pending = TlsQueue::default();
        self.tls = TlsState::Off;
        self.failed = false;
        result.map(|_| ())
    }

    pub fn finish_tls(&mut self) -> Result<()> {
        self.run(|sensor| {
            if sensor.tls != TlsState::Handshaking {
                return Err(Error::Device("TLS finalization outside handshake"));
            }
            sensor.drain()?;
            if let Err(error) =
                sensor.exchange(&packet::command(0xd4, &[0, 0]), true, None, ACK_TIMEOUT)
            {
                sensor.retry_check(&error)?;
            }
            let mut connected = false;
            let mut locked = false;
            for _ in 0..3 {
                sensor.device.pause(Duration::from_millis(10))?;
                locked = false;
                let state = sensor
                    .exchange(
                        &packet::command(0xae, &[0x55]),
                        false,
                        Some(Reply::Control(0xae, Some(10))),
                        CONTROL_TIMEOUT,
                    )
                    .and_then(|frame| packet::tls_state(&frame));
                match state {
                    Ok(state) => {
                        (connected, locked) = state;
                        if connected {
                            break;
                        }
                    }
                    Err(error) => sensor.retry_check(&error)?,
                }
            }
            if locked {
                if let Err(error) =
                    sensor.exchange(&packet::command(0xd4, &[0, 0]), true, None, ACK_TIMEOUT)
                {
                    sensor.retry_check(&error)?;
                }
            }
            if !connected {
                return Err(Error::Device("MCU did not confirm authenticated TLS"));
            }
            sensor.tls = TlsState::Connected;
            Ok(())
        })
    }

    /// Cleanup is intentionally independent of Cancellation and failed state.
    /// The caller closes the device by dropping Sensor after enclave teardown.
    /// TLS raced with IDLE is retained, never silently accepted as a fresh image.
    pub fn idle(&mut self) -> Result<()> {
        let request = packet::command(0x70, &[0x14, 0]);
        let expected = packet::command(0xb0, &[0x70, 1]);
        let mut prior_error = None;
        for _ in 0..2 {
            self.device.write(&request, false)?;
            let deadline = Instant::now() + ACK_TIMEOUT;
            while let Some(frame) = self.device.read(Wait::Until(deadline), false)? {
                if frame.as_slice() == expected.as_slice() {
                    return prior_error.map_or(Ok(()), Err);
                }
                // In-flight events are discarded during failed-session cleanup,
                // not reused to acknowledge any later live transaction.
                let result = match packet::envelope(&frame) {
                    Ok(Kind::Tls) => self.queue_tls(&frame[4..]),
                    Ok(Kind::Control) => match packet::ack(&frame) {
                        Ok(Some(target)) if self.optional_acks.0[usize::from(target)] != 0 => {
                            self.optional_acks.accept(target)
                        }
                        Ok(_) if self.failed => Ok(()),
                        Ok(Some(_)) => {
                            Err(Error::Device("unexpected MCU acknowledgement before IDLE"))
                        }
                        Ok(None) => self.late_replies.accept(&frame).and_then(|late| {
                            if late {
                                Ok(())
                            } else if frame[4] & 0xf1 == 0x30 {
                                // DOWN/UP remains armed until IDLE takes effect.
                                // Validate the last event, then discard it with this session.
                                packet::fdt(&frame).map(|_| ())
                            } else {
                                Err(Error::Device(
                                    "unexpected control data before IDLE acknowledgement",
                                ))
                            }
                        }),
                        Err(error) => Err(error),
                    },
                    Err(error) => Err(error),
                };
                if prior_error.is_none() {
                    prior_error = result.err();
                }
            }
        }
        Err(prior_error.unwrap_or(Error::Device("IDLE acknowledgement missing")))
    }

    pub fn nav(&mut self) -> Result<Secret> {
        self.run(|sensor| {
            sensor.require_released()?;
            sensor.drain()?;
            sensor.exchange(
                &packet::command(0x50, &[1, 0]),
                true,
                Some(Reply::Nav),
                CONTROL_TIMEOUT,
            )
        })
    }

    pub fn stability_threshold(&mut self) -> Result<u8> {
        self.run(|sensor| {
            let register = sensor.read_register(0x82, 2, CONTROL_TIMEOUT)?;
            // ChipRegRead swaps pairs; the high byte is wire reply[7].
            Ok(register[1])
        })
    }

    pub fn reset_image_evidence(&mut self) -> Result<()> {
        self.run(|sensor| {
            sensor.empty()?;
            sensor.image = ImageEvidence {
                prepared: true,
                ..ImageEvidence::default()
            };
            Ok(())
        })
    }

    pub fn request_image(&mut self) -> Result<()> {
        self.run(|sensor| {
            if sensor.tls != TlsState::Connected || !sensor.image.prepared || sensor.image.requested
            {
                return Err(Error::Device("IMAGE request without fresh evidence state"));
            }
            sensor.empty()?;
            sensor.image.requested = true;
            sensor.exchange(&packet::command(0x20, &[1, 0]), true, None, ACK_TIMEOUT)?;
            sensor.image.acknowledged = true;
            Ok(())
        })
    }

    /// Call after the runtime has read one complete image, before using its result.
    pub fn verify_image_evidence(&mut self) -> Result<()> {
        self.run(|sensor| {
            sensor.empty()?;
            sensor.image.verify()?;
            sensor.image = ImageEvidence::default();
            Ok(())
        })
    }

    pub fn assert_tls_empty(&mut self) -> Result<()> {
        self.run(Self::empty)
    }

    fn empty(&mut self) -> Result<()> {
        self.drain()?;
        if self.pending.bytes != 0 {
            return Err(Error::Device("unexpected queued TLS data"));
        }
        Ok(())
    }

    fn queue_tls(&mut self, bytes: &[u8]) -> Result<()> {
        if self.tls == TlsState::Off {
            return Err(Error::Device("TLS data before session start"));
        }
        self.pending.push(bytes)?;
        if self.image.requested {
            self.image.tls_frames += 1;
        }
        Ok(())
    }

    fn unsolicited(&mut self, frame: &[u8]) -> Result<()> {
        match packet::envelope(frame)? {
            Kind::Tls => self.queue_tls(&frame[4..]),
            Kind::Control => {
                if let Some(target) = packet::ack(frame)? {
                    self.optional_acks.accept(target)
                } else if self.late_replies.accept(frame)? {
                    Ok(())
                } else if frame[4] & 0xf1 == 0x30 {
                    self.queue_touch(frame)
                } else {
                    Err(Error::Device("unexpected or stale MCU data"))
                }
            }
        }
    }

    fn drain(&mut self) -> Result<()> {
        while let Some(frame) = self.device.read(Wait::Now, true)? {
            self.unsolicited(&frame)?;
        }
        Ok(())
    }

    fn exchange(
        &mut self,
        request: &[u8],
        required_ack: bool,
        reply: Option<Reply>,
        timeout: Duration,
    ) -> Result<Secret> {
        let target = request[4];
        self.device.write(request, true)?;
        if !required_ack {
            self.optional_acks.expect(target);
        }
        let mut exchange = Exchange::new(target, required_ack, reply, timeout);
        while !exchange.complete() {
            let Some(frame) = self.device.read(Wait::Until(exchange.deadline), true)? else {
                if exchange.retry() {
                    // OEM SpiSendDataToDevice retransmits the identical request once
                    // on an ACK timeout. Never retransmit merely for missing data.
                    self.device.write(request, true)?;
                    exchange.deadline = Instant::now() + ACK_TIMEOUT;
                    self.optional_acks.expect(target);
                    if reply.is_some() {
                        self.late_replies.expect(target);
                    }
                    continue;
                }
                if required_ack && !exchange.acknowledged {
                    self.optional_acks.expect(target);
                }
                if reply.is_some() && exchange.data.is_none() {
                    self.late_replies.expect(target);
                }
                return Err(Error::Device(if required_ack && !exchange.acknowledged {
                    "MCU command acknowledgement missing after retransmission"
                } else {
                    "MCU command data deadline expired"
                }));
            };
            match packet::envelope(&frame)? {
                Kind::Tls => self.queue_tls(&frame[4..])?,
                Kind::Control => {
                    let data = packet::ack(&frame)?.is_none();
                    if data
                        && (frame[4] != target || exchange.data.is_some())
                        && self.late_replies.accept(&frame)?
                    {
                        continue;
                    }
                    if data
                        && frame[4] & 0xf1 == 0x30
                        && !(matches!(reply, Some(Reply::ManualFdt))
                            && packet::fdt(&frame)?.0 == 0x100)
                    {
                        self.queue_touch(&frame)?;
                        continue;
                    }
                    exchange.accept(&frame, &mut self.optional_acks)?;
                }
            }
        }
        Ok(exchange.data.unwrap_or_else(|| Secret::new(Vec::new())))
    }
}

impl TlsIo for Sensor {
    fn receive(&mut self, output: &mut [u8]) -> Result<usize> {
        self.run(|sensor| {
            if sensor.tls == TlsState::Off || !(1..=32768).contains(&output.len()) {
                return Err(Error::Device("invalid TLS receive request"));
            }
            let deadline = Instant::now() + Duration::from_millis(100);
            while sensor.pending.bytes == 0 {
                let Some(frame) = sensor.device.read(Wait::Until(deadline), true)? else {
                    break;
                };
                sensor.unsolicited(&frame)?;
            }
            Ok(sensor.pending.read(output))
        })
    }

    fn send(&mut self, input: &[u8]) -> Result<usize> {
        self.run(|sensor| {
            if sensor.tls == TlsState::Off || !(1..=32768).contains(&input.len()) {
                return Err(Error::Device("invalid TLS send request"));
            }
            for chunk in input.chunks(packet::TLS_CHUNK) {
                sensor.device.write(&packet::tls(chunk)?, true)?;
                // OEM SendTLSPackage waits before reusing the EC TX mailbox.
                sensor.device.pause(Duration::from_millis(1))?;
            }
            Ok(input.len())
        })
    }
}

#[cfg(test)]
mod tests;
