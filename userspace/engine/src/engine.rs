//! Connection-scoped OEM sensor/enclave lifecycle and sealed-template operations.

use crate::{
    Cancellation,
    capture::{self, BaselineIo},
    error::{Error, Result},
    lifecycle::{Modules, RequestControl, SuspendEpoch},
    protocol::{ENROLL_STAGES, Request, Response, VERIFY_INDEX},
    sensor::{Sensor, SensorInfo, TouchEvent},
    server::{Backend, IdleSource},
    sgx::{ClassifiedImage, Runtime},
};
use std::{
    path::PathBuf,
    rc::Rc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub struct Config {
    pub assets: PathBuf,
    pub device: PathBuf,
    pub state: PathBuf,
}

pub struct Engine<'a> {
    config: &'a Config,
    modules: &'a mut Modules,
    control: Rc<RequestControl>,
    session: Option<Session>,
    epoch: Option<SuspendEpoch>,
    suspended_enrollment: Option<(i32, i32)>,
    resuming: bool,
}

impl<'a> Engine<'a> {
    pub fn new(config: &'a Config, modules: &'a mut Modules, control: Rc<RequestControl>) -> Self {
        Self {
            config,
            modules,
            control,
            session: None,
            epoch: None,
            suspended_enrollment: None,
            resuming: false,
        }
    }

    fn remember_enrollment(&mut self) {
        if let Some(session) = &self.session {
            self.suspended_enrollment =
                session.runtime.as_ref().and_then(Runtime::enrollment_state);
            self.resuming = true;
        }
    }

    fn start(&mut self) -> Result<&mut Session> {
        let epoch = SuspendEpoch::read()?;
        if self.session.is_some() && self.epoch.as_ref() != Some(&epoch) {
            self.remember_enrollment();
            // isgx invalidates enclaves on both completed and aborted suspend.
            if let Some(runtime) = self
                .session
                .as_mut()
                .and_then(|session| session.runtime.as_mut())
            {
                runtime.invalidate();
            }
            self.discard().map_err(|e| Error::Cleanup(Box::new(e)))?;
        }
        if self.session.is_none() {
            self.modules.load()?;
            let cancel: Rc<dyn Cancellation> = self.control.clone();
            let sensor = Sensor::open(&self.config.device, cancel.clone())?;
            self.session = Some(Session {
                runtime: None,
                sensor: Some(sensor),
                info: None,
                cancel,
                awaiting_release: false,
                temperature: Temperature::default(),
            });
            let session = self.session.as_mut().unwrap();
            session.initialize(self.config, self.resuming)?;
            if let Some((used, progress)) = self.suspended_enrollment.take() {
                session
                    .runtime
                    .as_mut()
                    .unwrap()
                    .resume_enrollment(used, progress)?;
            }
            self.resuming = false;
            self.epoch = Some(epoch);
        }
        Ok(self.session.as_mut().unwrap())
    }

    fn discard(&mut self) -> Result<()> {
        let _guard = self.control.cleanup();
        self.epoch = None;
        match self.session.take() {
            Some(mut session) => session.close(),
            None => Ok(()),
        }
    }

    fn search(&mut self, gallery: &[&[u8]], verify: bool) -> Result<Response> {
        if gallery.is_empty() {
            return Ok(Response::NoMatch);
        }
        if gallery.iter().any(|blob| blob.len() < 560) {
            return Err(Error::Template("sealed template is too short"));
        }
        let session = self.start()?;
        session.runtime.as_mut().unwrap().close_template()?;
        if !session.capture(false)? {
            return Ok(Response::Retry);
        }
        let runtime = session.runtime.as_mut().unwrap();
        for (index, blob) in gallery.iter().enumerate() {
            runtime.import_template(blob)?;
            let Some(outcome) = runtime.compare(index == 0, verify)? else {
                runtime.close_template()?;
                return Ok(Response::Retry);
            };
            if outcome.matched {
                runtime.close_template()?;
                return Ok(Response::Match {
                    index: if verify { VERIFY_INDEX } else { index as u16 },
                    updated: outcome.updated,
                });
            }
        }
        runtime.close_template()?;
        Ok(Response::NoMatch)
    }
}

impl Backend for Engine<'_> {
    fn execute(&mut self, request: Request<'_>) -> Result<Response> {
        match request {
            Request::Hello => Ok(Response::Hello),
            Request::Cancel => {
                self.suspended_enrollment = None;
                self.resuming = false;
                self.discard().map_err(|e| Error::Cleanup(Box::new(e)))?;
                Ok(Response::Ok)
            }
            Request::Suspend => {
                self.remember_enrollment();
                self.discard().map_err(|e| Error::Cleanup(Box::new(e)))?;
                Ok(Response::Ok)
            }
            Request::Resume => {
                self.start()?;
                Ok(Response::Ok)
            }
            Request::EnrollBegin => {
                let runtime = self.start()?.runtime.as_mut().unwrap();
                runtime.begin_enrollment()?;
                Ok(Response::Ok)
            }
            Request::EnrollCapture => {
                let session = self.start()?;
                if session
                    .runtime
                    .as_ref()
                    .unwrap()
                    .enrollment_state()
                    .is_none()
                {
                    return Err(Error::Protocol("enrollment has not begun"));
                }
                if !session.capture(true)? {
                    return Ok(Response::Retry);
                }
                let runtime = session.runtime.as_mut().unwrap();
                let Some(used) = runtime.add_sample()? else {
                    return Ok(Response::Retry);
                };
                if used < ENROLL_STAGES {
                    return Ok(Response::EnrollStage(used));
                }
                let template = runtime.seal()?;
                runtime.close_template()?;
                Ok(Response::EnrollDone(template))
            }
            Request::Verify(blob) => self.search(&[blob], true),
            Request::Identify(gallery) => self.search(&gallery, false),
        }
    }

    fn idle_source(&self) -> Option<IdleSource> {
        let session = self.session.as_ref()?;
        let sensor = session.sensor.as_ref()?;
        Some(IdleSource {
            descriptor: sensor.descriptor(),
            deadline: if sensor.has_touch_event() {
                Some(Instant::now())
            } else {
                session.temperature.deadline
            },
        })
    }

    fn on_idle(&mut self) -> Result<()> {
        let session = self.start()?;
        if let Some(event) = session
            .sensor
            .as_mut()
            .unwrap()
            .wait_touch(Some(Instant::now()))?
        {
            session.touch_event(event, None)?;
        } else if session.temperature.due() {
            session.temperature_tick()?;
        }
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        self.suspended_enrollment = None;
        self.resuming = false;
        self.discard()
    }
}

#[derive(Default)]
struct Temperature {
    exists: bool,
    deadline: Option<Instant>,
    busy: bool,
}

impl Temperature {
    fn start(&mut self) {
        if !self.exists {
            self.exists = true;
            self.deadline = Some(Instant::now() + Duration::from_secs(5));
        }
    }
    fn stop(&mut self) {
        self.exists = false;
        self.deadline = None;
    }
    fn retry(&mut self) {
        if self.exists {
            self.deadline = Some(Instant::now() + Duration::from_secs(2));
        }
    }
    fn due(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }
}

struct Session {
    runtime: Option<Runtime>,
    sensor: Option<Sensor>,
    info: Option<SensorInfo>,
    cancel: Rc<dyn Cancellation>,
    awaiting_release: bool,
    temperature: Temperature,
}

impl Session {
    fn initialize(&mut self, config: &Config, resuming: bool) -> Result<()> {
        let sensor = self.sensor.as_mut().unwrap();
        let sealed = sensor.sealed_input()?;
        self.runtime = Some(Runtime::open(
            &config.assets,
            &config.state,
            &sealed,
            self.cancel.clone(),
        )?);
        drop(sealed);
        let runtime = self.runtime.as_mut().unwrap();
        let cached_identity = runtime.cached_identity()?;
        for attempt in 0..3 {
            let result = (|| {
                let info =
                    sensor.prepare(&config.assets.join("gfspi.dll"), cached_identity.as_deref())?;
                runtime.initialize_fdt(info.threshold, info.tcode)?;
                sensor.configure(&info)?;
                Ok(info)
            })();
            match result {
                Ok(info) => {
                    self.info = Some(info);
                    break;
                }
                Err(error) => {
                    self.cancel.check_wait()?;
                    if attempt == 2 || !sensor.initialization_retryable() || !runtime.usable() {
                        return Err(error);
                    }
                }
            }
        }
        let info = self.info.as_ref().unwrap();
        let (threshold, tcode) = sensor.fdt_parameters();
        sensor.set_touch_threshold(threshold);
        runtime.initialize_fdt(threshold, tcode)?;
        runtime.initialize_image_buffers()?;
        for attempt in 0..3 {
            let result = (|| {
                runtime.tls_initialize(sensor)?;
                sensor.start_tls()?;
                let deadline = Instant::now() + Duration::from_secs(15);
                loop {
                    capture::before(deadline)?;
                    let state = runtime.tls_step(sensor)?;
                    capture::before(deadline)?;
                    if state.application {
                        return Err(Error::Device("image received during TLS setup"));
                    }
                    if state.state == 16 {
                        break;
                    }
                }
                sensor.finish_tls()
            })();
            if result.is_ok() {
                break;
            }
            let error = result.unwrap_err();
            self.cancel.check_wait()?;
            // D4 is the OEM failure recovery, including the final failed attempt.
            let _ = sensor.unlock_tls();
            if attempt == 2 || !runtime.usable() {
                return Err(error);
            }
        }
        runtime.initialize_engine()?;
        let loaded = runtime.load_base(&info.identity)?;
        if let Some(encoded) = loaded {
            sensor.restore_fdt(&encoded);
        }
        // Cold setup updates even an imported base. S3 trusts a matched file;
        // without one it tries the updater once, then uses MCU-default DOWN on failure.
        let mut default_down = false;
        if !resuming || loaded.is_none() {
            let attempts = if resuming { 1 } else { 2 };
            for attempt in 0..attempts {
                match self.refresh_base() {
                    Ok(()) => break,
                    Err(error) => {
                        self.retry_check(error)?;
                        if attempt + 1 == attempts {
                            default_down = true;
                        }
                    }
                }
            }
        }
        let sensor = self.sensor.as_mut().unwrap();
        if default_down {
            sensor.arm_default_down()?;
        } else {
            sensor.arm_down()?;
        }
        eprintln!("sensor: initialized");
        Ok(())
    }

    fn retry_check(&self, error: Error) -> Result<()> {
        self.cancel.check_wait()?;
        if matches!(
            error,
            Error::Cancelled | Error::Suspended | Error::Shutdown | Error::Cleanup(_)
        ) || !self.runtime.as_ref().unwrap().usable()
        {
            return Err(error);
        }
        Ok(())
    }

    fn refresh_base(&mut self) -> Result<()> {
        let runtime = self.runtime.as_mut().unwrap();
        let sensor = self.sensor.as_mut().unwrap();
        let initial = Zeroizing::new(*sensor.encoded_fdt());
        let exists = runtime.base_exists();
        let mut baseline = SensorBaseline {
            sensor,
            runtime,
            cancel: self.cancel.as_ref(),
        };
        capture::build_baseline(&mut baseline, &initial, exists)?;
        baseline
            .sensor
            .restore_fdt(baseline.runtime.encoded_base_fdt());
        Ok(())
    }

    fn acquire_image(&mut self, budget: Duration) -> Result<()> {
        let sensor = self.sensor.as_mut().unwrap();
        sensor.reset_image_evidence()?;
        sensor.request_image()?;
        read_image(self.runtime.as_mut().unwrap(), sensor, budget)?;
        sensor.verify_image_evidence()
    }

    fn check_base_after_release(&mut self) -> Result<()> {
        if self.runtime.as_ref().unwrap().base_valid() {
            return Ok(());
        }
        self.acquire_image(Duration::from_secs(6))?;
        let runtime = self.runtime.as_mut().unwrap();
        runtime.accept_baseline_image()?;
        let packed = self.sensor.as_mut().unwrap().nav()?;
        runtime.submit_nav(&packed)?;
        runtime.check_base()
    }

    fn temperature_update(&mut self) -> Result<()> {
        self.runtime.as_mut().unwrap().invalidate_base();
        self.sensor.as_mut().unwrap().clear_touch();
        match self.refresh_base() {
            Ok(()) => {
                self.sensor.as_mut().unwrap().arm_down()?;
                self.temperature.busy = false;
                self.runtime.as_mut().unwrap().temperature_updated();
            }
            Err(error) => {
                self.retry_check(error)?;
                self.temperature.retry();
                eprintln!("sensor: temperature base update failed");
            }
        }
        Ok(())
    }

    fn temperature_tick(&mut self) -> Result<()> {
        self.temperature.deadline = None;
        self.runtime.as_mut().unwrap().clear_ring()?;
        if let Err(error) = self.acquire_image(Duration::from_secs(6)) {
            self.retry_check(error)?;
            self.temperature.retry();
            return Ok(());
        }
        let runtime = self.runtime.as_mut().unwrap();
        runtime.accept_baseline_image()?;
        match runtime.classify_temperature()? {
            0 => {
                self.temperature.busy = true;
                self.temperature_update()
            }
            2 | 3 => self.sensor.as_mut().unwrap().arm_down(),
            _ => self.sensor.as_mut().unwrap().arm_up(),
        }
    }

    fn touch_event(&mut self, event: TouchEvent, enrollment: Option<bool>) -> Result<Option<bool>> {
        match event {
            TouchEvent::Down => {
                self.runtime.as_mut().unwrap().clear_ring()?;
                if let Some(enrollment) = enrollment {
                    self.temperature.stop();
                    if !self.temperature.busy {
                        return self.capture_down(enrollment);
                    }
                } else {
                    self.temperature.start();
                    self.sensor.as_mut().unwrap().arm_up()?;
                }
            }
            TouchEvent::Up | TouchEvent::Reset => {
                if event == TouchEvent::Reset {
                    if let Err(error) = self.sensor.as_mut().unwrap().recover_touch_reset() {
                        self.retry_check(error)?;
                    }
                }
                self.temperature.stop();
                self.awaiting_release = false;
                if !self.temperature.busy {
                    self.check_base_after_release()?;
                    self.sensor.as_mut().unwrap().arm_down()?;
                }
            }
            TouchEvent::Reverse => self.sensor.as_mut().unwrap().arm_down()?,
            TouchEvent::Wrong => {
                self.temperature.stop();
                self.awaiting_release = false;
                self.sensor.as_mut().unwrap().arm_down()?;
            }
        }
        Ok(None)
    }

    fn capture_down(&mut self, enrollment: bool) -> Result<Option<bool>> {
        if let Err(error) = self.acquire_image(Duration::from_secs(8)) {
            self.retry_check(error)?;
            self.sensor.as_mut().unwrap().arm_down()?;
            return Ok(None);
        }
        match self.runtime.as_mut().unwrap().classify_image()? {
            ClassifiedImage::Finger(image) => {
                let sensor = self.sensor.as_mut().unwrap();
                sensor.check_dac_once()?;
                let runtime = self.runtime.as_mut().unwrap();
                let accepted =
                    runtime.preprocess(image, &self.info.as_ref().unwrap().sensor_id, enrollment);
                // Every class-1 handoff has this tail, including quality rejection.
                let release = sensor
                    .post_capture_fdt()
                    .and_then(|()| runtime.clear_ring())
                    .and_then(|()| sensor.arm_up());
                self.awaiting_release = true;
                accepted.and_then(|accepted| release.map(|()| Some(accepted)))
            }
            ClassifiedImage::Temperature => {
                self.temperature.stop();
                self.temperature.busy = true;
                self.temperature_update()?;
                Ok(None)
            }
            ClassifiedImage::Rearm => {
                self.sensor.as_mut().unwrap().arm_down()?;
                Ok(None)
            }
        }
    }

    fn capture(&mut self, enrollment: bool) -> Result<bool> {
        if !self.awaiting_release {
            self.temperature.stop();
            self.sensor.as_mut().unwrap().arm_down()?;
        }
        eprintln!("capture: waiting for touch");
        loop {
            self.cancel.check_wait()?;
            let event = self
                .sensor
                .as_mut()
                .unwrap()
                .wait_touch(self.temperature.deadline)?;
            if let Some(event) = event {
                if let Some(accepted) = self.touch_event(event, Some(enrollment))? {
                    return Ok(accepted);
                }
            } else if self.temperature.due() {
                self.temperature_tick()?;
            }
        }
    }

    fn close(&mut self) -> Result<()> {
        self.temperature.stop();
        let enclave_result = match self.runtime.take() {
            Some(mut runtime) => runtime.finish(),
            None => Ok(()),
        };
        let sensor_result = match self.sensor.take() {
            Some(mut sensor) => sensor.idle(),
            None => Ok(()),
        };
        self.info.take();
        enclave_result.and(sensor_result)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("goodix-milanl-engine: cleanup failed: {error}");
        }
    }
}

fn read_image(runtime: &mut Runtime, sensor: &mut Sensor, budget: Duration) -> Result<()> {
    let deadline = Instant::now() + budget;
    loop {
        capture::before(deadline)?;
        let progress = runtime.tls_step(sensor)?;
        capture::before(deadline)?;
        if progress.state != 16 {
            return Err(Error::Device("TLS connection lost during image capture"));
        }
        if progress.application {
            return Ok(());
        }
    }
}

struct SensorBaseline<'a> {
    sensor: &'a mut Sensor,
    runtime: &'a mut Runtime,
    cancel: &'a dyn Cancellation,
}

impl BaselineIo for SensorBaseline<'_> {
    fn fdt(&mut self, down: &[u8; 24]) -> Result<[u8; 24]> {
        let raw = Zeroizing::new(self.sensor.manual_fdt(down)?);
        self.runtime.clear_ring()?;
        Ok(*raw)
    }
    fn navigation(&mut self) -> Result<()> {
        let packed = self.sensor.nav()?;
        self.runtime.submit_nav(&packed)
    }
    fn threshold(&mut self) -> Result<u8> {
        self.sensor.stability_threshold()
    }
    fn image(&mut self) -> Result<()> {
        self.sensor.reset_image_evidence()?;
        self.sensor.request_image()?;
        read_image(self.runtime, self.sensor, Duration::from_secs(6))?;
        self.sensor.verify_image_evidence()?;
        self.runtime.accept_baseline_image()
    }
    fn commit(&mut self, encoded: &[u8; 24]) -> Result<()> {
        self.runtime.commit_base(encoded)
    }
    fn checkpoint(&self) -> Result<()> {
        self.cancel.check_wait()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temperature_timer_is_created_once_and_does_not_rearm_after_expiry() {
        let mut timer = Temperature::default();
        assert!(!timer.exists && timer.deadline.is_none());
        timer.start();
        let first = timer.deadline;
        timer.start();
        assert_eq!(timer.deadline, first);
        timer.deadline = None;
        timer.start();
        assert!(timer.exists && timer.deadline.is_none());
        timer.retry();
        assert!(timer.deadline.is_some());
        timer.stop();
        timer.retry();
        assert!(!timer.exists && timer.deadline.is_none());
    }
}
