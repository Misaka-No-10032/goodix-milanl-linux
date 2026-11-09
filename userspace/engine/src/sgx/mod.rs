// SPDX-License-Identifier: GPL-2.0-only
// OEM Milan 3.00.20 runtime: local attestation, calibration and image processing.
mod abi;
mod baseline;
mod loader;
mod ocall;
mod templates;
#[cfg(test)]
mod tests;
mod transition;

use crate::{
    Cancellation, Secret, TlsIo,
    error::{Error, Result},
    state::State,
};
use abi::{buffer, pointer};
use loader::{Image, Package};
use std::{
    path::{Path, PathBuf},
    ptr,
    rc::Rc,
};
use zeroize::Zeroize;

const IMAGE_PACKED: usize = 0x56a0;
const NAV_PACKED: usize = 0x1290;
const ENCRYPTED_BYTES: usize = 0x7380 + 0x20;
const WANT_READ: i32 = -0x6900;
const UNSET: i32 = i32::MIN;
const MIN_TEMPLATE: usize = 560;
const MAX_TEMPLATE: usize = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsProgress {
    /// Exactly one complete IMAGE_PACKED+13 application image is available.
    pub application: bool,
    pub state: i32,
}
pub enum ClassifiedImage {
    Finger(Secret),
    Temperature,
    Rearm,
}
pub struct MatchOutcome {
    pub matched: bool,
    pub updated: Option<Secret>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Component {
    Launch,
    Wbdi,
    Engine,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum TemplateMode {
    None,
    Enrollment,
    Sealed,
    Imported,
}

/// Owns all native enclave state and the one process-wide transition boundary.
/// The Rc cancellation owner makes Runtime neither Send nor Sync. Results must
/// not be published until the caller has successfully called close_template().
pub struct Runtime {
    assets: PathBuf,
    cancel: Rc<dyn Cancellation>,
    le: Option<Image>,
    wbdi: Option<Image>,
    engine: Option<Image>,
    transition: Option<transition::Transition>,
    features: [u64; 6],
    sealed_input: Secret,
    state: State,
    base: baseline::BaseState,
    tls_state: i32,
    tls_live: bool,
    attached: bool,
    image_buffers: bool,
    algorithm_base_valid: u32,
    sensor_type_for_algorithm: u32,
    calibration_pending: bool,
    sample_mode: Option<bool>,
    template_mode: TemplateMode,
    template_failed: bool,
    template_used: i32,
    template_progress: i32,
    template_blob: Option<Secret>,
}
impl Runtime {
    pub fn open(
        assets: &Path,
        state_directory: &Path,
        sealed: &[u8],
        cancel: Rc<dyn Cancellation>,
    ) -> Result<Self> {
        if !(0x230..=2048).contains(&sealed.len()) {
            return Err(Error::Enclave("incorrect sealed firmware input length"));
        }
        cancel.check()?;
        let transition = transition::Transition::new(cancel.clone())?;
        let features = loader::cpu_features()?;
        let le = Package::open(&assets.join("windows-le.pages"), cancel.as_ref())?
            .load(&[0; 304], cancel.as_ref())?;
        let mut runtime = Self {
            assets: assets.to_owned(),
            cancel,
            le: Some(le),
            wbdi: None,
            engine: None,
            transition: Some(transition),
            features,
            sealed_input: Secret::new(sealed.to_vec()),
            state: State::open(state_directory)?,
            base: baseline::BaseState::default(),
            tls_state: 0,
            tls_live: false,
            attached: false,
            image_buffers: false,
            algorithm_base_valid: 0,
            sensor_type_for_algorithm: 0,
            calibration_pending: false,
            sample_mode: None,
            template_mode: TemplateMode::None,
            template_failed: false,
            template_used: 0,
            template_progress: 0,
            template_blob: None,
        };
        let mut features = runtime.features;
        runtime.call(Component::Launch, -1, &mut features)?;
        let mut cert = loader::exact_asset::<632>(assets, "goodix-whitelist.bin")?;
        let mut whitelist = abi::Whitelist {
            result: u32::MAX,
            cert: buffer(&mut cert),
            bytes: cert.len() as u32,
        };
        runtime.call(Component::Launch, 1, &mut whitelist)?;
        if whitelist.result != 0 {
            return Err(Error::Enclave("OEM launch whitelist rejected"));
        }
        let (package, token) = runtime.authorize("goodix")?;
        runtime.wbdi = Some(package.load(&token, runtime.cancel.as_ref())?);
        let mut features = runtime.features;
        runtime.call(Component::Wbdi, -1, &mut features)?;
        Ok(runtime)
    }
    fn authorize(&mut self, name: &str) -> Result<(Package, Secret)> {
        let package = Package::open(
            &self.assets.join(format!("{name}.pages")),
            self.cancel.as_ref(),
        )?;
        let mut measurement =
            loader::exact_asset::<32>(&self.assets, &format!("{name}-mrenclave.bin"))?;
        let mut signer = loader::exact_asset::<32>(&self.assets, &format!("{name}-mrsigner.bin"))?;
        package.verify_identity(&measurement, &signer)?;
        let mut attributes = [4u64, 3];
        let mut token = Secret::new(vec![0; 304]);
        let mut request = abi::Authorization {
            result: u32::MAX,
            measurement: buffer(&mut measurement),
            signer: buffer(&mut signer),
            attributes: pointer(&mut attributes),
            token: buffer(&mut token),
        };
        self.call(Component::Launch, 0, &mut request)?;
        if request.result != 0 || token[..4] != 1u32.to_le_bytes() {
            return Err(Error::Enclave("OEM launch authorization rejected"));
        }
        Ok((package, token))
    }
    pub fn tls_initialize(&mut self, io: &mut dyn TlsIo) -> Result<()> {
        if self.tls_live {
            self.call_none(Component::Wbdi, 40)?;
        }
        self.tls_state = 0;
        self.tls_live = true;
        let mut request = abi::TlsInitialize {
            result: UNSET,
            log_level: 0,
        };
        self.call_io(Component::Wbdi, 39, pointer(&mut request), Some(io))?;
        if request.result != 0 {
            let _ = self.state.remove("Goodix_Cache.bin");
        }
        if matches!(request.result, 0 | 1) {
            Ok(())
        } else {
            Err(Error::Enclave("OEM TLS initialization failed"))
        }
    }
    pub fn tls_step(&mut self, io: &mut dyn TlsIo) -> Result<TlsProgress> {
        if !self.tls_live {
            return Err(Error::Enclave("TLS is not initialized"));
        }
        let mut result = UNSET;
        self.call_io(Component::Wbdi, 41, pointer(&mut result), Some(io))?;
        if self.tls_state < 0 || (result < 0 && result != WANT_READ) {
            return Err(Error::Enclave("OEM TLS application read failed"));
        }
        let application = result == (IMAGE_PACKED + 13) as i32;
        if application && self.tls_state != 16 {
            return Err(Error::Enclave("image arrived before TLS establishment"));
        }
        Ok(TlsProgress {
            application,
            state: self.tls_state,
        })
    }
    pub fn initialize_engine(&mut self) -> Result<()> {
        if self.tls_state != 16 || self.engine.is_some() {
            return Err(Error::Enclave(
                "engine initialization requires fresh established TLS",
            ));
        }
        let (package, token) = self.authorize("engine")?;
        self.engine = Some(package.load(&token, self.cancel.as_ref())?);
        let mut features = self.features;
        self.call(Component::Engine, -1, &mut features)?;
        let mut sensor = 3u32;
        let (mut quality, mut coverage, mut overlay, mut preoverlay, mut liveness, mut retry) =
            (20u8, 65u8, 100u8, 100u8, 0u8, 0u8);
        let mut settings = [0u32, 0, 13, 13, 0, 0x02030104, 0x02030104, 0x02030104, 12];
        let mut version = [0u8; 64];
        let mut attach = abi::Attach {
            result: UNSET,
            sensor: pointer(&mut sensor),
            quality: pointer(&mut quality),
            coverage: pointer(&mut coverage),
            overlay: pointer(&mut overlay),
            preoverlay: pointer(&mut preoverlay),
            liveness: pointer(&mut liveness),
            retry: pointer(&mut retry),
            version: buffer(&mut version),
            version_bytes: 63,
            settings: pointer(&mut settings),
            settings_bytes: 36,
        };
        self.call(Component::Engine, 1, &mut attach)?;
        application(attach.result, "OEM algorithm attach failed")?;
        self.attached = true;
        if !version.starts_with(b"Milan_v_3.00.20\0") {
            return Err(Error::Enclave("only OEM Milan 3.00.20 is supported"));
        }
        let mut overlays = [4u8, 1, 5, 8, 4];
        let mut overlay = abi::OverlayConfig {
            values: overlays.each_mut().map(pointer),
        };
        self.call(Component::Engine, 2, &mut overlay)?;
        self.sensor_type_for_algorithm = 0;
        let mut input = 0x7380u64;
        let mut output = 0u32;
        let mut length = abi::DataLength {
            input: pointer(&mut input),
            output: pointer(&mut output),
        };
        self.call(Component::Engine, 6, &mut length)?;
        if output != ENCRYPTED_BYTES as u32 {
            return Err(Error::Enclave("unexpected OEM encrypted image length"));
        }
        self.initialize_link()?;
        let mut modern = 1u32;
        self.call(Component::Wbdi, 28, &mut modern)?;
        self.call(Component::Engine, 33, &mut modern)
    }
    fn initialize_link(&mut self) -> Result<()> {
        let (mut msg1, mut msg2, mut msg3) = (
            Secret::new(vec![0; 0x240]),
            Secret::new(vec![0; 0x200]),
            Secret::new(vec![0; 0x1c4]),
        );
        let (mut bytes1, mut bytes2, mut bytes3) = (0u32, 0u32, 0u32);
        let mut server = abi::DhOutput {
            result: UNSET,
            buffer: buffer(&mut msg1),
            capacity: msg1.len() as u32,
            bytes: pointer(&mut bytes1),
        };
        self.call(Component::Wbdi, 62, &mut server)?;
        if server.result != 0 || bytes1 != msg1.len() as u32 {
            return Err(Error::Enclave("WBDI attestation step one failed"));
        }
        let mut client = abi::DhExchange {
            result: UNSET,
            input: buffer(&mut msg1),
            input_bytes: bytes1,
            output: buffer(&mut msg2),
            capacity: msg2.len() as u32,
            bytes: pointer(&mut bytes2),
        };
        self.call(Component::Engine, 42, &mut client)?;
        if client.result != 0 || bytes2 != msg2.len() as u32 {
            return Err(Error::Enclave("engine attestation step one failed"));
        }
        let mut server = abi::DhExchange {
            result: UNSET,
            input: buffer(&mut msg2),
            input_bytes: bytes2,
            output: buffer(&mut msg3),
            capacity: msg3.len() as u32,
            bytes: pointer(&mut bytes3),
        };
        self.call(Component::Wbdi, 63, &mut server)?;
        if server.result != 0 || bytes3 != msg3.len() as u32 {
            return Err(Error::Enclave("WBDI attestation step two failed"));
        }
        let mut client = abi::DhFinish {
            result: UNSET,
            input: buffer(&mut msg3),
            bytes: bytes3,
        };
        self.call(Component::Engine, 43, &mut client)?;
        application(client.result, "engine attestation step two failed")?;
        // The authenticated OEM hello completes both channel state machines.
        const CONFIRMATION: &[u8; 48] = b"------------- Hello DH DONE -------------------\0";
        for (sender, generate_ordinal, receiver, receive_ordinal) in [
            (Component::Wbdi, 66, Component::Engine, 45),
            (Component::Engine, 44, Component::Wbdi, 67),
        ] {
            let mut encrypted = Secret::new(vec![0; 0x50]);
            let mut plain = Secret::new(vec![0; CONFIRMATION.len()]);
            let (mut encrypted_bytes, mut plain_bytes) = (0u32, 0u32);
            let mut generate = abi::DhOutput {
                result: UNSET,
                buffer: buffer(&mut encrypted),
                capacity: encrypted.len() as u32,
                bytes: pointer(&mut encrypted_bytes),
            };
            self.call(sender, generate_ordinal, &mut generate)?;
            if generate.result != 0 || encrypted_bytes != encrypted.len() as u32 {
                return Err(Error::Enclave("channel confirmation generation failed"));
            }
            let mut receive = abi::DhExchange {
                result: UNSET,
                input: buffer(&mut encrypted),
                input_bytes: encrypted_bytes,
                output: buffer(&mut plain),
                capacity: plain.len() as u32,
                bytes: pointer(&mut plain_bytes),
            };
            self.call(receiver, receive_ordinal, &mut receive)?;
            if receive.result != 0
                || plain_bytes != CONFIRMATION.len() as u32
                || plain.as_slice() != CONFIRMATION
            {
                return Err(Error::Enclave("channel confirmation authentication failed"));
            }
        }
        let (mut server_state, mut client_state) = (0i32, 0i32);
        self.call(Component::Wbdi, 69, &mut server_state)?;
        self.call(Component::Engine, 47, &mut client_state)?;
        if server_state != 7 || client_state != 7 {
            return Err(Error::Enclave(
                "local attestation did not establish both channels",
            ));
        }
        Ok(())
    }
    pub fn initialize_image_buffers(&mut self) -> Result<()> {
        let mut release = abi::RingRelease {
            retry: 0,
            reserved: 0,
        };
        self.call(Component::Wbdi, 9, &mut release)?;
        self.call_none(Component::Wbdi, 1)?;
        let (mut image_bytes, mut nav_bytes, mut sensor) = (0x7380u16, 0x18c0u16, 3u32);
        let mut request = abi::ImageBuffers {
            result: UNSET,
            image_bytes: pointer(&mut image_bytes),
            nav_bytes: pointer(&mut nav_bytes),
            sensor: pointer(&mut sensor),
            retry: 0,
            maximum: 1,
        };
        self.image_buffers = true;
        self.call(Component::Wbdi, 2, &mut request)?;
        application(request.result, "WBDI image buffer initialization failed")
    }
    pub fn initialize_fdt(&mut self, threshold: u8, tcode: u16) -> Result<()> {
        let (mut sensor, mut threshold, mut tcode) = (3u32, threshold, tcode);
        let mut request = abi::FdtInitialize {
            sensor: pointer(&mut sensor),
            threshold: pointer(&mut threshold),
            tcode: pointer(&mut tcode),
        };
        self.call(Component::Wbdi, 14, &mut request)
    }
    fn ring(&mut self, expected: i32) -> Result<()> {
        let mut empty = -1i32;
        self.call(Component::Wbdi, 4, &mut empty)?;
        if empty != expected {
            return Err(Error::Enclave("unexpected WBDI image ring state"));
        }
        Ok(())
    }
    pub fn clear_ring(&mut self) -> Result<()> {
        self.call_none(Component::Wbdi, 3)?;
        self.ring(1)
    }
    /// Input is the 4752 packed NAV bytes followed by its original four-byte CRC.
    pub fn submit_nav(&mut self, packed: &[u8]) -> Result<()> {
        validate_nav(packed)?;
        self.ring(1)?;
        let mut source = Secret::new(packed.to_vec());
        let mut request = abi::NavSource {
            result: u8::MAX,
            buffer: buffer(&mut source),
            bytes: source.len() as u16,
        };
        self.call(Component::Wbdi, 18, &mut request)?;
        if request.result != 1 {
            return Err(Error::Enclave("WBDI NAV submission failed"));
        }
        self.ring(0)?;
        self.call_none(Component::Wbdi, 6)?;
        self.clear_ring()
    }
    pub fn accept_baseline_image(&mut self) -> Result<()> {
        self.ring(0)?;
        self.call_none(Component::Wbdi, 5)?;
        self.clear_ring()
    }
    pub fn encoded_base_fdt(&self) -> &[u8; 24] {
        &self.base.fdt
    }
    pub fn invalidate_base(&mut self) {
        self.base.valid = 0;
    }
    pub fn temperature_updated(&mut self) {
        self.base.need_update = true;
    }
    pub fn classify_image(&mut self) -> Result<ClassifiedImage> {
        self.sample_mode = None;
        self.ring(0)?;
        self.call_none(Component::Wbdi, 5)?;
        let mut encrypted = Secret::new(vec![0; ENCRYPTED_BYTES]);
        let mut cipher = abi::ImageCipher {
            result: UNSET,
            buffer: buffer(&mut encrypted),
            bytes: ENCRYPTED_BYTES as u64,
        };
        self.call(Component::Wbdi, 36, &mut cipher)?;
        self.clear_ring()?;
        match cipher.result {
            0 => Ok(ClassifiedImage::Temperature),
            1 => Ok(ClassifiedImage::Finger(encrypted)),
            -1 | 2 | 3 => Ok(ClassifiedImage::Rearm),
            _ => Err(Error::Enclave("OEM touch classification failed")),
        }
    }
    pub fn preprocess(
        &mut self,
        mut image: Secret,
        sensor_id: &[u8; 16],
        enrollment: bool,
    ) -> Result<bool> {
        let mut encrypted = Secret::new(vec![0; ENCRYPTED_BYTES]);
        let mut cipher = abi::ImageCipher {
            result: UNSET,
            buffer: buffer(&mut encrypted),
            bytes: ENCRYPTED_BYTES as u64,
        };
        self.call(Component::Wbdi, 38, &mut cipher)?;
        application(cipher.result, "WBDI base encryption failed")?;
        let changed = std::mem::take(&mut self.base.need_update);
        if self.algorithm_base_valid == 0 || changed {
            let (mut need_update, mut valid) = (u32::from(changed), self.algorithm_base_valid);
            let mut sensor_id = Secret::new(sensor_id.to_vec());
            let mut initialize = abi::PreprocessorInitialize {
                result: UNSET,
                image: buffer(&mut encrypted),
                bytes: ENCRYPTED_BYTES as u32,
                sensor_id: buffer(&mut sensor_id),
                need_update_calibration: pointer(&mut need_update),
                base_valid: pointer(&mut valid),
            };
            self.call(Component::Engine, 7, &mut initialize)?;
            application(initialize.result, "OEM preprocessor initialization failed")?;
            self.calibration_pending = true;
            if valid == 1 {
                self.algorithm_base_valid = 1;
            }
        }
        if self.algorithm_base_valid == 0 {
            return Ok(false);
        }
        let (mut size, mut liveness, mut mode, mut sensor_type) = (
            ENCRYPTED_BYTES as u32,
            0u8,
            u8::from(enrollment),
            self.sensor_type_for_algorithm,
        );
        let mut request = abi::Preprocess {
            result: UNSET,
            image: buffer(&mut image),
            bytes: ENCRYPTED_BYTES as u32,
            sensor_type: pointer(&mut sensor_type),
            liveness: pointer(&mut liveness),
            size: pointer(&mut size),
            enrollment: pointer(&mut mode),
        };
        self.call(Component::Engine, 8, &mut request)?;
        let mut decision = UNSET;
        if request.result == 0 {
            self.call(Component::Engine, 9, &mut decision)?;
            if matches!(decision, 0 | -1) {
                self.engine_results()?;
            }
            if decision == -2 {
                self.algorithm_base_valid = 0;
            }
        }
        let accepted = quality_accepted(request.result, decision, enrollment);
        if accepted {
            self.sample_mode = Some(enrollment);
        }
        Ok(accepted)
    }
    fn engine_results(&mut self) -> Result<[i32; 8]> {
        let mut scores = [0i32; 8];
        let mut outputs = scores.each_mut().map(pointer);
        self.call(Component::Engine, 36, &mut outputs)?;
        Ok(scores)
    }
    fn call<T>(&mut self, component: Component, ordinal: i64, parameters: &mut T) -> Result<()> {
        self.call_io(component, ordinal, pointer(parameters), None)
    }
    fn call_none(&mut self, component: Component, ordinal: i64) -> Result<()> {
        self.call_io(component, ordinal, ptr::null_mut(), None)
    }
    fn call_io(
        &mut self,
        component: Component,
        mut ordinal: i64,
        mut parameters: abi::Pointer,
        mut io: Option<&mut dyn TlsIo>,
    ) -> Result<()> {
        let image = match component {
            Component::Launch => &self.le,
            Component::Wbdi => &self.wbdi,
            Component::Engine => &self.engine,
        };
        let tcs = image
            .as_ref()
            .ok_or(Error::Enclave("enclave is not loaded"))?
            .tcs;
        self.transition
            .as_mut()
            .ok_or(Error::Enclave("native session is closed"))?
            .begin()?;
        let result = (|| {
            for _ in 0..100 {
                let transition = self.transition.as_mut().unwrap();
                transition.check()?;
                let (status, exit) = transition.enter(tcs, ordinal, parameters)?;
                if exit.ordinal == -1 {
                    return if status == 0 {
                        Ok(())
                    } else {
                        Err(Error::Enclave("OEM ECALL returned SGX failure"))
                    };
                }
                self.handle_ocall(component, exit.ordinal, exit.parameters, &mut io)?;
                ordinal = -2;
                parameters = ptr::null_mut();
            }
            Err(Error::Enclave("OEM ECALL exceeded OCALL bound"))
        })();
        let ended = self.transition.as_mut().unwrap().end();
        let result = result.and(ended);
        if result.is_err() {
            self.transition.as_mut().unwrap().poisoned = true;
        }
        result
    }
    /// Suspend invalidates isgx mappings. Mark that known loss without entering
    /// any enclave; finish still releases all mappings and host-side secrets.
    pub fn invalidate(&mut self) {
        if let Some(transition) = self.transition.as_mut() {
            transition.poisoned = true;
        }
    }
    /// Fallible orderly teardown. AEX-aborted/faulted TCSs are never re-entered;
    /// their mappings and host secrets are still dropped on every exit path.
    pub fn finish(&mut self) -> Result<()> {
        if self.transition.is_none() {
            return Ok(());
        }
        let mut first = None;
        if self.calibration_pending && self.usable() {
            retain_first(&mut first, self.call_none(Component::Engine, 27));
        }
        self.calibration_pending = false;
        // A previously reported abort/invalidation is not a new cleanup error.
        // Only failures encountered by this teardown are returned below.
        if self.image_buffers && self.usable() {
            retain_first(&mut first, self.call_none(Component::Wbdi, 3));
            if self.usable() {
                let mut request = abi::RingRelease {
                    retry: 0,
                    reserved: 0,
                };
                retain_first(&mut first, self.call(Component::Wbdi, 9, &mut request));
            }
            if self.usable() {
                retain_first(&mut first, self.call_none(Component::Wbdi, 1));
            }
        }
        if self.attached && self.usable() {
            let mut detached = UNSET;
            let result = self
                .call(Component::Engine, 3, &mut detached)
                .and_then(|()| application(detached, "OEM algorithm detach failed"));
            retain_first(&mut first, result);
        }
        if self.tls_live && self.usable() {
            retain_first(&mut first, self.call_none(Component::Wbdi, 40));
        }
        for image in [self.engine.take(), self.wbdi.take(), self.le.take()]
            .into_iter()
            .flatten()
        {
            retain_first(&mut first, image.release());
        }
        self.transition.take();
        self.sealed_input.zeroize();
        self.base = baseline::BaseState::default();
        self.template_blob.take();
        self.template_mode = TemplateMode::None;
        self.tls_live = false;
        self.attached = false;
        self.image_buffers = false;
        self.algorithm_base_valid = 0;
        first.map_or(Ok(()), Err)
    }
    pub(crate) fn usable(&self) -> bool {
        self.transition
            .as_ref()
            .is_some_and(|transition| !transition.poisoned)
    }
}
fn retain_first(first: &mut Option<Error>, result: Result<()>) {
    if let Err(error) = result {
        if first.is_none() {
            *first = Some(error);
        }
    }
}
fn application(result: i32, message: &'static str) -> Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(Error::Enclave(message))
    }
}

fn packed_crc(packed: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in packed {
        crc ^= (*byte as u32) << 24;
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
fn validate_nav(source: &[u8]) -> Result<()> {
    if source.len() != NAV_PACKED + 4 {
        return Err(Error::Enclave("incorrect packed NAV length"));
    }
    let footer = &source[NAV_PACKED..];
    let expected = u32::from_be_bytes([footer[2], footer[3], footer[0], footer[1]]);
    if packed_crc(&source[..NAV_PACKED]) != expected {
        return Err(Error::Enclave("packed NAV CRC mismatch"));
    }
    Ok(())
}
fn quality_accepted(application: i32, decision: i32, enrollment: bool) -> bool {
    application == 0 && decision != -2 && !(enrollment && decision == -1)
}
