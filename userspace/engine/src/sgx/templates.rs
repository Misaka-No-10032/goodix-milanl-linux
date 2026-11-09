// SPDX-License-Identifier: GPL-2.0-only
// OEM Milan 3.00.20 enrollment, sealing, comparison and adaptation.
use super::{
    Component, MAX_TEMPLATE, MIN_TEMPLATE, MatchOutcome, Runtime, TemplateMode, UNSET,
    abi::{self, buffer, pointer},
};
use crate::{
    Secret,
    error::{Error, Result},
};

impl Runtime {
    pub fn begin_enrollment(&mut self) -> Result<()> {
        if !self.attached || self.template_failed {
            return Err(Error::Enclave("enrollment context is not ready"));
        }
        // EngineAdapterCreateEnrollment is idempotent while InProgress is set.
        if self.template_mode == TemplateMode::Enrollment {
            return Ok(());
        }
        if self.template_mode != TemplateMode::None {
            return Err(Error::Enclave("enrollment context is not ready"));
        }
        self.template_mode = TemplateMode::Enrollment;
        self.template_used = 0;
        self.template_progress = 0;
        let mut samples = 12u8;
        let mut create = abi::TemplateCreate {
            result: UNSET,
            samples: pointer(&mut samples),
        };
        let result = self
            .call(Component::Engine, 10, &mut create)
            .and_then(|()| {
                if create.result != 0 {
                    return Err(Error::Enclave("OEM enrollment creation failed"));
                }
                Ok(())
            });
        self.template_failed = result.is_err();
        result
    }
    pub fn resume_enrollment(&mut self, used: i32, progress: i32) -> Result<()> {
        if !self.attached || self.template_mode != TemplateMode::None || self.template_failed {
            return Err(Error::Enclave("enrollment context is not ready"));
        }
        validate_resume(used, progress)?;
        // S3 preserves host metadata, not enclave features. Engine11 creates a
        // new session itself, copies used/progress when used < 3, or returns -3
        // AFTER allocating that session. Calling Engine10 here skips this rule.
        self.template_mode = TemplateMode::Enrollment;
        self.template_used = used;
        self.template_progress = progress;
        self.sample_mode = None;
        Ok(())
    }
    pub fn enrollment_state(&self) -> Option<(i32, i32)> {
        (self.template_mode == TemplateMode::Enrollment)
            .then_some((self.template_used, self.template_progress))
    }
    fn enrollment_active(&self) -> bool {
        self.template_mode == TemplateMode::Enrollment && !self.template_failed
    }
    pub fn add_sample(&mut self) -> Result<Option<u16>> {
        if !self.enrollment_active() || self.sample_mode != Some(true) {
            return Err(Error::Enclave("no fresh accepted enrollment sample"));
        }
        self.sample_mode = None;
        let result = self.add_sample_inner();
        self.template_failed = result.is_err();
        result
    }
    fn add_sample_inner(&mut self) -> Result<Option<u16>> {
        // UpdateEnrollment clears a previously completed host count before
        // Engine11, including after S3 between the last status and commit.
        if self.template_used == 12 {
            self.template_used = 0;
        }
        let (mut samples, mut used, mut progress, mut liveness, mut hint) =
            (12u8, self.template_used, self.template_progress, 0u8, 0u32);
        let mut merge = abi::TemplateMerge {
            result: UNSET,
            samples: pointer(&mut samples),
            used: pointer(&mut used),
            progress: pointer(&mut progress),
            liveness: pointer(&mut liveness),
            hint: pointer(&mut hint),
        };
        self.call(Component::Engine, 11, &mut merge)?;
        match merge_outcome(merge.result)? {
            Merge::Retry => return Ok(None),
            Merge::Discard => {
                self.close_template()?;
                return Ok(None);
            }
            Merge::Accepted => {}
        }
        // EngineAdapterUpdateEnrollment queries status only after a successful
        // merge. In particular, -1 may have destroyed the enclave session and
        // must not be followed by Engine12 (which dereferences that session).
        let (mut required, mut used, mut progress) = (UNSET, UNSET, UNSET);
        let mut query = abi::TemplateQuery {
            result: UNSET,
            required: pointer(&mut required),
            used: pointer(&mut used),
            progress: pointer(&mut progress),
        };
        self.call(Component::Engine, 12, &mut query)?;
        self.template_used = used;
        self.template_progress = progress;
        validate_enrollment_progress(query.result, required, used, progress)?;
        Ok(Some(used as u16))
    }
    /// Produces opaque sealed bytes. The caller owns persistence and closing the
    /// enrollment; the OEM adapter closes only after storage succeeds.
    pub fn seal(&mut self) -> Result<Secret> {
        if self.template_mode != TemplateMode::Enrollment
            || self.template_failed
            || self.template_used != 12
            || self.template_progress != 100
        {
            return Err(Error::Enclave("enrollment is not complete"));
        }
        let result = (|| {
            let mut bytes = 0u64;
            let mut length = abi::TemplateLength {
                result: UNSET,
                bytes: pointer(&mut bytes),
            };
            self.call(Component::Engine, 14, &mut length)?;
            if length.result != 0 || !(MIN_TEMPLATE as u64..=MAX_TEMPLATE as u64).contains(&bytes) {
                return Err(Error::Enclave("invalid sealed template length"));
            }
            let mut blob = Secret::new(vec![0; bytes as usize]);
            let mut seal = abi::ImageCipher {
                result: UNSET,
                buffer: buffer(&mut blob),
                bytes,
            };
            self.call(Component::Engine, 15, &mut seal)?;
            if seal.result != 0 {
                return Err(Error::Enclave("OEM template sealing failed"));
            }
            self.template_mode = TemplateMode::Sealed;
            Ok(blob)
        })();
        self.template_failed = result.is_err();
        result
    }
    pub fn close_template(&mut self) -> Result<()> {
        let result = if self.template_mode == TemplateMode::None {
            Ok(())
        } else {
            self.call_none(Component::Engine, 4)
        };
        self.template_blob.take();
        self.template_mode = TemplateMode::None;
        self.template_failed = false;
        self.template_used = 0;
        self.template_progress = 0;
        // Do not reuse a host sample after ending this operation. Engine4 itself
        // only frees enrollment/template state, not the current feature image.
        self.sample_mode = None;
        result
    }
    pub fn import_template(&mut self, blob: &[u8]) -> Result<()> {
        if !self.attached
            || self.template_failed
            || !matches!(
                self.template_mode,
                TemplateMode::None | TemplateMode::Imported
            )
            || !(MIN_TEMPLATE..=MAX_TEMPLATE).contains(&blob.len())
        {
            return Err(Error::Template("invalid sealed template import"));
        }
        // The OEM gallery loop replaces candidates without closing the operation.
        self.template_blob = Some(Secret::new(blob.to_vec()));
        self.template_mode = TemplateMode::Imported;
        Ok(())
    }
    pub fn compare(&mut self, new_image: bool, verify: bool) -> Result<Option<MatchOutcome>> {
        if self.template_mode != TemplateMode::Imported
            || self.template_failed
            || self.sample_mode != Some(false)
        {
            return Err(Error::Enclave(
                "no accepted verification image or imported template",
            ));
        }
        let result = self.compare_inner(new_image, verify);
        self.template_failed = result.is_err();
        result
    }
    fn compare_inner(&mut self, new_image: bool, verify: bool) -> Result<Option<MatchOutcome>> {
        // Keep the input allocation local so its marshalling pointer never
        // aliases a mutable borrow of Runtime during OCALL processing.
        let mut blob = self
            .template_blob
            .take()
            .ok_or(Error::Enclave("missing imported template"))?;
        let (mut study, mut liveness, mut update_bytes) = (1u8, 0u8, 0u32);
        let mut compare = abi::TemplateCompare {
            result: UNSET,
            blob: buffer(&mut blob),
            bytes: blob.len() as u64,
            study: pointer(&mut study),
            update_bytes: pointer(&mut update_bytes),
            liveness: pointer(&mut liveness),
            new_image: u8::from(new_image),
            reserved: [0; 7],
        };
        self.call(Component::Engine, 17, &mut compare)?;
        // Engine36 is diagnostic, not an extra acceptance gate. Engine17 maps
        // algorithm errors and poor-quality nonmatches to its own result codes.
        let outcome = comparison_outcome(compare.result, update_bytes, verify)?;
        if outcome == Comparison::Retry {
            self.template_blob = Some(blob);
            return Ok(None);
        }
        let updated = if outcome == Comparison::Updated {
            let mut updated = Secret::new(vec![0; update_bytes as usize]);
            let mut request = abi::TemplateUpdate {
                result: UNSET,
                buffer: buffer(&mut updated),
                bytes: update_bytes,
            };
            self.call(Component::Engine, 16, &mut request)?;
            if request.result != 0 {
                return Err(Error::Enclave("OEM template update failed"));
            }
            self.template_blob = Some(Secret::new(updated.to_vec()));
            Some(updated)
        } else {
            self.template_blob = Some(blob);
            None
        };
        Ok(Some(MatchOutcome {
            matched: outcome != Comparison::NoMatch,
            updated,
        }))
    }
}

fn validate_resume(used: i32, progress: i32) -> Result<()> {
    if !(0..=12).contains(&used) || !(0..=100).contains(&progress) {
        return Err(Error::Enclave("invalid OEM enrollment resume state"));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Merge {
    Accepted,
    Retry,
    Discard,
}
fn merge_outcome(application: i32) -> Result<Merge> {
    match application {
        0 => Ok(Merge::Accepted),
        -1 | -2 => Ok(Merge::Retry),
        0x8001 | 0x8002 => Ok(Merge::Discard),
        -3 => Err(Error::Enclave(
            "OEM enrollment cannot resume after power loss",
        )),
        _ => Err(Error::Enclave("OEM enrollment merge failed")),
    }
}
fn validate_enrollment_progress(
    result: i32,
    required: i32,
    used: i32,
    progress: i32,
) -> Result<()> {
    match result {
        -1 | 0 => {}
        0x8001 => return Err(Error::Enclave("OEM enrollment status allocation failed")),
        0x8002 | 0x8006 => return Err(Error::Enclave("OEM enrollment status failed")),
        _ => return Err(Error::Enclave("invalid OEM enrollment status")),
    }
    // These are the sensor-3 enrolAddImage/Engine12 invariants, not an assumed
    // increment from the UI's last reported stage. Status owns the host count.
    if required != 12
        || !(1..=12).contains(&used)
        || result != if used < 12 { -1 } else { 0 }
        || progress != used * 100 / 12
    {
        return Err(Error::Enclave("invalid OEM enrollment progress"));
    }
    Ok(())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Comparison {
    NoMatch,
    Retry,
    Match,
    Updated,
}
fn comparison_outcome(application: i32, update_bytes: u32, verify: bool) -> Result<Comparison> {
    match application {
        -1 => Ok(Comparison::NoMatch),
        0x83 if verify => Ok(Comparison::NoMatch),
        -2 => Ok(Comparison::Retry),
        0 => Ok(Comparison::Match),
        1 if (MIN_TEMPLATE..=MAX_TEMPLATE).contains(&(update_bytes as usize)) => {
            Ok(Comparison::Updated)
        }
        0x8007 => Err(Error::Template("sealed template authentication failed")),
        _ => Err(Error::Enclave("invalid OEM comparison result")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn oem_input_pointer_and_flag_layouts() {
        assert_eq!(size_of::<abi::OverlayConfig>(), 40);
        assert_eq!(offset_of!(abi::OverlayConfig, values), 0);
        assert_eq!(
            offset_of!(abi::PreprocessorInitialize, need_update_calibration),
            32
        );
        assert_eq!(offset_of!(abi::PreprocessorInitialize, base_valid), 40);
        assert_eq!(offset_of!(abi::Preprocess, sensor_type), 24);
        assert_eq!(offset_of!(abi::TemplateMerge, liveness), 32);
        assert_eq!(size_of::<abi::TemplateCompare>(), 56);
        assert_eq!(offset_of!(abi::TemplateCompare, study), 24);
        assert_eq!(offset_of!(abi::TemplateCompare, update_bytes), 32);
        assert_eq!(offset_of!(abi::TemplateCompare, liveness), 40);
        assert_eq!(offset_of!(abi::TemplateCompare, new_image), 48);
        assert_eq!(offset_of!(abi::TemplateCompare, reserved), 49);
        assert_eq!(size_of::<abi::TemplateUpdate>(), 24);
        assert_eq!(offset_of!(abi::TemplateUpdate, bytes), 16);
    }

    #[test]
    fn status_uses_the_enclave_count_and_progress() {
        for used in 1..=12 {
            assert!(
                validate_enrollment_progress(
                    if used < 12 { -1 } else { 0 },
                    12,
                    used,
                    used * 100 / 12
                )
                .is_ok()
            );
        }
        assert!(validate_enrollment_progress(0, 12, 11, 91).is_err());
        assert!(validate_enrollment_progress(-1, 12, 12, 100).is_err());
        assert!(validate_enrollment_progress(-1, 12, 2, 17).is_err());
        assert!(validate_enrollment_progress(0, 12, 13, 100).is_err());
        assert!(validate_enrollment_progress(-1, 11, 2, 16).is_err());
        for result in [0x8001, 0x8002, 0x8006, 0x8008, UNSET] {
            assert!(validate_enrollment_progress(result, 12, 12, 100).is_err());
        }
    }

    #[test]
    fn resume_preserves_host_metadata_without_prejudging_engine11() {
        for used in 0..=12 {
            // >=3 must reach Engine11, which allocates before returning -3.
            assert!(validate_resume(used, used * 100 / 12).is_ok());
        }
        // UpdateEnrollment resets a completed used count without clearing
        // progress; suspension before the next merge can preserve this pair.
        assert!(validate_resume(0, 100).is_ok());
        assert!(validate_resume(-1, 0).is_err());
        assert!(validate_resume(13, 100).is_err());
        assert!(validate_resume(0, 101).is_err());
    }

    #[test]
    fn merge_retries_are_not_status_queries_or_fatal_errors() {
        assert_eq!(merge_outcome(0).unwrap(), Merge::Accepted);
        for result in [-1, -2] {
            assert_eq!(merge_outcome(result).unwrap(), Merge::Retry);
        }
        for result in [0x8001, 0x8002] {
            assert_eq!(merge_outcome(result).unwrap(), Merge::Discard);
        }
        for result in [-3, 0x8005, 0x8008, UNSET] {
            assert!(matches!(merge_outcome(result), Err(Error::Enclave(_))));
        }
    }

    #[test]
    fn comparison_uses_application_status_not_diagnostic_scores() {
        for verify in [false, true] {
            assert_eq!(
                comparison_outcome(-1, 0, verify).unwrap(),
                Comparison::NoMatch
            );
            assert_eq!(
                comparison_outcome(-2, 0, verify).unwrap(),
                Comparison::Retry
            );
            assert_eq!(comparison_outcome(0, 0, verify).unwrap(), Comparison::Match);
            assert_eq!(
                comparison_outcome(1, 560, verify).unwrap(),
                Comparison::Updated
            );
            assert!(comparison_outcome(1, 559, verify).is_err());
            assert!(comparison_outcome(1, 1_048_577, verify).is_err());
            assert!(comparison_outcome(0x8002, 0, verify).is_err());
        }
        assert_eq!(
            comparison_outcome(0x83, 0, true).unwrap(),
            Comparison::NoMatch
        );
        assert!(comparison_outcome(0x83, 0, false).is_err());
    }
}
