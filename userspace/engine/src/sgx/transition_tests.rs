// SPDX-License-Identifier: GPL-2.0-only
use super::*;
std::arch::global_asm!(include_str!("transition_test.S"), options(att_syntax));
unsafe extern "C" {
    fn milanl_enclave_test_aex(output: *mut Exit, snapshots: *mut u8) -> u64;
}
struct TestCancellation(std::cell::Cell<u8>);
impl Cancellation for TestCancellation {
    fn check(&self) -> Result<()> {
        match self.0.get() {
            1 => Err(Error::Cancelled),
            2 => panic!("test cancellation callback panic"),
            _ => Ok(()),
        }
    }
    fn descriptors(&self) -> Vec<std::os::fd::RawFd> {
        Vec::new()
    }
}
#[test]
fn synthetic_aex_restores_trusted_stack_fx_and_callee_saved_registers() {
    // One owner/test exercises all process-wide signal state, without SGX.
    let cancel = Rc::new(TestCancellation(std::cell::Cell::new(0)));
    let mut transition = Transition::new(cancel.clone()).unwrap();
    assert!(Transition::new(cancel.clone()).is_err());
    transition.begin().unwrap();
    transition.context.deadline = Instant::now();
    #[repr(align(16))]
    struct Snapshots([u8; 1024]);
    let mut snapshots = Snapshots([0; 1024]);
    let mut output = Exit {
        ordinal: 0,
        parameters: ptr::null_mut(),
    };
    let registers = unsafe { milanl_enclave_test_aex(&mut output, snapshots.0.as_mut_ptr()) };
    assert_eq!(registers, 0);
    assert_eq!(output.ordinal, -1);
    assert_eq!(output.parameters as usize, usize::MAX);
    assert_eq!(&snapshots.0[..416], &snapshots.0[512..928]);
    assert_eq!(transition.context.aborted.load(Ordering::Acquire), 1);
    assert!(matches!(
        transition.context.error,
        Some(Error::Enclave("enclave machine deadline expired"))
    ));
    transition.end().unwrap();
    let mut pending: libc::sigset_t = unsafe { zeroed() };
    assert_eq!(unsafe { libc::sigpending(&mut pending) }, 0);
    assert_eq!(unsafe { libc::sigismember(&pending, libc::SIGURG) }, 0);

    for mode in [1, 2] {
        transition.begin().unwrap();
        cancel.0.set(mode);
        assert_eq!(
            unsafe { milanl_enclave_test_aex(&mut output, snapshots.0.as_mut_ptr()) },
            0
        );
        assert_eq!(&snapshots.0[..416], &snapshots.0[512..928]);
        assert_eq!(transition.context.aborted.load(Ordering::Acquire), 1);
        if mode == 1 {
            assert!(matches!(transition.context.error, Some(Error::Cancelled)));
        } else {
            assert!(matches!(
                transition.context.error,
                Some(Error::Enclave("cancellation callback panicked"))
            ));
        }
        transition.end().unwrap();
        cancel.0.set(0);
    }

    // Test signal-PC filtering and redirect mechanics with a local ucontext;
    // neither an actual process fault nor an enclave instruction is needed.
    transition.begin().unwrap();
    let mut context: libc::ucontext_t = unsafe { zeroed() };
    context.uc_mcontext.gregs[libc::REG_RIP as usize] =
        milanl_enclave_eenter_instruction as *const () as libc::greg_t;
    fault(
        libc::SIGILL,
        ptr::null_mut(),
        ptr::from_mut(&mut context).cast(),
    );
    assert_eq!(
        context.uc_mcontext.gregs[libc::REG_RIP as usize],
        milanl_enclave_abort as *const () as libc::greg_t
    );
    assert_eq!(transition.context.aborted.load(Ordering::Acquire), 2);
    assert!(!boundary_pc(milanl_enclave_aex_check as *const () as usize));
    assert!(!boundary_pc(0));
    transition.end().unwrap();
    drop(transition);
    // The first failed duplicate acquisition must not have released the owner.
    let next = Transition::new(cancel.clone()).unwrap();
    use crate::{
        Secret,
        sgx::{Runtime, TemplateMode},
    };
    let state_directory =
        std::env::temp_dir().join(format!("milanl-transition-state-{}", std::process::id()));
    let mut runtime = Runtime {
        assets: std::path::PathBuf::new(),
        cancel: cancel.clone(),
        le: None,
        wbdi: None,
        engine: None,
        transition: Some(next),
        features: [0; 6],
        sealed_input: Secret::new(vec![1; 560]),
        state: crate::state::State::open(&state_directory).unwrap(),
        base: crate::sgx::baseline::BaseState::default(),
        tls_state: 16,
        tls_live: true,
        attached: true,
        image_buffers: true,
        algorithm_base_valid: 1,
        sensor_type_for_algorithm: 0,
        calibration_pending: true,
        sample_mode: None,
        template_mode: TemplateMode::Enrollment,
        template_failed: false,
        template_used: 0,
        template_progress: 0,
        template_blob: Some(Secret::new(vec![6; 560])),
    };
    runtime.invalidate();
    // No mapped enclaves exist in this test. Any accidental cleanup ECALL
    // would fail, while a previously poisoned session must clean up normally.
    assert!(runtime.finish().is_ok());
    assert!(runtime.transition.is_none());
    assert!(runtime.sealed_input.is_empty());
    assert!(runtime.template_blob.is_none());
    assert!(runtime.finish().is_ok());
    // A failure first encountered during an otherwise usable teardown remains
    // an error; invalidation must not become a blanket error suppression.
    runtime.transition = Some(Transition::new(cancel.clone()).unwrap());
    runtime.attached = true;
    assert!(runtime.finish().is_err());
    assert!(runtime.transition.is_none());
    let _reopened = Transition::new(cancel).unwrap();
    std::fs::remove_dir(state_directory).unwrap();
}
