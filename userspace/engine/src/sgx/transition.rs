// SPDX-License-Identifier: GPL-2.0-only
// Single-owner transition boundary for the Windows x64 enclave ABI.
use super::abi::{Exit, Pointer, Stack};
use crate::{
    Cancellation,
    error::{Error, Result},
};
use std::{
    ffi::c_void,
    mem::{offset_of, zeroed},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    rc::Rc,
    sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU32, AtomicUsize, Ordering},
    time::{Duration, Instant},
};
use zeroize::Zeroize;

std::arch::global_asm!(include_str!("entry.S"), options(att_syntax));
unsafe extern "C" {
    fn milanl_enclave_enter(
        tcs: usize,
        ordinal: i64,
        parameters: Pointer,
        output: *mut Exit,
    ) -> u64;
    fn milanl_enclave_eenter_instruction();
    fn milanl_enclave_eresume_instruction();
    fn milanl_enclave_aep();
    fn milanl_enclave_abort();
}

const MACHINE_LIMIT: Duration = Duration::from_secs(20);
const FAULT_SIGNALS: [i32; 3] = [libc::SIGSEGV, libc::SIGILL, libc::SIGBUS];
static OWNED: AtomicBool = AtomicBool::new(false);
static OWNER_TID: AtomicI32 = AtomicI32::new(0);
static PREVIOUS_HANDLERS: [AtomicUsize; 3] = [const { AtomicUsize::new(libc::SIG_DFL) }; 3];
static PREVIOUS_FLAGS: [AtomicI32; 3] = [const { AtomicI32::new(0) }; 3];
#[unsafe(no_mangle)]
static MILANL_ENCLAVE_CONTEXT: AtomicPtr<Context> = AtomicPtr::new(ptr::null_mut());

#[repr(C, align(16))]
struct Context {
    host_stack: usize,
    stack_top: usize,
    aep_stack: usize,
    reserved: usize,
    host_fx: [u8; 512],
    active: AtomicBool,
    aborted: AtomicU32,
    cancel: Rc<dyn Cancellation>,
    deadline: Instant,
    error: Option<Error>,
}
const _: () = {
    assert!(offset_of!(Context, host_stack) == 0);
    assert!(offset_of!(Context, stack_top) == 8);
    assert!(offset_of!(Context, aep_stack) == 16);
    assert!(offset_of!(Context, host_fx) == 32);
};
struct Owner;
impl Owner {
    fn acquire() -> Result<Self> {
        OWNED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                Error::Enclave("a native SGX session already owns the transition stack")
            })?;
        Ok(Self)
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        OWNED.store(false, Ordering::Release);
    }
}

// The only Rust callback reached by AEP. It runs on the saved host stack with
// host FX restored. Catching here prevents any unwinding across global_asm.
#[unsafe(no_mangle)]
extern "C" fn milanl_enclave_aex_check() -> u32 {
    let context = MILANL_ENCLAVE_CONTEXT.load(Ordering::Acquire);
    // The exclusive owner publishes this allocation before installing signals.
    let context = unsafe { &mut *context };
    let checked = catch_unwind(AssertUnwindSafe(|| {
        context.cancel.check()?;
        if Instant::now() >= context.deadline {
            return Err(Error::Enclave("enclave machine deadline expired"));
        }
        Ok(())
    }))
    .unwrap_or(Err(Error::Enclave("cancellation callback panicked")));
    match checked {
        Ok(()) => 0,
        Err(error) => {
            context.error = Some(error);
            context.aborted.store(1, Ordering::Release);
            1
        }
    }
}

extern "C" fn tick(_signal: i32) {}
fn boundary_pc(pc: usize) -> bool {
    pc == milanl_enclave_eenter_instruction as *const () as usize
        || pc == milanl_enclave_eresume_instruction as *const () as usize
        || pc == milanl_enclave_aep as *const () as usize
}
extern "C" fn fault(signal: i32, info: *mut libc::siginfo_t, opaque: *mut c_void) {
    // This handler never treats a Rust, OCALL, allocator, or unrelated-thread
    // fault as recoverable. No vendor memory is inspected from a signal handler.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
    if tid == OWNER_TID.load(Ordering::Acquire) {
        let context = MILANL_ENCLAVE_CONTEXT.load(Ordering::Acquire);
        if !context.is_null() {
            let registers =
                unsafe { &mut (*(opaque.cast::<libc::ucontext_t>())).uc_mcontext.gregs };
            if unsafe { (*context).active.load(Ordering::Acquire) }
                && boundary_pc(registers[libc::REG_RIP as usize] as usize)
            {
                unsafe { (*context).aborted.store(2, Ordering::Release) };
                registers[libc::REG_RIP as usize] =
                    milanl_enclave_abort as *const () as libc::greg_t;
                return;
            }
        }
    }
    if let Some(index) = FAULT_SIGNALS.iter().position(|number| *number == signal) {
        let previous = PREVIOUS_HANDLERS[index].load(Ordering::Acquire);
        if previous == libc::SIG_IGN {
            return;
        }
        if previous != libc::SIG_DFL {
            if PREVIOUS_FLAGS[index].load(Ordering::Acquire) & libc::SA_SIGINFO != 0 {
                let handler: extern "C" fn(i32, *mut libc::siginfo_t, *mut c_void) =
                    unsafe { std::mem::transmute(previous) };
                handler(signal, info, opaque);
            } else {
                let handler: extern "C" fn(i32) = unsafe { std::mem::transmute(previous) };
                handler(signal);
            }
            return;
        }
    }
    unsafe {
        let mut action: libc::sigaction = zeroed();
        action.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(signal, &action, ptr::null_mut());
        libc::syscall(libc::SYS_tgkill, libc::getpid(), tid, signal);
    }
}

pub(super) struct Transition {
    pub stack: Stack,
    context: Box<Context>,
    previous: [libc::sigaction; 3],
    installed: usize,
    previous_tick: libc::sigaction,
    tick_installed: bool,
    timer: Option<libc::timer_t>,
    previous_mask: libc::sigset_t,
    armed: bool,
    pub poisoned: bool,
    _owner: Owner,
}
impl Transition {
    pub fn new(cancel: Rc<dyn Cancellation>) -> Result<Self> {
        let owner = Owner::acquire()?;
        let stack = Stack::new()?;
        let mut transition = Self {
            context: Box::new(Context {
                host_stack: 0,
                stack_top: stack.top(),
                aep_stack: 0,
                reserved: 0,
                host_fx: [0; 512],
                active: AtomicBool::new(false),
                aborted: AtomicU32::new(0),
                cancel,
                deadline: Instant::now(),
                error: None,
            }),
            stack,
            previous: unsafe { zeroed() },
            installed: 0,
            previous_tick: unsafe { zeroed() },
            tick_installed: false,
            timer: None,
            previous_mask: unsafe { zeroed() },
            armed: false,
            poisoned: false,
            _owner: owner,
        };
        MILANL_ENCLAVE_CONTEXT.store(ptr::from_mut(&mut *transition.context), Ordering::Release);
        OWNER_TID.store(
            unsafe { libc::syscall(libc::SYS_gettid) } as i32,
            Ordering::Release,
        );
        for (index, signal) in FAULT_SIGNALS.iter().enumerate() {
            os_result(unsafe {
                libc::sigaction(*signal, ptr::null(), &mut transition.previous[index])
            })?;
            let previous = &transition.previous[index];
            PREVIOUS_HANDLERS[index].store(previous.sa_sigaction, Ordering::Release);
            PREVIOUS_FLAGS[index].store(previous.sa_flags, Ordering::Release);
            let mut action = *previous;
            action.sa_sigaction = fault as *const () as usize;
            action.sa_flags = (action.sa_flags | libc::SA_SIGINFO) & !libc::SA_RESETHAND;
            os_result(unsafe { libc::sigaction(*signal, &action, ptr::null_mut()) })?;
            transition.installed += 1;
        }
        os_result(unsafe {
            libc::sigaction(libc::SIGURG, ptr::null(), &mut transition.previous_tick)
        })?;
        if transition.previous_tick.sa_sigaction != libc::SIG_DFL
            && transition.previous_tick.sa_sigaction != libc::SIG_IGN
        {
            return Err(Error::Enclave(
                "SIGURG is already reserved by another component",
            ));
        }
        let mut action: libc::sigaction = unsafe { zeroed() };
        action.sa_sigaction = tick as *const () as usize;
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        os_result(unsafe { libc::sigaction(libc::SIGURG, &action, ptr::null_mut()) })?;
        transition.tick_installed = true;
        let mut event: libc::sigevent = unsafe { zeroed() };
        event.sigev_notify = libc::SIGEV_THREAD_ID;
        event.sigev_signo = libc::SIGURG;
        event.sigev_notify_thread_id = OWNER_TID.load(Ordering::Acquire);
        let mut timer: libc::timer_t = ptr::null_mut();
        os_result(unsafe { libc::timer_create(libc::CLOCK_MONOTONIC, &mut event, &mut timer) })?;
        transition.timer = Some(timer);
        Ok(transition)
    }
    pub fn begin(&mut self) -> Result<()> {
        if self.poisoned {
            return Err(Error::Enclave("native session is poisoned"));
        }
        self.context.cancel.check()?;
        self.context.deadline = Instant::now() + MACHINE_LIMIT;
        self.context.error = None;
        self.context.aborted.store(0, Ordering::Release);
        let urgent = urgent_set();
        let error =
            unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &urgent, &mut self.previous_mask) };
        if error != 0 {
            return Err(std::io::Error::from_raw_os_error(error).into());
        }
        self.armed = true;
        let tick = libc::timespec {
            tv_sec: 0,
            tv_nsec: 20_000_000,
        };
        let timer = libc::itimerspec {
            it_interval: tick,
            it_value: tick,
        };
        if let Err(error) = os_result(unsafe {
            libc::timer_settime(self.timer.unwrap(), 0, &timer, ptr::null_mut())
        }) {
            let _ = self.end();
            return Err(error);
        }
        self.context.active.store(true, Ordering::Release);
        Ok(())
    }
    pub fn check(&self) -> Result<()> {
        self.context.cancel.check()?;
        if Instant::now() >= self.context.deadline {
            return Err(Error::Enclave("enclave machine deadline expired"));
        }
        Ok(())
    }
    pub fn enter(&mut self, tcs: usize, ordinal: i64, parameters: Pointer) -> Result<(u64, Exit)> {
        let mut output = Exit {
            ordinal: i64::MIN,
            parameters: ptr::null_mut(),
        };
        let result = unsafe { milanl_enclave_enter(tcs, ordinal, parameters, &mut output) };
        if self.context.aborted.load(Ordering::Acquire) != 0 {
            self.poisoned = true;
            return Err(self
                .context
                .error
                .take()
                .unwrap_or(Error::Enclave("native SGX entry or resume fault")));
        }
        self.check()?;
        Ok((result, output))
    }
    pub fn end(&mut self) -> Result<()> {
        self.context.active.store(false, Ordering::Release);
        if !self.armed {
            return Ok(());
        }
        self.armed = false;
        // Block, disarm, drain, then restore the caller's mask. This prevents a
        // pending timer signal from escaping into a later session/disposition.
        let urgent = urgent_set();
        let blocked = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &urgent, ptr::null_mut()) };
        let disarmed = os_result(unsafe {
            libc::timer_settime(
                self.timer.unwrap(),
                0,
                &zeroed::<libc::itimerspec>(),
                ptr::null_mut(),
            )
        });
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        loop {
            let result = unsafe { libc::sigtimedwait(&urgent, ptr::null_mut(), &zero) };
            if result == libc::SIGURG {
                continue;
            }
            if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        let restored = unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous_mask, ptr::null_mut())
        };
        if blocked != 0 || restored != 0 {
            return Err(std::io::Error::from_raw_os_error(if blocked != 0 {
                blocked
            } else {
                restored
            })
            .into());
        }
        disarmed
    }
    pub fn wipe(&mut self) {
        self.stack.wipe();
        self.context.host_fx.zeroize();
    }
}
impl Drop for Transition {
    fn drop(&mut self) {
        let _ = self.end();
        if let Some(timer) = self.timer.take() {
            unsafe { libc::timer_delete(timer) };
        }
        if self.tick_installed {
            unsafe { libc::sigaction(libc::SIGURG, &self.previous_tick, ptr::null_mut()) };
        }
        for index in (0..self.installed).rev() {
            unsafe {
                libc::sigaction(FAULT_SIGNALS[index], &self.previous[index], ptr::null_mut())
            };
        }
        MILANL_ENCLAVE_CONTEXT.store(ptr::null_mut(), Ordering::Release);
        OWNER_TID.store(0, Ordering::Release);
        self.wipe();
    }
}
fn urgent_set() -> libc::sigset_t {
    let mut set: libc::sigset_t = unsafe { zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGURG);
    }
    set
}
fn os_result(result: i32) -> Result<()> {
    if result < 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "transition_tests.rs"]
mod tests;
