// SPDX-License-Identifier: GPL-2.0-only
// OEM enclave marshalling records and the pinned Intel isgx ioctl ABI.
// sgx_user.h: Copyright (c) 2016 Intel Corporation, GPLv2 license option.

use crate::error::{Error, Result};
use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    ffi::c_void,
    mem::size_of,
    ptr::NonNull,
};
use zeroize::Zeroize;

pub(super) const STACK_BYTES: usize = 262_144;
pub(super) const PAGE_BYTES: usize = 4096;
pub(super) type Pointer = *mut c_void;
pub(super) fn pointer<T>(value: &mut T) -> Pointer {
    std::ptr::from_mut(value).cast()
}
pub(super) fn buffer(value: &mut [u8]) -> Pointer {
    value.as_mut_ptr().cast()
}

/// Records copied from a bounds-checked, potentially unaligned OCALL buffer.
///
/// # Safety
/// Every bit pattern must be valid for the implementing type. Its fields must
/// not contain references, restricted discriminants, or owned resources.
pub(super) unsafe trait Pod: Copy {}
unsafe impl Pod for u16 {}
unsafe impl Pod for u32 {}
unsafe impl Pod for i32 {}

macro_rules! record {
    ($name:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub(super) struct $name { $(pub $field: $ty),* }
        unsafe impl Pod for $name {}
    };
}
record!(Exit {
    ordinal: i64,
    parameters: Pointer
});
record!(Authorization {
    result: u32,
    measurement: Pointer,
    signer: Pointer,
    attributes: Pointer,
    token: Pointer
});
record!(Whitelist {
    result: u32,
    cert: Pointer,
    bytes: u32
});
record!(TlsInitialize {
    result: i32,
    log_level: i32
});
record!(ImageBuffers {
    result: i32,
    image_bytes: Pointer,
    nav_bytes: Pointer,
    sensor: Pointer,
    retry: u32,
    maximum: u32
});
record!(RingRelease {
    retry: u32,
    reserved: u32
});
record!(DhOutput {
    result: i32,
    buffer: Pointer,
    capacity: u32,
    bytes: Pointer
});
record!(DhExchange {
    result: i32,
    input: Pointer,
    input_bytes: u32,
    output: Pointer,
    capacity: u32,
    bytes: Pointer
});
record!(DhFinish {
    result: i32,
    input: Pointer,
    bytes: u32
});
record!(ImageCipher {
    result: i32,
    buffer: Pointer,
    bytes: u64
});
record!(NavSource {
    result: u8,
    buffer: Pointer,
    bytes: u16
});
record!(UpdateBase {
    result: i32,
    exists: Pointer,
    valid: Pointer,
    changed: Pointer
});
record!(FdtInitialize {
    sensor: Pointer,
    threshold: Pointer,
    tcode: Pointer
});
record!(PreprocessorInitialize {
    result: i32,
    image: Pointer,
    bytes: u32,
    sensor_id: Pointer,
    need_update_calibration: Pointer,
    base_valid: Pointer
});
record!(Preprocess {
    result: i32,
    image: Pointer,
    bytes: u32,
    sensor_type: Pointer,
    liveness: Pointer,
    size: Pointer,
    enrollment: Pointer
});
record!(Attach {
    result: i32,
    sensor: Pointer,
    quality: Pointer,
    coverage: Pointer,
    overlay: Pointer,
    preoverlay: Pointer,
    liveness: Pointer,
    retry: Pointer,
    version: Pointer,
    version_bytes: u32,
    settings: Pointer,
    settings_bytes: u32
});
// Engine2 has no application-result slot: five input byte pointers.
record!(OverlayConfig {
    values: [Pointer; 5]
});
record!(DataLength {
    input: Pointer,
    output: Pointer
});
record!(TemplateCreate {
    result: i32,
    samples: Pointer
});
record!(TemplateMerge {
    result: i32,
    samples: Pointer,
    used: Pointer,
    progress: Pointer,
    liveness: Pointer,
    hint: Pointer
});
record!(TemplateQuery {
    result: i32,
    required: Pointer,
    used: Pointer,
    progress: Pointer
});
record!(TemplateLength {
    result: i32,
    bytes: Pointer
});
record!(TemplateCompare {
    result: i32,
    blob: Pointer,
    bytes: u64,
    study: Pointer,
    update_bytes: Pointer,
    liveness: Pointer,
    new_image: u8,
    reserved: [u8; 7]
});
record!(TemplateUpdate {
    result: i32,
    buffer: Pointer,
    bytes: u32
});
record!(OcallCalibration {
    result: i32,
    buffer: Pointer,
    bytes: u64,
    kind: u8
});
record!(OcallFiletime {
    high: Pointer,
    low: Pointer
});
record!(OcallReadPmk {
    result: i32,
    buffer: Pointer,
    capacity: u16,
    length: Pointer
});
record!(OcallWritePmk {
    result: i32,
    buffer: Pointer,
    bytes: u16
});
record!(OcallTls {
    result: i32,
    context: Pointer,
    buffer: Pointer,
    bytes: u64
});

// _IOW(0xa4, n, sizeof(struct)): ADD_PAGE is packed, with a u16 mrmask.
#[repr(C, packed)]
pub(super) struct EnclaveCreate {
    pub src: u64,
}
#[repr(C, packed)]
pub(super) struct EnclaveAdd {
    pub addr: u64,
    pub src: u64,
    pub secinfo: u64,
    pub mrmask: u16,
}
#[repr(C, packed)]
pub(super) struct EnclaveInit {
    pub addr: u64,
    pub sigstruct: u64,
    pub einittoken: u64,
}
const fn iow(number: u32, bytes: usize) -> libc::c_ulong {
    ((1u32 << 30) | ((bytes as u32) << 16) | (0xa4 << 8) | number) as libc::c_ulong
}
pub(super) const CREATE: libc::c_ulong = iow(0, size_of::<EnclaveCreate>());
pub(super) const ADD: libc::c_ulong = iow(1, size_of::<EnclaveAdd>());
pub(super) const INIT: libc::c_ulong = iow(2, size_of::<EnclaveInit>());

pub(super) struct Stack {
    memory: NonNull<u8>,
}
impl Stack {
    pub fn new() -> Result<Self> {
        let layout = Layout::from_size_align(STACK_BYTES, PAGE_BYTES).unwrap();
        let memory = NonNull::new(unsafe { alloc_zeroed(layout) })
            .ok_or(Error::Enclave("transition stack allocation failed"))?;
        Ok(Self { memory })
    }
    pub fn top(&self) -> usize {
        self.memory.as_ptr() as usize + STACK_BYTES
    }
    pub fn validate(&self, address: Pointer, bytes: usize) -> Result<()> {
        let offset = (address as usize)
            .checked_sub(self.memory.as_ptr() as usize)
            .ok_or(Error::Enclave("OCALL pointer outside transition stack"))?;
        if offset > STACK_BYTES || bytes > STACK_BYTES - offset {
            return Err(Error::Enclave("OCALL byte span outside transition stack"));
        }
        Ok(())
    }
    pub fn read<T: Pod>(&self, address: Pointer) -> Result<T> {
        self.validate(address, size_of::<T>())?;
        Ok(unsafe { address.cast::<T>().read_unaligned() })
    }
    pub fn write<T: Pod>(&mut self, address: Pointer, value: T) -> Result<()> {
        self.validate(address, size_of::<T>())?;
        unsafe { address.cast::<T>().write_unaligned(value) };
        Ok(())
    }
    pub fn bytes(&self, address: Pointer, bytes: usize) -> Result<&[u8]> {
        self.validate(address, bytes)?;
        Ok(unsafe { std::slice::from_raw_parts(address.cast::<u8>(), bytes) })
    }
    pub fn bytes_mut(&mut self, address: Pointer, bytes: usize) -> Result<&mut [u8]> {
        self.validate(address, bytes)?;
        Ok(unsafe { std::slice::from_raw_parts_mut(address.cast::<u8>(), bytes) })
    }
    pub fn wipe(&mut self) {
        unsafe { std::slice::from_raw_parts_mut(self.memory.as_ptr(), STACK_BYTES) }.zeroize();
    }
    #[cfg(test)]
    pub fn start(&self) -> Pointer {
        self.memory.as_ptr().cast()
    }
}
impl Drop for Stack {
    fn drop(&mut self) {
        self.wipe();
        unsafe {
            dealloc(
                self.memory.as_ptr(),
                Layout::from_size_align(STACK_BYTES, PAGE_BYTES).unwrap(),
            )
        };
    }
}
