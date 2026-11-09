// SPDX-License-Identifier: GPL-2.0-only
// Bounded OEM OCALL dispatch; vendor log payloads are discarded.
use super::{Component, Runtime, WANT_READ, abi};
use crate::{
    TlsIo,
    error::{Error, Result},
    state::State,
};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

fn tls_result(transfer: Result<usize>, capacity: usize, receive: bool) -> Result<i32> {
    match transfer {
        Ok(count) if count > capacity => Err(Error::Enclave("TLS transport exceeded OCALL buffer")),
        // Linux polls the mailbox synchronously. The OEM callback instead reads
        // an asynchronously filled FIFO (empty=0); use mbedTLS retry here.
        Ok(0) if receive => Ok(WANT_READ),
        Ok(count) => Ok(count as i32),
        // Transport failures return through the OEM callback ABI, allowing
        // WBDI40/39 recovery. Cancellation still aborts the transition.
        Err(Error::Io(_) | Error::Device(_)) => Ok(-1),
        Err(error) => Err(error),
    }
}

fn read_calibration(state: &State, name: &str, array: bool, output: &mut [u8]) {
    let mut read = 0;
    if let Ok(cache) = state.read(name, output.len()) {
        read = cache.len();
        output[..read].copy_from_slice(&cache);
    }
    // Adapter 0x180010c40 pads only kind 1; kind 0 keeps the caller's tail.
    if array {
        output[read..].zeroize();
    }
}

impl Runtime {
    pub(super) fn handle_ocall(
        &mut self,
        component: Component,
        ordinal: i64,
        parameters: abi::Pointer,
        io: &mut Option<&mut dyn TlsIo>,
    ) -> Result<()> {
        let engine = component == Component::Engine;
        // Vendor log strings may contain secrets. Do not read, format, or emit them.
        if ordinal == if engine { 5 } else { 14 } {
            return Ok(());
        }
        let stack = &mut self.transition.as_mut().unwrap().stack;
        if engine {
            match ordinal {
                0 | 1 => {
                    let request = stack.read::<abi::OcallCalibration>(parameters)?;
                    if request.kind > 1 {
                        return Err(Error::Enclave("invalid calibration kind"));
                    }
                    let expected = if request.kind == 1 { 0xa014 } else { 0x184bc };
                    let bytes = usize::try_from(request.bytes)
                        .map_err(|_| Error::Enclave("invalid calibration length"))?;
                    let array_write = request.kind == 1 && ordinal == 1;
                    if (array_write && !(20..=expected).contains(&bytes))
                        || (!array_write && bytes != expected)
                    {
                        return Err(Error::Enclave("incorrect OEM 3.00 calibration length"));
                    }
                    let data = stack.bytes(request.buffer, bytes)?;
                    if array_write
                        && u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize
                            != bytes - 20
                    {
                        return Err(Error::Enclave("invalid calibration array length"));
                    }
                    let name = if request.kind == 1 {
                        "goodix_Arr.dat"
                    } else {
                        "goodix_calib.dat"
                    };
                    if ordinal == 0 {
                        let output = stack.bytes_mut(request.buffer, bytes)?;
                        read_calibration(&self.state, name, request.kind == 1, output);
                    } else {
                        let _ = self.state.write(name, data);
                    }
                    // OEM callbacks always return 0 for file I/O; trusted code
                    // validates the identifier/content. ABI errors still fail above.
                    stack.write(parameters, 0i32)
                }
                4 => {
                    let request = stack.read::<abi::OcallFiletime>(parameters)?;
                    if !request.high.is_null() {
                        stack.validate(request.high, 4)?;
                    }
                    if !request.low.is_null() {
                        stack.validate(request.low, 4)?;
                    }
                    if !request.high.is_null() && !request.low.is_null() {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map_err(|_| Error::Enclave("invalid engine FILETIME"))?;
                        let ticks = now
                            .as_secs()
                            .checked_add(11_644_473_600)
                            .and_then(|seconds| seconds.checked_mul(10_000_000))
                            .and_then(|ticks| ticks.checked_add((now.subsec_nanos() / 100) as u64))
                            .ok_or(Error::Enclave("engine FILETIME overflow"))?;
                        stack.write(request.high, (ticks >> 32) as u32)?;
                        stack.write(request.low, ticks as u32)?;
                    }
                    Ok(())
                }
                _ => Err(Error::Enclave("unsupported engine OCALL")),
            }
        } else {
            match ordinal {
                6 | 7 => {
                    let request = stack.read::<abi::OcallReadPmk>(parameters)?;
                    stack.validate(request.buffer, request.capacity as usize)?;
                    stack.validate(request.length, 2)?;
                    let cache = if ordinal == 7 {
                        self.state
                            .read_optional("Goodix_Cache.bin", request.capacity as usize)
                            .ok()
                            .flatten()
                    } else {
                        None
                    };
                    let source = if ordinal == 6 {
                        Some(self.sealed_input.as_slice())
                    } else {
                        cache.as_deref().map(Vec::as_slice)
                    };
                    let result = if let Some(source) =
                        source.filter(|bytes| bytes.len() <= request.capacity as usize)
                    {
                        stack
                            .bytes_mut(request.buffer, source.len())?
                            .copy_from_slice(source);
                        stack.write(request.length, source.len() as u16)?;
                        0i32
                    } else {
                        stack.write(request.length, 0u16)?;
                        -1i32
                    };
                    stack.write(parameters, result)
                }
                8 => {
                    let request = stack.read::<abi::OcallWritePmk>(parameters)?;
                    let bytes = stack.bytes(request.buffer, request.bytes as usize)?;
                    let result = if self.state.write("Goodix_Cache.bin", bytes).is_ok() {
                        0i32
                    } else {
                        -1i32
                    };
                    stack.write(parameters, result)
                }
                0 | 1 => {
                    let request = stack.read::<abi::OcallTls>(parameters)?;
                    if request.bytes > 32768 {
                        return Err(Error::Enclave("TLS OCALL exceeds byte bound"));
                    }
                    let bytes = request.bytes as usize;
                    stack.validate(request.buffer, bytes)?;
                    let io = io
                        .as_mut()
                        .ok_or(Error::Enclave("TLS transport unavailable for this ECALL"))?;
                    let transfer = if ordinal == 0 {
                        io.receive(stack.bytes_mut(request.buffer, bytes)?)
                    } else {
                        io.send(stack.bytes(request.buffer, bytes)?)
                    };
                    let result = tls_result(transfer, bytes, ordinal == 0)?;
                    stack.write(parameters, result)
                }
                4 => {
                    if !parameters.is_null() {
                        return Err(Error::Enclave("invalid image event OCALL"));
                    }
                    Ok(())
                }
                9 => {
                    self.tls_state = stack.read::<i32>(parameters)?;
                    Ok(())
                }
                10 | 11 => {
                    if !parameters.is_null() {
                        return Err(Error::Enclave("invalid TLS state OCALL"));
                    }
                    self.tls_state = if ordinal == 11 { 16 } else { -1 };
                    Ok(())
                }
                _ => Err(Error::Enclave("unsupported WBDI/launch OCALL")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibration_read_pads_only_the_array_tail_and_retains_files() {
        let directory = std::env::temp_dir().join(format!(
            "milanl-calibration-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = State::open(&directory).unwrap();
        for (name, array) in [("goodix_calib.dat", false), ("goodix_Arr.dat", true)] {
            let mut output = [0x55; 4];
            read_calibration(&state, name, array, &mut output);
            assert_eq!(output, if array { [0; 4] } else { [0x55; 4] });
            state.write(name, &[1, 2]).unwrap();
            let reopened = State::open(&directory).unwrap();
            read_calibration(&reopened, name, array, &mut output);
            assert_eq!(
                output,
                if array {
                    [1, 2, 0, 0]
                } else {
                    [1, 2, 0x55, 0x55]
                }
            );
            assert_eq!(&*reopened.read(name, 4).unwrap(), &[1, 2]);
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn tls_transport_errors_return_to_enclave_but_cancellation_aborts() {
        assert_eq!(tls_result(Ok(0), 32, true).unwrap(), WANT_READ);
        assert_eq!(tls_result(Ok(7), 32, false).unwrap(), 7);
        for receive in [false, true] {
            assert_eq!(
                tls_result(Err(Error::Device("test I/O failure")), 32, receive).unwrap(),
                -1
            );
        }
        assert!(tls_result(Ok(33), 32, true).is_err());
        assert!(matches!(
            tls_result(Err(Error::Cancelled), 32, true),
            Err(Error::Cancelled)
        ));
    }
}
