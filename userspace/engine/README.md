# Goodix MilanL engine

Native Rust backend for the GXFP51B7 ACPI fingerprint sensor on MACHR-WX9, using
originally signed WBDI and Milan 3.00.20 enclaves on legacy Intel SGX1. The engine
is a separate process from fprintd and speaks libfprint protocol v2. fprintd owns
the persistent sealed-template store.

ACPI transport wiring and legacy isgx support are platform-specific; the product
name does not claim compatibility with every MilanL installation.

## Structure

| Module | Responsibility |
|---|---|
| `check.rs` | Read-only deployment diagnostics, separate from service startup |
| `protocol.rs` | Bounded v2 decoding, suspend interruption and sealed-template responses |
| `server.rs` | Serial Unix requests, idle sensor/timer dispatch and connection teardown |
| `lifecycle.rs` | Shutdown signals, cancellation, module ownership and suspend epoch |
| `engine.rs` | OEM session, capture/temperature state, enrollment and gallery matching |
| `capture.rs` | Single-cycle no-finger updater with existing-base retention |
| `state.rs` | Private OEM baseline, opaque key-cache and calibration storage |
| `sensor/` | MCU framing, OEM initialization, FDT touch/release and TLS transport |
| `sgx/` | Signed page loading, enclave entry/exit, OCALL validation and typed OEM ABI |

Only the SGX and operating-system boundaries use unsafe code. Vendor log messages
are discarded. Sealed input, cached key material, calibration, transport data and
template buffers are erased on release. No secret values or images are logged.
The engine has no template database; its OEM state files are private and separate
from fprintd's persistent prints.

## Build and assets

Linux x86-64, Rust/Cargo, a system linker and glibc are required. `Cargo.lock` pins
dependency versions; all project runtime code is in this crate.

```sh
cargo build --release --locked --manifest-path userspace/engine/Cargo.toml
cargo test --locked --manifest-path userspace/engine/Cargo.toml
```

`CARGO_TARGET_DIR` and `CARGO_HOME` may select external directories. Building does
not install a toolchain, service, kernel module or PAM configuration. For x86_64
Arch-based distributions, the [package build](../../packaging/README.md) snapshots
the crate and cached locked dependencies for offline Rust compilation.

[`tools/prepare-oem.py`](../../tools/prepare-oem.py) downloads the pinned Huawei
OEM ZIP and Intel Windows PSW from official HTTPS sources into separate new
private directories. It checks SHA-256 before extraction, then verifies original
signatures and reconstructed SGX measurements locally. The resulting `assets/`
directory holds three enclave page packages, four measurement/signer files, the
signed whitelist and `gfspi.dll`; `licenses/` holds the vendor notices. The DLL
supplies a validated configuration table; it is not executed. These proprietary
outputs remain private. See [asset provenance and licensing](../../docs/oem-sgx.md#inputs-and-provenance).

## Service interface

```sh
goodix-milanl-engine --socket /private/runtime/engine.sock --assets /private/oem --state /private/state
```

Run as root. The socket parent must already be root-owned and mode 0700; the
socket is mode 0600. The service never replaces an existing path. `READY=1` is
sent after listening. HELLO and an empty IDENTIFY gallery do not initialize
hardware.

The first hardware operation loads missing `isgx` and `goodix_milanl_transport`
modules with `modprobe`. `--isgx-module` and `--transport-module` select explicit
`.ko` files for isolated validation. Only modules loaded by this process are
unloaded by it. The transport device is `/dev/goodix-milanl-raw`; the libfprint
socket selector is `GOODIX_MILANL_ENGINE`. See the [interface naming contract](../README.md#source-layout-and-names).

For installation diagnosis, run `goodix-milanl-engine --check`. It uses
`/usr/lib/goodix-milanl/oem` by default; `--assets` selects a prepared directory.
It checks platform/SGX support, kernel headers/modules, OEM file availability,
module trust, SELinux and fprintd service wiring without starting the service or
opening sensor devices. Exit 1 lists missing deployment requirements. Run as root
to inspect private assets. See [deployment support](../../packaging/README.md#deployment-checks)
for Secure Boot and SELinux setup.

## Session lifetime

- Enrollment accepts 12 frames. A rejected sample returns RETRY without advancing.
  VERIFY/IDENTIFY uses one fresh image across all gallery candidates; the matched
  template context must close successfully before publishing its result.
- Each contact IMAGE follows FDT-down IRQ `0x002`. Only WBDI classification 1
  reaches Engine7/8/9. Class 0 drives temperature update; 2/3/-1 re-arm DOWN.
  Every class-1 handoff performs post-capture manual FDT and arms UP, including
  quality rejection. Human waits have no deadline.
- FDT-up IRQ `0x200` checks an invalid WBDI base through fresh IMAGE/NAV and
  WBDI27; it does not rebuild on every sample. Setup/resume/temperature use one
  accepted updater cycle. An unstable candidate retains an imported base;
  without one the updater retries. Idle DOWN creates a five-second one-shot
  temperature timer, with two-second requeue only on the OEM error paths.
- EOF cancels the request. No new connection is served until the old session is
  closed. Cleanup ignores pending client EOF/termination signals while retaining
  device/SGX transaction deadlines. A cleanup failure stops the service.
- SUSPEND may be queued behind an in-flight request. Finite work completes;
  human waits return INTERRUPTED. The same socket retains OEM host used/progress
  counters, not enclave features. RESUME rebuilds without Engine10. Engine11
  implements the original early-count continuation and later-count E_FAIL.
  Both successful and aborted Linux suspend epochs invalidate old enclaves.
- Adaptation returns a sealed blob to libfprint. Patched fprintd must save the
  matched print before reporting success.

The default state directory is `/var/lib/goodix-milanl`, created mode 0700;
its files are mode 0600. `goodix.dat` holds the OEM identity/encoded FDT/sealed
bases/CRC, `Goodix_Cache.bin` the opaque WBDI key cache, and `goodix_calib.dat` /
`goodix_Arr.dat` the two calibration formats. These survive enclave teardown.
Engine27 saves pending calibration before S3 or normal detach.

The engine uses the OEM reset/configuration sequence and performs the read-only
DAC comparison once at the first class-1 capture, not at startup. IRQ RESET400
restores vendor ID register `0x0008` to `0x1111` as the OEM worker does; it is not
a DAC adjustment. There is no firmware/key provisioning or DAC tuning.
Detailed contracts are in [hardware protocol](../../docs/hardware-protocol.md),
[SGX ABI](../../docs/oem-sgx.md) and [capture lifecycle](../../docs/capture.md).

Fingerprint authentication is convenience-only and must retain password fallback.
Package installation and PAM configuration are described in the
[package guide](../../packaging/README.md#host-installation-and-rollback).
