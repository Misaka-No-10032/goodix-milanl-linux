# Goodix MilanL Linux fingerprint stack

The Rust engine manages the GXFP51B7 ACPI sensor and originally signed WBDI/Milan
3.00.20 enclaves through legacy Intel SGX1. libfprint integrates it with fprintd:

```text
sensor + isgx + OEM enclaves
          |
  goodix-milanl-engine
          | AF_UNIX protocol v2: results and opaque sealed templates
  libfprint goodix_milanl driver
          |
  fprintd: D-Bus API and persistent template store
          |
  desktop settings / pam_fprintd
```

## Source layout and names

| Path | Responsibility |
|---|---|
| [`engine/`](engine/) | Rust service, sensor state machine, SGX runtime and Cargo tests |
| [`libfprint/goodix_milanl.c`](libfprint/goodix_milanl.c) | Asynchronous libfprint driver |
| [`libfprint/goodix_milanl_proto.h`](libfprint/goodix_milanl_proto.h) | Wire protocol v2 |
| [`libfprint/0001-register-goodix_milanl-driver.patch`](libfprint/0001-register-goodix_milanl-driver.patch) | Upstream driver registration |
| [`fprintd/`](fprintd/) | Matched-template persistence patch |
| [`../tests/`](../tests/README.md) | External kernel, tool, driver, D-Bus and packaging regression suites |
| [`../packaging/`](../packaging/) | Package recipes under `arch/`, service integration under `systemd/` |
| [`../kernel/`](../kernel/) | ACPI/EC kernel transport |

The source/build key is `goodix_milanl`; the transport module is
`goodix_milanl_transport`, its device is `/dev/goodix-milanl-raw`, and
`GOODIX_MILANL_ENGINE` selects the engine socket. Installed OEM assets live in
`/usr/lib/goodix-milanl/oem`.

libfprint uses driver ID `goodix_milanl` and default device ID `0`. Serialized
FpPrint objects and fprintd storage paths use the same identity; the per-user
storage path is `goodix_milanl/0/`.

## Build and run

Build the native engine with Rust/Cargo and a Linux x86-64 linker:

```sh
cargo build --release --locked --manifest-path userspace/engine/Cargo.toml
cargo test --locked --manifest-path userspace/engine/Cargo.toml
```

`CARGO_TARGET_DIR` and `CARGO_HOME` can select external build/cache directories.
For x86_64 Arch-based distributions, the [package guide](../packaging/README.md)
builds the full upstream default libfprint driver set plus `goodix_milanl`, patched
fprintd, the engine, two DKMS packages and the private `goodix-milanl-oem` package.
Its two vendor inputs are downloaded from pinned official HTTPS sources and
hash-checked before local preparation. Build scripts do not install dependencies
or packages, copy files into the host `/usr`, start services or edit PAM.

The hardware target is MACHR-WX9/GXFP51B7 with legacy SGX1. The ACPI transport
and enclave integration are platform-specific.

To run the engine directly with explicit module paths:

```sh
sudo /path/to/goodix-milanl-engine \
  --socket /private/runtime/engine.sock --assets /private/oem --state /private/state \
  --isgx-module /path/to/isgx.ko \
  --transport-module /path/to/goodix_milanl_transport.ko
```

The socket parent must already be root-owned and mode 0700. The engine creates a
0600 socket and never replaces an existing path. Installed deployments use
name-based `modprobe`; the systemd unit creates `/run/goodix-milanl` and reports
readiness only after listening. fprintd's dependency starts the engine on demand.

## Operation contracts

- Enrollment requires 12 accepted frames. RETRY does not advance progress.
- VERIFY/IDENTIFY captures one fresh image. All gallery candidates share its
  features; only the matched template may be adapted.
- Each contact capture follows FDT-down. FDT-up checks an invalid WBDI base with
  fresh IMAGE/NAV; it does not unconditionally rebuild the baseline. Setup,
  resume and temperature events drive the original single-cycle updater.
  Human touch/release waits have no deadline.
- Only classification 1 reaches the algorithm. Class 0 updates the temperature
  base; classes 2/3/-1 re-arm DOWN internally. Quality and merge retries follow
  the original application status, without an extra diagnostic-score gate.
- EOF cancels an outstanding request. Cleanup completes before another connection
  is served. A cleanup failure stops the service; only owned modules are unloaded.
- SUSPEND/RESUME keeps the same socket and the OEM host enrollment counters,
  while rebuilding enclaves without preserving old features or calling Engine10.
  Completed stages/results are retained; waiting requests receive INTERRUPTED.
- The engine keeps no template database. libfprint updates the matched FpPrint,
  and patched fprintd saves it before publishing authentication success.
- `/var/lib/goodix-milanl` (0700; `--state` overrides it) holds the OEM sealed
  baseline, opaque key cache and calibration files (0600), separately from prints.
- libfprint uses asynchronous GIO/FpiSsm operations and defers completion past the
  vfunc return, allowing fprintd to send its D-Bus Start reply first.

See the [engine guide](engine/README.md),
[capture contract](../docs/capture.md) and [SGX ABI](../docs/oem-sgx.md).

## Hardware-free regression checks

Run from the trusted repository root. Protocol peers and synthetic fixtures are
test inputs; these suites do not access the sensor or saved biometric templates.

```sh
python3 -B -m unittest discover -s tests/kernel -v
python3 -B -m unittest discover -s tests/tools -v
cargo test --offline --locked --manifest-path userspace/engine/Cargo.toml

python3 -I -B tests/libfprint/test_goodix_milanl_driver_async.py \
  --build-dir /path/to/libfprint/_build -v

# ROOT is a private unpacked package tree, never /.
sudo python3 -I -B tests/packaging/test_packaged_runtime.py --root "$ROOT" -v

LD_LIBRARY_PATH="$ROOT/usr/lib" GI_TYPELIB_PATH="$ROOT/usr/lib/girepository-1.0" \
  python3 -I -B tests/fprintd/test_adapted_print_storage.py \
  --fprintd "$ROOT/usr/lib/fprintd" --libfprint-libdir "$ROOT/usr/lib" -v
```

The packaged-runtime test retains the service's root-only requirement. The D-Bus
suite uses an isolated bus and synthetic templates, not system service activation.
The [suite guide](../tests/README.md) lists component responsibilities and fakeroot
IPC checks.

Fingerprint authentication is convenience-only with password fallback. Use PAM
for lock screen, sudo and polkit, while retaining password-only login; package
installation does not change PAM rules.
