# Regression suites

External regression suites are grouped by the component they exercise. Native
Rust unit and CLI tests remain in [`userspace/engine/`](../userspace/engine/).
Run the commands below from the trusted repository root with existing build/test
dependencies. Protocol and biometric fixtures are synthetic; the suites do not
access fingerprint hardware or saved biometric templates.

| Directory | Responsibility |
|---|---|
| [`kernel/`](kernel/) | Compile and exercise the actual transport IRQ handler with C mocks |
| [`tools/`](tools/) | PE layout, measurement and signature parser regressions; offline OEM download and hash-gate checks |
| [`libfprint/`](libfprint/) | Asynchronous driver behavior against a built libfprint and a scripted engine peer |
| [`fprintd/`](fprintd/) | Private-D-Bus matched-template persistence and failure/recovery checks |
| [`packaging/`](packaging/) | Unpacked native runtime, isolated signing/SELinux deployment checks and focused fakeroot IPC regressions |

## Kernel and offline tools

Discover these two suites separately; they are not a Python package tree:

```sh
python3 -B -m unittest discover -s tests/kernel -v
python3 -B -m unittest discover -s tests/tools -v
```

[`tools/test_prepare_oem.py`](tools/test_prepare_oem.py) exercises downloads with
synthetic inputs and no network access, including rejection of either input's
SHA-256 mismatch before any extraction. It does not establish official URL
availability or successful preparation of real vendor assets.

## Native engine

```sh
cargo test --offline --locked --manifest-path userspace/engine/Cargo.toml
```

## libfprint

Build libfprint with the Goodix MilanL driver first, then point the suite at its
build directory:

```sh
python3 -I -B tests/libfprint/test_goodix_milanl_driver_async.py \
  --build-dir /path/to/libfprint/_build -v
```

## fprintd persistence

Extract the userspace packages into a private `ROOT` (never `/`), preserving
archive modes as described in the [package guide](../packaging/README.md#package-checks):

```sh
LD_LIBRARY_PATH="$ROOT/usr/lib" GI_TYPELIB_PATH="$ROOT/usr/lib/girepository-1.0" \
  python3 -I -B tests/fprintd/test_adapted_print_storage.py \
  --fprintd "$ROOT/usr/lib/fprintd" --libfprint-libdir "$ROOT/usr/lib" -v
```

The suite runs a private D-Bus and synthetic prints. It does not activate system
services. See the [fprintd patch guide](../userspace/fprintd/README.md) for the
storage contract and alternative build-directory arguments.

## Packaging and build tooling

After extracting the engine and OEM packages into the same private staging root:

```sh
# Root is required by the native service, not for hardware access.
sudo python3 -I -B tests/packaging/test_packaged_runtime.py --root "$ROOT" -v

# Synthetic signing files; requires cc and current kernel headers/sign-file.
# Host-changing actions are mocked inside bwrap:
sudo python3 -I -B tests/packaging/test_secure_boot.py -v
python3 -I -B tests/packaging/test_selinux.py -v

# Use an existing private fakeroot build.
python3 -I -B tests/packaging/test_fakeroot_ipc.py \
  --fakeroot /private/new-fakeroot-build/prefix/bin/fakeroot -v
```

The runtime suite checks the actual ELF, CLI, service payload and Unix socket.
The fakeroot suite checks receive-error handling with temporary synthetic files;
see its [build-tool guide](../packaging/arch/fakeroot/README.md) for build and test
commands.
