# Arch-based distribution packaging

These recipes target x86_64 Arch-based distributions and the
MACHR-WX9/GXFP51B7 platform with legacy Intel SGX1.

Builds are separate from host installation. These scripts do **not** install
packages or dependencies, copy files into the host `/usr`, enable/start services,
edit PAM, access the sensor or change BIOS settings. They require existing tools,
local Git/Cargo caches and HTTPS access for the two pinned vendor downloads.
Each output directory must be new; an existing directory is never removed.

Package recipes, DKMS inputs and the four `build-*.sh` helpers live in
[`arch/`](arch/). Service definitions live in [`systemd/`](systemd/):
`goodix-milanl-engine.service` and
`fprintd.service.d/50-goodix-milanl.conf`. Official downloads and local OEM
preparation are handled by [`tools/prepare-oem.py`](../tools/prepare-oem.py);
regression suites live under [`tests/`](../tests/README.md).

## Package set

| Package | Contents |
|---|---|
| `libfprint-goodix-milanl` 1.94.100 | Full upstream default driver set plus `goodix_milanl`; library, headers, pkg-config, GIR and typelib. Provides/conflicts with `libfprint`. |
| `fprintd-goodix-milanl` 1.94.5 | D-Bus service, clients, policy, systemd unit and PAM module, plus matched-template persistence. Provides/conflicts with `fprintd`; depends on the patched libfprint. |
| `goodix-milanl-engine` 0.2.0 | Native Rust executable with deployment checks, systemd unit, fprintd drop-in, Secure Boot helper, optional SELinux policy and licenses. |
| `isgx-legacy-dkms` 2.11.0 | Legacy isgx sources, Linux kernel compatibility patch, DKMS configuration and modalias blacklist. |
| `goodix-milanl-transport-dkms` 0.1.0 | ACPI/EC transport sources, DKMS configuration and modalias blacklist. |
| `goodix-milanl-oem` 1.1.151.18 | Reconstructed, originally signed Milan 3.00.20/Intel enclave assets and original `gfspi.dll`. **Private local package, not for upload.** |

No package contains templates or an `/etc/pam.d` change.
Installing `pam_fprintd.so` does not enable
fingerprint authentication in any PAM service. In the separate `pacman -U`
installation step, the engine executable goes to `/usr/bin/goodix-milanl-engine`
and the locally built private `goodix-milanl-oem` package installs its assets to
`/usr/lib/goodix-milanl/oem`. Preparation/build scripts do not copy them there.
The saved-template identity is documented in the [stack guide](../userspace/README.md#source-layout-and-names).

## Pinned inputs and build

Run from the trusted repository, not an extracted archive. Required tools include
`makepkg`/`fakeroot`, Git, a C compiler, Rust/Cargo, Meson/Ninja and the dependencies
listed in the PKGBUILDs. Asset preparation also requires Python and `7zz`.
DKMS builds require headers and the compiler for the **target kernel**,
including Clang/LLVM when required by that kernel's configuration.

Local Git caches must contain these commits:

- libfprint: `6f9479c3d55f847c1b3769f28ceb99227f9858cf`
- fprintd: `b54a007ccf58ac0ae074c7151b223f35cbd17306`
- Intel linux-sgx-driver: `eea00a3f79bd1266adc7f4072c52a7a717b9e37e`

Builds start from these commits and apply repository patches, not edits in the
cached working trees. Project runtime files are an explicit snapshot of this
working tree; generated checksums identify that local build, not an upstream
release.

`Cargo.lock` pins Rust dependencies. They must already be cached in `CARGO_HOME`;
if needed, prepare the cache separately with
`cargo fetch --locked --manifest-path userspace/engine/Cargo.toml`.
`build-runtime.sh` uses `cargo vendor --offline --locked`, snapshots the crate and
dependencies, then builds/tests with `cargo --frozen` and an initially empty
build-local `CARGO_HOME`. Missing dependencies cause an error, not a download.
`PATH` and `CARGO_HOME` may select an existing isolated toolchain/cache.

```sh
WORK=/path/to/private/new-build
mkdir -m 700 "$WORK"

# For affected fakeroot 2.1.4: use a corrected private build, not a host replacement.
MESON=/path/to/venv/bin/meson bash packaging/arch/build-fakeroot.sh \
  "$WORK/fakeroot" /path/to/fakeroot_2.1.4.orig.tar.xz
export PATH="$WORK/fakeroot/prefix/bin:$PATH"

# MESON selects an existing isolated executable without putting its venv on PATH.
MESON=/path/to/venv/bin/meson bash packaging/arch/build-userspace.sh \
  "$WORK/userspace" /path/to/libfprint-git /path/to/fprintd-git

bash packaging/arch/build-kernel.sh \
  "$WORK/kernel" /path/to/linux-sgx-driver-git

bash packaging/arch/build-runtime.sh \
  "$WORK/runtime" /path/to/linux-sgx-driver-git
```

Packages land under each output's `packages/`; logs and staged sources remain
beside them. `--nodeps` avoids host dependency installation, including installing
the patched libfprint just to build fprintd. Tools/headers must already exist;
fprintd builds against the new libfprint's uninstalled pkg-config file.

The runtime helper takes only `NEW_OUTPUT_DIR ISGX_GIT` and invokes
`prepare-oem.py` itself. Its vendor downloads are limited to the pinned Huawei
OEM ZIP and Intel Windows PSW; Git and Cargo inputs still use the local caches
above. To prepare assets without building packages, run the tool separately with
only a new output directory:

```sh
python3 -I -B tools/prepare-oem.py "$WORK/oem"
```

The official HTTPS sources are fixed by `OEM_URL` and `INTEL_URL` in
[`prepare-oem.py`](../tools/prepare-oem.py). Each input is downloaded into its own
new private directory, `download-oem/` or `download-intel/`. Both complete archive
SHA-256 hashes must match before any extraction. Each nested ZIP/NSIS layer is
then extracted into its own new directory; no EXE or installer script is run.
Six selected vendor files are hash-checked; `tools/pe_enclave.py` verifies original
RSA signatures and reconstructed SGX measurements. Preparation produces local
`assets/` and `licenses/` directories, using the top-level WBDI, Engine
**3.00.20** and Intel Windows PSW **2.13.100.2**. See
[provenance, hashes and asset layout](../docs/oem-sgx.md#inputs-and-provenance).

Public project scripts and recipes are separate from proprietary downloaded
inputs and generated outputs. Keep the latter, including `goodix-milanl-oem`
and vendor-containing source bundles, private. The Intel agreement and Goodix
copyright notice accompany the OEM package. Project-authored sources use
[GPL-2.0-only](../LICENSE) unless otherwise specified. The engine package includes
the project license and Rust dependency licenses; third-party components and
patches retain their respective licenses.
[LICENSE-NOTICE](LICENSE-NOTICE) records these boundaries. Downloading or locally
packaging vendor content does not grant redistribution rights.

## Service and module lifetime

The fprintd drop-in uses `Requires=` and `After=` for
`goodix-milanl-engine.service`. `Type=notify` readiness is sent **after** the
root-only socket listens. `GOODIX_MILANL_ENGINE` points to
`/run/goodix-milanl/engine.sock`. The engine starts on fprintd demand and stops
when no longer needed; it does not need boot-time `systemctl enable`.

HELLO and empty galleries do not initialize hardware. The first hardware
operation uses `modprobe isgx` and
`modprobe goodix_milanl_transport enable_sealed_input=1 enable_raw_tx=1`.
Explicit `.ko` arguments are available for isolated validation. The engine
unloads only modules it loaded.

Both modules have ACPI aliases. Package-owned `/usr/lib/modprobe.d` blacklists
prevent udev from preloading them, while preserving explicit name-based loading.
No global raw-mode enable option is installed. `/dev/goodix-milanl-raw` is mode
0600 and requires `CAP_SYS_RAWIO`; generic isgx retains upstream permissions.

The engine has a private 0700 runtime directory, 0077 umask and disabled core
dumps. Its SGX/PE mappings require executable memory, so it must **not** inherit
fprintd's `MemoryDenyWriteExecute=true`. OEM files are root-owned 0600 inside a
0700 directory. `StateDirectory=goodix-milanl` creates `/var/lib/goodix-milanl`
mode 0700 for the OEM sealed baseline, opaque key cache and calibration files
(mode 0600); these survive service restarts. fprintd remains the only persistent
template store. The state directory is not an alternate print database.

## Package checks

Extract the engine and OEM packages into a private `ROOT` (never `/`), preserving
archive modes with `bsdtar -xpf /path/to/package.pkg.tar.zst -C "$ROOT"` for each
package. Then run:

```sh
# Root is required by the service; these requests do not open hardware.
sudo python3 -I -B tests/packaging/test_packaged_runtime.py --root "$ROOT" -v

# Also extract userspace packages; this uses a private D-Bus, not system activation.
LD_LIBRARY_PATH="$ROOT/usr/lib" GI_TYPELIB_PATH="$ROOT/usr/lib/girepository-1.0" \
  python3 -I -B tests/fprintd/test_adapted_print_storage.py \
  --fprintd "$ROOT/usr/lib/fprintd" --libfprint-libdir "$ROOT/usr/lib" -v
```

The packaged-runtime suite checks ELF/CLI/service contents, READY, HELLO,
empty-gallery and malformed requests, CANCEL/SUSPEND, reconnect and clean SIGTERM
shutdown without accessing hardware. The [fakeroot guide](arch/fakeroot/README.md)
covers the optional private build tool.

## Deployment checks

```sh
sudo goodix-milanl-engine --check
# Before installation, use the built executable and a private prepared asset directory:
sudo /path/to/goodix-milanl-engine --check --assets /private/oem/assets
```

The native check reports CPU SGX1/EPC availability, DMI/ACPI identity, running-kernel
headers and module versions, readable OEM assets, module-signing requirements,
SELinux policy/labels and the effective fprintd service dependency/socket setting.
It exits 0 when all checks pass and 1 with the missing items otherwise. Missing
installed modules or service configuration are reported directly during a
pre-installation run. It does not open the sensor, initialize an enclave, load
modules, connect to the engine socket or start a service. Root allows inspection
of the private OEM directory and signing certificate.

## Secure Boot module signing

The packages use DKMS's existing signing mechanism and administrator-configured
`mok_signing_key` / `mok_certificate` from `/etc/dkms/framework.conf` and its
`framework.conf.d` overrides. The default pair is `/var/lib/dkms/mok.key` and
`mok.pub`. No package hook changes boot keys or creates a separate project key.
Install the optional `mokutil` and `openssl` tools before using the helper.

For an existing **shim/MOK boot chain**, the explicitly invoked setup is:

```sh
sudo goodix-milanl-secure-boot prepare
sudo goodix-milanl-secure-boot enroll
```

`prepare` asks DKMS to create or reuse its signing pair and preserves an incomplete
existing pair rather than replacing it. `enroll` queues the certificate import;
the operator confirms it in MOK Manager on reboot. It reuses an enrolled certificate
and stops if the running boot chain has no shim MOK list. The helper does not
install shim, change firmware Secure Boot settings or manage a different boot
chain's keys; use that boot chain's existing module-trust setup.

After enrollment, rebuild both installed project modules so cached unsigned builds
are replaced, then check enrollment and each module's signing-certificate serial:

```sh
kernel=$(uname -r)
sudo dkms build --force -m isgx -v 2.11.0 -k "$kernel"
sudo dkms install --force -m isgx -v 2.11.0 -k "$kernel"
sudo dkms build --force -m goodix_milanl_transport -v 0.1.0 -k "$kernel"
sudo dkms install --force -m goodix_milanl_transport -v 0.1.0 -k "$kernel"
sudo goodix-milanl-secure-boot check
```

Later kernel updates use the same DKMS configuration through `AUTOINSTALL=yes`.
`check` is read-only; only `enroll` requests a MOK import. Keep the private key
under root control. Uninstalling this project leaves the shared DKMS key and its
trust enrollment intact.

## SELinux deployment

The engine package includes `goodix_milanl.te`, `goodix_milanl.fc` and an explicit
installer in `/usr/share/goodix-milanl/selinux`. On SELinux-enabled Arch systems,
use `selinux-refpolicy-arch`, `checkpolicy`, `semodule-utils`, `make`, `m4` and `gawk`
to build it:

```sh
# Compile, install policy and apply labels only when explicitly requested:
sudo bash /usr/share/goodix-milanl/selinux/install.sh --install
```

The installer requires the active policy's `nnp_nosuid_transition` capability,
retaining the service's `NoNewPrivileges=yes` setting.

The policy gives the separate engine domain access to the raw transport, legacy
isgx mappings, read-only OEM assets, private persistent state and owned module
operations. The state directory uses `goodix_milanl_state_t`. fprintd receives socket
access without raw-I/O or SGX execution permissions. The script does not enable
SELinux, relax enforcement, start services or alter PAM. Stop fingerprint services
before applying labels; then the next service start uses the new engine domain.
`goodix-milanl-engine --check` checks policy presence and persistent file labels.

## Host installation and rollback

This is a separate installation step; the build scripts do not run it.

1. Keep a working password-authenticated session open. Confirm target-kernel
   headers/compiler and retain the distro libfprint/fprintd package files for
   rollback. For module-signature enforcement, use the explicit signing workflow
   above; on SELinux systems, install the optional policy before starting services.
   Package installation does not change Secure Boot, SELinux enforcement or BIOS settings.
2. Stop fingerprint operations and fprintd. Install the **six exact generated
   package files together** with `pacman -U`, retaining its conflict/dependency
   checks. Do not install only half of the libfprint/fprintd pair. Package-manager
   and DKMS hooks now modify the host: check build results and `dkms status`.
3. Reload systemd units if the package-manager hook has not done so. Start fprintd
   or trigger D-Bus activation; its dependency starts the engine. Do not enable
   the engine at boot or globally set raw module parameters.
4. Validate the installed service, system D-Bus/polkit authorization, template
   save/reload and cancellation before any PAM change. Do not import synthetic
   test prints into a real user's store.
5. PAM is a separate change for lock screen, sudo and polkit, with mandatory
   password fallback. Login remains password-only.

Rollback: stop fprintd and `goodix-milanl-engine`. If the optional SELinux module
was installed, remove it with `semodule -r goodix_milanl` and restore the standard
labels on the engine, OEM and persistent-state directories, and any remaining
runtime/device nodes before removing their packages. Keep the shared DKMS signing key and enrollment. Remove
the engine package and
restore both retained distro userspace packages in one pacman transaction. Remove
`goodix-milanl-transport-dkms`, `isgx-legacy-dkms` and the local OEM package if no
longer needed; reload units as required. Do **not** delete saved prints, modify
PAM, force-remove dependencies or unload another process's modules. PAM needs its
own separately reviewed rollback if enabled later.
