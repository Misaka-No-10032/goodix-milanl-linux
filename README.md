# Goodix MilanL fingerprint driver for Linux

A native Rust engine with libfprint/fprintd integration for the Goodix MilanL
fingerprint sensor exposed as ACPI `GXFP51B7` on the MACHR-WX9 notebook.

The privileged engine owns the sensor transport and the originally signed OEM
SGX enclaves. libfprint exchanges results and opaque sealed templates with it;
fprintd owns persistent template storage and the standard D-Bus API.

## Components

| Directory | Purpose |
|---|---|
| [`kernel/`](kernel/) | ACPI/EC transport kernel module |
| [`userspace/engine/`](userspace/engine/) | Native Rust `goodix-milanl-engine`, including its Cargo tests |
| [`userspace/libfprint/`](userspace/libfprint/) | Asynchronous libfprint driver, registration patch and protocol v2 |
| [`userspace/fprintd/`](userspace/fprintd/) | Matched-template persistence patch |
| [`packaging/arch/`](packaging/arch/) | x86_64 Arch-based package recipes, build helpers, DKMS and private fakeroot build |
| [`packaging/systemd/`](packaging/systemd/) | Engine service and fprintd dependency drop-in |
| [`tools/`](tools/) | Pinned official downloads, local OEM asset preparation and signed-enclave reconstruction |
| [`tests/`](tests/README.md) | Kernel, tool, libfprint, fprintd and packaging regression suites |
| [`docs/`](docs/) | Hardware, SGX and capture protocol specifications |

Start with the [userspace stack guide](userspace/README.md) and
[package build instructions](packaging/README.md). Building packages does
not install them, enable services or change PAM.

## Maintained specifications

- [Hardware and MCU protocol](docs/hardware-protocol.md): ACPI mailbox, framing,
  initialization, TLS and FDT.
- [OEM assets and SGX ABI](docs/oem-sgx.md): pinned inputs, original signatures,
  launch authorization and enclave interfaces.
- [Capture and template lifecycle](docs/capture.md): baseline ordering,
  preprocessing, quality gates, enrollment and adaptation.

## Platform requirements

This implementation targets MACHR-WX9/GXFP51B7 with legacy Intel SGX1 and the
pinned OEM **3.00.20** engine. ACPI/EC transport and enclave support are
platform-specific; other MilanL devices are outside this target. The package
recipes target x86_64 Arch-based distributions and require headers and build
tools for the target kernel.

Initialization, capture, preprocessing, enrollment, matching, calibration and
suspend/resume follow the original OEM host contracts. Regression commands are
listed in the [test guide](tests/README.md).

## Passkeys

For fingerprint-confirmed passkeys, use
[passkey-tpm](https://github.com/dangerousplay/passkey-tpm), a TPM-backed FIDO2/WebAuthn
authenticator for Linux.

Enroll a fingerprint through fprintd or your desktop settings, then follow
passkey-tpm's installation and setup instructions. It uses fprintd for fingerprint
verification and handles passkey credentials and signing separately from this
driver. PAM configuration is not required for passkey use.

## License

Project-authored code, scripts and documentation are licensed under
[GPL-2.0-only](LICENSE), unless otherwise specified. Third-party components and
patches retain their respective licenses; see the
[license notice](packaging/LICENSE-NOTICE).

## Data and authentication

OEM inputs are downloaded from pinned official sources and prepared locally;
proprietary inputs and generated assets remain private. Public project scripts
and recipes are distinct from vendor-containing packages and archives; the
[license boundary](packaging/LICENSE-NOTICE) applies separately to project source
and vendor content. Do not redistribute vendor binaries, biometric templates,
PMK/OTP data or pixels.

Fingerprint authentication is convenience-only and must retain password fallback.
PAM configuration is separate from package installation; the packages do not
change authentication rules.
