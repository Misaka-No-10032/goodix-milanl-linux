# OEM assets and SGX ABI

The runtime executes originally signed Intel Launch Enclave (LE), Goodix WBDI
and Milan **3.00.20** enclaves through legacy isgx on Linux x86-64. `gfspi.dll`
is only a hash-checked configuration data source. Windows, UMDF and Wine are not
runtime dependencies. All `0x180…` code/data addresses below are preferred image
VAs with image base `0x180000000`; subtract that base to obtain an RVA.

See also [hardware protocol](hardware-protocol.md) and
[capture/template lifecycle](capture.md).

## Inputs and provenance

The preparation tool downloads `MateBook_X_Pro_FingerPrint_1.1.151.18.zip` from
Huawei's official HTTPS source and Intel Windows PSW **2.13.100.2** from Intel's
official HTTPS source. The fixed URLs are `OEM_URL` and `INTEL_URL` in
[`tools/prepare-oem.py`](../tools/prepare-oem.py); the archive hashes are pinned
below rather than accepting whatever a vendor currently serves.

The OEM extraction chain is outer ZIP → inner ZIP of the same name →
`FingerPrint_1.1.151.18.exe` (NSIS) → nested EXE of the same name → `source/`.
`source/gfspi.inf` records `DriverVer=07/30/2024,1.1.151.18`, ACPI `GXFP51B7`,
UMDF 2.15 and direct hardware access. Use the **top-level** WBDI and whitelist,
not the different WBDI under `SGXDriver/`. Intel LE and its production SIGSTRUCT
come from `Intel SGX PSW for Windows v2.13.100.2/PSW_INF_RS3_and_above/`.

Run from the trusted repository root with Python and `7zz` already installed:

```sh
python3 -I -B tools/prepare-oem.py /path/to/private/new-oem-output
```

The only argument is a new output directory. Each download is stored in its own
new private subdirectory, `download-oem/` or `download-intel/`. Both complete
archive SHA-256 hashes must match before **any extraction**. Each nested ZIP/NSIS
layer is then extracted into its own new directory; the six selected runtime
input files are hash-checked before original-signature and SGX-measurement
verification. The tool produces `assets/` and `licenses/` locally. It never runs
an EXE or installer script, installs files into the host `/usr`, activates a
service or changes PAM.

Pinned SHA-256 values:

| Input | SHA-256 |
|---|---|
| OEM ZIP | `eae4baecf92ed4a33e1ae2720cc458cb6d005297c2b1b97d6d0541650e429123` |
| Intel PSW EXE | `2f8d0344d5853bc1a5ea3167e779c8718eeb67b3e855be2e2bb3b1c67b8ad084` |
| `gfspi.dll` | `d98e873e02b00d03d90ccdd78ac69624676a6b9c3662ce66dfca220551b675cd` |
| `WBDI_Enclave.signed.dll` | `8811f32411a236b28c61a0f0d9c134c42357e0dcddd71c2c324873e9219618b4` |
| `Engine_Enclave_3.00.20.signed.dll` | `fa0602a1c8c037e014c07093e455128f1596f2efa8580d8ba34bedc1bac742d1` |
| `sgx_white_list_cert.bin` | `fd2723344d1acf470fc231a93920bf6c2b9efe18474b3ab9247ec2960e8b9223` |
| `le.signed.dll` | `8122bb622d75cc39a689a305bdf9f5c9055eec64ceb4af01d13115caef34e705` |
| `le_prod_css.bin` | `02366e59874e0698a1b8827a1152bce389a1ff3ff3bed0b52e694fff5404f0c6` |
| `EngineAdapter.dll` — static ABI reference, not installed | `01be203e1553041aaac7f10961ee98f58bee02a267909a17c3597123c5e1d1fe` |

`EngineAdapter.dll!initialize_enclave` (`0x180012370`) selects **3.00.20** for
sensor type 3, with version string `Milan_v_3.00.20`. This is the only supported
algorithm-enclave version.

### Private asset layout and licensing

Local preparation outputs `assets/` and `licenses/`. The
[Arch-based package build](../packaging/README.md) puts them in the private
`goodix-milanl-oem` package; a separately authorized `pacman -U` installation
places these nine runtime files in `/usr/lib/goodix-milanl/oem`:

- `windows-le.pages`, `goodix.pages`, `engine.pages`;
- `goodix-mrenclave.bin`, `goodix-mrsigner.bin`, `engine-mrenclave.bin`,
  `engine-mrsigner.bin`;
- `goodix-whitelist.bin`, `gfspi.dll`.

The directory is root-owned 0700 and files are 0600. Downloading and reconstructing
vendor content does not make it freely redistributable. Keep downloaded inputs,
the OEM package, extracted binaries and vendor-containing source bundles private.
The original Intel agreement and Goodix copyright notice accompany the local
package. Signed filenames, exported functions and ABI ordinals retain their OEM
names.

Public distribution of project scripts and recipes is separate from redistribution
of their proprietary outputs; the scripts grant no rights to vendor content.
Project SPDX declarations and dependency licenses remain in force. Some project
sources do not yet have a blanket license; `LicenseRef-Unspecified` is not a
license grant. Resolve that gap before redistribution. Full terms and attribution
boundaries are in [LICENSE-NOTICE](../packaging/LICENSE-NOTICE).
No templates, PMK, OTP, pixels or host secrets belong in any package.

## Original measurement reconstruction

[`tools/pe_enclave.py`](../tools/pe_enclave.py) accepts the verified Windows SGX
metadata v1.2 (`0x100000002`, size `0x754`, SIGSTRUCT at metadata+`0x44`). It
reconstructs headers/sections, relocation-page write permissions, TLS/thread data,
TCS/SSA, heap, stack and guard layout. Measurement follows ECREATE/EADD/EEXTEND,
including the unextended heap. It verifies RSA-3072/SHA-256 signatures and requires
the reconstructed MRENCLAVE to match both the embedded and any supplied original
SIGSTRUCT. No enclave code is patched or re-signed. The supported size limit is
256 MiB; this is a layout limit, not a claim of available EPC capacity.

| Original image | Pages | MRENCLAVE |
|---|---:|---|
| Intel Windows `le.signed.dll` | 142 | `c511d78c419eca8dbca308cbca38a63bf512e6290d2f15f4d9fa42c158c44dc4` |
| `WBDI_Enclave.signed.dll` | 3433 | `5aad3180e84e86ad4a0d5c017b13d43d065a15e8d25e6520104bb7c5d5fc4343` |
| `Engine_Enclave_3.00.20.signed.dll` | 3896 | `d2936ab0674a20a56d0fa4f4a140bbb4d522af6ede169cf4a8041cc42eca1d6f` |

The native [`sgx/`](../userspace/engine/src/sgx/) runtime loads these signed
pages through isgx, initializes the Windows enclave runtime and dispatches bounded
ECALL/OCALL records. CPU capability initialization must include supported SSE4.2,
which the Intel LE's ECC implementation requires.

## Launch authorization

The OEM certificate is 632 bytes, LE product ID 0, version 14, with 13 signers
including Goodix. The matching Windows LE accepts it and issues a valid launch
token for the original WBDI/Engine signer. Both enclave families retain the same
original Goodix MRSIGNER and release signatures.

The signed certificate binds the LE product ID and signer set. Use the matching
Windows LE, OEM whitelist and original release signatures together.

WBDI39 obtains keys internally: OCALL7 reads opaque `Goodix_Cache.bin`, OCALL6
supplies sealed firmware input on a cache miss, and OCALL8 persists the re-sealed
cache. Nonzero WBDI39 application status invalidates the cache; 0 and 1 proceed.
Cache files are private mode 0600, never logged. TLS uses the
[MCU authentication sequence](hardware-protocol.md#authenticated-mcu-tls).

## ECALL and OCALL boundaries

Records use x86-64 natural alignment. [`abi.rs`](../userspace/engine/src/sgx/abi.rs)
is the maintained typed layout. SGX transition status and application status are
independent: SGX=0 alone does not mean success. In particular, WBDI18 returns
**bool=1**, Engine1/7/8 begin with a real `i32 result`, and some calls have no
application return field. The transition stack is 256 KiB. OCALL request and
buffer spans must remain inside it; pointer values are snapshotted before writes
that could alias a request.

### WBDI/Engine local authentication

Use the original split DH interfaces, with no nested enclave reentry or shared
active transition stack:

| Stage | WBDI ordinal | Engine ordinal | Message length |
|---|---:|---:|---:|
| Server step 1 | 62 | — | 576 |
| Client step 1 | — | 42 | 512 |
| Server step 2 | 63 | — | 452 |
| Client step 2 | — | 43 | — |
| Generate/retrieve authenticated test message | 66 / 67 | 44 / 45 | Ciphertext 80, plaintext 48 |
| Final state | 69 | 47 | Both must be 7 |

Original SGX reports, signer checks and GCM authentication remain in force;
authentication failure is not bypassed. WBDI28 and Engine33 select the authenticated
split-DH context before image encryption/decryption. Keys stay inside the enclaves.

### Calibration and default settings

Engine Attach uses sensor 3, minimum quality **20**, coverage **65**,
overlay/preoverlay 100, liveness/retry 0, and the original 36-byte settings block
(nine little-endian u32 values):

```text
{0, 0, 13, 13, 0, 0x02030104, 0x02030104, 0x02030104, 12}
```

These are the EngineAdapter defaults at `0x18000ad00`, configuration base
`0x1800837c0`, passed by `0x180014f60`; no Windows registry override is assumed.
The version-output capacity is 63 bytes. Engine1 is followed by Engine2
(Adapter wrapper `0x180027c50`): five input byte pointers with defaults
`{4, 1, 5, 8, 4}`, and no application-result slot. Successful Attach does not
initialize the image preprocessor; it resets the Adapter's base-valid flag and
public sensor-type field to zero.

Engine OCALL0/1 read/write calibration with
`{i32 result; void *buffer; u64 bytes; u8 type;}`:

| 3.00.20 type | Exact contract |
|---|---|
| 0 | 99516 (`0x184bc`) bytes, including the 16-byte identifier |
| 1 | Read capacity 40980 (`0xa014`); writes 20..40980 bytes with `u32(buffer+16) == bytes-20` |

The Adapter persists scalar calibration and the calibration array separately as
`goodix_calib.dat` and `goodix_Arr.dat` (OCALL read `0x180010c40`, write
`0x180010e50`). The trusted read buffers are zero-initialized; the host additionally
zero-pads short type-1 reads, but does not perform that extra padding for type 0.
The host callbacks return zero regardless of file-I/O results; the trusted code
validates the returned identifier and calibration content. These files are not
interchangeable, and destroying an enclave does not delete them. The Linux host
enforces bounds, pointer and private-storage checks.

The 3.00.20 save helper `0x180001be0` has three modes: mode 0 writes only type 0,
mode 1 only type 1, and mode 2 writes type 0 followed by type 1. Its triggers are:

- Engine7 (`0x180001e50`) reads type 1 and then type 0, checks identifiers and
  falls back to default calibration if loading fails. Successful preprocessor
  initialization immediately saves mode 0.
- The first successful Engine8 (`0x180006230`) with no valid array loaded from
  file saves mode 2 and sets its internal data-in-file flag.
- Engine27 (`0x180004970`) saves mode 2. Its request pointer is NULL; there is no
  application-result record.

The Adapter's pending-save flag is independent of the Engine8 internal flag.
`AcceptSampleData` sets host `ctx+0x12c` at `0x1800184f2` only after Engine7's SGX
and application results both succeed. This happens **before** checking the
returned base-valid value, so a later invalid-base, Engine8 or quality rejection
does not undo the pending save. Engine7 failure does not newly set it. Normal
Detach (`0x1800163a0`, Engine27 call at `0x1800165e3`) and S3
`NotifyPowerChange` (`0x18001e770`) consume this flag, invoke Engine27 and clear
it; normal Detach then calls Engine3 and destroys the enclave.

In 3.00.20, `preprocessor_init` (`0x180017170`) invokes B calibration. After the
16-byte identifier, payload+8 contains Kr, +`0x9928` B, +`0x18488` the processed-frame
count. Native state uses the two calibration filenames under the private `--state`
directory, along with the separate sealed baseline and opaque WBDI cache.

### Engine7/8/9 preprocessing contract

Engine7's marshalling record is 48 bytes. At offset `+0x20` is an input
`u32 *need_update_calibration`; at `+0x28` is an input/output `u32 *base_valid`.
The 3.00.20 wrapper (`0x1800070e0`) copies the first input but does not copy it
back; the trusted implementation validates that pointer without reading its
value. The Adapter calls Engine7 only when its own base-valid flag is false or
the image-base update indicator requires it. A returned base-valid value of 1
sets host `ctx+0x84`.

Engine8's pointer at record offset `+0x18` is `m_sensorTypeforpub`. Its value is
copied into the raw-image and FeatureSet metadata at `+0x1c`. The wrapper
(`0x1800073b0`) treats this and the liveness, size and enrollment pointers as
inputs, with no pointer-output copy-back.
Do not conflate this public sensor-type field or the Adapter's base-valid flag
with WBDI's separate base sequence/validation state.

The Adapter's `AcceptSampleData` (`0x180016dd0`) distinguishes transition errors,
preprocessor results and quality results:

| Condition | Original host action |
|---|---|
| Engine7 SGX or application result is nonzero | E_FAIL (`0x180018431` / `0x180018497`), not a capture retry |
| Engine7 succeeds but host base-valid is still false | BAD_CAPTURE (`0x1800185a2`); the pending-save flag is already set |
| Engine8 SGX result is nonzero | E_FAIL |
| Engine8 application result is nonzero | BAD_CAPTURE in the normal sensor-3 path |
| Engine8 succeeds | Query Engine9 |
| Enrollment: Engine9 returns -1 | BAD_CAPTURE |
| Enrollment or comparison: Engine9 returns -2 | BAD_CAPTURE and clear **Adapter host** base-valid, not WBDI base-validation history |
| Verify/identify: Engine9 returns -1 | Continue to comparison; do not impose the enrollment quality gate |

Engine9 (`0x180006190`) checks coverage <65 or quality <20 first and returns -1;
its subsequent zero/zero check returns -2. With these configured nonzero
thresholds, zero/zero already takes the -1 branch. The host still has the -2
handling above. Normal sensor-3 retry is disabled; the separate OEM power retry
mode permits at most two frames total, not two additional attempts. Engine36
statistics are diagnostics, not an additional host acceptance gate.

### Enrollment, comparison and S3

`EngineAdapterCreateEnrollment` (`0x18001c300`) is idempotent while host
InProgress is set and does not require Engine7 first. Engine10 creates a
12-sample enrollment. Update (`0x18001c950`) passes the actual host
required/used/progress values to Engine11, then queries Engine12 **only after a
successful merge**. Engine11 -1/-2 are capture retries; 0x8001/0x8002 also discard
the enrollment; -3 returns E_FAIL without querying status. A -1 path can already
have freed the enclave enrollment session, so an unconditional Engine12 query
would be invalid. Engine12 owns the returned count/progress; the UI's last
reported count is not a substitute for these host values.

Engine4 (`0x180001de0`) releases the enrollment session and template staging
buffers, **not the current FeatureSet**. Engine3 (`0x180003d30`) releases the
preprocessor/FeatureSet and other algorithm state. Candidate comparisons do not
require Engine4 between templates. Commit (`0x18001da60`) seals with Engine14/15,
then adds the record to storage, and only after successful storage calls Engine4
and clears InProgress; storage failure does not perform that cleanup.

Engine17's 56-byte record has `study` (input byte pointer) at `+0x18`, update
length (output u32 pointer) at `+0x20`, `liveness` (input byte pointer) at `+0x28`,
and **by-value u8** `new_image` at `+0x30`, followed by seven padding bytes.
The Adapter defaults study to 1 and liveness to 0. Verify passes new_image=1;
Identify passes 1 for the first candidate of each frame and 0 for later
candidates. In **3.00.20**, the trusted Engine17 implementation (`0x180002ff0`)
reads this new_image value at `0x18000333b` for logging only.

The Adapter treats Engine17 -1 as no-match, -2 as BAD_CAPTURE, and 0/1 as a match;
Verify additionally accepts 0x83 as no-match. Result 1 retrieves the adapted blob
through Engine16, not through an Engine36 score threshold. Obtaining an adapted
blob is distinct from persisting it: `EngineAdapterDeactivate` (`0x18001f090`)
flushes the pending host adaptation to storage. Linux updates the corresponding
FpPrint only after a fully validated successful match result.

S3 `NotifyPowerChange` (`0x18001e770`, power code 4) saves pending calibration and
destroys the enclave. Destroy (`0x180013490`) clears the enclave handle/algorithm
state but retains host InProgress, used and progress. Resume notifications
0x0a/0x12 do not themselves recreate the algorithm; the next operation lazily
recreates and attaches it. The new algorithm resets base-valid/public sensor-type
state, but **does not call Engine10 to replace a retained enrollment**.

When Engine11 (`0x180003f00`) sees a missing session, it allocates one **before**
testing the signed host used count against 3 (`0x180004189`–`0x18000418e`). With
used <3, it copies used/progress into that new session (`0x18000419b`,
`0x1800041a9`) and merges the new frame; old FeatureSets are not restored. With
used >=3, it returns -3 (`0x180004231`) after allocation, without a merge. The
host must neither pre-reject this before Engine11 nor silently restart via
Engine10. Update also resets a previously complete used=12 to 0 before its next
merge without clearing progress, so the transient host pair `(0,100)` can be
preserved across interruption.

### Linux client protocol v2

The wire contract is in
[`goodix_milanl_proto.h`](../userspace/libfprint/goodix_milanl_proto.h). HELLO
negotiates version 2. The only request allowed while another is outstanding is
SUSPEND, encoded as `u32le length=1` followed by opcode 7, **after the original
request has been fully written**. The server sends the original normal result
or `R_INTERRUPTED=9` with no payload, followed by SUSPEND's own response.
Other requests remain serialized; true cancellation remains socket EOF.

SUSPEND and RESUME use the same socket so the daemon retains actual OEM host
used/progress, including updates completed before their response reached the
client. The client reports completed stages, holds a completed final enrollment
or match result until RESUME, and does not repeat already completed work. A
successful BEGIN resumes at CAPTURE; an interrupted, unfinished BEGIN remains
BEGIN. The first resumed stage can differ from the UI's previous count, including
the OEM complete-count reset described above. Pending response reads and the
SUSPEND write must both finish before their shared client state is freed.

Opaque blobs are bounded at **1 MiB**, galleries at **16 entries**, and complete
frame bodies at `16 * (1 MiB + 4) + 3` bytes, enough for the largest valid gallery.
These are transport allocation bounds, not algorithmic matching thresholds.

### Time, logging and events

Engine OCALL4 implements `GetSystemTimeAsFileTime`, request
`{u32 *high; u32 *low;}` with no application return field:

```text
FILETIME = (unix_seconds + 11644473600) * 10000000 + nanoseconds / 100
```

Write high first, then low; if either pointer is NULL, write neither. Validate
all non-NULL output spans and reject invalid clock values. This host-provided
template metadata is not a trusted security clock. The OEM path is Adapter table
`0x180075420` → `0x1800293d0` → `0x180011030`.

WBDI OCALL4 is a **different** interface: a no-argument event emitted only by
the one-key IMAGE branch (metadata begins `0xaa`). Ordinary IMAGE completion
must not depend on it. Engine log OCALL5 and WBDI log OCALL14 payloads are
discarded without reading or formatting; unsupported OCALLs fail explicitly.
