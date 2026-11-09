# Capture and template lifecycle

This specification describes the OEM host contract used by the native engine.
Binary references use the [pinned OEM inputs](oem-sgx.md#inputs-and-provenance).
All `0x180…` addresses are **preferred image VAs**, image base `0x180000000`,
not RVAs; each reference names its DLL. Hardware framing is specified
[separately](hardware-protocol.md).

## Baseline and frame ordering

The full baseline operation is:

```text
FDT0 → NAV / WBDI6 → FDT1 → threshold check
     → IMAGE / WBDI5 → FDT2 → stability check → WBDI26
```

The first comparison is FDT0↔FDT1, the second FDT1↔FDT2, over all 12 raw u16
values against the decoded register `0x82` high-byte threshold. Each absolute
difference must be at most that threshold. NAV instability prevents IMAGE;
IMAGE instability prevents commit. With `exists=0`, instability restarts at
FDT0. With `exists=1`, either rejection returns success without committing the
candidate, preserving the previously committed base.

`gfspi!gf_update_all_base` (`0x18005c738`) commits **one** accepted stable
candidate through WBDI26 at `gfspi!0x18005d055`.
[capture.rs](../userspace/engine/src/capture.rs) implements that single-cycle
contract. Transport/enclave errors return to the caller, which owns setup retries
or capture rearming. Human waits have no arbitrary deadline.

### Initial FDT, cold setup and resume

`gfspi!gf_get_fdtbase` (`0x18005a1a0`, call at `gfspi!0x18005a26f`) uses
`SetMode(3,3,1)` for FDT0, FDT1 and FDT2: command `0x36` with the 34-byte payload:

```text
[0x0d, 0x01] + encoded DOWN[24] + zero[8]
```

The first input is the current **encoded** host DOWN array. Subsequent manual
measurements update DOWN with `((raw_u16 >> 1) * 0x101) mod 65536`. The initial
DOWN array (`gfspi!0x1800dd588`) comes from PE zero-filled storage when the OEM
DLL is loaded; this initialization does not clear the array on every resume.

The setup branches are distinct:

- Cold setup calls the updater at `gfspi!0x180053a78`, even after importing a
  matched file. Only failure causes a second call at `gfspi!0x180053ac4`.
- Resume (`gfspi!0x180055f74`) skips the updater after a matched import. Without
  one it calls the updater once at `gfspi!0x180056632`.
- After the final updater failure, **both** branches fall back to
  `SetMode(3,1,0)`: command `0x32`, payload **`[0x0c, 0x00]` only**. This arms
  MCU-default DOWN without transmitting any 24-byte host base and without
  clearing the host DOWN/UP arrays. Sending a normal 34-byte request containing
  zeros is not equivalent.
- Successful update/import uses the ordinary encoded-base DOWN arm.

[Session initialization](../userspace/engine/src/engine.rs) follows these branch
counts and short-DOWN fallback. Cancellation, teardown and an unusable enclave
transition remain errors, not reasons to continue using invalid resources.

### WBDI ownership and state

| State | Meaning |
|---|---|
| Host `exists` | A matching persisted baseline was imported; saving a fresh baseline does not set it |
| Host/WBDI `valid` | Classification-history result; not image quality or a successful-commit counter |
| WBDI `imagebase_ready` | A committed IMAGE is available to ordinal 38 |
| Engine `algorithm_base_valid` | Algorithm preprocessing state managed through Engine7/9 |
| Host `NeedUpdateImageBase` | Pending notification for the next class-1 handoff |

These states must not be substituted for one another. In particular, ordinal 38
is governed by committed IMAGE readiness, not by host `valid`.

WBDI ring ownership is essential. Records below use x86-64 natural alignment;
application results are separate from SGX transition status.

| Ordinal | Contract |
|---:|---|
| 2 | Initialize buffers with IMAGE `0x7380`, NAV `0x18c0`, sensor 3, retry 0, maximum 1 |
| 14 | `FDT_Init` receives sensor type and actual OTP-derived threshold/tcode |
| 3 / 4 | Clear ring / query `i32 empty`; receiving a frame is not consuming it |
| 18 | `{u8 result; void *source; u16 bytes;}` (24 bytes); exact 4756-byte packed NAV+CRC, **result=1** succeeds |
| 6 | Consume queued NAV into current NAV |
| 41 / 5 | TLS-decrypt and queue IMAGE / consume it into current IMAGE |
| 11 | `{u32 *nav_bytes; u32 *image_bytes;}` (16 bytes); sealed sizes, no application-result field |
| 12 / 13 | `{void *nav; u32 nav_bytes; void *image; u32 image_bytes;}` (32 bytes); export/import sealed bases, no application-result field |
| 25 | `{i32 result;}`; temperature classification of already consumed IMAGE, not another IMAGE read |
| 26 | `{i32 result; u32 *exists,*valid,*changed;}` (32 bytes); update bases from current NAV/IMAGE, application result 0 |
| 27 | `{i32 result; u32 *need_update,*valid;}` (24 bytes); update/check from current IMAGE/NAV, normal result 0/1; **no sequence field** |
| 36 / 38 | Encrypt/classify current contact IMAGE / encrypt committed IMAGE base; each uses a 29600-byte output |
| 3 / 9 / 1 | Clear ring → release ring (`retry=reserved=0`) → release image/base buffers |

NAV requires independent exact-length and CRC validation before WBDI18: its
fixed unpacker cannot safely consume a shorter buffer merely because that buffer
has a valid CRC. NAV passes through plaintext host RAM; IMAGE remains in the live
TLS/WBDI path. WBDI41 does not parse NAV as an IMAGE.

Manual FDT (`gfspi!milanLget_fdtdata`, `0x180039c70`, IRQ `0x100`) clears the
ring through WBDI3, as does DOWN handling. Consume NAV via WBDI6 before the next
FDT and IMAGE via WBDI5 before its next FDT. **The contact frame must also pass
WBDI5 before WBDI36.** A source read or successful TLS read does not populate the
algorithm's current frame by itself.

WBDI26 with `exists=0` copies current IMAGE/NAV, marks IMAGE ready and sets
`changed=1`; it does not set `exists` or advance validity history. With an
existing base, IMAGE and NAV classifications govern their respective updates
and validity history. Initialize `changed=0` before the call and save when it is
set.

WBDI27 is **not a status query**. On UP/RESET, when host `valid=0`, obtain and
consume a new IMAGE, then NAV, before calling it. Initialize `need_update=0`;
retain the returned `valid`, propagate a set update flag, and save when its
application result is 1. With `valid!=0`, skip this check. This replaces neither
the initial full updater nor the algorithm's quality judgment.

### Persisted baseline

[sgx/baseline.rs](../userspace/engine/src/sgx/baseline.rs) owns the OEM
`goodix.dat` record:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 32 | Complete OEM-normalized sensor identity |
| 32 | 24 | **Already encoded** DOWN FDT |
| 56 | 6896 | Sealed NAV (`0x18c0 + 0x230`) |
| 6952 | 30128 | Sealed IMAGE (`0x7380 + 0x230`) |
| 37080 | 4 | CRC, stored little-endian |

The record is 37084 (`0x90dc`) bytes. The CRC covers all preceding bytes and is
CRC-32/MPEG-2: polynomial `0x04c11db7`, initial value `0xffffffff`, MSB-first,
non-reflected, no final xor (`123456789 → 0x0376e6e7`). It is not zlib's IEEE CRC.

A complete record, matching CRC and all 32 matching identity bytes are required
before WBDI13 import. Restore FDT directly into host DOWN/UP; do not encode it a
second time. Ordinal 13 exposes SGX status but no application unseal result.
WBDI12's disk-sealed bases are distinct from WBDI38's session-DH encrypted
29600-byte IMAGE output.

Missing/unreadable files, short reads and identity/CRC mismatch make the cache
unavailable; they do not themselves fail initialization. Save is a void OEM
operation (`gfspi!0x18005b680`): disk write failure/short write is logged, the
live base remains usable, and `NeedUpdateImageBase` is still set. Native State
path, owner and mode checks remain enforced; rejecting an unsafe cache does not
authorize importing it. SGX transition errors are separate from disk I/O errors
and are not swallowed by this file fallback.

## Capture, release and temperature

`gfspi!gf_captureFingerdata` (`0x180058468`) obtains and consumes IMAGE before
WBDI36 (`gfspi!0x180063c8c`):

| WBDI36 result | Host action |
|---:|---|
| 1, finger | Export committed base through WBDI38 and hand current/base ciphertext to EngineAdapter |
| 0, temperature | Stop/clear the temperature timer and run the temperature update when not already busy |
| 2, void / 3, bad | Rearm DOWN; no full baseline refresh and no successful sample |
| -1, encryption failure | Rearm DOWN; not another quality classification |

Only class 1 reaches Engine7/8. Baseline maintenance runs during setup/resume,
temperature updates and conditional UP/RESET checks.

Every class-1 handoff has the post-capture tail, including algorithm quality
rejection: manual FDT → ring clear → arm UP. The manual result's flags are ORed
with the flags saved at the original DOWN. Compute the threshold-dependent UP
candidate and replace each UP **u16** with `min(previous, candidate)`. This is
not a bytewise minimum and does not modify DOWN. Ordinary baseline manual FDT
updates DOWN instead.

[sensor/touch.rs](../userspace/engine/src/sensor/touch.rs) keeps encoded DOWN/UP,
saved flags and pressed state separate from Session timer/busy state. UP and
REVERSE update DOWN from their raw measurements; RESET does not. RESET IRQ
`0x400` first performs `ChipRegWrite(0x0008, [0x11,0x11], 2, 100)`:
command `0x80`, payload `[0,8,0,0x11,0x11]`, ACK only. It then takes the UP
worker path: stop the timer, clear contact state, and, when not busy, perform
the conditional WBDI27 check and arm DOWN. This is not `HardResetMcu`.

Asynchronous FDT arriving during ACK/TLS exchanges is validated and queued raw.
Its host-state changes are applied in FIFO order when the event is consumed,
not when queued; an early UP must not overwrite state before its DOWN is
processed. Human and timer-bounded event waits remain cancellation/suspend aware.
The OEM manual-call parameters of 500 ms (baseline) and 200 ms (post-capture)
are not their final effective wait: ACK and following event waits each promote
nonzero values below one second to one second.

### One-shot temperature timer

Timer existence and its pending deadline are separate state:

- A DOWN **without a pending capture request** creates the timer if absent,
  schedules its first tick in **5 seconds**, and arms UP. Startup/resume do not
  create a timer on their own.
- A tick consumes its deadline but leaves the timer object present. It clears
  the ring, acquires/consumes IMAGE, then calls WBDI25: class 0 runs the updater,
  classes 2/3 arm DOWN, and other results arm UP.
- The timer is one-shot, not periodic. A successful tick does not schedule the
  next tick. IMAGE acquisition failure or temperature-update failure may
  reschedule for **2 seconds only while the timer still exists**.
- Normal capture has already stopped/cleared the timer. A class-0 update
  failure there therefore does not imply a two-second retry.
- Temperature update clears host validity/contact state, runs the full updater,
  and on success arms DOWN, clears busy and sets `NeedUpdateImageBase`.
- UP/RESET, capture takeover and teardown stop pending timer work. No callback
  may outlive its sensor/enclave session.

## Preprocessing and quality

`EngineAdapter!EngineAdapterAcceptSampleData` (`0x180016dd0`) receives the
current/base ciphertext pair. `ctx+0x84` is algorithm `basevalid`;
`sample+0xeb6c` bit 0 is `NeedUpdateImageBase`.

1. If algorithm basevalid=0 or NeedUpdateImageBase is set, Engine7 initializes
   from the **current committed** encrypted base. Its final pointers are
   `need_update_calibration` and `base_valid`, not size/initialized outputs.
   Require successful SGX/application status and a usable algorithm base before
   proceeding. Successful initialization also marks calibration-save pending.
2. Engine8 preprocesses the current image with its enrollment/non-enrollment
   purpose. Its third pointer argument is `sensor_type`, not a sequence counter.
3. Only Engine8 application result 0 leads to Engine9:
   - 0: accept;
   - -1: reject enrollment as poor quality, but accept the non-enrollment path;
   - -2: reject and clear algorithm basevalid, requiring Engine7 on a later sample.
4. An Engine8 application error rejects the capture without calling Engine9 or
   clearing algorithm basevalid merely because of that error.

NeedUpdateImageBase is set by baseline save (`gfspi!0x18005ba9e`), WBDI27
handling (`gfspi!0x180059793`), successful temperature update (`gfspi!0x18005c729`)
and `gfspi!needupdate_engine_base` (`0x18005e434`). The pending notification is
consumed by the class-1 handoff; it is distinct from algorithm base validity.

| Engine ordinal | ABI / result |
|---:|---|
| 7 | `{i32 result; void *base; u32 bytes; void *id16; u32 *need_update_calibration,*base_valid;}`; base length 29600 |
| 8 | `{i32 result; void *image; u32 bytes; u32 *sensor_type; u8 *liveness; u32 *size; u8 *enrollment;}` |
| 9 | `i32 result`; purpose-dependent quality judgment, not identity match |
| 36 | Eight `i32 *`: coverage, quality, algorithm, match, similarity, update, preoverlay, overlay; diagnostic outputs, not an additional acceptance gate |

The original minimums remain quality **20** and coverage **65**. Quality and
coverage are not matching similarity. Application `0x8002` wraps an algorithm
rejection; `30001`/`50001` must not be labeled wrong-finger, PMK failure or transport
failure. Multiple branches can produce `30001`, so its number alone does not
identify the cause. High image quality also does not guarantee mergeable features.

### Calibration file contract

`EngineAdapter!0x180010c40` / `EngineAdapter!0x180010e50` are the OEM calibration
read/write callbacks. Kind 0 uses `goodix_calib.dat`; kind 1 uses `goodix_Arr.dat`.
Both callbacks return application 0 even after file-open, short-read or write
failure. Kind-0 reads leave bytes beyond the actual read unchanged. Kind-1 reads
zero only the unread tail; a missing file therefore zeros its entire requested
buffer. This is not an unconditional pre-read clear for both kinds.

Kind 0 uses `0x184bc` bytes. Kind-1 reads request `0xa014` bytes; writes contain a
20-byte header plus the payload length recorded at offset 16, bounded by that
capacity. Native ABI/buffer validation is separate from these nonfatal disk I/O
semantics.

Engine7 reads the array and scalar calibration and can save scalar calibration;
Engine8 can save both on its first successful initialization path. When the host
has calibration-save pending, Engine27(NULL) saves both forms before S3 or normal
detach. These are preprocessing calibration files, not enrollment checkpoints.

## S3 and enrollment state

`EngineAdapter!EngineAdapterNotifyPowerChange` (`0x18001e770`) optionally calls
Engine27 for pending calibration, then destroys the algorithm enclave through
`EngineAdapter!0x180013490`. `gfspi!MilanEvtDeviceD0Exit` (`0x18001fd60`) also
tears down WBDI for the full power transition; D3/S0 idle has a separate shortcut.
OEM resume recreates WBDI and restores/updates its base according to the branches
above; the next sample lazily recreates the algorithm enclave through
`EngineAdapter!_Check_Start_Enclave_Init_Algo` (`0x1800135a0`).

The adapter retains host InProgress and used/progress metadata, **not accumulated
features**. When `Engine_Enclave_3.00.20.signed.dll!MergeFeatureSetWithEnrollment_ecall`
(`0x180003f00`) finds no session, it allocates one and checks the supplied used
count at `Engine_Enclave_3.00.20.signed.dll!0x180004189`:

- Below 3: copy used/progress metadata and merge the fresh sample.
- At least 3: return application -3, mapped by EngineAdapter UpdateEnrollment to
  `E_FAIL` at `EngineAdapter!0x18001cc9c`.

The threshold applies to the count passed to Engine11; UpdateEnrollment clears a
previously completed count of 12 before attempting another merge. The -3 branch
has already allocated a session and does not itself discard it. Subsequent
Windows UI/service handling is outside these binaries.

The native engine retains used/progress on suspend or a changed suspend epoch,
recreates sensor/enclave resources, and restores only that host metadata through
`Runtime::resume_enrollment`. It does not call Engine10 on that continuation:
the next Engine11 must take its own recreated-session branch. Cancel discards
the retained metadata. No old feature buffer or full enrollment sample history
is preserved across power loss.

## Enrollment, sealing and comparison

The EngineAdapter WBF table is at `EngineAdapter!0x18008c490`. Create
(`EngineAdapter!0x18001c300`), status (`EngineAdapter!0x18001cd70`), commit
(`EngineAdapter!0x18001da60`), discard (`EngineAdapter!0x18001e2e0`) and verify
(`EngineAdapter!0x180019650`) map to the following Engine calls. Each `i32 result`
is an application status, separate from SGX status:

| Ordinal | Request / condition |
|---:|---|
| 10 | `{i32 result; u8 *samples;}`; create with 12, application 0; repeated host create while InProgress is set is a no-op |
| 11 | `{i32 result; u8 *samples; i32 *used,*progress; u8 *liveness; u32 *hint;}`; merge fresh accepted features |
| 12 | `{i32 result; i32 *required,*used,*progress;}`; required=12, used=n, progress=n×100/12; application -1 until the twelfth accepted frame, then 0 |
| 14 | `{i32 result; u64 *bytes;}`; sealed-template size bounded to 560..1048576 bytes before allocation |
| 15 | `{i32 result; void *buffer; u64 bytes;}`; retrieve sealed template, application 0 |
| 4 | NULL; release enrollment/template context, no application-result field; does not itself free the current feature image |
| 17 | `{i32 result; void *blob; u64 bytes; u8 *study; u32 *update_bytes; u8 *liveness; u8 new_image; u8 reserved[7];}`; 56 bytes, study input 1, new_image is inline |
| 16 | `{i32 result; void *buffer; u32 bytes;}`; retrieve adaptation, **u32** length unlike ordinal 15 |

Engine11 result 0 permits a status query; -1/-2 requests another sample;
`0x8001`/`0x8002` require discard; -3 is the power-loss continuation failure above.
A failed merge can destroy the enclave enrollment context, so never call
Engine12 after it. Engine36 diagnostic slots add no extra merge acceptance gate.

`Runtime::seal` returns opaque sealed bytes. The OEM adapter closes its enrollment
after successful storage. At the Linux service boundary, the engine returns the
sealed blob and closes its context; libfprint/fprintd owns persistence. Discard
releases the context without producing a template.

Engine17 owns the comparison result: 0 means match; 1 means match with adaptation
that must be retrieved successfully through Engine16; -1 means no-match; -2
requests another capture. Verify also treats `0x83` as no-match. Application 0
requires no update length/flag. Do not impose additional Engine36 algorithm,
match or positive-similarity gates. Sealed authentication failure (`0x8007`) is
an error, never an accepted identity.

VERIFY and IDENTIFY acquire one fresh accepted image. Gallery candidates reuse
that feature set, with inline `new_image=1` for the first candidate and 0 for
later ones. The host keeps the operation open between candidates. Only the
matching template may be replaced by an adapted sealed blob. libfprint preserves
FpPrint metadata, and
[patched fprintd](../userspace/fprintd/README.md) saves it **before** signaling
authentication success. A save failure reports an error, even when the successful
match produced no changed blob.

Template persistence remains outside the engine; sealed baseline and calibration
state are State-backed. Session cleanup first stops temperature work, saves
pending calibration while the enclave is usable, releases WBDI/Engine resources,
exits TLS and returns the sensor to IDLE. Sensitive host buffers are erased, and
the previous session must finish cleanup before another client is served.
