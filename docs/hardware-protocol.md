# Hardware and MCU protocol

Scope: the Goodix MilanL `0x2205` sensor on MACHR-WX9, ACPI `GXFP51B7`.
The transport is ACPI/EC shared memory, not USB. ACPI identity alone does not
establish the chip model; initialization checks the sensor's register reply.
Binary references use the [pinned OEM inputs](oem-sgx.md#inputs-and-provenance).
Addresses beginning `0x180…` are preferred image VAs with image base
`0x180000000`, not RVAs.

## Platform and ACPI mailbox

The target platform uses an Intel Core i5-8265U with SGX1 and no flexible launch
control (FLC). Launch authorization requires legacy isgx launch tokens and the
matching Intel Windows Launch Enclave; see
[launch authorization](oem-sgx.md#launch-authorization).

SSDT11 defines `\_SB.SPBA` with `_HID`/`_CID` `GXFP51B7` and:

| Interface     | Contract                                                                                                                       |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `_CRS` memory | `Memory32Fixed`, read/write, length `0x8000`; base `FPDA` is supplied dynamically through firmware `HWNS`, never hard-coded    |
| GPIO          | Level-triggered active-low interrupt plus a separate output for host acknowledgment                                            |
| `_DSM`        | UUID `cc58b68a-4479-4893-a8bb-961209db59e5`, revision 0                                                                        |
| Function 0    | Returns supported-function mask `0x07`                                                                                         |
| Function 1    | Returns the `0x800`-byte FPDT area; its memory base derives from firmware `FPKY`                                               |
| Function 2    | Calls `\_SB.PCI0.LPCB.HWEC.ECMD(0xF0)` to notify the EC; it is not a side-effect-free read or proof of a reply                 |
| Functions 3/4 | Check `H_EC.ECMD` but call `HWEC.ECMD(0xF1/0xF2)`; not advertised by function 0, so not usable as assumed ACK/reset primitives |

The mapped window is TX `[0,0x1000)` and RX `[0x1000,0x8000)`. The transport
writes TX, issues a write barrier and invokes `_DSM` function 2. For a valid RX
header, its IRQ handler copies the mailbox **before** acknowledging it: output
low, wait 5–6 ms, output high, then publish the frame/error and wake readers.
The minimum 5 ms low interval follows OEM `WriteDriverOutGPIO` (`0x180018744`).
Identical arrivals are not deduplicated. A 32-frame FIFO reports overflow as
`ENOBUFS` rather than silently overwriting; released frames and queues are erased.

The current kernel interface is [`goodix_milanl_transport`](../kernel/goodix_milanl_transport.c),
`/dev/goodix-milanl-raw`, mode 0600, single-open and `CAP_SYS_RAWIO`-gated.
`poll`/`pread` consume IRQ-captured frames, not arbitrary mailbox snapshots.
By default only the fixed chip-ID, OTP, MCU-state, PMK-hash and IMAGE/NAV/IDLE
requests are allowed. Other correctly framed requests require explicit
`enable_raw_tx=1`.

### Sealed firmware input

[`GOODIX_MILANL_IOC_SEALED_INPUT`](../kernel/goodix_milanl_uapi.h) additionally
requires `enable_sealed_input=1`. It returns a bounded sealed blob, not the whole
FPDT or a plaintext key. The driver checks the ACPI length, blob/payload bounds,
SEAL key name 4 and MRSIGNER policy 2; ACPI/kernel temporary buffers are erased.
WBDI performs unsealing inside SGX under its original MRSIGNER identity.

## Wire framing and replies

The common four-byte MP envelope is:

```text
kind | payload_length:u16le | sum(first 3 bytes) mod 256
```

The MCU runtime accepts exact channel bytes `0xa0` (control) and `0xb0` (TLS).
For control, the payload is `command:u8 | inner_length:u16le | data | checksum`,
where `inner_length = len(data)+1` and the sum from command through checksum is
`0xaa` modulo 256. A control ACK has command `0xb0`, data `[target_command, status]`;
status 1 is success. Do not confuse that control command with the TLS envelope.
An ACK is not the command's data/event reply. Commands with both must collect
and validate the appropriate fresh replies, including when their order varies.

TLS envelopes contain TLS bytes directly, with no ordinary inner command or
`0xaa` checksum. `SendTLSPackage` (`0x18004f528`) uses this framing; the EC
`SendNopCmd` path does nothing. Host TX payload chunks fit the 4096-byte mailbox
including its four-byte envelope.

### Register and OTP decoding

`ChipRegRead` command `0x82` has data
`00 | address:u16le | byte_count:u16le`. Reading register `0x220`, two bytes,
therefore uses data `00 20 02 02 00`. **Every adjacent pair of reply bytes is
swapped** before interpreting register values. For the ID reply this produces
`a2 05 22 00`; OEM `init_FPSensor` takes bytes 1–3 as a little-endian value,
`0x2205`. `device_enable_init_by_chip` (`0x180054ef4`) maps it to MilanL.

OTP command `0xa6` returns 32 bytes. OEM validation accepts five formats: legacy,
sum8, and 22-, 23- or 25-byte CRC8 variants. CRC8 uses polynomial `0x07`, initial
zero and final XOR `0xff`. A cached identity can supply the original compatibility
fallback only when its first 16 bytes match and its OTP checksum validates.
Invalid OTP takes the original diagnostic/default path rather than rejecting
initialization outright. Raw values are never logged; the original 32-byte
identity metadata remains inside the private `goodix.dat` state file.

## Initialization and DAC contract

The original `gf_set_config` first calls `gfresetMCUAndfingerprint`: command
10/subcommand 1 (`0xa2`), data `05 14`, with the CHIP_RESET `0xa2` completion.
The firmware restores the sensor's factory DAC. The helper then sleeps 1 ms.
The engine sends the OEM volatile configuration; the **read-only** DAC check
belongs to the first classification-1 capture, not startup. No direct DAC write
is implemented.

Startup follows the original retry structure: driver-state `0x96` twice, EC
version `0xa8` up to four times, chip detection up to three, then a shared
three-attempt OTP/configuration loop. `HardResetMcu` at `0x180016e84` is a stub
returning 1, so Linux does not invent an ACPI or kernel hard-reset operation.
WBDI14 runs before configuration and again with the HAL's retained parameters;
WBDI9/1/2 initialize image buffers before WBDI39.

`download_general_config` (`0x18001c11c`) selects the sensor-3, 256-byte table at
file offset `0x92010` in the pinned `gfspi.dll`. Its last little-endian word is:

```text
-(0xa5a5 + sum(first 127 little-endian u16 words)) mod 65536
```

For a valid complementary OTP pair (`otp[22] != 0`, sum of bytes 22/23 is 255),
`CheckTcodeAndDiff` derives:

```text
tcode = ((otp[22] >> 4) + 1) * 16
delta = (((otp[22] & 15) + 2) * 0x6400 / tcode / 3) >> 4
```

Integer division is sequential. The timing field updates register `0x5c`; the
threshold updates the high byte of `0x82`, followed by checksum recomputation.
Otherwise the OEM defaults remain. Configuration command `0x90` requires both
its ACK and a separate result reply whose first data byte is 1 on success.
ACK and data waits have independent deadlines; a nonzero sub-second wait is
raised to one second. Only ACK timeout retransmits the original command once.
WBDI14 receives the derived threshold/tcode; for the invalid complementary-pair
branch its first call is 0/0 and its final call uses the HAL's retained tcode.

The raw-OTP `CheckDac` state is precise:

1. `MilanL_Open(&DAT_180206980)` establishes the context; `context+0x5164` aliases
   `DAT_18020bae4`, and `context+0x513c` aliases the checked flag `DAT_18020babc`.
2. With valid OTP and checked=0, `milanL_check_sensor` (`0x180039260`) sets
   `state = ((otp[0x13] & 0x80) << 8) | otp[0x1f]`. This is a **coarse field**.
3. `CheckDac` (`0x18004c844`) requires `(register_word >> 4) == state`. Only on
   success does it store `(state << 4) | (register_word & 15)` and set checked=1.
4. Later captures skip the checked comparison; OTP loading must not overwrite
   the normalized full word with the coarse field.

The first class-1 capture reads register `0x220` for this comparison; a failed
first read/check takes the original reset-idle and retry path. Reset and baseline
updates do not clear the checked flag. The engine does not tune or scan DAC values
and does not read Windows registry overrides.

## Authenticated MCU TLS

The enclave is the TLS server, MCU the client: TLS 1.2,
`PSK-AES128-CBC-SHA256` (`0x00ae`), identity `Client_identity`.
WBDI39 obtains and unseals keys itself through OCALL7 (opaque `Goodix_Cache.bin`),
OCALL6 (sealed firmware input on cache miss) and OCALL8 (cache write).
A nonzero WBDI39 application result invalidates the cache; 0 and 1 continue
through the original handshake path. Key material is not logged.

Command `0xd0` with two zero bytes starts the handshake; WBDI41 exchanges records.
After enclave state 16, finish sends `0xd4`, then tries three `Sleep(10 ms) → 0xae`
queries. Connected and locked are independent bits: connected is required;
a remaining lock causes another D4. An ordinary D4 error does not suppress AE.
The outer TLS setup loop allows three attempts, D4 on each failed attempt
including the final one, and WBDI40 before reinitializing an existing context.
IMAGE decryption uses this live enclave/TLS context; WBDI40 exits it on teardown.

OEM write OCALL failure returns `i32 -1`, while its SGX wrapper succeeds. OEM
read OCALL reads an asynchronously populated FIFO and returns 0 when empty.
Linux's synchronous mailbox adapter reports temporary empty reads as mbedTLS
WANT_READ and real I/O failure as -1, both through the callback result field;
ordinary I/O failure does not poison the enclave transition.

## Image and FDT data

| Data | Geometry / length |
|---|---|
| NAV | 132×24, 3168 pixels; 4752 packed bytes + four-byte CRC |
| IMAGE | 132×112, 14784 pixels; 22176 packed bytes + four-byte CRC |
| Unpacked enclave buffers | IMAGE `0x7380` (29568), NAV `0x18c0` (6336) bytes |
| IMAGE TLS payload | WBDI read length `0x56ad` (22189); packed source length `0x56a4` (22180) |

Packing maps six bytes to four 12-bit pixels. CRC is MSB-first CRC32/MPEG-2,
polynomial `0x04c11db7`, initial `0xffffffff`, no final XOR; the wire CRC swaps
the two 16-bit halves of its big-endian representation. NAV has a five-byte
image header before the packed source and ends with `0x88`. It is plaintext in
the transport/host RAM, not end-to-end TLS; IMAGE stays encrypted until WBDI.

Manual FDT produces IRQ `0x100` and 24 raw bytes (12 little-endian u16 values).
The raw snapshot is `context+0xa88e == 0x18021120e`. The transmitted down-base is
a different representation, `((word >> 1) * 0x101) & 0xffff`, **not** a byte swap.
`SetMode(3,3,1)` uses command `0x36`, data `0d 01 + down_base[24] + zero[8]`,
42 bytes total; completion requires ACK and the independent manual FDT event.
Every updater FDT0/FDT1/FDT2 uses this command, including the initial zero-filled
host DOWN state. An exhausted cold/resume updater uses `SetMode(3,1,0)`:
command `0x32`, data `0c 00` only,
leaving host DOWN/UP unchanged. Successful cache import restores the already
encoded 24-byte FDT to both arrays without another conversion.

FDT-down IRQ `0x002` starts contact capture; FDT-up IRQ `0x200` detects release.
Baseline stability compares all 12 raw words before/after NAV and IMAGE, rejecting
when any absolute difference exceeds the decoded register `0x82` high byte.
Equality is allowed; threshold zero requires equality throughout. FDT processing
clears the WBDI ring, so NAV/IMAGE must enter their current buffers before the
next FDT. Class-1 post-capture manual FDT merges the saved DOWN flags and updates
UP by wordwise minima, without changing DOWN. IRQ `0x400` restores vendor ID
register `0x0008 = 0x1111` using command `0x80`, data `00 08 00 11 11`, ACK-only;
it then shares UP processing and does not overwrite DOWN measurements.
See [capture ordering](capture.md#baseline-and-frame-ordering).
