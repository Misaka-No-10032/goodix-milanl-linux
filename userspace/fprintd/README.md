# fprintd adapted-template persistence

Target: fprintd 1.94.5, commit `b54a007ccf58ac0ae074c7151b223f35cbd17306`.

`0001-persist-matched-prints.patch` saves the successfully matched template in the
shared `match_cb()` in `src/device.c` before reporting authentication success:

- For successful, error-free verify/identify operations that have not been
  cancelled, call `store.print_data_save(match)` before emitting
  `VerifyStatus("verify-match", true)`.
- Save the enrolled object `match`, not the scanned object `print`. The Goodix
  MilanL driver replaces `fpi-data` in place before reporting the match; the
  original username, finger, enrollment date, description and other metadata
  remain unchanged.
- On save failure, log a warning and the storage backend's return code, then use
  the existing `G_IO_ERROR_FAILED` mapping to report the terminal
  `verify-unknown-error` status. No success is reported first, and no new D-Bus
  status is introduced. `VerifyStop` and subsequent operations remain available.
- Do not save on retry, no-match or cancelled operations. Storage layout, protocol
  and authorization remain unchanged.

libfprint exposes no adaptation-dirty flag, so the patch saves **every successful
match**, including unchanged templates. If storage is not writable, a successful
match with an unchanged template also ends with `verify-unknown-error`. The patch
uses the existing synchronous storage API without adding state or an asynchronous
storage framework.

## Build and regression tests

The [packaging workflow](../../packaging/README.md) builds
`libfprint-goodix-milanl` with the full default driver set and
`fprintd-goodix-milanl` with this patch, without installing them on the host.
Tests require Python 3, PyGObject, the FPrint 2.0 typelib and `dbus-daemon`;
`python-dbusmock` is not required.

After extracting the binaries and libraries from the packages, run the external
regression suite from the repository root:

```sh
# ROOT is a private unpacked package tree, not /.
LD_LIBRARY_PATH="$ROOT/usr/lib" GI_TYPELIB_PATH="$ROOT/usr/lib/girepository-1.0" \
  python3 -I -B tests/fprintd/test_adapted_print_storage.py \
  --fprintd "$ROOT/usr/lib/fprintd" --libfprint-libdir "$ROOT/usr/lib" -v
```

Alternatively, use `--libfprint-build /path/to/libfprint/_build` together with
`--fprintd` to select a compiled daemon. The suite runs fprintd and the asynchronous
libfprint driver rather than mocking `match_cb()`.

The six regression cases cover:

1. Verify updates a template. Check the stored data and metadata when the
   authentication signal arrives; the next `VerifyStart` must load the new blob.
2. Identify selects one of two enrolled prints and updates only its file, then
   verify the updated template separately.
3. A verify save failure reports failure only. After storage recovers, verification
   and saving can succeed again.
4. An identify save failure likewise rejects authentication and supports recovery.
5. A MATCH without adaptation still saves successfully, leaving template contents
   unchanged.
6. Retry, no-match and cancellation during a blocked capture leave the template
   and its inode/mtime unchanged. Reconnect after cancellation and complete a save.

Save failures are triggered deterministically by creating a directory at the
output file path in a temporary store, without changing host storage permissions.
The tests first enroll synthetic templates over D-Bus, with a scripted protocol
peer responding to all 12 stages; these are not user fingerprints.

## Isolation

`test_adapted_print_storage.py` creates a private `dbus-daemon` with no service
activation directories, registers a Polkit test object only on that bus, and sets
`DBUS_SYSTEM_BUS_ADDRESS`, `STATE_DIRECTORY` and `RUNTIME_DIRECTORY` for the test
fprintd process. The driver allowlist follows the
[persisted identity contract](../README.md#source-layout-and-names).

The tests do not connect to the host system bus, start system services, modify
policies, install libraries, or access fingerprint hardware or real templates.
The packaged fprintd may read `/etc/fprintd.conf` but does not modify it. The
private bus has no logind service, so sleep-inhibitor warnings are expected.

The tests always use a scripted protocol peer. The five-second watchdog applies
only to synthetic automated tests, never to human touch/release waits. Synthetic
templates must not be imported into real user accounts.

PAM configuration is separate from package installation. Fingerprint use for the
lock screen, sudo and polkit must retain password fallback; login remains
password-only.
