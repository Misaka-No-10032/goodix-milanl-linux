# Private fakeroot build

This helper builds fakeroot 2.1.4 with a SysV receive-handling patch. It is an
optional build tool, not part of the fingerprint runtime or its packages.
The patch checks `msgrcv()` before decoding a reply: EINTR retries the receive,
and other errors use the existing error-reporting path.

## Build

Supply the original upstream archive locally:

- Source: <https://deb.debian.org/debian/pool/main/f/fakeroot/fakeroot_2.1.4.orig.tar.xz>
- SHA-256: `0822bd5a9f0cf19d2ba0546b88b0432d4d3d9917db62c57b74044ccadba06e49`
- License: GPL-3.0-or-later; the archive's COPYING file applies.

From the repository root, using existing Meson/Ninja, C compiler and test tools:

```sh
MESON=/path/to/venv/bin/meson bash packaging/arch/build-fakeroot.sh \
  /private/new-fakeroot-build /path/to/fakeroot_2.1.4.orig.tar.xz

export PATH="/private/new-fakeroot-build/prefix/bin:$PATH"
# Run build-runtime.sh, build-kernel.sh or build-userspace.sh with this PATH.
```

The helper verifies the archive before extraction, refuses an existing output
directory, applies the patch without fuzz, stages the tool under that output's
`prefix/`, and requires the focused IPC tests to pass. It neither downloads
dependencies nor replaces the system fakeroot package. Keep the selected prefix
available while makepkg runs; no fakeroot binary or library is added to the
fingerprint runtime packages.

## Tests

```sh
python3 -I -B tests/packaging/test_fakeroot_ipc.py \
  --fakeroot /private/new-fakeroot-build/prefix/bin/fakeroot -v
```

The tests exercise real fakeroot/faked ownership replies using synthetic temporary
files. A test-only receive interposer injects EINTR or EIO to check retries,
request/reply alignment and error reporting. File ownership outside fakeroot
remains unchanged.

The build helper gates on these focused IPC tests. Run the upstream suite
separately:

```sh
VERBOSE=1 /path/to/venv/bin/meson test \
  -C /private/new-fakeroot-build/build --no-rebuild --print-errorlogs
```
