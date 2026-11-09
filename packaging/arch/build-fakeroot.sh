#!/usr/bin/env bash
# Build a corrected packaging tool in a private prefix; never replace host files.
set -euo pipefail
if (( $# != 2 )); then
    printf 'Usage: %s NEW_OUTPUT_DIR FAKEROOT_2.1.4_SOURCE_ARCHIVE\n' "$0" >&2
    exit 2
fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(realpath -m -- "$1")
archive=$(realpath -- "$2")
meson=${MESON:-meson}
command -v "$meson" cc patch bsdtar python3 >/dev/null
printf '0822bd5a9f0cf19d2ba0546b88b0432d4d3d9917db62c57b74044ccadba06e49  %s\n' \
    "$archive" | sha256sum -c -
umask 077
mkdir -m 700 -- "$work"
mkdir -- "$work/source"
bsdtar -xf "$archive" -C "$work/source"
source_dir="$work/source/fakeroot-2.1.4"
patch --batch --fuzz=0 -d "$source_dir" -p1 \
    < "$repo/packaging/arch/fakeroot/0001-check-msgrcv-before-decoding.patch"
"$meson" setup "$work/build" "$source_dir" --prefix="$work/prefix" \
    --libdir=lib --buildtype=release -Dipc=sysv -Ddocs=false
"$meson" compile -C "$work/build"
"$meson" install -C "$work/build" --no-rebuild
python3 -I -B "$repo/tests/packaging/test_fakeroot_ipc.py" \
    --fakeroot "$work/prefix/bin/fakeroot" -v
printf 'FAKEROOT_BUILD_PASS: add %s/prefix/bin to PATH for makepkg; host unchanged\n' "$work"
