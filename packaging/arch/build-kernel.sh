#!/usr/bin/env bash
# Build local DKMS packages without downloading, installing or loading anything.
set -euo pipefail
if (( $# != 2 )); then
    printf 'Usage: %s NEW_OUTPUT_DIR ISGX_GIT\n' "$0" >&2
    exit 2
fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(realpath -m -- "$1")
isgx_git=$(realpath -- "$2")
command -v makepkg git >/dev/null
# Refuse to reuse an output directory, preserving existing packages and sources.
mkdir -m 700 -- "$work"
mkdir -- "$work/sources" "$work/packages" "$work/isgx-dkms" "$work/transport-dkms"
# Only local Git transport is allowed, including during makepkg's VCS checkout.
export GIT_ALLOW_PROTOCOL=file
git clone --mirror -- "$isgx_git" "$work/sources/isgx"
git -C "$work/sources/isgx" remote set-url origin \
    'https://github.com/intel/linux-sgx-driver.git'
for project in isgx-dkms transport-dkms; do
    cp -- "$repo/packaging/arch/$project/PKGBUILD" \
        "$repo/packaging/arch/$project/dkms.conf" "$work/$project/"
done
cp -- "$repo/packaging/arch/isgx-dkms/isgx-linux73.patch" \
    "$repo/packaging/arch/isgx-dkms/isgx-legacy.conf" "$work/isgx-dkms/"
cp -- "$repo/kernel/Makefile" "$repo/kernel/goodix_milanl_transport.c" \
    "$repo/kernel/goodix_milanl_uapi.h" \
    "$repo/packaging/arch/transport-dkms/goodix-milanl-transport.conf" "$work/transport-dkms/"
export SRCDEST="$work/sources" PKGDEST="$work/packages"
# --holdver keeps the pinned local Git cache offline; never use --syncdeps.
# These source-only packages need no host DKMS installation to be assembled.
for project in isgx-dkms transport-dkms; do
    printf 'PACKAGE_BUILD: %s; log=%s/%s.log\n' "$project" "$work" "$project"
    if makepkg -D "$work/$project" --holdver --nodeps --noconfirm --nocolor \
            >"$work/$project.log" 2>&1; then
        printf 'PACKAGE_BUILT: %s\n' "$project"
    else
        code=$?
        printf 'PACKAGE_BUILD_FAILED: %s; exit=%s; log=%s/%s.log\n' "$project" "$code" "$work" "$project" >&2
        exit "$code"
    fi
done
printf 'PACKAGE_BUILD_PASS: %s/packages; no system installation performed\n' "$work"
