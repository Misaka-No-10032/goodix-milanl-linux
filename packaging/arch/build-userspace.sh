#!/usr/bin/env bash
# Build local replacement packages without downloading, installing or enabling anything.
set -euo pipefail
if (( $# != 3 )); then
    printf 'Usage: %s NEW_OUTPUT_DIR LIBFPRINT_GIT FPRINTD_GIT\n' "$0" >&2
    exit 2
fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(realpath -m -- "$1")
libfprint_git=$(realpath -- "$2")
fprintd_git=$(realpath -- "$3")
command -v makepkg git "${MESON:-meson}" >/dev/null
# Refuse to reuse an output directory: no removal of older packages or source trees.
mkdir -m 700 -- "$work"
mkdir -- "$work/sources" "$work/packages" "$work/libfprint" "$work/fprintd"
for project in libfprint fprintd; do
    source_tree=$libfprint_git
    if [[ $project == fprintd ]]; then source_tree=$fprintd_git; fi
    git clone --mirror -- "$source_tree" "$work/sources/$project"
    git -C "$work/sources/$project" remote set-url origin \
        "https://gitlab.freedesktop.org/libfprint/$project.git"
    cp -- "$repo/packaging/arch/$project/PKGBUILD" "$work/$project/"
done
cp -- "$repo/userspace/libfprint/0001-register-goodix_milanl-driver.patch" \
    "$repo/userspace/libfprint/goodix_milanl.c" "$repo/userspace/libfprint/goodix_milanl_proto.h" "$work/libfprint/"
cp -- "$repo/userspace/fprintd/0001-persist-matched-prints.patch" "$work/fprintd/"
cp -- "$repo/LICENSE" "$work/libfprint/LICENSE.goodix-milanl"
export SRCDEST="$work/sources" PKGDEST="$work/packages"
# --holdver keeps the pinned, locally cached VCS sources offline.
# --nodeps is intentional: the patched libfprint is staged, never host-installed.
# Build tools/headers must already be available; this script never uses --syncdeps.
for project in libfprint fprintd; do
    if [[ $project == fprintd ]]; then
        export PKG_CONFIG_PATH="$work/libfprint/src/build/meson-uninstalled${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    fi
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
