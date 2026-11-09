#!/usr/bin/env bash
# Fetch official OEM inputs and build packages; no installation or hardware access.
set -euo pipefail
if (( $# != 2 )); then
    printf 'Usage: %s NEW_OUTPUT_DIR ISGX_GIT\n' "$0" >&2
    exit 2
fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(realpath -m -- "$1")
isgx=$(realpath -- "$2")
command -v makepkg git cc rustc cargo python3 7zz >/dev/null
umask 077
mkdir -m 700 -- "$work"
mkdir -- "$work/packages" "$work/engine" "$work/oem"
python3 -I -B "$repo/tools/prepare-oem.py" "$work/vendor"
tar -cf "$work/oem/oem-assets.tar" -C "$work/vendor" assets licenses
# Snapshot only the self-contained crate, excluding build output.
crate="$repo/userspace/engine"
mkdir -- "$work/goodix-milanl" "$work/goodix-milanl/.cargo"
cp -R -- "$crate/Cargo.toml" "$crate/Cargo.lock" "$crate/README.md" \
    "$crate/src" "$crate/tests" "$work/goodix-milanl/"
# Dependencies must already be cached. The package then builds offline with an
# empty CARGO_HOME; no registry cache or repository path is needed by makepkg.
cargo vendor --offline --locked --versioned-dirs --manifest-path "$crate/Cargo.toml" \
    "$work/goodix-milanl/vendor" > /dev/null
printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "vendor"\n' \
    > "$work/goodix-milanl/.cargo/config.toml"
tar -cf "$work/engine/runtime.tar" -C "$work" goodix-milanl
commit=eea00a3f79bd1266adc7f4072c52a7a717b9e37e
git -C "$isgx" show "$commit:License.txt" > "$work/engine/isgx-License.txt"
cp -- "$repo/packaging/systemd/goodix-milanl-engine.service" \
    "$repo/packaging/systemd/fprintd.service.d/50-goodix-milanl.conf" "$work/engine/"
cp -- "$repo/packaging/secure-boot.sh" \
    "$repo/packaging/selinux/goodix_milanl.te" "$repo/packaging/selinux/goodix_milanl.fc" \
    "$work/engine/"
cp -- "$repo/packaging/selinux/install.sh" "$work/engine/install-selinux.sh"
export PKGDEST="$work/packages"
for project in oem engine; do
    cp -- "$repo/packaging/arch/$project/PKGBUILD" \
        "$repo/packaging/LICENSE-NOTICE" "$work/$project/"
    # Every source is local; makepkg pins the exact staged snapshot before building.
    SRCDEST="$work/$project" makepkg -D "$work/$project" --geninteg \
        >> "$work/$project/PKGBUILD"
    printf 'PACKAGE_BUILD: %s; log=%s/%s.log\n' "$project" "$work" "$project"
    if SRCDEST="$work/$project" makepkg -D "$work/$project" --nodeps --noconfirm --nocolor \
            >"$work/$project.log" 2>&1; then
        printf 'PACKAGE_BUILT: %s\n' "$project"
    else
        code=$?
        printf 'PACKAGE_BUILD_FAILED: %s; exit=%s; log=%s/%s.log\n' \
            "$project" "$code" "$work" "$project" >&2
        exit "$code"
    fi
done
printf 'PACKAGE_BUILD_PASS: %s/packages; local only; no system installation performed\n' "$work"
