#!/bin/sh
set -eu

usage() {
    printf '%s\n' "Usage: $0 --install" \
        'Build and install goodix_milanl for the active SELinux reference policy.' \
        'Requires policy headers, make, m4, gawk, checkpolicy, semodule-utils and policycoreutils.' \
        'On Arch, use selinux-refpolicy-arch with SELinux-enabled systemd/udev.' \
        'Run as root with goodix-milanl-engine.service stopped. No services are started.'
}

case "${1:-}" in
    --help|-h) usage; exit 0 ;;
    --install) [ "$#" -eq 1 ] || { usage >&2; exit 2; } ;;
    *) usage >&2; exit 2 ;;
esac

[ "$(id -u)" -eq 0 ] || { printf '%s\n' 'Run --install as root.' >&2; exit 1; }
selinuxenabled || { printf '%s\n' 'SELinux must already be enabled.' >&2; exit 1; }
grep -qx 1 /sys/fs/selinux/policy_capabilities/nnp_nosuid_transition || {
    printf '%s\n' 'The active policy must support nnp_nosuid_transition.' >&2
    exit 1
}
if systemctl is-active --quiet goodix-milanl-engine.service; then
    printf '%s\n' 'Stop goodix-milanl-engine.service before installing its policy.' >&2
    exit 1
fi

name=$(LC_ALL=C sestatus | awk '/^Loaded policy name:/ {print $4}')
headers=/usr/share/selinux/$name/include
[ -r "$headers/Makefile" ] || { printf 'Missing reference-policy headers: %s\n' "$headers" >&2; exit 1; }
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
umask 077
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$source_dir/goodix_milanl.te" "$source_dir/goodix_milanl.fc" "$work/"
make -C "$work" -f "$headers/Makefile" NAME="$name" goodix_milanl.pp
semodule -i "$work/goodix_milanl.pp"
restorecon -R /usr/bin/goodix-milanl-engine /usr/lib/goodix-milanl/oem
for path in /run/goodix-milanl /var/lib/goodix-milanl /dev/goodix-milanl-raw /dev/isgx; do
    if [ -e "$path" ]; then
        restorecon -R "$path"
    fi
done
printf '%s\n' 'Installed goodix_milanl policy and labels; no services were started.'
