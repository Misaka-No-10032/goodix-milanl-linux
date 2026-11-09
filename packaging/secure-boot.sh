#!/usr/bin/env bash
set -euo pipefail
usage() {
    printf 'Usage: goodix-milanl-secure-boot {check|prepare|enroll}\n'
}
if (( $# != 1 )); then usage >&2; exit 2; fi
case "$1" in
    -h|--help) usage; exit 0 ;;
    check|prepare|enroll) action=$1 ;;
    *) usage >&2; exit 2 ;;
esac
kernelver=$(uname -r)
mok_signing_key=/var/lib/dkms/mok.key
mok_certificate=/var/lib/dkms/mok.pub
try_sign_modules=not_in_chroot
# Use the administrator's DKMS configuration and the same override order as DKMS.
for config in /etc/dkms/framework.conf /etc/dkms/framework.conf.d/*.conf; do
    if [[ -f "$config" ]]; then source "$config"; fi
done
if [[ "$try_sign_modules" == false ]]; then
    printf 'DKMS module signing is disabled in framework.conf. Enable it before proceeding.\n' >&2
    exit 1
fi
case "$action" in
    prepare)
        if (( EUID != 0 )); then printf 'Run prepare as root.\n' >&2; exit 1; fi
        if [[ "$mok_signing_key" != pkcs11:* ]] &&
           { { [[ -e "$mok_signing_key" ]] && [[ ! -e "$mok_certificate" ]]; } ||
             { [[ ! -e "$mok_signing_key" ]] && [[ -e "$mok_certificate" ]]; }; }; then
            printf 'Incomplete DKMS key/certificate pair; preserving the existing file.\n' >&2
            exit 1
        fi
        umask 077
        dkms generate_mok
        printf 'DKMS signing uses %s; public certificate: %s\n' "$mok_signing_key" "$mok_certificate"
        printf 'Next: enroll the certificate, then rebuild/install the two project DKMS modules.\n'
        ;;
    enroll)
        if (( EUID != 0 )); then printf 'Run enroll as root.\n' >&2; exit 1; fi
        if [[ ! -f "$mok_certificate" ]]; then
            printf 'Run prepare first; certificate missing: %s\n' "$mok_certificate" >&2
            exit 1
        fi
        if ! compgen -G '/sys/firmware/efi/efivars/MokListRT-*' >/dev/null; then
            printf 'The running boot chain exposes no shim MOK list. Use its existing module-signing trust setup; this command does not install shim or alter firmware keys.\n' >&2
            exit 1
        fi
        if mokutil --test-key "$mok_certificate"; then exit 0; fi
        mokutil --import "$mok_certificate"
        printf 'Enrollment queued. Reboot through shim and confirm this certificate in MOK Manager.\n'
        ;;
    check)
        if [[ ! -f "$mok_certificate" ]]; then
            printf 'DKMS certificate missing: %s; run prepare.\n' "$mok_certificate" >&2
            exit 1
        fi
        if ! mokutil --test-key "$mok_certificate"; then
            printf 'The configured DKMS certificate is not enrolled in MOK.\n' >&2
            exit 1
        fi
        # kmod reports the PKCS#7 signer's certificate serial in sig_key.
        certificate_id=$(openssl x509 -inform DER -in "$mok_certificate" -noout -serial)
        certificate_id=${certificate_id#serial=}
        certificate_id=${certificate_id//[[:space:]:]/}
        certificate_id=${certificate_id^^}
        if [[ ! "$certificate_id" =~ ^[0-9A-F]+$ ]]; then
            printf 'DKMS certificate has no usable serial number.\n' >&2
            exit 1
        fi
        for module in isgx goodix_milanl_transport; do
            module_id=$(modinfo -k "$kernelver" -F sig_key "$module")
            module_id=${module_id//[[:space:]:]/}
            if [[ "${module_id^^}" != "$certificate_id" ]]; then
                printf '%s: not signed with the enrolled DKMS key; rebuild/install this DKMS module for %s.\n' "$module" "$kernelver" >&2
                exit 1
            fi
            printf '%s: signed with the enrolled DKMS key\n' "$module"
        done
        ;;
esac
