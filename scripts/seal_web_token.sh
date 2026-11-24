#!/usr/bin/env bash
# Seal the existing KeePass-backed web login token to TPM2 PCR 7.
# The plaintext travels only through a pipe from the unlocked auto-pass daemon
# to systemd-creds and is never written or printed.
set -euo pipefail

OUTPUT=/etc/credstore.encrypted/auto-pass-web-token
NAME=auto-pass-web-token
ENTRY=auto-pass/web-token
DB=
SERVICE_USER=${SUDO_USER:-}
AUTO_PASS_BIN=
FORCE=0
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

usage() {
  cat <<'EOF'
Usage: sudo bash scripts/seal_web_token.sh --user USER [options]

Options:
  --db ALIAS          Vault alias containing auto-pass/web-token.
  --entry PATH        Alternate token entry (default: auto-pass/web-token).
  --auto-pass-bin P   Installed auto-pass executable (default: USER_HOME/.local/bin/auto-pass).
  --output FILE       Encrypted credential output path.
  --force             Replace an existing encrypted credential.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) SERVICE_USER="${2:?--user needs a value}"; shift ;;
    --db) DB="${2:?--db needs a value}"; shift ;;
    --entry) ENTRY="${2:?--entry needs a value}"; shift ;;
    --auto-pass-bin) AUTO_PASS_BIN="${2:?--auto-pass-bin needs a value}"; shift ;;
    --output) OUTPUT="${2:?--output needs a value}"; shift ;;
    --force) FORCE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

[[ $EUID -eq 0 ]] || { echo "error: run with sudo" >&2; exit 1; }
[[ -n "$SERVICE_USER" ]] || { echo "error: --user is required" >&2; exit 2; }
command -v systemd-creds >/dev/null || { echo "error: systemd-creds not found" >&2; exit 1; }
command -v runuser >/dev/null || { echo "error: runuser not found" >&2; exit 1; }

SERVICE_HOME=$(getent passwd "$SERVICE_USER" | cut -d: -f6)
[[ -n "$SERVICE_HOME" ]] || { echo "error: user not found: $SERVICE_USER" >&2; exit 1; }
AUTO_PASS_BIN=${AUTO_PASS_BIN:-$SERVICE_HOME/.local/bin/auto-pass}
[[ -x "$AUTO_PASS_BIN" ]] || { echo "error: auto-pass executable not found: $AUTO_PASS_BIN" >&2; exit 1; }

if [[ -e "$OUTPUT" && $FORCE -ne 1 ]]; then
  echo "error: $OUTPUT exists; use --force to replace it" >&2
  exit 1
fi

install -d -m 0755 "$(dirname "$OUTPUT")"
tmp=$(mktemp "$(dirname "$OUTPUT")/.auto-pass-web-token.XXXXXX")
trap 'rm -f "$tmp"' EXIT

get_token=(runuser -u "$SERVICE_USER" -- env HOME="$SERVICE_HOME" "$AUTO_PASS_BIN" --no-env-file provision-get "$ENTRY")
if [[ -n "$DB" ]]; then
  get_token+=(--db "$DB")
fi

cd "$REPO_ROOT"
"${get_token[@]}" | systemd-creds encrypt --with-key=tpm2 --tpm2-pcrs=7 --name="$NAME" - "$tmp"
chmod 0600 "$tmp"

size=$(systemd-creds decrypt --name="$NAME" "$tmp" - | wc -c)
if [[ "$size" -le 1 ]]; then
  echo "error: sealed credential decrypted empty; nothing installed" >&2
  exit 1
fi

mv -f "$tmp" "$OUTPUT"
trap - EXIT
echo "sealed Auto Pass web credential installed: $OUTPUT (TPM2 PCR 7)"
