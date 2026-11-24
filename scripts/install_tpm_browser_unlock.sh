#!/usr/bin/env bash
# Install the TPM-sealed PIN gate and Auto Pass web bootstrap as system services.
set -euo pipefail

DRY_RUN=0
WEB_TOKEN_DB=infra
AUTO_PASS_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WIRING_ROOT=$(cd "$AUTO_PASS_ROOT/../wiring-harness" 2>/dev/null && pwd || true)
SERVICE_USER=$(id -un)
SERVICE_UID=$(id -u)
SERVICE_HOME=${HOME:?HOME is required}
AUTO_PASS_BIN=$(command -v auto-pass || true)

usage() {
  cat <<'EOF'
Usage: bash scripts/install_tpm_browser_unlock.sh [options]

Options:
  --dry-run              Validate and print the privileged actions only.
  --web-token-db ALIAS   Vault holding auto-pass/web-token (default: infra).
  --wiring-root PATH     wiring-harness checkout (default: sibling checkout).
  --auto-pass-bin PATH   Installed auto-pass executable.

Run this as the service user, not root. The script invokes /usr/bin/sudo only
for the credential, /etc, and system-service operations that require it.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --web-token-db) WEB_TOKEN_DB="${2:?--web-token-db needs a value}"; shift ;;
    --wiring-root) WIRING_ROOT="${2:?--wiring-root needs a value}"; shift ;;
    --auto-pass-bin) AUTO_PASS_BIN="${2:?--auto-pass-bin needs a value}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

[[ $EUID -ne 0 ]] || { echo "error: run as the service user, not root" >&2; exit 1; }
[[ -n "$AUTO_PASS_BIN" && -x "$AUTO_PASS_BIN" ]] || { echo "error: auto-pass executable not found" >&2; exit 1; }
[[ -d "$WIRING_ROOT" ]] || { echo "error: wiring-harness checkout not found: $WIRING_ROOT" >&2; exit 1; }
for path in \
  "$AUTO_PASS_ROOT/scripts/seal_web_token.sh" \
  "$AUTO_PASS_ROOT/config/systemd/auto-pass-web.system.service.example" \
  "$WIRING_ROOT/scripts/seal_pin_key.sh" \
  "$WIRING_ROOT/config/systemd/wiring-harness-pin-gate.system.service.example"; do
  [[ -f "$path" ]] || { echo "error: required file not found: $path" >&2; exit 1; }
done
for command in /usr/bin/bash /usr/bin/curl /usr/bin/grep /usr/bin/sed /usr/bin/sleep /usr/bin/sudo /usr/bin/systemctl /usr/bin/systemd-analyze; do
  [[ -x "$command" ]] || { echo "error: required command not found: $command" >&2; exit 1; }
done

export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$SERVICE_UID}
export DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}
/usr/bin/systemctl --user is-active --quiet auto-pass-serve.service || {
  echo "error: auto-pass-serve.service is not running" >&2
  exit 1
}
daemon_status=$($AUTO_PASS_BIN --no-env-file daemon-status)
[[ "$daemon_status" == *"locked: False"* ]] || {
  echo "error: unlock the daemon with 'auto-pass unlock' before installing" >&2
  exit 1
}

tmpdir=$(mktemp -d)
success=0
cutover_started=0
auto_user_active=0
pin_user_active=0
auto_user_enabled=0
pin_user_enabled=0
auto_system_existed=0
pin_system_existed=0
auto_system_active=0
pin_system_active=0
auto_system_enabled=0
pin_system_enabled=0

cleanup() {
  local rc=$?
  if [[ $success -ne 1 && $DRY_RUN -ne 1 && $cutover_started -eq 1 ]]; then
    echo "cutover failed; restoring the previous service state" >&2
    /usr/bin/sudo /usr/bin/systemctl disable --now auto-pass-web.service wiring-harness-pin-gate.service >/dev/null 2>&1 || true
    if [[ $auto_system_existed -eq 1 ]]; then
      /usr/bin/sudo install -m 0644 "$tmpdir/auto-pass-web.service.old" /etc/systemd/system/auto-pass-web.service
    else
      /usr/bin/sudo rm -f /etc/systemd/system/auto-pass-web.service
    fi
    if [[ $pin_system_existed -eq 1 ]]; then
      /usr/bin/sudo install -m 0644 "$tmpdir/wiring-harness-pin-gate.service.old" /etc/systemd/system/wiring-harness-pin-gate.service
    else
      /usr/bin/sudo rm -f /etc/systemd/system/wiring-harness-pin-gate.service
    fi
    /usr/bin/sudo /usr/bin/systemctl daemon-reload || true
    [[ $auto_system_enabled -eq 1 ]] && /usr/bin/sudo /usr/bin/systemctl enable auto-pass-web.service >/dev/null 2>&1 || true
    [[ $pin_system_enabled -eq 1 ]] && /usr/bin/sudo /usr/bin/systemctl enable wiring-harness-pin-gate.service >/dev/null 2>&1 || true
    [[ $auto_system_active -eq 1 ]] && /usr/bin/sudo /usr/bin/systemctl start auto-pass-web.service || true
    [[ $pin_system_active -eq 1 ]] && /usr/bin/sudo /usr/bin/systemctl start wiring-harness-pin-gate.service || true
    [[ $auto_user_enabled -eq 1 ]] && /usr/bin/systemctl --user enable auto-pass-web.service >/dev/null 2>&1 || true
    [[ $pin_user_enabled -eq 1 ]] && /usr/bin/systemctl --user enable wiring-harness-pin-gate.service >/dev/null 2>&1 || true
    [[ $auto_user_active -eq 1 ]] && /usr/bin/systemctl --user start auto-pass-web.service || true
    [[ $pin_user_active -eq 1 ]] && /usr/bin/systemctl --user start wiring-harness-pin-gate.service || true
  fi
  rm -rf "$tmpdir"
  return "$rc"
}
trap cleanup EXIT

wait_for_http() {
  local label=$1
  shift
  local attempt
  for ((attempt = 1; attempt <= 30; attempt++)); do
    if /usr/bin/curl --silent --fail "$@" >/dev/null 2>&1; then
      return 0
    fi
    /usr/bin/sleep 1
  done
  echo "error: $label did not become ready within 30 seconds" >&2
  /usr/bin/curl --silent --show-error --fail "$@" >/dev/null
}

sed_escape() { printf '%s' "$1" | /usr/bin/sed 's/[&|]/\\&/g'; }
auto_parent=$(sed_escape "$(dirname "$AUTO_PASS_ROOT")")
wiring_parent=$(sed_escape "$(dirname "$WIRING_ROOT")")
user_escaped=$(sed_escape "$SERVICE_USER")
home_escaped=$(sed_escape "$SERVICE_HOME")

/usr/bin/sed \
  -e "s|<user>|$user_escaped|g" \
  -e "s|<home>|$home_escaped|g" \
  -e "s|<path-to>|$auto_parent|g" \
  "$AUTO_PASS_ROOT/config/systemd/auto-pass-web.system.service.example" \
  > "$tmpdir/auto-pass-web.service"
/usr/bin/sed \
  -e "s|<user>|$user_escaped|g" \
  -e "s|<home>|$home_escaped|g" \
  -e "s|<path-to>|$wiring_parent|g" \
  "$WIRING_ROOT/config/systemd/wiring-harness-pin-gate.system.service.example" \
  > "$tmpdir/wiring-harness-pin-gate.service"
if /usr/bin/grep -R -nE '<[^>]+>' "$tmpdir" >/dev/null; then
  echo "error: an unsubstituted unit placeholder remains" >&2
  exit 1
fi
/usr/bin/systemd-analyze verify \
  "$tmpdir/auto-pass-web.service" "$tmpdir/wiring-harness-pin-gate.service"

# A system unit does not inherit the user's PATH; the PIN gate runs `auto-pass`, so the PATH the unit
# sets must resolve it. Checked before anything is installed so a bad unit never replaces a working one.
unit_path=$(/usr/bin/sed -n 's/^Environment=PATH=//p' "$tmpdir/wiring-harness-pin-gate.service" | /usr/bin/head -n 1)
if [[ -z "$unit_path" ]]; then
  echo "error: the PIN gate unit sets no PATH, so it cannot run auto-pass" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$unit_path" /usr/bin/bash -c 'command -v auto-pass' >/dev/null; then
  echo "error: auto-pass is not found on the PIN gate unit's PATH ($unit_path)" >&2
  exit 1
fi

if [[ $DRY_RUN -eq 1 ]]; then
  echo "dry run: would seal the PIN key and Auto Pass web token to TPM2 PCR 7"
  echo "dry run: would install and enable system auto-pass-web.service and wiring-harness-pin-gate.service"
  echo "dry run: would disable the two same-named user services after recording their state"
  echo "dry run: the PIN gate unit's PATH resolves auto-pass"
  echo "dry run: would verify the Auto Pass login page and PIN keypad over loopback"
  success=1
  exit 0
fi

/usr/bin/sudo -v
if [[ ! -e /etc/credstore.encrypted/wiring-harness-pin-seal-key ]]; then
  /usr/bin/sudo /usr/bin/bash "$WIRING_ROOT/scripts/seal_pin_key.sh"
fi
if [[ ! -e /etc/credstore.encrypted/auto-pass-web-token ]]; then
  /usr/bin/sudo /usr/bin/bash "$AUTO_PASS_ROOT/scripts/seal_web_token.sh" \
    --user "$SERVICE_USER" --db "$WEB_TOKEN_DB" --auto-pass-bin "$AUTO_PASS_BIN"
fi

/usr/bin/systemctl --user is-active --quiet auto-pass-web.service && auto_user_active=1 || true
/usr/bin/systemctl --user is-active --quiet wiring-harness-pin-gate.service && pin_user_active=1 || true
/usr/bin/systemctl --user is-enabled --quiet auto-pass-web.service && auto_user_enabled=1 || true
/usr/bin/systemctl --user is-enabled --quiet wiring-harness-pin-gate.service && pin_user_enabled=1 || true
if /usr/bin/sudo test -e /etc/systemd/system/auto-pass-web.service; then
  auto_system_existed=1
  /usr/bin/sudo /usr/bin/systemctl is-active --quiet auto-pass-web.service && auto_system_active=1 || true
  /usr/bin/sudo /usr/bin/systemctl is-enabled --quiet auto-pass-web.service && auto_system_enabled=1 || true
  /usr/bin/sudo cp /etc/systemd/system/auto-pass-web.service "$tmpdir/auto-pass-web.service.old"
  /usr/bin/sudo chown "$SERVICE_UID" "$tmpdir/auto-pass-web.service.old"
fi
if /usr/bin/sudo test -e /etc/systemd/system/wiring-harness-pin-gate.service; then
  pin_system_existed=1
  /usr/bin/sudo /usr/bin/systemctl is-active --quiet wiring-harness-pin-gate.service && pin_system_active=1 || true
  /usr/bin/sudo /usr/bin/systemctl is-enabled --quiet wiring-harness-pin-gate.service && pin_system_enabled=1 || true
  /usr/bin/sudo cp /etc/systemd/system/wiring-harness-pin-gate.service "$tmpdir/wiring-harness-pin-gate.service.old"
  /usr/bin/sudo chown "$SERVICE_UID" "$tmpdir/wiring-harness-pin-gate.service.old"
fi

cutover_started=1
/usr/bin/sudo install -m 0644 "$tmpdir/auto-pass-web.service" /etc/systemd/system/auto-pass-web.service
/usr/bin/sudo install -m 0644 "$tmpdir/wiring-harness-pin-gate.service" /etc/systemd/system/wiring-harness-pin-gate.service
/usr/bin/sudo /usr/bin/systemctl daemon-reload
/usr/bin/systemctl --user disable --now auto-pass-web.service wiring-harness-pin-gate.service
/usr/bin/sudo /usr/bin/systemctl enable --now auto-pass-web.service wiring-harness-pin-gate.service
/usr/bin/sudo /usr/bin/systemctl is-active --quiet auto-pass-web.service wiring-harness-pin-gate.service
wait_for_http "Auto Pass web UI" http://127.0.0.1:8081/login
wait_for_http "wiring-harness PIN gate" \
  -H 'X-Pin-Site: clockwork-web' http://127.0.0.1:8781/_pin/unlock >/dev/null

success=1
echo "TPM browser unlock installed and verified"
echo "next: reboot once, leave auto-pass locked, and prove the Auto Pass keypad and /daemon unlock page work"
