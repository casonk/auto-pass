#!/usr/bin/env bash
# Create a virtualenv and install auto-pass into it.
#
# Why this exists: the previous instruction, `python3 -m pip install -e .`, is
# refused on current Debian, Ubuntu, Arch and openSUSE. Since PEP 668 those
# distros mark the system Python "externally managed", and pip declines rather
# than write into a tree the system package manager owns:
#
#     error: externally-managed-environment
#
# Fedora still permits it, which is why the old instruction appeared to work on
# some machines and not others. A virtualenv sidesteps the question entirely and
# is correct everywhere, including macOS and Windows.
#
# Usage:
#   ./bootstrap.sh                # venv + editable install, with the dev extra
#   ./bootstrap.sh --no-dev       # runtime dependencies only
#   ./bootstrap.sh --venv PATH    # somewhere other than ./.venv

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${REPO_ROOT}/.venv"
PYTHON="${PYTHON:-python3}"
WITH_DEV=1
MIN_PYTHON="3.11"

usage() {
  sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-dev) WITH_DEV=0; shift ;;
    --venv) VENV="${2:?--venv needs a path}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown option: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "error: '$PYTHON' not found. Install Python ${MIN_PYTHON}+ or set PYTHON=/path/to/python3." >&2
  exit 1
fi

# Fail on the version here rather than letting pip fail later with a wall of
# resolver output that buries the actual cause.
"$PYTHON" - "$MIN_PYTHON" <<'PY' || exit 1
import sys
minimum = tuple(int(p) for p in sys.argv[1].split("."))
if sys.version_info[:len(minimum)] < minimum:
    have = ".".join(str(p) for p in sys.version_info[:3])
    print(f"error: this project needs Python {sys.argv[1]}+, found {have}", file=sys.stderr)
    raise SystemExit(1)
PY

echo "==> creating virtualenv at ${VENV}"
"$PYTHON" -m venv "$VENV"

# Windows layout differs; support Git Bash / WSL invocations too.
VPY="${VENV}/bin/python"
[ -x "$VPY" ] || VPY="${VENV}/Scripts/python.exe"
VBIN="$(dirname "$VPY")"

echo "==> upgrading pip"
"$VPY" -m pip install --upgrade pip --quiet

if [ "$WITH_DEV" -eq 1 ]; then
  TARGET='.[dev]'
else
  TARGET='.'
fi

echo "==> installing ${TARGET} (editable)"
cd "$REPO_ROOT"
"$VPY" -m pip install -e "$TARGET"

# Installing is not the same as working: pip will happily write a console-script
# launcher for an entry point whose module does not exist. Check it runs.
echo "==> verifying the install"
"$VPY" -c "import auto_pass; print('  import auto_pass: ok')"
"${VBIN}/auto-pass" --help >/dev/null && echo "  auto-pass --help: ok"

cat <<EOF

Done. Activate the environment with:

    . ${VENV}/bin/activate

or run the command directly without activating:

    ${VBIN}/auto-pass --help

auto-pass shells out to the KeePassXC CLI, which is a separate system package.
If \`keepassxc-cli\` is not already on PATH, install it before use.
EOF
