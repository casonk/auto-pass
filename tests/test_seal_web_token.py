from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "seal_web_token.sh"

FAKE_RUNUSER = """#!/usr/bin/env bash
echo "$@" >> "$FAKE_RUNUSER_LOG"
printf 'token-value\\n'
"""

FAKE_SYSTEMD_CREDS = """#!/usr/bin/env bash
echo "$@" >> "$FAKE_CREDS_LOG"
case "$1" in
  encrypt) cat > /dev/null; printf 'SEALED' > "${@: -1}" ;;
  decrypt) [[ "${FAKE_EMPTY:-0}" == 1 ]] || printf 'recovered-token\\n' ;;
esac
"""

FAKE_GETENT = """#!/usr/bin/env bash
printf 'tester:x:1000:1000::%s:/bin/bash\\n' "$FAKE_HOME"
"""


def _write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def _fixture(tmp_path: Path) -> tuple[Path, dict[str, str], Path, Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(parents=True)
    runuser_log = tmp_path / "runuser.log"
    creds_log = tmp_path / "creds.log"
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    auto_pass = fake_home / "auto-pass"
    _write_executable(auto_pass, "#!/usr/bin/env bash\nexit 0\n")
    _write_executable(fake_bin / "runuser", FAKE_RUNUSER)
    _write_executable(fake_bin / "systemd-creds", FAKE_SYSTEMD_CREDS)
    _write_executable(fake_bin / "getent", FAKE_GETENT)

    script = tmp_path / "seal.sh"
    script.write_text(
        SCRIPT.read_text(encoding="utf-8").replace("[[ $EUID -eq 0 ]] ||", "[[ 1 -eq 1 ]] ||"),
        encoding="utf-8",
    )
    output = tmp_path / "creds" / "web-token"
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "FAKE_RUNUSER_LOG": str(runuser_log),
        "FAKE_CREDS_LOG": str(creds_log),
        "FAKE_HOME": str(fake_home),
    }
    return script, env, output, auto_pass


def _run(tmp_path: Path, *extra: str, empty: bool = False) -> subprocess.CompletedProcess[str]:
    script, env, output, auto_pass = _fixture(tmp_path)
    if empty:
        env["FAKE_EMPTY"] = "1"
    return subprocess.run(
        [
            "bash",
            str(script),
            "--user",
            "tester",
            "--db",
            "infra",
            "--auto-pass-bin",
            str(auto_pass),
            "--output",
            str(output),
            *extra,
        ],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )


def test_script_syntax_is_valid() -> None:
    assert subprocess.run(["bash", "-n", str(SCRIPT)], check=False).returncode == 0


def test_seals_the_daemon_token_without_printing_it(tmp_path: Path) -> None:
    result = _run(tmp_path)
    output = tmp_path / "creds" / "web-token"
    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="utf-8") == "SEALED"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert "token-value" not in result.stdout + result.stderr
    assert "provision-get auto-pass/web-token --db infra" in (tmp_path / "runuser.log").read_text()
    creds = (tmp_path / "creds.log").read_text()
    assert "--with-key=tpm2" in creds
    assert "--tpm2-pcrs=7" in creds
    assert "--name=auto-pass-web-token" in creds


def test_refuses_to_replace_an_existing_credential_without_force(tmp_path: Path) -> None:
    assert _run(tmp_path).returncode == 0
    output = tmp_path / "creds" / "web-token"
    output.write_text("original", encoding="utf-8")
    script, env, _, auto_pass = _fixture(tmp_path / "again")
    result = subprocess.run(
        [
            "bash",
            str(script),
            "--user",
            "tester",
            "--auto-pass-bin",
            str(auto_pass),
            "--output",
            str(output),
        ],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    assert result.returncode == 1
    assert output.read_text(encoding="utf-8") == "original"


def test_installs_nothing_when_the_credential_decrypts_empty(tmp_path: Path) -> None:
    result = _run(tmp_path, empty=True)
    assert result.returncode == 1
    assert not (tmp_path / "creds" / "web-token").exists()
