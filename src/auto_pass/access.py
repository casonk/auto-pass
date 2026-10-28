"""Check that this login can use every configured KeePass vault.

A vault can stop being readable without anything being wrong with auto-pass:
a sync tool that runs as another account rewrites the file, and the new file
is owned by that account with no access for the login. Every consumer then
fails with "not readable", which looks like a bad password or a locked vault.
This turns that into a named, actionable finding.
"""

from __future__ import annotations

import getpass
import os
import re
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

_PROFILE_PATH_RE = re.compile(r"^AUTO_PASS_PROFILE_([A-Z0-9_]+)_KEEPASSXC_DB_PATH$")
_DEFAULT_PATH_VAR = "AUTO_PASS_KEEPASSXC_DB_PATH"


@dataclass(frozen=True)
class AccessFinding:
    label: str
    path: Path
    problem: str
    hint: str

    def as_dict(self) -> dict[str, str]:
        return {
            "vault": self.label,
            "path": str(self.path),
            "problem": self.problem,
            "hint": self.hint,
        }


def vault_paths(environ: Mapping[str, str] | None = None) -> dict[str, Path]:
    """Map each configured vault label to its database path."""
    env = os.environ if environ is None else environ
    found: dict[str, Path] = {}
    for key, value in env.items():
        text = str(value).strip()
        match = _PROFILE_PATH_RE.match(key)
        if match and text:
            found[match.group(1).lower()] = Path(text).expanduser()
    default = str(env.get(_DEFAULT_PATH_VAR, "")).strip()
    if default and Path(default).expanduser() not in found.values():
        found["default"] = Path(default).expanduser()
    return dict(sorted(found.items()))


def _owner(path: Path) -> str | None:
    try:
        import pwd

        return pwd.getpwuid(path.stat().st_uid).pw_name
    except (ImportError, KeyError, OSError):
        return None


def _hint(path: Path, login: str, problem: str) -> str:
    if problem == "missing":
        return "check the path, or that the volume holding it is mounted"
    owner = _owner(path)
    if owner == login:
        return f"chmod u+rw {path}"
    return f"sudo setfacl -m u:{login}:rw {path}"


def check_vaults(paths: Mapping[str, Path], *, login: str | None = None) -> list[AccessFinding]:
    """Return one finding per vault this login cannot read and write."""
    who = login or getpass.getuser()
    findings: list[AccessFinding] = []
    for label, path in paths.items():
        if not path.exists():
            problem = "missing"
        elif not os.access(path, os.R_OK):
            problem = "unreadable"
        elif not os.access(path, os.W_OK):
            problem = "read-only"
        else:
            continue
        findings.append(AccessFinding(label, path, problem, _hint(path, who, problem)))
    return findings


def default_acl_missing(directory: Path, login: str) -> bool:
    """True when a directory we own lacks a default ACL entry for this login.

    New files created there by another account inherit the directory's default
    ACL, so this entry is what keeps a later rewrite readable.
    """
    getfacl = shutil.which("getfacl")
    if not getfacl or _owner(directory) != login:
        return False
    result = subprocess.run(  # noqa: S603
        [getfacl, "-p", str(directory)], capture_output=True, text=True, check=False
    )
    return result.returncode == 0 and f"default:user:{login}:" not in result.stdout


def fix_default_acl(directory: Path, login: str) -> bool:
    """Add the default ACL entry for this login on a directory we own."""
    setfacl = shutil.which("setfacl")
    if not setfacl or _owner(directory) != login:
        return False
    result = subprocess.run(  # noqa: S603
        [setfacl, "-d", "-m", f"u:{login}:rwx", str(directory)],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0
