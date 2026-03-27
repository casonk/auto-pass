from __future__ import annotations

import os
import re
import shlex
from pathlib import Path
from typing import Mapping, MutableMapping


DEFAULT_ENV_FILE = Path("config/auto-pass.env.local")
_ASSIGNMENT_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
_PROFILE_ENV_MAP = {
    "KEEPASSXC_DB_PATH": "AUTO_PASS_KEEPASSXC_DB_PATH",
    "KEEPASSXC_DB_PASSWORD": "AUTO_PASS_KEEPASSXC_DB_PASSWORD",
    "KEEPASSXC_KEY_FILE": "AUTO_PASS_KEEPASSXC_KEY_FILE",
}


class EnvFileError(RuntimeError):
    """Raised when the local env file is malformed."""


def normalize_profile_name(value: str) -> str:
    text = str(value or "").strip().upper()
    text = re.sub(r"[^A-Z0-9]+", "_", text)
    return text.strip("_")


def parse_env_text(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ASSIGNMENT_RE.match(stripped)
        if not match:
            raise EnvFileError(f"Invalid env assignment at line {lineno}: {raw_line!r}")
        key = match.group(1)
        raw_value = match.group(2).strip()
        if not raw_value:
            values[key] = ""
            continue
        try:
            tokens = shlex.split(raw_value, posix=True)
        except ValueError as exc:
            raise EnvFileError(
                f"Invalid env value at line {lineno} for {key}: {exc}"
            ) from exc
        values[key] = tokens[0] if len(tokens) == 1 else " ".join(tokens)
    return values


def load_env_file(
    path: str | Path = DEFAULT_ENV_FILE,
    *,
    override: bool = False,
    environ: MutableMapping[str, str] | None = None,
) -> dict[str, str]:
    env = os.environ if environ is None else environ
    env_path = Path(path)
    if not env_path.exists():
        return {}
    loaded = parse_env_text(env_path.read_text(encoding="utf-8"))
    for key, value in loaded.items():
        if override or not str(env.get(key, "")).strip():
            env[key] = value
    return loaded


def apply_keepass_profile_environment(
    environ: MutableMapping[str, str] | None = None,
    *,
    override: bool = False,
) -> dict[str, str]:
    env = os.environ if environ is None else environ
    active_profile = normalize_profile_name(env.get("AUTO_PASS_PROFILE", ""))
    if not active_profile:
        return {}

    applied: dict[str, str] = {}
    for suffix, target_name in _PROFILE_ENV_MAP.items():
        source_name = f"AUTO_PASS_PROFILE_{active_profile}_{suffix}"
        value = str(env.get(source_name, "")).strip()
        if not value:
            continue
        if override or not str(env.get(target_name, "")).strip():
            env[target_name] = value
            applied[target_name] = value
    return applied


def load_config_environment(
    path: str | Path = DEFAULT_ENV_FILE,
    *,
    override: bool = False,
    environ: MutableMapping[str, str] | None = None,
) -> tuple[dict[str, str], dict[str, str]]:
    env = os.environ if environ is None else environ
    loaded = load_env_file(path, override=override, environ=env)
    applied = apply_keepass_profile_environment(env, override=override)
    return loaded, applied

