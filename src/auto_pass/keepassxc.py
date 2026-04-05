from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path

from .notifications import (
    PasswordRetrievalNotificationError,
    maybe_notify_password_retrieval,
)

log = logging.getLogger(__name__)

ATTRIBUTE_ALIASES = {
    "title": "Title",
    "user_name": "UserName",
    "username": "UserName",
    "user": "UserName",
    "un": "UserName",
    "password": "Password",
    "pass": "Password",
    "pw": "Password",
    "url": "URL",
    "website": "URL",
    "notes": "Notes",
    "note": "Notes",
    "totp": "TOTP",
    "otp": "TOTP",
}

ENTRY_NOT_FOUND_MARKERS = (
    "not found",
    "no entry",
    "could not find",
)
GROUP_EXISTS_MARKERS = (
    "already exists",
    "group exists",
)


class KeepassCommandError(RuntimeError):
    """Raised when keepassxc-cli fails or configuration is incomplete."""


@dataclass(frozen=True)
class KeepassXCStoreConfig:
    database_path_env_names: tuple[str, ...] = (
        "AUTO_PASS_KEEPASSXC_DB_PATH",
        "PF_KEEPASSXC_DB_PATH",
    )
    database_password_env_names: tuple[str, ...] = (
        "AUTO_PASS_KEEPASSXC_DB_PASSWORD",
        "PF_KEEPASSXC_DB_PASSWORD",
    )
    database_key_file_env_names: tuple[str, ...] = (
        "AUTO_PASS_KEEPASSXC_KEY_FILE",
        "PF_KEEPASSXC_KEY_FILE",
    )
    database_path: str = ""
    database_key_file: str = ""
    database_password_cache_enabled: bool = True
    database_password_cache_ttl_seconds: int = 86400
    database_password_cache_dir: str = "~/.cache/auto-pass"
    database_password_cache_file: str = ""


@dataclass(frozen=True)
class ResolvedKeepassContext:
    db_path: str
    db_password: str
    key_file: str
    password_env_name: str
    interactive_allowed: bool


def normalize_keepass_attribute_name(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return text
    return ATTRIBUTE_ALIASES.get(text.lower(), text)


def lookup_keepass_field_case_insensitive(
    fields: Mapping[str, str],
    key_name: str,
) -> str:
    requested = str(key_name or "").strip()
    if not requested:
        return ""
    normalized = normalize_keepass_attribute_name(requested)
    for candidate in (requested, normalized):
        value = str(fields.get(candidate, "")).strip()
        if value:
            return value
    lowered = normalized.lower()
    for key, value in fields.items():
        if str(key).strip().lower() == lowered:
            text = str(value or "").strip()
            if text:
                return text
    return ""


def _resolve_env_value(names: tuple[str, ...]) -> tuple[str, str]:
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return name, value
    return names[0], ""


def _resolve_db_path(config: KeepassXCStoreConfig) -> str:
    _, db_path = _resolve_env_value(config.database_path_env_names)
    db_path = db_path or str(config.database_path).strip()
    if not db_path:
        raise KeepassCommandError(
            "KeePassXC database path is not set. Export "
            f"{config.database_path_env_names[0]} or configure database_path."
        )
    return db_path


def _resolve_key_file(config: KeepassXCStoreConfig) -> str:
    _, key_file = _resolve_env_value(config.database_key_file_env_names)
    return key_file or str(config.database_key_file).strip()


def _default_cache_path(config: KeepassXCStoreConfig, db_path: str) -> Path:
    configured = str(config.database_password_cache_file).strip()
    if configured:
        return Path(configured).expanduser()
    fingerprint = hashlib.sha256(db_path.encode("utf-8")).hexdigest()[:16]
    return (
        Path(config.database_password_cache_dir).expanduser()
        / f"keepassxc-db-password-{fingerprint}.json"
    )


def seed_keepass_password_env_for_tty(
    config: KeepassXCStoreConfig = KeepassXCStoreConfig(),
) -> None:
    password_env_name, existing_password = _resolve_env_value(config.database_password_env_names)
    if existing_password:
        return

    db_path = _resolve_db_path(config)
    cache_path = _default_cache_path(config, db_path)
    cache_ttl_seconds = max(0, int(config.database_password_cache_ttl_seconds))

    if config.database_password_cache_enabled and cache_path.exists():
        try:
            age_seconds = max(0.0, time.time() - cache_path.stat().st_mtime)
            if cache_ttl_seconds > 0 and age_seconds > float(cache_ttl_seconds):
                cache_path.unlink(missing_ok=True)
            else:
                payload = json.loads(cache_path.read_text(encoding="utf-8"))
                cached_password = str(payload.get("password", "")).strip()
                if cached_password:
                    os.environ[password_env_name] = cached_password
                    return
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pass

    if not sys.stdin.isatty():
        return

    prompt = f"KeePassXC DB password for {db_path}: "
    entered = ""
    try:
        entered = getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        return
    if not entered:
        return

    os.environ[password_env_name] = entered
    if not config.database_password_cache_enabled:
        return
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(
            json.dumps({"password": entered}, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )
        cache_path.chmod(0o600)
    except OSError:
        return


def _resolve_context(
    config: KeepassXCStoreConfig,
    *,
    allow_interactive: bool,
) -> ResolvedKeepassContext:
    db_path = _resolve_db_path(config)
    seed_keepass_password_env_for_tty(config)
    password_env_name, db_password = _resolve_env_value(config.database_password_env_names)
    key_file = _resolve_key_file(config)
    interactive_allowed = bool(allow_interactive or sys.stdin.isatty())
    if not db_password and not interactive_allowed:
        raise KeepassCommandError(
            "KeePassXC database password is not set. Export "
            f"{password_env_name} for non-interactive runs."
        )
    return ResolvedKeepassContext(
        db_path=db_path,
        db_password=db_password,
        key_file=key_file,
        password_env_name=password_env_name,
        interactive_allowed=interactive_allowed,
    )


def _run_keepass_command(
    cmd: list[str],
    *,
    context: ResolvedKeepassContext,
    stdin_suffix: str = "",
) -> subprocess.CompletedProcess[str]:
    if context.db_password:
        return subprocess.run(
            cmd,
            input=context.db_password + "\n" + stdin_suffix,
            capture_output=True,
            text=True,
            check=False,
        )
    if stdin_suffix:
        raise KeepassCommandError(
            "Updating entry passwords requires the KeePass database password to be "
            f"available in {context.password_env_name} or cached by an interactive run."
        )
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=None,
        text=True,
        check=False,
    )


def _raise_keepass_error(
    result: subprocess.CompletedProcess[str],
    *,
    target: str,
    context: ResolvedKeepassContext,
) -> None:
    stderr = (result.stderr or "").strip()
    mode = "non_interactive_env_password" if context.db_password else "interactive_prompt"
    details = f"; stderr={stderr}" if stderr else ""
    raise KeepassCommandError(
        f"keepassxc-cli failed for target {target!r}: {result.returncode}; "
        "keepass_context("
        f"mode={mode}, "
        f"password_env_present={bool(context.db_password)}, "
        f"key_file_present={bool(context.key_file)}"
        f"){details}"
    )


def resolve_keepassxc_entry(
    entry: str,
    attrs_map: Mapping[str, str],
    *,
    allow_interactive: bool = False,
    config: KeepassXCStoreConfig = KeepassXCStoreConfig(),
) -> dict[str, str]:
    entry = str(entry or "").strip()
    if not entry:
        raise KeepassCommandError("KeePassXC entry is required.")
    if not attrs_map:
        raise KeepassCommandError("attrs_map must be a non-empty mapping.")

    context = _resolve_context(config, allow_interactive=allow_interactive)
    requested_attrs = [str(value).strip() for value in attrs_map.values()]
    resolved_by_requested = {
        value: normalize_keepass_attribute_name(value) for value in requested_attrs
    }
    attr_order = list(dict.fromkeys(resolved_by_requested.values()))

    cmd = ["keepassxc-cli", "show", "-s"]
    for attr in attr_order:
        cmd.extend(["-a", attr])
    if context.key_file:
        cmd.extend(["-k", context.key_file])
    cmd.extend([context.db_path, entry])

    result = _run_keepass_command(cmd, context=context)
    if result.returncode != 0:
        _raise_keepass_error(result, target=entry, context=context)

    lines = [line.rstrip("\n") for line in str(result.stdout or "").splitlines()]
    if len(lines) < len(attr_order):
        raise KeepassCommandError(
            f"keepassxc-cli returned {len(lines)} attributes, expected "
            f"{len(attr_order)} for entry {entry!r}."
        )

    raw_values = {attr_order[idx]: lines[idx] for idx in range(len(attr_order))}
    resolved: dict[str, str] = {}
    for logical_name, attr_name in attrs_map.items():
        requested = str(attr_name).strip()
        keepass_attr = resolved_by_requested.get(
            requested,
            normalize_keepass_attribute_name(requested),
        )
        resolved[str(logical_name)] = raw_values.get(keepass_attr, "")
    try:
        maybe_notify_password_retrieval(
            entry=entry,
            requested_attributes=attr_order,
            context=context,
        )
    except PasswordRetrievalNotificationError as exc:
        log.warning("password-retrieval notification failed (non-fatal): %s", exc)
    return resolved


def resolve_keepassxc_entry_all_fields(
    entry: str,
    *,
    allow_interactive: bool = False,
    config: KeepassXCStoreConfig = KeepassXCStoreConfig(),
) -> dict[str, str]:
    entry = str(entry or "").strip()
    if not entry:
        raise KeepassCommandError("KeePassXC entry is required.")

    context = _resolve_context(config, allow_interactive=allow_interactive)
    cmd = ["keepassxc-cli", "show", "--all", "-s"]
    if context.key_file:
        cmd.extend(["-k", context.key_file])
    cmd.extend([context.db_path, entry])

    result = _run_keepass_command(cmd, context=context)
    if result.returncode != 0:
        _raise_keepass_error(result, target=entry, context=context)

    fields: dict[str, str] = {}
    current_key = ""
    for raw_line in str(result.stdout or "").splitlines():
        line = raw_line.rstrip("\n")
        if ":" in line:
            key_part, value_part = line.split(":", 1)
            key = key_part.strip()
            value = value_part.strip()
            if not key:
                continue
            if key.lower() in {"attributes", "attachments"} and not value:
                current_key = ""
                continue
            fields[key] = value
            current_key = key if key.lower() == "notes" else ""
            continue
        if current_key and line.strip():
            existing = fields.get(current_key, "")
            fields[current_key] = f"{existing}\n{line.strip()}" if existing else line.strip()
    try:
        maybe_notify_password_retrieval(
            entry=entry,
            requested_attributes=fields.keys(),
            context=context,
        )
    except PasswordRetrievalNotificationError as exc:
        log.warning("password-retrieval notification failed (non-fatal): %s", exc)
    return fields


def _entry_parent_group(entry: str) -> str:
    parts = [part for part in str(entry).strip("/").split("/") if part]
    if len(parts) <= 1:
        return ""
    return "/".join(parts[:-1])


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    lowered = str(text or "").strip().lower()
    return any(marker in lowered for marker in markers)


def ensure_group(
    group: str,
    *,
    allow_interactive: bool = False,
    config: KeepassXCStoreConfig = KeepassXCStoreConfig(),
) -> bool:
    group = str(group or "").strip().strip("/")
    if not group:
        raise KeepassCommandError("KeePassXC group path is required.")

    context = _resolve_context(config, allow_interactive=allow_interactive)
    cmd = ["keepassxc-cli", "mkdir", "-q"]
    if context.key_file:
        cmd.extend(["-k", context.key_file])
    cmd.extend([context.db_path, group])

    result = _run_keepass_command(cmd, context=context)
    if result.returncode == 0:
        return True
    if _contains_any(result.stderr or "", GROUP_EXISTS_MARKERS):
        return False
    _raise_keepass_error(result, target=group, context=context)
    raise AssertionError("unreachable")


def upsert_keepassxc_entry(
    entry: str,
    *,
    username: str | None = None,
    password: str | None = None,
    url: str | None = None,
    notes: str | None = None,
    create_group: bool = True,
    allow_interactive: bool = False,
    config: KeepassXCStoreConfig = KeepassXCStoreConfig(),
) -> str:
    entry = str(entry or "").strip()
    if not entry:
        raise KeepassCommandError("KeePassXC entry is required.")
    if all(value is None for value in (username, password, url, notes)):
        raise KeepassCommandError(
            "At least one of username, password, url, or notes must be provided."
        )

    context = _resolve_context(config, allow_interactive=allow_interactive)
    cmd_common = ["-q"]
    if username is not None:
        cmd_common.extend(["-u", username])
    if url is not None:
        cmd_common.extend(["--url", url])
    if notes is not None:
        cmd_common.extend(["--notes", notes])
    stdin_suffix = ""
    if password is not None:
        cmd_common.append("-p")
        stdin_suffix = f"{password}\n{password}\n"
    if context.key_file:
        cmd_common.extend(["-k", context.key_file])

    edit_cmd = ["keepassxc-cli", "edit", *cmd_common, context.db_path, entry]
    edit_result = _run_keepass_command(
        edit_cmd,
        context=context,
        stdin_suffix=stdin_suffix,
    )
    if edit_result.returncode == 0:
        return "edit"

    if not _contains_any(edit_result.stderr or "", ENTRY_NOT_FOUND_MARKERS):
        _raise_keepass_error(edit_result, target=entry, context=context)

    parent_group = _entry_parent_group(entry)
    if create_group and parent_group:
        ensure_group(
            parent_group,
            allow_interactive=allow_interactive,
            config=config,
        )

    add_cmd = ["keepassxc-cli", "add", *cmd_common, context.db_path, entry]
    add_result = _run_keepass_command(
        add_cmd,
        context=context,
        stdin_suffix=stdin_suffix,
    )
    if add_result.returncode == 0:
        return "add"

    _raise_keepass_error(add_result, target=entry, context=context)
    raise AssertionError("unreachable")
