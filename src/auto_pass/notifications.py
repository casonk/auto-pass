from __future__ import annotations

import getpass
import os
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from .envfile import get_active_keepass_profile

if TYPE_CHECKING:
    from collections.abc import Iterable, MutableMapping

    from .keepassxc import ResolvedKeepassContext

PASSWORD_RETRIEVAL_NOTIFY_ENV = "AUTO_PASS_NOTIFY_PASSWORD_RETRIEVAL"
PASSWORD_RETRIEVAL_NOTIFY_SUPPRESS_ENV = "AUTO_PASS_NOTIFY_PASSWORD_RETRIEVAL_SUPPRESS"
PASSWORD_RETRIEVAL_NOTIFY_EMAIL_TO_ENV = "AUTO_PASS_NOTIFY_PASSWORD_RETRIEVAL_EMAIL_TO"
PASSWORD_RETRIEVAL_NOTIFY_SIGNAL_TO_ENV = "AUTO_PASS_NOTIFY_PASSWORD_RETRIEVAL_SIGNAL_TO"
PASSWORD_RETRIEVAL_NOTIFY_SUBJECT_PREFIX_ENV = "AUTO_PASS_NOTIFY_PASSWORD_RETRIEVAL_SUBJECT_PREFIX"
SHOCK_RELAY_ROOT_ENV = "AUTO_PASS_NOTIFY_SHOCK_RELAY_ROOT"
SHOCK_RELAY_EMAIL_CONFIG_ENV = "AUTO_PASS_NOTIFY_SHOCK_RELAY_EMAIL_CONFIG"
SHOCK_RELAY_SIGNAL_CONFIG_ENV = "AUTO_PASS_NOTIFY_SHOCK_RELAY_SIGNAL_CONFIG"


class PasswordRetrievalNotificationError(RuntimeError):
    """Raised when a configured password-retrieval notification cannot be sent."""


@dataclass(frozen=True)
class PasswordRetrievalNotificationConfig:
    shock_relay_root: Path
    email_to: str
    signal_to: str
    email_config_path: Path
    signal_config_path: Path
    subject_prefix: str


def _is_truthy(value: str) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _default_shock_relay_root() -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root.parent / "shock-relay"


def _load_notification_config(
    environ: MutableMapping[str, str],
) -> PasswordRetrievalNotificationConfig:
    shock_relay_root = Path(
        str(environ.get(SHOCK_RELAY_ROOT_ENV, "")).strip() or _default_shock_relay_root()
    ).expanduser()
    email_to = str(environ.get(PASSWORD_RETRIEVAL_NOTIFY_EMAIL_TO_ENV, "")).strip()
    signal_to = str(environ.get(PASSWORD_RETRIEVAL_NOTIFY_SIGNAL_TO_ENV, "")).strip()
    email_config_path = Path(
        str(environ.get(SHOCK_RELAY_EMAIL_CONFIG_ENV, "")).strip()
        or shock_relay_root / "services/gmail-imap/config.local.yaml"
    ).expanduser()
    signal_config_path = Path(
        str(environ.get(SHOCK_RELAY_SIGNAL_CONFIG_ENV, "")).strip()
        or shock_relay_root / "services/signal-cli/config.local.yaml"
    ).expanduser()
    subject_prefix = (
        str(environ.get(PASSWORD_RETRIEVAL_NOTIFY_SUBJECT_PREFIX_ENV, "")).strip() or "[auto-pass]"
    )
    return PasswordRetrievalNotificationConfig(
        shock_relay_root=shock_relay_root,
        email_to=email_to,
        signal_to=signal_to,
        email_config_path=email_config_path,
        signal_config_path=signal_config_path,
        subject_prefix=subject_prefix,
    )


def _normalized_requested_attributes(requested_attributes: Iterable[str]) -> list[str]:
    from .keepassxc import normalize_keepass_attribute_name

    values: list[str] = []
    for item in requested_attributes:
        normalized = normalize_keepass_attribute_name(str(item).strip())
        if normalized and normalized not in values:
            values.append(normalized)
    return values


def _build_audit_lines(
    *,
    entry: str,
    requested_attributes: list[str],
    context: ResolvedKeepassContext,
    environ: MutableMapping[str, str],
) -> list[str]:
    profile = get_active_keepass_profile(environ=environ) or "direct"
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    return [
        "auto-pass retrieved password material.",
        f"entry: {entry}",
        f"profile: {profile}",
        f"database: {Path(context.db_path).name}",
        f"fields: {', '.join(requested_attributes)}",
        f"user: {getpass.getuser()}",
        f"host: {socket.gethostname()}",
        f"pid: {os.getpid()}",
        f"timestamp: {timestamp}",
    ]


def _relay_environment(environ: MutableMapping[str, str]) -> dict[str, str]:
    child_env = dict(environ)
    child_env[PASSWORD_RETRIEVAL_NOTIFY_SUPPRESS_ENV] = "1"
    return child_env


def _is_signal_note_to_self(value: str) -> bool:
    return str(value or "").strip().lower() in {"note-to-self", "note_to_self", "self"}


def _extract_signal_cli_fields(config_path: Path) -> tuple[str, str]:
    try:
        config_text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PasswordRetrievalNotificationError(
            f"shock-relay signal config could not be read: {config_path} ({exc})"
        ) from exc

    account = ""
    bus_name = ""
    in_signal_cli = False
    base_indent: int | None = None

    def value_from_line(line: str) -> str:
        match = re.match(
            r"^\s*[^:]+:\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s#]+))\s*(?:#.*)?$",
            line,
        )
        if not match:
            return ""
        return next(value for value in match.groups() if value is not None)

    for line in config_text.splitlines():
        if not in_signal_cli:
            if re.match(r"^\s*signal_cli:\s*$", line):
                in_signal_cli = True
                base_indent = len(line) - len(line.lstrip())
            continue
        if line.strip():
            indent = len(line) - len(line.lstrip())
            if base_indent is not None and indent <= base_indent:
                break
        if re.match(r"^\s*account:\s*", line):
            account = value_from_line(line)
        elif re.match(r"^\s*bus_name:\s*", line):
            bus_name = value_from_line(line)
    if not account:
        raise PasswordRetrievalNotificationError(
            "shock-relay signal config is missing signal_cli.account"
        )
    return account, bus_name


def _run_relay_command(
    *,
    channel: str,
    cmd: list[str],
    config: PasswordRetrievalNotificationConfig,
    environ: MutableMapping[str, str],
) -> None:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            cwd=str(config.shock_relay_root),
            env=_relay_environment(environ),
        )
    except OSError as exc:
        raise PasswordRetrievalNotificationError(
            f"shock-relay {channel} notification failed to start: {type(exc).__name__}: {exc}"
        ) from exc

    if result.returncode == 0:
        return

    details = (result.stderr or result.stdout or "").strip()
    detail_text = f": {details.splitlines()[0]}" if details else ""
    raise PasswordRetrievalNotificationError(
        f"shock-relay {channel} notification failed with exit code {result.returncode}{detail_text}"
    )


def _run_signal_note_to_self(
    *,
    config: PasswordRetrievalNotificationConfig,
    body: str,
    environ: MutableMapping[str, str],
) -> None:
    account, bus_name = _extract_signal_cli_fields(config.signal_config_path)
    cmd = ["signal-cli", "-a", account]
    if bus_name:
        cmd.extend(["--bus-name", bus_name])
    cmd.extend(["send", "--note-to-self", "-m", body])
    _run_relay_command(
        channel="signal",
        cmd=cmd,
        config=config,
        environ=environ,
    )


def maybe_notify_password_retrieval(
    *,
    entry: str,
    requested_attributes: Iterable[str],
    context: ResolvedKeepassContext,
    environ: MutableMapping[str, str] | None = None,
) -> None:
    env = os.environ if environ is None else environ
    if _is_truthy(env.get(PASSWORD_RETRIEVAL_NOTIFY_SUPPRESS_ENV, "")):
        return
    if not _is_truthy(env.get(PASSWORD_RETRIEVAL_NOTIFY_ENV, "")):
        return

    normalized_requested = _normalized_requested_attributes(requested_attributes)
    if "Password" not in normalized_requested:
        return

    config = _load_notification_config(env)
    if not config.shock_relay_root.is_dir():
        raise PasswordRetrievalNotificationError(
            "password-retrieval notifications are enabled but "
            f"{config.shock_relay_root} is not a shock-relay checkout"
        )

    if not config.email_to and not config.signal_to:
        raise PasswordRetrievalNotificationError(
            "password-retrieval notifications are enabled but no email or signal recipient "
            "is configured"
        )

    audit_lines = _build_audit_lines(
        entry=entry,
        requested_attributes=normalized_requested,
        context=context,
        environ=env,
    )
    subject = f"{config.subject_prefix} Password retrieved for {entry}"
    body = "\n".join(audit_lines)

    errors: list[str] = []
    if config.email_to:
        email_script = config.shock_relay_root / "services/gmail-imap/send_email.py"
        try:
            _run_relay_command(
                channel="email",
                cmd=[
                    sys.executable,
                    str(email_script),
                    "--config",
                    str(config.email_config_path),
                    config.email_to,
                    subject,
                    body,
                ],
                config=config,
                environ=env,
            )
        except PasswordRetrievalNotificationError as exc:
            errors.append(str(exc))

    if config.signal_to:
        try:
            if _is_signal_note_to_self(config.signal_to):
                _run_signal_note_to_self(
                    config=config,
                    body=body,
                    environ=env,
                )
            else:
                signal_script = config.shock_relay_root / "services/signal-cli/send_message.py"
                _run_relay_command(
                    channel="signal",
                    cmd=[
                        sys.executable,
                        str(signal_script),
                        "--config",
                        str(config.signal_config_path),
                        config.signal_to,
                        body,
                    ],
                    config=config,
                    environ=env,
                )
        except PasswordRetrievalNotificationError as exc:
            errors.append(str(exc))

    if errors:
        raise PasswordRetrievalNotificationError("; ".join(errors))
