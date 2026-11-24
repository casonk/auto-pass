"""Cross-platform, secret-redacting process logging for Auto Pass."""

from __future__ import annotations

import contextlib
import logging
import logging.handlers
import os
import sys
from pathlib import Path

from .redaction import redact

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
LEVEL_ENV = "AUTO_PASS_LOG_LEVEL"
FILE_ENV = "AUTO_PASS_LOG_FILE"
MAX_FILE_BYTES = 5 * 1024 * 1024
FILE_BACKUPS = 3
_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


class RedactingFilter(logging.Filter):
    """Mask secrets in formatted messages and exception text."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = None
        if record.exc_info and not record.exc_text:
            record.exc_text = redact(logging.Formatter().formatException(record.exc_info))
        return True


def resolve_level(value: str | None) -> int:
    name = (value or os.environ.get(LEVEL_ENV) or "INFO").strip().upper()
    return getattr(logging, name if name in _LEVELS else "INFO")


def default_log_path(platform: str | None = None, env: dict[str, str] | None = None) -> Path:
    platform = platform or sys.platform
    env = os.environ if env is None else env
    home = Path(env.get("HOME") or env.get("USERPROFILE") or Path.home())
    if platform == "win32":
        base = Path(env.get("LOCALAPPDATA") or home / "AppData" / "Local")
        return base / "auto-pass" / "Logs" / "auto-pass.log"
    if platform == "darwin":
        return home / "Library" / "Logs" / "auto-pass" / "auto-pass.log"
    state = Path(env.get("XDG_STATE_HOME") or home / ".local" / "state")
    return state / "auto-pass" / "auto-pass.log"


def resolve_log_file(value: str | None, platform: str | None = None) -> Path | None:
    raw = (value if value is not None else os.environ.get(FILE_ENV) or "auto").strip()
    lowered = raw.lower()
    platform = platform or sys.platform
    if lowered in {"", "off", "none", "0", "false"}:
        return None
    if lowered == "auto":
        return default_log_path(platform) if platform in {"win32", "darwin"} else None
    if lowered == "default":
        return default_log_path(platform)
    return Path(raw).expanduser()


class _SafeRotatingFileHandler(logging.handlers.RotatingFileHandler):
    def doRollover(self) -> None:  # noqa: N802
        try:
            super().doRollover()
        except OSError:
            if self.stream is None:
                self.stream = self._open()


def _open_private_file(path: Path) -> logging.Handler:
    path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        path.parent.chmod(0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.close(fd)
    with contextlib.suppress(OSError):
        path.chmod(0o600)
    return _SafeRotatingFileHandler(
        path, maxBytes=MAX_FILE_BYTES, backupCount=FILE_BACKUPS, encoding="utf-8", delay=True
    )


def _mark(handler: logging.Handler, kind: str) -> logging.Handler:
    handler._auto_pass = kind  # type: ignore[attr-defined]
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    handler.addFilter(RedactingFilter())
    return handler


def configure_logging(level: str | None = None, log_file: str | None = None) -> None:
    """Install idempotent redacting stderr and optional rotating-file handlers."""
    root = logging.getLogger()
    root.setLevel(resolve_level(level))
    have = {getattr(handler, "_auto_pass", None) for handler in root.handlers}
    if "stderr" not in have:
        root.addHandler(_mark(logging.StreamHandler(sys.stderr), "stderr"))
    path = resolve_log_file(log_file)
    if path is not None and "file" not in have:
        try:
            root.addHandler(_mark(_open_private_file(path), "file"))
        except OSError as exc:
            logging.getLogger(__name__).warning("log file %s unavailable: %s", path, exc)
