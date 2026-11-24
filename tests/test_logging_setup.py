from __future__ import annotations

import logging
import stat
import sys

from auto_pass.logging_setup import (
    RedactingFilter,
    configure_logging,
    default_log_path,
    resolve_level,
    resolve_log_file,
)

SECRET = "sk-ant-api03-" + "A" * 40


def test_resolve_level_prefers_argument_then_environment(monkeypatch):
    monkeypatch.setenv("AUTO_PASS_LOG_LEVEL", "warning")
    assert resolve_level(None) == logging.WARNING
    assert resolve_level("debug") == logging.DEBUG
    assert resolve_level("nonsense") == logging.INFO


def test_default_log_path_per_platform(tmp_path):
    env = {"HOME": str(tmp_path), "LOCALAPPDATA": str(tmp_path / "Local")}
    assert default_log_path("linux", env) == tmp_path / ".local/state/auto-pass/auto-pass.log"
    assert default_log_path("darwin", env) == (tmp_path / "Library/Logs/auto-pass/auto-pass.log")
    assert default_log_path("win32", env) == tmp_path / "Local/auto-pass/Logs/auto-pass.log"


def test_resolve_log_file_modes(tmp_path, monkeypatch):
    monkeypatch.delenv("AUTO_PASS_LOG_FILE")
    assert resolve_log_file(None, "linux") is None
    assert resolve_log_file(None, "darwin") is not None
    assert resolve_log_file(None, "win32") is not None
    assert resolve_log_file("off", "win32") is None
    assert resolve_log_file("default", "linux") is not None
    assert resolve_log_file(str(tmp_path / "x.log"), "linux") == tmp_path / "x.log"


def test_logging_is_private_redacted_and_idempotent(tmp_path):
    target = tmp_path / "logs" / "auto-pass.log"
    configure_logging("info", str(target))
    configure_logging("info", str(target))
    ours = [
        handler for handler in logging.getLogger().handlers if getattr(handler, "_auto_pass", None)
    ]
    assert [handler._auto_pass for handler in ours] == ["stderr", "file"]

    logging.getLogger("auto_pass.test").warning("token=%s", SECRET)
    file_handler = next(handler for handler in ours if handler._auto_pass == "file")
    file_handler.flush()
    text = target.read_text(encoding="utf-8")
    assert "[REDACTED]" in text
    assert SECRET not in text
    assert "WARNING auto_pass.test:" in text
    if not sys.platform.startswith("win"):
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700


def test_filter_redacts_exception_text():
    try:
        raise RuntimeError(f"password={SECRET}")
    except RuntimeError:
        record = logging.LogRecord("x", logging.ERROR, "f", 1, "failed", None, sys.exc_info())
    RedactingFilter().filter(record)
    assert SECRET not in (record.exc_text or "")


def test_unwritable_log_file_does_not_stop_startup(tmp_path, capsys):
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    configure_logging("info", str(blocker / "sub" / "auto-pass.log"))
    assert "unavailable" in capsys.readouterr().err
