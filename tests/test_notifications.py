from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from auto_pass.notifications import (
    DAILY_LOG_PATH_ENV,
    DAILY_SUMMARY_ENV,
    PASSWORD_RETRIEVAL_NOTIFY_EMAIL_TO_ENV,
    PASSWORD_RETRIEVAL_NOTIFY_ENV,
    PASSWORD_RETRIEVAL_NOTIFY_EVERY_N_ENV,
    PASSWORD_RETRIEVAL_NOTIFY_SIGNAL_TO_ENV,
    PASSWORD_RETRIEVAL_NOTIFY_SUPPRESS_ENV,
    SHOCK_RELAY_ROOT_ENV,
    PasswordRetrievalNotificationError,
    _read_and_increment_counter,
    _read_retrieval_log,
    maybe_notify_password_retrieval,
    send_daily_summary,
)


class NotificationsTests(unittest.TestCase):
    def test_password_retrieval_notifications_send_email_and_signal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shock_relay_root = Path(tmp) / "shock-relay"
            email_script = shock_relay_root / "services/gmail-imap/send_email.py"
            signal_script = shock_relay_root / "services/signal-cli/send_message.py"
            email_script.parent.mkdir(parents=True, exist_ok=True)
            signal_script.parent.mkdir(parents=True, exist_ok=True)
            email_script.write_text("", encoding="utf-8")
            signal_script.write_text("", encoding="utf-8")
            captured_calls: list[dict[str, object]] = []

            def fake_run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
                captured_calls.append({"cmd": list(cmd), "kwargs": kwargs})
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

            env = {
                PASSWORD_RETRIEVAL_NOTIFY_ENV: "1",
                PASSWORD_RETRIEVAL_NOTIFY_EMAIL_TO_ENV: "alerts@example.test",
                PASSWORD_RETRIEVAL_NOTIFY_SIGNAL_TO_ENV: "+15555550123",
                SHOCK_RELAY_ROOT_ENV: str(shock_relay_root),
                "AUTO_PASS_PROFILE": "infra",
            }
            context = type(
                "Context",
                (),
                {
                    "db_path": "/vaults/infra.kdbx",
                    "key_file": "",
                    "db_password": "secret",
                    "password_env_name": "AUTO_PASS_KEEPASSXC_DB_PASSWORD",
                    "interactive_allowed": False,
                },
            )()

            with patch("auto_pass.notifications.subprocess.run", side_effect=fake_run):
                maybe_notify_password_retrieval(
                    entry="service/example",
                    requested_attributes=["UserName", "Password"],
                    context=context,
                    environ=env,
                )

        self.assertEqual(len(captured_calls), 2)
        email_call, signal_call = captured_calls
        self.assertEqual(email_call["cmd"][:2], [sys.executable, str(email_script)])
        self.assertEqual(signal_call["cmd"][:2], [sys.executable, str(signal_script)])
        self.assertEqual(
            email_call["kwargs"]["env"][PASSWORD_RETRIEVAL_NOTIFY_SUPPRESS_ENV],
            "1",
        )
        self.assertEqual(
            signal_call["kwargs"]["env"][PASSWORD_RETRIEVAL_NOTIFY_SUPPRESS_ENV],
            "1",
        )
        self.assertEqual(email_call["kwargs"]["cwd"], str(shock_relay_root))
        self.assertEqual(signal_call["kwargs"]["cwd"], str(shock_relay_root))
        self.assertIn("Password retrieved for service/example", email_call["cmd"][5])
        self.assertIn("service/example", signal_call["cmd"][5])

    def test_password_retrieval_notifications_support_signal_note_to_self(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shock_relay_root = Path(tmp) / "shock-relay"
            email_script = shock_relay_root / "services/gmail-imap/send_email.py"
            signal_config = shock_relay_root / "services/signal-cli/config.local.yaml"
            email_script.parent.mkdir(parents=True, exist_ok=True)
            signal_config.parent.mkdir(parents=True, exist_ok=True)
            email_script.write_text("", encoding="utf-8")
            signal_config.write_text(
                "\n".join(
                    [
                        "signal_cli:",
                        '  account: "+15555550123"',
                        '  bus_name: "fedora-cli"',
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            captured_cmds: list[list[str]] = []

            def fake_run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
                captured_cmds.append(list(cmd))
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

            env = {
                PASSWORD_RETRIEVAL_NOTIFY_ENV: "1",
                PASSWORD_RETRIEVAL_NOTIFY_EMAIL_TO_ENV: "alerts@example.test",
                PASSWORD_RETRIEVAL_NOTIFY_SIGNAL_TO_ENV: "note-to-self",
                SHOCK_RELAY_ROOT_ENV: str(shock_relay_root),
            }
            context = type(
                "Context",
                (),
                {
                    "db_path": "/vaults/infra.kdbx",
                    "key_file": "",
                    "db_password": "secret",
                    "password_env_name": "AUTO_PASS_KEEPASSXC_DB_PASSWORD",
                    "interactive_allowed": False,
                },
            )()

            with patch("auto_pass.notifications.subprocess.run", side_effect=fake_run):
                maybe_notify_password_retrieval(
                    entry="service/example",
                    requested_attributes=["Password"],
                    context=context,
                    environ=env,
                )

        self.assertEqual(len(captured_cmds), 2)
        self.assertEqual(
            captured_cmds[1][:6],
            ["signal-cli", "-a", "+15555550123", "--bus-name", "fedora-cli", "send"],
        )
        self.assertIn("--note-to-self", captured_cmds[1])

    def test_password_retrieval_notifications_skip_when_suppressed(self) -> None:
        context = type(
            "Context",
            (),
            {
                "db_path": "/vaults/infra.kdbx",
                "key_file": "",
                "db_password": "secret",
                "password_env_name": "AUTO_PASS_KEEPASSXC_DB_PASSWORD",
                "interactive_allowed": False,
            },
        )()

        with patch("auto_pass.notifications.subprocess.run") as run:
            maybe_notify_password_retrieval(
                entry="service/example",
                requested_attributes=["Password"],
                context=context,
                environ={
                    PASSWORD_RETRIEVAL_NOTIFY_ENV: "1",
                    PASSWORD_RETRIEVAL_NOTIFY_SUPPRESS_ENV: "1",
                    PASSWORD_RETRIEVAL_NOTIFY_EMAIL_TO_ENV: "alerts@example.test",
                    SHOCK_RELAY_ROOT_ENV: "/tmp/shock-relay",
                },
            )

        run.assert_not_called()

    def test_password_retrieval_notifications_require_a_recipient(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shock_relay_root = Path(tmp) / "shock-relay"
            shock_relay_root.mkdir(parents=True, exist_ok=True)
            context = type(
                "Context",
                (),
                {
                    "db_path": "/vaults/infra.kdbx",
                    "key_file": "",
                    "db_password": "secret",
                    "password_env_name": "AUTO_PASS_KEEPASSXC_DB_PASSWORD",
                    "interactive_allowed": False,
                },
            )()

            with self.assertRaises(PasswordRetrievalNotificationError) as exc:
                maybe_notify_password_retrieval(
                    entry="service/example",
                    requested_attributes=["Password"],
                    context=context,
                    environ={
                        PASSWORD_RETRIEVAL_NOTIFY_ENV: "1",
                        SHOCK_RELAY_ROOT_ENV: str(shock_relay_root),
                    },
                )

        self.assertIn("no email or signal recipient", str(exc.exception))


class DailySummaryTests(unittest.TestCase):
    def _context(self):
        return type(
            "Context",
            (),
            {
                "db_path": "/vaults/infra.kdbx",
                "key_file": "",
                "db_password": "secret",
                "password_env_name": "AUTO_PASS_KEEPASSXC_DB_PASSWORD",
                "interactive_allowed": False,
            },
        )()

    def test_daily_summary_mode_logs_to_file_instead_of_sending(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "retrieval_log.jsonl"
            env = {
                PASSWORD_RETRIEVAL_NOTIFY_ENV: "1",
                DAILY_SUMMARY_ENV: "1",
                DAILY_LOG_PATH_ENV: str(log_path),
                PASSWORD_RETRIEVAL_NOTIFY_EMAIL_TO_ENV: "alerts@example.test",
                SHOCK_RELAY_ROOT_ENV: tmp,
            }
            with patch("auto_pass.notifications.subprocess.run") as run:
                maybe_notify_password_retrieval(
                    entry="svc/example",
                    requested_attributes=["Password"],
                    context=self._context(),
                    environ=env,
                )
            run.assert_not_called()
            records = _read_retrieval_log(log_path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["entry"], "svc/example")
        self.assertEqual(records[0]["database"], "infra.kdbx")

    def test_daily_summary_bypasses_throttle(self):
        """Every retrieval is logged in daily mode even when every_n > 1."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "retrieval_log.jsonl"
            env = {
                PASSWORD_RETRIEVAL_NOTIFY_ENV: "1",
                DAILY_SUMMARY_ENV: "1",
                DAILY_LOG_PATH_ENV: str(log_path),
                PASSWORD_RETRIEVAL_NOTIFY_EVERY_N_ENV: "5",
                PASSWORD_RETRIEVAL_NOTIFY_EMAIL_TO_ENV: "alerts@example.test",
                SHOCK_RELAY_ROOT_ENV: tmp,
            }
            with patch("auto_pass.notifications.subprocess.run"):
                for _ in range(3):
                    maybe_notify_password_retrieval(
                        entry="svc/example",
                        requested_attributes=["Password"],
                        context=self._context(),
                        environ=env,
                    )
            records = _read_retrieval_log(log_path)
        self.assertEqual(len(records), 3)

    def test_send_daily_summary_sends_digest_and_clears_log(self):
        import json as _json

        with tempfile.TemporaryDirectory() as tmp:
            shock_relay_root = Path(tmp) / "shock-relay"
            email_script = shock_relay_root / "services/gmail-imap/send_email.py"
            email_script.parent.mkdir(parents=True, exist_ok=True)
            email_script.write_text("", encoding="utf-8")
            log_path = Path(tmp) / "retrieval_log.jsonl"
            log_path.write_text(
                _json.dumps(
                    {
                        "entry": "svc/a",
                        "profile": "infra",
                        "database": "infra.kdbx",
                        "fields": ["Password"],
                        "user": "u",
                        "host": "h",
                        "pid": 1,
                        "timestamp": "2026-05-05T10:00:00-04:00",
                    }
                )
                + "\n"
                + _json.dumps(
                    {
                        "entry": "svc/b",
                        "profile": "infra",
                        "database": "infra.kdbx",
                        "fields": ["Password"],
                        "user": "u",
                        "host": "h",
                        "pid": 2,
                        "timestamp": "2026-05-05T11:00:00-04:00",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            captured: list[list[str]] = []

            def fake_run(cmd, **kwargs):
                captured.append(list(cmd))
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

            env = {
                PASSWORD_RETRIEVAL_NOTIFY_EMAIL_TO_ENV: "alerts@example.test",
                SHOCK_RELAY_ROOT_ENV: str(shock_relay_root),
            }
            with patch("auto_pass.notifications.subprocess.run", side_effect=fake_run):
                count = send_daily_summary(environ=env, log_path=log_path)

            self.assertEqual(count, 2)
            self.assertEqual(len(captured), 1)
            email_cmd = captured[0]
            self.assertIn("Daily summary: 2 retrieval(s)", email_cmd[5])
            self.assertIn("svc/a", email_cmd[6])
            self.assertIn("svc/b", email_cmd[6])
            self.assertEqual(log_path.read_text(encoding="utf-8"), "")

    def test_send_daily_summary_empty_log_is_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "empty.jsonl"
            with patch("auto_pass.notifications.subprocess.run") as run:
                count = send_daily_summary(
                    environ={SHOCK_RELAY_ROOT_ENV: tmp},
                    log_path=log_path,
                )
            run.assert_not_called()
        self.assertEqual(count, 0)


class CounterThrottleTests(unittest.TestCase):
    def test_every_1_always_fires(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "counter"
            for _ in range(5):
                self.assertTrue(_read_and_increment_counter(1, counter_path=path))

    def test_every_3_fires_on_third_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "counter"
            results = [_read_and_increment_counter(3, counter_path=path) for _ in range(6)]
        self.assertEqual(results, [False, False, True, False, False, True])

    def test_missing_counter_file_treated_as_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "counter"
            # File does not exist — first increment should land at 1, not fire for N=3
            self.assertFalse(_read_and_increment_counter(3, counter_path=path))

    def test_maybe_notify_throttled_to_every_3(self):
        with tempfile.TemporaryDirectory() as tmp:
            shock_relay_root = Path(tmp) / "shock-relay"
            signal_script = shock_relay_root / "services/signal-cli/send_message.py"
            signal_script.parent.mkdir(parents=True, exist_ok=True)
            signal_script.write_text("", encoding="utf-8")
            counter_path = Path(tmp) / "counter"
            captured: list[int] = []

            def fake_run(cmd, **kwargs):
                captured.append(1)
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

            context = type(
                "Context",
                (),
                {
                    "db_path": "/vaults/infra.kdbx",
                    "key_file": "",
                    "db_password": "secret",
                    "password_env_name": "AUTO_PASS_KEEPASSXC_DB_PASSWORD",
                    "interactive_allowed": False,
                },
            )()
            env = {
                PASSWORD_RETRIEVAL_NOTIFY_ENV: "1",
                PASSWORD_RETRIEVAL_NOTIFY_EVERY_N_ENV: "3",
                PASSWORD_RETRIEVAL_NOTIFY_SIGNAL_TO_ENV: "+15555550123",
                SHOCK_RELAY_ROOT_ENV: str(shock_relay_root),
            }

            with (
                patch("auto_pass.notifications.subprocess.run", side_effect=fake_run),
                patch("auto_pass.notifications._counter_file", return_value=counter_path),
            ):
                for _ in range(6):
                    maybe_notify_password_retrieval(
                        entry="svc/example",
                        requested_attributes=["Password"],
                        context=context,
                        environ=env,
                    )

        self.assertEqual(len(captured), 2)  # only calls 3 and 6
