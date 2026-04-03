from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from auto_pass.notifications import (
    PASSWORD_RETRIEVAL_NOTIFY_EMAIL_TO_ENV,
    PASSWORD_RETRIEVAL_NOTIFY_ENV,
    PASSWORD_RETRIEVAL_NOTIFY_SIGNAL_TO_ENV,
    PASSWORD_RETRIEVAL_NOTIFY_SUPPRESS_ENV,
    SHOCK_RELAY_ROOT_ENV,
    PasswordRetrievalNotificationError,
    maybe_notify_password_retrieval,
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
