from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from auto_pass.keepassxc import (
    KeepassCommandError,
    KeepassXCStoreConfig,
    ensure_group,
    lookup_keepass_field_case_insensitive,
    resolve_keepassxc_entry,
    resolve_keepassxc_entry_all_fields,
    seed_keepass_password_env_for_tty,
    upsert_keepassxc_entry,
)
from auto_pass.notifications import PasswordRetrievalNotificationError

DEFAULT_ENV = {
    "AUTO_PASS_KEEPASSXC_DB_PATH": "/tmp/test-db.kdbx",
    "AUTO_PASS_KEEPASSXC_DB_PASSWORD": "test-password",
    "PF_KEEPASSXC_DB_PATH": "",
    "PF_KEEPASSXC_DB_PASSWORD": "",
    "AUTO_PASS_KEEPASSXC_KEY_FILE": "",
    "PF_KEEPASSXC_KEY_FILE": "",
}


class KeepassResolutionTests(unittest.TestCase):
    def test_resolve_keepassxc_entry_maps_aliases(self) -> None:
        captured_cmd: list[str] = []

        def fake_run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
            nonlocal captured_cmd
            captured_cmd = list(cmd)
            self.assertEqual(kwargs["input"], "test-password\n")
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout="app-key\napp-secret\n",
                stderr="",
            )

        with patch.dict(os.environ, DEFAULT_ENV, clear=False):
            with patch("auto_pass.keepassxc.subprocess.run", side_effect=fake_run):
                resolved = resolve_keepassxc_entry(
                    entry="web/github",
                    attrs_map={"api_key": "un", "api_secret": "pw"},
                )

        self.assertEqual(resolved["api_key"], "app-key")
        self.assertEqual(resolved["api_secret"], "app-secret")
        self.assertIn("UserName", captured_cmd)
        self.assertIn("Password", captured_cmd)
        self.assertNotIn("un", captured_cmd)
        self.assertNotIn("pw", captured_cmd)

    def test_resolve_keepassxc_entry_notifies_on_password_reads(self) -> None:
        with (
            patch.dict(os.environ, DEFAULT_ENV, clear=False),
            patch(
                "auto_pass.keepassxc.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout="octocat\nsecret\n",
                    stderr="",
                ),
            ),
            patch("auto_pass.keepassxc.maybe_notify_password_retrieval") as notify,
        ):
            resolve_keepassxc_entry(
                entry="web/github",
                attrs_map={"username": "username", "password": "password"},
            )

        notify.assert_called_once()
        self.assertEqual(notify.call_args.kwargs["requested_attributes"], ["UserName", "Password"])

    def test_resolve_keepassxc_entry_skips_notifications_for_non_password_reads(self) -> None:
        with (
            patch.dict(os.environ, DEFAULT_ENV, clear=False),
            patch(
                "auto_pass.keepassxc.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout="octocat\n",
                    stderr="",
                ),
            ),
            patch("auto_pass.keepassxc.maybe_notify_password_retrieval") as notify,
        ):
            resolve_keepassxc_entry(
                entry="web/github",
                attrs_map={"username": "username"},
            )

        notify.assert_called_once()
        self.assertEqual(notify.call_args.kwargs["requested_attributes"], ["UserName"])

    def test_resolve_keepassxc_entry_wraps_notification_failures(self) -> None:
        with (
            patch.dict(os.environ, DEFAULT_ENV, clear=False),
            patch(
                "auto_pass.keepassxc.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout="octocat\nsecret\n",
                    stderr="",
                ),
            ),
            patch(
                "auto_pass.keepassxc.maybe_notify_password_retrieval",
                side_effect=PasswordRetrievalNotificationError("notification failed"),
            ),
        ):
            with self.assertRaises(KeepassCommandError) as exc:
                resolve_keepassxc_entry(
                    entry="web/github",
                    attrs_map={"username": "username", "password": "password"},
                )

        self.assertIn("notification failed", str(exc.exception))

    def test_resolve_keepassxc_entry_all_fields_parses_multiline_notes(self) -> None:
        def fake_run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout=(
                    "Title: GitHub\n"
                    "UserName: octocat\n"
                    "Password: secret\n"
                    "Notes: first line\n"
                    "second line\n"
                    "URL: https://github.com\n"
                ),
                stderr="",
            )

        with patch.dict(os.environ, DEFAULT_ENV, clear=False):
            with patch("auto_pass.keepassxc.subprocess.run", side_effect=fake_run):
                resolved = resolve_keepassxc_entry_all_fields("web/github")

        self.assertEqual(resolved["Title"], "GitHub")
        self.assertEqual(resolved["UserName"], "octocat")
        self.assertEqual(resolved["Notes"], "first line\nsecond line")

    def test_resolve_keepassxc_entry_all_fields_notifies_with_field_names(self) -> None:
        with (
            patch.dict(os.environ, DEFAULT_ENV, clear=False),
            patch(
                "auto_pass.keepassxc.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout="Title: GitHub\nUserName: octocat\nPassword: secret\n",
                    stderr="",
                ),
            ),
            patch("auto_pass.keepassxc.maybe_notify_password_retrieval") as notify,
        ):
            resolve_keepassxc_entry_all_fields("web/github")

        notify.assert_called_once()
        self.assertEqual(
            list(notify.call_args.kwargs["requested_attributes"]),
            ["Title", "UserName", "Password"],
        )

    def test_lookup_keepass_field_case_insensitive_handles_aliases(self) -> None:
        fields = {"UserName": "octocat", "Password": "secret"}
        self.assertEqual(
            lookup_keepass_field_case_insensitive(fields, "username"),
            "octocat",
        )
        self.assertEqual(
            lookup_keepass_field_case_insensitive(fields, "pw"),
            "secret",
        )


class KeepassPromptTests(unittest.TestCase):
    def test_seed_keepass_password_env_for_tty_reads_cached_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache_file = Path(tmp) / "keepass-cache.json"
            cache_file.write_text(
                json.dumps({"password": "cached-db-pass"}, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
            config = KeepassXCStoreConfig(
                database_password_cache_file=str(cache_file),
                database_password_cache_ttl_seconds=3600,
            )

            with (
                patch.dict(
                    os.environ,
                    {
                        **DEFAULT_ENV,
                        "AUTO_PASS_KEEPASSXC_DB_PASSWORD": "",
                    },
                    clear=False,
                ),
                patch(
                    "auto_pass.keepassxc.sys.stdin",
                    SimpleNamespace(isatty=lambda: False),
                ),
            ):
                seed_keepass_password_env_for_tty(config)
                resolved = os.getenv("AUTO_PASS_KEEPASSXC_DB_PASSWORD", "")

        self.assertEqual(resolved, "cached-db-pass")

    def test_seed_keepass_password_env_for_tty_prompts_and_writes_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache_file = Path(tmp) / "keepass-cache.json"
            config = KeepassXCStoreConfig(
                database_password_cache_file=str(cache_file),
                database_password_cache_ttl_seconds=3600,
            )

            with (
                patch.dict(
                    os.environ,
                    {
                        **DEFAULT_ENV,
                        "AUTO_PASS_KEEPASSXC_DB_PASSWORD": "",
                    },
                    clear=False,
                ),
                patch(
                    "auto_pass.keepassxc.sys.stdin",
                    SimpleNamespace(isatty=lambda: True),
                ),
            ):
                with patch(
                    "auto_pass.keepassxc.getpass",
                    return_value="prompted-db-pass",
                ):
                    seed_keepass_password_env_for_tty(config)
                resolved = os.getenv("AUTO_PASS_KEEPASSXC_DB_PASSWORD", "")

            cached = json.loads(cache_file.read_text(encoding="utf-8"))

        self.assertEqual(resolved, "prompted-db-pass")
        self.assertEqual(cached.get("password"), "prompted-db-pass")


class KeepassWriteTests(unittest.TestCase):
    def test_upsert_keepassxc_entry_edits_existing_entry(self) -> None:
        captured_calls: list[tuple[list[str], str]] = []

        def fake_run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
            captured_calls.append((list(cmd), kwargs["input"]))
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout="",
                stderr="",
            )

        with patch.dict(os.environ, DEFAULT_ENV, clear=False):
            with patch("auto_pass.keepassxc.subprocess.run", side_effect=fake_run):
                mode = upsert_keepassxc_entry(
                    "web/github",
                    username="octocat",
                    password="new-secret",
                    url="https://github.com",
                )

        self.assertEqual(mode, "edit")
        self.assertEqual(len(captured_calls), 1)
        cmd, stdin_payload = captured_calls[0]
        self.assertEqual(cmd[:3], ["keepassxc-cli", "edit", "-q"])
        self.assertEqual(stdin_payload, "test-password\nnew-secret\nnew-secret\n")

    def test_upsert_keepassxc_entry_adds_missing_entry_and_creates_group(self) -> None:
        captured_cmds: list[list[str]] = []

        responses = iter(
            [
                subprocess.CompletedProcess(
                    args=[],
                    returncode=1,
                    stdout="",
                    stderr="Entry web/github was not found.\n",
                ),
                subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout="",
                    stderr="",
                ),
                subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout="",
                    stderr="",
                ),
            ]
        )

        def fake_run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
            captured_cmds.append(list(cmd))
            return next(responses)

        with patch.dict(os.environ, DEFAULT_ENV, clear=False):
            with patch("auto_pass.keepassxc.subprocess.run", side_effect=fake_run):
                mode = upsert_keepassxc_entry(
                    "web/github",
                    username="octocat",
                    password="new-secret",
                    create_group=True,
                )

        self.assertEqual(mode, "add")
        self.assertEqual(captured_cmds[0][:2], ["keepassxc-cli", "edit"])
        self.assertEqual(captured_cmds[1][:2], ["keepassxc-cli", "mkdir"])
        self.assertEqual(captured_cmds[2][:2], ["keepassxc-cli", "add"])

    def test_ensure_group_returns_false_when_group_exists(self) -> None:
        def fake_run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=1,
                stdout="",
                stderr="Group already exists.\n",
            )

        with patch.dict(os.environ, DEFAULT_ENV, clear=False):
            with patch("auto_pass.keepassxc.subprocess.run", side_effect=fake_run):
                created = ensure_group("web")

        self.assertFalse(created)


if __name__ == "__main__":
    unittest.main()
