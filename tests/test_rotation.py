from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from auto_pass.keepassxc import KeepassCommandError
from auto_pass.rotation import (
    PasswordPolicy,
    configure_rotation_registry,
    discard_rotation,
    generate_password,
    infer_password_policy,
    infer_rotation_registry,
    list_rotation_registries,
    pending_entry_path,
    prepare_rotation,
    promote_rotation,
    registry_entry_path,
    rotation_registry_status,
    rotation_status,
    sync_rotation_todo,
)


class RotationPolicyTests(unittest.TestCase):
    def test_generate_password_respects_required_groups(self) -> None:
        password = generate_password(PasswordPolicy(length=32))

        self.assertEqual(len(password), 32)
        self.assertTrue(any(ch.islower() for ch in password))
        self.assertTrue(any(ch.isupper() for ch in password))
        self.assertTrue(any(ch.isdigit() for ch in password))
        self.assertTrue(any(not ch.isalnum() for ch in password))

    def test_generate_password_rejects_empty_policy(self) -> None:
        with self.assertRaises(ValueError):
            generate_password(
                PasswordPolicy(
                    lower=False,
                    upper=False,
                    numeric=False,
                    special=False,
                )
            )

    def test_pending_entry_path_appends_suffix(self) -> None:
        self.assertEqual(pending_entry_path("web/github"), "web/github@rotation-pending")

    def test_registry_entry_path_appends_suffix(self) -> None:
        self.assertEqual(registry_entry_path("web/github"), "web/github@rotation-config")

    def test_infer_password_policy_uses_observed_character_groups(self) -> None:
        policy = infer_password_policy("Abc123!_-")

        self.assertEqual(policy.length, 9)
        self.assertTrue(policy.lower)
        self.assertTrue(policy.upper)
        self.assertTrue(policy.numeric)
        self.assertTrue(policy.special)
        self.assertEqual(policy.special_chars, "!_-")


class RotationLifecycleTests(unittest.TestCase):
    def test_prepare_rotation_uses_existing_entry_url_when_missing(self) -> None:
        with (
            patch(
                "auto_pass.rotation.resolve_keepassxc_entry_all_fields",
                side_effect=[
                    KeepassCommandError("Entry web/github@rotation-config not found"),
                    {"URL": "https://github.com/settings/security"},
                ],
            ) as read_entry,
            patch(
                "auto_pass.rotation.upsert_keepassxc_entry",
                return_value="add",
            ) as upsert,
            patch(
                "auto_pass.rotation.generate_password",
                return_value="GeneratedPassword123!",
            ),
        ):
            result = prepare_rotation(
                "web/github",
                policy=PasswordPolicy(length=20),
                note="manual site rotation",
            )

        self.assertEqual(result["mode"], "add")
        self.assertEqual(result["homepage_url"], "https://github.com/settings/security")
        self.assertEqual(result["pending_entry"], "web/github@rotation-pending")
        self.assertEqual(read_entry.call_count, 2)
        self.assertEqual(
            read_entry.call_args_list[0].args,
            ("web/github@rotation-config",),
        )
        self.assertEqual(
            read_entry.call_args_list[1].args,
            ("web/github",),
        )
        self.assertEqual(upsert.call_args.args[0], "web/github@rotation-pending")
        self.assertEqual(upsert.call_args.kwargs["password"], "GeneratedPassword123!")

    def test_prepare_rotation_uses_registry_defaults(self) -> None:
        with (
            patch(
                "auto_pass.rotation.resolve_keepassxc_entry_all_fields",
                return_value={
                    "Notes": (
                        "{"
                        '"entry":"web/github",'
                        '"registry_entry":"web/github@rotation-config",'
                        '"homepage_url":"https://github.com/login",'
                        '"reset_url":"https://github.com/settings/security",'
                        '"rotation_interval_days":90,'
                        '"policy":{"length":30,"special":false,"lower":true,"upper":true,"numeric":true,"special_chars":"!@#","exclude_chars":"","every_group":true},'
                        '"schema_version":1'
                        "}"
                    )
                },
            ),
            patch(
                "auto_pass.rotation.generate_password",
                return_value="GeneratedPassword123ABC",
            ),
            patch(
                "auto_pass.rotation.upsert_keepassxc_entry",
                return_value="edit",
            ) as upsert,
        ):
            result = prepare_rotation("web/github")

        self.assertEqual(result["homepage_url"], "https://github.com/login")
        self.assertEqual(result["reset_url"], "https://github.com/settings/security")
        self.assertEqual(result["length"], 30)
        self.assertEqual(upsert.call_args.kwargs["url"], "https://github.com/settings/security")

    def test_rotation_status_returns_pending_false_when_missing(self) -> None:
        with patch(
            "auto_pass.rotation.resolve_keepassxc_entry_all_fields",
            side_effect=[
                KeepassCommandError("Entry web/github@rotation-config not found"),
                KeepassCommandError("Entry web/github@rotation-pending not found"),
            ],
        ):
            result = rotation_status("web/github")

        self.assertEqual(
            result,
            {
                "entry": "web/github",
                "pending": False,
                "pending_entry": "web/github@rotation-pending",
                "registry_entry": "web/github@rotation-config",
                "registry_present": False,
            },
        )

    def test_rotation_status_reads_pending_metadata(self) -> None:
        with patch(
            "auto_pass.rotation.resolve_keepassxc_entry_all_fields",
            return_value={
                "Password": "GeneratedPassword123!",
                "Notes": (
                    "{\n"
                    '  "created_at": "2026-06-18T12:00:00+00:00",\n'
                    '  "entry": "web/github",\n'
                    '  "homepage_url": "https://github.com",\n'
                    '  "note": "manual rotation",\n'
                    '  "pending_entry": "web/github@rotation-pending",\n'
                    '  "policy": {"length": 20},\n'
                    '  "reset_url": "https://github.com/settings/security",\n'
                    '  "schema_version": 1\n'
                    "}"
                ),
            },
        ):
            result = rotation_status("web/github")

        self.assertTrue(result["pending"])
        self.assertEqual(result["length"], 21)
        self.assertEqual(result["reset_url"], "https://github.com/settings/security")
        self.assertEqual(result["policy"], {"length": 20})

    def test_promote_rotation_updates_real_entry_and_removes_pending(self) -> None:
        with (
            patch(
                "auto_pass.rotation.resolve_keepassxc_entry_all_fields",
                return_value={
                    "Password": "GeneratedPassword123!",
                    "Notes": '{"created_at":"2026-06-18T12:00:00+00:00"}',
                },
            ),
            patch(
                "auto_pass.rotation.upsert_keepassxc_entry",
                return_value="edit",
            ) as upsert,
            patch(
                "auto_pass.rotation.read_rotation_registry",
                return_value=None,
            ),
            patch(
                "auto_pass.rotation.remove_keepassxc_entry",
                return_value=True,
            ) as remove_entry,
        ):
            result = promote_rotation("web/github")

        self.assertTrue(result["promoted"])
        real_entry_call = upsert.call_args_list[0]
        self.assertEqual(real_entry_call.args[0], "web/github")
        self.assertEqual(real_entry_call.kwargs["password"], "GeneratedPassword123!")
        self.assertEqual(result["policy_source"], "manual")
        self.assertEqual(result["policy_confidence"], "high")
        remove_entry.assert_called_once_with(
            "web/github@rotation-pending",
            allow_interactive=False,
        )

    def test_sync_rotation_todo_replaces_managed_category_items(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            todo_file = Path(tmp) / "todo.json"
            todo_file.write_text(
                json.dumps(
                    {
                        "categories": [
                            {"name": "Tasks", "items": [{"title": "Pay taxes", "done": False}]},
                            {
                                "name": "Password Rotation",
                                "items": [{"title": "stale item", "done": True}],
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with patch(
                "auto_pass.rotation.list_rotation_registries",
                return_value=[
                    {
                        "entry": "web/github",
                        "due_status": "overdue",
                        "days_until_due": -3,
                        "policy_source": "manual",
                        "policy_confidence": "high",
                    },
                    {
                        "entry": "web/gitlab",
                        "due_status": "scheduled",
                        "days_until_due": 12,
                        "policy_source": "inferred-from-current-password",
                        "policy_confidence": "low",
                    },
                ],
            ):
                result = sync_rotation_todo(todo_file, due_within_days=30)

            self.assertEqual(result["item_count"], 2)
            payload = json.loads(todo_file.read_text(encoding="utf-8"))
            self.assertEqual(payload["categories"][0]["items"][0]["title"], "Pay taxes")
            self.assertEqual(
                payload["categories"][1]["items"],
                [
                    {
                        "title": "Rotate password: web/github (overdue; verified rules)",
                        "done": False,
                    },
                    {
                        "title": "Rotate password: web/gitlab (due in 12d; inferred rules)",
                        "done": False,
                    },
                ],
            )

    def test_discard_rotation_removes_pending_entry(self) -> None:
        with patch(
            "auto_pass.rotation.remove_keepassxc_entry",
            return_value=True,
        ) as remove_entry:
            result = discard_rotation("web/github")

        self.assertEqual(
            result,
            {
                "entry": "web/github",
                "discarded": True,
                "pending_entry": "web/github@rotation-pending",
            },
        )
        remove_entry.assert_called_once_with(
            "web/github@rotation-pending",
            allow_interactive=False,
        )

    def test_configure_rotation_registry_writes_companion_entry(self) -> None:
        with (
            patch(
                "auto_pass.rotation.resolve_keepassxc_entry_all_fields",
                side_effect=KeepassCommandError("Entry web/github@rotation-config not found"),
            ),
            patch(
                "auto_pass.rotation.upsert_keepassxc_entry",
                return_value="add",
            ) as upsert,
        ):
            result = configure_rotation_registry(
                "web/github",
                policy=PasswordPolicy(length=28, special=False),
                homepage_url="https://github.com/login",
                reset_url="https://github.com/settings/security",
                rotation_interval_days=120,
            )

        self.assertTrue(result["configured"])
        self.assertEqual(result["registry_entry"], "web/github@rotation-config")
        self.assertEqual(upsert.call_args.args[0], "web/github@rotation-config")
        self.assertEqual(upsert.call_args.kwargs["url"], "https://github.com/settings/security")

    def test_rotation_registry_status_reads_registry(self) -> None:
        with patch(
            "auto_pass.rotation.resolve_keepassxc_entry_all_fields",
            return_value={
                "Notes": (
                    "{"
                    '"entry":"web/github",'
                    '"registry_entry":"web/github@rotation-config",'
                    '"updated_at":"2026-06-19T12:00:00+00:00",'
                    '"homepage_url":"https://github.com/login",'
                    '"reset_url":"https://github.com/settings/security",'
                    '"note":"rotate on travel",'
                    '"rotation_interval_days":120,'
                    '"policy":{"length":28},'
                    '"policy_source":"manual",'
                    '"policy_confidence":"high",'
                    '"schema_version":1'
                    "}"
                )
            },
        ):
            result = rotation_registry_status("web/github")

        self.assertTrue(result["configured"])
        self.assertEqual(result["updated_at"], "2026-06-19T12:00:00+00:00")
        self.assertEqual(result["rotation_interval_days"], 120)
        self.assertEqual(result["policy"], {"length": 28})
        self.assertEqual(result["policy_source"], "manual")
        self.assertEqual(result["policy_confidence"], "high")

    def test_infer_rotation_registry_writes_inferred_defaults(self) -> None:
        with (
            patch(
                "auto_pass.rotation.resolve_keepassxc_entry_all_fields",
                side_effect=[
                    KeepassCommandError("Entry web/github@rotation-config not found"),
                    {
                        "Password": "Abc123!_-",
                        "URL": "https://github.com/login",
                    },
                ],
            ),
            patch(
                "auto_pass.rotation.upsert_keepassxc_entry",
                return_value="add",
            ) as upsert,
        ):
            result = infer_rotation_registry(
                "web/github",
                rotation_interval_days=180,
            )

        self.assertTrue(result["configured"])
        self.assertEqual(result["homepage_url"], "https://github.com/login")
        self.assertEqual(result["rotation_interval_days"], 180)
        self.assertEqual(result["policy_source"], "inferred-from-current-password")
        self.assertEqual(result["policy_confidence"], "low")
        self.assertEqual(result["policy"]["length"], 9)
        self.assertEqual(result["policy"]["special_chars"], "!_-")
        self.assertEqual(upsert.call_args.args[0], "web/github@rotation-config")

    def test_list_rotation_registries_reports_due_status_and_filter(self) -> None:
        overdue_updated_at = (
            (datetime.now(UTC) - timedelta(days=190)).replace(microsecond=0).isoformat()
        )
        upcoming_updated_at = (
            (datetime.now(UTC) - timedelta(days=160)).replace(microsecond=0).isoformat()
        )
        with (
            patch(
                "auto_pass.rotation.list_keepassxc_entries",
                return_value=[
                    "web/github@rotation-config",
                    "web/gitlab@rotation-config",
                    "web/github",
                ],
            ),
            patch(
                "auto_pass.rotation.resolve_keepassxc_entry_all_fields",
                side_effect=[
                    {
                        "Notes": (
                            "{"
                            f'"entry":"web/github",'
                            f'"registry_entry":"web/github@rotation-config",'
                            f'"updated_at":"{overdue_updated_at}",'
                            '"rotation_interval_days":180,'
                            '"policy_source":"manual",'
                            '"policy_confidence":"high",'
                            '"schema_version":1'
                            "}"
                        )
                    },
                    {
                        "Notes": (
                            "{"
                            f'"entry":"web/gitlab",'
                            f'"registry_entry":"web/gitlab@rotation-config",'
                            f'"updated_at":"{upcoming_updated_at}",'
                            '"rotation_interval_days":180,'
                            '"policy_source":"inferred-from-current-password",'
                            '"policy_confidence":"low",'
                            '"schema_version":1'
                            "}"
                        )
                    },
                    {
                        "Notes": (
                            "{"
                            f'"entry":"web/github",'
                            f'"registry_entry":"web/github@rotation-config",'
                            f'"updated_at":"{overdue_updated_at}",'
                            '"rotation_interval_days":180,'
                            '"policy_source":"manual",'
                            '"policy_confidence":"high",'
                            '"schema_version":1'
                            "}"
                        )
                    },
                    {
                        "Notes": (
                            "{"
                            f'"entry":"web/gitlab",'
                            f'"registry_entry":"web/gitlab@rotation-config",'
                            f'"updated_at":"{upcoming_updated_at}",'
                            '"rotation_interval_days":180,'
                            '"policy_source":"inferred-from-current-password",'
                            '"policy_confidence":"low",'
                            '"schema_version":1'
                            "}"
                        )
                    },
                ],
            ),
        ):
            registries = list_rotation_registries()
            due_soon = list_rotation_registries(due_within_days=30)

        self.assertEqual([item["entry"] for item in registries], ["web/github", "web/gitlab"])
        self.assertEqual(registries[0]["due_status"], "overdue")
        self.assertLess(registries[0]["days_until_due"], 0)
        self.assertEqual(registries[1]["due_status"], "scheduled")
        self.assertGreaterEqual(registries[1]["days_until_due"], 0)
        self.assertEqual(due_soon, [registries[0], registries[1]])


if __name__ == "__main__":
    unittest.main()
