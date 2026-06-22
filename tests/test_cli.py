from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from auto_pass.cli import DEFAULT_ENV_FILE, main


class CliProfileTests(unittest.TestCase):
    def test_main_passes_profile_override_into_config_loader(self) -> None:
        stdout = io.StringIO()
        with (
            patch("auto_pass.cli.load_config_environment") as load_config_environment,
            patch(
                "auto_pass.cli.resolve_keepassxc_entry",
                return_value={"username": "octocat"},
            ) as resolve_keepassxc_entry,
            redirect_stdout(stdout),
        ):
            rc = main(["--profile", "work", "get", "web/github", "--field", "username"])

        self.assertEqual(rc, 0)
        load_config_environment.assert_called_once_with(
            str(DEFAULT_ENV_FILE),
            profile="work",
        )
        resolve_keepassxc_entry.assert_called_once_with(
            entry="web/github",
            attrs_map={"username": "username"},
            allow_interactive=False,
        )
        self.assertEqual(stdout.getvalue(), "octocat\n")

    def test_main_applies_profile_without_env_file_loading(self) -> None:
        stdout = io.StringIO()
        with (
            patch("auto_pass.cli.load_config_environment") as load_config_environment,
            patch("auto_pass.cli.activate_keepass_profile") as activate_keepass_profile,
            patch(
                "auto_pass.cli.apply_keepass_profile_environment",
            ) as apply_keepass_profile_environment,
            patch(
                "auto_pass.cli.resolve_keepassxc_entry",
                return_value={"username": "octocat"},
            ),
            redirect_stdout(stdout),
        ):
            rc = main(
                [
                    "--no-env-file",
                    "--profile",
                    "work",
                    "get",
                    "web/github",
                    "--field",
                    "username",
                ]
            )

        self.assertEqual(rc, 0)
        load_config_environment.assert_not_called()
        activate_keepass_profile.assert_called_once_with("work")
        apply_keepass_profile_environment.assert_called_once_with()
        self.assertEqual(stdout.getvalue(), "octocat\n")

    def test_list_profiles_prints_active_profile_with_marker(self) -> None:
        stdout = io.StringIO()
        with (
            patch("auto_pass.cli.load_config_environment"),
            patch("auto_pass.cli.get_active_keepass_profile", return_value="work"),
            patch("auto_pass.cli.list_keepass_profiles", return_value=["infra", "work"]),
            redirect_stdout(stdout),
        ):
            rc = main(["list-profiles"])

        self.assertEqual(rc, 0)
        self.assertEqual(stdout.getvalue().splitlines(), ["  infra", "* work"])

    def test_list_profiles_can_emit_json(self) -> None:
        stdout = io.StringIO()
        with (
            patch("auto_pass.cli.load_config_environment"),
            patch("auto_pass.cli.get_active_keepass_profile", return_value="infra"),
            patch("auto_pass.cli.list_keepass_profiles", return_value=["infra", "master"]),
            redirect_stdout(stdout),
        ):
            rc = main(["list-profiles", "--json"])

        self.assertEqual(rc, 0)
        self.assertEqual(
            stdout.getvalue(),
            '{\n  "active_profile": "infra",\n  "profiles": [\n    "infra",\n    "master"\n  ]\n}\n',
        )

    def test_rotate_prepare_dispatches_password_policy(self) -> None:
        stdout = io.StringIO()
        with (
            patch("auto_pass.cli.load_config_environment"),
            patch("auto_pass.cli.prepare_rotation") as prepare_rotation,
            redirect_stdout(stdout),
        ):
            prepare_rotation.return_value = {
                "entry": "web/github",
                "pending": True,
                "pending_entry": "web/github@rotation-pending",
                "length": 28,
            }
            rc = main(
                [
                    "rotate",
                    "prepare",
                    "web/github",
                    "--length",
                    "28",
                    "--reset-url",
                    "https://github.com/settings/security",
                    "--no-special",
                ]
            )

        self.assertEqual(rc, 0)
        prepare_rotation.assert_called_once()
        policy = prepare_rotation.call_args.kwargs["policy"]
        self.assertEqual(policy.length, 28)
        self.assertFalse(policy.special)
        self.assertEqual(
            prepare_rotation.call_args.kwargs["reset_url"],
            "https://github.com/settings/security",
        )
        self.assertIn("pending_entry=web/github@rotation-pending", stdout.getvalue())

    def test_rotate_prepare_uses_registry_defaults_when_flags_omitted(self) -> None:
        stdout = io.StringIO()
        with (
            patch("auto_pass.cli.load_config_environment"),
            patch("auto_pass.cli.prepare_rotation") as prepare_rotation,
            redirect_stdout(stdout),
        ):
            prepare_rotation.return_value = {
                "entry": "web/github",
                "pending": True,
                "pending_entry": "web/github@rotation-pending",
            }
            rc = main(["rotate", "prepare", "web/github"])

        self.assertEqual(rc, 0)
        self.assertIsNone(prepare_rotation.call_args.kwargs["policy"])
        self.assertIsNone(prepare_rotation.call_args.kwargs["homepage_url"])
        self.assertIsNone(prepare_rotation.call_args.kwargs["reset_url"])

    def test_rotate_configure_dispatches_registry_update(self) -> None:
        stdout = io.StringIO()
        with (
            patch("auto_pass.cli.load_config_environment"),
            patch("auto_pass.cli.configure_rotation_registry") as configure_rotation_registry,
            redirect_stdout(stdout),
        ):
            configure_rotation_registry.return_value = {
                "entry": "web/github",
                "configured": True,
                "registry_entry": "web/github@rotation-config",
            }
            rc = main(
                [
                    "rotate",
                    "configure",
                    "web/github",
                    "--length",
                    "30",
                    "--homepage-url",
                    "https://github.com/login",
                    "--rotation-interval-days",
                    "90",
                ]
            )

        self.assertEqual(rc, 0)
        policy = configure_rotation_registry.call_args.kwargs["policy"]
        self.assertEqual(policy.length, 30)
        self.assertEqual(
            configure_rotation_registry.call_args.kwargs["rotation_interval_days"],
            90,
        )
        self.assertIn("registry_entry=web/github@rotation-config", stdout.getvalue())

    def test_rotate_status_can_emit_json(self) -> None:
        stdout = io.StringIO()
        with (
            patch("auto_pass.cli.load_config_environment"),
            patch(
                "auto_pass.cli.rotation_status",
                return_value={"entry": "web/github", "pending": False},
            ),
            redirect_stdout(stdout),
        ):
            rc = main(["rotate", "status", "web/github", "--json"])

        self.assertEqual(rc, 0)
        self.assertEqual(stdout.getvalue(), '{\n  "entry": "web/github",\n  "pending": false\n}\n')

    def test_rotate_show_config_can_emit_json(self) -> None:
        stdout = io.StringIO()
        with (
            patch("auto_pass.cli.load_config_environment"),
            patch(
                "auto_pass.cli.rotation_registry_status",
                return_value={"entry": "web/github", "configured": False},
            ),
            redirect_stdout(stdout),
        ):
            rc = main(["rotate", "show-config", "web/github", "--json"])

        self.assertEqual(rc, 0)
        self.assertEqual(
            stdout.getvalue(),
            '{\n  "configured": false,\n  "entry": "web/github"\n}\n',
        )

    def test_rotate_infer_config_dispatches_registry_inference(self) -> None:
        stdout = io.StringIO()
        with (
            patch("auto_pass.cli.load_config_environment"),
            patch("auto_pass.cli.infer_rotation_registry") as infer_rotation_registry,
            redirect_stdout(stdout),
        ):
            infer_rotation_registry.return_value = {
                "entry": "web/github",
                "configured": True,
                "registry_entry": "web/github@rotation-config",
                "policy_source": "inferred-from-current-password",
            }
            rc = main(
                [
                    "rotate",
                    "infer-config",
                    "web/github",
                    "--rotation-interval-days",
                    "180",
                ]
            )

        self.assertEqual(rc, 0)
        self.assertEqual(
            infer_rotation_registry.call_args.kwargs["rotation_interval_days"],
            180,
        )
        self.assertIn("policy_source=inferred-from-current-password", stdout.getvalue())

    def test_rotate_list_configs_prints_due_summary(self) -> None:
        stdout = io.StringIO()
        with (
            patch("auto_pass.cli.load_config_environment"),
            patch(
                "auto_pass.cli.list_rotation_registries",
                return_value=[
                    {
                        "entry": "web/github",
                        "due_status": "overdue",
                        "days_until_due": -10,
                        "policy_source": "manual",
                    }
                ],
            ) as list_rotation_registries,
            redirect_stdout(stdout),
        ):
            rc = main(["rotate", "list-configs", "--due-within-days", "30"])

        self.assertEqual(rc, 0)
        self.assertEqual(
            list_rotation_registries.call_args.kwargs["due_within_days"],
            30,
        )
        self.assertIn("web/github", stdout.getvalue())
        self.assertIn("due_status=overdue", stdout.getvalue())

    def test_rotate_sync_todo_dispatches_clockwork_sync(self) -> None:
        stdout = io.StringIO()
        with (
            patch("auto_pass.cli.load_config_environment"),
            patch("auto_pass.cli.sync_rotation_todo") as sync_rotation_todo,
            redirect_stdout(stdout),
        ):
            sync_rotation_todo.return_value = {
                "todo_file": "/tmp/todo.json",
                "category": "Password Rotation",
                "item_count": 2,
            }
            rc = main(
                [
                    "rotate",
                    "sync-todo",
                    "--todo-file",
                    "/tmp/todo.json",
                    "--due-within-days",
                    "14",
                ]
            )

        self.assertEqual(rc, 0)
        self.assertEqual(sync_rotation_todo.call_args.args[0], "/tmp/todo.json")
        self.assertEqual(sync_rotation_todo.call_args.kwargs["due_within_days"], 14)
        self.assertIn("item_count=2", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
