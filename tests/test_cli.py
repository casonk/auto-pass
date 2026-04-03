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


if __name__ == "__main__":
    unittest.main()
