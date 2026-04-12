from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from auto_pass.envfile import (
    EnvFileError,
    activate_keepass_profile,
    apply_keepass_profile_environment,
    get_active_keepass_profile,
    list_keepass_profiles,
    load_config_environment,
    normalize_profile_name,
    parse_env_text,
)


class EnvFileTests(unittest.TestCase):
    def test_parse_env_text_supports_export_and_quotes(self) -> None:
        parsed = parse_env_text(
            """
            # comment
            export AUTO_PASS_PROFILE=work
            AUTO_PASS_PROFILE_WORK_KEEPASSXC_DB_PATH="/tmp/work db.kdbx"
            AUTO_PASS_PROFILE_WORK_KEEPASSXC_DB_PASSWORD='secret value'
            """
        )

        self.assertEqual(parsed["AUTO_PASS_PROFILE"], "work")
        self.assertEqual(
            parsed["AUTO_PASS_PROFILE_WORK_KEEPASSXC_DB_PATH"],
            "/tmp/work db.kdbx",
        )
        self.assertEqual(
            parsed["AUTO_PASS_PROFILE_WORK_KEEPASSXC_DB_PASSWORD"],
            "secret value",
        )

    def test_apply_keepass_profile_environment_sets_active_profile(self) -> None:
        env = {
            "AUTO_PASS_PROFILE": "work",
            "AUTO_PASS_PROFILE_WORK_KEEPASSXC_DB_PATH": "/tmp/work.kdbx",
            "AUTO_PASS_PROFILE_WORK_KEEPASSXC_DB_PASSWORD": "secret",
            "AUTO_PASS_PROFILE_WORK_KEEPASSXC_KEY_FILE": "/tmp/work.keyx",
        }

        applied = apply_keepass_profile_environment(env)

        self.assertEqual(env["AUTO_PASS_KEEPASSXC_DB_PATH"], "/tmp/work.kdbx")
        self.assertEqual(env["AUTO_PASS_KEEPASSXC_DB_PASSWORD"], "secret")
        self.assertEqual(env["AUTO_PASS_KEEPASSXC_KEY_FILE"], "/tmp/work.keyx")
        self.assertIn("AUTO_PASS_KEEPASSXC_DB_PATH", applied)

    def test_load_config_environment_loads_file_then_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "auto-pass.env.local"
            env_file.write_text(
                "\n".join(
                    [
                        "AUTO_PASS_PROFILE=infra",
                        "AUTO_PASS_PROFILE_INFRA_KEEPASSXC_DB_PATH=/tmp/infra.kdbx",
                        "AUTO_PASS_PROFILE_INFRA_KEEPASSXC_DB_PASSWORD=infra-secret",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            env: dict[str, str] = {}

            loaded, applied = load_config_environment(env_file, environ=env)

        self.assertEqual(loaded["AUTO_PASS_PROFILE"], "infra")
        self.assertEqual(env["AUTO_PASS_KEEPASSXC_DB_PATH"], "/tmp/infra.kdbx")
        self.assertEqual(env["AUTO_PASS_KEEPASSXC_DB_PASSWORD"], "infra-secret")
        self.assertIn("AUTO_PASS_KEEPASSXC_DB_PASSWORD", applied)

    def test_load_config_environment_profile_override_wins_over_file_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "auto-pass.env.local"
            env_file.write_text(
                "\n".join(
                    [
                        "AUTO_PASS_PROFILE=personal",
                        "AUTO_PASS_PROFILE_PERSONAL_KEEPASSXC_DB_PATH=/tmp/personal.kdbx",
                        "AUTO_PASS_PROFILE_PERSONAL_KEEPASSXC_DB_PASSWORD=personal-secret",
                        "AUTO_PASS_PROFILE_WORK_KEEPASSXC_DB_PATH=/tmp/work.kdbx",
                        "AUTO_PASS_PROFILE_WORK_KEEPASSXC_DB_PASSWORD=work-secret",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            env: dict[str, str] = {}

            loaded, applied = load_config_environment(
                env_file,
                profile="work",
                environ=env,
            )

        self.assertEqual(loaded["AUTO_PASS_PROFILE"], "personal")
        self.assertEqual(env["AUTO_PASS_PROFILE"], "work")
        self.assertEqual(env["AUTO_PASS_KEEPASSXC_DB_PATH"], "/tmp/work.kdbx")
        self.assertEqual(env["AUTO_PASS_KEEPASSXC_DB_PASSWORD"], "work-secret")
        self.assertIn("AUTO_PASS_KEEPASSXC_DB_PASSWORD", applied)

    def test_activate_keepass_profile_rejects_blank_value(self) -> None:
        with self.assertRaises(EnvFileError):
            activate_keepass_profile("   ", environ={})

    def test_get_active_keepass_profile_normalizes_to_lowercase(self) -> None:
        self.assertEqual(
            get_active_keepass_profile({"AUTO_PASS_PROFILE": "work-laptop"}),
            "work_laptop",
        )

    def test_list_keepass_profiles_returns_sorted_profiles_with_db_paths(self) -> None:
        env = {
            "AUTO_PASS_PROFILE_WORK_KEEPASSXC_DB_PATH": "/tmp/work.kdbx",
            "AUTO_PASS_PROFILE_INFRA_KEEPASSXC_DB_PATH": "/tmp/infra.kdbx",
            "AUTO_PASS_PROFILE_EMPTY_KEEPASSXC_DB_PATH": "",
            "AUTO_PASS_PROFILE_WORK_KEEPASSXC_DB_PASSWORD": "secret",
        }

        self.assertEqual(list_keepass_profiles(env), ["infra", "work"])

    def test_normalize_profile_name(self) -> None:
        self.assertEqual(normalize_profile_name("work-laptop"), "WORK_LAPTOP")


if __name__ == "__main__":
    unittest.main()
