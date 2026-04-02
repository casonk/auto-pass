"""Integration tests using dyno-lab utilities.

Uses ``TempWorkdir`` from ``dyno_lab.fs`` and ``EnvPatch`` from ``dyno_lab.env``
to test auto-pass env-file loading, profile resolution, and KeePassXC helpers
without depending on real databases or real environment state.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dyno_lab.env import EnvPatch
from dyno_lab.fs import TempWorkdir

from auto_pass.envfile import (
    apply_keepass_profile_environment,
    load_config_environment,
    normalize_profile_name,
    parse_env_text,
)
from auto_pass.keepassxc import (
    KeepassXCStoreConfig,
    resolve_keepassxc_entry,
    seed_keepass_password_env_for_tty,
)


# ---------------------------------------------------------------------------
# Default env values used across keepassxc tests
# ---------------------------------------------------------------------------

_KEEPASS_ENV = {
    "AUTO_PASS_KEEPASSXC_DB_PATH": "/fake/db.kdbx",
    "AUTO_PASS_KEEPASSXC_DB_PASSWORD": "test-pass",
    "AUTO_PASS_KEEPASSXC_KEY_FILE": "",
    "PF_KEEPASSXC_DB_PATH": "",
    "PF_KEEPASSXC_DB_PASSWORD": "",
    "PF_KEEPASSXC_KEY_FILE": "",
}


# ---------------------------------------------------------------------------
# TempWorkdir — file-reading/writing tests
# ---------------------------------------------------------------------------

class TempWorkdirEnvFileTests(unittest.TestCase):
    """Tests that read/write env files using TempWorkdir."""

    def test_load_config_environment_parses_file_in_tempdir(self) -> None:
        with TempWorkdir() as wd:
            env_file = wd.write(
                "auto-pass.env.local",
                "\n".join([
                    "AUTO_PASS_PROFILE=staging",
                    "AUTO_PASS_PROFILE_STAGING_KEEPASSXC_DB_PATH=/mnt/vault/staging.kdbx",
                    "AUTO_PASS_PROFILE_STAGING_KEEPASSXC_DB_PASSWORD=staging-secret",
                    "",
                ]),
            )
            env: dict[str, str] = {}
            loaded, applied = load_config_environment(env_file, environ=env)

        self.assertEqual(loaded["AUTO_PASS_PROFILE"], "staging")
        self.assertEqual(env["AUTO_PASS_KEEPASSXC_DB_PATH"], "/mnt/vault/staging.kdbx")
        self.assertEqual(env["AUTO_PASS_KEEPASSXC_DB_PASSWORD"], "staging-secret")
        self.assertIn("AUTO_PASS_KEEPASSXC_DB_PASSWORD", applied)

    def test_load_config_environment_handles_key_file_line(self) -> None:
        with TempWorkdir() as wd:
            env_file = wd.write(
                "custom.env",
                "\n".join([
                    "AUTO_PASS_PROFILE=dev",
                    "AUTO_PASS_PROFILE_DEV_KEEPASSXC_DB_PATH=/dev/db.kdbx",
                    "AUTO_PASS_PROFILE_DEV_KEEPASSXC_DB_PASSWORD=dev-pass",
                    "AUTO_PASS_PROFILE_DEV_KEEPASSXC_KEY_FILE=/dev/keyfile.keyx",
                    "",
                ]),
            )
            env: dict[str, str] = {}
            load_config_environment(env_file, environ=env)

        self.assertEqual(env["AUTO_PASS_KEEPASSXC_KEY_FILE"], "/dev/keyfile.keyx")

    def test_seed_reads_password_from_cache_file_in_tempdir(self) -> None:
        with TempWorkdir() as wd:
            cache_file = wd.write(
                "keepass-cache.json",
                json.dumps({"password": "cached-secret"}) + "\n",
            )
            config = KeepassXCStoreConfig(
                database_password_cache_file=str(cache_file),
                database_password_cache_ttl_seconds=3600,
            )
            target_env = {**_KEEPASS_ENV, "AUTO_PASS_KEEPASSXC_DB_PASSWORD": ""}
            with EnvPatch(target_env):
                with patch(
                    "auto_pass.keepassxc.sys.stdin",
                    SimpleNamespace(isatty=lambda: False),
                ):
                    seed_keepass_password_env_for_tty(config)
                resolved = os.getenv("AUTO_PASS_KEEPASSXC_DB_PASSWORD", "")

        self.assertEqual(resolved, "cached-secret")

    def test_seed_writes_cache_file_on_tty_prompt(self) -> None:
        with TempWorkdir() as wd:
            cache_file = wd.path / "keepass-cache.json"
            config = KeepassXCStoreConfig(
                database_password_cache_file=str(cache_file),
                database_password_cache_ttl_seconds=3600,
            )
            target_env = {**_KEEPASS_ENV, "AUTO_PASS_KEEPASSXC_DB_PASSWORD": ""}
            with EnvPatch(target_env):
                with patch(
                    "auto_pass.keepassxc.sys.stdin",
                    SimpleNamespace(isatty=lambda: True),
                ):
                    with patch("auto_pass.keepassxc.getpass", return_value="prompted-pass"):
                        seed_keepass_password_env_for_tty(config)

            wd.assert_exists("keepass-cache.json")
            cached = json.loads(wd.read("keepass-cache.json"))

        self.assertEqual(cached.get("password"), "prompted-pass")

    def test_tempworkdir_assert_contains_matches_file_content(self) -> None:
        with TempWorkdir() as wd:
            wd.write(
                "auto-pass.env.local",
                "AUTO_PASS_PROFILE=myprofile\n",
            )
            wd.assert_contains("auto-pass.env.local", "AUTO_PASS_PROFILE=myprofile")


# ---------------------------------------------------------------------------
# EnvPatch — environment-variable-driven tests
# ---------------------------------------------------------------------------

class EnvPatchAutoPassTests(unittest.TestCase):
    """Tests that verify env-driven resolution using EnvPatch."""

    def test_apply_keepass_profile_environment_with_env_patch(self) -> None:
        profile_env = {
            "AUTO_PASS_PROFILE": "work",
            "AUTO_PASS_PROFILE_WORK_KEEPASSXC_DB_PATH": "/work/db.kdbx",
            "AUTO_PASS_PROFILE_WORK_KEEPASSXC_DB_PASSWORD": "work-pass",
            "AUTO_PASS_PROFILE_WORK_KEEPASSXC_KEY_FILE": "",
        }
        # apply_keepass_profile_environment works on the dict passed in,
        # so we provide an isolated copy — EnvPatch is used to mirror what
        # the function would read from os.environ in a real session.
        with EnvPatch(profile_env):
            env_copy = dict(os.environ)
            applied = apply_keepass_profile_environment(env_copy)

        self.assertEqual(env_copy["AUTO_PASS_KEEPASSXC_DB_PATH"], "/work/db.kdbx")
        self.assertEqual(env_copy["AUTO_PASS_KEEPASSXC_DB_PASSWORD"], "work-pass")
        self.assertIn("AUTO_PASS_KEEPASSXC_DB_PATH", applied)

    def test_resolve_keepassxc_entry_reads_db_path_from_env(self) -> None:
        captured_cmds: list[list[str]] = []

        def fake_run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
            captured_cmds.append(list(cmd))
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="user\npass\n", stderr=""
            )

        with EnvPatch(_KEEPASS_ENV):
            with patch("auto_pass.keepassxc.subprocess.run", side_effect=fake_run):
                resolved = resolve_keepassxc_entry(
                    "web/myapp", attrs_map={"username": "un", "password": "pw"}
                )

        # The db path from env should appear in the keepassxc-cli invocation
        self.assertTrue(
            any("/fake/db.kdbx" in arg for cmd in captured_cmds for arg in cmd),
            msg=f"db path not found in captured commands: {captured_cmds}",
        )

    def test_resolve_keepassxc_entry_sends_password_via_stdin(self) -> None:
        stdin_inputs: list[str] = []

        def fake_run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
            stdin_inputs.append(kwargs.get("input", ""))
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="alice\nhunter2\n", stderr=""
            )

        with EnvPatch(_KEEPASS_ENV):
            with patch("auto_pass.keepassxc.subprocess.run", side_effect=fake_run):
                resolve_keepassxc_entry(
                    "web/myapp", attrs_map={"username": "un", "password": "pw"}
                )

        # The db password must be delivered via stdin to keepassxc-cli
        self.assertTrue(
            any("test-pass" in inp for inp in stdin_inputs),
            msg=f"db password not found in stdin inputs: {stdin_inputs}",
        )

    def test_normalize_profile_name_via_env_patch_value(self) -> None:
        with EnvPatch({"AUTO_PASS_PROFILE": "my-work-laptop"}):
            raw_profile = os.environ["AUTO_PASS_PROFILE"]
            normalized = normalize_profile_name(raw_profile)
        self.assertEqual(normalized, "MY_WORK_LAPTOP")

    def test_env_patch_restores_previous_value_on_exit(self) -> None:
        original = os.environ.get("AUTO_PASS_KEEPASSXC_DB_PATH", "__unset__")
        with EnvPatch({"AUTO_PASS_KEEPASSXC_DB_PATH": "/temporary/override.kdbx"}):
            inside = os.environ.get("AUTO_PASS_KEEPASSXC_DB_PATH")
        after = os.environ.get("AUTO_PASS_KEEPASSXC_DB_PATH", "__unset__")

        self.assertEqual(inside, "/temporary/override.kdbx")
        self.assertEqual(after, original)


if __name__ == "__main__":
    unittest.main()
