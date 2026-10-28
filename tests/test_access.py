from __future__ import annotations

import io
import json
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from auto_pass import access
from auto_pass.cli import main


class VaultAccessTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def vault(self, name: str, mode: int = 0o600) -> Path:
        path = self.root / name
        path.write_bytes(b"kdbx")
        path.chmod(mode)
        self.addCleanup(path.chmod, 0o600)
        return path

    def test_vault_paths_reads_profiles_and_the_default_once(self) -> None:
        a, b = self.vault("a.kdbx"), self.vault("b.kdbx")
        env = {
            "AUTO_PASS_PROFILE_MASTER_KEEPASSXC_DB_PATH": str(a),
            "AUTO_PASS_PROFILE_INFRA_KEEPASSXC_DB_PATH": str(b),
            "AUTO_PASS_KEEPASSXC_DB_PATH": str(a),  # already covered by a profile
        }

        self.assertEqual(access.vault_paths(env), {"infra": b, "master": a})
        self.assertEqual(
            access.vault_paths({"AUTO_PASS_KEEPASSXC_DB_PATH": str(a)}), {"default": a}
        )

    def test_a_readable_writable_vault_has_no_findings(self) -> None:
        self.assertEqual(access.check_vaults({"master": self.vault("ok.kdbx")}), [])

    def test_missing_unreadable_and_read_only_vaults_are_named(self) -> None:
        unreadable = self.vault("locked.kdbx", 0o000)
        read_only = self.vault("ro.kdbx", 0o400)
        findings = access.check_vaults(
            {"gone": self.root / "gone.kdbx", "locked": unreadable, "ro": read_only}
        )

        problems = {f.label: f.problem for f in findings}
        self.assertEqual(problems, {"gone": "missing", "locked": "unreadable", "ro": "read-only"})
        # A file we own is fixed with chmod; no sudo is suggested for it.
        self.assertTrue(all("sudo" not in f.hint for f in findings if f.label != "gone"))

    def test_a_file_owned_by_someone_else_gets_a_setfacl_hint(self) -> None:
        path = self.vault("other.kdbx", 0o000)
        with patch.object(access, "_owner", return_value="snowbridge"):
            (finding,) = access.check_vaults({"master": path}, login="user")

        self.assertEqual(finding.hint, f"sudo setfacl -m u:user:rw {path}")

    def test_cli_exits_nonzero_and_prints_the_fix(self) -> None:
        locked = self.vault("locked.kdbx", 0o000)
        env = {"AUTO_PASS_PROFILE_MASTER_KEEPASSXC_DB_PATH": str(locked)}
        out = io.StringIO()
        with (
            patch("auto_pass.cli.load_config_environment"),
            patch.dict("os.environ", env, clear=True),
            redirect_stdout(out),
        ):
            code = main(["--no-env-file", "check-access", "--json"])

        self.assertEqual(code, 1)
        (row,) = json.loads(out.getvalue())
        self.assertEqual((row["vault"], row["problem"]), ("master", "unreadable"))

    def test_cli_is_quiet_success_when_every_vault_is_usable(self) -> None:
        ok = self.vault("ok.kdbx")
        env = {"AUTO_PASS_PROFILE_MASTER_KEEPASSXC_DB_PATH": str(ok)}
        out = io.StringIO()
        with patch.dict("os.environ", env, clear=True), redirect_stdout(out):
            code = main(["--no-env-file", "check-access"])

        self.assertEqual(code, 0)
        self.assertIn("ok: 1 vault(s)", out.getvalue())
        self.assertEqual(stat.S_IMODE(ok.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
