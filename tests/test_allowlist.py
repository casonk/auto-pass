from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from auto_pass.allowlist import AllowlistEnforcer, resolve_caller_repo


def _write(path: Path, content: str) -> None:
    path.write_bytes(content.encode())


class TestAllowlistEnforcer:
    def test_missing_file_denies_everything(self, tmp_path):
        e = AllowlistEnforcer(tmp_path / "nonexistent.toml")
        assert not e.is_permitted("any-repo", "testdb", "any/path")

    def test_empty_repos_table_denies_everything(self, tmp_path):
        p = tmp_path / "al.toml"
        _write(p, "[repos]\n")
        e = AllowlistEnforcer(p)
        assert not e.is_permitted("any-repo", "testdb", "any/path")

    def test_exact_path_permitted(self, tmp_path):
        p = tmp_path / "al.toml"
        _write(p, '[repos.myrepo]\ndb = "testdb"\nallowed_paths = ["web/github"]\n')
        e = AllowlistEnforcer(p)
        assert e.is_permitted("myrepo", "testdb", "web/github")

    def test_exact_path_not_permitted_for_other_path(self, tmp_path):
        p = tmp_path / "al.toml"
        _write(p, '[repos.myrepo]\ndb = "testdb"\nallowed_paths = ["web/github"]\n')
        e = AllowlistEnforcer(p)
        assert not e.is_permitted("myrepo", "testdb", "web/gitlab")

    def test_wrong_db_denied_even_if_path_matches(self, tmp_path):
        p = tmp_path / "al.toml"
        _write(p, '[repos.myrepo]\ndb = "testdb"\nallowed_paths = ["web/github"]\n')
        e = AllowlistEnforcer(p)
        assert not e.is_permitted("myrepo", "otherdb", "web/github")

    def test_glob_wildcard_matches_children(self, tmp_path):
        p = tmp_path / "al.toml"
        _write(p, '[repos.myrepo]\ndb = "testdb"\nallowed_paths = ["infra/*"]\n')
        e = AllowlistEnforcer(p)
        assert e.is_permitted("myrepo", "testdb", "infra/nordvpn")
        assert e.is_permitted("myrepo", "testdb", "infra/aws")
        assert not e.is_permitted("myrepo", "testdb", "web/github")

    def test_unknown_repo_denied_even_if_path_matches_another_repo(self, tmp_path):
        p = tmp_path / "al.toml"
        _write(p, '[repos.other]\ndb = "testdb"\nallowed_paths = ["*"]\n')
        e = AllowlistEnforcer(p)
        assert not e.is_permitted("myrepo", "testdb", "web/github")

    def test_multiple_patterns_any_match_permits(self, tmp_path):
        p = tmp_path / "al.toml"
        _write(p, '[repos.r]\ndb = "testdb"\nallowed_paths = ["a/b", "c/d"]\n')
        e = AllowlistEnforcer(p)
        assert e.is_permitted("r", "testdb", "a/b")
        assert e.is_permitted("r", "testdb", "c/d")
        assert not e.is_permitted("r", "testdb", "a/c")

    def test_empty_allowed_paths_denies_everything(self, tmp_path):
        p = tmp_path / "al.toml"
        _write(p, '[repos.r]\ndb = "testdb"\nallowed_paths = []\n')
        e = AllowlistEnforcer(p)
        assert not e.is_permitted("r", "testdb", "anything")

    def test_known_repos_sorted(self, tmp_path):
        p = tmp_path / "al.toml"
        _write(
            p,
            '[repos.zebra]\ndb = "testdb"\nallowed_paths = []\n'
            '[repos.alpha]\ndb = "testdb"\nallowed_paths = []\n',
        )
        e = AllowlistEnforcer(p)
        assert e.known_repos() == ["alpha", "zebra"]

    def test_permitted_paths_returns_patterns(self, tmp_path):
        p = tmp_path / "al.toml"
        _write(p, '[repos.r]\ndb = "testdb"\nallowed_paths = ["a/b", "c/*"]\n')
        e = AllowlistEnforcer(p)
        assert e.permitted_paths("r", "testdb") == ["a/b", "c/*"]

    def test_permitted_paths_wrong_db_returns_empty(self, tmp_path):
        p = tmp_path / "al.toml"
        _write(p, '[repos.r]\ndb = "testdb"\nallowed_paths = ["a/b"]\n')
        e = AllowlistEnforcer(p)
        assert e.permitted_paths("r", "otherdb") == []

    def test_reload_picks_up_new_content(self, tmp_path):
        p = tmp_path / "al.toml"
        _write(p, '[repos.old]\ndb = "testdb"\nallowed_paths = ["x/y"]\n')
        e = AllowlistEnforcer(p)
        assert e.is_permitted("old", "testdb", "x/y")

        _write(p, '[repos.new]\ndb = "testdb"\nallowed_paths = ["a/b"]\n')
        e.reload()
        assert not e.is_permitted("old", "testdb", "x/y")
        assert e.is_permitted("new", "testdb", "a/b")

    def test_repo_default_db_simple_form(self, tmp_path):
        p = tmp_path / "al.toml"
        _write(p, '[repos.r]\ndb = "infra"\nallowed_paths = ["x/y"]\n')
        e = AllowlistEnforcer(p)
        assert e.repo_default_db("r") == "infra"

    def test_repo_default_db_multi_vault_returns_none(self, tmp_path):
        p = tmp_path / "al.toml"
        _write(
            p,
            '[repos.r.vaults.master]\nallowed_paths = ["a/b"]\n'
            '[repos.r.vaults.infra]\nallowed_paths = ["c/d"]\n',
        )
        e = AllowlistEnforcer(p)
        assert e.repo_default_db("r") is None

    def test_multi_vault_form_permitted(self, tmp_path):
        p = tmp_path / "al.toml"
        _write(
            p,
            '[repos.r.vaults.master]\nallowed_paths = ["a/b"]\n'
            '[repos.r.vaults.infra]\nallowed_paths = ["c/d"]\n',
        )
        e = AllowlistEnforcer(p)
        assert e.is_permitted("r", "master", "a/b")
        assert e.is_permitted("r", "infra", "c/d")
        assert not e.is_permitted("r", "master", "c/d")
        assert not e.is_permitted("r", "infra", "a/b")
        assert not e.is_permitted("r", "other", "a/b")

    def test_repo_vaults_simple_form(self, tmp_path):
        p = tmp_path / "al.toml"
        _write(p, '[repos.r]\ndb = "infra"\nallowed_paths = ["x"]\n')
        e = AllowlistEnforcer(p)
        assert e.repo_vaults("r") == ["infra"]

    def test_repo_vaults_multi_form(self, tmp_path):
        p = tmp_path / "al.toml"
        _write(
            p,
            '[repos.r.vaults.master]\nallowed_paths = ["a"]\n'
            '[repos.r.vaults.infra]\nallowed_paths = ["b"]\n',
        )
        e = AllowlistEnforcer(p)
        assert e.repo_vaults("r") == ["infra", "master"]


class TestResolveCallerRepo:
    def test_returns_none_for_unreadable_proc_entry(self):
        result = resolve_caller_repo(pid=999999999)
        assert result is None

    def test_returns_repo_name_from_git_remote(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        with (
            patch("auto_pass.allowlist.os.readlink", return_value=str(tmp_path)),
            patch(
                "auto_pass.allowlist._git_remote_name",
                return_value="my-repo",
            ),
        ):
            result = resolve_caller_repo(pid=1)
        assert result == "my-repo"

    def test_falls_back_to_dir_name_when_no_remote(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        with (
            patch("auto_pass.allowlist.os.readlink", return_value=str(tmp_path)),
            patch("auto_pass.allowlist._git_remote_name", return_value=None),
            patch.dict("auto_pass.allowlist._repo_root_cache", {}, clear=True),
        ):
            result = resolve_caller_repo(pid=1)
        assert result == tmp_path.name

    def test_returns_none_when_no_git_root(self, tmp_path):
        non_git = tmp_path / "not-a-repo"
        non_git.mkdir()

        with patch("auto_pass.allowlist.os.readlink", return_value=str(non_git)):
            result = resolve_caller_repo(pid=1)
        assert result is None
