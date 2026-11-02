"""Edges of the authorization inputs: caller identity, the allowlist file, vault access, the index.

Whatever these cannot read or understand must end in a refusal, never in a permission: an
unreadable or corrupt allowlist grants nothing, a caller that is not in a git repository has no
identity, and a damaged database index is an error rather than an empty set of vaults.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from auto_pass import access, allowlist, dbindex
from auto_pass.allowlist import AllowlistEnforcer

# --------------------------------------------------------------------------- caller identity


def completed(stdout="", returncode=0):
    return SimpleNamespace(stdout=stdout, stderr="", returncode=returncode)


@pytest.mark.parametrize(
    ("url", "name"),
    [
        ("git@github.com:owner/my-repo.git\n", "my-repo"),
        ("https://github.com/owner/my-repo.git", "my-repo"),
        ("https://github.com/owner/my-repo/", "my-repo"),
        ("https://github.com/owner/my-repo", "my-repo"),
        ("ssh://git@host/a/b/c.git", "c"),
    ],
)
def test_the_repo_name_is_the_last_part_of_the_origin_url(monkeypatch, tmp_path, url, name):
    monkeypatch.setattr(allowlist.subprocess, "run", lambda *a, **k: completed(url))
    assert allowlist._git_remote_name(tmp_path) == name


@pytest.mark.parametrize(
    "outcome", [completed("", 0), completed("x", 1), completed("   \n", 0), completed(".git", 0)]
)
def test_no_usable_origin_means_no_name(monkeypatch, tmp_path, outcome):
    monkeypatch.setattr(allowlist.subprocess, "run", lambda *a, **k: outcome)
    assert allowlist._git_remote_name(tmp_path) is None


@pytest.mark.parametrize(
    "error", [FileNotFoundError("git"), subprocess.TimeoutExpired("git", 5), OSError("boom")]
)
def test_a_git_that_fails_or_is_missing_means_no_name(monkeypatch, tmp_path, error):
    def run(*args, **kwargs):
        raise error

    monkeypatch.setattr(allowlist.subprocess, "run", run)
    assert allowlist._git_remote_name(tmp_path) is None


def test_the_git_root_is_found_by_walking_up(tmp_path):
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    deep = tmp_path / "repo" / "a" / "b"
    deep.mkdir(parents=True)
    assert allowlist._find_git_root(deep) == (tmp_path / "repo").resolve()
    assert allowlist._find_git_root(tmp_path / "repo") == (tmp_path / "repo").resolve()


def test_a_directory_with_no_git_root_above_it_has_none(tmp_path, monkeypatch):
    # the walk reaches "/", and some machines have a stray /tmp/.git, so hide every .git
    original = Path.exists
    monkeypatch.setattr(
        Path, "exists", lambda self: False if self.name == ".git" else original(self)
    )
    lonely = tmp_path / "elsewhere"
    lonely.mkdir()
    assert allowlist._find_git_root(lonely) is None


def test_a_worktree_style_dot_git_file_also_marks_a_root(tmp_path):
    (tmp_path / "wt").mkdir()
    (tmp_path / "wt" / ".git").write_text("gitdir: /elsewhere", encoding="utf-8")
    assert allowlist._find_git_root(tmp_path / "wt") == (tmp_path / "wt").resolve()


def test_the_caller_lookup_is_cached_per_repo_root(monkeypatch, tmp_path):
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    monkeypatch.setattr(allowlist.os, "readlink", lambda path: str(tmp_path / "repo"))
    monkeypatch.setattr(allowlist, "_repo_root_cache", {})
    calls = []
    monkeypatch.setattr(allowlist, "_git_remote_name", lambda root: calls.append(root) or "named")
    assert allowlist.resolve_caller_repo(1) == "named"
    assert allowlist.resolve_caller_repo(2) == "named"
    assert len(calls) == 1


def test_a_process_with_no_readable_cwd_has_no_identity(monkeypatch):
    def readlink(path):
        raise PermissionError(path)

    monkeypatch.setattr(allowlist.os, "readlink", readlink)
    assert allowlist.resolve_caller_repo(1) is None


def test_the_directory_name_is_the_identity_when_there_is_no_remote(monkeypatch, tmp_path):
    (tmp_path / "fallback-name" / ".git").mkdir(parents=True)
    monkeypatch.setattr(allowlist.os, "readlink", lambda path: str(tmp_path / "fallback-name"))
    monkeypatch.setattr(allowlist, "_repo_root_cache", {})
    monkeypatch.setattr(allowlist, "_git_remote_name", lambda root: None)
    assert allowlist.resolve_caller_repo(1) == "fallback-name"


# --------------------------------------------------------------------------- the allowlist file


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "allowlist.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_a_missing_allowlist_denies_everything_and_a_later_file_is_picked_up_on_reload(tmp_path):
    path = tmp_path / "allowlist.toml"
    enforcer = AllowlistEnforcer(path)
    assert not enforcer.is_permitted("r", "master", "x") and enforcer.known_repos() == []
    path.write_text('[repos.r]\ndb = "master"\nallowed_paths = ["x"]\n', encoding="utf-8")
    enforcer.reload()
    assert enforcer.is_permitted("r", "master", "x")


def test_a_corrupt_allowlist_on_reload_fails_closed(tmp_path):
    path = write(tmp_path, '[repos.r]\ndb = "master"\nallowed_paths = ["x"]\n')
    enforcer = AllowlistEnforcer(path)
    assert enforcer.is_permitted("r", "master", "x")
    path.write_text("[repos.r\nbroken", encoding="utf-8")
    with pytest.raises(Exception):  # noqa: B017, PT011 - tomllib.TOMLDecodeError
        enforcer.reload()
    # the old permissions must not survive a reload that could not read the new file
    assert not enforcer.is_permitted("r", "master", "x")
    assert enforcer.known_repos() == []


def test_an_allowlist_that_is_not_readable_toml_stops_the_daemon_at_start(tmp_path):
    with pytest.raises(Exception):  # noqa: B017, PT011
        AllowlistEnforcer(write(tmp_path, "not = [toml"))


@pytest.mark.parametrize(
    ("pattern", "entry", "allowed"),
    [
        ("web/*", "web/github", True),
        ("web/*", "web/a/b", True),
        ("web/*", "web", False),
        ("web/*", "webx/y", False),
        ("a?c", "abc", True),
        ("a?c", "ac", False),
        ("[ab]x", "ax", True),
        ("[ab]x", "cx", False),
        ("*", "anything/at/all", True),
        ("exact#field", "exact#field", True),
        ("exact#field", "exact#other", False),
        ("Web/*", "web/x", False),
    ],
)
def test_entry_patterns_are_shell_globs_and_case_sensitive(tmp_path, pattern, entry, allowed):
    enforcer = AllowlistEnforcer(
        write(tmp_path, f'[repos.r]\ndb = "m"\nallowed_paths = [{json.dumps(pattern)}]\n')
    )
    assert enforcer.is_permitted("r", "m", entry) is allowed


def test_a_repo_with_neither_form_or_no_paths_is_never_permitted(tmp_path):
    path = write(
        tmp_path,
        '[repos.bare]\nnote = "nothing"\n[repos.none]\ndb = "m"\nallowed_paths = []\n'
        "[repos.emptyvault.vaults.m]\nallowed_paths = []\n[repos.novault.vaults]\n",
    )
    enforcer = AllowlistEnforcer(path)
    for repo in ("bare", "none", "emptyvault", "novault"):
        assert not enforcer.is_permitted(repo, "m", "anything"), repo
        assert enforcer.permitted_paths(repo, "m") == []


def test_the_listing_helpers_cover_both_forms_and_unknown_repos(tmp_path):
    path = write(
        tmp_path,
        '[repos.simple]\ndb = "m"\nallowed_paths = ["a"]\n'
        '[repos.multi.vaults.m]\nallowed_paths = ["b"]\n[repos.multi.vaults.i]\nallowed_paths = ["c"]\n',
    )
    enforcer = AllowlistEnforcer(path)
    assert enforcer.known_repos() == ["multi", "simple"]
    assert enforcer.repo_vaults("simple") == ["m"] and enforcer.repo_vaults("multi") == ["i", "m"]
    assert enforcer.repo_vaults("ghost") == [] and enforcer.repo_default_db("ghost") is None
    assert enforcer.repo_default_db("simple") == "m" and enforcer.repo_default_db("multi") is None
    assert (
        enforcer.permitted_paths("multi", "i") == ["c"]
        and enforcer.permitted_paths("multi", "zzz") == []
    )
    assert (
        enforcer.permitted_paths("simple", "other") == []
        and enforcer.permitted_paths("ghost", "m") == []
    )


def test_the_allowlist_path_comes_from_the_environment_or_the_repo_config_dir(monkeypatch):
    monkeypatch.setenv("AUTO_PASS_PROVISIONING_ALLOWLIST", "  /etc/ap/list.toml ")
    assert allowlist.default_allowlist_path() == Path("/etc/ap/list.toml")
    monkeypatch.setenv("AUTO_PASS_PROVISIONING_ALLOWLIST", "   ")
    assert allowlist.default_allowlist_path().name == "provisioning-allowlist.local.toml"
    assert allowlist.default_allowlist_path().parent.name == "config"


# --------------------------------------------------------------------------- vault access


def test_a_missing_unreadable_and_read_only_vault_each_get_their_own_finding(tmp_path):
    missing = tmp_path / "missing.kdbx"
    readonly = tmp_path / "ro.kdbx"
    readonly.write_bytes(b"x")
    readonly.chmod(0o400)
    fine = tmp_path / "fine.kdbx"
    fine.write_bytes(b"x")
    fine.chmod(0o600)
    findings = access.check_vaults({"missing": missing, "ro": readonly, "fine": fine}, login="me")
    by_label = {f.label: f for f in findings}
    assert set(by_label) == {"missing", "ro"} if os.geteuid() != 0 else True
    if os.geteuid() != 0:
        assert by_label["missing"].problem == "missing" and "mounted" in by_label["missing"].hint
        assert by_label["ro"].problem == "read-only"
    readonly.chmod(0o600)


def test_the_hint_is_a_chmod_for_a_vault_you_own_and_an_acl_for_someone_elses(
    tmp_path, monkeypatch
):
    path = tmp_path / "v.kdbx"
    path.write_bytes(b"x")
    monkeypatch.setattr(access, "_owner", lambda p: "me")
    assert access._hint(path, "me", "read-only") == f"chmod u+rw {path}"
    monkeypatch.setattr(access, "_owner", lambda p: "other")
    assert access._hint(path, "me", "read-only") == f"sudo setfacl -m u:me:rw {path}"
    assert access._hint(path, "me", "missing").startswith("check the path")


def test_an_owner_that_cannot_be_looked_up_is_none(tmp_path):
    assert access._owner(tmp_path / "does-not-exist") is None


def test_the_default_acl_check_needs_getfacl_and_a_directory_we_own(tmp_path, monkeypatch):
    monkeypatch.setattr(access.shutil, "which", lambda name: None)
    assert access.default_acl_missing(tmp_path, "me") is False
    monkeypatch.setattr(access.shutil, "which", lambda name: "/usr/bin/getfacl")
    monkeypatch.setattr(access, "_owner", lambda p: "someone-else")
    assert access.default_acl_missing(tmp_path, "me") is False


def test_the_default_acl_is_missing_only_when_getfacl_succeeds_without_an_entry_for_the_login(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(access.shutil, "which", lambda name: "/usr/bin/getfacl")
    monkeypatch.setattr(access, "_owner", lambda p: "me")
    for stdout, code, expected in (
        ("# file\ndefault:user::rwx\n", 0, True),
        ("default:user:me:rwx\n", 0, False),
        ("", 1, False),
    ):
        monkeypatch.setattr(
            access.subprocess, "run", lambda *a, out=stdout, rc=code, **k: completed(out, rc)
        )
        assert access.default_acl_missing(tmp_path, "me") is expected


def test_fixing_the_acl_sets_a_default_entry_only_on_a_directory_we_own(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(access.shutil, "which", lambda name: "/usr/bin/setfacl")
    monkeypatch.setattr(access, "_owner", lambda p: "me")
    monkeypatch.setattr(
        access.subprocess, "run", lambda argv, **k: calls.append(argv) or completed("", 0)
    )
    assert access.fix_default_acl(tmp_path, "me") is True
    assert calls == [["/usr/bin/setfacl", "-d", "-m", "u:me:rwx", str(tmp_path)]]
    monkeypatch.setattr(access.subprocess, "run", lambda *a, **k: completed("", 1))
    assert access.fix_default_acl(tmp_path, "me") is False
    calls.clear()
    monkeypatch.setattr(access, "_owner", lambda p: "other")
    assert access.fix_default_acl(tmp_path, "me") is False and calls == []
    monkeypatch.setattr(access, "_owner", lambda p: "me")
    monkeypatch.setattr(access.shutil, "which", lambda name: None)
    assert access.fix_default_acl(tmp_path, "me") is False


# --------------------------------------------------------------------------- the database index


def index(tmp_path: Path, payload) -> Path:
    path = tmp_path / "dbs.json"
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
    return path


def test_the_index_path_prefers_an_argument_then_the_environment_then_the_repo_default(
    monkeypatch, tmp_path
):
    monkeypatch.setenv(dbindex.DB_INDEX_PATH_ENV_VAR, "/env/dbs.json")
    assert dbindex.resolve_db_index_path("/arg/dbs.json") == Path("/arg/dbs.json")
    assert dbindex.resolve_db_index_path() == Path("/env/dbs.json")
    monkeypatch.setenv(dbindex.DB_INDEX_PATH_ENV_VAR, "  ")
    assert dbindex.resolve_db_index_path() == dbindex.DEFAULT_DB_INDEX_FILE


def test_a_missing_index_is_an_empty_set_of_vaults_and_a_missing_alias_is_an_error(tmp_path):
    assert dbindex.load_database_index(tmp_path / "absent.json") == {}
    with pytest.raises(dbindex.DatabaseIndexError, match="not found"):
        dbindex.resolve_database_alias("infra", tmp_path / "absent.json")


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ("{not json", "Invalid JSON"),
        ("[1, 2]", "top-level JSON object"),
        ({"databases": []}, "'databases' must be a JSON object"),
        ({"databases": {"": {}}}, "blank database alias"),
        ({"databases": {"   ": {}}}, "blank database alias"),
        ({"databases": {"infra": "path"}}, "must be a JSON object"),
    ],
)
def test_a_damaged_index_is_an_error_naming_the_problem_not_an_empty_list(
    tmp_path, payload, message
):
    with pytest.raises(dbindex.DatabaseIndexError, match=message):
        dbindex.load_database_index(index(tmp_path, payload))


def test_aliases_are_matched_case_insensitively_and_listed_sorted(tmp_path):
    path = index(
        tmp_path,
        {"databases": {"Infra": {"database_path": "/i"}, "alpha": {"database_path": "/a"}}},
    )
    assert dbindex.resolve_database_alias("  INFRA ", path) == {"database_path": "/i"}
    assert dbindex.list_database_aliases(path) == ["alpha", "infra"]
    assert dbindex.load_database_index(index(tmp_path, {})) == {}


def test_a_blank_alias_is_refused_and_the_returned_entry_is_a_copy(tmp_path):
    path = index(tmp_path, {"databases": {"infra": {"database_path": "/i"}}})
    for blank in ("", "   ", None):
        with pytest.raises(dbindex.DatabaseIndexError, match="blank"):
            dbindex.resolve_database_alias(blank, path)
    entry = dbindex.resolve_database_alias("infra", path)
    entry["database_path"] = "/tampered"
    assert dbindex.resolve_database_alias("infra", path)["database_path"] == "/i"
