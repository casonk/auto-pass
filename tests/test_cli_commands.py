"""The command-line front end: argument handling, output shape, exit codes, and failure text.

Every collaborator (vault tool, daemon client, server, rotation engine, web server) is replaced,
so no vault, daemon, socket or listening port is touched, and ``--no-env-file`` keeps the real
config file out of it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from auto_pass import cli
from auto_pass.client import ProvisioningClientError
from auto_pass.rotation import PasswordPolicy


def run(*argv):
    return cli.main(["--no-env-file", *argv])


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    monkeypatch.delenv("AUTO_PASS_KEEPASSXC_DB_PATH", raising=False)
    monkeypatch.delenv("AUTO_PASS_KEEPASSXC_KEY_FILE", raising=False)


def record(monkeypatch, name, result=None, exc=None):
    calls = []

    def fake(*args, **kwargs):
        calls.append((args, kwargs))
        if exc is not None:
            raise exc
        return result

    monkeypatch.setattr(cli, name, fake)
    return calls


# --- get / get-all ------------------------------------------------------------------------


def test_get_prints_a_single_value_bare(monkeypatch, capsys):
    record(monkeypatch, "resolve_keepassxc_entry", {"password": "hunter2"})
    assert run("get", "web/x", "--field", "password") == 0
    assert capsys.readouterr().out == "hunter2\n"


def test_get_defaults_to_username_and_password_as_key_value_lines(monkeypatch, capsys):
    calls = record(monkeypatch, "resolve_keepassxc_entry", {"username": "u", "password": "p"})
    assert run("get", "web/x") == 0
    assert capsys.readouterr().out == "username=u\npassword=p\n"
    assert calls[0][1]["attrs_map"] == {"username": "username", "password": "password"}


def test_get_json_is_sorted_and_indented(monkeypatch, capsys):
    record(monkeypatch, "resolve_keepassxc_entry", {"b": "2", "a": "1"})
    assert run("get", "web/x", "--field", "a", "--field", "b", "--json") == 0
    assert capsys.readouterr().out == json.dumps({"a": "1", "b": "2"}, indent=2) + "\n"


def test_get_passes_the_interactive_flag(monkeypatch):
    calls = record(monkeypatch, "resolve_keepassxc_entry", {"password": "p"})
    run("get", "web/x", "--field", "password", "--allow-interactive")
    assert calls[0][1]["allow_interactive"] is True


def test_get_all_prints_every_field_as_json(monkeypatch, capsys):
    record(monkeypatch, "resolve_keepassxc_entry_all_fields", {"Title": "T", "Notes": "n"})
    assert run("get-all", "web/x") == 0
    assert json.loads(capsys.readouterr().out) == {"Notes": "n", "Title": "T"}


# --- set / mkdir --------------------------------------------------------------------------


def test_set_passes_every_field_through_and_prints_the_outcome(monkeypatch, capsys):
    calls = record(monkeypatch, "upsert_keepassxc_entry", "add")
    rc = run(
        "set", "g/e", "--username", "u", "--password", "p", "--url", "https://x.test",
        "--notes", "n", "--no-create-group", "--allow-interactive",
    )  # fmt: skip
    assert rc == 0
    assert capsys.readouterr().out == "add\n"
    assert calls[0][1] == {
        "entry": "g/e",
        "username": "u",
        "password": "p",
        "url": "https://x.test",
        "notes": "n",
        "create_group": False,
        "allow_interactive": True,
    }


def test_set_reads_the_password_from_stdin_without_the_trailing_newline(monkeypatch, capsys):
    calls = record(monkeypatch, "upsert_keepassxc_entry", "edit")
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(read=lambda: "from-stdin\n"))
    assert run("set", "g/e", "--password-stdin") == 0
    assert calls[0][1]["password"] == "from-stdin"
    assert calls[0][1]["create_group"] is True


def test_set_notes_file_beats_inline_notes(monkeypatch, tmp_path):
    notes = tmp_path / "n.txt"
    notes.write_text("line1\nline2\n", encoding="utf-8")
    calls = record(monkeypatch, "upsert_keepassxc_entry", "edit")
    run("set", "g/e", "--notes", "inline", "--notes-file", str(notes))
    assert calls[0][1]["notes"] == "line1\nline2\n"


def test_set_without_notes_sends_none_so_existing_notes_are_kept(monkeypatch):
    calls = record(monkeypatch, "upsert_keepassxc_entry", "edit")
    run("set", "g/e", "--username", "u")
    assert calls[0][1]["notes"] is None


def test_set_explicit_empty_notes_are_sent_to_clear_them(monkeypatch):
    calls = record(monkeypatch, "upsert_keepassxc_entry", "edit")
    run("set", "g/e", "--notes", "")
    assert calls[0][1]["notes"] == ""


@pytest.mark.parametrize(("created", "word"), [(True, "created"), (False, "exists")])
def test_mkdir_reports_created_or_exists(monkeypatch, capsys, created, word):
    record(monkeypatch, "ensure_group", created)
    assert run("mkdir", "web") == 0
    assert capsys.readouterr().out == f"{word}\n"


# --- profiles -----------------------------------------------------------------------------


def test_list_profiles_marks_the_active_one(monkeypatch, capsys):
    monkeypatch.setattr(cli, "get_active_keepass_profile", lambda: "work")
    monkeypatch.setattr(cli, "list_keepass_profiles", lambda: ["home", "work"])
    assert run("list-profiles") == 0
    assert capsys.readouterr().out == "  home\n* work\n"


def test_list_profiles_json(monkeypatch, capsys):
    monkeypatch.setattr(cli, "get_active_keepass_profile", lambda: "work")
    monkeypatch.setattr(cli, "list_keepass_profiles", lambda: ["home", "work"])
    assert run("list-profiles", "--json") == 0
    assert json.loads(capsys.readouterr().out) == {
        "active_profile": "work",
        "profiles": ["home", "work"],
    }


# --- check-access -------------------------------------------------------------------------


@pytest.fixture
def access(monkeypatch):
    from auto_pass import access as access_module

    state = SimpleNamespace(
        paths={"master": Path("/v/a/master.kdbx"), "dev": Path("/v/b/dev.kdbx")},
        findings=[],
        missing={"/v/a"},
        fixed=[],
        fix_ok=True,
    )
    monkeypatch.setattr(cli, "getuser", lambda: "tester")
    monkeypatch.setattr(access_module, "vault_paths", lambda: state.paths)
    monkeypatch.setattr(access_module, "check_vaults", lambda paths, login: list(state.findings))
    monkeypatch.setattr(
        access_module, "default_acl_missing", lambda d, login: str(d) in state.missing
    )

    def fix(directory, login):
        state.fixed.append(str(directory))
        return state.fix_ok

    monkeypatch.setattr(access_module, "fix_default_acl", fix)
    state.finding = access_module.AccessFinding("dev", Path("/v/b/dev.kdbx"), "read-only", "chmod")
    return state


def test_check_access_ok(access, capsys):
    assert run("check-access") == 0
    assert capsys.readouterr().out == "ok: 2 vault(s) readable and writable by tester\n"


def test_check_access_reports_each_problem_with_its_fix_and_fails(access, capsys):
    access.findings = [access.finding]
    assert run("check-access") == 1
    assert capsys.readouterr().out == ("error: vault dev read-only: /v/b/dev.kdbx (fix: chmod)\n")


def test_check_access_json(access, capsys):
    access.findings = [access.finding]
    assert run("check-access", "--json") == 1
    assert json.loads(capsys.readouterr().out) == [access.finding.as_dict()]


def test_fix_acl_only_touches_directories_that_need_it(access, capsys):
    assert run("check-access", "--fix-acl") == 0
    captured = capsys.readouterr()
    assert access.fixed == ["/v/a"]
    assert "added default ACL u:tester:rwx on /v/a" in captured.err
    assert "/v/b" not in captured.err


def test_fix_acl_stays_quiet_when_the_fix_did_not_apply(access, capsys):
    access.fix_ok = False
    run("check-access", "--fix-acl")
    assert "added default ACL" not in capsys.readouterr().err


def test_without_fix_acl_nothing_is_changed(access):
    run("check-access")
    assert access.fixed == []


# --- daemon commands ----------------------------------------------------------------------


class FakeClient:
    def __init__(self, **kw):
        self.running = kw.get("running", True)
        self.status_result = kw.get("status", {"ok": True, "locked": False})
        self.status_exc = kw.get("status_exc")
        self.unlock_exc = kw.get("unlock_exc")
        self.lock_exc = kw.get("lock_exc")
        self.get_result = kw.get("get", "value")
        self.get_exc = kw.get("get_exc")
        self.unlocked_with = []
        self.gets = []
        self.locked = False

    def is_running(self):
        return self.running

    def status(self):
        if self.status_exc:
            raise self.status_exc
        return self.status_result

    def unlock(self, password):
        if self.unlock_exc:
            raise self.unlock_exc
        self.unlocked_with.append(password)

    def lock(self):
        if self.lock_exc:
            raise self.lock_exc
        self.locked = True

    def get(self, entry, field="password", db=None):
        self.gets.append((entry, field, db))
        if self.get_exc:
            raise self.get_exc
        return self.get_result


def use_client(monkeypatch, **kw):
    client = FakeClient(**kw)
    monkeypatch.setattr(cli, "_provision_client", lambda args: client)
    return client


def test_unlock_with_a_password_on_stdin(monkeypatch, capsys):
    client = use_client(monkeypatch)
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(read=lambda: "master-pw\n"))
    assert run("unlock", "--password-stdin") == 0
    assert client.unlocked_with == ["master-pw"]
    captured = capsys.readouterr()
    assert captured.out == "unlocked\n"
    assert "master-pw" not in captured.out + captured.err


def test_unlock_prompts_when_stdin_is_not_used(monkeypatch):
    client = use_client(monkeypatch)
    monkeypatch.setattr(cli, "getpass", lambda prompt: "typed")
    assert run("unlock") == 0
    assert client.unlocked_with == ["typed"]


def test_unlock_refuses_when_the_daemon_is_not_running(monkeypatch, capsys):
    client = use_client(monkeypatch, running=False)
    monkeypatch.setattr(cli, "getpass", lambda prompt: pytest.fail("must not prompt"))
    assert run("unlock") == 1
    assert "not running" in capsys.readouterr().err
    assert client.unlocked_with == []


@pytest.mark.parametrize("exc", [EOFError(), KeyboardInterrupt()])
def test_unlock_prompt_abort_fails_cleanly(monkeypatch, exc):
    client = use_client(monkeypatch)

    def abort(prompt):
        raise exc

    monkeypatch.setattr(cli, "getpass", abort)
    assert run("unlock") == 1
    assert client.unlocked_with == []


def test_unlock_requires_a_password(monkeypatch, capsys):
    client = use_client(monkeypatch)
    monkeypatch.setattr(cli, "getpass", lambda prompt: "")
    assert run("unlock") == 1
    assert "password is required" in capsys.readouterr().err
    assert client.unlocked_with == []


def test_unlock_rejection_is_reported_without_the_password(monkeypatch, capsys):
    use_client(monkeypatch, unlock_exc=ProvisioningClientError("unlock: wrong password"))
    monkeypatch.setattr(cli, "getpass", lambda prompt: "secret-attempt")
    assert run("unlock") == 1
    captured = capsys.readouterr()
    assert "wrong password" in captured.err
    assert "secret-attempt" not in captured.out + captured.err


def test_lock(monkeypatch, capsys):
    client = use_client(monkeypatch)
    assert run("lock") == 0
    assert client.locked and capsys.readouterr().out == "locked\n"


@pytest.mark.parametrize("exc", [OSError("no socket"), ProvisioningClientError("lock: refused")])
def test_lock_failure(monkeypatch, capsys, exc):
    use_client(monkeypatch, lock_exc=exc)
    assert run("lock") == 1
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("status", "text"),
    [
        ({"ok": True, "locked": False}, "daemon: running  locked: False\n"),
        ({"ok": True, "locked": True}, "daemon: running  locked: True\n"),
        ({"ok": False}, "daemon: not running\n"),
    ],
)
def test_daemon_status_text(monkeypatch, capsys, status, text):
    use_client(monkeypatch, status=status)
    assert run("daemon-status") == 0
    assert capsys.readouterr().out == text


def test_daemon_status_when_the_socket_is_missing_reads_as_not_running_and_locked(
    monkeypatch, capsys
):
    use_client(monkeypatch, status_exc=OSError("gone"))
    assert run("daemon-status", "--json") == 0
    assert json.loads(capsys.readouterr().out) == {"running": False, "locked": True}


def test_daemon_status_when_the_daemon_errors_reads_as_not_running(monkeypatch, capsys):
    use_client(monkeypatch, status_exc=ProvisioningClientError("status: bad"))
    assert run("daemon-status") == 0
    assert capsys.readouterr().out == "daemon: not running\n"


def test_daemon_status_json(monkeypatch, capsys):
    use_client(monkeypatch, status={"ok": True, "locked": False})
    run("daemon-status", "--json")
    assert json.loads(capsys.readouterr().out) == {"running": True, "locked": False}


def test_provision_get_defaults_and_prints_the_value(monkeypatch, capsys):
    client = use_client(monkeypatch, get="the-value")
    assert run("provision-get", "web/x") == 0
    assert capsys.readouterr().out == "the-value\n"
    assert client.gets == [("web/x", "password", None)]


def test_provision_get_passes_field_and_vault(monkeypatch):
    client = use_client(monkeypatch)
    run("provision-get", "web/x", "--field", "username", "--db", "dev")
    assert client.gets == [("web/x", "username", "dev")]


@pytest.mark.parametrize("exc", [OSError("no socket"), ProvisioningClientError("get: denied")])
def test_provision_get_failure_prints_nothing_to_stdout(monkeypatch, capsys, exc):
    use_client(monkeypatch, get_exc=exc)
    assert run("provision-get", "web/x") == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error:" in captured.err


def test_provision_client_uses_the_given_socket(monkeypatch, tmp_path):
    from auto_pass import client as client_module

    seen = {}

    class Spy:
        def __init__(self, socket_path):
            seen["path"] = socket_path

    monkeypatch.setattr(client_module, "ProvisioningClient", Spy)
    cli._provision_client(SimpleNamespace(socket=str(tmp_path / "s.sock")))
    assert seen["path"] == tmp_path / "s.sock"


def test_provision_client_falls_back_to_the_default_socket(monkeypatch, tmp_path):
    from auto_pass import client as client_module
    from auto_pass import server as server_module

    seen = {}

    class Spy:
        def __init__(self, socket_path):
            seen["path"] = socket_path

    monkeypatch.setattr(client_module, "ProvisioningClient", Spy)
    monkeypatch.setattr(server_module, "default_socket_path", lambda: tmp_path / "d.sock")
    cli._provision_client(SimpleNamespace(socket=None))
    assert seen["path"] == tmp_path / "d.sock"


# --- serve --------------------------------------------------------------------------------


@pytest.fixture
def serve_env(monkeypatch, tmp_path):
    from auto_pass import allowlist as allowlist_module
    from auto_pass import dbindex
    from auto_pass import server as server_module

    built = []

    class FakeServer:
        def __init__(self, **kwargs):
            built.append(kwargs)
            self.served = False

        def serve(self):
            built[-1]["served"] = True

    monkeypatch.setattr(server_module, "ProvisioningServer", FakeServer)
    monkeypatch.setattr(server_module, "default_socket_path", lambda: tmp_path / "d.sock")
    monkeypatch.setattr(allowlist_module, "default_allowlist_path", lambda: tmp_path / "al.toml")
    monkeypatch.setattr(dbindex, "resolve_database_alias", lambda alias, path: {})
    return SimpleNamespace(built=built, dbindex=dbindex, tmp=tmp_path)


def test_serve_builds_the_server_from_flags_and_serves(serve_env, capsys):
    allow = serve_env.tmp / "allow.toml"
    allow.write_text("")
    rc = run(
        "serve", "--db-path", " /v/master.kdbx ", "--key-file", "/v/k.key",
        "--master-alias", " root ", "--allowlist", str(allow),
        "--socket", str(serve_env.tmp / "x.sock"), "--db-index", str(serve_env.tmp / "i.json"),
    )  # fmt: skip
    assert rc == 0
    kwargs = serve_env.built[0]
    assert kwargs == {
        "master_db_path": "/v/master.kdbx",
        "master_key_file": "/v/k.key",
        "master_db_alias": "root",
        "allowlist_path": allow,
        "socket_path": serve_env.tmp / "x.sock",
        "db_index_path": serve_env.tmp / "i.json",
        "served": True,
    }
    assert "warning" not in capsys.readouterr().err


def test_serve_falls_back_to_env_then_defaults(serve_env, monkeypatch, capsys):
    monkeypatch.setenv("AUTO_PASS_KEEPASSXC_DB_PATH", "/env/master.kdbx")
    monkeypatch.setenv("AUTO_PASS_KEEPASSXC_KEY_FILE", "/env/k.key")
    assert run("serve") == 0
    kwargs = serve_env.built[0]
    assert kwargs["master_db_path"] == "/env/master.kdbx"
    assert kwargs["master_key_file"] == "/env/k.key"
    assert kwargs["master_db_alias"] == "master"
    assert kwargs["socket_path"] == serve_env.tmp / "d.sock"
    assert kwargs["allowlist_path"] == serve_env.tmp / "al.toml"
    assert kwargs["db_index_path"] is None


def test_serve_warns_that_a_missing_allowlist_denies_everything(serve_env, monkeypatch, capsys):
    monkeypatch.setenv("AUTO_PASS_KEEPASSXC_DB_PATH", "/v/m.kdbx")
    assert run("serve") == 0
    err = capsys.readouterr().err
    assert "allowlist not found" in err
    assert "denied" in err
    assert serve_env.built[0]["served"] is True


def test_serve_takes_the_master_path_from_the_database_index(serve_env, monkeypatch):
    monkeypatch.setattr(
        serve_env.dbindex,
        "resolve_database_alias",
        lambda alias, path: {"database_path": " /idx/master.kdbx "},
    )
    assert run("serve") == 0
    assert serve_env.built[0]["master_db_path"] == "/idx/master.kdbx"


def test_serve_without_any_master_path_refuses_to_start(serve_env, monkeypatch, capsys):
    def missing(alias, path):
        raise serve_env.dbindex.DatabaseIndexError("no index")

    monkeypatch.setattr(serve_env.dbindex, "resolve_database_alias", missing)
    assert run("serve") == 1
    assert "master database path not set" in capsys.readouterr().err
    assert serve_env.built == []


def test_serve_with_an_index_entry_lacking_a_path_refuses_to_start(serve_env, capsys):
    assert run("serve") == 1  # the stubbed index answers {} with no database_path
    assert serve_env.built == []


# --- notify-summary -----------------------------------------------------------------------


def test_notify_summary_reports_a_count(monkeypatch, capsys):
    from auto_pass import notifications

    monkeypatch.setattr(notifications, "send_daily_summary", lambda: 3)
    assert run("notify-summary") == 0
    assert capsys.readouterr().out == "Sent summary of 3 retrieval(s).\n"


def test_notify_summary_is_silent_when_there_is_nothing_to_send(monkeypatch, capsys):
    from auto_pass import notifications

    monkeypatch.setattr(notifications, "send_daily_summary", lambda: 0)
    assert run("notify-summary") == 0
    assert capsys.readouterr().out == ""


def test_notify_summary_failure(monkeypatch, capsys):
    from auto_pass import notifications

    def boom():
        raise notifications.PasswordRetrievalNotificationError("channel down")

    monkeypatch.setattr(notifications, "send_daily_summary", boom)
    assert run("notify-summary") == 1
    assert "channel down" in capsys.readouterr().err


# --- web ----------------------------------------------------------------------------------


@pytest.fixture
def web(monkeypatch):
    from auto_pass import client as client_module

    state = SimpleNamespace(ran=[], token=None, get_exc=None, requested=[])
    monkeypatch.setitem(
        sys.modules,
        "uvicorn",
        SimpleNamespace(run=lambda app, **kw: state.ran.append(kw)),
    )
    monkeypatch.delenv("AUTO_PASS_WEB_TOKEN", raising=False)
    monkeypatch.delenv("AUTO_PASS_WEB_TOKEN_KEEPASS_ENTRY", raising=False)
    monkeypatch.delenv("AUTO_PASS_WEB_TOKEN_KEEPASS_DB", raising=False)

    class FakeClient:
        def get(self, entry, db=None):
            state.requested.append((entry, db))
            if state.get_exc:
                raise state.get_exc
            return state.token

    monkeypatch.setattr(client_module, "ProvisioningClient", FakeClient)
    return state


def test_web_without_its_dependencies_says_how_to_install_them(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "uvicorn", None)  # makes `import uvicorn` fail
    assert run("web") == 1
    assert "web dependencies not installed" in capsys.readouterr().err


def test_web_uses_the_token_from_the_environment(web, monkeypatch, capsys):
    monkeypatch.setenv("AUTO_PASS_WEB_TOKEN", "env-token")
    assert run("web", "--host", "0.0.0.0", "--port", "9999") == 0
    assert web.ran == [{"host": "0.0.0.0", "port": 9999, "log_level": "info"}]
    assert web.requested == []  # the daemon is not asked when the env has a token
    assert "http://0.0.0.0:9999" in capsys.readouterr().out


def test_web_fetches_its_token_from_the_daemon_when_unset(web, monkeypatch):
    web.token = "daemon-token"
    monkeypatch.setenv("AUTO_PASS_WEB_TOKEN_KEEPASS_ENTRY", "my/web-token")
    monkeypatch.setenv("AUTO_PASS_WEB_TOKEN_KEEPASS_DB", "dev")
    assert run("web") == 0
    assert web.requested == [("my/web-token", "dev")]
    assert cli.os.environ["AUTO_PASS_WEB_TOKEN"] == "daemon-token"
    monkeypatch.delenv("AUTO_PASS_WEB_TOKEN")


def test_web_default_token_entry_and_vault(web, monkeypatch):
    web.token = "t"
    assert run("web") == 0
    assert web.requested == [("auto-pass/web-token", None)]
    monkeypatch.delenv("AUTO_PASS_WEB_TOKEN")


@pytest.mark.parametrize("exc", [OSError("no socket"), ProvisioningClientError("get: locked")])
def test_web_refuses_to_start_unauthenticated_when_the_daemon_is_unavailable(web, capsys, exc):
    web.get_exc = exc
    assert run("web") == 1
    err = capsys.readouterr().err
    assert "AUTO_PASS_WEB_TOKEN is not set" in err
    assert "start and unlock the provisioning daemon" in err
    assert web.ran == []


@pytest.mark.parametrize("empty", ["", None])
def test_web_refuses_an_empty_token_from_the_daemon(web, capsys, empty):
    web.token = empty
    assert run("web") == 1
    assert "empty web token" in capsys.readouterr().err
    assert web.ran == []
    assert "AUTO_PASS_WEB_TOKEN" not in cli.os.environ


# --- rotate -------------------------------------------------------------------------------


ROTATE_FUNCS = {
    "prepare": "prepare_rotation",
    "status": "rotation_status",
    "promote": "promote_rotation",
    "discard": "discard_rotation",
    "configure": "configure_rotation_registry",
    "show-config": "rotation_registry_status",
    "list-configs": "list_rotation_registries",
    "infer-config": "infer_rotation_registry",
    "sync-todo": "sync_rotation_todo",
}


@pytest.mark.parametrize(
    ("sub", "extra"),
    [
        ("prepare", ["web/x"]),
        ("status", ["web/x"]),
        ("promote", ["web/x"]),
        ("discard", ["web/x"]),
        ("configure", ["web/x"]),
        ("show-config", ["web/x"]),
        ("list-configs", []),
        ("infer-config", ["web/x"]),
        ("sync-todo", ["--todo-file", "t.md"]),
    ],
)
def test_each_rotate_subcommand_calls_its_own_engine_function(monkeypatch, capsys, sub, extra):
    calls = {name: record(monkeypatch, name, {"ok": "yes"}) for name in ROTATE_FUNCS.values()}

    assert run("rotate", sub, *extra) == 0

    for other, name in ROTATE_FUNCS.items():
        assert len(calls[name]) == (1 if other == sub else 0), other
    assert capsys.readouterr().out == "ok=yes\n"


def test_rotate_prepare_passes_its_options(monkeypatch):
    calls = record(monkeypatch, "prepare_rotation", {})
    run(
        "rotate", "prepare", "web/x", "--homepage-url", "https://h", "--reset-url", "https://r",
        "--note", "n", "--allow-interactive", "--length", "12",
    )  # fmt: skip
    args, kwargs = calls[0]
    assert args == ("web/x",)
    assert kwargs["homepage_url"] == "https://h"
    assert kwargs["reset_url"] == "https://r"
    assert kwargs["note"] == "n"
    assert kwargs["allow_interactive"] is True
    assert kwargs["policy"] == PasswordPolicy(length=12)


def test_rotate_without_policy_flags_sends_no_policy(monkeypatch):
    calls = record(monkeypatch, "prepare_rotation", {})
    run("rotate", "prepare", "web/x")
    assert calls[0][1]["policy"] is None


def test_rotate_policy_flags_override_one_field_at_a_time(monkeypatch):
    calls = record(monkeypatch, "configure_rotation_registry", {})
    run(
        "rotate", "configure", "web/x", "--no-special", "--no-every-group",
        "--exclude-chars", "0Ol", "--special-chars", "!?", "--rotation-interval-days", "30",
    )  # fmt: skip
    kwargs = calls[0][1]
    assert kwargs["policy"] == PasswordPolicy(
        special=False, every_group=False, exclude_chars="0Ol", special_chars="!?"
    )
    assert kwargs["rotation_interval_days"] == 30


def test_rotate_list_configs_passes_filters(monkeypatch):
    calls = record(monkeypatch, "list_rotation_registries", [])
    run("rotate", "list-configs", "--group", "web", "--due-within-days", "14")
    assert calls[0][1] == {"group": "web", "due_within_days": 14, "allow_interactive": False}


def test_rotate_sync_todo_passes_its_options(monkeypatch):
    calls = record(monkeypatch, "sync_rotation_todo", {})
    run(
        "rotate", "sync-todo", "--todo-file", "t.md", "--category", "pw", "--group", "web",
        "--due-within-days", "7",
    )  # fmt: skip
    assert calls[0][0] == ("t.md",)
    assert calls[0][1]["category"] == "pw"
    assert calls[0][1]["group"] == "web"
    assert calls[0][1]["due_within_days"] == 7


def test_rotate_lists_are_printed_one_tab_separated_line_per_entry(monkeypatch, capsys):
    record(
        monkeypatch,
        "list_rotation_registries",
        [
            {"entry": "web/a", "due_status": "due", "days_until_due": 3, "policy_source": "entry"},
            {"entry": "web/b"},
        ],
    )
    assert run("rotate", "list-configs") == 0
    assert capsys.readouterr().out == (
        "web/a\tdue_status=due\tdays_until_due=3\tpolicy_source=entry\n"
        "web/b\tdue_status=\tdays_until_due=\tpolicy_source=\n"
    )


def test_rotate_json_output_is_sorted(monkeypatch, capsys):
    record(monkeypatch, "rotation_status", {"b": 2, "a": 1})
    assert run("rotate", "status", "web/x", "--json") == 0
    assert capsys.readouterr().out == json.dumps({"a": 1, "b": 2}, indent=2) + "\n"


def test_rotate_json_output_for_a_list(monkeypatch, capsys):
    record(monkeypatch, "list_rotation_registries", [{"entry": "web/a"}])
    assert run("rotate", "list-configs", "--json") == 0
    assert json.loads(capsys.readouterr().out) == [{"entry": "web/a"}]


@pytest.mark.parametrize("exc", [ValueError("bad policy"), RuntimeError("vault locked")])
def test_rotate_errors_are_reported_not_raised(monkeypatch, capsys, exc):
    record(monkeypatch, "rotation_status", exc=exc)
    assert run("rotate", "status", "web/x") == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"error: {exc}" in captured.err


def test_an_unhandled_rotate_command_is_a_programming_error():
    with pytest.raises(AssertionError, match="Unhandled rotate command"):
        cli._cmd_rotate(SimpleNamespace(rotate_command="bogus", json=False))


def test_an_unhandled_command_is_a_programming_error(monkeypatch):
    class Parser:
        def parse_args(self, argv):
            return SimpleNamespace(
                no_env_file=True, profile=None, command="bogus", env_file="", argv=argv
            )

    monkeypatch.setattr(cli, "build_parser", lambda: Parser())
    with pytest.raises(AssertionError, match="Unhandled command"):
        cli.main([])


def test_module_entry_point_runs_main(monkeypatch):
    import runpy

    monkeypatch.setattr(sys, "argv", ["auto-pass", "--no-env-file", "list-profiles", "--json"])
    monkeypatch.setattr("auto_pass.envfile.get_active_keepass_profile", lambda: "")
    monkeypatch.setattr("auto_pass.envfile.list_keepass_profiles", lambda: [])
    with pytest.raises(SystemExit) as info:
        runpy.run_module("auto_pass", run_name="__main__")
    assert info.value.code == 0


def test_web_refuses_a_blank_token_from_the_daemon(web, monkeypatch, capsys):
    web.token = "   "
    assert run("web") == 1
    assert "AUTO_PASS_WEB_TOKEN is not set" in capsys.readouterr().err
    assert web.ran == []
    monkeypatch.delenv("AUTO_PASS_WEB_TOKEN", raising=False)


def test_daemon_status_without_a_locked_field_reads_as_locked(monkeypatch, capsys):
    use_client(monkeypatch, status={"ok": True})
    assert run("daemon-status") == 0
    assert capsys.readouterr().out == "daemon: running  locked: True\n"
