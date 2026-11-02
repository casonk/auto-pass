"""The provisioning daemon's decisions: who is answered, which secret is handed to whom.

The daemon hands a secret to a local caller only if the caller is the owner's UID, the vault
is unlocked, the caller's repository can be identified, and the allowlist permits that
repository to read that entry from that vault. Everything outside that is a refusal that must
not reveal anything. The vault tool, the caller lookup and the sockets are all replaced:
nothing here touches a vault, a process table or a real socket.
"""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path

import pytest

from auto_pass import server as server_module
from auto_pass.keepassxc import KeepassCommandError
from auto_pass.server import ProvisioningServer

ME = os.getuid()
ALLOWLIST = """
[repos.simple]
db = "master"
allowed_paths = ["web/*", "exact/entry"]

[repos.multi.vaults.master]
allowed_paths = ["dev/*"]

[repos.multi.vaults.infra]
allowed_paths = ["codecov/*"]
"""
DB_INDEX = {
    "databases": {
        "infra": {
            "database_path": "/vaults/infra.kdbx",
            "database_password_source": {
                "database_alias": "master",
                "entry": "vault-passwords/infra",
                "attribute": "Password",
            },
        },
        "nosource": {"database_path": "/vaults/nosource.kdbx"},
        "chained": {
            "database_path": "/vaults/chained.kdbx",
            "database_password_source": {"database_alias": "infra", "entry": "x"},
        },
        "nopath": {"database_password_source": {"database_alias": "master", "entry": "x"}},
    }
}


class Harness:
    def __init__(self, tmp_path: Path, monkeypatch):
        self.show_calls: list[dict] = []
        self.show_result: dict[str, str] | Exception = {"password": "the-secret"}
        self.caller: str | None = "simple"
        self.valid_password = "master-pw"
        allowlist = tmp_path / "allowlist.toml"
        allowlist.write_text(ALLOWLIST, encoding="utf-8")
        index = tmp_path / "dbs.json"
        index.write_text(json.dumps(DB_INDEX), encoding="utf-8")
        self.server = ProvisioningServer(
            master_db_path="/vaults/master.kdbx",
            master_key_file="/keys/master.key",
            allowlist_path=allowlist,
            socket_path=tmp_path / "s.sock",
            db_index_path=index,
        )
        self.audit = tmp_path / "audit.jsonl"
        monkeypatch.setattr(server_module, "_AUDIT_LOG", self.audit)
        monkeypatch.setattr(server_module, "resolve_caller_repo", lambda pid: self.caller)
        monkeypatch.setattr(
            server_module,
            "validate_keepassxc_database",
            lambda path, password, key_file: password == self.valid_password,
        )
        monkeypatch.setattr(server_module, "run_keepassxc_show_direct", self._show)

    def _show(self, entry, attrs, *, db_path, db_password, key_file):
        self.show_calls.append(
            {
                "entry": entry,
                "attrs": attrs,
                "db_path": db_path,
                "db_password": db_password,
                "key_file": key_file,
            }
        )
        if isinstance(self.show_result, Exception):
            raise self.show_result
        return dict(self.show_result)

    def ask(self, request: dict, uid: int = ME, pid: int = 4242) -> dict:
        return self.server.handle_request(request, caller_pid=pid, caller_uid=uid)

    def unlock(self) -> None:
        assert self.ask({"op": "unlock", "password": self.valid_password}) == {"ok": True}

    def events(self) -> list[dict]:
        if not self.audit.exists():
            return []
        return [json.loads(line) for line in self.audit.read_text().splitlines()]


@pytest.fixture
def h(tmp_path, monkeypatch):
    return Harness(tmp_path, monkeypatch)


# --------------------------------------------------------------------------- who is answered


def test_a_caller_with_another_uid_gets_nothing_for_any_operation(h):
    h.unlock()
    for request in (
        {"op": "status"},
        {"op": "get", "path": "web/x"},
        {"op": "admin_context"},
        {"op": "lock"},
        {"op": "unlock", "password": "master-pw"},
    ):
        assert h.ask(request, uid=ME + 1) == {"ok": False, "error": "unauthorized"}
    assert h.server.is_unlocked, "a refused lock must not lock"
    assert h.show_calls == []


def test_status_reports_locked_until_unlocked_and_after_a_lock(h):
    assert h.ask({"op": "status"}) == {"ok": True, "locked": True}
    h.unlock()
    assert h.ask({"op": "status"}) == {"ok": True, "locked": False}
    assert h.ask({"op": "lock"}) == {"ok": True}
    assert h.ask({"op": "status"}) == {"ok": True, "locked": True}


def test_an_unknown_or_missing_op_is_refused_by_name(h):
    assert h.ask({"op": "frobnicate"}) == {"ok": False, "error": "unknown op: 'frobnicate'"}
    assert h.ask({})["ok"] is False


def test_unlock_needs_the_right_password_and_a_wrong_one_does_not_unlock(h):
    assert h.ask({"op": "unlock"}) == {"ok": False, "error": "password required"}
    assert h.ask({"op": "unlock", "password": ""}) == {"ok": False, "error": "password required"}
    assert h.ask({"op": "unlock", "password": "guess"}) == {
        "ok": False,
        "error": "invalid password",
    }
    assert not h.server.is_unlocked
    h.unlock()
    assert h.server.is_unlocked


def test_the_password_is_forgotten_on_lock(h):
    h.unlock()
    h.server.lock()
    assert h.server._db_password is None


def test_reload_rereads_the_allowlist_from_disk(h, tmp_path):
    h.unlock()
    assert h.ask({"op": "get", "path": "web/x"})["ok"] is True
    (tmp_path / "allowlist.toml").write_text("[repos]\n", encoding="utf-8")
    assert h.ask({"op": "get", "path": "web/x"})["ok"] is True, "the old list stays until a reload"
    assert h.ask({"op": "reload"}) == {"ok": True}
    assert h.ask({"op": "get", "path": "web/x"})["ok"] is False


# --------------------------------------------------------------------------- admin context


def test_admin_context_is_refused_while_locked_and_hands_over_the_master_after_unlock(h):
    assert h.ask({"op": "admin_context"}) == {"ok": False, "error": "daemon is locked"}
    h.unlock()
    assert h.ask({"op": "admin_context"}) == {
        "ok": True,
        "master_db_path": "/vaults/master.kdbx",
        "master_db_password": "master-pw",
        "master_key_file": "/keys/master.key",
        "master_db_alias": "master",
    }


# --------------------------------------------------------------------------- get: the gate


def test_get_is_refused_while_locked_and_asks_no_vault(h):
    response = h.ask({"op": "get", "path": "web/x"})
    assert response == {"ok": False, "error": "daemon is locked — run: auto-pass unlock"}
    assert h.show_calls == []


def test_a_permitted_entry_is_returned_with_the_requested_field_and_audited(h):
    h.unlock()
    h.show_result = {"token": "tok-123"}
    response = h.ask({"op": "get", "path": "web/github", "field": "token"}, pid=777)
    assert response == {"ok": True, "value": "tok-123"}
    call = h.show_calls[0]
    assert call["entry"] == "web/github" and call["attrs"] == {"token": "token"}
    assert (call["db_path"], call["db_password"], call["key_file"]) == (
        "/vaults/master.kdbx",
        "master-pw",
        "/keys/master.key",
    )
    [event] = h.events()
    assert event["op"] == "get" and event["repo"] == "simple" and event["db"] == "master"
    assert event["path"] == "web/github" and event["field"] == "token" and event["pid"] == 777
    # the audit log records who read what, never the secret itself
    assert "tok-123" not in json.dumps(event) and "value" not in event


def test_the_field_defaults_to_password_and_blank_is_the_default(h):
    h.unlock()
    for field in ({}, {"field": ""}, {"field": "   "}):
        h.show_calls.clear()
        assert h.ask({"op": "get", "path": "web/x", **field})["value"] == "the-secret"
        assert h.show_calls[0]["attrs"] == {"password": "password"}


@pytest.mark.parametrize("path", ["", "   "])
def test_a_missing_path_is_refused(h, path):
    h.unlock()
    assert h.ask({"op": "get", "path": path}) == {"ok": False, "error": "path required"}
    assert h.ask({"op": "get"}) == {"ok": False, "error": "path required"}


def test_a_caller_that_cannot_be_identified_gets_nothing(h):
    h.unlock()
    h.caller = None
    assert h.ask({"op": "get", "path": "web/x"}) == {
        "ok": False,
        "error": "could not resolve caller identity",
    }
    assert h.show_calls == [] and h.events() == []


@pytest.mark.parametrize(
    "path", ["other/entry", "exact/entry/extra", "WEB/x", "webx", "", "../web/x"]
)
def test_an_entry_the_allowlist_does_not_cover_is_refused_and_never_read(h, path):
    h.unlock()
    response = h.ask({"op": "get", "path": path or "x"})
    assert response["ok"] is False and "not permitted" in response["error"]
    assert h.show_calls == [] and h.events() == []


def test_a_repo_not_in_the_allowlist_is_refused(h):
    h.unlock()
    h.caller = "stranger"
    response = h.ask({"op": "get", "path": "web/x", "db": "master"})
    assert response["ok"] is False and "not permitted" in response["error"]
    assert h.show_calls == []


def test_the_refusal_names_the_repo_entry_and_vault_but_nothing_secret(h):
    h.unlock()
    response = h.ask({"op": "get", "path": "nope/x"})
    assert (
        response["error"] == "repo 'simple' is not permitted to access 'nope/x' in vault 'master'"
    )
    assert "master-pw" not in json.dumps(response)


def test_a_repo_can_only_read_from_the_vault_its_allowlist_names(h):
    h.unlock()
    # "simple" is allowed web/* in "master" only
    for vault in ("infra", "other"):
        response = h.ask({"op": "get", "path": "web/x", "db": vault})
        assert response["ok"] is False and "not permitted" in response["error"]
    assert h.show_calls == []


def test_a_multi_vault_repo_must_say_which_vault_it_means(h):
    h.unlock()
    h.caller = "multi"
    response = h.ask({"op": "get", "path": "dev/x"})
    assert response["ok"] is False and "multi-vault config" in response["error"]
    assert h.show_calls == []
    assert h.ask({"op": "get", "path": "dev/x", "db": "master"})["ok"] is True
    assert (
        h.ask({"op": "get", "path": "dev/x", "db": "infra"})["ok"] is False
    )  # dev/* is master only


# --------------------------------------------------------------------------- sub-vault passwords


def test_a_sub_vault_password_comes_from_the_master_entry_its_index_names(h, monkeypatch):
    h.unlock()
    h.caller = "multi"
    results = iter([{"Password": "infra-vault-pw"}, {"password": "codecov-pat"}])

    def show(entry, attrs, *, db_path, db_password, key_file):
        h.show_calls.append(
            {
                "entry": entry,
                "attrs": attrs,
                "db_path": db_path,
                "db_password": db_password,
                "key_file": key_file,
            }
        )
        return next(results)

    monkeypatch.setattr(server_module, "run_keepassxc_show_direct", show)
    response = h.ask({"op": "get", "path": "codecov/pat", "db": "infra"})
    assert response == {"ok": True, "value": "codecov-pat"}
    first, second = h.show_calls
    assert first["entry"] == "vault-passwords/infra" and first["db_path"] == "/vaults/master.kdbx"
    assert first["db_password"] == "master-pw" and first["attrs"] == {"Password": "Password"}
    assert second["entry"] == "codecov/pat" and second["db_path"] == "/vaults/infra.kdbx"
    assert second["db_password"] == "infra-vault-pw" and second["key_file"] == ""


@pytest.mark.parametrize(
    ("alias", "message"),
    [
        ("missing", "not found"),
        ("nosource", "no database_password_source"),
        ("chained", "beyond master is not supported"),
        ("nopath", "no database_path"),
    ],
)
def test_a_sub_vault_that_cannot_be_resolved_is_refused_by_reason(h, alias, message):
    h.unlock()
    with pytest.raises(KeepassCommandError, match=message):
        h.server._resolve_db_credentials(alias)


def test_an_empty_sub_vault_password_is_an_error_not_an_empty_unlock(h):
    h.unlock()
    h.show_result = {"Password": "   "}
    with pytest.raises(KeepassCommandError, match="returned empty password"):
        h.server._resolve_db_credentials("infra")


def test_a_locked_daemon_resolves_no_credentials(h):
    with pytest.raises(KeepassCommandError, match="daemon is locked"):
        h.server._resolve_db_credentials("master")


def test_a_vault_error_becomes_a_refusal_with_its_message_and_no_audit_entry(h):
    h.unlock()
    h.show_result = KeepassCommandError("entry not found")
    assert h.ask({"op": "get", "path": "web/x"}) == {"ok": False, "error": "entry not found"}
    assert h.events() == []


def test_a_missing_field_reads_as_empty_not_an_error(h):
    h.unlock()
    h.show_result = {}
    assert h.ask({"op": "get", "path": "web/x"}) == {"ok": True, "value": ""}


def test_an_unwritable_audit_log_does_not_stop_a_permitted_read(h, tmp_path, monkeypatch):
    h.unlock()
    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setattr(server_module, "_AUDIT_LOG", blocker / "audit.jsonl")  # parent is a file
    assert h.ask({"op": "get", "path": "web/x"}) == {"ok": True, "value": "the-secret"}


# --------------------------------------------------------------------------- the socket plumbing


class FakeConn:
    def __init__(self, *chunks: bytes, uid: int = ME, pid: int = 4242, fail_on_send: bool = False):
        self.chunks = list(chunks)
        self.cred = struct.pack("3i", pid, uid, 0)
        self.sent: list[bytes] = []
        self.closed = False
        self.fail_on_send = fail_on_send

    def getsockopt(self, level, option, size):
        return self.cred

    def recv(self, size):
        return self.chunks.pop(0) if self.chunks else b""

    def sendall(self, data):
        if self.fail_on_send:
            raise OSError("broken pipe")
        self.sent.append(data)

    def close(self):
        self.closed = True

    def reply(self) -> dict:
        return json.loads(b"".join(self.sent))


def test_a_request_split_across_reads_is_assembled_and_answered_then_closed(h):
    conn = FakeConn(b'{"op": "sta', b'tus"}\n')
    h.server._handle_connection(conn)
    assert conn.reply() == {"ok": True, "locked": True} and conn.closed


def test_the_peer_uid_comes_from_the_kernel_not_the_request(h):
    conn = FakeConn(b'{"op": "status", "uid": 0}\n', uid=ME + 1)
    h.server._handle_connection(conn)
    assert conn.reply() == {"ok": False, "error": "unauthorized"}


def test_the_peer_pid_reaches_the_caller_lookup(h, monkeypatch):
    seen = []
    monkeypatch.setattr(
        server_module, "resolve_caller_repo", lambda pid: seen.append(pid) or "simple"
    )
    h.unlock()
    h.server._handle_connection(FakeConn(b'{"op": "get", "path": "web/x"}\n', pid=31337))
    assert seen == [31337]


@pytest.mark.parametrize("payload", [b"not json\n", b"\n", b"{broken\n", b"[1, 2\n"])
def test_invalid_json_is_answered_with_a_fixed_message(h, payload):
    conn = FakeConn(payload)
    h.server._handle_connection(conn)
    assert conn.reply() == {"ok": False, "error": "invalid JSON"} and conn.closed


def test_an_unexpected_error_is_answered_without_its_details(h, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("secret detail: master-pw")

    monkeypatch.setattr(h.server, "handle_request", boom)
    conn = FakeConn(b'{"op": "status"}\n')
    h.server._handle_connection(conn)
    assert conn.reply() == {"ok": False, "error": "internal error"}
    assert "master-pw" not in b"".join(conn.sent).decode() and conn.closed


def test_a_client_that_hangs_up_does_not_crash_the_handler(h):
    conn = FakeConn(b'{"op": "status"}\n', fail_on_send=True)
    h.server._handle_connection(conn)
    assert conn.closed


def test_a_connection_that_sends_nothing_is_closed_with_an_error(h):
    conn = FakeConn()
    h.server._handle_connection(conn)
    assert conn.reply() == {"ok": False, "error": "invalid JSON"} and conn.closed


class FakeListener:
    def __init__(self, conns):
        self.conns = list(conns)
        self.bound = None
        self.listening = None
        self.closed = False

    def bind(self, path):
        self.bound = path

    def listen(self, backlog):
        self.listening = backlog

    def accept(self):
        if not self.conns:
            raise OSError("closed")
        return self.conns.pop(0), None

    def close(self):
        self.closed = True


def test_serve_binds_a_private_socket_replaces_a_stale_one_and_serves_each_connection(
    h, tmp_path, monkeypatch
):
    stale = tmp_path / "s.sock"
    stale.write_text("stale")
    listener = FakeListener([FakeConn(b'{"op": "status"}\n'), FakeConn(b'{"op": "status"}\n')])
    monkeypatch.setattr(server_module.socket, "socket", lambda *a, **k: listener)
    chmods = []
    monkeypatch.setattr(
        server_module.os, "chmod", lambda path, mode: chmods.append((str(path), mode))
    )
    started = []

    class SyncThread:
        def __init__(self, target, args, daemon):
            self.target, self.args = target, args
            assert daemon is True

        def start(self):
            started.append(self)
            self.target(*self.args)

    monkeypatch.setattr(server_module.threading, "Thread", SyncThread)
    h.server.serve()
    assert not stale.exists(), "a stale socket file must be removed before binding"
    assert listener.bound == str(tmp_path / "s.sock") and listener.listening == 16
    assert chmods == [(str(tmp_path / "s.sock"), 0o600)]
    assert len(started) == 2 and all(conn.closed for conn in [t.args[0] for t in started])


def test_default_socket_path_uses_the_environment_or_the_cache_dir(monkeypatch):
    monkeypatch.setenv("AUTO_PASS_PROVISIONING_SOCKET", "  /run/custom.sock ")
    assert server_module.default_socket_path() == Path("/run/custom.sock")
    monkeypatch.setenv("AUTO_PASS_PROVISIONING_SOCKET", "   ")
    assert server_module.default_socket_path() == server_module._DEFAULT_SOCKET
    monkeypatch.delenv("AUTO_PASS_PROVISIONING_SOCKET")
    assert server_module.default_socket_path().name == "provisioning.sock"
