"""The daemon's scoped `set`: change the password of an existing entry a repo may write."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from auto_pass import keepassxc as kp
from auto_pass.allowlist import AllowlistEnforcer
from auto_pass.client import ProvisioningClient, ProvisioningClientError
from auto_pass.server import ProvisioningServer

MY_UID = os.getuid()
READ_ONLY = '[repos.gate.vaults.master]\nallowed_paths = ["portfolio/pin/*"]\n'
WRITABLE = (
    '[repos.gate.vaults.master]\nallowed_paths = ["portfolio/pin/*", "portfolio/key"]\n'
    'writable_paths = ["portfolio/pin/*"]\n'
)


def _server(tmp_path: Path, allowlist: str) -> ProvisioningServer:
    path = tmp_path / "allowlist.toml"
    path.write_text(allowlist)
    server = ProvisioningServer(
        master_db_path="/fake/db.kdbx",
        master_key_file="",
        allowlist_path=path,
        socket_path=tmp_path / "s.sock",
    )
    server._db_password = "vault-pw"
    return server


def _set(server, **fields):
    request = {"op": "set", "path": "portfolio/pin/app", "value": "4821", "db": "master", **fields}
    return server.handle_request(request, caller_pid=1, caller_uid=MY_UID)


class TestAllowlistWritable:
    def test_writing_is_granted_separately_from_reading(self, tmp_path):
        (tmp_path / "a.toml").write_text(WRITABLE)
        enforcer = AllowlistEnforcer(tmp_path / "a.toml")
        assert enforcer.is_writable("gate", "master", "portfolio/pin/app")
        assert not enforcer.is_writable("gate", "master", "portfolio/key")  # readable, not writable
        assert enforcer.is_permitted("gate", "master", "portfolio/key")

    def test_read_access_alone_is_not_write_access(self, tmp_path):
        (tmp_path / "a.toml").write_text(READ_ONLY)
        assert not AllowlistEnforcer(tmp_path / "a.toml").is_writable(
            "gate", "master", "portfolio/pin/app"
        )

    def test_writable_paths_alone_do_not_grant_reading(self, tmp_path):
        (tmp_path / "a.toml").write_text('[repos.gate.vaults.master]\nwritable_paths = ["x/*"]\n')
        enforcer = AllowlistEnforcer(tmp_path / "a.toml")
        assert enforcer.is_writable("gate", "master", "x/y")
        assert not enforcer.is_permitted("gate", "master", "x/y")

    def test_simple_form_and_wrong_vault_or_repo(self, tmp_path):
        (tmp_path / "a.toml").write_text('[repos.gate]\ndb = "master"\nwritable_paths = ["x/*"]\n')
        enforcer = AllowlistEnforcer(tmp_path / "a.toml")
        assert enforcer.is_writable("gate", "master", "x/y")
        assert not enforcer.is_writable("gate", "other", "x/y")
        assert not enforcer.is_writable("someone-else", "master", "x/y")


class TestServerSet:
    def test_permitted_write_reaches_the_vault_and_is_audited_without_the_value(self, tmp_path):
        server = _server(tmp_path, WRITABLE)
        with (
            patch("auto_pass.server.resolve_caller_repo", return_value="gate"),
            patch.object(server, "_resolve_db_credentials", return_value=("/db", "pw", "")),
            patch("auto_pass.server.run_keepassxc_set_password_direct") as write,
            patch("auto_pass.server._append_audit") as audit,
        ):
            assert _set(server) == {"ok": True}
        write.assert_called_once_with(
            "portfolio/pin/app", "4821", db_path="/db", db_password="pw", key_file=""
        )
        event = audit.call_args.args[0]
        assert (
            event["op"] == "set"
            and event["path"] == "portfolio/pin/app"
            and event["repo"] == "gate"
        )
        assert "4821" not in json.dumps(event)

    def test_read_only_repo_is_refused(self, tmp_path):
        server = _server(tmp_path, READ_ONLY)
        with (
            patch("auto_pass.server.resolve_caller_repo", return_value="gate"),
            patch("auto_pass.server.run_keepassxc_set_password_direct") as write,
        ):
            response = _set(server)
        assert response["ok"] is False and "not permitted to write" in response["error"]
        write.assert_not_called()

    def test_locked_daemon_unknown_caller_and_bad_requests_are_refused(self, tmp_path):
        server = _server(tmp_path, WRITABLE)
        with patch("auto_pass.server.run_keepassxc_set_password_direct") as write:
            server._db_password = None
            assert "locked" in _set(server)["error"]
            server._db_password = "vault-pw"
            with patch("auto_pass.server.resolve_caller_repo", return_value=None):
                assert "identity" in _set(server)["error"]
            with patch("auto_pass.server.resolve_caller_repo", return_value="gate"):
                assert _set(server, path="")["error"] == "path required"
                assert _set(server, value="")["error"] == "value required"
                assert _set(server, value=1234)["error"] == "value required"
                assert _set(server, db="")["error"] == "db required for set"
        write.assert_not_called()

    def test_vault_errors_are_returned_not_raised(self, tmp_path):
        server = _server(tmp_path, WRITABLE)
        with (
            patch("auto_pass.server.resolve_caller_repo", return_value="gate"),
            patch.object(server, "_resolve_db_credentials", return_value=("/db", "pw", "")),
            patch(
                "auto_pass.server.run_keepassxc_set_password_direct",
                side_effect=kp.KeepassCommandError("no entry"),
            ),
        ):
            assert _set(server) == {"ok": False, "error": "no entry"}

    def test_other_users_are_rejected(self, tmp_path):
        server = _server(tmp_path, WRITABLE)
        response = server.handle_request(
            {"op": "set", "path": "portfolio/pin/app", "value": "1", "db": "master"},
            caller_pid=1,
            caller_uid=MY_UID + 1,
        )
        assert response["error"] == "unauthorized"


class TestDirectWrite:
    def test_edits_an_existing_entry_through_stdin_and_never_argv(self):
        done = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with patch.object(kp.subprocess, "run", return_value=done) as run:
            kp.run_keepassxc_set_password_direct(
                "portfolio/pin/app", "4821", db_path="/db", db_password="vault-pw"
            )
        command = run.call_args.args[0]
        assert command[:4] == ["keepassxc-cli", "edit", "-q", "-p"]
        assert command[-2:] == ["/db", "portfolio/pin/app"]
        assert "4821" not in command and "vault-pw" not in command
        assert run.call_args.kwargs["input"] == "vault-pw\n4821\n4821\n"

    def test_a_key_file_is_passed(self):
        done = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with patch.object(kp.subprocess, "run", return_value=done) as run:
            kp.run_keepassxc_set_password_direct(
                "e", "pw", db_path="/db", db_password="v", key_file="/k"
            )
        assert run.call_args.args[0][4:6] == ["-k", "/k"]

    def test_unusable_values_are_rejected_before_running_anything(self):
        with patch.object(kp.subprocess, "run") as run:
            for bad in ("", "a\nb", "a\rb"):
                with pytest.raises(kp.KeepassCommandError):
                    kp.run_keepassxc_set_password_direct("e", bad, db_path="/db", db_password="v")
            with pytest.raises(kp.KeepassCommandError):
                kp.run_keepassxc_set_password_direct("", "pw", db_path="/db", db_password="v")
            with pytest.raises(kp.KeepassCommandError):
                kp.run_keepassxc_set_password_direct("e", "pw", db_path="", db_password="v")
        run.assert_not_called()

    def test_a_missing_entry_is_an_error_not_a_creation(self):
        missing = subprocess.CompletedProcess(
            [], 1, stdout="", stderr="Could not find entry with path e."
        )
        with patch.object(kp.subprocess, "run", return_value=missing) as run:
            with pytest.raises(kp.KeepassCommandError):
                kp.run_keepassxc_set_password_direct("e", "pw", db_path="/db", db_password="v")
        assert run.call_count == 1  # no follow-up `add`


class TestClientSet:
    def _serve(self, path: Path, reply: dict, seen: list[dict]) -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        listener.listen(1)

        def run():
            conn, _ = listener.accept()
            seen.append(json.loads(conn.makefile().readline()))
            conn.sendall(json.dumps(reply).encode() + b"\n")
            conn.close()
            listener.close()

        threading.Thread(target=run, daemon=True).start()

    def test_sends_the_set_operation(self, tmp_path):
        seen: list[dict] = []
        self._serve(tmp_path / "s", {"ok": True}, seen)
        ProvisioningClient(socket_path=tmp_path / "s").set("portfolio/pin/app", "4821", db="master")
        assert seen == [{"op": "set", "path": "portfolio/pin/app", "value": "4821", "db": "master"}]

    def test_a_refusal_raises_without_echoing_the_value(self, tmp_path):
        self._serve(tmp_path / "s", {"ok": False, "error": "not permitted to write"}, [])
        with pytest.raises(ProvisioningClientError) as error:
            ProvisioningClient(socket_path=tmp_path / "s").set(
                "portfolio/pin/app", "4821", db="master"
            )
        assert "4821" not in str(error.value)
