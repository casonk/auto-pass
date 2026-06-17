from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from auto_pass.server import ProvisioningServer


def _make_server(tmp_path: Path, allowlist_content: str = "[repos]\n") -> ProvisioningServer:
    allowlist = tmp_path / "allowlist.toml"
    allowlist.write_bytes(allowlist_content.encode())
    return ProvisioningServer(
        master_db_path="/fake/db.kdbx",
        master_key_file="",
        allowlist_path=allowlist,
        socket_path=tmp_path / "test.sock",
    )


_MY_UID = os.getuid()
_OTHER_UID = _MY_UID + 1


class TestProvisioningServerHandleRequest:
    def test_status_when_locked(self, tmp_path):
        srv = _make_server(tmp_path)
        resp = srv.handle_request({"op": "status"}, caller_pid=1, caller_uid=_MY_UID)
        assert resp == {"ok": True, "locked": True}

    def test_status_when_unlocked(self, tmp_path):
        srv = _make_server(tmp_path)
        srv._db_password = "secret"
        resp = srv.handle_request({"op": "status"}, caller_pid=1, caller_uid=_MY_UID)
        assert resp == {"ok": True, "locked": False}

    def test_different_uid_rejected(self, tmp_path):
        srv = _make_server(tmp_path)
        resp = srv.handle_request({"op": "status"}, caller_pid=1, caller_uid=_OTHER_UID)
        assert resp["ok"] is False
        assert "unauthorized" in resp["error"]

    def test_lock_clears_password(self, tmp_path):
        srv = _make_server(tmp_path)
        srv._db_password = "stored"
        srv.handle_request({"op": "lock"}, caller_pid=1, caller_uid=_MY_UID)
        assert not srv.is_unlocked

    def test_reload_returns_ok(self, tmp_path):
        srv = _make_server(tmp_path)
        resp = srv.handle_request({"op": "reload"}, caller_pid=1, caller_uid=_MY_UID)
        assert resp == {"ok": True}

    def test_unknown_op(self, tmp_path):
        srv = _make_server(tmp_path)
        resp = srv.handle_request({"op": "bogus"}, caller_pid=1, caller_uid=_MY_UID)
        assert resp["ok"] is False
        assert "unknown op" in resp["error"]

    def test_unlock_with_invalid_password(self, tmp_path):
        srv = _make_server(tmp_path)
        with patch("auto_pass.server.validate_keepassxc_database", return_value=False):
            resp = srv.handle_request(
                {"op": "unlock", "password": "wrong"}, caller_pid=1, caller_uid=_MY_UID
            )
        assert resp["ok"] is False
        assert not srv.is_unlocked

    def test_unlock_with_valid_password(self, tmp_path):
        srv = _make_server(tmp_path)
        with patch("auto_pass.server.validate_keepassxc_database", return_value=True):
            resp = srv.handle_request(
                {"op": "unlock", "password": "correct"}, caller_pid=1, caller_uid=_MY_UID
            )
        assert resp == {"ok": True}
        assert srv.is_unlocked

    def test_unlock_then_lock_cycle(self, tmp_path):
        srv = _make_server(tmp_path)
        with patch("auto_pass.server.validate_keepassxc_database", return_value=True):
            srv.handle_request({"op": "unlock", "password": "pw"}, caller_pid=1, caller_uid=_MY_UID)
        assert srv.is_unlocked
        srv.handle_request({"op": "lock"}, caller_pid=1, caller_uid=_MY_UID)
        assert not srv.is_unlocked

    def test_unlock_missing_password_field(self, tmp_path):
        srv = _make_server(tmp_path)
        resp = srv.handle_request({"op": "unlock"}, caller_pid=1, caller_uid=_MY_UID)
        assert resp["ok"] is False
        assert "password required" in resp["error"]


class TestProvisioningServerGet:
    def test_get_while_locked_returns_error(self, tmp_path):
        srv = _make_server(tmp_path)
        resp = srv.handle_request(
            {"op": "get", "path": "web/github", "field": "password", "db": "master"},
            caller_pid=1,
            caller_uid=_MY_UID,
        )
        assert resp["ok"] is False
        assert "locked" in resp["error"]

    def test_get_missing_path_returns_error(self, tmp_path):
        srv = _make_server(tmp_path)
        srv._db_password = "pw"
        with patch("auto_pass.server.resolve_caller_repo", return_value="r"):
            resp = srv.handle_request(
                {"op": "get", "field": "password", "db": "master"},
                caller_pid=1,
                caller_uid=_MY_UID,
            )
        assert resp["ok"] is False
        assert "path required" in resp["error"]

    def test_get_unresolvable_identity_returns_error(self, tmp_path):
        srv = _make_server(tmp_path)
        srv._db_password = "pw"
        with patch("auto_pass.server.resolve_caller_repo", return_value=None):
            resp = srv.handle_request(
                {"op": "get", "path": "web/github", "db": "master"},
                caller_pid=1,
                caller_uid=_MY_UID,
            )
        assert resp["ok"] is False
        assert "identity" in resp["error"]

    def test_get_not_in_allowlist_returns_error(self, tmp_path):
        allowlist = '[repos.other-repo]\ndb = "master"\nallowed_paths = ["web/github"]\n'
        srv = _make_server(tmp_path, allowlist)
        srv._db_password = "pw"
        with patch("auto_pass.server.resolve_caller_repo", return_value="my-repo"):
            resp = srv.handle_request(
                {"op": "get", "path": "web/github", "db": "master"},
                caller_pid=1,
                caller_uid=_MY_UID,
            )
        assert resp["ok"] is False
        assert "not permitted" in resp["error"]

    def test_get_path_not_matching_glob_denied(self, tmp_path):
        allowlist = '[repos.my-repo]\ndb = "master"\nallowed_paths = ["infra/*"]\n'
        srv = _make_server(tmp_path, allowlist)
        srv._db_password = "pw"
        with patch("auto_pass.server.resolve_caller_repo", return_value="my-repo"):
            resp = srv.handle_request(
                {"op": "get", "path": "web/github", "db": "master"},
                caller_pid=1,
                caller_uid=_MY_UID,
            )
        assert resp["ok"] is False
        assert "not permitted" in resp["error"]

    def test_get_permitted_returns_value(self, tmp_path):
        allowlist = '[repos.my-repo]\ndb = "master"\nallowed_paths = ["web/github"]\n'
        srv = _make_server(tmp_path, allowlist)
        srv._db_password = "pw"
        with (
            patch("auto_pass.server.resolve_caller_repo", return_value="my-repo"),
            patch(
                "auto_pass.server.run_keepassxc_show_direct",
                return_value={"password": "s3cr3t"},
            ),
        ):
            resp = srv.handle_request(
                {"op": "get", "path": "web/github", "field": "password", "db": "master"},
                caller_pid=1,
                caller_uid=_MY_UID,
            )
        assert resp == {"ok": True, "value": "s3cr3t"}

    def test_get_permitted_glob_match(self, tmp_path):
        allowlist = '[repos.my-repo]\ndb = "master"\nallowed_paths = ["services/*"]\n'
        srv = _make_server(tmp_path, allowlist)
        srv._db_password = "pw"
        with (
            patch("auto_pass.server.resolve_caller_repo", return_value="my-repo"),
            patch(
                "auto_pass.server.run_keepassxc_show_direct",
                return_value={"username": "admin"},
            ),
        ):
            resp = srv.handle_request(
                {"op": "get", "path": "services/vpn", "field": "username", "db": "master"},
                caller_pid=1,
                caller_uid=_MY_UID,
            )
        assert resp == {"ok": True, "value": "admin"}

    def test_get_keepass_error_propagated(self, tmp_path):
        from auto_pass.keepassxc import KeepassCommandError

        allowlist = '[repos.my-repo]\ndb = "master"\nallowed_paths = ["web/github"]\n'
        srv = _make_server(tmp_path, allowlist)
        srv._db_password = "pw"
        with (
            patch("auto_pass.server.resolve_caller_repo", return_value="my-repo"),
            patch(
                "auto_pass.server.run_keepassxc_show_direct",
                side_effect=KeepassCommandError("entry not found"),
            ),
        ):
            resp = srv.handle_request(
                {"op": "get", "path": "web/github", "db": "master"},
                caller_pid=1,
                caller_uid=_MY_UID,
            )
        assert resp["ok"] is False
        assert "entry not found" in resp["error"]

    def test_get_no_db_field_uses_allowlist_default(self, tmp_path):
        """When request omits db, repo_default_db() from allowlist is used."""
        allowlist = '[repos.my-repo]\ndb = "master"\nallowed_paths = ["web/github"]\n'
        srv = _make_server(tmp_path, allowlist)
        srv._db_password = "pw"
        with (
            patch("auto_pass.server.resolve_caller_repo", return_value="my-repo"),
            patch(
                "auto_pass.server.run_keepassxc_show_direct",
                return_value={"password": "s3cr3t"},
            ),
        ):
            resp = srv.handle_request(
                {"op": "get", "path": "web/github", "field": "password"},
                caller_pid=1,
                caller_uid=_MY_UID,
            )
        assert resp == {"ok": True, "value": "s3cr3t"}

    def test_get_no_db_and_multi_vault_repo_errors(self, tmp_path):
        """Multi-vault repos without db in request get a clear error."""
        allowlist = (
            '[repos.my-repo.vaults.master]\nallowed_paths = ["a/b"]\n'
            '[repos.my-repo.vaults.infra]\nallowed_paths = ["c/d"]\n'
        )
        srv = _make_server(tmp_path, allowlist)
        srv._db_password = "pw"
        with patch("auto_pass.server.resolve_caller_repo", return_value="my-repo"):
            resp = srv.handle_request(
                {"op": "get", "path": "a/b"},
                caller_pid=1,
                caller_uid=_MY_UID,
            )
        assert resp["ok"] is False
        assert "specify" in resp["error"]
