from __future__ import annotations

import json
import socket
import threading
from pathlib import Path

import pytest

from auto_pass.client import ProvisioningClient, ProvisioningClientError


def _mock_server(sock_path: Path, handler) -> threading.Thread:
    """Bind a one-shot Unix socket server in a background thread."""
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(str(sock_path))
    srv.listen(4)
    srv.settimeout(5.0)

    def _serve():
        try:
            conn, _ = srv.accept()
            data = b""
            while b"\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            request = json.loads(data.strip())
            response = handler(request)
            conn.sendall(json.dumps(response).encode() + b"\n")
            conn.close()
        except Exception:
            pass
        finally:
            srv.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return t


class TestProvisioningClientGet:
    def test_get_returns_value(self, tmp_path):
        sock_path = tmp_path / "test.sock"
        _mock_server(sock_path, lambda _req: {"ok": True, "value": "mysecret"})
        client = ProvisioningClient(socket_path=sock_path)
        assert client.get("web/github") == "mysecret"

    def test_get_sends_correct_op_and_path(self, tmp_path):
        sock_path = tmp_path / "test.sock"
        captured: list[dict] = []

        def handler(req):
            captured.append(req)
            return {"ok": True, "value": "x"}

        _mock_server(sock_path, handler)
        client = ProvisioningClient(socket_path=sock_path)
        client.get("infra/nordvpn", field="username")
        assert captured[0] == {"op": "get", "path": "infra/nordvpn", "field": "username"}

    def test_get_error_response_raises(self, tmp_path):
        sock_path = tmp_path / "test.sock"
        _mock_server(sock_path, lambda _req: {"ok": False, "error": "not permitted"})
        client = ProvisioningClient(socket_path=sock_path)
        with pytest.raises(ProvisioningClientError, match="not permitted"):
            client.get("web/github")


class TestProvisioningClientStatus:
    def test_status_returns_locked_state(self, tmp_path):
        sock_path = tmp_path / "test.sock"
        _mock_server(sock_path, lambda _req: {"ok": True, "locked": False})
        client = ProvisioningClient(socket_path=sock_path)
        result = client.status()
        assert result["locked"] is False

    def test_is_running_true_when_server_up(self, tmp_path):
        sock_path = tmp_path / "test.sock"
        _mock_server(sock_path, lambda _req: {"ok": True, "locked": True})
        client = ProvisioningClient(socket_path=sock_path)
        assert client.is_running()

    def test_is_running_false_when_no_server(self, tmp_path):
        sock_path = tmp_path / "no_server.sock"
        client = ProvisioningClient(socket_path=sock_path)
        assert not client.is_running()


class TestProvisioningClientUnlockLock:
    def test_unlock_success(self, tmp_path):
        sock_path = tmp_path / "test.sock"
        _mock_server(sock_path, lambda _req: {"ok": True})
        client = ProvisioningClient(socket_path=sock_path)
        client.unlock("password123")  # should not raise

    def test_unlock_failure_raises(self, tmp_path):
        sock_path = tmp_path / "test.sock"
        _mock_server(sock_path, lambda _req: {"ok": False, "error": "invalid password"})
        client = ProvisioningClient(socket_path=sock_path)
        with pytest.raises(ProvisioningClientError, match="invalid password"):
            client.unlock("wrong")

    def test_lock_success(self, tmp_path):
        sock_path = tmp_path / "test.sock"
        _mock_server(sock_path, lambda _req: {"ok": True})
        client = ProvisioningClient(socket_path=sock_path)
        client.lock()  # should not raise

    def test_reload_success(self, tmp_path):
        sock_path = tmp_path / "test.sock"
        _mock_server(sock_path, lambda _req: {"ok": True})
        client = ProvisioningClient(socket_path=sock_path)
        client.reload()  # should not raise
