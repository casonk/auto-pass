"""
Thin client for downstream repos to request credentials from the provisioning daemon.

Basic usage::

    from auto_pass.client import ProvisioningClient, ProvisioningClientError

    client = ProvisioningClient()
    try:
        password = client.get("messaging/gmail", field="password")
        username = client.get("messaging/gmail", field="username")
    except ProvisioningClientError as exc:
        # daemon locked, not permitted, entry not found, etc.
        raise RuntimeError(f"credential unavailable: {exc}") from exc

The socket path defaults to ~/.cache/auto-pass/provisioning.sock and can be
overridden with the AUTO_PASS_PROVISIONING_SOCKET environment variable.
"""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

_PROVISION_SOCKET_ENV = "AUTO_PASS_PROVISIONING_SOCKET"
_DEFAULT_SOCKET = Path.home() / ".cache" / "auto-pass" / "provisioning.sock"


class ProvisioningClientError(RuntimeError):
    """Raised when the provisioning daemon returns an error or is unreachable."""


class ProvisioningClient:
    """Client for the auto-pass provisioning Unix socket daemon."""

    def __init__(self, socket_path: Path | None = None) -> None:
        env_val = os.environ.get(_PROVISION_SOCKET_ENV, "").strip()
        self._socket_path = Path(env_val) if env_val else (socket_path or _DEFAULT_SOCKET)

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------

    def _send(self, request: dict) -> dict:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(str(self._socket_path))
            sock.sendall(json.dumps(request).encode() + b"\n")
            data = b""
            while b"\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            return json.loads(data.strip())
        finally:
            sock.close()

    def _require_ok(self, response: dict, label: str = "") -> dict:
        if not response.get("ok"):
            error = response.get("error", "unknown error")
            raise ProvisioningClientError(f"{label}: {error}" if label else error)
        return response

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(
        self,
        entry_path: str,
        field: str = "password",
        db: str | None = None,
    ) -> str:
        """Retrieve a single field from a KeePassXC entry via the daemon.

        Raises ProvisioningClientError if the daemon is locked, the calling
        repo is not pre-approved for this entry, or the entry does not exist.
        """
        request: dict = {"op": "get", "path": entry_path, "field": field}
        if db:
            request["db"] = db
        response = self._require_ok(
            self._send(request),
            f"get({entry_path!r}, {field!r})",
        )
        return str(response.get("value", ""))

    def set(self, entry_path: str, value: str, *, db: str) -> None:
        """Replace the password of an existing entry the calling repo may write.

        Needs ``writable_paths`` in the allowlist; read access alone is not enough. The entry
        must already exist, and ``db`` is required because a write never infers its vault.
        """
        request = {"op": "set", "path": entry_path, "value": value, "db": db}
        self._require_ok(self._send(request), f"set({entry_path!r})")

    def status(self) -> dict:
        """Return the daemon status dict, e.g. ``{"ok": True, "locked": False}``."""
        return self._require_ok(self._send({"op": "status"}), "status")

    def unlock(self, password: str) -> None:
        """Send the KeePassXC master password to the daemon to unlock it."""
        self._require_ok(self._send({"op": "unlock", "password": password}), "unlock")

    def lock(self) -> None:
        """Instruct the daemon to clear its in-memory master password."""
        self._require_ok(self._send({"op": "lock"}), "lock")

    def reload(self) -> None:
        """Tell the daemon to reload the allowlist from disk."""
        self._require_ok(self._send({"op": "reload"}), "reload")

    def admin_context(self) -> dict:
        """Return db_path, db_password, key_file from the daemon for privileged ops.

        Requires the daemon to be unlocked. Used by the web server to perform
        direct KeePassXC operations (entry creation, full reads) as the admin.
        The daemon also requires this process's repository identity in the
        allowlist's top-level ``admin_repos`` list.
        """
        return self._require_ok(self._send({"op": "admin_context"}), "admin_context")

    def is_running(self) -> bool:
        """Return True if the daemon socket is accepting connections."""
        try:
            self.status()
            return True
        except (OSError, ProvisioningClientError):
            return False
