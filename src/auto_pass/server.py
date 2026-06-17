"""
Provisioning daemon — Unix socket server.

Start with: auto-pass serve

The daemon unlocks the master KeePassXC vault interactively, then resolves
sub-vault passwords from the master on demand.  All vaults listed in
config/keepass-dbs.local.json are reachable; each repo in the allowlist
declares which vault(s) it may access.

Unlock from any shell on the machine::

    auto-pass unlock           # prompts for the KeePassXC master password
    auto-pass unlock --password-stdin <<< "$MY_PASSWORD"

Remote-unlock paths (all reach the same local command):
  - pit-box / webterm  : open a browser terminal and run auto-pass unlock
  - windscreen / xserver: forward an X session; use the GUI or a terminal
  - snowbridge / smb   : mount the share, open a terminal
  - shock-relay        : notification triggers you to SSH in and unlock

Protocol: newline-delimited JSON over a Unix domain socket (AF_UNIX / SOCK_STREAM).

Supported operations (all require caller UID == daemon owner UID):

    {"op": "unlock",  "password": "..."}            → {"ok": true}
    {"op": "lock"}                                   → {"ok": true}
    {"op": "status"}                                 → {"ok": true, "locked": bool}
    {"op": "reload"}                                 → {"ok": true}
    {"op": "get",  "path": "entry/path",
                   "field": "password",
                   "db":  "infra"}                   → {"ok": true, "value": "..."}
    {"op": "admin_context"}                          → {"ok": true,
                                                         "master_db_path": "...",
                                                         "master_db_password": "...",
                                                         "master_key_file": "..."}

The ``db`` field in ``get`` is optional for single-vault repos; the daemon
infers it from the allowlist.  Multi-vault repos must specify it explicitly.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import signal
import socket
import struct
import threading
from datetime import UTC, datetime
from pathlib import Path

from .allowlist import AllowlistEnforcer, default_allowlist_path, resolve_caller_repo
from .dbindex import DatabaseIndexError, resolve_database_alias
from .keepassxc import KeepassCommandError, run_keepassxc_show_direct, validate_keepassxc_database

log = logging.getLogger(__name__)

_PROVISION_SOCKET_ENV = "AUTO_PASS_PROVISIONING_SOCKET"
_DEFAULT_SOCKET = Path.home() / ".cache" / "auto-pass" / "provisioning.sock"
_AUDIT_LOG = Path.home() / ".cache" / "auto-pass" / "audit.jsonl"

_SO_PEERCRED: int = getattr(socket, "SO_PEERCRED", 17)
_PEERCRED_FMT = "3i"
_PEERCRED_SIZE = struct.calcsize(_PEERCRED_FMT)


def _append_audit(event: dict) -> None:
    try:
        _AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(_AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, separators=(",", ":")) + "\n")
    except OSError:
        pass


def default_socket_path() -> Path:
    env_val = os.environ.get(_PROVISION_SOCKET_ENV, "").strip()
    return Path(env_val) if env_val else _DEFAULT_SOCKET


class ProvisioningServer:
    """Unix socket daemon serving pre-approved credentials to local repos.

    Unlocks the master vault interactively; resolves sub-vault passwords
    from the master on demand using config/keepass-dbs.local.json.

    All ``get`` operations are gated by the per-repo allowlist which specifies
    both the permitted vault (db alias) and entry path globs.
    """

    def __init__(
        self,
        *,
        master_db_path: str,
        master_key_file: str = "",
        master_db_alias: str = "master",
        allowlist_path: Path | None = None,
        socket_path: Path | None = None,
        db_index_path: Path | None = None,
    ) -> None:
        self._master_db_path = master_db_path
        self._master_key_file = master_key_file
        self._master_db_alias = master_db_alias
        self._socket_path = socket_path or default_socket_path()
        self._enforcer = AllowlistEnforcer(allowlist_path or default_allowlist_path())
        self._db_index_path = db_index_path
        self._state_lock = threading.Lock()
        self._db_password: str | None = None
        self._owner_uid = os.getuid()

    @property
    def is_unlocked(self) -> bool:
        with self._state_lock:
            return self._db_password is not None

    def unlock(self, password: str) -> bool:
        """Validate password against the master vault, then store it."""
        if not validate_keepassxc_database(self._master_db_path, password, self._master_key_file):
            return False
        with self._state_lock:
            self._db_password = password
        return True

    def lock(self) -> None:
        with self._state_lock:
            self._db_password = None

    # ------------------------------------------------------------------
    # Sub-vault password resolution
    # ------------------------------------------------------------------

    def _resolve_db_credentials(self, db_alias: str) -> tuple[str, str, str]:
        """Return (db_path, db_password, key_file) for any configured alias.

        For the master alias, returns the in-memory password directly.
        For sub-vaults, reads the password from the master vault using the
        database_password_source field in keepass-dbs.local.json.
        """
        with self._state_lock:
            master_pw = self._db_password

        if master_pw is None:
            raise KeepassCommandError("daemon is locked")

        if db_alias == self._master_db_alias:
            return self._master_db_path, master_pw, self._master_key_file

        try:
            db_entry = resolve_database_alias(db_alias, self._db_index_path)
        except DatabaseIndexError as exc:
            raise KeepassCommandError(str(exc)) from exc

        db_path = str(db_entry.get("database_path", "")).strip()
        if not db_path:
            raise KeepassCommandError(f"no database_path for alias {db_alias!r}")

        pw_source = db_entry.get("database_password_source")
        if not pw_source:
            raise KeepassCommandError(
                f"alias {db_alias!r} has no database_password_source — "
                "cannot auto-resolve its password from the master vault"
            )

        source_alias = str(pw_source.get("database_alias", "master")).strip()
        if source_alias != self._master_db_alias:
            raise KeepassCommandError(
                f"password-source chain beyond master is not supported "
                f"(alias {db_alias!r} → {source_alias!r})"
            )

        source_entry = str(pw_source.get("entry", "")).strip()
        source_attr = str(pw_source.get("attribute", "Password")).strip()

        pw_fields = run_keepassxc_show_direct(
            source_entry,
            {source_attr: source_attr},
            db_path=self._master_db_path,
            db_password=master_pw,
            key_file=self._master_key_file,
        )
        sub_pw = pw_fields.get(source_attr, "").strip()
        if not sub_pw:
            raise KeepassCommandError(
                f"master entry {source_entry!r} returned empty password for alias {db_alias!r}"
            )

        return db_path, sub_pw, ""

    # ------------------------------------------------------------------
    # Request dispatch
    # ------------------------------------------------------------------

    def handle_request(self, request: dict, caller_pid: int, caller_uid: int) -> dict:
        if caller_uid != self._owner_uid:
            return {"ok": False, "error": "unauthorized"}

        op = str(request.get("op", ""))

        if op == "status":
            return {"ok": True, "locked": not self.is_unlocked}

        if op == "reload":
            self._enforcer.reload()
            return {"ok": True}

        if op == "lock":
            self.lock()
            return {"ok": True}

        if op == "unlock":
            password = str(request.get("password", ""))
            if not password:
                return {"ok": False, "error": "password required"}
            if self.unlock(password):
                log.info("daemon unlocked by pid=%d", caller_pid)
                return {"ok": True}
            return {"ok": False, "error": "invalid password"}

        if op == "get":
            return self._handle_get(request, caller_pid=caller_pid)

        if op == "admin_context":
            with self._state_lock:
                if self._db_password is None:
                    return {"ok": False, "error": "daemon is locked"}
                return {
                    "ok": True,
                    "master_db_path": self._master_db_path,
                    "master_db_password": self._db_password,
                    "master_key_file": self._master_key_file,
                    "master_db_alias": self._master_db_alias,
                }

        return {"ok": False, "error": f"unknown op: {op!r}"}

    def _handle_get(self, request: dict, *, caller_pid: int) -> dict:
        if not self.is_unlocked:
            return {"ok": False, "error": "daemon is locked — run: auto-pass unlock"}

        entry_path = str(request.get("path", "")).strip()
        field = str(request.get("field", "password")).strip() or "password"
        requested_db = str(request.get("db", "")).strip() or None

        if not entry_path:
            return {"ok": False, "error": "path required"}

        repo_id = resolve_caller_repo(caller_pid)
        if repo_id is None:
            log.warning("get denied: unresolvable caller identity pid=%d", caller_pid)
            return {"ok": False, "error": "could not resolve caller identity"}

        # Resolve which DB to use: explicit in request, or from allowlist default
        if requested_db:
            db_alias = requested_db
        else:
            db_alias = self._enforcer.repo_default_db(repo_id)
            if db_alias is None:
                return {
                    "ok": False,
                    "error": (
                        f"repo '{repo_id}' has multi-vault config — specify 'db' in the request"
                    ),
                }

        if not self._enforcer.is_permitted(repo_id, db_alias, entry_path):
            log.warning(
                "get denied: repo=%r db=%r path=%r pid=%d",
                repo_id,
                db_alias,
                entry_path,
                caller_pid,
            )
            return {
                "ok": False,
                "error": (
                    f"repo '{repo_id}' is not permitted to access "
                    f"'{entry_path}' in vault '{db_alias}'"
                ),
            }

        try:
            db_path, db_password, key_file = self._resolve_db_credentials(db_alias)
            fields = run_keepassxc_show_direct(
                entry_path,
                {field: field},
                db_path=db_path,
                db_password=db_password,
                key_file=key_file,
            )
        except KeepassCommandError as exc:
            return {"ok": False, "error": str(exc)}

        value = fields.get(field, "")
        _append_audit(
            {
                "ts": datetime.now(UTC).isoformat(),
                "op": "get",
                "repo": repo_id,
                "db": db_alias,
                "path": entry_path,
                "field": field,
                "pid": caller_pid,
            }
        )
        return {"ok": True, "value": value}

    # ------------------------------------------------------------------
    # Connection handling
    # ------------------------------------------------------------------

    def _handle_connection(self, conn: socket.socket) -> None:
        try:
            cred_bytes = conn.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED, _PEERCRED_SIZE)
            pid, uid, _gid = struct.unpack(_PEERCRED_FMT, cred_bytes)

            data = b""
            while b"\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk

            request = json.loads(data.strip())
            response = self.handle_request(request, caller_pid=pid, caller_uid=uid)
            conn.sendall(json.dumps(response).encode() + b"\n")
        except json.JSONDecodeError:
            with contextlib.suppress(OSError):
                conn.sendall(json.dumps({"ok": False, "error": "invalid JSON"}).encode() + b"\n")
        except Exception as exc:
            log.error("connection handler error: %s", exc)
            with contextlib.suppress(OSError):
                conn.sendall(json.dumps({"ok": False, "error": "internal error"}).encode() + b"\n")
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Main serve loop
    # ------------------------------------------------------------------

    def serve(self) -> None:
        """Bind the socket and serve requests until interrupted (SIGINT/SIGTERM)."""
        self._socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self._socket_path.exists():
            self._socket_path.unlink()

        srv_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv_sock.bind(str(self._socket_path))
        os.chmod(self._socket_path, 0o600)
        srv_sock.listen(16)

        log.info(
            "provisioning server listening on %s (master=%s) — locked; run: auto-pass unlock",
            self._socket_path,
            self._master_db_path,
        )

        def _shutdown(signum: int, frame: object) -> None:
            log.info("shutting down (signal %d)", signum)
            self.lock()
            with contextlib.suppress(OSError):
                srv_sock.close()
            with contextlib.suppress(OSError):
                self._socket_path.unlink(missing_ok=True)

        try:
            signal.signal(signal.SIGTERM, _shutdown)
            signal.signal(signal.SIGINT, _shutdown)
        except (OSError, ValueError):
            pass

        while True:
            try:
                conn, _ = srv_sock.accept()
                threading.Thread(target=self._handle_connection, args=(conn,), daemon=True).start()
            except OSError:
                break
