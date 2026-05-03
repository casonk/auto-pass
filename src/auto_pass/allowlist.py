from __future__ import annotations

import fnmatch
import logging
import os
import subprocess
import tomllib
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

_PROVISION_ALLOWLIST_ENV = "AUTO_PASS_PROVISIONING_ALLOWLIST"

_repo_root_cache: dict[Path, Optional[str]] = {}


def _git_remote_name(repo_root: Path) -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        url = result.stdout.strip().rstrip("/")
        name = url.split("/")[-1].removesuffix(".git")
        return name or None
    except Exception:
        return None


def _find_git_root(start: Path) -> Optional[Path]:
    candidate = start.resolve()
    while True:
        if (candidate / ".git").exists():
            return candidate
        parent = candidate.parent
        if parent == candidate:
            return None
        candidate = parent


def resolve_caller_repo(pid: int) -> Optional[str]:
    """Return the git repo name for the process with the given PID.

    Reads /proc/<pid>/cwd, walks up to the git root, and returns the
    last component of the origin remote URL (without .git). Falls back
    to the directory name if there is no remote. Returns None when the
    caller cannot be mapped to a git repository.
    """
    try:
        cwd = Path(os.readlink(f"/proc/{pid}/cwd")).resolve()
    except OSError:
        return None
    repo_root = _find_git_root(cwd)
    if repo_root is None:
        return None
    if repo_root in _repo_root_cache:
        return _repo_root_cache[repo_root]
    name = _git_remote_name(repo_root) or repo_root.name
    _repo_root_cache[repo_root] = name
    return name


class AllowlistError(ValueError):
    """Raised on allowlist configuration problems."""


class AllowlistEnforcer:
    """Loads and enforces the per-repo credential access allowlist.

    Two TOML forms are supported:

    **Simple form** (single vault per repo)::

        [repos.nordility]
        db = "infra"
        allowed_paths = ["vpn/provider#access-token"]

    **Multi-vault form** (repo accesses more than one database)::

        [repos.shock-relay.vaults.master]
        allowed_paths = ["casonkonzer@gmail.com#imap-fedora@intake"]

        [repos.shock-relay.vaults.infra]
        allowed_paths = ["Twilio/Twilio#API-Main", "Twilio/Twilio#Token"]

    ``is_permitted(repo_id, db, entry_path)`` returns True iff the given
    (repo, vault, entry) triple matches the allowlist.  When the client
    does not specify a ``db``, ``repo_default_db`` provides the single-vault
    default so downstream repos can omit the db parameter.
    """

    def __init__(self, allowlist_path: Path) -> None:
        self._path = allowlist_path
        self._repos: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            log.debug("allowlist not found at %s — all requests denied", self._path)
            return
        with open(self._path, "rb") as fh:
            data = tomllib.load(fh)
        for repo_name, repo_cfg in data.get("repos", {}).items():
            self._repos[str(repo_name)] = dict(repo_cfg)

    def reload(self) -> None:
        """Re-read the allowlist file from disk."""
        self._repos = {}
        self._load()

    def is_permitted(self, repo_id: str, db: str, entry_path: str) -> bool:
        """Return True iff (repo_id, db, entry_path) is allowed by the allowlist."""
        repo = self._repos.get(repo_id)
        if not repo:
            return False

        # Simple form: repo has top-level db + allowed_paths
        if "allowed_paths" in repo:
            if repo.get("db", "") != db:
                return False
            return any(fnmatch.fnmatch(entry_path, p) for p in repo["allowed_paths"])

        # Multi-vault form: repo has vaults subtable
        vaults = repo.get("vaults", {})
        vault = vaults.get(db)
        if not vault:
            return False
        return any(fnmatch.fnmatch(entry_path, p) for p in vault.get("allowed_paths", []))

    def repo_default_db(self, repo_id: str) -> Optional[str]:
        """Return the single-vault DB alias for simple-form repos, else None."""
        repo = self._repos.get(repo_id)
        if not repo:
            return None
        return repo.get("db") or None

    def permitted_paths(self, repo_id: str, db: str) -> list[str]:
        repo = self._repos.get(repo_id)
        if not repo:
            return []
        if "allowed_paths" in repo:
            return list(repo["allowed_paths"]) if repo.get("db") == db else []
        return list(repo.get("vaults", {}).get(db, {}).get("allowed_paths", []))

    def known_repos(self) -> list[str]:
        return sorted(self._repos)

    def repo_vaults(self, repo_id: str) -> list[str]:
        """Return the list of DB aliases this repo is allowed to access."""
        repo = self._repos.get(repo_id)
        if not repo:
            return []
        if "db" in repo:
            return [repo["db"]]
        return sorted(repo.get("vaults", {}).keys())


def default_allowlist_path() -> Path:
    env_val = os.environ.get(_PROVISION_ALLOWLIST_ENV, "").strip()
    if env_val:
        return Path(env_val)
    return Path(__file__).parent.parent.parent / "config" / "provisioning-allowlist.local.toml"
