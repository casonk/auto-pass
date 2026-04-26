from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_INDEX_FILE = _REPO_ROOT / "config" / "keepass-dbs.local.json"
DB_INDEX_PATH_ENV_VAR = "AUTO_PASS_DB_INDEX_PATH"


class DatabaseIndexError(RuntimeError):
    """Raised when the local KeePass database index cannot be loaded."""


def resolve_db_index_path(path: str | Path | None = None) -> Path:
    """Return the effective local DB-index path."""
    if path is not None:
        return Path(path).expanduser()
    env_path = str(os.getenv(DB_INDEX_PATH_ENV_VAR, "")).strip()
    if env_path:
        return Path(env_path).expanduser()
    return DEFAULT_DB_INDEX_FILE


def load_database_index(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    """Load the local KeePass database index keyed by lowercase alias."""
    index_path = resolve_db_index_path(path)
    if not index_path.exists():
        return {}
    try:
        payload = json.loads(index_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DatabaseIndexError(f"Invalid JSON in {index_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise DatabaseIndexError(f"{index_path} must contain a top-level JSON object.")
    databases = payload.get("databases", {})
    if not isinstance(databases, dict):
        raise DatabaseIndexError(f"{index_path} field 'databases' must be a JSON object.")

    normalized: dict[str, dict[str, Any]] = {}
    for raw_alias, raw_entry in databases.items():
        alias = str(raw_alias or "").strip().lower()
        if not alias:
            raise DatabaseIndexError(f"{index_path} contains a blank database alias.")
        if not isinstance(raw_entry, dict):
            raise DatabaseIndexError(
                f"{index_path} database entry {raw_alias!r} must be a JSON object."
            )
        normalized[alias] = dict(raw_entry)
    return normalized


def resolve_database_alias(
    alias: str,
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Return the DB-index metadata for a specific alias."""
    alias_text = str(alias or "").strip().lower()
    if not alias_text:
        raise DatabaseIndexError("Database alias is blank.")
    databases = load_database_index(path)
    if alias_text not in databases:
        index_path = resolve_db_index_path(path)
        raise DatabaseIndexError(f"Database alias {alias_text!r} not found in {index_path}.")
    return dict(databases[alias_text])


def list_database_aliases(path: str | Path | None = None) -> list[str]:
    """Return the configured database aliases in sorted order."""
    return sorted(load_database_index(path))
