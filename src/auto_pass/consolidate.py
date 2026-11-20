"""Fold every configured sub-vault into the master, so the master holds everything.

Each sub-vault's entries land under a top-level group named after its alias
(``<alias>/<original path>``). Nothing already in the master is removed or renamed, and the
sub-vault files are not modified: this is additive, and re-running it is idempotent because
entry UUIDs are preserved and ``merge`` matches on them.

The default is a plan. ``apply`` backs up the master and every source first.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from . import kdbx
from .dbindex import load_database_index, resolve_db_index_path
from .keepassxc import KeepassCommandError
from .scopes import RESERVED_PREFIX as RESERVED
from .scopes import Master, ScopeError, _cli

COMMON_ALIAS = "common"
COMMON_PASSWORD_ENTRY = "vaults/common.kdbx"


@dataclass
class VaultPlan:
    alias: str
    path: str
    entries: int = 0
    new: int = 0
    skipped_reason: str = ""
    create: bool = False  # the vault does not exist yet and will be created from the master
    target_paths: list[str] = field(default_factory=list)


def _source_password(master_entries: dict[str, kdbx.Entry], source: dict) -> str:
    entry = str(source.get("entry", "")).strip().strip("/")
    attr = str(source.get("attribute", "Password")).strip() or "Password"
    found = master_entries.get(entry)
    return found.fields.get(attr, "") if found else ""


def _common_path(master: Master) -> Path:
    return Path(master.db_path).expanduser().with_name("common.kdbx")


def _common_entries(master_entries: dict[str, kdbx.Entry], index: dict) -> set[str]:
    """What the master holds today, minus bookkeeping and anything already merged in."""
    merged = tuple(f"{alias}/" for alias in index) + (RESERVED,)
    return {p for p in master_entries if not p.startswith(merged)}


def plan(
    master: Master, index_path: Path | None = None, *, with_common: bool = False
) -> list[VaultPlan]:
    index = load_database_index(index_path)
    master_entries = kdbx.read_entries(master.db_path, master.password, master.key_file)
    plans: list[VaultPlan] = []
    if with_common and COMMON_ALIAS not in index:
        mine = _common_entries(master_entries, index)
        plans.append(
            VaultPlan(
                COMMON_ALIAS,
                str(_common_path(master)),
                entries=len(mine),
                new=len(mine),
                create=True,
                target_paths=[f"{COMMON_ALIAS}/{p}" for p in sorted(mine)],
            )
        )
    for alias, meta in sorted(index.items()):
        path = str(meta.get("database_path", "")).strip()
        item = VaultPlan(alias=alias, path=path)
        plans.append(item)
        if str(Path(path).expanduser()) == str(Path(master.db_path).expanduser()):
            item.skipped_reason = "is the master"
            continue
        if not path or not Path(path).expanduser().is_file():
            item.skipped_reason = "database file not found"
            continue
        source = meta.get("database_password_source")
        password = _source_password(master_entries, source) if isinstance(source, dict) else ""
        if not password:
            item.skipped_reason = "password not resolvable from the master"
            continue
        try:
            entries = kdbx.read_entries(str(Path(path).expanduser()), password)
        except KeepassCommandError as exc:
            item.skipped_reason = str(exc)
            continue
        item.entries = len(entries)
        item.target_paths = [f"{alias}/{p}" for p in sorted(entries)]
        item.new = sum(1 for t in item.target_paths if t not in master_entries)
    return plans


def _backup(path: Path, stamp: str) -> Path:
    target = path.with_name(f"{path.name}.bak-{stamp}")
    shutil.copy2(path, target)
    os.chmod(target, 0o600)
    return target


def _create_common(master: Master, index_path: Path | None, stamp: str) -> list[Path]:
    """Copy what the master holds today into ``common.kdbx`` and register it as a sub-vault."""
    index = load_database_index(index_path)
    xml = kdbx.export_xml(master.db_path, master.password, master.key_file)
    entries = kdbx.entries_from_xml(xml)
    keep = _common_entries(entries, index)
    target = _common_path(master)
    if target.exists():
        raise ScopeError(f"{target} already exists; not overwriting it")
    password = secrets.token_urlsafe(32)
    kdbx.import_xml(kdbx.filter_xml(xml, keep, drop_history=False), target, password)
    # The vault's password goes in the master, where every other sub-vault's password lives.
    group = COMMON_PASSWORD_ENTRY.rsplit("/", 1)[0]
    _cli(master, ["mkdir", "-q"], group, tolerate="already exists")
    _cli(master, ["add", "-q", "-p"], COMMON_PASSWORD_ENTRY, stdin=f"{password}\n{password}\n")
    # Register the alias in the local index (gitignored), keeping a backup of it.
    idx = resolve_db_index_path(index_path)
    backups = []
    payload: dict = {"databases": {}}
    if idx.exists():
        backups.append(_backup(idx, stamp))
        payload = json.loads(idx.read_text(encoding="utf-8"))
    payload.setdefault("databases", {})[COMMON_ALIAS] = {
        "database_path": str(target),
        "database_password_source": {
            "database_alias": "master",
            "entry": COMMON_PASSWORD_ENTRY,
            "attribute": "Password",
        },
    }
    idx.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return backups


def apply(
    master: Master, index_path: Path | None = None, *, with_common: bool = False
) -> tuple[list[VaultPlan], list[Path]]:
    """Merge every resolvable sub-vault into the master. Returns the plan and the backups."""
    plans = plan(master, index_path, with_common=with_common)
    if not any(p.new for p in plans if not p.skipped_reason):
        return plans, []
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backups = [_backup(Path(master.db_path).expanduser(), stamp)]
    if any(p.create for p in plans):
        backups += _create_common(master, index_path, stamp)
        plans = plan(master, index_path)  # re-plan: common is now a real sub-vault
    todo = [p for p in plans if not p.skipped_reason and p.new]
    index = load_database_index(index_path)
    master_entries = kdbx.read_entries(master.db_path, master.password, master.key_file)
    for item in todo:
        meta = index[item.alias]
        src = Path(item.path).expanduser()
        password = _source_password(master_entries, meta.get("database_password_source", {}))
        if not password:
            raise ScopeError(f"password for {item.alias!r} vanished from the master")
        backups.append(_backup(src, stamp))
        xml = kdbx.export_xml(str(src), password)
        every = {p for p, _ in kdbx.iter_entries(xml)}
        staged_pw = secrets.token_urlsafe(24)
        with kdbx._private_dir() as tmp:
            staged = tmp / "staged.kdbx"
            filtered = kdbx.filter_xml(xml, every, prefix=item.alias, drop_history=False)
            if item.alias == COMMON_ALIAS:  # shares UUIDs with the master's own entries
                kdbx.remap_uuids(filtered, COMMON_ALIAS)
            kdbx.import_xml(filtered, staged, staged_pw)
            kdbx.merge_into(
                master.db_path, master.password, str(staged), staged_pw, master.key_file
            )
    return plans, backups
