"""Scoped vaults: one small KeePass database per service, built from the master.

The master database holds everything. A *scope* names a service, the entry globs it needs and
(optionally) the few entries it may change. ``sync`` builds a database containing only those
entries, protected by its own random password, so a pod that gets the file can never see
anything else. The per-scope password lives in the master under ``auto-pass/scopes/<name>``;
the master password never leaves the host.

Write-back is deliberately narrow, because the pod's copy is untrusted input:

* only entries matching the scope's ``writable`` globs are considered;
* only the ``Password`` field is read, and only for an entry that already exists in the master
  and is also inside the scope's ``entries``;
* if only the pod changed an entry, the change is applied; if both sides changed it since the
  last sync, the later modification time wins (a pod timestamp in the future is not believed
  and the master is kept);
* new entries, edits to other fields and anything outside the scope are ignored.
"""

from __future__ import annotations

import fnmatch
import hmac
import json
import os
import re
import secrets
import tomllib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import kdbx
from .keepassxc import KeepassCommandError, run_keepassxc_set_password_direct

SCOPE_CONFIG_ENV = "AUTO_PASS_SCOPES_CONFIG"
SCOPE_STATE_ENV = "AUTO_PASS_SCOPES_STATE"
RESERVED_PREFIX = "auto-pass/"
PASSWORD_ENTRY_PREFIX = "auto-pass/scopes/"
_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")

_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = _REPO_ROOT / "config" / "scopes.local.toml"
DEFAULT_STATE = Path.home() / ".cache" / "auto-pass" / "scope-state.json"
DEFAULT_SCOPES_DIR = Path.home() / ".local" / "share" / "auto-pass" / "scopes"


class ScopeError(RuntimeError):
    """Raised on scope configuration or sync problems."""


@dataclass(frozen=True)
class Master:
    db_path: str
    password: str
    key_file: str = ""


@dataclass(frozen=True)
class Scope:
    name: str
    namespace: str
    secret_name: str
    entries: tuple[str, ...]
    writable: tuple[str, ...] = ()
    writeback_path: str = ""
    writeback: str = "path"  # "path": a file on the host; "secret": a return Secret in the cluster
    output: str = ""
    allow_empty: bool = False

    @property
    def return_secret(self) -> str:
        return f"{self.secret_name}-return"


@dataclass(frozen=True)
class ScopeConfig:
    scopes: dict[str, Scope]
    scopes_dir: Path = DEFAULT_SCOPES_DIR
    kubectl: tuple[str, ...] = ("kubectl",)
    kubeconfig: str = ""
    pod_security: str = "restricted"
    sync_kind: str = "ServiceAccount"
    sync_name: str = "auto-pass-sync"
    sync_namespace: str = "auto-pass-system"

    def writeback_file(self, scope: Scope) -> Path | None:
        if scope.writeback_path:
            return Path(scope.writeback_path).expanduser()
        if scope.writeback == "secret":
            return self.scopes_dir / f"{scope.name}.return.kdbx"
        return None

    def output_path(self, scope: Scope) -> Path:
        if scope.output:
            return Path(scope.output).expanduser()
        return self.scopes_dir / f"{scope.name}.kdbx"


def default_config_path() -> Path:
    env = os.environ.get(SCOPE_CONFIG_ENV, "").strip()
    return Path(env).expanduser() if env else DEFAULT_CONFIG


def _globs(value: object, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise ScopeError(f"{where} must be a list of non-empty strings")
    return tuple(v.strip().strip("/") for v in value)


def load_config(path: Path | None = None) -> ScopeConfig:
    cfg_path = path or default_config_path()
    if not cfg_path.exists():
        raise ScopeError(f"no scope config at {cfg_path} (start from config/scopes.example.toml)")
    with open(cfg_path, "rb") as fh:
        data = tomllib.load(fh)

    settings = data.get("settings", {})
    k8s = data.get("k8s", {})
    subject = k8s.get("sync_subject", {})
    kubectl = settings.get("kubectl", "kubectl")
    argv = tuple(kubectl.split()) if isinstance(kubectl, str) else tuple(kubectl)
    if not argv:
        raise ScopeError("settings.kubectl is empty")
    if subject.get("kind", "ServiceAccount") not in {"ServiceAccount", "User", "Group"}:
        raise ScopeError("k8s.sync_subject.kind must be ServiceAccount, User or Group")

    scopes: dict[str, Scope] = {}
    secret_names: set[tuple[str, str]] = set()
    for name, raw in data.get("scopes", {}).items():
        if not _NAME_RE.match(name):
            raise ScopeError(f"scope name {name!r} must be a lowercase DNS label")
        where = f"scopes.{name}"
        entries = _globs(raw.get("entries"), f"{where}.entries")
        if not entries:
            raise ScopeError(f"{where}.entries must list at least one glob")
        writable = _globs(raw.get("writable"), f"{where}.writable")
        namespace = str(raw.get("namespace", name))
        secret_name = str(raw.get("secret_name", f"{name}-vault"))
        for label, value in (("namespace", namespace), ("secret_name", secret_name)):
            if not _NAME_RE.match(value):
                raise ScopeError(f"{where}.{label} {value!r} must be a lowercase DNS label")
        if (namespace, secret_name) in secret_names:
            raise ScopeError(f"{where} reuses secret {namespace}/{secret_name}")
        secret_names.add((namespace, secret_name))
        mode = str(raw.get("writeback", "path"))
        if mode not in {"path", "secret"}:
            raise ScopeError(f"{where}.writeback must be 'path' or 'secret'")
        if writable and mode == "path" and not raw.get("writeback_path"):
            raise ScopeError(f'{where}.writable needs writeback_path (or writeback = "secret")')
        if mode == "secret" and not writable:
            raise ScopeError(f'{where}.writeback = "secret" needs a writable list')
        scopes[name] = Scope(
            name=name,
            namespace=namespace,
            secret_name=secret_name,
            entries=entries,
            writable=writable,
            writeback_path=str(raw.get("writeback_path", "")),
            writeback=mode,
            output=str(raw.get("output", "")),
            allow_empty=bool(raw.get("allow_empty", False)),
        )

    return ScopeConfig(
        scopes=scopes,
        scopes_dir=Path(settings.get("scopes_dir", DEFAULT_SCOPES_DIR)).expanduser(),
        kubectl=argv,
        kubeconfig=str(settings.get("kubeconfig", "")),
        pod_security=str(k8s.get("pod_security", "restricted")),
        sync_kind=str(subject.get("kind", "ServiceAccount")),
        sync_name=str(subject.get("name", "auto-pass-sync")),
        sync_namespace=str(subject.get("namespace", "auto-pass-system")),
    )


def select(cfg: ScopeConfig, names: list[str] | None) -> list[Scope]:
    if not names:
        return list(cfg.scopes.values())
    missing = [n for n in names if n not in cfg.scopes]
    if missing:
        raise ScopeError(f"unknown scope(s): {', '.join(missing)}")
    return [cfg.scopes[n] for n in names]


def _matches(globs: tuple[str, ...], path: str) -> bool:
    return any(fnmatch.fnmatch(path, g) for g in globs)


def match_entries(scope: Scope, master: dict[str, kdbx.Entry]) -> dict[str, kdbx.Entry]:
    """Entries of the master this scope may hold (never the auto-pass bookkeeping entries)."""
    return {
        path: entry
        for path, entry in master.items()
        if not path.startswith(RESERVED_PREFIX) and _matches(scope.entries, path)
    }


# ----------------------------------------------------------------------
# State
# ----------------------------------------------------------------------


@dataclass
class State:
    key: bytes
    scopes: dict[str, dict] = field(default_factory=dict)
    path: Path = DEFAULT_STATE

    @classmethod
    def load(cls, path: Path | None = None) -> State:
        target = path or Path(os.environ.get(SCOPE_STATE_ENV, "") or DEFAULT_STATE)
        if target.exists():
            data = json.loads(target.read_text(encoding="utf-8"))
            return cls(bytes.fromhex(data["hmac_key"]), data.get("scopes", {}), target)
        return cls(secrets.token_bytes(32), {}, target)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"hmac_key": self.key.hex(), "scopes": self.scopes}, indent=1)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)

    def get(self, name: str) -> dict:
        return self.scopes.get(name, {})


def _scope_digest(entries: dict[str, kdbx.Entry], key: bytes) -> str:
    material = json.dumps(sorted((p, e.digest(key)) for p, e in entries.items()))
    return hmac.new(key, material.encode(), "sha256").hexdigest()


# ----------------------------------------------------------------------
# Master access
# ----------------------------------------------------------------------


def _scope_password(master: Master, entries: dict[str, kdbx.Entry], scope: Scope) -> str:
    """The scope database password, generating and storing it in the master on first use."""
    path = f"{PASSWORD_ENTRY_PREFIX}{scope.name}"
    existing = entries.get(path)
    if existing and existing.fields.get("Password"):
        return existing.fields["Password"]
    password = secrets.token_urlsafe(32)
    group = path.rsplit("/", 1)[0]
    for sub in _group_chain(group):
        _cli(master, ["mkdir", "-q"], sub, tolerate="already exists")
    _cli(
        master,
        ["add", "-q", "-p", "--notes", f"scoped vault password for {scope.name}"],
        path,
        stdin=f"{password}\n{password}\n",
    )
    return password


def _group_chain(group: str) -> list[str]:
    parts = group.split("/")
    return ["/".join(parts[: i + 1]) for i in range(len(parts))]


def _cli(
    master: Master, args: list[str], target: str, *, stdin: str = "", tolerate: str = ""
) -> None:
    cmd = ["keepassxc-cli", args[0], *args[1:]]
    if master.key_file:
        cmd.extend(["-k", master.key_file])
    cmd.extend([master.db_path, target])
    try:
        kdbx._run(cmd, f"{master.password}\n{stdin}", what=args[0])
    except KeepassCommandError as exc:
        if not (tolerate and tolerate in str(exc).lower()):
            raise


# ----------------------------------------------------------------------
# Sync
# ----------------------------------------------------------------------


@dataclass
class ScopeResult:
    name: str
    matched: int = 0
    rebuilt: bool = False
    applied: bool = False
    written_back: list[str] = field(default_factory=list)
    resolved: list[str] = field(default_factory=list)  # both sides changed; says who won
    conflicts: list[str] = field(default_factory=list)  # could not be decided; master kept
    ignored: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    secret_payload: tuple[bytes, str, str] | None = None  # (kdbx bytes, password, digest)

    def summary(self) -> dict:
        return {
            "scope": self.name,
            "entries": self.matched,
            "rebuilt": self.rebuilt,
            "applied_to_cluster": self.applied,
            "written_back": self.written_back,
            "resolved": self.resolved,
            "conflicts": self.conflicts,
            "ignored": self.ignored,
            "warnings": self.warnings,
        }


_CLOCK_SKEW = timedelta(minutes=5)


def _parse_time(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def _write_back(
    scope: Scope,
    source: Path | None,
    master: Master,
    master_entries: dict[str, kdbx.Entry],
    scope_password: str,
    state: State,
    result: ScopeResult,
) -> bool:
    """Apply permitted password changes from the pod's copy. True if the master changed."""
    if not scope.writable or source is None or not source.is_file():
        return False
    # Each version of the pod's file is consumed once. A copy older than the last build is
    # the pod's view of a superseded vault, and replaying it would undo the master's value.
    stat = source.stat()
    signature = f"{stat.st_mtime_ns}:{stat.st_size}"
    prior = state.get(scope.name)
    built = prior.get("built_at", "")
    if signature == prior.get("wb_seen") or (
        built and datetime.fromtimestamp(stat.st_mtime, UTC).isoformat() < built
    ):
        return False
    state.scopes.setdefault(scope.name, {})["wb_seen"] = signature
    try:
        pod = kdbx.read_entries(str(source), scope_password)
    except KeepassCommandError as exc:
        result.warnings.append(f"write-back copy unreadable: {exc}")
        return False

    allowed = match_entries(scope, master_entries)
    baseline = state.get(scope.name).get("passwords", {})
    changed = False
    for path, entry in pod.items():
        if path not in allowed:
            result.ignored.append(path)  # an entry the pod added, or one outside the scope
            continue
        pod_digest = entry.password_digest(state.key)
        current = allowed[path].password_digest(state.key)
        base = baseline.get(path)
        if pod_digest in (current, base):
            continue  # unchanged by the pod, or already identical to the master
        if not _matches(scope.writable, path):
            result.ignored.append(path)  # changed, but the scope may not write it
            continue
        if base is None:
            result.conflicts.append(f"{path} (no baseline; master kept)")
            continue
        if current != base:
            # Both sides changed since the last sync: the later modification wins.
            pod_time, master_time = _parse_time(entry.modified), _parse_time(allowed[path].modified)
            if (
                pod_time is None
                or master_time is None
                or pod_time > datetime.now(UTC) + _CLOCK_SKEW
            ):
                result.conflicts.append(f"{path} (untrusted pod timestamp; master kept)")
                continue
            if pod_time <= master_time:
                result.resolved.append(f"{path}: master newer, kept")
                continue
            result.resolved.append(f"{path}: pod newer, applied")
        try:
            run_keepassxc_set_password_direct(
                path,
                entry.fields.get("Password", ""),
                db_path=master.db_path,
                db_password=master.password,
                key_file=master.key_file,
            )
        except KeepassCommandError as exc:
            result.warnings.append(f"write-back of {path} refused: {exc}")
            continue
        result.written_back.append(path)
        changed = True
    return changed


def sync_scope(
    scope: Scope,
    cfg: ScopeConfig,
    master: Master,
    state: State,
    *,
    force: bool = False,
    write_back: bool = True,
    dry_run: bool = False,
    need_payload: bool = False,
) -> ScopeResult:
    """Reconcile one scope: pull permitted changes into the master, rebuild if it moved."""
    result = ScopeResult(scope.name)
    xml = kdbx.export_xml(master.db_path, master.password, master.key_file)
    master_entries = kdbx.entries_from_xml(xml)
    matched = match_entries(scope, master_entries)
    if not matched and not scope.allow_empty:
        raise ScopeError(f"scope {scope.name!r} matches no entries in the master")
    for path in master_entries:
        if path.startswith(RESERVED_PREFIX) and _matches(scope.entries, path):
            result.warnings.append(f"{path} matches an entries glob but is reserved; excluded")
    for entry in matched.values():
        if entry.attachments:
            result.warnings.append(f"{entry.path} has attachments, which are copied as-is")

    if dry_run:
        result.matched = len(matched)
        return result

    scope_pw = _scope_password(master, master_entries, scope)
    wb_file = cfg.writeback_file(scope)
    if write_back and _write_back(scope, wb_file, master, master_entries, scope_pw, state, result):
        xml = kdbx.export_xml(master.db_path, master.password, master.key_file)
        master_entries = kdbx.entries_from_xml(xml)
        matched = match_entries(scope, master_entries)

    result.matched = len(matched)
    digest = _scope_digest(matched, state.key)
    out = cfg.output_path(scope)
    prior = state.get(scope.name)
    if force or prior.get("digest") != digest or not out.is_file():
        kdbx.import_xml(kdbx.filter_xml(xml, set(matched)), out, scope_pw)
        result.rebuilt = True
        state.scopes[scope.name] = {
            "digest": digest,
            "built_at": datetime.now(UTC).isoformat(),
            "passwords": {p: e.password_digest(state.key) for p, e in matched.items()},
            "applied": prior.get("applied", "") if prior.get("digest") == digest else "",
            "wb_seen": state.get(scope.name).get("wb_seen", ""),
        }
    if need_payload:
        result.secret_payload = (out.read_bytes(), scope_pw, digest)
    return result


def mark_applied(state: State, scope: Scope, digest: str) -> None:
    state.scopes.setdefault(scope.name, {})["applied"] = digest


def needs_apply(state: State, scope: Scope, digest: str) -> bool:
    return state.get(scope.name).get("applied") != digest
