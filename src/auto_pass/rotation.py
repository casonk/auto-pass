from __future__ import annotations

import json
import random
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from .keepassxc import (
    KeepassCommandError,
    is_keepass_entry_not_found_error,
    list_keepassxc_entries,
    remove_keepassxc_entry,
    resolve_keepassxc_entry_all_fields,
    upsert_keepassxc_entry,
)

DEFAULT_SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}:,.?"
PENDING_ENTRY_SUFFIX = "@rotation-pending"
REGISTRY_ENTRY_SUFFIX = "@rotation-config"
ROTATION_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class PasswordPolicy:
    length: int = 24
    lower: bool = True
    upper: bool = True
    numeric: bool = True
    special: bool = True
    special_chars: str = DEFAULT_SPECIAL_CHARS
    exclude_chars: str = ""
    every_group: bool = True


@dataclass(frozen=True)
class RotationMetadata:
    schema_version: int
    entry: str
    pending_entry: str
    created_at: str
    homepage_url: str = ""
    reset_url: str = ""
    note: str = ""
    policy: dict[str, object] | None = None


@dataclass(frozen=True)
class RotationRegistry:
    schema_version: int
    entry: str
    registry_entry: str
    updated_at: str = ""
    homepage_url: str = ""
    reset_url: str = ""
    note: str = ""
    rotation_interval_days: int | None = None
    policy: dict[str, object] | None = None
    policy_source: str = ""
    policy_confidence: str = ""


def pending_entry_path(entry: str) -> str:
    return f"{str(entry or '').strip()}{PENDING_ENTRY_SUFFIX}"


def registry_entry_path(entry: str) -> str:
    return f"{str(entry or '').strip()}{REGISTRY_ENTRY_SUFFIX}"


def generate_password(policy: PasswordPolicy) -> str:
    groups: list[str] = []
    if policy.lower:
        groups.append(_filtered_chars("abcdefghijklmnopqrstuvwxyz", policy.exclude_chars))
    if policy.upper:
        groups.append(_filtered_chars("ABCDEFGHIJKLMNOPQRSTUVWXYZ", policy.exclude_chars))
    if policy.numeric:
        groups.append(_filtered_chars("0123456789", policy.exclude_chars))
    if policy.special:
        groups.append(_filtered_chars(policy.special_chars, policy.exclude_chars))

    groups = [group for group in groups if group]
    if not groups:
        raise ValueError("Password policy must allow at least one non-empty character group.")
    if policy.length < len(groups) and policy.every_group:
        raise ValueError("Password length is shorter than the required number of character groups.")

    alphabet = "".join(dict.fromkeys("".join(groups)))
    if not alphabet:
        raise ValueError("Password policy produced an empty character set.")

    chars = [secrets.choice(group) for group in groups] if policy.every_group else []
    while len(chars) < policy.length:
        chars.append(secrets.choice(alphabet))
    random.SystemRandom().shuffle(chars)
    return "".join(chars[: policy.length])


def prepare_rotation(
    entry: str,
    *,
    policy: PasswordPolicy | None = None,
    homepage_url: str | None = None,
    reset_url: str | None = None,
    note: str | None = None,
    allow_interactive: bool = False,
) -> dict[str, object]:
    entry = _require_entry(entry)
    registry = read_rotation_registry(
        entry,
        allow_interactive=allow_interactive,
    )
    effective_policy = _resolve_policy(policy, registry)
    resolved_homepage = _resolve_homepage_url(
        entry,
        homepage_url=homepage_url,
        registry=registry,
        allow_interactive=allow_interactive,
    )
    resolved_reset_url = _prefer_override(reset_url, registry.reset_url if registry else "")
    resolved_note = _prefer_override(note, registry.note if registry else "")
    pending_entry = pending_entry_path(entry)
    password = generate_password(effective_policy)
    metadata = RotationMetadata(
        schema_version=ROTATION_SCHEMA_VERSION,
        entry=entry,
        pending_entry=pending_entry,
        created_at=_now_iso(),
        homepage_url=resolved_homepage,
        reset_url=resolved_reset_url,
        note=resolved_note,
        policy=asdict(effective_policy),
    )
    mode = upsert_keepassxc_entry(
        pending_entry,
        username=f"pending-for:{entry}",
        password=password,
        url=resolved_reset_url or resolved_homepage,
        notes=json.dumps(asdict(metadata), indent=2, sort_keys=True),
        allow_interactive=allow_interactive,
    )
    return {
        "entry": entry,
        "pending": True,
        "pending_entry": pending_entry,
        "mode": mode,
        "registry_entry": registry_entry_path(entry),
        "homepage_url": resolved_homepage,
        "reset_url": resolved_reset_url,
        "created_at": metadata.created_at,
        "length": effective_policy.length,
    }


def rotation_status(
    entry: str,
    *,
    allow_interactive: bool = False,
) -> dict[str, object]:
    entry = _require_entry(entry)
    registry = read_rotation_registry(entry, allow_interactive=allow_interactive)
    pending_entry = pending_entry_path(entry)
    try:
        fields = resolve_keepassxc_entry_all_fields(
            pending_entry,
            allow_interactive=allow_interactive,
            notify=False,
        )
    except KeepassCommandError as exc:
        if is_keepass_entry_not_found_error(exc):
            return {
                "entry": entry,
                "pending": False,
                "pending_entry": pending_entry,
                "registry_entry": registry_entry_path(entry),
                "registry_present": registry is not None,
            }
        raise

    metadata = _parse_metadata(fields.get("Notes", ""), entry=entry, pending_entry=pending_entry)
    password = str(fields.get("Password", "") or "")
    return {
        "entry": entry,
        "pending": True,
        "pending_entry": pending_entry,
        "registry_entry": registry_entry_path(entry),
        "registry_present": registry is not None,
        "created_at": metadata.created_at,
        "homepage_url": metadata.homepage_url,
        "reset_url": metadata.reset_url,
        "note": metadata.note,
        "length": len(password),
        "policy": metadata.policy or {},
    }


def promote_rotation(
    entry: str,
    *,
    allow_interactive: bool = False,
) -> dict[str, object]:
    entry = _require_entry(entry)
    pending_entry = pending_entry_path(entry)
    fields = resolve_keepassxc_entry_all_fields(
        pending_entry,
        allow_interactive=allow_interactive,
        notify=False,
    )
    password = str(fields.get("Password", "") or "")
    if not password:
        raise KeepassCommandError(f"Pending rotation entry {pending_entry!r} does not contain a password.")

    metadata = _parse_metadata(fields.get("Notes", ""), entry=entry, pending_entry=pending_entry)
    mode = upsert_keepassxc_entry(
        entry,
        password=password,
        allow_interactive=allow_interactive,
    )
    registry = _sync_registry_from_completed_rotation(
        entry,
        metadata,
        allow_interactive=allow_interactive,
    )
    removed = remove_keepassxc_entry(
        pending_entry,
        allow_interactive=allow_interactive,
    )
    return {
        "entry": entry,
        "promoted": True,
        "mode": mode,
        "pending_entry_removed": removed,
        "created_at": metadata.created_at,
        "homepage_url": metadata.homepage_url,
        "reset_url": metadata.reset_url,
        "registry_entry": registry.registry_entry,
        "registry_updated_at": registry.updated_at,
        "policy_source": registry.policy_source,
        "policy_confidence": registry.policy_confidence,
    }


def discard_rotation(
    entry: str,
    *,
    allow_interactive: bool = False,
) -> dict[str, object]:
    entry = _require_entry(entry)
    pending_entry = pending_entry_path(entry)
    removed = remove_keepassxc_entry(
        pending_entry,
        allow_interactive=allow_interactive,
    )
    return {
        "entry": entry,
        "discarded": removed,
        "pending_entry": pending_entry,
    }


def configure_rotation_registry(
    entry: str,
    *,
    policy: PasswordPolicy | None = None,
    homepage_url: str | None = None,
    reset_url: str | None = None,
    note: str | None = None,
    rotation_interval_days: int | None = None,
    allow_interactive: bool = False,
) -> dict[str, object]:
    entry = _require_entry(entry)
    registry_entry = registry_entry_path(entry)
    current = read_rotation_registry(entry, allow_interactive=allow_interactive)
    effective_policy = _resolve_policy(policy, current)
    metadata = RotationRegistry(
        schema_version=ROTATION_SCHEMA_VERSION,
        entry=entry,
        registry_entry=registry_entry,
        updated_at=_now_iso(),
        homepage_url=_prefer_override(homepage_url, current.homepage_url if current else ""),
        reset_url=_prefer_override(reset_url, current.reset_url if current else ""),
        note=_prefer_override(note, current.note if current else ""),
        rotation_interval_days=(
            rotation_interval_days
            if rotation_interval_days is not None
            else (current.rotation_interval_days if current else None)
        ),
        policy=asdict(effective_policy),
        policy_source="manual",
        policy_confidence="high",
    )
    mode = upsert_keepassxc_entry(
        registry_entry,
        username=f"config-for:{entry}",
        url=metadata.reset_url or metadata.homepage_url,
        notes=json.dumps(asdict(metadata), indent=2, sort_keys=True),
        allow_interactive=allow_interactive,
    )
    return {
        "entry": entry,
        "configured": True,
        "registry_entry": registry_entry,
        "mode": mode,
        "homepage_url": metadata.homepage_url,
        "reset_url": metadata.reset_url,
        "rotation_interval_days": metadata.rotation_interval_days,
        "policy": metadata.policy or {},
        "policy_source": metadata.policy_source,
        "policy_confidence": metadata.policy_confidence,
    }


def infer_rotation_registry(
    entry: str,
    *,
    homepage_url: str | None = None,
    reset_url: str | None = None,
    note: str | None = None,
    rotation_interval_days: int | None = None,
    allow_interactive: bool = False,
) -> dict[str, object]:
    entry = _require_entry(entry)
    registry_entry = registry_entry_path(entry)
    current = read_rotation_registry(entry, allow_interactive=allow_interactive)
    fields = resolve_keepassxc_entry_all_fields(
        entry,
        allow_interactive=allow_interactive,
        notify=False,
    )
    password = str(fields.get("Password", "") or "")
    if not password:
        raise KeepassCommandError(f"Entry {entry!r} does not contain a password to infer from.")
    inferred_policy = infer_password_policy(password)
    metadata = RotationRegistry(
        schema_version=ROTATION_SCHEMA_VERSION,
        entry=entry,
        registry_entry=registry_entry,
        updated_at=_now_iso(),
        homepage_url=_prefer_override(
            homepage_url,
            current.homepage_url if current else str(fields.get("URL", "") or ""),
        ),
        reset_url=_prefer_override(reset_url, current.reset_url if current else ""),
        note=_prefer_override(note, current.note if current else ""),
        rotation_interval_days=(
            rotation_interval_days
            if rotation_interval_days is not None
            else (current.rotation_interval_days if current else None)
        ),
        policy=asdict(inferred_policy),
        policy_source="inferred-from-current-password",
        policy_confidence="low",
    )
    mode = upsert_keepassxc_entry(
        registry_entry,
        username=f"config-for:{entry}",
        url=metadata.reset_url or metadata.homepage_url,
        notes=json.dumps(asdict(metadata), indent=2, sort_keys=True),
        allow_interactive=allow_interactive,
    )
    return {
        "entry": entry,
        "configured": True,
        "registry_entry": registry_entry,
        "mode": mode,
        "homepage_url": metadata.homepage_url,
        "reset_url": metadata.reset_url,
        "rotation_interval_days": metadata.rotation_interval_days,
        "policy": metadata.policy or {},
        "policy_source": metadata.policy_source,
        "policy_confidence": metadata.policy_confidence,
    }


def read_rotation_registry(
    entry: str,
    *,
    allow_interactive: bool = False,
) -> RotationRegistry | None:
    entry = _require_entry(entry)
    registry_entry = registry_entry_path(entry)
    try:
        fields = resolve_keepassxc_entry_all_fields(
            registry_entry,
            allow_interactive=allow_interactive,
            notify=False,
        )
    except KeepassCommandError as exc:
        if is_keepass_entry_not_found_error(exc):
            return None
        raise
    return _parse_registry(fields.get("Notes", ""), entry=entry, registry_entry=registry_entry)


def rotation_registry_status(
    entry: str,
    *,
    allow_interactive: bool = False,
) -> dict[str, object]:
    entry = _require_entry(entry)
    registry = read_rotation_registry(entry, allow_interactive=allow_interactive)
    registry_entry = registry_entry_path(entry)
    if registry is None:
        return {
            "entry": entry,
            "configured": False,
            "registry_entry": registry_entry,
        }
    return {
        "entry": entry,
        "configured": True,
        "registry_entry": registry_entry,
        "updated_at": registry.updated_at,
        "homepage_url": registry.homepage_url,
        "reset_url": registry.reset_url,
        "note": registry.note,
        "rotation_interval_days": registry.rotation_interval_days,
        "policy": registry.policy or {},
        "policy_source": registry.policy_source,
        "policy_confidence": registry.policy_confidence,
    }


def list_rotation_registries(
    *,
    group: str = "/",
    due_within_days: int | None = None,
    allow_interactive: bool = False,
) -> list[dict[str, object]]:
    entries = list_keepassxc_entries(
        group,
        recursive=True,
        flatten=True,
        allow_interactive=allow_interactive,
    )
    results: list[dict[str, object]] = []
    for raw_entry in entries:
        if not raw_entry.endswith(REGISTRY_ENTRY_SUFFIX):
            continue
        entry = raw_entry[: -len(REGISTRY_ENTRY_SUFFIX)]
        registry = read_rotation_registry(entry, allow_interactive=allow_interactive)
        if registry is None:
            continue
        item = _registry_summary(registry)
        if due_within_days is not None and not _is_due_within(item, due_within_days):
            continue
        results.append(item)
    return sorted(results, key=_registry_sort_key)


def sync_rotation_todo(
    todo_file: str | Path,
    *,
    category: str = "Password Rotation",
    group: str = "/",
    due_within_days: int = 30,
    allow_interactive: bool = False,
) -> dict[str, object]:
    path = Path(todo_file).expanduser()
    managed_category = str(category or "").strip() or "Password Rotation"
    registries = list_rotation_registries(
        group=group,
        due_within_days=due_within_days,
        allow_interactive=allow_interactive,
    )
    desired_titles = [_registry_todo_title(item) for item in registries]
    data = _load_clockwork_todo_file(path)
    todo_category = _find_clockwork_category(data, managed_category)
    if todo_category is None:
        todo_category = {"name": managed_category, "items": []}
        data["categories"].append(todo_category)
    todo_category["items"] = [{"title": title, "done": False} for title in desired_titles]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return {
        "todo_file": str(path),
        "category": managed_category,
        "item_count": len(desired_titles),
        "due_within_days": due_within_days,
        "entries": [item["entry"] for item in registries],
    }


def _filtered_chars(chars: str, excluded: str) -> str:
    excluded_set = set(excluded)
    return "".join(char for char in chars if char not in excluded_set)


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _require_entry(entry: str) -> str:
    resolved = str(entry or "").strip()
    if not resolved:
        raise ValueError("KeePass entry is required.")
    return resolved


def _read_entry_url(entry: str, *, allow_interactive: bool) -> str:
    try:
        fields = resolve_keepassxc_entry_all_fields(
            entry,
            allow_interactive=allow_interactive,
            notify=False,
        )
    except KeepassCommandError:
        return ""
    return str(fields.get("URL", "") or "").strip()


def _resolve_policy(
    override: PasswordPolicy | None,
    registry: RotationRegistry | None,
) -> PasswordPolicy:
    if override is not None:
        return override
    if registry and isinstance(registry.policy, dict):
        return _policy_from_mapping(registry.policy)
    return PasswordPolicy()


def infer_password_policy(password: str) -> PasswordPolicy:
    text = str(password or "")
    if not text:
        raise ValueError("Cannot infer a password policy from an empty password.")
    special_chars = _unique_chars_in_order(
        char for char in text if not char.isalnum() and not char.isspace() and char.isprintable()
    )
    return PasswordPolicy(
        length=len(text),
        lower=any(char.islower() for char in text),
        upper=any(char.isupper() for char in text),
        numeric=any(char.isdigit() for char in text),
        special=bool(special_chars),
        special_chars=special_chars or DEFAULT_SPECIAL_CHARS,
        exclude_chars="",
        every_group=True,
    )


def _registry_summary(registry: RotationRegistry) -> dict[str, object]:
    last_updated_at = registry.updated_at or ""
    due_status = _due_status(last_updated_at, registry.rotation_interval_days)
    return {
        "entry": registry.entry,
        "registry_entry": registry.registry_entry,
        "updated_at": last_updated_at,
        "homepage_url": registry.homepage_url,
        "reset_url": registry.reset_url,
        "rotation_interval_days": registry.rotation_interval_days,
        "policy_source": registry.policy_source,
        "policy_confidence": registry.policy_confidence,
        "due_status": due_status["due_status"],
        "days_until_due": due_status["days_until_due"],
        "policy": registry.policy or {},
    }


def _due_status(updated_at: str, rotation_interval_days: int | None) -> dict[str, object]:
    if not updated_at or rotation_interval_days is None:
        return {"due_status": "unknown", "days_until_due": None}
    try:
        updated = datetime.fromisoformat(updated_at)
    except ValueError:
        return {"due_status": "unknown", "days_until_due": None}
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=UTC)
    now = datetime.now(UTC)
    elapsed_days = (now - updated.astimezone(UTC)).days
    days_until_due = rotation_interval_days - elapsed_days
    if days_until_due < 0:
        status = "overdue"
    elif days_until_due == 0:
        status = "due"
    else:
        status = "scheduled"
    return {"due_status": status, "days_until_due": days_until_due}


def _is_due_within(item: dict[str, object], due_within_days: int) -> bool:
    days_until_due = item.get("days_until_due")
    if days_until_due is None:
        return False
    return int(days_until_due) <= due_within_days


def _registry_sort_key(item: dict[str, object]) -> tuple[int, int, str]:
    days_until_due = item.get("days_until_due")
    normalized_days = int(days_until_due) if days_until_due is not None else 10**9
    status = str(item.get("due_status") or "")
    priority = {"overdue": 0, "due": 1, "scheduled": 2, "unknown": 3}.get(status, 4)
    return (priority, normalized_days, str(item.get("entry") or ""))


def _sync_registry_from_completed_rotation(
    entry: str,
    metadata: RotationMetadata,
    *,
    allow_interactive: bool,
) -> RotationRegistry:
    current = read_rotation_registry(entry, allow_interactive=allow_interactive)
    registry_entry = registry_entry_path(entry)
    registry = RotationRegistry(
        schema_version=ROTATION_SCHEMA_VERSION,
        entry=entry,
        registry_entry=registry_entry,
        updated_at=_now_iso(),
        homepage_url=_prefer_override(metadata.homepage_url, current.homepage_url if current else ""),
        reset_url=_prefer_override(metadata.reset_url, current.reset_url if current else ""),
        note=_prefer_override(metadata.note, current.note if current else ""),
        rotation_interval_days=current.rotation_interval_days if current else None,
        policy=metadata.policy or (current.policy if current else None),
        policy_source="manual",
        policy_confidence="high",
    )
    upsert_keepassxc_entry(
        registry_entry,
        username=f"config-for:{entry}",
        url=registry.reset_url or registry.homepage_url,
        notes=json.dumps(asdict(registry), indent=2, sort_keys=True),
        allow_interactive=allow_interactive,
    )
    return registry


def _load_clockwork_todo_file(path: Path) -> dict[str, object]:
    if not path.exists():
        return {"categories": []}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Clockwork todo file {path} is not valid JSON.") from exc
    categories = payload.get("categories") if isinstance(payload, dict) else None
    if not isinstance(categories, list):
        raise ValueError(f"Clockwork todo file {path} does not contain a categories list.")
    normalized_categories: list[dict[str, object]] = []
    for category in categories:
        if not isinstance(category, dict):
            continue
        name = str(category.get("name") or "").strip()
        if not name:
            continue
        items = []
        for item in category.get("items", []):
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or "").strip()
            if not title:
                continue
            items.append({"title": title, "done": bool(item.get("done", False))})
        normalized_categories.append({"name": name, "items": items})
    return {"categories": normalized_categories}


def _find_clockwork_category(data: dict[str, object], name: str) -> dict[str, object] | None:
    categories = data.get("categories")
    if not isinstance(categories, list):
        return None
    wanted = name.strip().lower()
    for category in categories:
        if not isinstance(category, dict):
            continue
        if str(category.get("name") or "").strip().lower() == wanted:
            return category
    return None


def _registry_todo_title(item: dict[str, object]) -> str:
    entry = str(item.get("entry") or "").strip()
    due_status = str(item.get("due_status") or "").strip()
    days_until_due = item.get("days_until_due")
    if due_status == "overdue":
        timing = "overdue"
    elif due_status == "due":
        timing = "due today"
    elif isinstance(days_until_due, int):
        timing = f"due in {days_until_due}d"
    else:
        timing = due_status or "unscheduled"
    trust = _registry_trust_label(item)
    return f"Rotate password: {entry} ({timing}; {trust} rules)"


def _registry_trust_label(item: dict[str, object]) -> str:
    source = str(item.get("policy_source") or "").strip()
    confidence = str(item.get("policy_confidence") or "").strip()
    if source == "manual" and confidence == "high":
        return "verified"
    if source == "inferred-from-current-password":
        return "inferred"
    return source or "unknown"


def _policy_from_mapping(data: dict[str, object]) -> PasswordPolicy:
    return PasswordPolicy(
        length=int(data.get("length", 24)),
        lower=bool(data.get("lower", True)),
        upper=bool(data.get("upper", True)),
        numeric=bool(data.get("numeric", True)),
        special=bool(data.get("special", True)),
        special_chars=str(data.get("special_chars", DEFAULT_SPECIAL_CHARS)),
        exclude_chars=str(data.get("exclude_chars", "")),
        every_group=bool(data.get("every_group", True)),
    )


def _resolve_homepage_url(
    entry: str,
    *,
    homepage_url: str | None,
    registry: RotationRegistry | None,
    allow_interactive: bool,
) -> str:
    direct = _prefer_override(homepage_url, registry.homepage_url if registry else "")
    return direct or _read_entry_url(entry, allow_interactive=allow_interactive)


def _prefer_override(value: str | None, fallback: str) -> str:
    if value is None:
        return str(fallback or "").strip()
    return str(value).strip()


def _unique_chars_in_order(chars) -> str:
    seen: set[str] = set()
    ordered: list[str] = []
    for char in chars:
        if char not in seen:
            seen.add(char)
            ordered.append(char)
    return "".join(ordered)


def _parse_metadata(notes: str, *, entry: str, pending_entry: str) -> RotationMetadata:
    text = str(notes or "").strip()
    if not text:
        return RotationMetadata(
            schema_version=ROTATION_SCHEMA_VERSION,
            entry=entry,
            pending_entry=pending_entry,
            created_at="",
        )
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise KeepassCommandError(f"Pending rotation notes for {pending_entry!r} are not valid JSON metadata.")
    return RotationMetadata(
        schema_version=int(payload.get("schema_version", ROTATION_SCHEMA_VERSION)),
        entry=str(payload.get("entry") or entry).strip(),
        pending_entry=str(payload.get("pending_entry") or pending_entry).strip(),
        created_at=str(payload.get("created_at") or "").strip(),
        homepage_url=str(payload.get("homepage_url") or "").strip(),
        reset_url=str(payload.get("reset_url") or "").strip(),
        note=str(payload.get("note") or "").strip(),
        policy=payload.get("policy") if isinstance(payload.get("policy"), dict) else None,
    )


def _parse_registry(notes: str, *, entry: str, registry_entry: str) -> RotationRegistry:
    text = str(notes or "").strip()
    if not text:
        return RotationRegistry(
            schema_version=ROTATION_SCHEMA_VERSION,
            entry=entry,
            registry_entry=registry_entry,
        )
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise KeepassCommandError(
            f"Rotation registry notes for {registry_entry!r} are not valid JSON metadata."
        )
    interval = payload.get("rotation_interval_days")
    return RotationRegistry(
        schema_version=int(payload.get("schema_version", ROTATION_SCHEMA_VERSION)),
        entry=str(payload.get("entry") or entry).strip(),
        registry_entry=str(payload.get("registry_entry") or registry_entry).strip(),
        updated_at=str(payload.get("updated_at") or "").strip(),
        homepage_url=str(payload.get("homepage_url") or "").strip(),
        reset_url=str(payload.get("reset_url") or "").strip(),
        note=str(payload.get("note") or "").strip(),
        rotation_interval_days=int(interval) if interval is not None else None,
        policy=payload.get("policy") if isinstance(payload.get("policy"), dict) else None,
        policy_source=str(payload.get("policy_source") or "").strip(),
        policy_confidence=str(payload.get("policy_confidence") or "").strip(),
    )
