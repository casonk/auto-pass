from __future__ import annotations

import json
from pathlib import Path
from typing import Any

AUDIT_LOG = Path.home() / ".cache" / "auto-pass" / "audit.jsonl"


def read_events(limit: int = 500) -> list[dict[str, Any]]:
    """Return up to ``limit`` most-recent audit events, newest first."""
    if not AUDIT_LOG.exists():
        return []
    lines: list[str] = []
    try:
        lines = AUDIT_LOG.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    events: list[dict] = []
    for line in reversed(lines[-limit * 2 :]):
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
        if len(events) >= limit:
            break
    return events
