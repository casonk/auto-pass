"""Whole-database KeePass helpers built on ``keepassxc-cli export`` / ``import`` / ``merge``.

``keepassxc-cli add`` and ``edit`` cannot set custom attributes or TOTP seeds, so copying an
entry that way silently drops them. Exporting the database as XML, filtering it in memory and
importing the result into a new database keeps every attribute. The XML holds secrets in
plaintext: it is only ever held in this process, or written to a private directory on a tmpfs
for the one ``import`` call that needs a file path, and removed straight afterwards.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .keepassxc import KeepassCommandError

_TMPFS = Path("/dev/shm")
_TIMEOUT = 120


@dataclass(frozen=True)
class Entry:
    path: str
    fields: dict[str, str]
    modified: str = ""
    attachments: int = 0

    def digest(self, key: bytes) -> str:
        """Keyed digest of every field, so state files never hold a guessable hash."""
        payload = json.dumps(
            [sorted(self.fields.items()), self.attachments], separators=(",", ":")
        ).encode()
        return hmac.new(key, payload, hashlib.sha256).hexdigest()

    def password_digest(self, key: bytes) -> str:
        return hmac.new(key, self.fields.get("Password", "").encode(), hashlib.sha256).hexdigest()


def _run(cmd: list[str], stdin: str, *, what: str) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(  # noqa: S603
            cmd, input=stdin, capture_output=True, text=True, timeout=_TIMEOUT, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise KeepassCommandError(f"keepassxc-cli {what} failed: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or "").strip().splitlines()
        raise KeepassCommandError(f"keepassxc-cli {what} failed: {detail[-1] if detail else '?'}")
    return result


def export_xml(db_path: str, db_password: str, key_file: str = "") -> ET.Element:
    """Return the decrypted database as an XML tree (in memory only)."""
    cmd = ["keepassxc-cli", "export", "-q", "-f", "xml"]
    if key_file:
        cmd.extend(["-k", key_file])
    cmd.append(db_path)
    result = _run(cmd, db_password + "\n", what="export")
    try:
        return ET.fromstring(result.stdout)
    except ET.ParseError as exc:
        raise KeepassCommandError(f"unparseable export of {Path(db_path).name}") from exc


def _recycle_bin(root: ET.Element) -> str:
    return (root.findtext("./Meta/RecycleBinUUID") or "").strip()


def _title(entry: ET.Element) -> str:
    for string in entry.findall("String"):
        if string.findtext("Key") == "Title":
            return string.findtext("Value") or ""
    return ""


def _walk(group: ET.Element, prefix: str, skip_uuid: str) -> Iterator[tuple[str, ET.Element]]:
    for entry in group.findall("Entry"):
        yield (f"{prefix}{_title(entry)}", entry)
    for child in group.findall("Group"):
        if skip_uuid and (child.findtext("UUID") or "").strip() == skip_uuid:
            continue
        yield from _walk(child, f"{prefix}{child.findtext('Name') or ''}/", skip_uuid)


def iter_entries(root: ET.Element) -> Iterator[tuple[str, ET.Element]]:
    """Yield ``(path, <Entry>)`` for every live entry; the root group name is not in the path."""
    top = root.find("./Root/Group")
    if top is None:
        return
    yield from _walk(top, "", _recycle_bin(root))


def _to_entry(path: str, element: ET.Element) -> Entry:
    fields = {
        s.findtext("Key") or "": s.findtext("Value") or ""
        for s in element.findall("String")
        if s.findtext("Key")
    }
    return Entry(
        path=path,
        fields=fields,
        modified=element.findtext("./Times/LastModificationTime") or "",
        attachments=len(element.findall("Binary")),
    )


def entries_from_xml(root: ET.Element) -> dict[str, Entry]:
    return {path: _to_entry(path, el) for path, el in iter_entries(root)}


def read_entries(db_path: str, db_password: str, key_file: str = "") -> dict[str, Entry]:
    """Every live entry in a database, keyed by path."""
    return entries_from_xml(export_xml(db_path, db_password, key_file))


def filter_xml(
    root: ET.Element, keep: set[str], *, prefix: str = "", drop_history: bool = True
) -> ET.Element:
    """Return a copy of ``root`` that holds only the entries in ``keep``.

    Groups left empty are pruned, the recycle bin and deletion log are dropped, and (by
    default) entry history is stripped so a scoped copy never carries superseded passwords.
    ``prefix`` nests the kept tree under a new top-level group (used when consolidating).
    """
    out = ET.fromstring(ET.tostring(root))
    top = out.find("./Root/Group")
    if top is None:
        raise KeyError("export has no root group")
    bin_uuid = _recycle_bin(out)

    def prune(group: ET.Element, path: str) -> bool:
        for entry in list(group.findall("Entry")):
            if f"{path}{_title(entry)}" not in keep:
                group.remove(entry)
            elif drop_history:
                for hist in entry.findall("History"):
                    for old in list(hist):
                        hist.remove(old)
        for child in list(group.findall("Group")):
            is_bin = bool(bin_uuid) and (child.findtext("UUID") or "").strip() == bin_uuid
            if is_bin or not prune(child, f"{path}{child.findtext('Name') or ''}/"):
                group.remove(child)
        return bool(group.findall("Entry") or group.findall("Group"))

    prune(top, "")
    deleted = out.find("./Root/DeletedObjects")
    if deleted is not None:
        for item in list(deleted):
            deleted.remove(item)
    if prefix:
        wrapper = ET.Element("Group")
        ET.SubElement(wrapper, "Name").text = prefix
        for child in list(top):
            if child.tag in {"Entry", "Group"}:
                top.remove(child)
                wrapper.append(child)
        top.append(wrapper)
    return out


def remap_uuids(root: ET.Element, salt: str) -> None:
    """Give every group and entry (history included) a new, deterministic UUID, in place.

    ``merge`` matches by UUID, so a copy that shares UUIDs with the database it is merged into
    would collapse onto the originals instead of adding anything. Deriving the new ids from
    the old ones keeps a repeated merge idempotent.
    """
    for node in root.findall("./Root//UUID"):
        old = (node.text or "").strip()
        node.text = base64.b64encode(
            hashlib.sha256(f"{salt}:{old}".encode()).digest()[:16]
        ).decode()


@contextlib.contextmanager
def _private_dir() -> Iterator[Path]:
    base = _TMPFS if _TMPFS.is_dir() and os.access(_TMPFS, os.W_OK) else None
    path = Path(tempfile.mkdtemp(prefix="auto-pass-", dir=base))
    os.chmod(path, 0o700)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def import_xml(root: ET.Element, out_path: str | Path, password: str) -> None:
    """Create a new database at ``out_path`` from an XML tree, protected by ``password``."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with _private_dir() as tmp:
        xml_file = tmp / "in.xml"
        fd = os.open(xml_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            ET.ElementTree(root).write(fh, encoding="utf-8", xml_declaration=True)
        staged = tmp / "out.kdbx"
        _run(
            ["keepassxc-cli", "import", "-q", "-p", str(xml_file), str(staged)],
            f"{password}\n{password}\n",
            what="import",
        )
        # tmpfs → disk cannot be a rename; copy next to the target, then replace atomically.
        part = out.with_name(out.name + ".part")
        shutil.copyfile(staged, part)
        os.chmod(part, 0o600)
        os.replace(part, out)


def merge_into(
    db_path: str, db_password: str, other_path: str, other_password: str, key_file: str = ""
) -> None:
    """Merge ``other`` into ``db`` (KeePass last-modified-wins semantics)."""
    cmd = ["keepassxc-cli", "merge", "-q"]
    if key_file:
        cmd.extend(["-k", key_file])
    cmd.extend([db_path, other_path])
    _run(cmd, f"{db_password}\n{other_password}\n", what="merge")
