"""The Entries page's list and lookup, and the Allowlist page with a simple-form repo."""

from __future__ import annotations

import contextlib
import json

from auto_pass.web import app as web
from auto_pass.web.app import templates


def _render(name: str, **context: object) -> str:
    return templates.get_template(name).render(
        request=None, active=name.removesuffix(".html"), url_for=lambda *a, **k: "/", **context
    )


def test_allowlist_template_renders_a_repo_without_allowed_paths():
    html = _render(
        "allowlist.html",
        repos={"simple": {"db": "vault"}, "paths": {"allowed_paths": ["a/*"]}},
        daemon={},
    )
    assert "editRepo('simple', [])" in html
    assert "editRepo('paths', [&#34;a/*&#34;]" in html or "editRepo('paths', [\"a/*\"]" in html


def test_entries_list_returns_sorted_paths_only(monkeypatch):
    monkeypatch.setattr(web, "require_session", lambda request: None)
    monkeypatch.setattr(
        web, "_get_admin_context", lambda: {"master_db_path": "x", "master_db_password": "pw"}
    )
    monkeypatch.setattr(web, "with_keepassxc_context", lambda *a, **k: contextlib.nullcontext())
    monkeypatch.setattr(web, "list_keepassxc_entries", lambda group: ["web/b", "web/", "api/a"])
    response = web.entries_list(None)
    assert json.loads(response.body) == {"ok": True, "entries": ["api/a", "web/b"]}


def test_entries_page_has_the_list_tree_and_filter():
    html = _render("entries.html", daemon={"running": True, "locked": False})
    assert 'id="entry-list"' in html and 'id="entry-filter"' in html
    assert "function buildTree" in html and "setAllFolders(true)" in html


def test_entries_lookup_does_not_embed_fields_in_an_attribute():
    html = _render("entries.html", daemon={"running": True, "locked": False})
    assert "JSON.stringify(j.fields)" not in html
    assert "edit.onclick = () => fillSetForm(j.fields, path)" in html


def test_entries_lookup_can_reveal_and_copy_secret_fields():
    html = _render("entries.html", daemon={"running": True, "locked": False})
    assert "navigator.clipboard.writeText" in html and "(empty)" in html
