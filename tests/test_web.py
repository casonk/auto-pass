"""The web UI's trust boundary: who gets in, what they can change, and what is written to disk.

The UI can unlock and lock the vault daemon, read any entry and rewrite the allowlist that
decides which repositories may read which secrets. Every test here runs against a fake
provisioning client, a temporary allowlist and a temporary audit log: nothing reaches a real
daemon, vault or home directory. The tests pin that no route does anything without a valid
session, that a login cannot be used to bounce someone off-site, and that the allowlist file
is always valid TOML containing exactly what was entered.
"""

from __future__ import annotations

import contextlib
import json
import tomllib

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("multipart")
from fastapi.testclient import TestClient  # noqa: E402

from auto_pass.client import ProvisioningClientError  # noqa: E402
from auto_pass.keepassxc import KeepassCommandError  # noqa: E402
from auto_pass.web import app as web_app  # noqa: E402
from auto_pass.web import audit, auth  # noqa: E402

TOKEN = "correct-horse-battery-staple"


class FakeClient:
    """Records every call, so a refused request can be shown to have done nothing."""

    def __init__(self):
        self.calls: list[tuple] = []
        self.fail: Exception | None = None
        self.running = True
        self.locked = False
        self.context = {
            "master_db_path": "/db.kdbx",
            "master_db_password": "pw",
            "master_key_file": "",
        }

    def _do(self, *call):
        self.calls.append(call)
        if self.fail is not None:
            raise self.fail

    def status(self):
        self.calls.append(("status",))
        if not self.running:
            raise OSError("no socket")
        return {"ok": True, "locked": self.locked}

    def unlock(self, password):
        self._do("unlock", password)

    def lock(self):
        self._do("lock")

    def reload(self):
        self._do("reload")

    def admin_context(self):
        self._do("admin_context")
        return self.context


@pytest.fixture
def fake(monkeypatch, tmp_path):
    client = FakeClient()
    monkeypatch.setenv(auth._TOKEN_ENV, TOKEN)
    monkeypatch.setattr(web_app, "_client", lambda: client)
    monkeypatch.setattr(
        web_app, "default_allowlist_path", lambda: tmp_path / "cfg" / "allowlist.toml"
    )
    monkeypatch.setattr(web_app, "default_socket_path", lambda: tmp_path / "test.sock")
    monkeypatch.setattr(audit, "AUDIT_LOG", tmp_path / "audit.jsonl")
    client.allowlist = tmp_path / "cfg" / "allowlist.toml"
    client.audit = tmp_path / "audit.jsonl"
    return client


@pytest.fixture
def anon(fake):
    return TestClient(web_app.app, follow_redirects=False)


@pytest.fixture
def client(fake):
    c = TestClient(web_app.app, follow_redirects=False)
    c.cookies.set(auth._SESSION_COOKIE, TOKEN)
    return c


JSON = {"accept": "application/json"}


# --------------------------------------------------------------------------- the token and the session


def test_the_token_must_be_configured_and_is_stripped(monkeypatch):
    monkeypatch.delenv(auth._TOKEN_ENV, raising=False)
    with pytest.raises(RuntimeError, match="AUTO_PASS_WEB_TOKEN is not set"):
        auth.get_configured_token()
    monkeypatch.setenv(auth._TOKEN_ENV, "   ")
    with pytest.raises(RuntimeError):
        auth.get_configured_token()
    monkeypatch.setenv(auth._TOKEN_ENV, "  abc \n")
    assert auth.get_configured_token() == "abc"


PROTECTED = [
    ("get", "/"),
    ("get", "/audit/events"),
    ("get", "/daemon"),
    ("post", "/daemon/unlock"),
    ("post", "/daemon/lock"),
    ("post", "/daemon/reload"),
    ("get", "/allowlist"),
    ("get", "/allowlist/data"),
    ("post", "/allowlist/repo"),
    ("delete", "/allowlist/repo/anything"),
    ("get", "/entries"),
    ("post", "/entries/get"),
    ("post", "/entries/set"),
]


@pytest.mark.parametrize(("method", "path"), PROTECTED)
def test_no_route_does_anything_without_a_session(anon, fake, method, path):
    data = {"password": "x", "repo_name": "r", "entry_path": "e"} if method == "post" else None
    response = getattr(anon, method)(path, headers=JSON, **({"data": data} if data else {}))
    assert response.status_code == 401
    assert response.json() == {"detail": "not authenticated"}
    # the daemon was never asked anything, and nothing was written
    assert [c for c in fake.calls if c[0] != "status"] == []
    assert not fake.allowlist.exists()


@pytest.mark.parametrize(("method", "path"), PROTECTED)
def test_a_wrong_or_empty_cookie_is_refused_everywhere(fake, method, path):
    for value in ("", "wrong", TOKEN + "x", TOKEN[:-1]):
        c = TestClient(web_app.app, follow_redirects=False)
        c.cookies.set(auth._SESSION_COOKIE, value)
        assert getattr(c, method)(path, headers=JSON).status_code in (401, 422)
    assert [c for c in fake.calls if c[0] != "status"] == []


def test_a_cookie_with_non_ascii_text_is_a_401_not_a_server_error(anon, fake):
    # httpx's cookie jar only takes ASCII, so send the header as raw bytes
    headers = [(b"accept", b"application/json"), (b"cookie", "ap_session=tökën".encode())]
    assert anon.get("/audit/events", headers=headers).status_code == 401


def test_a_browser_is_sent_to_the_login_page_and_a_script_gets_a_401(anon):
    browser = anon.get("/allowlist", headers={"accept": "text/html,application/xhtml+xml"})
    assert browser.status_code == 302
    assert browser.headers["location"] == "/login?next=/allowlist"
    assert anon.get("/allowlist", headers=JSON).status_code == 401


def test_the_session_cookie_is_http_only_lax_and_thirty_days(fake):
    response = auth.make_session_response("/daemon")
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{auth._SESSION_COOKIE}=")
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie and f"Max-Age={86400 * 30}" in cookie
    assert response.headers["location"] == "/daemon" and response.status_code == 302


# --------------------------------------------------------------------------- login and logout


def test_the_login_page_renders(anon):
    response = anon.get("/login?next=/daemon")
    assert response.status_code == 200 and "text/html" in response.headers["content-type"]


def test_the_right_token_logs_in_even_with_padding_and_a_wrong_one_does_not(anon):
    ok = anon.post("/login", data={"token": f"  {TOKEN}\n", "next": "/daemon"})
    assert ok.status_code == 302 and ok.headers["location"] == "/daemon"
    assert f"{auth._SESSION_COOKIE}={TOKEN}" in ok.headers["set-cookie"]
    for bad in ("wrong", TOKEN + "x", TOKEN.upper(), " "):
        refused = anon.post("/login", data={"token": bad})
        assert refused.status_code == 401
        assert "set-cookie" not in refused.headers
        assert "Invalid token" in refused.text
    # an empty field never reaches the comparison: the form is rejected as incomplete
    empty = anon.post("/login", data={"token": ""})
    assert empty.status_code == 422 and "set-cookie" not in empty.headers


def test_a_non_ascii_token_is_refused_not_a_server_error(anon):
    assert anon.post("/login", data={"token": "tökën"}).status_code == 401


def test_a_server_with_no_token_configured_cannot_log_anyone_in(anon, monkeypatch):
    monkeypatch.delenv(auth._TOKEN_ENV, raising=False)
    response = anon.post("/login", data={"token": "anything"})
    assert response.status_code == 500 and "set-cookie" not in response.headers
    assert "AUTO_PASS_WEB_TOKEN is not set" in response.text


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.example/",
        "//evil.example/",
        "http://evil.example",
        "/\\evil.example",
        "javascript:alert(1)",
        "evil",
        "",
    ],
)
def test_a_login_never_redirects_off_site(anon, target):
    response = anon.post("/login", data={"token": TOKEN, "next": target})
    assert response.status_code == 302
    assert response.headers["location"] == "/"


@pytest.mark.parametrize("target", ["/", "/daemon", "/allowlist", "/entries?x=1"])
def test_a_login_follows_a_path_on_this_site(anon, target):
    assert anon.post("/login", data={"token": TOKEN, "next": target}).headers["location"] == target


def test_logout_clears_the_cookie_and_returns_to_login(client):
    response = client.get("/logout")
    assert response.status_code == 302 and response.headers["location"] == "/login"
    assert (
        f'{auth._SESSION_COOKIE}=""' in response.headers["set-cookie"]
        or "Max-Age=0" in response.headers["set-cookie"]
    )


# --------------------------------------------------------------------------- the audit log


def write_events(fake, *lines):
    fake.audit.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_audit_events_come_newest_first_and_skip_blank_and_corrupt_lines(fake):
    write_events(
        fake,
        json.dumps({"n": 1}),
        "",
        "not json",
        json.dumps({"n": 2}),
        "   ",
        json.dumps({"n": 3}),
    )
    assert [e["n"] for e in audit.read_events()] == [3, 2, 1]


def test_the_audit_log_is_bounded_by_the_limit(fake):
    write_events(fake, *[json.dumps({"n": i}) for i in range(50)])
    assert [e["n"] for e in audit.read_events(limit=3)] == [49, 48, 47]


def test_a_missing_or_unreadable_audit_log_is_empty(fake, monkeypatch):
    assert audit.read_events() == []
    fake.audit.mkdir()  # reading a directory raises OSError
    assert audit.read_events() == []


def test_the_audit_api_caps_the_limit_at_a_thousand(client, fake, monkeypatch):
    seen = []
    monkeypatch.setattr(web_app, "read_events", lambda limit: seen.append(limit) or [])
    client.get("/audit/events?limit=999999")
    client.get("/audit/events?limit=7")
    client.get("/audit/events")
    assert seen == [1000, 7, 200]


def test_the_dashboard_shows_events_and_daemon_state(client, fake):
    write_events(
        fake, json.dumps({"ts": "t", "repo": "marker-repo-name", "path": "p", "decision": "allow"})
    )
    response = client.get("/")
    assert response.status_code == 200 and "text/html" in response.headers["content-type"]
    assert client.get("/audit/events").json()[0]["repo"] == "marker-repo-name"


# --------------------------------------------------------------------------- the daemon


def test_the_daemon_page_reports_running_locked_or_not_running(client, fake):
    assert client.get("/daemon").status_code == 200
    fake.locked = True
    assert client.get("/daemon").status_code == 200
    fake.running = False
    assert web_app._daemon_status() == {"running": False, "locked": True}
    fake.running, fake.locked = True, False
    assert web_app._daemon_status() == {"running": True, "locked": False}
    fake.fail = None
    assert client.get("/daemon").status_code == 200


def test_unlock_lock_and_reload_succeed_and_pass_the_password_only_to_the_daemon(client, fake):
    assert client.post("/daemon/unlock", data={"password": "the vault password"}).json() == {
        "ok": True
    }
    assert client.post("/daemon/lock").json() == {"ok": True}
    assert client.post("/daemon/reload").json() == {"ok": True}
    assert fake.calls == [("unlock", "the vault password"), ("lock",), ("reload",)]


@pytest.mark.parametrize("path", ["/daemon/unlock", "/daemon/lock", "/daemon/reload"])
@pytest.mark.parametrize(
    "error", [ProvisioningClientError("wrong password"), OSError("daemon is down")]
)
def test_a_daemon_failure_is_a_400_with_its_reason_and_never_the_password(
    client, fake, path, error
):
    fake.fail = error
    response = client.post(path, data={"password": "the vault password"})
    assert response.status_code == 400
    assert response.json()["ok"] is False and str(error) in response.json()["error"]
    assert "the vault password" not in response.text


def test_unlock_needs_a_password(client, fake):
    assert client.post("/daemon/unlock").status_code == 422
    assert fake.calls == []


# --------------------------------------------------------------------------- the allowlist


def saved(fake) -> dict:
    return tomllib.loads(fake.allowlist.read_text(encoding="utf-8"))


def add(client, **form):
    return client.post("/allowlist/repo", data=form)


def test_adding_a_repo_writes_its_paths_and_asks_the_daemon_to_reload(client, fake):
    response = add(
        client, repo_name=" myrepo ", allowed_paths="web/github\n  infra/*  \n\n", db="infra"
    )
    assert response.json() == {"ok": True}
    assert saved(fake)["repos"]["myrepo"] == {
        "db": "infra",
        "allowed_paths": ["web/github", "infra/*"],
    }
    assert ("reload",) in fake.calls


def test_a_repo_without_a_db_has_no_db_key_and_replacing_a_repo_replaces_it(client, fake):
    add(client, repo_name="r", allowed_paths="a")
    assert saved(fake)["repos"]["r"] == {"allowed_paths": ["a"]}
    add(client, repo_name="r", allowed_paths="b", db="d")
    assert saved(fake)["repos"]["r"] == {"db": "d", "allowed_paths": ["b"]}


def test_a_repo_name_is_required(client, fake):
    response = add(client, repo_name="   ", allowed_paths="a")
    assert response.status_code == 400 and response.json()["error"] == "repo name required"
    assert add(client, repo_name="", allowed_paths="a").status_code == 422  # rejected as incomplete
    assert not fake.allowlist.exists()


def test_a_reload_failure_does_not_undo_the_save(client, fake):
    fake.fail = ProvisioningClientError("daemon is down")
    assert add(client, repo_name="r", allowed_paths="a").json() == {"ok": True}
    assert saved(fake)["repos"]["r"]["allowed_paths"] == ["a"]


def test_the_saved_file_lists_repos_in_sorted_order_and_keeps_vault_scoped_entries(client, fake):
    fake.allowlist.parent.mkdir(parents=True)
    fake.allowlist.write_text(
        '[repos.zeta.vaults.infra]\nallowed_paths = ["codecov/*"]\n\n'
        '[repos.zeta.vaults.master]\nallowed_paths = ["dev/*"]\n',
        encoding="utf-8",
    )
    add(client, repo_name="alpha", allowed_paths="x")
    data = saved(fake)
    assert list(data["repos"]) == ["alpha", "zeta"]
    assert data["repos"]["zeta"]["vaults"] == {
        "infra": {"allowed_paths": ["codecov/*"]},
        "master": {"allowed_paths": ["dev/*"]},
    }


@pytest.mark.parametrize(
    "path",
    [
        'has"quote',
        "back\\slash",
        'multi"] \n[repos.evil]\nallowed_paths = ["*',
        "tab\there",
        "unicode-é-✓",
        "del\x7fchar",
        "bell\x07",
    ],
)
def test_an_allowed_path_is_stored_exactly_as_typed_whatever_it_contains(client, fake, path):
    # a line break separates paths, so only the first line of an injected value is one path
    first_line = path.splitlines()[0].strip()
    add(client, repo_name="r", allowed_paths=path)
    data = saved(fake)
    assert set(data["repos"]) == {"r"}, "form input must not create another repository"
    assert data["repos"]["r"]["allowed_paths"][0] == first_line


def test_existing_entries_with_unusual_names_are_rewritten_as_they_were_not_merged_or_broken(
    client, fake
):
    fake.allowlist.parent.mkdir(parents=True)
    fake.allowlist.write_text(
        '[repos."odd.name".vaults."v.1"]\nallowed_paths = ["a/*"]\n\n'
        '[repos."has space".vaults.master]\nallowed_paths = ["b/*"]\n',
        encoding="utf-8",
    )
    add(client, repo_name="plain", allowed_paths="x")
    data = saved(fake)
    # a dotted name stays one repository (not repos.odd -> name), and a spaced one stays intact
    assert set(data["repos"]) == {"odd.name", "has space", "plain"}
    assert data["repos"]["odd.name"]["vaults"] == {"v.1": {"allowed_paths": ["a/*"]}}
    assert data["repos"]["has space"]["vaults"] == {"master": {"allowed_paths": ["b/*"]}}


@pytest.mark.parametrize(
    "name", ['a"b', "a]b", "a\nb", "a b", "a.b", "../x", "evil]\n[repos.other", "[x]"]
)
def test_a_repo_name_that_is_not_a_plain_key_is_refused(client, fake, name):
    response = add(client, repo_name=name, allowed_paths="a")
    assert response.status_code == 400
    assert not fake.allowlist.exists()


def test_a_db_value_is_stored_exactly_as_typed(client, fake):
    add(client, repo_name="r", allowed_paths="a", db='in"fra')
    assert saved(fake)["repos"]["r"]["db"] == 'in"fra'


def test_the_allowlist_pages_read_what_is_on_disk(client, fake):
    assert client.get("/allowlist/data").json() == {}
    assert client.get("/allowlist").status_code == 200
    add(client, repo_name="r", allowed_paths="a")
    assert client.get("/allowlist/data").json() == {"r": {"allowed_paths": ["a"]}}


def test_deleting_a_repo_removes_only_that_repo(client, fake):
    add(client, repo_name="keep", allowed_paths="a")
    add(client, repo_name="drop", allowed_paths="b")
    fake.calls.clear()
    assert client.delete("/allowlist/repo/drop").json() == {"ok": True}
    assert set(saved(fake)["repos"]) == {"keep"}
    assert ("reload",) in fake.calls


def test_deleting_an_unknown_repo_is_a_404_and_changes_nothing(client, fake):
    add(client, repo_name="keep", allowed_paths="a")
    before = fake.allowlist.read_text()
    response = client.delete("/allowlist/repo/nope")
    assert response.status_code == 404 and response.json()["error"] == "repo not found"
    assert fake.allowlist.read_text() == before


# --------------------------------------------------------------------------- entries


@pytest.fixture
def keepass(monkeypatch):
    calls = {"context": [], "get": [], "set": []}

    @contextlib.contextmanager
    def context(db, password, key_file):
        calls["context"].append((db, password, key_file))
        yield

    state = {"error": None}

    def get(entry):
        calls["get"].append(entry)
        if state["error"]:
            raise state["error"]
        return {"username": "u", "password": "p"}

    def upsert(**kwargs):
        calls["set"].append(kwargs)
        if state["error"]:
            raise state["error"]
        return "updated"

    monkeypatch.setattr(web_app, "with_keepassxc_context", context)
    monkeypatch.setattr(web_app, "resolve_keepassxc_entry_all_fields", get)
    monkeypatch.setattr(web_app, "upsert_keepassxc_entry", upsert)
    calls["state"] = state
    return calls


def test_the_entries_page_renders(client):
    assert client.get("/entries").status_code == 200


def test_reading_an_entry_opens_the_master_db_with_the_daemons_context(client, fake, keepass):
    response = client.post("/entries/get", data={"entry_path": "  web/github  "})
    assert response.json() == {"ok": True, "fields": {"username": "u", "password": "p"}}
    assert keepass["get"] == ["web/github"]
    assert keepass["context"] == [("/db.kdbx", "pw", "")]


def test_entries_need_the_daemon_and_report_keepass_errors(client, fake, keepass):
    keepass["state"]["error"] = KeepassCommandError("no such entry")
    bad = client.post("/entries/get", data={"entry_path": "x"})
    assert bad.status_code == 400 and bad.json() == {"ok": False, "error": "no such entry"}
    fake.fail = ProvisioningClientError("daemon is locked")
    for path in ("/entries/get", "/entries/set"):
        response = client.post(path, data={"entry_path": "x"})
        assert response.status_code == 503 and "locked" in response.json()["error"]
    fake.fail = None
    fake.running = False  # admin_context raising OSError is also "daemon not running"
    fake.fail = OSError("gone")
    assert client.post("/entries/get", data={"entry_path": "x"}).status_code == 503


def test_setting_an_entry_passes_blank_fields_as_unchanged_and_creates_the_group(
    client, fake, keepass
):
    response = client.post("/entries/set", data={"entry_path": " new/entry ", "password": "s3cret"})
    assert response.json() == {"ok": True, "mode": "updated"}
    call = keepass["set"][0]
    assert call["entry"] == "new/entry" and call["password"] == "s3cret"
    assert call["username"] is None and call["url"] is None and call["notes"] is None
    assert call["create_group"] is True


def test_a_failed_set_is_a_400_and_does_not_echo_the_password(client, fake, keepass):
    keepass["state"]["error"] = KeepassCommandError("database is read-only")
    response = client.post("/entries/set", data={"entry_path": "x", "password": "topsecret"})
    assert response.status_code == 400 and response.json()["error"] == "database is read-only"
    assert "topsecret" not in response.text
