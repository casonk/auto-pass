"""
auto-pass web UI — FastAPI application.

Start with: auto-pass web [--port 8080] [--host 127.0.0.1]

Requires the [web] optional dependencies:
    pip install "auto-pass[web]"

Environment:
    AUTO_PASS_WEB_TOKEN               Required. Static token for the UI.
    AUTO_PASS_PROVISIONING_SOCKET     Optional. Daemon socket path.
    AUTO_PASS_PROVISIONING_ALLOWLIST  Optional. Allowlist TOML path.

Authentication: cookie session. Visit /login, enter the token; session lasts 30 days.
The server should be accessed over a secure tunnel (pit-box, windscreen, short-circuit).
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, Form, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from ..allowlist import default_allowlist_path
from ..client import ProvisioningClient, ProvisioningClientError
from ..keepassxc import (
    KeepassCommandError,
    resolve_keepassxc_entry_all_fields,
    upsert_keepassxc_entry,
    with_keepassxc_context,
)
from ..server import default_socket_path
from .audit import read_events
from .auth import get_configured_token, make_session_response, require_session

_TEMPLATES_DIR = Path(__file__).parent / "templates"

app = FastAPI(title="auto-pass", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _client() -> ProvisioningClient:
    return ProvisioningClient(socket_path=default_socket_path())


def _daemon_status() -> dict:
    try:
        result = _client().status()
        return {"running": True, "locked": result.get("locked", True)}
    except (OSError, ProvisioningClientError):
        return {"running": False, "locked": True}


def _get_admin_context() -> dict:
    try:
        return _client().admin_context()
    except OSError as exc:
        raise ProvisioningClientError(f"daemon not running: {exc}") from exc


def _load_allowlist_raw() -> dict:
    path = default_allowlist_path()
    if not path.exists():
        return {}
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def _save_allowlist(repos: dict[str, dict]) -> None:
    """Write repos dict back to the allowlist TOML file."""
    path = default_allowlist_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Provisioning allowlist — managed by auto-pass web", ""]
    for repo_name in sorted(repos):
        cfg = repos[repo_name]
        if "allowed_paths" in cfg:
            lines.append(f"[repos.{repo_name}]")
            db = cfg.get("db", "")
            if db:
                lines.append(f'db = "{db}"')
            items = ", ".join(f'"{p}"' for p in cfg["allowed_paths"])
            lines.append(f"allowed_paths = [{items}]")
            lines.append("")
        else:
            for vault_name in sorted(cfg.get("vaults", {})):
                vault = cfg["vaults"][vault_name]
                lines.append(f"[repos.{repo_name}.vaults.{vault_name}]")
                items = ", ".join(f'"{p}"' for p in vault.get("allowed_paths", []))
                lines.append(f"allowed_paths = [{items}]")
                lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/") -> HTMLResponse:
    return templates.TemplateResponse(
        "login.html", {"request": request, "next": next, "error": None}
    )


@app.post("/login")
def login_submit(
    request: Request,
    token: Annotated[str, Form()],
    next: Annotated[str, Form()] = "/",
) -> Any:
    import secrets

    try:
        expected = get_configured_token()
    except RuntimeError as exc:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "next": next, "error": str(exc)},
            status_code=500,
        )
    if not secrets.compare_digest(token.strip(), expected):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "next": next, "error": "Invalid token."},
            status_code=401,
        )
    return make_session_response(next_path=next)


@app.get("/logout")
def logout() -> RedirectResponse:
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("ap_session")
    return response


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    require_session(request)
    events = read_events(limit=200)
    daemon = _daemon_status()
    return templates.TemplateResponse(
        "audit.html",
        {"request": request, "events": events, "daemon": daemon, "active": "audit"},
    )


@app.get("/audit/events")
def audit_events_api(request: Request, limit: int = 200) -> JSONResponse:
    require_session(request)
    return JSONResponse(read_events(limit=min(limit, 1000)))


# ---------------------------------------------------------------------------
# Daemon control
# ---------------------------------------------------------------------------


@app.get("/daemon", response_class=HTMLResponse)
def daemon_page(request: Request) -> HTMLResponse:
    require_session(request)
    daemon = _daemon_status()
    return templates.TemplateResponse(
        "daemon.html",
        {
            "request": request,
            "daemon": daemon,
            "socket_path": str(default_socket_path()),
            "active": "daemon",
        },
    )


@app.post("/daemon/unlock")
def daemon_unlock(
    request: Request,
    password: Annotated[str, Form()],
) -> JSONResponse:
    require_session(request)
    try:
        _client().unlock(password)
        return JSONResponse({"ok": True})
    except (OSError, ProvisioningClientError) as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)


@app.post("/daemon/lock")
def daemon_lock(request: Request) -> JSONResponse:
    require_session(request)
    try:
        _client().lock()
        return JSONResponse({"ok": True})
    except (OSError, ProvisioningClientError) as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)


@app.post("/daemon/reload")
def daemon_reload(request: Request) -> JSONResponse:
    require_session(request)
    try:
        _client().reload()
        return JSONResponse({"ok": True})
    except (OSError, ProvisioningClientError) as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)


# ---------------------------------------------------------------------------
# Allowlist management
# ---------------------------------------------------------------------------


@app.get("/allowlist", response_class=HTMLResponse)
def allowlist_page(request: Request) -> HTMLResponse:
    require_session(request)
    data = _load_allowlist_raw()
    repos = data.get("repos", {})
    daemon = _daemon_status()
    return templates.TemplateResponse(
        "allowlist.html",
        {"request": request, "repos": repos, "daemon": daemon, "active": "allowlist"},
    )


@app.get("/allowlist/data")
def allowlist_data(request: Request) -> JSONResponse:
    require_session(request)
    return JSONResponse(_load_allowlist_raw().get("repos", {}))


@app.post("/allowlist/repo")
def allowlist_upsert_repo(
    request: Request,
    repo_name: Annotated[str, Form()],
    allowed_paths: Annotated[str, Form()] = "",
    db: Annotated[str, Form()] = "",
) -> JSONResponse:
    """Add or replace a simple-form repo. allowed_paths is a newline-separated list of globs."""
    require_session(request)
    name = repo_name.strip()
    if not name:
        return JSONResponse({"ok": False, "error": "repo name required"}, status_code=400)
    paths = [p.strip() for p in allowed_paths.splitlines() if p.strip()]
    data = _load_allowlist_raw()
    repos = data.get("repos", {})
    repo_cfg: dict = {"allowed_paths": paths}
    if db.strip():
        repo_cfg["db"] = db.strip()
    repos[name] = repo_cfg
    _save_allowlist(repos)
    try:
        _client().reload()
    except (OSError, ProvisioningClientError):
        pass
    return JSONResponse({"ok": True})


@app.delete("/allowlist/repo/{repo_name}")
def allowlist_delete_repo(request: Request, repo_name: str) -> JSONResponse:
    require_session(request)
    data = _load_allowlist_raw()
    repos = data.get("repos", {})
    if repo_name not in repos:
        return JSONResponse({"ok": False, "error": "repo not found"}, status_code=404)
    del repos[repo_name]
    _save_allowlist(repos)
    try:
        _client().reload()
    except (OSError, ProvisioningClientError):
        pass
    return JSONResponse({"ok": True})


# ---------------------------------------------------------------------------
# Entry manager
# ---------------------------------------------------------------------------


@app.get("/entries", response_class=HTMLResponse)
def entries_page(request: Request) -> HTMLResponse:
    require_session(request)
    daemon = _daemon_status()
    return templates.TemplateResponse(
        "entries.html",
        {"request": request, "daemon": daemon, "active": "entries"},
    )


@app.post("/entries/get")
def entries_get(
    request: Request,
    entry_path: Annotated[str, Form()],
) -> JSONResponse:
    require_session(request)
    try:
        ctx = _get_admin_context()
    except ProvisioningClientError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=503)
    with with_keepassxc_context(
        ctx["master_db_path"], ctx["master_db_password"], ctx.get("master_key_file", "")
    ):
        try:
            fields = resolve_keepassxc_entry_all_fields(entry=entry_path.strip())
            return JSONResponse({"ok": True, "fields": fields})
        except KeepassCommandError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)


@app.post("/entries/set")
def entries_set(
    request: Request,
    entry_path: Annotated[str, Form()],
    username: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
    url: Annotated[str, Form()] = "",
    notes: Annotated[str, Form()] = "",
) -> JSONResponse:
    require_session(request)
    try:
        ctx = _get_admin_context()
    except ProvisioningClientError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=503)
    with with_keepassxc_context(
        ctx["master_db_path"], ctx["master_db_password"], ctx.get("master_key_file", "")
    ):
        try:
            mode = upsert_keepassxc_entry(
                entry=entry_path.strip(),
                username=username or None,
                password=password or None,
                url=url or None,
                notes=notes or None,
                create_group=True,
            )
            return JSONResponse({"ok": True, "mode": mode})
        except KeepassCommandError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
