from __future__ import annotations

import os
import secrets

from fastapi import Cookie, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

_TOKEN_ENV = "AUTO_PASS_WEB_TOKEN"
_SESSION_COOKIE = "ap_session"


def get_configured_token() -> str:
    token = os.environ.get(_TOKEN_ENV, "").strip()
    if not token:
        raise RuntimeError(
            f"AUTO_PASS_WEB_TOKEN is not set. "
            "Add it to config/auto-pass.env.local before starting the web server."
        )
    return token


def verify_session(request: Request) -> bool:
    """Return True if the request carries a valid session cookie."""
    token = get_configured_token()
    cookie = request.cookies.get(_SESSION_COOKIE, "")
    return secrets.compare_digest(cookie, token)


def require_session(request: Request) -> None:
    """Raise 401 (API) or redirect to /login (browser) when not authenticated."""
    if verify_session(request):
        return
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        raise HTTPException(
            status_code=status.HTTP_302_FOUND,
            headers={"location": f"/login?next={request.url.path}"},
        )
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="not authenticated")


def make_session_response(next_path: str = "/") -> RedirectResponse:
    token = get_configured_token()
    response = RedirectResponse(url=next_path, status_code=302)
    response.set_cookie(
        _SESSION_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        max_age=86400 * 30,
    )
    return response
