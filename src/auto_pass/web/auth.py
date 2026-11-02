from __future__ import annotations

import os
import secrets

from fastapi import HTTPException, Request, status
from fastapi.responses import RedirectResponse

_TOKEN_ENV = "AUTO_PASS_WEB_TOKEN"
_SESSION_COOKIE = "ap_session"


def get_configured_token() -> str:
    token = os.environ.get(_TOKEN_ENV, "").strip()
    if not token:
        raise RuntimeError(
            "AUTO_PASS_WEB_TOKEN is not set. "
            "Add it to config/auto-pass.env.local before starting the web server."
        )
    return token


def tokens_match(supplied: str, expected: str) -> bool:
    """Constant-time comparison that is safe for any text.

    ``secrets.compare_digest`` on two ``str`` raises TypeError if either holds a non-ASCII
    character, which would turn a hostile cookie or form value into a server error.
    """
    return secrets.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))


def safe_next(path: str) -> str:
    """A post-login destination on this site, or ``/``.

    Only an absolute path is accepted: a scheme, a host (``//host``) or a backslash, which
    some browsers treat as a slash, would send the user to another site after they log in.
    """
    if path.startswith("/") and not path.startswith("//") and "\\" not in path:
        return path
    return "/"


def verify_session(request: Request) -> bool:
    """Return True if the request carries a valid session cookie."""
    token = get_configured_token()
    cookie = request.cookies.get(_SESSION_COOKIE, "")
    return tokens_match(cookie, token)


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
    response = RedirectResponse(url=safe_next(next_path), status_code=302)
    response.set_cookie(
        _SESSION_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        max_age=86400 * 30,
    )
    return response
