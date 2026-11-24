"""Best-effort masking for secret-like values before they reach logs."""

from __future__ import annotations

import re

REDACTED = "[REDACTED]"

_PEM_BLOCK = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
    re.DOTALL,
)
_QUERY_PARAM = re.compile(
    r"([?&](?:access_token|refresh_token|id_token|token|client_secret|api_key|apikey|key|"
    r"password|secret|sig|signature)=)(?!\[REDACTED\])[^&\s\"'<>`)\]]+",
    re.IGNORECASE,
)
_URL_USERINFO = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s/:@]+:)[^\s/@]+(@)", re.IGNORECASE)
_AUTH_HEADER = re.compile(
    r"\b(Bearer|Basic)\s+(?!\[REDACTED\])[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE
)
_NAMED_SECRET = re.compile(
    r"""(?ix)
    (\b[\w.-]*(?:secret|token|passw(?:or)?d|passwd|api[_-]?key|private[_-]?key|credential)[\w.-]*
     ["']?\s*[:=]\s*["']?)
    (?!\[REDACTED\])
    [^\s"',;&)\]}]{8,}
    """
)
_TOKEN_SHAPES = tuple(
    re.compile(pattern)
    for pattern in (
        r"\bya29\.[A-Za-z0-9_-]{20,}",
        r"\bgh[pousr]_[A-Za-z0-9]{30,}",
        r"\bgithub_pat_[A-Za-z0-9_]{30,}",
        r"\bglpat-[A-Za-z0-9_-]{16,}",
        r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}",
        r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
        r"\bAKIA[0-9A-Z]{16}\b",
        r"\bnpm_[A-Za-z0-9]{30,}",
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
    )
)


def redact(text: str) -> str:
    """Return text with common credential shapes replaced."""
    if not text:
        return text
    text = _PEM_BLOCK.sub(REDACTED, text)
    text = _QUERY_PARAM.sub(rf"\1{REDACTED}", text)
    text = _URL_USERINFO.sub(rf"\1{REDACTED}\2", text)
    text = _AUTH_HEADER.sub(rf"\1 {REDACTED}", text)
    for shape in _TOKEN_SHAPES:
        text = shape.sub(REDACTED, text)
    return _NAMED_SECRET.sub(rf"\1{REDACTED}", text)
