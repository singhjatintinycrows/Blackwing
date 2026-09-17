"""Identity / authentication.

Blackwing is NOT open to anonymous submission — the whole app sits behind the org SSO. This
module is the single seam where that integration lives. In production, replace ``current_user``
with your SSO (OIDC/SAML) session check. For local development it accepts a signed-cookie
identity set by a simple dev login, and it *always* requires an authenticated identity — there
is no anonymous path.
"""
from __future__ import annotations

import os

from fastapi import Request
from fastapi.responses import RedirectResponse
from starlette.exceptions import HTTPException

# Users allowed to approve engagements (the human-approval step). In production, source this
# from an SSO group / role claim rather than an env list.
REVIEWERS = set(
    filter(None, os.environ.get("BLACKWING_REVIEWERS", "reviewer@tinycrows.com").split(","))
)


def current_user(request: Request) -> str | None:
    """Return the authenticated identity, or None. Reads the dev session cookie or a trusted
    reverse-proxy SSO header (X-Forwarded-User) if present."""
    sso_header = request.headers.get("x-forwarded-user")
    if sso_header:
        return sso_header
    return request.session.get("user")


def require_user(request: Request) -> str:
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=307, headers={"Location": "/login"})
    return user


def is_reviewer(user: str) -> bool:
    return user in REVIEWERS
