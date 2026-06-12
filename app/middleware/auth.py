"""Auth dependency — extracts user identity from BFF-forwarded headers.

The Express BFF authenticates users via SSO/LDAP and forwards identity
in X-User-* headers. FastAPI trusts these headers since only the BFF
can reach the backend on the internal network.
"""

from dataclasses import dataclass

from fastapi import Request


@dataclass
class CurrentUser:
    user_id: str
    user_email: str
    user_team: str


def get_current_user(request: Request) -> CurrentUser:
    """FastAPI dependency — extract user from request headers."""
    return CurrentUser(
        user_id=request.headers.get("X-User-Id", "anonymous"),
        user_email=request.headers.get("X-User-Email", ""),
        user_team=request.headers.get("X-User-Team", ""),
    )
