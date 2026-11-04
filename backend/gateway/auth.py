"""Authentication: API keys (X-API-Key) or HS256 JWT bearer tokens.

JWT claims used: sub (user id), role, tenant, permissions (optional list), exp.
Unauthenticated requests are rejected: there is no anonymous access.
"""
from __future__ import annotations

import hmac
import threading
import time
from collections import deque

import jwt
from fastapi import Depends, Header, HTTPException, status

from .config import get_settings
from .models import Principal
from .policy.engine import can_approve, load_policy


def authenticate(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)) -> Principal:
    s = get_settings()
    if x_api_key:
        for key, ident in s.api_keys.items():
            if hmac.compare_digest(key, x_api_key):
                return _rate_limited(Principal(**ident, auth_method="api_key"))
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid API key")
    if authorization and authorization.lower().startswith("bearer "):
        if not s.jwt_secret:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "JWT auth is not enabled")
        try:
            claims = jwt.decode(authorization[7:], s.jwt_secret, algorithms=[s.jwt_algorithm], options={"require": ["sub", "exp"]})
        except jwt.PyJWTError as e:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"invalid token: {e}") from e
        role = claims.get("role", "employee")
        if role not in load_policy()["roles"]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"unknown role '{role}'")
        # By default the role alone decides permissions; a token cannot grant itself extras.
        extra = [x for x in claims.get("permissions", []) if x != "*"] if s.jwt_trust_permissions else []
        return _rate_limited(Principal(user_id=claims["sub"], role=role, tenant=claims.get("tenant", "default"),
                                       permissions=extra, auth_method="jwt"))
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing credentials (X-API-Key or Bearer token)")


_hits: dict[str, deque] = {}
_hits_lock = threading.Lock()


def _rate_limited(p: Principal) -> Principal:
    """Sliding one-minute window per principal (in memory; use Redis with several replicas)."""
    limit = get_settings().rate_limit_per_min
    if limit <= 0:
        return p
    key, now = f"{p.tenant}/{p.user_id}", time.monotonic()
    with _hits_lock:
        q = _hits.setdefault(key, deque())
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= limit:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, f"rate limit: {limit} requests per minute",
                                headers={"Retry-After": "60"})
        q.append(now)
    return p


def reset_rate_limits() -> None:
    with _hits_lock:
        _hits.clear()


def require_approver(p: Principal = Depends(authenticate)) -> Principal:
    if not can_approve(p):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "approver role required")
    return p
