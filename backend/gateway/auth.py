"""Authentication: API keys (X-API-Key) or HS256 JWT bearer tokens.

JWT claims used: sub (user id), role, tenant, permissions (optional list), exp.
Unauthenticated requests are rejected: there is no anonymous access.
"""
from __future__ import annotations

import hmac

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
                return Principal(**ident, auth_method="api_key")
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
        return Principal(user_id=claims["sub"], role=role, tenant=claims.get("tenant", "default"),
                         permissions=list(claims.get("permissions", [])), auth_method="jwt")
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing credentials (X-API-Key or Bearer token)")


def require_approver(p: Principal = Depends(authenticate)) -> Principal:
    if not can_approve(p):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "approver role required")
    return p
