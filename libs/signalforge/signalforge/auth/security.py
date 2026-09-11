"""Password hashing and JWT issue/verify.

Passwords use PBKDF2-HMAC-SHA256 from the standard library with a per-password
salt and a stored iteration count, so the format can be upgraded without
invalidating existing hashes and there is no native dependency to install.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import jwt

from ..config import Settings, get_settings

PBKDF2_ITERATIONS = 260_000
HASH_PREFIX = "pbkdf2_sha256"

TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_REFRESH = "refresh"

#: Role -> the roles it implies.  Checked by :func:`role_allows`.
ROLE_HIERARCHY: Dict[str, int] = {
    "viewer": 10,
    "analyst": 20,
    "responder": 30,
    "admin": 40,
}


class AuthError(Exception):
    """Authentication or authorization failure."""


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #
def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    if not password:
        raise AuthError("password cannot be empty")
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "%s$%d$%s$%s" % (
        HASH_PREFIX,
        iterations,
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode(),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        prefix, iterations, salt_b64, digest_b64 = encoded.split("$")
        if prefix != HASH_PREFIX:
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, expected)


def needs_rehash(encoded: str, *, iterations: int = PBKDF2_ITERATIONS) -> bool:
    try:
        _, stored_iterations, _, _ = encoded.split("$")
        return int(stored_iterations) < iterations
    except ValueError:
        return True


def generate_password(length: int = 20) -> str:
    return secrets.token_urlsafe(length)


# --------------------------------------------------------------------------- #
# Tokens
# --------------------------------------------------------------------------- #
@dataclass
class Principal:
    """The authenticated caller, as reconstructed from a token."""

    user_id: str
    email: str
    tenant: str
    role: str = "analyst"
    scopes: List[str] = None  # type: ignore[assignment]
    token_type: str = TOKEN_TYPE_ACCESS
    jti: Optional[str] = None
    expires_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if self.scopes is None:
            self.scopes = []

    def has_role(self, required: str) -> bool:
        return role_allows(self.role, required)

    def require_role(self, required: str) -> None:
        if not self.has_role(required):
            raise AuthError("role %r is not sufficient (requires %r)" % (self.role, required))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "email": self.email,
            "tenant": self.tenant,
            "role": self.role,
            "scopes": list(self.scopes),
        }


def role_allows(role: str, required: str) -> bool:
    return ROLE_HIERARCHY.get(role, 0) >= ROLE_HIERARCHY.get(required, 99)


def create_token(
    *,
    user_id: str,
    email: str,
    tenant: str,
    role: str = "analyst",
    scopes: Optional[List[str]] = None,
    token_type: str = TOKEN_TYPE_ACCESS,
    settings: Optional[Settings] = None,
    ttl_seconds: Optional[int] = None,
) -> str:
    settings = settings or get_settings()
    ttl = ttl_seconds or (
        settings.access_token_ttl_seconds
        if token_type == TOKEN_TYPE_ACCESS
        else settings.refresh_token_ttl_seconds
    )
    issued_at = int(time.time())
    payload = {
        "sub": user_id,
        "email": email,
        "tenant": tenant,
        "role": role,
        "scopes": scopes or [],
        "typ": token_type,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": issued_at + ttl,
        "jti": str(uuid.uuid4()),
        "iss": "signalforge",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(
    token: str,
    *,
    settings: Optional[Settings] = None,
    expected_type: Optional[str] = TOKEN_TYPE_ACCESS,
) -> Principal:
    settings = settings or get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            issuer="signalforge",
            options={"require": ["exp", "sub", "tenant"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("invalid token: %s" % exc) from exc

    token_type = payload.get("typ", TOKEN_TYPE_ACCESS)
    if expected_type and token_type != expected_type:
        raise AuthError("expected a %s token, got %s" % (expected_type, token_type))
    return Principal(
        user_id=str(payload["sub"]),
        email=str(payload.get("email") or ""),
        tenant=str(payload["tenant"]),
        role=str(payload.get("role") or "analyst"),
        scopes=list(payload.get("scopes") or []),
        token_type=token_type,
        jti=payload.get("jti"),
        expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
    )
