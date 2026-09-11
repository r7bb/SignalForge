"""Authentication, tenancy and role-based access control."""

from .security import (
    ROLE_HIERARCHY,
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_REFRESH,
    AuthError,
    Principal,
    create_token,
    decode_token,
    generate_password,
    hash_password,
    needs_rehash,
    role_allows,
    verify_password,
)
from .service import VALID_ROLES, AuthService

__all__ = [
    "ROLE_HIERARCHY",
    "TOKEN_TYPE_ACCESS",
    "TOKEN_TYPE_REFRESH",
    "VALID_ROLES",
    "AuthError",
    "AuthService",
    "Principal",
    "create_token",
    "decode_token",
    "generate_password",
    "hash_password",
    "needs_rehash",
    "role_allows",
    "verify_password",
]
