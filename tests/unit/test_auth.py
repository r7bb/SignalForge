"""Passwords, tokens, roles and tenancy."""

from __future__ import annotations

import time

import pytest
from signalforge.auth import (
    AuthError,
    AuthService,
    Principal,
    create_token,
    decode_token,
    hash_password,
    needs_rehash,
    role_allows,
    verify_password,
)
from signalforge.auth.security import TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH


# ------------------------------------------------------------- passwords -----
def test_hash_is_salted_and_verifies() -> None:
    first = hash_password("correct horse battery staple")
    second = hash_password("correct horse battery staple")
    assert first != second, "each hash carries its own salt"
    assert verify_password("correct horse battery staple", first)
    assert not verify_password("wrong password", first)


def test_hash_format_is_self_describing() -> None:
    encoded = hash_password("hunter2", iterations=1000)
    prefix, iterations, salt, digest = encoded.split("$")
    assert prefix == "pbkdf2_sha256"
    assert int(iterations) == 1000
    assert salt and digest
    assert needs_rehash(encoded) is True  # below the current cost
    assert needs_rehash(hash_password("hunter2")) is False


def test_garbage_hash_does_not_verify() -> None:
    assert not verify_password("anything", "not-a-hash")
    assert not verify_password("anything", "pbkdf2_sha256$abc$def$ghi")


def test_empty_password_is_refused() -> None:
    with pytest.raises(AuthError):
        hash_password("")


# ---------------------------------------------------------------- tokens -----
def test_round_trip(settings) -> None:
    token = create_token(
        user_id="u1",
        email="analyst@acme.io",
        tenant="acme",
        role="analyst",
        settings=settings,
    )
    principal = decode_token(token, settings=settings)
    assert principal.user_id == "u1"
    assert principal.tenant == "acme"
    assert principal.role == "analyst"
    assert principal.token_type == TOKEN_TYPE_ACCESS


def test_token_type_is_enforced(settings) -> None:
    refresh = create_token(
        user_id="u1",
        email="a@b.c",
        tenant="acme",
        token_type=TOKEN_TYPE_REFRESH,
        settings=settings,
    )
    # A refresh token must not be usable as an access token.
    with pytest.raises(AuthError):
        decode_token(refresh, settings=settings, expected_type=TOKEN_TYPE_ACCESS)
    assert (
        decode_token(refresh, settings=settings, expected_type=TOKEN_TYPE_REFRESH).user_id == "u1"
    )


def test_expired_token_is_rejected(settings) -> None:
    token = create_token(
        user_id="u1", email="a@b.c", tenant="acme", settings=settings, ttl_seconds=-1
    )
    with pytest.raises(AuthError):
        decode_token(token, settings=settings)


def test_token_signed_with_another_secret_is_rejected(settings) -> None:
    token = create_token(user_id="u1", email="a@b.c", tenant="acme", settings=settings)
    forged = settings.model_copy(update={"jwt_secret": "a-different-secret"})
    with pytest.raises(AuthError):
        decode_token(token, settings=forged)


def test_malformed_token_is_rejected(settings) -> None:
    with pytest.raises(AuthError):
        decode_token("not.a.jwt", settings=settings)


# ------------------------------------------------------------------ roles ----
@pytest.mark.parametrize(
    ("role", "required", "allowed"),
    [
        ("admin", "responder", True),
        ("responder", "analyst", True),
        ("analyst", "viewer", True),
        ("viewer", "analyst", False),
        ("analyst", "responder", False),
        ("responder", "admin", False),
        ("nonsense", "viewer", False),
    ],
)
def test_role_hierarchy(role: str, required: str, allowed: bool) -> None:
    assert role_allows(role, required) is allowed
    principal = Principal(user_id="u", email="a@b.c", tenant="acme", role=role)
    assert principal.has_role(required) is allowed
    if not allowed:
        with pytest.raises(AuthError):
            principal.require_role(required)


# ---------------------------------------------------------------- service ----
@pytest.fixture
def auth(session_factory, settings) -> AuthService:
    return AuthService(session_factory, settings)


def test_bootstrap_is_idempotent(auth: AuthService) -> None:
    first = auth.bootstrap()
    assert first["created"] is True
    assert auth.bootstrap()["created"] is False


def test_authenticate_issues_a_pair(auth: AuthService) -> None:
    auth.ensure_tenant("acme")
    auth.create_user(tenant="acme", email="analyst@acme.io", password="s3cret", role="analyst")
    session = auth.authenticate(tenant="acme", email="analyst@acme.io", password="s3cret")
    assert session["access_token"] and session["refresh_token"]
    assert session["user"]["role"] == "analyst"
    assert "password_hash" not in session["user"]

    principal = auth.principal_from_token(session["access_token"])
    assert principal.email == "analyst@acme.io"


def test_authentication_failures(auth: AuthService) -> None:
    auth.create_user(tenant="acme", email="analyst@acme.io", password="s3cret")
    with pytest.raises(AuthError):
        auth.authenticate(tenant="acme", email="analyst@acme.io", password="wrong")
    with pytest.raises(AuthError):
        auth.authenticate(tenant="acme", email="nobody@acme.io", password="s3cret")
    with pytest.raises(AuthError):
        auth.authenticate(tenant="globex", email="analyst@acme.io", password="s3cret")


def test_same_email_in_two_tenants_is_allowed(auth: AuthService) -> None:
    auth.create_user(tenant="acme", email="shared@example.com", password="one")
    auth.create_user(tenant="globex", email="shared@example.com", password="two")
    acme = auth.authenticate(tenant="acme", email="shared@example.com", password="one")
    globex = auth.authenticate(tenant="globex", email="shared@example.com", password="two")
    assert acme["user"]["tenant"] == "acme"
    assert globex["user"]["tenant"] == "globex"
    assert acme["user"]["id"] != globex["user"]["id"]


def test_duplicate_user_in_one_tenant_is_refused(auth: AuthService) -> None:
    auth.create_user(tenant="acme", email="analyst@acme.io", password="one")
    with pytest.raises(AuthError):
        auth.create_user(tenant="acme", email="analyst@acme.io", password="two")


def test_invalid_role_is_refused(auth: AuthService) -> None:
    with pytest.raises(AuthError):
        auth.create_user(tenant="acme", email="x@acme.io", password="p", role="wizard")


def test_role_change_is_reflected_in_new_tokens(auth: AuthService) -> None:
    auth.create_user(tenant="acme", email="analyst@acme.io", password="s3cret", role="analyst")
    auth.set_role(tenant="acme", email="analyst@acme.io", role="responder", actor="admin@acme.io")
    session = auth.authenticate(tenant="acme", email="analyst@acme.io", password="s3cret")
    assert auth.principal_from_token(session["access_token"]).role == "responder"


def test_refresh_returns_a_fresh_access_token(auth: AuthService) -> None:
    auth.create_user(tenant="acme", email="analyst@acme.io", password="s3cret")
    session = auth.authenticate(tenant="acme", email="analyst@acme.io", password="s3cret")
    time.sleep(0.01)
    refreshed = auth.refresh(session["refresh_token"])
    assert refreshed["access_token"]
    assert auth.principal_from_token(refreshed["access_token"]).tenant == "acme"


def test_list_users_is_tenant_scoped(auth: AuthService) -> None:
    auth.create_user(tenant="acme", email="a@acme.io", password="p")
    auth.create_user(tenant="globex", email="b@globex.io", password="p")
    assert [user["email"] for user in auth.list_users("acme")] == ["a@acme.io"]
    assert auth.list_users("nonexistent") == []
