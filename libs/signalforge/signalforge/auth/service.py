"""User and tenant management, sign-in and token refresh."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select

from ..config import Settings, get_settings
from ..storage import db as dbm
from .security import (
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_REFRESH,
    AuthError,
    Principal,
    create_token,
    decode_token,
    hash_password,
    needs_rehash,
    verify_password,
)

log = logging.getLogger("signalforge.auth")

VALID_ROLES = ("viewer", "analyst", "responder", "admin")


class AuthService:
    def __init__(self, session_factory: Any, settings: Optional[Settings] = None) -> None:
        self.session_factory = session_factory
        self.settings = settings or get_settings()

    # ------------------------------------------------------------------ #
    # Tenants and users
    # ------------------------------------------------------------------ #
    def ensure_tenant(self, key: str, name: Optional[str] = None) -> Dict[str, Any]:
        with self.session_factory() as session:
            row = session.scalars(select(dbm.Tenant).where(dbm.Tenant.key == key)).first()
            if row is None:
                row = dbm.Tenant(key=key, name=name or key.title())
                session.add(row)
                dbm.record_audit(
                    session,
                    tenant=key,
                    actor="system",
                    action="tenant.created",
                    entity_type="tenant",
                    entity_id=row.id,
                    detail=row.name,
                )
                session.commit()
            return {"id": row.id, "key": row.key, "name": row.name}

    def create_user(
        self,
        *,
        tenant: str,
        email: str,
        password: str,
        role: str = "analyst",
        full_name: Optional[str] = None,
        actor: str = "system",
    ) -> Dict[str, Any]:
        if role not in VALID_ROLES:
            raise AuthError("invalid role %r (expected one of %s)" % (role, ", ".join(VALID_ROLES)))
        tenant_row = self.ensure_tenant(tenant)
        with self.session_factory() as session:
            existing = session.scalars(
                select(dbm.User).where(
                    dbm.User.tenant_id == tenant_row["id"],
                    dbm.User.email == email.lower(),
                )
            ).first()
            if existing is not None:
                raise AuthError("user %s already exists in tenant %s" % (email, tenant))
            row = dbm.User(
                tenant_id=tenant_row["id"],
                email=email.lower(),
                full_name=full_name,
                password_hash=hash_password(password),
                role=role,
            )
            session.add(row)
            dbm.record_audit(
                session,
                tenant=tenant,
                actor=actor,
                action="user.created",
                entity_type="user",
                entity_id=row.id,
                detail=email,
                role=role,
            )
            session.commit()
            return _user_dict(row, tenant)

    def set_role(self, *, tenant: str, email: str, role: str, actor: str) -> Dict[str, Any]:
        if role not in VALID_ROLES:
            raise AuthError("invalid role %r" % role)
        with self.session_factory() as session:
            row = self._find_user(session, tenant, email)
            previous = row.role
            row.role = role
            dbm.record_audit(
                session,
                tenant=tenant,
                actor=actor,
                action="user.role_changed",
                entity_type="user",
                entity_id=row.id,
                detail="%s -> %s" % (previous, role),
            )
            session.commit()
            return _user_dict(row, tenant)

    def list_users(self, tenant: str) -> List[Dict[str, Any]]:
        with self.session_factory() as session:
            tenant_row = session.scalars(select(dbm.Tenant).where(dbm.Tenant.key == tenant)).first()
            if tenant_row is None:
                return []
            rows = session.scalars(
                select(dbm.User).where(dbm.User.tenant_id == tenant_row.id)
            ).all()
            return [_user_dict(row, tenant) for row in rows]

    # ------------------------------------------------------------------ #
    # Sign-in
    # ------------------------------------------------------------------ #
    def authenticate(self, *, tenant: str, email: str, password: str) -> Dict[str, Any]:
        with self.session_factory() as session:
            try:
                row = self._find_user(session, tenant, email)
            except AuthError:
                # Same error and roughly the same work either way, so a caller
                # cannot enumerate accounts from the response.
                verify_password(password, hash_password("decoy-comparison"))
                # Deliberately not chained: the caller must not learn which half failed.
                raise AuthError("invalid credentials") from None
            if not row.is_active:
                raise AuthError("account is disabled")
            if not verify_password(password, row.password_hash):
                dbm.record_audit(
                    session,
                    tenant=tenant,
                    actor=email,
                    action="auth.failed",
                    entity_type="user",
                    entity_id=row.id,
                )
                session.commit()
                raise AuthError("invalid credentials")
            if needs_rehash(row.password_hash):
                row.password_hash = hash_password(password)
            row.last_login_at = datetime.now(tz=timezone.utc)
            dbm.record_audit(
                session,
                tenant=tenant,
                actor=email,
                action="auth.succeeded",
                entity_type="user",
                entity_id=row.id,
                role=row.role,
            )
            session.commit()
            user = _user_dict(row, tenant)

        return self._issue(user)

    def refresh(self, refresh_token: str) -> Dict[str, Any]:
        principal = decode_token(
            refresh_token, settings=self.settings, expected_type=TOKEN_TYPE_REFRESH
        )
        with self.session_factory() as session:
            row = session.get(dbm.User, principal.user_id)
            if row is None or not row.is_active:
                raise AuthError("user is no longer active")
            user = _user_dict(row, principal.tenant)
        return self._issue(user)

    def _issue(self, user: Dict[str, Any]) -> Dict[str, Any]:
        common = {
            "user_id": user["id"],
            "email": user["email"],
            "tenant": user["tenant"],
            "role": user["role"],
            "settings": self.settings,
        }
        return {
            "access_token": create_token(token_type=TOKEN_TYPE_ACCESS, **common),
            "refresh_token": create_token(token_type=TOKEN_TYPE_REFRESH, **common),
            "token_type": "bearer",
            "expires_in": self.settings.access_token_ttl_seconds,
            "user": {key: value for key, value in user.items() if key != "password_hash"},
        }

    def principal_from_token(self, token: str) -> Principal:
        return decode_token(token, settings=self.settings, expected_type=TOKEN_TYPE_ACCESS)

    # ------------------------------------------------------------------ #
    def bootstrap(self) -> Dict[str, Any]:
        """Create the configured tenant and admin if they do not exist yet."""
        tenant = self.settings.bootstrap_tenant
        self.ensure_tenant(tenant, tenant.title())
        email = self.settings.bootstrap_admin_email
        with self.session_factory() as session:
            tenant_row = session.scalars(select(dbm.Tenant).where(dbm.Tenant.key == tenant)).first()
            existing = session.scalars(
                select(dbm.User).where(
                    dbm.User.tenant_id == tenant_row.id, dbm.User.email == email.lower()
                )
            ).first()
        if existing is not None:
            return {"tenant": tenant, "admin": email, "created": False}
        self.create_user(
            tenant=tenant,
            email=email,
            password=self.settings.bootstrap_admin_password,
            role="admin",
            full_name="Bootstrap Administrator",
            actor="bootstrap",
        )
        if self.settings.bootstrap_admin_password == "signalforge":
            log.warning(
                "bootstrap admin is using the default password - change it before exposing "
                "this instance",
                extra={"email": email},
            )
        return {"tenant": tenant, "admin": email, "created": True}

    # ------------------------------------------------------------------ #
    @staticmethod
    def _find_user(session: Any, tenant: str, email: str) -> dbm.User:
        tenant_row = session.scalars(select(dbm.Tenant).where(dbm.Tenant.key == tenant)).first()
        if tenant_row is None:
            raise AuthError("unknown tenant %r" % tenant)
        row = session.scalars(
            select(dbm.User).where(
                dbm.User.tenant_id == tenant_row.id, dbm.User.email == email.lower()
            )
        ).first()
        if row is None:
            raise AuthError("unknown user %r" % email)
        return row


def _user_dict(row: dbm.User, tenant: str) -> Dict[str, Any]:
    return {
        "id": row.id,
        "email": row.email,
        "full_name": row.full_name,
        "role": row.role,
        "tenant": tenant,
        "is_active": row.is_active,
        "last_login_at": row.last_login_at,
    }
