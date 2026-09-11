"""FastAPI dependencies: state access, authentication and tenant scoping."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordBearer
from signalforge.auth import AuthError, Principal
from signalforge.config import Settings

from .state import AppState

bearer_scheme = HTTPBearer(auto_error=False, description="SignalForge access token")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)


def get_state(request: Request) -> AppState:
    state: Optional[AppState] = getattr(request.app.state, "sf", None)
    if state is None:  # pragma: no cover - only if startup failed
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="application state is not initialised",
        )
    return state


def get_settings_dep(state: AppState = Depends(get_state)) -> Settings:
    return state.settings


def current_principal(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    token: Optional[str] = Depends(oauth2_scheme),
    state: AppState = Depends(get_state),
) -> Principal:
    """Resolve the caller from a bearer token."""
    raw = credentials.credentials if credentials else token
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return state.auth.principal_from_token(raw)
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def require_role(required: str) -> Any:
    """Dependency factory enforcing the role hierarchy."""

    def _dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if not principal.has_role(required):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="role %r is not permitted to perform this action (requires %r)"
                % (principal.role, required),
            )
        return principal

    return _dependency


require_viewer = require_role("viewer")
require_analyst = require_role("analyst")
require_responder = require_role("responder")
require_admin = require_role("admin")


def tenant_scope(
    tenant: Optional[str] = None,
    principal: Principal = Depends(current_principal),
) -> str:
    """The tenant a request may read.

    Callers normally omit ``tenant`` and get their own.  Asking for another
    tenant is a 403 - there is no cross-tenant read, including for admins,
    because an admin is an admin *of one tenant*.
    """
    if tenant and tenant != principal.tenant:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="not permitted to access tenant %r" % tenant,
        )
    return principal.tenant
