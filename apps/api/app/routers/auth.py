"""Sign-in, token refresh and user administration."""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Form
from fastapi.security import OAuth2PasswordRequestForm
from signalforge.auth import Principal

from ..deps import current_principal, get_state, require_admin
from ..schemas import CreateUserRequest, LoginRequest, RefreshRequest, TokenResponse
from ..state import AppState

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, state: AppState = Depends(get_state)) -> Dict[str, Any]:
    tenant = payload.tenant or state.settings.bootstrap_tenant
    return state.auth.authenticate(tenant=tenant, email=payload.email, password=payload.password)


@router.post("/token", response_model=TokenResponse, include_in_schema=False)
async def token(
    form: OAuth2PasswordRequestForm = Depends(),
    tenant: str = Form(default=""),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """OAuth2 password flow, so the generated docs have a working Authorize button."""
    return state.auth.authenticate(
        tenant=tenant or state.settings.bootstrap_tenant,
        email=form.username,
        password=form.password,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(payload: RefreshRequest, state: AppState = Depends(get_state)) -> Dict[str, Any]:
    return state.auth.refresh(payload.refresh_token)


@router.get("/me")
async def me(principal: Principal = Depends(current_principal)) -> Dict[str, Any]:
    return principal.to_dict()


@router.get("/users")
async def list_users(
    principal: Principal = Depends(require_admin),
    state: AppState = Depends(get_state),
) -> List[Dict[str, Any]]:
    return state.auth.list_users(principal.tenant)


@router.post("/users", status_code=201)
async def create_user(
    payload: CreateUserRequest,
    principal: Principal = Depends(require_admin),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    return state.auth.create_user(
        tenant=principal.tenant,
        email=payload.email,
        password=payload.password,
        role=payload.role,
        full_name=payload.full_name,
        actor=principal.email,
    )


@router.post("/users/{email}/role")
async def set_role(
    email: str,
    role: str,
    principal: Principal = Depends(require_admin),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    return state.auth.set_role(
        tenant=principal.tenant, email=email, role=role, actor=principal.email
    )
