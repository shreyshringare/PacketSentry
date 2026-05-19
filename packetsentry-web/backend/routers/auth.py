# packetsentry-web/backend/routers/auth.py
"""Auth endpoints: login, demo token, whoami."""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address

from auth import create_access_token, hash_password, verify_password
from audit import log_event
from dependencies import get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])
limiter = Limiter(key_func=get_remote_address)

# Admin credentials from environment
_ADMIN_PASSWORD_HASH: str = ""


def set_admin_password(plain: str) -> None:
    """Called at startup to hash and store the admin password."""
    global _ADMIN_PASSWORD_HASH
    _ADMIN_PASSWORD_HASH = hash_password(plain)


class LoginRequest(BaseModel):
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
def login(request: Request, body: LoginRequest) -> TokenResponse:
    """Admin login. Password from PACKETSENTRY_ADMIN_PASSWORD env var."""
    if not _ADMIN_PASSWORD_HASH:
        raise HTTPException(status_code=500, detail="Auth not configured")
    if not verify_password(body.password, _ADMIN_PASSWORD_HASH):
        log_event("login_fail", request.client.host if request.client else None, False, "bad password")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
        )
    log_event("login_success", request.client.host if request.client else None, True)
    token = create_access_token(sub="admin", role="admin")
    return TokenResponse(access_token=token, role="admin")


@router.get("/demo-token", response_model=TokenResponse)
@limiter.limit("30/minute")
def demo_token(request: Request) -> TokenResponse:
    """Issue a read-only demo JWT (no password required)."""
    log_event("demo_token", request.client.host if request.client else None, True)
    token = create_access_token(sub="demo", role="demo")
    return TokenResponse(access_token=token, role="demo")


@router.get("/me")
def whoami(user: dict = Depends(get_current_user)) -> dict:
    """Return current user info from JWT."""
    return {"sub": user["sub"], "role": user["role"]}
