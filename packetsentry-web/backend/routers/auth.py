# packetsentry-web/backend/routers/auth.py
"""Auth endpoints: login, demo token, whoami."""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from auth import create_access_token, hash_password, verify_password
from dependencies import get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])

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
def login(body: LoginRequest) -> TokenResponse:
    """Admin login. Password from PACKETSENTRY_ADMIN_PASSWORD env var."""
    if not _ADMIN_PASSWORD_HASH:
        raise HTTPException(status_code=500, detail="Auth not configured")
    if not verify_password(body.password, _ADMIN_PASSWORD_HASH):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
        )
    token = create_access_token(sub="admin", role="admin")
    return TokenResponse(access_token=token, role="admin")


@router.get("/demo-token", response_model=TokenResponse)
def demo_token() -> TokenResponse:
    """Issue a read-only demo JWT (no password required)."""
    token = create_access_token(sub="demo", role="demo")
    return TokenResponse(access_token=token, role="demo")


@router.get("/me")
def whoami(user: dict = Depends(get_current_user)) -> dict:
    """Return current user info from JWT."""
    return {"sub": user["sub"], "role": user["role"]}
