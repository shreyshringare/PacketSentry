# packetsentry-web/backend/tests/test_auth.py
import pytest
from auth import create_access_token, verify_password, hash_password, decode_token


def test_hash_and_verify_password():
    hashed = hash_password("secret123")
    assert verify_password("secret123", hashed)
    assert not verify_password("wrong", hashed)


def test_create_and_decode_token():
    token = create_access_token(sub="admin", role="admin")
    payload = decode_token(token)
    assert payload["sub"] == "admin"
    assert payload["role"] == "admin"


def test_demo_token_has_demo_role():
    token = create_access_token(sub="demo", role="demo")
    payload = decode_token(token)
    assert payload["role"] == "demo"


def test_invalid_token_returns_none():
    result = decode_token("not.a.valid.token")
    assert result is None
