from datetime import datetime, timedelta, timezone

import jwt
from fastapi import HTTPException, status
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash

from app.core.config import settings

# ── Password hashing ──────────────────────────────────────────────────────────
password_hash = PasswordHash.recommended()
DUMMY_HASH = password_hash.hash("dummypassword")


def verify_password(plain: str, hashed: str) -> bool:
    return password_hash.verify(plain, hashed)


def get_password_hash(plain: str) -> str:
    return password_hash.hash(plain)


# ── Access token ──────────────────────────────────────────────────────────────
def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=15)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


# ── Access token blacklist (in-memory) ───────────────────────────────────────
# In production replace with Redis using TTL = ACCESS_TOKEN_EXPIRE_MINUTES
_access_token_blacklist: set[str] = set()


def revoke_access_token(token: str) -> None:
    _access_token_blacklist.add(token)


def is_access_token_revoked(token: str) -> bool:
    return token in _access_token_blacklist


# ── Refresh token store (in-memory) ──────────────────────────────────────────
# In production replace with Redis: { token: username }
_refresh_store: dict[str, str] = {}


def create_refresh_token(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    payload = {"sub": username, "type": "refresh", "exp": expire}
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    _refresh_store[token] = username
    return token


def verify_refresh_token(token: str) -> str:
    """Returns username or raises 401."""
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if token not in _refresh_store:
        raise exc
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        if payload.get("type") != "refresh":
            raise exc
        username: str | None = payload.get("sub")
        if username is None:
            raise exc
        return username
    except InvalidTokenError:
        _refresh_store.pop(token, None)
        raise exc


def revoke_refresh_token(token: str) -> None:
    _refresh_store.pop(token, None)


def rotate_refresh_token(old_token: str, username: str) -> str:
    """Revoke old refresh token and issue a new one."""
    revoke_refresh_token(old_token)
    return create_refresh_token(username)


def purge_expired_tokens() -> None:
    """
    Remove expired tokens from both stores.
    Call periodically (e.g. via APScheduler or a background task).
    """
    now = datetime.now(timezone.utc).timestamp()

    expired_refresh = [
    t for t in list(_refresh_store)
    if try_decode_exp(t) < now 
    ]
    
    for t in expired_refresh:
        _refresh_store.pop(t, None)

    expired_access = [
        t for t in list(_access_token_blacklist)
        if try_decode_exp(t) < now
    ]
    for t in expired_access:
        _access_token_blacklist.discard(t)


def try_decode_exp(token: str) -> float:
    """Returns token exp timestamp, or 0 if undecodable."""
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
        return float(payload.get("exp", 0))
    except Exception:
        return 0