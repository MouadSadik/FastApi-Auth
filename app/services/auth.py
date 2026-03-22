from datetime import timedelta

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import InvalidTokenError
from typing import Annotated
import jwt

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    is_access_token_revoked,
)
from app.models.user import db_authenticate, db_get_user
from app.schemas.user import User


# ── Custom exceptions (keep HTTP concerns out of service layer) 
class InvalidCredentialsError(Exception):
    pass


# ── OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")  # fixed: was "login"


# ── Login
def login_user(username: str, password: str) -> tuple[str, str]:
    """
    Authenticates credentials and returns (access_token, refresh_token).
    Raises InvalidCredentialsError on failure — NOT HTTPException.
    """
    user = db_authenticate(username, password)
    if not user:
        raise InvalidCredentialsError()

    access_token = create_access_token(
        data={"sub": user["username"]},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    refresh_token = create_refresh_token(user["username"])
    return access_token, refresh_token


# ── Dependencies
async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Check blacklist first (covers logged-out tokens)
    if is_access_token_revoked(token):
        raise credentials_exception

    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        username: str | None = payload.get("sub")
        if username is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception

    record = db_get_user(username)
    if record is None:
        raise credentials_exception

    return User(**record)


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    if current_user.disabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )
    return current_user