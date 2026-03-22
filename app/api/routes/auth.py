from typing import Annotated
from datetime import timedelta

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from fastapi.security import OAuth2PasswordRequestForm

from app.core.security import (
    create_access_token,
    revoke_access_token,
    revoke_refresh_token,
    rotate_refresh_token,
    verify_refresh_token,
)
from app.core.config import settings
from app.models.user import db_create_user, db_get_user
from app.schemas.auth import RegisterRequest, Token
from app.schemas.user import User
from app.services.auth import (
    InvalidCredentialsError,
    get_current_user,
    login_user,
    oauth2_scheme,
)

router = APIRouter(prefix="/auth", tags=["auth"])

COOKIE_MAX_AGE = 60 * 60 * 24 * settings.REFRESH_TOKEN_EXPIRE_DAYS

_COOKIE_KWARGS = dict(
    key="refresh_token",
    httponly=True,
    secure=True,
    samesite="lax",
    path="/",
)


# ── Register
@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=User)
async def register(body: RegisterRequest):
    if db_get_user(body.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )
    record = db_create_user(
        username=body.username,
        email=body.email,
        password=body.password,
        full_name=body.full_name,
    )
    return User(**record)


# ── Login
@router.post("/login", response_model=Token)
async def login(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
):
    try:
        access_token, refresh_token = login_user(
            form_data.username, form_data.password
        )
    except InvalidCredentialsError:  # specific, not bare Exception
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    response.set_cookie(
        value=refresh_token,
        max_age=COOKIE_MAX_AGE,
        **_COOKIE_KWARGS,
    )
    return Token(access_token=access_token, token_type="bearer")


# ── Refresh
@router.post("/refresh", response_model=Token)
async def refresh(
    response: Response,
    refresh_token: Annotated[str | None, Cookie()] = None,
):
    if refresh_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing",
        )

    # verify_refresh_token raises 401 on failure
    username = verify_refresh_token(refresh_token)

    record = db_get_user(username)
    if record is None or record.get("disabled"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    new_refresh_token = rotate_refresh_token(refresh_token, username)

    access_token = create_access_token(
        data={"sub": username},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    response.set_cookie(
        value=new_refresh_token,
        max_age=COOKIE_MAX_AGE,
        **_COOKIE_KWARGS,
    )
    return Token(access_token=access_token, token_type="bearer")


# ── Logout 
@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    response: Response,
    token: Annotated[str, Depends(oauth2_scheme)],  # access token
    refresh_token: Annotated[str | None, Cookie()] = None,
):
    # Revoke both tokens
    revoke_access_token(token)
    if refresh_token:
        revoke_refresh_token(refresh_token)

    response.delete_cookie(**_COOKIE_KWARGS)