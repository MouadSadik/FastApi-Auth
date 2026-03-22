from pydantic import BaseModel, EmailStr


# ── Responses
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ── Internal
class TokenData(BaseModel):
    username: str | None = None


# ── Requests
class RegisterRequest(BaseModel):
    username: str
    email: str
    full_name: str | None = None
    password: str