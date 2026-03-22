from fastapi import FastAPI

from app.api.routes import auth
from app.api.routes import users
from app.core.config import settings
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(
    title="FastAPI Auth",
    version="1.0.0",
    docs_url="/docs" if settings.APP_ENV == "development" else None,
    redoc_url="/redoc" if settings.APP_ENV == "development" else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[""],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(users.router)


@app.get("/health", tags=["health"])
async def health():
    return {"status": "ok"}