"""SafeLink API - URL Security Scanner."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.health import router as health_router
from app.api.scan import router as scan_router
from app.core.config import get_settings
from app.core.database import engine
from app.core.logging import setup_logging
from app.core.redis_client import close_redis
from app.models.scan import Base


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    setup_logging(settings.debug)

    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield
    await close_redis()
    await engine.dispose()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        return response


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="SafeLink API",
        description="Defensive URL security scanner API",
        version=settings.app_version,
        lifespan=lifespan,
        docs_url="/api/docs" if settings.debug else None,
        redoc_url=None,
    )

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
        max_age=3600,
    )

    app.include_router(health_router, prefix="/api/v1")
    app.include_router(scan_router, prefix="/api/v1")

    return app


app = create_app()
