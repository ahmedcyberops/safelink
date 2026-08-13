"""Health check API."""

from fastapi import APIRouter

from app.core.config import get_settings
from app.core.redis_client import get_redis
from app.schemas.scan import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health_check():
    settings = get_settings()
    services = {"api": "healthy"}

    try:
        redis = await get_redis()
        await redis.ping()
        services["redis"] = "healthy"
    except Exception:
        services["redis"] = "unavailable"

    try:
        from app.core.database import engine
        async with engine.connect() as conn:
            await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        services["database"] = "healthy"
    except Exception:
        services["database"] = "unavailable"

    overall = "healthy" if all(v == "healthy" for v in services.values()) else "degraded"
    return HealthResponse(status=overall, version=settings.app_version, services=services)
