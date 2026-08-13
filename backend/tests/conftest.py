"""Test configuration and fixtures."""

import os
import pytest
from unittest.mock import AsyncMock, patch

# Set test environment before imports
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test.db"
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("REPUTATION_PROVIDER", "mock")


@pytest.fixture(autouse=True)
def mock_redis():
    """Mock Redis for all tests."""
    mock_redis_instance = AsyncMock()
    mock_redis_instance.ping = AsyncMock(return_value=True)
    mock_redis_instance.incr = AsyncMock(return_value=1)
    mock_redis_instance.expire = AsyncMock(return_value=True)
    mock_redis_instance.pipeline = lambda: MockPipeline()

    with patch("app.services.rate_limiter.get_redis", return_value=mock_redis_instance):
        with patch("app.core.redis_client.get_redis", return_value=mock_redis_instance):
            with patch("app.api.health.get_redis", return_value=mock_redis_instance):
                yield mock_redis_instance


class MockPipeline:
    def incr(self, key):
        return self

    def expire(self, key, ttl):
        return self

    async def execute(self):
        return [1, True, 1, True]


@pytest.fixture(autouse=True)
async def setup_database():
    """Create database tables for each test."""
    from app.core.database import engine, Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
