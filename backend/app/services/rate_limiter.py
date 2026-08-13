"""Rate limiting service using Redis."""

from __future__ import annotations

import time

from app.core.config import get_settings
from app.core.redis_client import get_redis


class RateLimitExceeded(Exception):
    def __init__(self, retry_after: int):
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded. Retry after {retry_after}s")


async def check_rate_limit(client_ip: str) -> None:
    """Check and increment rate limit counters for a client IP."""
    settings = get_settings()
    redis = await get_redis()
    now = int(time.time())

    minute_key = f"rl:min:{client_ip}:{now // 60}"
    hour_key = f"rl:hour:{client_ip}:{now // 3600}"

    pipe = redis.pipeline()
    pipe.incr(minute_key)
    pipe.expire(minute_key, 60)
    pipe.incr(hour_key)
    pipe.expire(hour_key, 3600)
    results = await pipe.execute()

    minute_count = results[0]
    hour_count = results[2]

    if minute_count > settings.rate_limit_per_minute:
        raise RateLimitExceeded(60 - (now % 60))
    if hour_count > settings.rate_limit_per_hour:
        raise RateLimitExceeded(3600 - (now % 3600))
