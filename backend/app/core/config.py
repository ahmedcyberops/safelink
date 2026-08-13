from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "SafeLink"
    app_version: str = "1.0.0"
    debug: bool = False
    environment: str = "development"

    # Database
    database_url: str = "postgresql+asyncpg://safelink:safelink@postgres:5432/safelink"

    # Redis
    redis_url: str = "redis://redis:6379/0"

    # CORS
    cors_origins: str = "http://localhost:3000,http://frontend:3000"

    # Rate limiting
    rate_limit_per_minute: int = 10
    rate_limit_per_hour: int = 60

    # HTTP client limits
    http_connect_timeout: float = 5.0
    http_total_timeout: float = 15.0
    http_max_redirects: int = 5
    http_max_response_size: int = 512_000  # 512 KB
    http_max_concurrent: int = 10

    # Scan retention (hours)
    scan_retention_hours: int = 24

    # Risk scoring thresholds
    risk_threshold_low: int = 20
    risk_threshold_moderate: int = 50
    risk_threshold_suspicious: int = 75

    # Reputation providers
    reputation_api_key: str = ""
    reputation_provider: str = "mock"  # mock | virustotal

    # Security
    max_url_length: int = 2048
    secret_key: str = "change-me-in-production"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
