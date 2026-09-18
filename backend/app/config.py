"""PhishGuard backend configuration via environment variables."""

from typing import Optional

from pydantic import Field

try:
    from pydantic_settings import BaseSettings
except ImportError:
    # Fallback for pydantic v1 or missing pydantic-settings
    from pydantic import BaseSettings  # type: ignore


class Settings(BaseSettings):
    # Server
    HOST: str = Field(default="0.0.0.0")
    PORT: int = Field(default=7860)
    DEBUG: bool = Field(default=True)

    # Redis (optional — server works fine without it). When None, rate
    # limiting is in-memory per-process; set REDIS_URL to share rate-limit
    # counters across instances.
    REDIS_URL: Optional[str] = Field(default=None)

    # Threat intelligence API keys (optional — enhances detection)
    PHISHTANK_API_KEY: str = Field(default="")
    VIRUSTOTAL_API_KEY: str = Field(default="")
    GOOGLE_SAFE_BROWSING_KEY: str = Field(default="")

    # Rate limiting
    RATE_LIMIT: str = Field(default="100/minute")

    # Per-install rate-limit keying (experimental; default off). When true, a
    # request carrying a valid X-Install-Token header is rate-limited under
    # install:<token> instead of its client IP. The token is caller-supplied
    # and freely rotatable — this is per-install fairness for honest clients,
    # never an authentication boundary or anti-abuse wall.
    INSTALL_TOKEN_ENABLED: bool = Field(default=False)

    # API authentication (optional — skip auth if empty)
    EXTENSION_API_KEY: str = Field(default="")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()
