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

    # Sandbox detonation bounds (env-driven). Chromium is heavy: at most
    # MAX_CONCURRENT_DETONATIONS browsers are alive at once PER WORKER —
    # the cap applies per worker process, so with uvicorn --workers N the
    # ceiling is N × MAX_CONCURRENT_DETONATIONS; size
    # MAX_CONCURRENT_DETONATIONS / workers accordingly. Excess requests
    # queue for a slot instead of exhausting the host. Every active
    # detonation is hard-CANCELLED at DETONATION_TOTAL_S (the asyncio.wait_for
    # budget wraps the whole browser block, so a slow page is interrupted,
    # not merely reported late). Keep TOTAL comfortably above the crawler's
    # internal budgets (page load 15s + settle 2s + telemetry/screenshot).
    # Both are gt=0: a 0 cap would hang every detonation on a semaphore
    # that never opens, a 0 budget would 504 every request, and negatives
    # would crash at first use.
    MAX_CONCURRENT_DETONATIONS: int = Field(default=3, gt=0)
    DETONATION_TOTAL_S: float = Field(default=30.0, gt=0)

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()
