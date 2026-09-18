"""
PhishGuard Backend — FastAPI Application
─────────────────────────────────────────
"""
import asyncio
import re
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import structlog
import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

# App services
from app.config import settings
from app.services.visual_analyzer import visual_analyzer, HASH_BITS
from app.services.threat_intel import compute_meta_score, check_threat_feeds
from app.services.feed_manager import feed_manager
from app.middleware.auth import verify_api_key

# Logging
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.dev.ConsoleRenderer(),
    ],
)
logger = structlog.get_logger(__name__)


def _parse_rate_limit(value: str) -> tuple:
    """Parse '100/minute' style strings into (max_requests, window_seconds)."""
    count_str, window_str = value.strip().lower().split("/")
    count = int(count_str)
    windows = {
        "second": 1, "seconds": 1,
        "minute": 60, "minutes": 60,
        "hour": 3600, "hours": 3600,
    }
    window = windows.get(window_str, 60)
    return count, window


_RATE_MAX, _RATE_WINDOW = _parse_rate_limit(settings.RATE_LIMIT)

# Optional per-install rate-limit keying (INSTALL_TOKEN_ENABLED, default off).
# Caller-supplied token, not an auth credential: it must never carry structure
# the limiter would interpret, so the alphabet is kept to [A-Za-z0-9._-] —
# no ':' (the Redis key is "phishguard:ratelimit:<key>:<bucket>", and ':'
# would blur its segments), no whitespace, no control chars, hard-capped
# at 64 chars.
_INSTALL_TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


# ── Rate limiting: pluggable storage ─────────────────────────────────────────
# In-memory is the default and preserves the original single-process behaviour
# exactly. Redis is opt-in via REDIS_URL for multi-instance deployments that
# need a shared counter. Every Redis failure path degrades to the in-memory
# store (fail-open-to-local): limiting continues per-process rather than
# 500ing every request or disabling limiting entirely. Never crash startup
# because Redis is unreachable.


class InMemoryRateStore:
    """Sliding-window store for a single process. Zero dependencies.

    Bounded memory: entries older than the window are pruned on each check,
    AND the keyspace itself is capped at ``max_keys`` distinct keys. The cap
    matters once keys stop being client IPs: with per-install token keying
    (INSTALL_TOKEN_ENABLED) an attacker rotates tokens freely, and an
    uncapped dict would let each rotation leak one dict entry.
    Uses time.monotonic() for drift-free windowing.
    """

    def __init__(self, max_keys: int = 100_000) -> None:
        if max_keys < 1:
            raise ValueError("max_keys must be >= 1")
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._max_keys = max_keys

    def _evict_for(self, now: float, window: float) -> None:
        """Make room for one new key.

        First sweep drops dormant keys — every timestamp outside the window
        carries no live quota state, so evicting them changes nothing about
        who is currently limited. If nothing is dormant (a real rotation
        flood inside a single window), fall back to evicting the
        oldest-inserted entries until there is room. Eviction only ever
        costs an evicted key its history; every retained key keeps full
        quota enforcement.
        """
        for stale in [
            key
            for key, ts in self._hits.items()
            if not any(now - t < window for t in ts)
        ]:
            del self._hits[stale]
        while len(self._hits) >= self._max_keys:
            self._hits.pop(next(iter(self._hits)))

    def hit(self, key: str, max_requests: int, window: float) -> Optional[int]:
        """Register a request for ``key``.

        Returns Retry-After seconds when the request exceeds the limit,
        or None when it is allowed.
        """
        now = time.monotonic()
        if key not in self._hits and len(self._hits) >= self._max_keys:
            self._evict_for(now, window)
        timestamps = [t for t in self._hits[key] if now - t < window]
        if len(timestamps) >= max_requests:
            self._hits[key] = timestamps
            return max(int(window - (now - timestamps[0])) + 1, 1)
        timestamps.append(now)
        self._hits[key] = timestamps
        return None


class RedisRateStore:
    """Fixed-window counters in Redis, shared across processes/instances.

    Uses one INCR+EXPIRE bucket per client per window. Buckets are aligned to
    wall-clock time (time.time(), not monotonic) so every process increments
    the same counter for the same window.

    Degradation: if a Redis call fails, mark the backend down for
    _RETRY_SECONDS and serve from the in-memory fallback. A recovered Redis
    is picked up without a restart. Request-time Redis errors never become
    HTTP 500s.
    """

    _RETRY_SECONDS = 30.0

    def __init__(self, client, fallback: InMemoryRateStore) -> None:
        self._client = client
        self._fallback = fallback
        self._redis_down_until = 0.0

    def hit(self, key: str, max_requests: int, window: float) -> Optional[int]:
        now = time.time()
        if now < self._redis_down_until:
            return self._fallback.hit(key, max_requests, window)
        bucket = int(now // window)
        rkey = f"phishguard:ratelimit:{key}:{bucket}"
        try:
            # INCR + EXPIRE in one pipeline; the key always gets a TTL, so
            # memory in Redis stays bounded by the number of active clients.
            pipe = self._client.pipeline(transaction=False)
            pipe.incr(rkey)
            pipe.expire(rkey, max(int(window), 1))
            count, _ = pipe.execute()
        except Exception as exc:  # redis.exceptions.*, OSError — any transport fault
            logger.warning("rate_limit_redis_error_using_memory", error=str(exc))
            self._redis_down_until = now + self._RETRY_SECONDS
            return self._fallback.hit(key, max_requests, window)
        if count > max_requests:
            return max(int(window - (now % window)) + 1, 1)
        return None


def _build_rate_store() -> Tuple[object, str]:
    """Select the rate-limit backend.

    Redis only when REDIS_URL is set AND the redis package imports AND the
    server answers PING. Every other outcome lands on the in-memory store —
    a configured-but-broken Redis must never crash startup.
    """
    redis_url = getattr(settings, "REDIS_URL", None)
    if not redis_url:
        return InMemoryRateStore(), "memory"
    try:
        import redis  # type: ignore
    except ImportError:
        logger.warning(
            "rate_limit_redis_unavailable",
            reason="REDIS_URL set but the redis package is not installed",
            fallback="in-memory per-process limiting",
        )
        return InMemoryRateStore(), "memory"
    try:
        client = redis.Redis.from_url(
            redis_url, socket_connect_timeout=1.0, socket_timeout=1.0
        )
        client.ping()
    except Exception as exc:
        logger.warning(
            "rate_limit_redis_unreachable",
            error=str(exc),
            fallback="in-memory per-process limiting",
        )
        return InMemoryRateStore(), "memory"
    logger.info("rate_limit_backend_selected", backend="redis")
    return RedisRateStore(client, InMemoryRateStore()), "redis"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiter keyed by client IP: 429 + Retry-After on excess.

    Storage is pluggable (in-memory default, Redis when REDIS_URL is set);
    the 429/Retry-After response contract is identical for both backends.

    Optional per-install keying (INSTALL_TOKEN_ENABLED, default off): a
    request carrying a syntactically valid X-Install-Token header is
    limited under install:<token> INSTEAD of its IP — the token replaces
    the key wholesale, it is never combined with IP or path. Missing or
    invalid header falls back to IP limiting unchanged. The flag is read
    once at construction from settings; the constructor signature is
    deliberately untouched (test_rate_limit pins its defaults).
    """

    def __init__(self, app, max_requests: int = _RATE_MAX, window: float = _RATE_WINDOW, store=None):
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window
        self.install_token_enabled = bool(
            getattr(settings, "INSTALL_TOKEN_ENABLED", False)
        )
        if store is None:
            self.store, self.backend = _build_rate_store()
        else:
            self.store, self.backend = store, type(store).__name__

    @property
    def _hits(self):
        """Direct view of the local hit map — the in-memory store's own dict,
        or the Redis store's degradation fallback. Test/ops introspection only.
        """
        store = self.store
        if isinstance(store, RedisRateStore):
            store = store._fallback
        return store._hits

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        key = client_ip
        if self.install_token_enabled:
            token = request.headers.get("X-Install-Token")
            if token and _INSTALL_TOKEN_RE.match(token):
                key = f"install:{token}"
        retry_after = self.store.hit(key, self.max_requests, self.window)
        if retry_after is not None:
            return Response(
                content='{"detail":"Rate limit exceeded. Try again later."}',
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)

app = FastAPI(
    title="PhishGuard API",
    description="Real-time phishing detection with visual similarity analysis",
    version="1.0.0",
)

# Privacy Middleware (Phase 8)
try:
    from app.middleware.privacy import PrivacyMiddleware
    app.add_middleware(PrivacyMiddleware)
    logger.info("privacy_middleware_loaded")
except ImportError:
    logger.debug("privacy_middleware_not_found")

# Rate limiting — BEFORE CORS so it applies to all requests
app.add_middleware(RateLimitMiddleware)
logger.info("rate_limit_middleware_loaded", rate_limit=settings.RATE_LIMIT)

# CORS — allow Chrome extension origins explicitly
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "chrome-extension://*",
    ],
    allow_origin_regex=r"^chrome-extension://.*$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class QuickCheckRequest(BaseModel):
    url: str
    client_score: float = Field(default=0.0, ge=0.0, le=1.0)

# ── Stage 5: derived visual features replace screenshots ───────────────────
# The extension computes these in-page; the backend never receives, decodes,
# or stores image bytes. Every field is attacker-controllable, so the model
# is tightly constrained: a hash that isn't a 0/1 string of ≤256 chars,
# more than 8 colours, or non-integer components is rejected with 422 by
# pydantic before any scoring runs. The old screenshot path accepted 8 MiB
# base64 payloads; the largest attack surface this model exposes is ~300 bytes.
class VisualFeatures(BaseModel):
    model_config = {"extra": "forbid"}

    favicon_ahash: Optional[str] = Field(
        default=None,
        max_length=HASH_BITS,
        pattern=r"^[01]*$",
        description="256-bit average hash of the page favicon",
    )
    color_summary: Optional[List[Tuple[int, int, int]]] = Field(
        default=None,
        max_length=8,
        description="Up to 8 dominant RGB colours (favicon or page CSS)",
    )
    color_source: Optional[str] = Field(
        default=None,
        max_length=16,
        description='"favicon" | "page" | "unavailable" — where colours came from',
    )

class FullAnalysisRequest(BaseModel):
    model_config = {"extra": "forbid"}

    url: str
    client_score: float = Field(default=0.0, ge=0.0, le=1.0)
    visual_features: Optional[VisualFeatures] = None

# ── Track B: sandboxed detonation ────────────────────────────────────────────
# The Tier-2 investigation agent asks the sandbox crawler to visit a URL and
# return telemetry. The request surface is one constrained string — anything
# else pydantic rejects with 422 before a browser process ever starts.
class DetonateRequest(BaseModel):
    model_config = {"extra": "forbid"}

    url: str = Field(max_length=2048)

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": {
            "visual_analyzer": True,
            "threat_intel": True,
            "feed_manager": True,
            "feed_stats": feed_manager.get_stats(),
        },
    }

@app.post("/api/v1/analyze/quick", dependencies=[Depends(verify_api_key)])
async def analyze_quick(request: QuickCheckRequest):
    try:
        threat_result = await check_threat_feeds(request.url, client_score=request.client_score)
        parsed = urlparse(request.url)
        domain = parsed.netloc or ""
        if feed_manager.is_domain_blocked(domain):
            threat_result["is_known_threat"] = True
            threat_result["source"] = "phishguard_feed"

        meta = await compute_meta_score(url=request.url, client_score=request.client_score, threat_feed_result=threat_result)
        return {
            "url": request.url,
            "verdict": meta["verdict"],
            "score": meta["score"],
            "confidence": meta.get("confidence", 0.0),
            "reasons": meta.get("reasons", []),
            "source": meta.get("source"),
            "feeds_checked": meta.get("feeds_checked", []),
            "feeds_flagged": meta.get("feeds_flagged", []),
            "signals": meta.get("signals", []),
            "evidence_trail": meta.get("evidence_trail", []),
            "threat_feed": threat_result
        }
    except Exception as e:
        correlation_id = uuid.uuid4().hex
        logger.error("quick_analysis_failed", error=str(e), url=str(request.url), correlation_id=correlation_id)
        raise HTTPException(status_code=500, detail=f"Analysis failed (ref {correlation_id})")

@app.post("/api/v1/analyze/full", dependencies=[Depends(verify_api_key)])
async def analyze_full(request: FullAnalysisRequest):
    try:
        threat_result = await check_threat_feeds(request.url, client_score=request.client_score)
        parsed = urlparse(request.url)
        domain = parsed.netloc or ""
        if feed_manager.is_domain_blocked(domain):
            threat_result["is_known_threat"] = True

        # Stage 5: derived features in, never pixels. A missing feature set
        # is legitimate (favicon unavailable) — the analyzer reports why in
        # details rather than failing the request.
        visual_result = None
        if request.visual_features is not None:
            visual_result = visual_analyzer.analyze_features(
                request.visual_features.model_dump(), domain
            )

        meta = await compute_meta_score(url=request.url, client_score=request.client_score, threat_feed_result=threat_result, visual_result=visual_result)
        final_score = meta["score"]
        evidence_trail = meta.get("evidence_trail", [])

        # Backend uses SAME thresholds as extension USED to use
        PHISHING_THRESHOLD = 0.65
        SUSPICIOUS_THRESHOLD = 0.35
        
        if final_score >= PHISHING_THRESHOLD:
            verdict = "phishing"
        elif final_score >= SUSPICIOUS_THRESHOLD:
            verdict = "suspicious"
        else:
            verdict = "safe"

        return {
            "url": str(request.url),
            "verdict": verdict,
            "score": final_score,
            "confidence": final_score,
            "reasons": [s["human_readable"] for s in evidence_trail],
            "source": "backend",
            "feeds_checked": meta.get("feeds_checked", []),
            "feeds_flagged": meta.get("feeds_flagged", []),
            "signals": [s["signal"] for s in evidence_trail],
            "evidence_trail": evidence_trail,
            "threat_feed": threat_result,
            "visual_analysis": visual_result,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        correlation_id = uuid.uuid4().hex
        logger.error("full_analysis_failed", error=str(e), url=str(request.url), correlation_id=correlation_id)
        raise HTTPException(status_code=500, detail=f"Analysis failed (ref {correlation_id})")

@app.post("/api/v1/investigate/detonate", dependencies=[Depends(verify_api_key)])
async def detonate(request: DetonateRequest):
    try:
        # Lazy import: the crawler module itself loads playwright only inside
        # detonate_url, so a machine without browsers still gets the SSRF
        # entry guard (→ 400 for refused targets) without touching playwright.
        from app.services.sandbox_crawler import detonate_url, SandboxTargetError
        result = await detonate_url(request.url)
        return result
    except HTTPException:
        raise
    except SandboxTargetError as e:
        # Refused targets are client errors, not server faults — the message
        # tells the agent exactly which guard fired and why.
        raise HTTPException(status_code=400, detail=str(e))
    except ImportError:
        # Public target, but this backend cannot launch a sandbox (playwright
        # or its browsers not installed) — degrade visibly, never silently.
        raise HTTPException(status_code=503, detail="Sandbox crawler unavailable")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Detonation exceeded its time budget")
    except Exception as e:
        correlation_id = uuid.uuid4().hex
        logger.error("detonation_failed", error=str(e), url=str(request.url), correlation_id=correlation_id)
        raise HTTPException(status_code=500, detail=f"Detonation failed (ref {correlation_id})")

@app.post("/api/v1/feed/update", dependencies=[Depends(verify_api_key)])
async def update_feeds():
    stats = await feed_manager.update_feeds()
    return {"success": True, "stats": stats}

@app.get("/api/v1/feed/rules", dependencies=[Depends(verify_api_key)])
async def get_feed_rules(limit: int = 5000, offset: int = 0):
    return {"rules": feed_manager.get_rules(limit, offset), "total": feed_manager.total_rules}

@app.on_event("startup")
async def startup_event():
    try: await feed_manager.update_feeds()
    except: pass

if __name__ == "__main__":
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
