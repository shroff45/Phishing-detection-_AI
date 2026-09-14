"""
PhishGuard Backend — FastAPI Application
─────────────────────────────────────────
"""
import asyncio
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import structlog
import uvicorn
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

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
