"""
PhishGuard Backend — FastAPI Application
─────────────────────────────────────────
"""
import base64
import binascii
import uuid
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import structlog
import uvicorn
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# App services
from app.config import settings
from app.services.visual_analyzer import visual_analyzer
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

# 8 MiB decoded. Screenshots are downscaled client-side; anything larger is an
# attempt to drive the image decoder into memory pressure, not a real capture.
MAX_SCREENSHOT_BYTES = 8 * 1024 * 1024
MAX_SCREENSHOT_B64_CHARS = (MAX_SCREENSHOT_BYTES * 4) // 3 + 128

class FullAnalysisRequest(BaseModel):
    url: str
    client_score: float = Field(default=0.0, ge=0.0, le=1.0)
    screenshot_base64: Optional[str] = Field(default=None, max_length=MAX_SCREENSHOT_B64_CHARS)

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

        visual_result = None
        b64_data = request.screenshot_base64
        if b64_data and isinstance(b64_data, str):
            if "," in b64_data:
                b64_data = b64_data.split(",", 1)[1]
            try:
                screenshot_bytes = base64.b64decode(b64_data, validate=True)
            except (binascii.Error, ValueError):
                raise HTTPException(status_code=400, detail="screenshot_base64 is not valid base64")
            if len(screenshot_bytes) > MAX_SCREENSHOT_BYTES:
                raise HTTPException(status_code=413, detail="Screenshot exceeds maximum size")
            visual_result = await visual_analyzer.analyze_screenshot(screenshot_bytes, domain)

        meta = await compute_meta_score(url=request.url, client_score=request.client_score, threat_feed_result=threat_result, visual_result=visual_result)
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
            "threat_feed": threat_result,
            "visual_analysis": visual_result
        }
    except HTTPException:
        raise
    except Exception as e:
        correlation_id = uuid.uuid4().hex
        logger.error("full_analysis_failed", error=str(e), url=str(request.url), correlation_id=correlation_id)
        raise HTTPException(status_code=500, detail=f"Analysis failed (ref {correlation_id})")

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
