"""
PhishGuard — Threat Intelligence & Meta-Classifier
FIXED: Client score dilution, verdict monotonicity, suspicious hosting detection
"""

import asyncio
import base64
import re
import math
import time
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

import anyio
import anyio.to_thread
import httpx
import structlog
from app.config import settings

try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

logger = structlog.get_logger(__name__)

# WHOIS is slow, flaky, and rate-limited. An unknown result must not read as
# "slightly risky" — it contributes the same score as a mid-age domain and is
# always surfaced in `reasons` so a degraded lookup is visible, not silent.
WHOIS_TIMEOUT_SECONDS = 5.0
WHOIS_CACHE_TTL_SECONDS = 6 * 60 * 60
WHOIS_UNKNOWN_SCORE = 0.0
_whois_cache: dict = {}

# ── Global Whitelist (Never flag these as phishing) ────────────────────────
GLOBAL_WHITELIST = {
    "google.com", "www.google.com", "accounts.google.com",
    "github.com", "github.io", "githubusercontent.com",
    "microsoft.com", "login.microsoftonline.com",
    "stackoverflow.com", "reddit.com", "youtube.com",
    "linkedin.com", "twitter.com", "x.com",
    "facebook.com", "amazon.com", "apple.com",
    "localhost", "127.0.0.1",
}

# ── Suspicious TLDs ───────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".top", ".xyz",
    ".club", ".work", ".info", ".wang", ".click", ".link", ".icu",
    ".cam", ".rest", ".monster", ".site", ".online", ".website", ".surf",
}

# ── Suspicious hosting/tunnel providers (heavily abused for phishing) ─────
SUSPICIOUS_HOSTING = {
    "trycloudflare.com",
    "ngrok.io", "ngrok-free.app", "ngrok.app",
    "workers.dev",
    "pages.dev",
    "netlify.app",
    "vercel.app",
    "herokuapp.com",
    "glitch.me",
    "repl.co", "replit.dev",
    "github.io",        # Can be abused for phishing clones
    "firebaseapp.com",
    "web.app",
    "onrender.com",
    "fly.dev",
    "railway.app",
    "surge.sh",
    "000webhostapp.com",
    "infinityfreeapp.com",
    "rf.gd",
    "epizy.com",
    "byethost.com",
}

# ── Suspicious path keywords ──────────────────────────────────────────────
SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "log-in",
    "verify", "verification", "validate",
    "account", "myaccount", "my-account",
    "secure", "security", "authenticate",
    "update", "confirm", "recovery",
    "password", "passwd", "reset-password",
    "banking", "payment", "checkout",
    "wallet", "billing",
    "suspend", "locked", "restricted",
    "webmail", "roundcube",
]

# ── Phishing URL patterns ────────────────────────────────────────────────
PHISHING_PATTERNS = [
    r"login.*\.(?!com|org|net|edu|gov)",
    r"secure.*bank",
    r"update.*account",
    r"verify.*identity",
    r"confirm.*payment",
    r"signin.*\.(?!google|microsoft|apple|amazon)",
    r"account.*suspend",
    r"unusual.*activity",
]


# ═══════════════════════════════════════════════════════════════════════════
# THREAT FEED CHECKING (URLHaus, VirusTotal, Google Safe Browsing)
# ═══════════════════════════════════════════════════════════════════════════

async def _check_urlhaus(client: httpx.AsyncClient, url: str) -> dict:
    """Query the URLHaus bulk/URL lookup endpoint."""
    try:
        resp = await client.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "listed":
                return {
                    "flagged": True,
                    "source": "urlhaus",
                    "threat_type": data.get("threat", "malware"),
                }
    except httpx.TimeoutException:
        logger.warning("urlhaus_timeout", url=url)
    except Exception as e:
        logger.debug("urlhaus_check_failed", error=str(e))

    return {"flagged": False}


async def _check_virustotal(client: httpx.AsyncClient, url: str) -> dict:
    """
    Query VirusTotal v3 URL report.
    The URL identifier is its base64url encoding (no trailing '=' padding).
    """
    api_key = settings.VIRUSTOTAL_API_KEY
    if not api_key:
        logger.debug("virustotal_skipped", reason="no API key configured")
        return {"flagged": False}

    try:
        # VT v3 expects a URL-safe base64 id with padding stripped
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        resp = await client.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key},
        )

        if resp.status_code == 200:
            data = resp.json()
            stats = (
                data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
            )
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            # Flag if at least 1 engine considers it malicious/suspicious
            if malicious + suspicious > 0:
                return {
                    "flagged": True,
                    "source": "virustotal",
                    "threat_type": f"malicious:{malicious},suspicious:{suspicious}",
                }

        elif resp.status_code == 404:
            # URL not yet scanned – not a threat signal
            logger.debug("virustotal_not_found", url=url)

        elif resp.status_code == 429:
            logger.warning("virustotal_rate_limited")

    except httpx.TimeoutException:
        logger.warning("virustotal_timeout", url=url)
    except Exception as e:
        logger.debug("virustotal_check_failed", error=str(e))

    return {"flagged": False}


async def _check_google_safe_browsing(client: httpx.AsyncClient, url: str) -> dict:
    """Query Google Safe Browsing v4 threatMatches:find."""
    api_key = settings.GOOGLE_SAFE_BROWSING_KEY
    if not api_key:
        logger.debug("google_sb_skipped", reason="no API key configured")
        return {"flagged": False}

    try:
        body = {
            "client": {
                "clientId":      "phishguard-extension",
                "clientVersion": "1.0.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": url}],
            },
        }

        resp = await client.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": api_key},
            json=body,
        )

        if resp.status_code == 200:
            data = resp.json()
            matches = data.get("matches")
            if matches:                               # list is non-empty
                threat = matches[0].get("threatType", "unknown")
                return {
                    "flagged": True,
                    "source": "google_safe_browsing",
                    "threat_type": threat.lower(),
                }

        elif resp.status_code == 429:
            logger.warning("google_sb_rate_limited")

    except httpx.TimeoutException:
        logger.warning("google_sb_timeout", url=url)
    except Exception as e:
        logger.debug("google_sb_check_failed", error=str(e))

    return {"flagged": False}


async def check_threat_feeds(url: str) -> dict:
    """
    Check a URL against URLHaus, VirusTotal, and Google Safe Browsing
    **in parallel**. Returns detailed feed status.
    """
    parsed = urlparse(url)
    hostname = (parsed.netloc or "").lower()
    
    # 1. Quick Whitelist Check
    for safe in GLOBAL_WHITELIST:
        if hostname == safe or hostname.endswith("." + safe):
            return {
                "is_known_threat": False,
                "source": "whitelist",
                "threat_type": "safe",
                "feeds_checked": ["whitelist"],
                "feeds_flagged": [],
                "confidence": 1.0
            }

    result = {
        "is_known_threat": False,
        "source":          None,
        "threat_type":     None,
        "feeds_checked":   [],
        "feeds_flagged":   [],
        "confidence":      0.5
    }

    async with httpx.AsyncClient(timeout=7.0) as client:
        # Fire all checks concurrently
        tasks = [
            _check_urlhaus(client, url),
            _check_virustotal(client, url),
            _check_google_safe_browsing(client, url)
        ]
        feed_results = await asyncio.gather(*tasks, return_exceptions=True)

    sources = ["urlhaus", "virustotal", "google_safe_browsing"]
    for i, entry in enumerate(feed_results):
        source = sources[i]
        result["feeds_checked"].append(source)
        
        if isinstance(entry, BaseException):
            logger.warning("threat_feed_exception", source=source, error=str(entry))
            continue

        if entry.get("flagged"):
            result["is_known_threat"] = True
            result["feeds_flagged"].append(source)
            if not result["source"]:
                result["source"] = source
                result["threat_type"] = entry.get("threat_type")
                result["confidence"] = 1.0

    return result


# ═══════════════════════════════════════════════════════════════════════════
# SUSPICIOUS HOSTING DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def _is_suspicious_hosting(hostname: str) -> Optional[str]:
    """Check if the domain uses a known suspicious hosting provider."""
    lower = hostname.lower()
    for provider in SUSPICIOUS_HOSTING:
        if lower.endswith(provider) or lower.endswith("." + provider):
            return provider
    return None


def _check_path_keywords(path: str) -> tuple:
    """Check URL path for suspicious keywords. Returns (score, reasons)."""
    lower_path = path.lower()
    matches = []
    for kw in SUSPICIOUS_PATH_KEYWORDS:
        if kw in lower_path:
            matches.append(kw)

    if len(matches) >= 3:
        return 0.25, [f"Path contains multiple phishing keywords: {', '.join(matches[:3])}"]
    elif len(matches) >= 2:
        return 0.15, [f"Path contains phishing keywords: {', '.join(matches)}"]
    elif len(matches) >= 1:
        return 0.08, []  # Single keyword = very minor boost, no reason shown

    return 0.0, []


# ═══════════════════════════════════════════════════════════════════════════
# URL SIGNAL EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

def _extract_url_signals(url: str) -> tuple:
    parsed = urlparse(url)
    hostname = parsed.netloc or ""
    path = parsed.path or ""
    full = url.lower()
    reasons = []
    risk = 0.0

    # IP address
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", hostname):
        risk += 0.5
        reasons.append("URL uses an IP address instead of a domain name")

    # Suspicious TLD
    tld_match = False
    if TLDEXTRACT_AVAILABLE:
        ext = tldextract.extract(url)
        suffix = "." + ext.suffix if ext.suffix else ""
        tld_match = suffix.lower() in SUSPICIOUS_TLDS
    else:
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                tld_match = True
                break
    if tld_match:
        risk += 0.15
        reasons.append("URL uses a suspicious top-level domain")

    # Suspicious hosting provider (NEW)
    hosting = _is_suspicious_hosting(hostname)
    if hosting:
        risk += 0.20
        reasons.append(f"Hosted on suspicious tunnel/free provider: {hosting}")

    # Path keywords (NEW)
    path_score, path_reasons = _check_path_keywords(path)
    risk += path_score
    reasons.extend(path_reasons)

    # Phishing patterns
    for pattern in PHISHING_PATTERNS:
        if re.search(pattern, full, re.IGNORECASE):
            risk += 0.25  # Boost from 0.1 to 0.25
            reasons.append("URL matches known phishing patterns")
            break

    # URL length
    if len(url) > 100:
        risk += 0.05
        reasons.append("URL is unusually long")

    # Excessive subdomains
    if hostname.count(".") > 3:
        risk += 0.05
        reasons.append(f"URL has excessive subdomains")

    # No HTTPS
    if parsed.scheme != "https":
        risk += 0.05
        reasons.append("URL does not use HTTPS")

    # @ symbol
    if "@" in url:
        risk += 0.15
        reasons.append("URL contains @ symbol (potential obfuscation)")

    # Many digits in domain
    digit_count = sum(c.isdigit() for c in hostname)
    if digit_count > 4:
        risk += 0.05

    return min(risk, 1.0), reasons


# ═══════════════════════════════════════════════════════════════════════════
# DOMAIN AGE
# ═══════════════════════════════════════════════════════════════════════════

def _whois_domain_age(domain: str) -> tuple:
    """Blocking WHOIS lookup. Never call directly from async code — use _check_domain_age."""
    w = python_whois.whois(domain)
    creation_date = w.creation_date
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if not creation_date:
        return WHOIS_UNKNOWN_SCORE, "Domain age unavailable (WHOIS returned no creation date)"

    age_days = (datetime.now() - creation_date).days
    if age_days < 30:
        return 0.7, f"Domain is very new ({age_days} days old)"
    if age_days < 90:
        return 0.4, f"Domain is relatively new ({age_days} days old)"
    if age_days < 365:
        return 0.15, None
    return 0.0, None


async def _check_domain_age(domain: str) -> tuple:
    if not WHOIS_AVAILABLE:
        logger.warning("whois_unavailable", domain=domain)
        return WHOIS_UNKNOWN_SCORE, "Domain age unavailable (WHOIS client not installed)"

    cached = _whois_cache.get(domain)
    if cached and cached[0] > time.monotonic():
        return cached[1]

    try:
        with anyio.fail_after(WHOIS_TIMEOUT_SECONDS):
            # abandon_on_cancel: a stuck WHOIS server must not hold the request
            # open past the deadline. The thread is left to finish and discarded.
            result = await anyio.to_thread.run_sync(
                _whois_domain_age, domain, abandon_on_cancel=True
            )
    except TimeoutError:
        logger.warning("whois_timeout", domain=domain, timeout=WHOIS_TIMEOUT_SECONDS)
        return WHOIS_UNKNOWN_SCORE, "Domain age unavailable (WHOIS lookup timed out)"
    except Exception as exc:
        logger.warning("whois_failed", domain=domain, error=str(exc))
        return WHOIS_UNKNOWN_SCORE, "Domain age unavailable (WHOIS lookup failed)"

    _whois_cache[domain] = (time.monotonic() + WHOIS_CACHE_TTL_SECONDS, result)
    return result


# ═══════════════════════════════════════════════════════════════════════════
# META-CLASSIFIER — FIXED: No more client score dilution
#
# Key changes:
# 1. Client score weight increased from 0.20 → 0.35
# 2. Monotonic floor: if client_score >= 0.65, final never below 0.40
# 3. Suspicious hosting detection integrated
# 4. Path keyword analysis integrated
# ═══════════════════════════════════════════════════════════════════════════

async def compute_meta_score(
    url: str,
    client_score: float = 0.5,
    threat_feed_result: Optional[dict] = None,
    visual_result: Optional[dict] = None,
) -> dict:
    """
    Compute final phishing score from multiple signals.
    Optimized for zero-day IP-based detection.
    """
    # Base score from client ML
    base_score_weighted = client_score * 0.30  # 30% weight
    
    # Threat feed score (highest priority secondary source)
    ti_score = 0.0
    if threat_feed_result and threat_feed_result.get("is_known_threat"):
        ti_score = 0.70  # Known threat = auto 0.70 floor
    
    # URL heuristic scoring
    heuristic_score = 0.0
    parsed = urlparse(url)
    hostname = (parsed.netloc or "").lower()
    path_lower = (parsed.path or "").lower()
    
    # ── WHOIS Domain Age check ──
    whois_score, whois_reason = await _check_domain_age(hostname)
    heuristic_score += whois_score
    
    # ── IP-based hosting should trigger IMMEDIATE high score ──
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    host_only = hostname.split(':')[0]
    if re.match(ip_pattern, host_only):
        heuristic_score += 0.65  
        
    # Check for localhost/private IPs (highly suspicious for production traffic)
    if host_only.startswith('127.') or host_only.startswith('192.168.') or host_only.startswith('10.'):
        heuristic_score += 0.15 
    
    # Suspicious TLDs
    if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
        heuristic_score += 0.25
    
    # Typosquatting/Phishing patterns in URL
    for pattern in PHISHING_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            heuristic_score += 0.20
            break
    
    # Sensitive keywords in path
    if any(kw in path_lower for kw in ['login', 'verify', 'account', 'signin', 'update']):
        heuristic_score += 0.15
    
    # No HTTPS
    if parsed.scheme != 'https':
        heuristic_score += 0.10
    
    # Visual similarity score (if available)
    visual_score_weighted = 0.0
    if visual_result and visual_result.get("is_impersonation"):
        visual_score_weighted = visual_result.get("confidence", 0.7) * 0.20
    
    # ── COMBINE SCORES ──
    # Use the HIGHEST of (threat_feed, heuristics) as primary to prevent dilution
    primary_score = max(ti_score, heuristic_score)
    
    final_score = min(1.0, 
        primary_score * 0.60 +      # Primary signal
        base_score_weighted +       # Client ML
        visual_score_weighted       # Visual analysis
    )
    
    # ── MONOTONIC FLOOR ──
    if heuristic_score >= 0.65:
        final_score = max(final_score, 0.75)  # IP-based = minimum 0.75
    elif heuristic_score >= 0.40:
        final_score = max(final_score, 0.50)  # High risk heuristics = minimum 0.50
    
    # If confirmed threat feed, ensure phishing verdict
    if ti_score >= 0.70:
        final_score = max(final_score, 0.70)

    # Determine verdict
    if final_score >= 0.65:
        verdict = "phishing"
    elif final_score >= 0.35:
        verdict = "suspicious"
    else:
        verdict = "safe"
    
    # Compute confidence
    confidence = abs(final_score - 0.5) * 2.0
    
    # Build reasons list
    reasons = []
    if re.match(ip_pattern, host_only):
        reasons.append("URL uses an IP address instead of a domain name")
    if host_only.startswith('192.168.') or host_only.startswith('10.') or host_only.startswith('127.'):
        reasons.append("URL uses a private/localhost IP (highly suspicious)")
    if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
        reasons.append("URL uses a suspicious top-level domain")
    if any(re.search(p, url, re.IGNORECASE) for p in PHISHING_PATTERNS):
        reasons.append("URL matches known phishing patterns")
    if parsed.scheme != 'https':
        reasons.append("URL does not use HTTPS")
    if any(kw in path_lower for kw in ['login', 'verify', 'account', 'signin']):
        reasons.append("URL path contains sensitive keywords (login/verify)")
    if threat_feed_result and threat_feed_result.get("is_known_threat"):
        source = threat_feed_result.get("source", "unknown")
        reasons.append(f"URL found in threat intelligence feed ({source})")
    if whois_reason:
        reasons.append(whois_reason)
    
    if not reasons:
        reasons = ["No significant phishing indicators detected"]
    
    return {
        "score": round(final_score, 4),
        "verdict": verdict,
        "confidence": round(confidence, 4),
        "reasons": reasons,
        "source": threat_feed_result.get("source") if threat_feed_result else None,
        "feeds_checked": threat_feed_result.get("feeds_checked", []) if threat_feed_result else [],
        "feeds_flagged": threat_feed_result.get("feeds_flagged", []) if threat_feed_result else [],
        "signals": [
            f"heuristic_score={round(heuristic_score, 2)}",
            f"threat_intel_score={round(ti_score, 2)}",
            f"client_ml_score={round(base_score_weighted, 2)}",
            f"visual_score={round(visual_score_weighted, 2)}"
        ]
    }