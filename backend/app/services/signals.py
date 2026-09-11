"""
PhishGuard Backend — Certificate & DNS Signals
Stage 3: Signals outside attacker control

Three new checkers, all fully async with strict timeouts:

  cert_age_check(domain)
    → Queries crt.sh for the most-recent certificate.  Certs issued
      within 24 h are a very strong zero-day signal; attackers must
      obtain a cert before they can serve HTTPS — so the cert issuance
      date is an independent timestamp the attacker cannot backdate.

  dns_asn_check(domain)
    → Resolves A records via a DNS-over-HTTPS resolver (Cloudflare)
      then maps each IP to an ASN via ipapi.co.  Known bulletproof /
      cheap-hosting ASNs get a risk bump.  Completely separate from
      WHOIS, so it works even when WHOIS is blocked or rate-limited.

  redirect_chain_check(url)
    → Follows the redirect chain (up to MAX_REDIRECTS hops) with a
      HEAD request, tracking each hop.  Detects:
        • Shortener → shortener chains
        • Cross-origin hops through legitimate infrastructure (open-redirect)
        • Chains that eventually land on a suspicious TLD/hosting provider
      Uses HEAD to avoid loading page bodies.  The final destination URL
      is returned so compute_meta_score can re-analyse it.

All three contribute scored signals back to compute_meta_score through
the new gather_signals() coroutine, which runs them in parallel.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
import structlog

logger = structlog.get_logger(__name__)

# ── Timeouts ───────────────────────────────────────────────────────────────
CERT_TIMEOUT_S    = 6.0
DNS_TIMEOUT_S     = 5.0
REDIRECT_TIMEOUT_S = 8.0

# ── Redirect following ─────────────────────────────────────────────────────
MAX_REDIRECTS = 8

# ── Bulletproof / abused-hosting ASN prefixes (partial list) ──────────────
# These are ASNs heavily associated with phishing infrastructure.
# We flag on substring match so minor sub-ASNs are caught.
BULLETPROOF_ASN_NAMES = {
    "as209588", "as396073", "as49581",   # Frantech / BuyVM
    "as7922",                             # Comcast (rarely — FP risk, kept as example)
    "as205016",                           # Hostinger
    "as9009",                             # M247 (heavily abused)
    "as57523",                            # ChangYou cloud
    "as51167",                            # Contabo
    "as202306", "as205100",              # Alexhost / Aeza
}

# Hosting names that appear in ASN org strings
BULLETPROOF_ASN_SUBSTRINGS = [
    "frantech", "buyvm", "m247", "contabo", "aeza", "alexhost",
    "hostinger", "namecheap", "serverius", "liteserver",
]

# ── Shortener domains (subset, for redirect-chain detection) ───────────────
SHORTENER_DOMAINS_SET = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "short.io",
    "s.id", "rb.gy", "clck.ru", "bl.ink", "tiny.cc",
}

# Suspicious TLDs (must match what evaluate.py and service-worker.js use)
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".top", ".xyz",
    ".club", ".work", ".info", ".click", ".link", ".icu",
    ".cam", ".rest", ".monster", ".site", ".online", ".website", ".surf",
}


# ═══════════════════════════════════════════════════════════════════════════
# 1.  Certificate age via crt.sh
# ═══════════════════════════════════════════════════════════════════════════

async def cert_age_check(domain: str, client: Optional[httpx.AsyncClient] = None) -> dict:
    """
    Query crt.sh for the most-recently issued certificate for *domain*.

    Returns a dict with keys:
      score       float  0..1 risk contribution
      reason      str | None  human-readable explanation
      cert_age_h  float | None  age of newest cert in hours
      error       str | None
    """
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=CERT_TIMEOUT_S)

    try:
        # crt.sh JSON API — de-duplicate by DISTINCT(not_before)
        resp = await client.get(
            "https://crt.sh/",
            params={"q": domain, "output": "json"},
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            return {"score": 0.0, "reason": None, "cert_age_h": None,
                    "error": f"crt.sh returned {resp.status_code}"}

        data = resp.json()
        if not data:
            # No certificate found — could be newly registered with no cert yet
            return {"score": 0.15, "reason": "No TLS certificate found in crt.sh",
                    "cert_age_h": None, "error": None}

        # Find the most recently issued cert
        newest_dt: Optional[datetime] = None
        for entry in data:
            nb_raw = entry.get("not_before") or entry.get("entry_timestamp")
            if not nb_raw:
                continue
            try:
                # crt.sh returns "2024-01-02T03:04:05" (UTC, no tz suffix)
                dt = datetime.fromisoformat(str(nb_raw).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if newest_dt is None or dt > newest_dt:
                    newest_dt = dt
            except ValueError:
                continue

        if newest_dt is None:
            return {"score": 0.0, "reason": None, "cert_age_h": None,
                    "error": "crt.sh returned entries but no parseable dates"}

        now = datetime.now(tz=timezone.utc)
        age_h = (now - newest_dt).total_seconds() / 3600.0

        if age_h < 24:
            return {"score": 0.55, "cert_age_h": round(age_h, 1),
                    "reason": f"TLS certificate issued {age_h:.1f} h ago — zero-day indicator",
                    "error": None}
        if age_h < 72:
            return {"score": 0.25, "cert_age_h": round(age_h, 1),
                    "reason": f"TLS certificate issued {age_h:.0f} h ago (very recent)",
                    "error": None}
        if age_h < 24 * 30:  # < 30 days
            return {"score": 0.10, "cert_age_h": round(age_h, 1),
                    "reason": f"TLS certificate issued {age_h / 24:.0f} days ago",
                    "error": None}

        return {"score": 0.0, "cert_age_h": round(age_h, 1),
                "reason": None, "error": None}

    except httpx.TimeoutException:
        logger.warning("cert_age_timeout", domain=domain)
        return {"score": 0.0, "reason": None, "cert_age_h": None,
                "error": "crt.sh timed out"}
    except Exception as exc:
        logger.debug("cert_age_failed", domain=domain, error=str(exc))
        return {"score": 0.0, "reason": None, "cert_age_h": None,
                "error": str(exc)}
    finally:
        if own_client:
            await client.aclose()


# ═══════════════════════════════════════════════════════════════════════════
# 2.  DNS → ASN reputation via ipapi.co
# ═══════════════════════════════════════════════════════════════════════════

def _is_private_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


async def dns_asn_check(domain: str, client: Optional[httpx.AsyncClient] = None) -> dict:
    """
    Resolve *domain* → IPs via Cloudflare DoH, then look each IP up via
    ipapi.co to get the hosting organisation / ASN.

    Returns a dict with keys:
      score   float  0..1
      reason  str | None
      asn     str | None   e.g. "AS9009 M247 Ltd"
      ips     list[str]
      error   str | None
    """
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=DNS_TIMEOUT_S)

    try:
        # ── DNS-over-HTTPS resolution (Cloudflare) ──────────────────────────
        doh_resp = await client.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": domain, "type": "A"},
            headers={"Accept": "application/dns-json"},
        )
        if doh_resp.status_code != 200:
            return {"score": 0.0, "reason": None, "asn": None, "ips": [],
                    "error": f"DoH returned {doh_resp.status_code}"}

        doh_data = doh_resp.json()
        answers = doh_data.get("Answer", [])
        ips = [a["data"] for a in answers if a.get("type") == 1]  # type 1 = A record

        if not ips:
            # NXDOMAIN or no A records — slightly suspicious if we got here
            return {"score": 0.05, "reason": "Domain has no A records (DNS NXDOMAIN?)",
                    "asn": None, "ips": [], "error": None}

        # ── ASN lookup for the first non-private IP ─────────────────────────
        public_ip = next((ip for ip in ips if not _is_private_ip(ip)), None)
        if not public_ip:
            return {"score": 0.30, "reason": "Domain resolves to private IP range",
                    "asn": None, "ips": ips, "error": None}

        asn_resp = await client.get(
            f"https://ipapi.co/{public_ip}/json/",
            headers={"User-Agent": "PhishGuard/1.0"},
        )

        score = 0.0
        reason = None
        asn_str = None

        if asn_resp.status_code == 200:
            asn_data = asn_resp.json()
            org = (asn_data.get("org") or "").lower()
            asn_str = asn_data.get("org", "")

            # Check bulletproof ASN substrings
            for substr in BULLETPROOF_ASN_SUBSTRINGS:
                if substr in org:
                    score = 0.35
                    reason = f"Hosted by bulletproof/abuse-prone provider: {asn_str}"
                    break

        return {"score": score, "reason": reason, "asn": asn_str, "ips": ips, "error": None}

    except httpx.TimeoutException:
        logger.warning("dns_asn_timeout", domain=domain)
        return {"score": 0.0, "reason": None, "asn": None, "ips": [],
                "error": "DNS/ASN lookup timed out"}
    except Exception as exc:
        logger.debug("dns_asn_failed", domain=domain, error=str(exc))
        return {"score": 0.0, "reason": None, "asn": None, "ips": [],
                "error": str(exc)}
    finally:
        if own_client:
            await client.aclose()


# ═══════════════════════════════════════════════════════════════════════════
# 3.  Redirect-chain follower
# ═══════════════════════════════════════════════════════════════════════════

def _domain_from_url(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _tld_of(domain: str) -> str:
    parts = domain.rsplit(".", 1)
    return "." + parts[-1] if len(parts) > 1 else ""


async def redirect_chain_check(url: str, client: Optional[httpx.AsyncClient] = None) -> dict:
    """
    Follow the redirect chain of *url* (HEAD requests) up to MAX_REDIRECTS hops.

    Returns a dict with keys:
      score           float  0..1
      reason          str | None
      chain           list[str]  all URLs visited
      final_url       str | None  last URL in the chain
      cross_origin    bool        at least one cross-origin hop
      shortener_hops  int         number of known-shortener hops
      error           str | None
    """
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(
            timeout=REDIRECT_TIMEOUT_S,
            follow_redirects=False,  # We follow manually to inspect each hop
        )

    chain: list[str] = [url]
    current = url
    cross_origin = False
    shortener_hops = 0
    origin_domain = _domain_from_url(url)

    try:
        for _ in range(MAX_REDIRECTS):
            try:
                resp = await client.head(current, follow_redirects=False)
            except Exception:
                # Network error on this hop — stop chain here
                break

            if resp.status_code not in (301, 302, 303, 307, 308):
                break  # Not a redirect; we've reached the destination

            location = resp.headers.get("location", "")
            if not location:
                break

            # Resolve relative redirects
            if location.startswith("/"):
                parsed = urlparse(current)
                location = f"{parsed.scheme}://{parsed.netloc}{location}"

            next_domain = _domain_from_url(location)
            if next_domain and next_domain != origin_domain:
                cross_origin = True

            if any(next_domain.endswith(sd) or next_domain == sd
                   for sd in SHORTENER_DOMAINS_SET):
                shortener_hops += 1

            chain.append(location)
            current = location

        final_url = chain[-1] if chain else url
        final_domain = _domain_from_url(final_url)
        final_tld = _tld_of(final_domain)

        # ── Score ────────────────────────────────────────────────────────────
        score = 0.0
        reason = None

        if shortener_hops > 1:
            score = max(score, 0.35)
            reason = f"Redirect chain passes through {shortener_hops} URL shorteners"

        if cross_origin and shortener_hops >= 1:
            score = max(score, 0.40)
            reason = (reason or "") + "; cross-origin hop through shortener detected"

        if final_tld in SUSPICIOUS_TLDS and final_url != url:
            score = max(score, 0.30)
            reason = (reason or "") + f"; chain lands on suspicious TLD ({final_tld})"

        # Open-redirect pattern: legitimate domain redirects to suspicious destination
        orig_tld = _tld_of(origin_domain)
        if orig_tld not in SUSPICIOUS_TLDS and final_tld in SUSPICIOUS_TLDS:
            score = max(score, 0.45)
            reason = (
                f"Open-redirect: starts at {origin_domain!r} "
                f"but ends at {final_domain!r} ({final_tld})"
            )

        if score == 0.0:
            reason = None

        return {
            "score": score,
            "reason": reason,
            "chain": chain,
            "final_url": final_url,
            "cross_origin": cross_origin,
            "shortener_hops": shortener_hops,
            "error": None,
        }

    except httpx.TimeoutException:
        logger.warning("redirect_chain_timeout", url=url)
        return {"score": 0.0, "reason": None, "chain": chain, "final_url": current,
                "cross_origin": cross_origin, "shortener_hops": shortener_hops,
                "error": "Redirect chain timed out"}
    except Exception as exc:
        logger.debug("redirect_chain_failed", url=url, error=str(exc))
        return {"score": 0.0, "reason": None, "chain": [url], "final_url": url,
                "cross_origin": False, "shortener_hops": 0, "error": str(exc)}
    finally:
        if own_client:
            await client.aclose()


# ═══════════════════════════════════════════════════════════════════════════
# 4.  Parallel orchestrator — gather_signals()
# ═══════════════════════════════════════════════════════════════════════════

async def gather_signals(url: str, domain: str) -> dict:
    """
    Run all three Stage-3 signal checks in parallel.

    Returns a dict with keys:
      cert        dict   result of cert_age_check
      dns_asn     dict   result of dns_asn_check
      redirect    dict   result of redirect_chain_check
      total_score float  sum of individual scores, capped at 1.0
      reasons     list[str]  non-None reasons from all checkers
    """
    async with httpx.AsyncClient(timeout=max(CERT_TIMEOUT_S, DNS_TIMEOUT_S, REDIRECT_TIMEOUT_S)) as client:
        cert_task     = asyncio.create_task(cert_age_check(domain, client=client))
        dns_task      = asyncio.create_task(dns_asn_check(domain, client=client))
        redirect_task = asyncio.create_task(redirect_chain_check(url, client=client))

        cert_result, dns_result, redirect_result = await asyncio.gather(
            cert_task, dns_task, redirect_task, return_exceptions=False
        )

    total_score = min(1.0,
        cert_result.get("score", 0.0)
        + dns_result.get("score", 0.0)
        + redirect_result.get("score", 0.0)
    )

    reasons: list[str] = [
        r for r in (
            cert_result.get("reason"),
            dns_result.get("reason"),
            redirect_result.get("reason"),
        )
        if r
    ]

    return {
        "cert":        cert_result,
        "dns_asn":     dns_result,
        "redirect":    redirect_result,
        "total_score": round(total_score, 4),
        "reasons":     reasons,
    }
