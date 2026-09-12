"""
PhishGuard Backend — Stage 3 Signals + Stage 4 Evidence-Trail Records
Signals outside attacker control: certificate age, DNS/ASN, redirect chain.

Stage 3 shipped the three checks. This module now also implements the
Stage 3.1 plumbing the plan called for, which Stage 4's evidence-trail
UI depends on:

  • Uniform record format — every tool (and every signal surfaced by
    compute_meta_score) returns:
        {signal, value, weight, human_readable, status}
    `weight` is the risk contribution the tool actually made, 0..1.
    A tool with status != "ok" always carries weight 0.0 and STILL
    appears in the trail — a degraded check must read as *unknown*,
    never as *safe*.

  • Per-tool timeouts — each check runs inside its own asyncio budget.
    One slow tool cannot consume the latency of the others.

  • Domain-keyed cache with TTL — cert and DNS/ASN results are stable
    for hours. Redirect chains are deliberately NOT cached: an attacker
    can rotate a destination between two navigations.

  • Redirect-follower hardening — loop detection, a hop cap, an
    independent total-time cap, cookie stripping between hops, scheme
    validation, and a byte-safe GET fallback for servers that reject
    HEAD. Response bodies are never read.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
import structlog

logger = structlog.get_logger(__name__)

# ── Per-tool timeout budgets (seconds) ─────────────────────────────────────
CERT_TIMEOUT_S     = 6.0
DNS_TIMEOUT_S      = 5.0
REDIRECT_TIMEOUT_S = 8.0    # per-hop request timeout
REDIRECT_TOTAL_S   = 12.0   # independent cap for the whole walk

# ── Redirect following ──────────────────────────────────────────────────────
MAX_REDIRECTS = 10
# Servers that reject HEAD (405/501) get one GET fallback. We only read
# status + headers; the body is never read, so memory cannot be blown up
# by an oversized response.
GET_FALLBACK_STATUSES = {405, 501}

# ── Domain cache ────────────────────────────────────────────────────────────
# cert + DNS/ASN results keyed by registrable host, shared across requests.
# Expiry is a time.monotonic() deadline. Redirect chains are not cached.
SIGNAL_CACHE_TTL_S = 6 * 60 * 60
_signal_cache: dict[str, tuple[float, tuple[dict, dict]]] = {}

# ── Bulletproof / abused-hosting ASNs ──────────────────────────────────────
# Flagged on substring match so minor sub-ASNs are caught.
BULLETPROOF_ASN_SUBSTRINGS = [
    "frantech", "buyvm", "m247", "contabo", "aeza", "alexhost",
    "hostinger", "namecheap", "serverius", "liteserver",
]

# ── Shortener domains (for redirect-chain detection) ────────────────────────
SHORTENER_DOMAINS_SET = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "short.io",
    "s.id", "rb.gy", "clck.ru", "bl.ink", "tiny.cc",
}

# Suspicious TLDs (must match evaluate.py and service-worker.js)
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".top", ".xyz",
    ".club", ".work", ".info", ".click", ".link", ".icu",
    ".cam", ".rest", ".monster", ".site", ".online", ".website", ".surf",
}

# ── Record statuses: ok | timeout | unavailable ─────────────────────────────


def _record(signal: str, value, weight: float, human_readable: str,
            status: str = "ok", **extra) -> dict:
    """Build one evidence-trail record. A non-ok status forces weight 0."""
    if status != "ok":
        weight = 0.0
    rec = {
        "signal": signal,
        "value": value,
        "weight": round(float(weight), 4),
        "human_readable": human_readable,
        "status": status,
    }
    rec.update(extra)
    return rec


# ═══════════════════════════════════════════════════════════════════════════
# 1.  Certificate age via crt.sh
# ═══════════════════════════════════════════════════════════════════════════

async def cert_age_check(domain: str, client: Optional[httpx.AsyncClient] = None) -> dict:
    """
    Query crt.sh for the most-recently issued certificate for *domain*.

    A cert issued within 24 h is a strong zero-day signal — the attacker
    must obtain a cert before serving HTTPS, and cannot backdate CT entry.
    """
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=CERT_TIMEOUT_S)

    try:
        resp = await client.get(
            "https://crt.sh/",
            params={"q": domain, "output": "json"},
            headers={"Accept": "application/json"},
            timeout=CERT_TIMEOUT_S,
        )
        if resp.status_code != 200:
            return _record(
                "cert_age", None, 0.0,
                "Certificate transparency lookup unavailable",
                "unavailable",
                error=f"crt.sh returned {resp.status_code}",
            )

        data = resp.json()
        if not data:
            return _record(
                "cert_age", None, 0.15,
                "No TLS certificate found in transparency logs",
            )

        # Find the most recently issued cert
        newest_dt: Optional[datetime] = None
        for entry in data:
            nb_raw = entry.get("not_before") or entry.get("entry_timestamp")
            if not nb_raw:
                continue
            try:
                dt = datetime.fromisoformat(str(nb_raw).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if newest_dt is None or dt > newest_dt:
                    newest_dt = dt
            except ValueError:
                continue

        if newest_dt is None:
            return _record(
                "cert_age", None, 0.0,
                "Certificate log entries were unparseable",
                "unavailable",
                error="crt.sh returned entries but no parseable dates",
            )

        now = datetime.now(tz=timezone.utc)
        age_h = (now - newest_dt).total_seconds() / 3600.0

        if age_h < 24:
            return _record(
                "cert_age", round(age_h, 1), 0.55,
                f"TLS certificate issued {age_h:.1f} h ago — zero-day indicator",
            )
        if age_h < 72:
            return _record(
                "cert_age", round(age_h, 1), 0.25,
                f"TLS certificate issued {age_h:.0f} h ago (very recent)",
            )
        if age_h < 24 * 30:
            return _record(
                "cert_age", round(age_h, 1), 0.10,
                f"TLS certificate issued {age_h / 24:.0f} days ago",
            )
        return _record(
            "cert_age", round(age_h, 1), 0.0,
            f"TLS certificate issued {age_h / 24:.0f} days ago — established",
        )

    except httpx.TimeoutException:
        logger.warning("cert_age_timeout", domain=domain)
        return _record(
            "cert_age", None, 0.0,
            "Certificate age check timed out — not counted",
            "timeout", error="crt.sh timed out",
        )
    except Exception as exc:
        logger.debug("cert_age_failed", domain=domain, error=str(exc))
        return _record(
            "cert_age", None, 0.0,
            "Certificate age check failed — not counted",
            "unavailable", error=str(exc),
        )
    finally:
        if own_client:
            await client.aclose()


# ═══════════════════════════════════════════════════════════════════════════
# 2.  DNS → ASN reputation via Cloudflare DoH + ipapi.co
# ═══════════════════════════════════════════════════════════════════════════

def _is_private_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


async def dns_asn_check(domain: str, client: Optional[httpx.AsyncClient] = None) -> dict:
    """
    Resolve *domain* → IPs via DNS-over-HTTPS, then look the public IP up
    to identify the hosting organisation. Bulletproof/abuse-prone
    providers get a risk bump.
    """
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=DNS_TIMEOUT_S)

    try:
        doh_resp = await client.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": domain, "type": "A"},
            headers={"Accept": "application/dns-json"},
            timeout=DNS_TIMEOUT_S,
        )
        if doh_resp.status_code != 200:
            return _record(
                "dns_asn", None, 0.0,
                "DNS resolution unavailable",
                "unavailable",
                ips=[], error=f"DoH returned {doh_resp.status_code}",
            )

        answers = doh_resp.json().get("Answer", [])
        ips = [a["data"] for a in answers if a.get("type") == 1]

        if not ips:
            return _record(
                "dns_asn", None, 0.05,
                "Domain has no A records (DNS NXDOMAIN?)",
                ips=[],
            )

        public_ip = next((ip for ip in ips if not _is_private_ip(ip)), None)
        if not public_ip:
            return _record(
                "dns_asn", None, 0.30,
                "Domain resolves to a private IP range",
                ips=ips,
            )

        asn_resp = await client.get(
            f"https://ipapi.co/{public_ip}/json/",
            headers={"User-Agent": "PhishGuard/1.0"},
            timeout=DNS_TIMEOUT_S,
        )

        if asn_resp.status_code != 200:
            return _record(
                "dns_asn", None, 0.0,
                "Hosting provider lookup unavailable",
                "unavailable",
                ips=ips, error=f"ipapi.co returned {asn_resp.status_code}",
            )

        asn_data = asn_resp.json()
        org = (asn_data.get("org") or "").lower()
        asn_str = asn_data.get("org", "") or None

        for substr in BULLETPROOF_ASN_SUBSTRINGS:
            if substr in org:
                return _record(
                    "dns_asn", asn_str, 0.35,
                    f"Hosted by bulletproof/abuse-prone provider: {asn_str}",
                    ips=ips,
                )

        if asn_str:
            return _record(
                "dns_asn", asn_str, 0.0,
                f"Hosted by {asn_str}",
                ips=ips,
            )
        return _record(
            "dns_asn", None, 0.0,
            "Hosting provider could not be identified",
            ips=ips,
        )

    except httpx.TimeoutException:
        logger.warning("dns_asn_timeout", domain=domain)
        return _record(
            "dns_asn", None, 0.0,
            "DNS/ASN check timed out — not counted",
            "timeout", ips=[], error="DNS/ASN lookup timed out",
        )
    except Exception as exc:
        logger.debug("dns_asn_failed", domain=domain, error=str(exc))
        return _record(
            "dns_asn", None, 0.0,
            "DNS/ASN check failed — not counted",
            "unavailable", ips=[], error=str(exc),
        )
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


def _normalise_location(current: str, location: str) -> Optional[str]:
    """Resolve a Location header against the current URL. None = malformed."""
    if not location:
        return None
    if location.startswith("//"):
        # protocol-relative — inherit the current scheme
        scheme = urlparse(current).scheme or "https"
        location = f"{scheme}:{location}"
    if location.startswith("/"):
        parsed = urlparse(current)
        location = f"{parsed.scheme}://{parsed.netloc}{location}"
    parsed = urlparse(location)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    return location


async def redirect_chain_check(url: str, client: Optional[httpx.AsyncClient] = None) -> dict:
    """
    Follow the redirect chain of *url* manually, up to MAX_REDIRECTS hops,
    inside an independent total-time cap.

    Safety posture: this makes our server touch attacker-controlled
    infrastructure, so every hop is treated as hostile input — no cookies
    are carried between hops, response bodies are never read, non-http
    schemes and malformed Location headers end the walk, and loops break
    on first revisit.
    """
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(
            timeout=REDIRECT_TIMEOUT_S,
            follow_redirects=False,  # we inspect every hop ourselves
        )

    chain: list[str] = [url]
    seen: set[str] = {url}
    current = url
    cross_origin = False
    shortener_hops = 0
    looped = False
    hop_cap_hit = False
    conn_failed = False
    origin_domain = _domain_from_url(url)

    try:
        async with asyncio.timeout(REDIRECT_TOTAL_S):
            for _ in range(MAX_REDIRECTS):
                try:
                    resp = await client.head(
                        current, follow_redirects=False, timeout=REDIRECT_TIMEOUT_S,
                    )
                    if resp.status_code in GET_FALLBACK_STATUSES:
                        # Server rejects HEAD. Streamed GET: status and
                        # headers only — the body is never read.
                        async with client.stream(
                            "GET", current, follow_redirects=False,
                            timeout=REDIRECT_TIMEOUT_S,
                        ) as get_resp:
                            status = get_resp.status_code
                            location = get_resp.headers.get("location", "")
                    else:
                        status = resp.status_code
                        location = resp.headers.get("location", "")
                except httpx.TimeoutException:
                    raise
                except Exception:
                    # Network error on this hop — chain ends here; what we
                    # observed so far is still evidence.
                    conn_failed = True
                    break

                # Never carry cookies into the next hop.
                try:
                    client.cookies.clear()
                except Exception:
                    pass

                if status not in (301, 302, 303, 307, 308):
                    break  # terminal response — chain complete

                next_url = _normalise_location(current, location)
                if next_url is None:
                    break  # malformed or hostile Location header

                if next_url in seen:
                    looped = True
                    break
                seen.add(next_url)

                next_domain = _domain_from_url(next_url)
                if next_domain and next_domain != origin_domain:
                    cross_origin = True

                if any(next_domain.endswith(sd) or next_domain == sd
                       for sd in SHORTENER_DOMAINS_SET):
                    shortener_hops += 1

                chain.append(next_url)
                current = next_url
            else:
                hop_cap_hit = True  # walk ended by the hop cap, not a terminal

        final_url = chain[-1]
        final_domain = _domain_from_url(final_url)
        final_tld = _tld_of(final_domain)

        # ── Score ────────────────────────────────────────────────────────────
        score = 0.0
        reason_parts: list[str] = []

        if shortener_hops > 1:
            score = max(score, 0.35)
            reason_parts.append(
                f"redirect chain passes through {shortener_hops} URL shorteners")
        if cross_origin and shortener_hops >= 1:
            score = max(score, 0.40)
            reason_parts.append("cross-origin hop through a shortener")
        if final_tld in SUSPICIOUS_TLDS and final_url != url:
            score = max(score, 0.30)
            reason_parts.append(f"chain lands on suspicious TLD ({final_tld})")

        orig_tld = _tld_of(origin_domain)
        if orig_tld not in SUSPICIOUS_TLDS and final_tld in SUSPICIOUS_TLDS:
            score = max(score, 0.45)
            reason = (
                f"Open-redirect: starts at {origin_domain!r} "
                f"but ends at {final_domain!r} ({final_tld})"
            )
            return _record(
                "redirect_chain", len(chain) - 1, score, reason,
                chain=chain, final_url=final_url, cross_origin=cross_origin,
                shortener_hops=shortener_hops, looped=looped,
            )

        hops = len(chain) - 1
        if score > 0:
            human = f"Redirect chain ({hops} hop{'s' if hops != 1 else ''}): " + \
                    "; ".join(reason_parts)
        elif looped:
            human = "Redirect chain loops back on itself — obfuscation indicator"
            score = 0.25
        elif conn_failed:
            human = f"Redirect chain ended after {hops} hop{'s' if hops != 1 else ''} (connection failed)"
        elif hop_cap_hit:
            human = f"Redirect chain exceeded {MAX_REDIRECTS} hops — obfuscation indicator"
            score = 0.25
        elif hops == 0:
            human = "URL does not redirect"
        else:
            human = f"Redirect chain of {hops} hop{'s' if hops != 1 else ''} — nothing unusual"

        return _record(
            "redirect_chain", hops, score, human,
            chain=chain, final_url=final_url, cross_origin=cross_origin,
            shortener_hops=shortener_hops, looped=looped,
        )

    except (httpx.TimeoutException, TimeoutError):
        logger.warning("redirect_chain_timeout", url=url)
        return _record(
            "redirect_chain", len(chain) - 1, 0.0,
            "Redirect chain check timed out — not counted",
            "timeout", chain=chain, final_url=current,
            cross_origin=cross_origin, shortener_hops=shortener_hops,
        )
    except Exception as exc:
        logger.debug("redirect_chain_failed", url=url, error=str(exc))
        return _record(
            "redirect_chain", 0, 0.0,
            "Redirect chain check failed — not counted",
            "unavailable", chain=[url], final_url=url,
            cross_origin=False, shortener_hops=0, error=str(exc),
        )
    finally:
        if own_client:
            await client.aclose()


# ═══════════════════════════════════════════════════════════════════════════
# 4.  Parallel orchestrator — gather_signals()
# ═══════════════════════════════════════════════════════════════════════════

def _cached_pair(domain: str) -> Optional[tuple[dict, dict]]:
    entry = _signal_cache.get(domain)
    if entry and entry[0] > time.monotonic():
        return entry[1]
    return None


async def _cert_with_timeout(client: httpx.AsyncClient, domain: str) -> dict:
    return await asyncio.wait_for(
        cert_age_check(domain, client=client), CERT_TIMEOUT_S + 1.0)


async def _dns_with_timeout(client: httpx.AsyncClient, domain: str) -> dict:
    return await asyncio.wait_for(
        dns_asn_check(domain, client=client), DNS_TIMEOUT_S + 1.0)


async def _redirect_with_timeout(client: httpx.AsyncClient, url: str) -> dict:
    """Redirect chains are attacker-rotatable — never cached, hard-capped."""
    try:
        return await asyncio.wait_for(
            redirect_chain_check(url, client=client), REDIRECT_TOTAL_S + 2.0)
    except asyncio.TimeoutError:
        return _record("redirect_chain", 0, 0.0,
                       "Redirect chain check timed out — not counted",
                       "timeout")


async def _guarded(tool_coro, signal: str, label: str) -> dict:
    """
    Run one signal tool inside its own budget and convert ANY failure —
    budget expiry, network timeout, or unexpected crash — into a
    weight-0 trail record. A tool that dies must degrade visibly, never
    silently read as safe (THREAT-MODEL §9.4).
    """
    try:
        return await tool_coro
    except (asyncio.TimeoutError, httpx.TimeoutException):
        return _record(signal, None, 0.0, f"{label} timed out — not counted",
                       "timeout")
    except Exception as exc:
        logger.debug("signal_tool_crashed", signal=signal, error=str(exc))
        return _record(signal, None, 0.0, f"{label} failed — not counted",
                       "unavailable", error=str(exc))


async def gather_signals(url: str, domain: str) -> dict:
    """
    Run the cert-age, DNS/ASN, and redirect checks in parallel, each
    inside its own timeout budget.

    Returns:
      trail        list[dict]  one record per check, in stable order
      total_score  float       sum of weights, capped at 1.0
      reasons      list[str]   human strings for the `reasons` field
    """
    trail: list[dict] = []

    async with httpx.AsyncClient(
        timeout=REDIRECT_TIMEOUT_S,
        follow_redirects=False,
        headers={"User-Agent": "PhishGuard/1.0"},
    ) as client:
        cached = _cached_pair(domain)
        if cached is not None:
            cert_rec, dns_rec = cached
            redirect_rec = await _guarded(
                _redirect_with_timeout(client, url), "redirect_chain",
                "Redirect chain check")
        else:
            # All three tools run concurrently; cert + DNS/ASN are
            # domain-stable and get cached once both land, the redirect
            # chain is attacker-rotatable and never is.
            cert_rec, dns_rec, redirect_rec = await asyncio.gather(
                _guarded(_cert_with_timeout(client, domain), "cert_age",
                         "Certificate age check"),
                _guarded(_dns_with_timeout(client, domain), "dns_asn",
                         "DNS/ASN check"),
                _guarded(_redirect_with_timeout(client, url), "redirect_chain",
                         "Redirect chain check"))
            _signal_cache[domain] = (
                time.monotonic() + SIGNAL_CACHE_TTL_S, (cert_rec, dns_rec))

    trail = [cert_rec, dns_rec, redirect_rec]

    total_score = min(1.0, sum(r.get("weight", 0.0) for r in trail))
    reasons = [r["human_readable"] for r in trail
               if r.get("status") != "ok" or r.get("weight", 0.0) > 0]

    return {
        "trail": trail,
        "total_score": round(total_score, 4),
        "reasons": reasons,
    }
