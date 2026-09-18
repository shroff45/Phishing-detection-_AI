"""
PhishGuard Backend — Tier 2 Headless Sandbox Crawler (Track B)
Safe, isolated detonation of suspicious URLs for the investigation agent.

The service worker's lexical pass (Tier 1) never fetches attacker
content. This module is where the backend finally lets a suspicious
URL execute — inside a throwaway headless Chromium that holds no
credentials, shares no state, and reaches no internal services.

Security posture (each rule is a hard boundary, not a preference):

  • Fresh context per detonation — a new browser, new profile, no
    cookies, no storage, no extensions. Nothing crosses detonations.
    Costs ~1s of launch latency; correctness over throughput.

  • Detonations are never cached — an attacker can rotate a
    destination between two navigations (same rule as signals.py).

  • SSRF is refused, not mitigated — the entry URL must resolve to
    a public address, and every request from the page to a literal
    private/loopback host is aborted mid-flight. The sandbox has no
    ambient credentials, but it must not become a probe of the
    backend's own localhost surface either. Residual risk: a DNS
    rebinding target that resolves public at the entry check and
    private at request time is only caught after the fact — noted in
    the result, never silently passed.

  • Screenshots are sanitized — form field values are blanked and
    password/file inputs removed from the DOM before capture, and
    the JPEG is hard-capped so an attacker page cannot balloon the
    payload. A screenshot that will not fit is dropped, not shrunk.

  • Degraded reads as unknown — a timed-out or crashed check gets
    status "timeout"/"unavailable" and empty evidence. A failed
    detonation must never read as a clean one.

  • Response bodies stay in the sandbox — the only artifacts that
    leave are the redirect chain (URLs only), the DOM telemetry
    object, and the capped screenshot.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import socket
import time
from typing import Optional
from urllib.parse import urlsplit

import structlog

from app.services.signals import SHORTENER_DOMAINS_SET

logger = structlog.get_logger(__name__)

# ── Budgets (seconds) ────────────────────────────────────────────────────────
# Mirrors the signals.py doctrine: every tool hard-capped, one slow
# detonation cannot consume the event loop.
PAGE_LOAD_TIMEOUT_S = 15.0   # single page.goto budget
SETTLE_S = 2.0               # JS settle window before telemetry capture
DETONATION_TOTAL_S = 30.0    # independent cap for the whole detonation

# ── Redirects ────────────────────────────────────────────────────────────────
MAX_REDIRECTS = 10           # must match signals.MAX_REDIRECTS

# ── Screenshot cap ────────────────────────────────────────────────────────────
# Raw JPEG cap. base64 expands 4/3, so the wire form stays well under
# main.py's 8 MiB screenshot envelope. Oversize → dropped, not resized.
SCREENSHOT_MAX_BYTES = 4 * 1024 * 1024
SCREENSHOT_JPEG_QUALITY = 60

# ── Sandbox fingerprint ──────────────────────────────────────────────────────
# Deliberately NOT a stealth browser: the crawler identifies itself.
SANDBOX_USER_AGENT = "PhishGuardSandbox/1.0 (+sandboxed-detonation)"
VIEWPORT = {"width": 1280, "height": 800}


class SandboxTargetError(ValueError):
    """Target refused BEFORE launch — non-HTTP(S) scheme or a
    private/loopback/reserved address. Client error, not a crash."""


# ── SSRF guard ────────────────────────────────────────────────────────────────
def _ip_is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Explicit chain (not just `not is_private`) — same doctrine as
    signals._is_private_ip: reserved, link-local, multicast and
    unspecified are all refused even though `is_private` alone would
    let some of them through."""
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ) and ip.is_global


def _host_is_obviously_local(host: Optional[str]) -> bool:
    """Fast literal check used per-request inside the route guard —
    no DNS in the request path (the entry guard did the resolution).
    Hostnames are left to the entry guard; DNS rebinding after the
    entry check is a documented residual, flagged in the result."""
    if not host:
        return False
    h = host.lower()
    if h == "localhost" or h.endswith(".localhost") or h.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False  # a hostname — verdict unknown here, entry guard resolved it
    return not _ip_is_public(ip)


def _assert_public_http_target(url: str) -> None:
    """Refuse before launch. Runs in a worker thread (getaddrinfo
    blocks). Raises SandboxTargetError on any refusal."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise SandboxTargetError(
            f"scheme {parts.scheme!r} is not allowed — only http(s) targets are detonated"
        )
    host = parts.hostname
    if not host:
        raise SandboxTargetError("URL has no host")

    if host.lower() == "localhost" or host.lower().endswith((".localhost", ".local")):
        raise SandboxTargetError(f"host {host!r} is local — refused")

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise SandboxTargetError(f"host {host!r} does not resolve — refused ({exc})")

    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue  # not an IP literal form getaddrinfo produced — skip
        if not _ip_is_public(ip):
            raise SandboxTargetError(
                f"host {host!r} resolves to a non-public address ({ip_str}) — refused"
            )


# ── Shortener counting (chain analysis only — the crawler observes,
#    it does not score; scoring stays with the meta-score pipeline) ──────────
def _shortener_hops_of(chain: list[str]) -> int:
    hops = 0
    for u in chain[1:]:
        host = (urlsplit(u).hostname or "").lower()
        if any(host == sd or host.endswith("." + sd) for sd in SHORTENER_DOMAINS_SET):
            hops += 1
    return hops


# ── In-page JS (mirrors extension/content/content-script.js — same
#    signal names, same thresholds, so backend telemetry and the
#    client-side boost agree on what a BitB page is) ─────────────────────────

# Installed right after goto: counts DOM mutations during the settle
# window (content script: >200 in 3s → rapidDomMutations; here the
# settle window is 2s, so the same 200-mutation bar is stricter).
_OBSERVER_JS = """
() => {
  window.__pgMutations = 0;
  try {
    const t0 = Date.now();
    const obs = new MutationObserver((m) => {
      window.__pgMutations += m.length;
      if (Date.now() - t0 > 3000) obs.disconnect();
    });
    obs.observe(document.body || document.documentElement,
                { childList: true, subtree: true, attributes: true });
    window.__pgObs = obs;
  } catch (e) {}
  return true;
}
"""

# The telemetry payload. Every block is its own try/catch — one
# hostile DOM quirk must not zero out the rest of the evidence.
_TELEMETRY_JS = """
() => {
  const BRAND_KEYWORDS = {
    google:    ["google", "gmail", "sign in to google", "one account. all of google"],
    microsoft: ["microsoft", "outlook", "sign in to your account", "xbox", "office 365"],
    paypal:    ["paypal", "send money", "pay after delivery"],
    apple:     ["apple id", "icloud", "app store", "itunes"],
    facebook:  ["facebook", "log into facebook", "create new account"],
    amazon:    ["amazon", "sign-in", "your orders"],
    netflix:   ["netflix", "sign in", "unlimited movies"],
    instagram: ["instagram", "log in to instagram"],
    twitter:   ["twitter", "log in to x", "sign in to x"],
    linkedin:  ["linkedin", "sign in", "join now"],
  };
  const s = {
    hasBitB: false, bitbScore: 0, fakeTitleBar: false, fakeUrlBar: false,
    fakeCloseButton: false, hasPasswordField: false, formCount: 0,
    externalFormAction: false, hiddenInputCount: 0, autoCompleteOff: false,
    suspiciousIframes: 0, invisibleOverlays: 0, dataUriImages: 0,
    hasClipboardHijack: false, rapidDomMutations: false, domCloaking: false,
    fakeSslIndicator: false, rightClickDisabled: false,
    textSelectionDisabled: false, hasLoginKeywords: false,
    hasBrandImpersonation: false, brandDetected: null,
  };

  try {  // BitB geometry — thresholds identical to the content script
    let score = 0;
    for (const el of document.querySelectorAll("*")) {
      const style = window.getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      if ((style.position === "fixed" || style.position === "absolute") &&
          rect.height >= 20 && rect.height <= 45 && rect.top <= 10 &&
          rect.width > window.innerWidth * 0.3) {
        const text = el.textContent || "";
        const hasControls = /[\\u2715\\u2716\\u00d7\\u2717\\u2613]/.test(text) ||
          el.querySelectorAll('[class*="close"], [class*="minimize"], [class*="maximize"]').length > 0;
        if (hasControls || style.cursor === "grab" || style.cursor === "move" ||
            el.getAttribute("draggable") === "true") {
          s.fakeTitleBar = true; score += 2;
        }
      }
      if ((el.tagName === "INPUT" || el.tagName === "DIV" || el.tagName === "SPAN") &&
          (style.position === "absolute" || style.position === "fixed")) {
        const content = (el.textContent || el.value || "").trim();
        if (/^https?:\\/\\//.test(content) && rect.width > 200) {
          s.fakeUrlBar = true; score += 3;
        }
      }
      if ((style.position === "absolute" || style.position === "fixed") &&
          rect.width <= 60 && rect.height <= 40) {
        const text = (el.textContent || "").trim();
        if (/^[\\u2715\\u2716\\u00d7\\u2717\\u2500\\u25a1\\u2610\\u25a2]$/.test(text) ||
            /^[xX_\\-\\[\\]]$/.test(text)) {
          s.fakeCloseButton = true; score += 1;
        }
      }
      if (el.tagName === "SVG" || el.tagName === "IMG" || el.tagName === "I") {
        const cls = (el.className || "").toString().toLowerCase();
        const src = (el.getAttribute("src") || "").toLowerCase();
        if ((cls.includes("lock") || cls.includes("secure") ||
             src.includes("lock") || src.includes("padlock")) &&
            (style.position === "absolute" || style.position === "fixed")) {
          s.fakeSslIndicator = true; score += 2;
        }
      }
    }
    for (const iframe of document.querySelectorAll("iframe")) {
      const style = window.getComputedStyle(iframe);
      const rect = iframe.getBoundingClientRect();
      if ((style.position === "fixed" || style.position === "absolute") &&
          parseInt(style.zIndex) > 999 && rect.width >= 300 && rect.height >= 400) {
        s.suspiciousIframes++; score += 2;
      }
    }
    s.bitbScore = score;
    if (score >= 4) s.hasBitB = true;
  } catch (e) {}

  try {  // forms / credential harvesting
    const forms = document.querySelectorAll("form");
    s.formCount = forms.length;
    for (const form of forms) {
      const pwFields = form.querySelectorAll('input[type="password"]');
      if (pwFields.length > 0) s.hasPasswordField = true;
      const action = form.getAttribute("action");
      if (action) {
        try {
          const actionUrl = new URL(action, window.location.href);
          if (actionUrl.hostname !== window.location.hostname) s.externalFormAction = true;
        } catch (e2) {}
      }
      s.hiddenInputCount += form.querySelectorAll('input[type="hidden"]').length;
      for (const pw of pwFields) {
        if (pw.getAttribute("autocomplete") === "off" ||
            pw.getAttribute("autocomplete") === "new-password") s.autoCompleteOff = true;
      }
    }
    if (!s.hasPasswordField) {
      s.hasPasswordField = document.querySelectorAll('input[type="password"]').length > 0;
    }
  } catch (e) {}

  try {  // cloaking / obfuscation
    for (const el of document.querySelectorAll("div, a, iframe")) {
      const style = window.getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      if ((style.position === "fixed" || style.position === "absolute") &&
          parseFloat(style.opacity) < 0.1 &&
          rect.width > window.innerWidth * 0.5 &&
          rect.height > window.innerHeight * 0.5 &&
          parseInt(style.zIndex) > 100) {
        s.invisibleOverlays++;
      }
    }
    for (const img of document.querySelectorAll("img")) {
      if (img.src && img.src.startsWith("data:")) s.dataUriImages++;
    }
    if (window.getComputedStyle(document.body).userSelect === "none") {
      s.textSelectionDisabled = true;
    }
    if (document.oncontextmenu &&
        document.oncontextmenu.toString().includes("return false")) {
      s.rightClickDisabled = true;
    }
    if (s.invisibleOverlays > 0 || s.dataUriImages > 5) s.domCloaking = true;
  } catch (e) {}

  try {  // clipboard: sandbox variant — the content script waits for the
         // page to CALL a patched writeText; here we simply ask whether the
         // method is still native code (a hijack replaces it).
    const fn = navigator.clipboard && navigator.clipboard.writeText;
    s.hasClipboardHijack = !!fn && !fn.toString().includes("[native code]");
  } catch (e) {}

  try {  // mutation count from the observer installed at goto
    if (window.__pgObs) window.__pgObs.disconnect();
    s.rapidDomMutations = (window.__pgMutations || 0) > 200;
  } catch (e) {}

  try {  // brand impersonation — same keyword lists, same >=2 rules
    const pageTitle = (document.title || "").toLowerCase();
    const pageText = ((document.body && document.body.innerText) || "").toLowerCase();
    const combinedText = pageTitle + " " + pageText;
    const loginKeywords = ["sign in", "log in", "login", "password", "email",
                           "username", "forgot password", "create account", "verify"];
    if (loginKeywords.filter(kw => combinedText.includes(kw)).length >= 2) {
      s.hasLoginKeywords = true;
      const hostname = window.location.hostname.toLowerCase();
      for (const [brand, keywords] of Object.entries(BRAND_KEYWORDS)) {
        if (keywords.filter(kw => combinedText.includes(kw)).length >= 2) {
          const isLegit = hostname.includes(brand) ||
            hostname.endsWith("." + brand + ".com") ||
            hostname === brand + ".com";
          if (!isLegit) {
            s.hasBrandImpersonation = true;
            s.brandDetected = brand;
            break;
          }
        }
      }
    }
  } catch (e) {}

  s.title = (document.title || "").slice(0, 300);
  s.hostname = window.location.hostname || "";
  return s;
}
"""

# Screenshots are sanitized, not just capped: every field value is
# blanked and password/file inputs are removed before capture, so a
# half-typed credential (auto-fill, prior page state) can never reach
# the JPEG. Viewport-only capture bounds the size from the start.
_SANITIZE_JS = """
() => {
  try {
    for (const el of document.querySelectorAll("input, textarea")) {
      el.value = "";
      el.setAttribute("value", "");
      el.defaultValue = "";
      el.checked = false;
    }
    for (const p of document.querySelectorAll('input[type="password"], input[type="file"]')) {
      p.remove();
    }
  } catch (e) {}
  return true;
}
"""


# ── Detonation ────────────────────────────────────────────────────────────────
async def detonate_url(url: str) -> dict:
    """
    Detonate `url` in a fresh, isolated headless Chromium context and
    return the evidence bundle for the investigation agent.

    Raises:
      SandboxTargetError — refused before launch (client error).
      TimeoutError        — the whole-detonation budget expired.

    Returns a dict with:
      status              "detonated" | "timeout" | "unavailable"
      final_url           where the chain actually landed
      redirect            {chain, hops, cross_origin, shortener_hops,
                           looped, hop_cap_hit, blocked_local_requests}
      content_signals     DOM telemetry (content-script signal names) or None
      screenshot_base64   sanitized JPEG, or None if dropped/failed
      reasons             human-readable strings (signals.py tone)
      elapsed_s           wall time

    Result is NOT cached — an attacker can rotate a destination
    between two navigations.
    """
    started = time.monotonic()

    # Entry guard — refuses before any browser exists. getaddrinfo
    # blocks, so it runs off the event loop.
    await asyncio.to_thread(_assert_public_http_target, url)

    state: dict = {
        "chain": [],          # every main-frame hop in order
        "seen": set(),        # loop detection, mirrors signals.py
        "looped": False,
        "hop_cap_hit": False,
        "blocked_local": 0,   # requests the route guard refused
    }

    # Doubly-lazy: main.py imports this module inside its handler, and
    # playwright itself loads only here — so a machine without browsers
    # still gets the SSRF entry guard above (→ 400 for refused targets)
    # and only a genuinely-public target maps to ImportError → 503.
    from playwright.async_api import Error as PlaywrightError
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=["--no-first-run", "--disable-dev-shm-usage"],
        )
        try:
            # Fresh context per detonation: no cookies, no storage, no
            # extensions, no shared state with any previous detonation.
            context = await browser.new_context(
                user_agent=SANDBOX_USER_AGENT,
                viewport=VIEWPORT,
                locale="en-US",
                timezone_id="UTC",
            )
            page = await context.new_page()

            def on_request(request) -> None:
                try:  # telemetry only — never let the observer kill the run
                    if not request.is_navigation_request():
                        return
                    frame = request.frame
                    if frame is not None and frame is not page.main_frame:
                        return  # sub-frame navigations are not chain hops
                    hop_url = request.url
                    state["chain"].append(hop_url)
                    if hop_url in state["seen"]:
                        state["looped"] = True
                    state["seen"].add(hop_url)
                    if len(state["chain"]) - 1 >= MAX_REDIRECTS:
                        state["hop_cap_hit"] = True
                except Exception:
                    pass

            page.on("request", on_request)

            async def route_guard(route, request) -> None:
                try:
                    host = urlsplit(request.url).hostname
                    if _host_is_obviously_local(host):
                        # The page tried to reach a private/loopback
                        # target — refuse mid-flight and say so.
                        state["blocked_local"] += 1
                        await route.abort("blockedbyclient")
                        return
                    if (request.is_navigation_request()
                            and len(state["chain"]) > MAX_REDIRECTS):
                        state["hop_cap_hit"] = True
                        await route.abort("blockedbyclient")
                        return
                    await route.continue_()
                except Exception:
                    try:
                        await route.continue_()
                    except Exception:
                        pass

            await context.route("**/*", route_guard)

            # ── navigate ────────────────────────────────────────────────
            status = "detonated"
            goto_error: Optional[str] = None
            try:
                await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=PAGE_LOAD_TIMEOUT_S * 1000,
                )
            except PlaywrightTimeoutError:
                status = "timeout"
                goto_error = "page load timed out"
            except PlaywrightError as exc:
                # Chrome's own refusal (bad DNS, too many redirects,
                # or our route guard's blockedbyclient) lands here.
                status = "unavailable"
                goto_error = str(exc)

            # ── DOM telemetry ────────────────────────────────────────────
            content_signals: Optional[dict] = None
            if status != "unavailable":
                try:
                    await page.evaluate(_OBSERVER_JS)
                    await asyncio.wait_for(
                        page.wait_for_timeout(SETTLE_S * 1000),
                        SETTLE_S + 1.0,
                    )
                    content_signals = await page.evaluate(_TELEMETRY_JS)
                except Exception as exc:
                    logger.debug("dom_telemetry_failed", url=url, error=str(exc))

            # ── sanitized screenshot ─────────────────────────────────────
            screenshot_b64: Optional[str] = None
            screenshot_bytes: Optional[int] = None
            if status != "unavailable":
                try:
                    await page.evaluate(_SANITIZE_JS)
                    shot = await asyncio.wait_for(
                        page.screenshot(
                            type="jpeg",
                            quality=SCREENSHOT_JPEG_QUALITY,
                            full_page=False,
                        ),
                        PAGE_LOAD_TIMEOUT_S,
                    )
                    if len(shot) > SCREENSHOT_MAX_BYTES:
                        # Oversize → dropped, not resized. The cap is a
                        # boundary, not a suggestion.
                        logger.warning(
                            "screenshot_over_cap_dropped",
                            url=url,
                            bytes=len(shot),
                        )
                    else:
                        screenshot_bytes = len(shot)
                        screenshot_b64 = base64.b64encode(shot).decode("ascii")
                except Exception as exc:
                    logger.debug("screenshot_failed", url=url, error=str(exc))

            await context.close()
        finally:
            await browser.close()

    # ── chain analysis (observe-only — no scoring here) ──────────────────
    chain = state["chain"] or [url]
    hops = max(0, len(chain) - 1)
    origin_host = (urlsplit(url).hostname or "").lower()
    final_host = (urlsplit(chain[-1]).hostname or "").lower()
    cross_origin = final_host != origin_host and final_host != ""
    shortener_hops = _shortener_hops_of(chain)

    reasons: list[str] = []
    if state["looped"]:
        reasons.append("Redirect chain loops back on itself — obfuscation indicator")
    if state["hop_cap_hit"]:
        reasons.append(
            f"Redirect chain exceeded {MAX_REDIRECTS} hops — obfuscation indicator"
        )
    if state["blocked_local"]:
        reasons.append(
            f"{state['blocked_local']} request(s) to a private/loopback host refused — "
            "internal probing attempt"
        )
    if shortener_hops > 1:
        reasons.append(f"Redirect chain passes through {shortener_hops} URL shorteners")
    if cross_origin and shortener_hops >= 1:
        reasons.append("Cross-origin redirect chain through a shortener")
    if not reasons:
        if hops == 0:
            reasons.append("URL does not redirect")
        else:
            reasons.append(
                f"Redirect chain of {hops} hop{'s' if hops != 1 else ''} — nothing unusual"
            )

    if status == "timeout":
        reasons.append("Detonation timed out — partial evidence retained")
    if content_signals is None and status != "unavailable":
        reasons.append("DOM telemetry unavailable — not counted")

    elapsed = round(time.monotonic() - started, 2)
    if elapsed >= DETONATION_TOTAL_S:  # budget already spent — stop here
        raise asyncio.TimeoutError()

    result = {
        "url": url,
        "status": status,
        "final_url": chain[-1],
        "goto_error": goto_error,
        "redirect": {
            "chain": chain,
            "hops": hops,
            "cross_origin": cross_origin,
            "shortener_hops": shortener_hops,
            "looped": state["looped"],
            "hop_cap_hit": state["hop_cap_hit"],
            "blocked_local_requests": state["blocked_local"],
        },
        "content_signals": content_signals,
        "screenshot_base64": screenshot_b64,
        "screenshot_bytes": screenshot_bytes,
        "reasons": reasons,
        "elapsed_s": elapsed,
    }

    logger.info(
        "detonation_complete",
        url=url,
        status=status,
        hops=hops,
        cross_origin=cross_origin,
        screenshot=bool(screenshot_b64),
        elapsed_s=elapsed,
    )
    return result
