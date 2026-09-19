"""
PhishGuard — Integration Tests: Sandbox Crawler (Track B)

The SSRF entry guard and request validation run before any browser
process exists, so these tests hold on machines without playwright
installed. The one live-detonation test is opt-in
(PHISHGUARD_LIVE_DETONATION=1) — it drives a real browser at a real
public URL, never a fixture server: the crawler refuses localhost by
design, so a local fixture would exercise nothing but the refusal
path these tests already cover.
"""

import asyncio
import os
import socket
import sys
import threading
import time
import types

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings, settings
from app.main import app
from app.services import sandbox_crawler
from app.services.sandbox_crawler import (
    SandboxTargetError,
    _assert_public_http_target,
)

client = TestClient(app)


# ── Detonation fakes (no real browsers, no real DNS) ─────────────────────────
# The crawler imports playwright lazily INSIDE detonate_url and resolves it
# from sys.modules on every call, so injecting a fake `playwright.async_api`
# module drives detonations without launching a browser; monkeypatch restores
# sys.modules at teardown. The fake replicates the exact Playwright surface
# the crawler depends on: a route guard invoked per request — including
# redirect hops, which Chromium re-submits through interception — plus an
# on_request observer and close() calls that run even under cancellation.

# Classic public documentation-serving IPs for the fake DNS tables.
PUBLIC_IP = "93.184.216.34"   # example.com — is_global
PUBLIC_IP_2 = "8.8.8.8"
PUBLIC_IP_3 = "1.1.1.1"


class _FakeRoute:
    """Playwright Route stand-in: records the guard's decision."""

    def __init__(self):
        self.aborted = False
        self.continued = False

    async def abort(self, error_code=None):
        self.aborted = True

    async def continue_(self):
        self.continued = True


class _FakeRequest:
    def __init__(self, url, *, is_navigation=True, explode=False):
        self._url = url
        self._is_navigation = is_navigation
        self.frame = None  # main frame
        self._explode = explode

    @property
    def url(self):
        if self._explode:
            raise RuntimeError("hostile request object")
        return self._url

    def is_navigation_request(self):
        return self._is_navigation


class _ActiveBrowsers:
    """Counts browsers alive right now — the resource the semaphore exists
    to bound. Max_seen is the high-water mark the cap is pinned against."""

    def __init__(self):
        self.active = 0
        self.max_seen = 0
        self._lock = threading.Lock()

    def opened(self):
        with self._lock:
            self.active += 1
            self.max_seen = max(self.max_seen, self.active)

    def closed(self):
        with self._lock:
            self.active -= 1


class _FakePage:
    def __init__(self, context):
        self._ctx = context
        self._observer = None

    def on(self, event, callback):
        self._observer = callback

    @property
    def main_frame(self):
        return None  # fake requests carry frame=None (main frame)

    async def goto(self, url, wait_until=None, timeout=None):
        env = self._ctx._env
        await asyncio.sleep(env["goto_delay"](url))
        events = env["events"] or [(url, True)]
        for ev_url, is_nav in events:
            request = _FakeRequest(
                ev_url,
                is_navigation=is_nav,
                explode=(ev_url in env["explode"]),
            )
            if self._observer is not None:
                self._observer(request)
            route = _FakeRoute()
            guard = self._ctx._route_guard
            if guard is not None:
                await guard(route, request)
            env["route_log"].append(
                (ev_url, "aborted" if route.aborted else "continued")
            )
            if route.aborted and is_nav:
                # Chromium surfaces a route-aborted navigation as an error
                # at goto — the crawler maps it to status "unavailable".
                raise env["error_cls"](f"net::ERR_BLOCKED_BY_CLIENT: {ev_url}")

    async def evaluate(self, script):
        return {}

    async def wait_for_timeout(self, ms):
        await asyncio.sleep(0)

    async def screenshot(self, **kwargs):
        return b"\xff\xd8\xff\xe0" + b"\x00" * 16  # tiny well-formed-ish JPEG


class _FakeContext:
    def __init__(self, env):
        self._env = env
        self._route_guard = None

    async def new_page(self):
        return _FakePage(self)

    async def route(self, pattern, handler):
        self._route_guard = handler

    async def close(self):
        pass


class _FakeBrowser:
    def __init__(self, env):
        self._env = env

    async def new_context(self, **kwargs):
        return _FakeContext(self._env)

    async def close(self):
        # Runs from the crawler's `finally` — including during wait_for
        # cancellation — so the slot-release invariant stays observable.
        tracker = self._env.get("tracker")
        if tracker is not None:
            tracker.closed()


class _FakeChromium:
    def __init__(self, env):
        self._env = env

    async def launch(self, **kwargs):
        tracker = self._env.get("tracker")
        if tracker is not None:
            tracker.opened()
        return _FakeBrowser(self._env)


class _FakePlaywrightCM:
    def __init__(self, env):
        self.chromium = _FakeChromium(env)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _install_fake_playwright(
    monkeypatch, *, events=None, goto_delay=None, tracker=None, explode=()
):
    """Inject a fake `playwright.async_api`; returns the env dict so tests
    can read `route_log` after the detonation."""
    env = {
        "events": events,          # list of (url, is_navigation) per detonation
        "goto_delay": goto_delay or (lambda url: 0.0),
        "route_log": [],
        "tracker": tracker,
        "explode": set(explode),
    }

    class FakePlaywrightError(Exception):
        pass

    class FakePlaywrightTimeoutError(FakePlaywrightError):
        pass

    env["error_cls"] = FakePlaywrightError

    fake_module = types.ModuleType("playwright.async_api")
    fake_module.Error = FakePlaywrightError
    fake_module.TimeoutError = FakePlaywrightTimeoutError
    fake_module.async_playwright = lambda: _FakePlaywrightCM(env)

    monkeypatch.setitem(sys.modules, "playwright.async_api", fake_module)
    return env


def _fake_getaddrinfo(table, calls):
    """A getaddrinfo stand-in over a static table; hosts absent from the
    table NXDOMAIN (gaierror). `calls` counts lookups per host so tests can
    pin the per-detonation cache."""

    def fake(host, port=None, *args, **kwargs):
        calls[host] = calls.get(host, 0) + 1
        ips = table.get(host)
        if ips is None:
            raise socket.gaierror(f"[Errno 11004] host not found: {host}")
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 0))
            for ip in ips
        ]

    return fake


def _patch_dns(monkeypatch, table, calls):
    # sandbox_crawler holds `import socket` and calls socket.getaddrinfo at
    # call time (entry guard + route guard); patching the attribute covers
    # both and restores at teardown.
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(table, calls))


class TestSsrfEntryGuard:
    """The guard refuses before launch — no browser process ever starts.

    Each test pins the exact refusal message: the message is the
    product here, telling the investigation agent which guard fired.
    """

    async def _refuse(self, url: str) -> SandboxTargetError:
        with pytest.raises(SandboxTargetError) as exc_info:
            await asyncio.to_thread(_assert_public_http_target, url)
        return exc_info.value

    async def test_non_http_scheme_refused(self):
        exc = await self._refuse("ftp://example.com/")
        assert str(exc) == (
            "scheme 'ftp' is not allowed — only http(s) targets are detonated"
        )

    async def test_missing_host_refused(self):
        exc = await self._refuse("http:///no-host")
        assert str(exc) == "URL has no host"

    async def test_localhost_refused(self):
        exc = await self._refuse("http://localhost/x")
        assert str(exc) == "host 'localhost' is local — refused"

    async def test_dot_localhost_suffix_refused(self):
        exc = await self._refuse("http://sub.localhost/")
        assert str(exc) == "host 'sub.localhost' is local — refused"

    async def test_loopback_ip_refused(self):
        exc = await self._refuse("http://127.0.0.1/x")
        assert str(exc) == (
            "host '127.0.0.1' resolves to a non-public address (127.0.0.1) — refused"
        )

    async def test_private_ip_refused(self):
        exc = await self._refuse("http://192.168.1.1/x")
        assert str(exc) == (
            "host '192.168.1.1' resolves to a non-public address (192.168.1.1) — refused"
        )

    async def test_non_resolving_host_refused(self):
        # Not a real TLD — the resolver must NXDOMAIN (and a fully offline
        # machine also fails to resolve, so the refusal holds either way).
        exc = await self._refuse("http://nonexistent-invalid.phishguard-test/")
        assert str(exc).startswith(
            "host 'nonexistent-invalid.phishguard-test' does not resolve — refused"
        )


class TestDetonateEndpoint:
    """Refused targets surface as 400 — the guard fires inside
    detonate_url before playwright loads, so these pass without
    browsers installed."""

    def _post(self, payload, headers=None):
        return client.post(
            "/api/v1/investigate/detonate",
            json=payload,
            headers=headers or {"X-API-Key": "phishguard-dev-key"},
        )

    def test_local_target_refused_400(self):
        response = self._post({"url": "http://localhost/x"})
        assert response.status_code == 400
        assert response.json()["detail"] == "host 'localhost' is local — refused"

    def test_non_http_scheme_refused_400(self):
        response = self._post({"url": "ftp://example.com/"})
        assert response.status_code == 400
        assert "not allowed" in response.json()["detail"]

    def test_empty_url_refused_400(self):
        # "" clears pydantic (no min_length) but carries no scheme — the
        # guard still refuses it, never a browser launch.
        response = self._post({"url": ""})
        assert response.status_code == 400

    def test_oversized_url_rejected_422(self):
        response = self._post({"url": "https://example.com/" + "a" * 2049})
        assert response.status_code == 422

    def test_extra_fields_rejected_422(self):
        # Same doctrine as the Stage-5 models: extra="forbid". An old or
        # hostile client gets a loud 422, not a silent no-op.
        response = self._post({"url": "https://example.com/", "client_score": 0.9})
        assert response.status_code == 422


class TestDetonateAuth:
    """X-API-Key is enforced only when EXTENSION_API_KEY is configured;
    by default the backend runs in dev mode with auth skipped.

    Every request here targets a refused URL so no browser can ever
    launch, whatever auth decides.
    """

    def _post(self, headers):
        return client.post(
            "/api/v1/investigate/detonate",
            json={"url": "http://localhost/x"},
            headers=headers,
        )

    def test_wrong_key_401(self, monkeypatch):
        monkeypatch.setattr(settings, "EXTENSION_API_KEY", "configured-secret")
        response = self._post({"X-API-Key": "not-the-secret"})
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid API key"

    def test_missing_key_401(self, monkeypatch):
        monkeypatch.setattr(settings, "EXTENSION_API_KEY", "configured-secret")
        response = self._post({})
        assert response.status_code == 401

    def test_correct_key_passes_auth_then_guard_refuses(self, monkeypatch):
        monkeypatch.setattr(settings, "EXTENSION_API_KEY", "configured-secret")
        response = self._post({"X-API-Key": "configured-secret"})
        # Auth passed — the 400 is now the SSRF guard's, not auth's.
        assert response.status_code == 400

    def test_dev_mode_skips_auth(self, monkeypatch):
        monkeypatch.setattr(settings, "EXTENSION_API_KEY", "")
        response = self._post({"X-API-Key": "totally-wrong"})
        # Reached the guard, not a 401 — dev mode lets anything through.
        assert response.status_code == 400


class TestLiveDetonation:
    """Opt-in: drives a real browser at a real public URL. Local fixture
    servers are useless here — the crawler refuses localhost by
    design, so the only honest fixture is the public internet."""

    async def test_public_url_detonates(self):
        pytest.importorskip("playwright")
        if not os.environ.get("PHISHGUARD_LIVE_DETONATION"):
            pytest.skip("set PHISHGUARD_LIVE_DETONATION=1 to drive a real browser")

        from app.services.sandbox_crawler import detonate_url

        target = os.environ.get("PHISHGUARD_DETONATE_URL", "https://example.com/")
        result = await detonate_url(target)

        assert result["url"] == target
        assert result["status"] in ("detonated", "timeout", "unavailable")
        assert result["final_url"]
        assert set(result["redirect"]) == {
            "chain",
            "hops",
            "cross_origin",
            "shortener_hops",
            "looped",
            "hop_cap_hit",
            "blocked_local_requests",
        }
        assert result["reasons"]
        assert result["elapsed_s"] >= 0
        # The screenshot cap is a boundary, not a suggestion — whatever
        # comes back must fit, or have been dropped to None.
        if result["screenshot_base64"] is not None:
            assert result["screenshot_bytes"] <= 4 * 1024 * 1024


class TestDetonationConcurrency:
    """Finding: unbounded Chromium per request.

    The detonation semaphore caps live browsers at
    settings.MAX_CONCURRENT_DETONATIONS (fresh per event loop, so the
    monkeypatched value is what each test's loop sees), and the
    whole-detonation budget actively cancels slow work via
    asyncio.wait_for instead of reporting late.
    """

    async def test_never_more_than_max_browsers_alive(self, monkeypatch):
        tracker = _ActiveBrowsers()
        _install_fake_playwright(
            monkeypatch, goto_delay=lambda url: 0.05, tracker=tracker
        )
        monkeypatch.setattr(settings, "MAX_CONCURRENT_DETONATIONS", 2)
        _patch_dns(monkeypatch, {"public-target.example": [PUBLIC_IP]}, {})

        results = await asyncio.gather(
            *[sandbox_crawler.detonate_url("https://public-target.example/")
              for _ in range(5)]
        )
        assert all(r["status"] == "detonated" for r in results)
        # The cap held... (both slots are taken for ~50ms, far longer than
        # the µs the loop needs to start the tasks, so this is not flaky)
        assert tracker.max_seen <= 2
        assert tracker.max_seen == 2  # ...and parallelism actually happened
        assert tracker.active == 0    # nothing leaked

    async def test_total_budget_cancels_slow_browser(self, monkeypatch):
        tracker = _ActiveBrowsers()
        _install_fake_playwright(
            monkeypatch, goto_delay=lambda url: 5.0, tracker=tracker
        )
        monkeypatch.setattr(settings, "DETONATION_TOTAL_S", 0.3)
        _patch_dns(monkeypatch, {"slow.public.example": [PUBLIC_IP]}, {})

        started = time.monotonic()
        with pytest.raises(asyncio.TimeoutError):
            await sandbox_crawler.detonate_url("https://slow.public.example/")
        elapsed = time.monotonic() - started
        # Cancelled AT the budget (0.3s), not after the fake's 5s of work.
        assert elapsed < 2.0
        # browser.close() ran from the finally during cancellation.
        assert tracker.active == 0

    async def test_slot_released_after_timeout(self, monkeypatch):
        _install_fake_playwright(
            monkeypatch,
            goto_delay=lambda url: 5.0 if "slow" in url else 0.01,
        )
        monkeypatch.setattr(settings, "MAX_CONCURRENT_DETONATIONS", 1)
        monkeypatch.setattr(settings, "DETONATION_TOTAL_S", 0.3)
        _patch_dns(
            monkeypatch,
            {"slow.public.example": [PUBLIC_IP], "fast.public.example": [PUBLIC_IP_2]},
            {},
        )

        with pytest.raises(asyncio.TimeoutError):
            await sandbox_crawler.detonate_url("https://slow.public.example/")
        # Cap is 1: if the timed-out detonation still held its slot, this
        # follow-up would hang forever instead of detonating.
        monkeypatch.setattr(settings, "DETONATION_TOTAL_S", 10.0)
        result = await sandbox_crawler.detonate_url("https://fast.public.example/")
        assert result["status"] == "detonated"

    async def test_queued_detonations_all_complete(self, monkeypatch):
        tracker = _ActiveBrowsers()
        _install_fake_playwright(
            monkeypatch, goto_delay=lambda url: 0.02, tracker=tracker
        )
        monkeypatch.setattr(settings, "MAX_CONCURRENT_DETONATIONS", 1)
        _patch_dns(monkeypatch, {"public-target.example": [PUBLIC_IP]}, {})

        results = await asyncio.gather(
            *[sandbox_crawler.detonate_url("https://public-target.example/")
              for _ in range(4)]
        )
        assert all(r["status"] == "detonated" for r in results)
        assert tracker.max_seen == 1  # strictly serialized

    def test_endpoint_queues_burst_and_never_500s(self, monkeypatch):
        """End-to-end through HTTP with a forced cap below the burst:
        every queued request eventually returns 200, none 500."""
        tracker = _ActiveBrowsers()
        _install_fake_playwright(
            monkeypatch, goto_delay=lambda url: 0.05, tracker=tracker
        )
        monkeypatch.setattr(settings, "MAX_CONCURRENT_DETONATIONS", 1)
        _patch_dns(monkeypatch, {"public-target.example": [PUBLIC_IP]}, {})

        n = 4
        responses = []

        # Enter the client context so all requests share ONE portal event
        # loop — the same topology as production (one loop per uvicorn
        # worker). Without the context manager this starlette build gives
        # each request its own throwaway loop, which would measure the
        # harness instead of the cap.
        with TestClient(app) as burst_client:

            def _hit():
                responses.append(
                    burst_client.post(
                        "/api/v1/investigate/detonate",
                        json={"url": "https://public-target.example/"},
                        headers={"X-API-Key": "phishguard-dev-key"},
                    )
                )

            threads = [threading.Thread(target=_hit) for _ in range(n)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
        assert not any(t.is_alive() for t in threads), "a request hung > 30s"
        assert len(responses) == n
        assert all(r.status_code == 200 for r in responses)
        assert tracker.max_seen == 1  # the cap held end-to-end

    def test_endpoint_total_timeout_maps_to_504(self, monkeypatch):
        """Timeout contract unchanged: an active detonation exceeding
        DETONATION_TOTAL_S is cancelled by wait_for and surfaces as 504,
        not a silent degraded read or a 500."""
        _install_fake_playwright(monkeypatch, goto_delay=lambda url: 5.0)
        monkeypatch.setattr(settings, "DETONATION_TOTAL_S", 0.3)
        _patch_dns(monkeypatch, {"slow.public.example": [PUBLIC_IP]}, {})

        response = client.post(
            "/api/v1/investigate/detonate",
            json={"url": "https://slow.public.example/"},
            headers={"X-API-Key": "phishguard-dev-key"},
        )
        assert response.status_code == 504
        assert response.json()["detail"] == "Detonation exceeded its time budget"


class TestRouteGuardRedirectSsrf:
    """Finding: redirect-phase SSRF. The route guard re-resolves EVERY
    request's host (redirect hops included — Playwright re-enters route
    interception for each hop) and fails CLOSED: private resolutions and
    guard errors abort, never continue. Verdicts are cached per
    detonation. The fake browser replays redirect hops exactly as Chromium
    presents them to the guard."""

    async def _detonate(self, monkeypatch, url, *, events, table, explodes=()):
        env = _install_fake_playwright(monkeypatch, events=events, explode=explodes)
        calls = {}
        _patch_dns(monkeypatch, table, calls)
        result = await sandbox_crawler.detonate_url(url)
        return result, env["route_log"], calls

    async def test_redirect_to_loopback_lookalike_aborted(self, monkeypatch):
        # The verified pivot: public entry → 302 → 127.0.0.1.nip.io.
        result, route_log, _ = await self._detonate(
            monkeypatch,
            "https://entry.public.example/",
            events=[
                ("https://entry.public.example/", True),
                ("http://127.0.0.1.nip.io/", True),
            ],
            table={
                "entry.public.example": [PUBLIC_IP],
                "127.0.0.1.nip.io": ["127.0.0.1"],
            },
        )
        assert route_log == [
            ("https://entry.public.example/", "continued"),
            ("http://127.0.0.1.nip.io/", "aborted"),
        ]
        assert result["redirect"]["blocked_local_requests"] == 1
        assert "http://127.0.0.1.nip.io/" in result["redirect"]["chain"]
        assert result["status"] == "unavailable"
        assert any("private/loopback" in r for r in result["reasons"])

    async def test_redirect_chain_ending_public_allowed(self, monkeypatch):
        result, route_log, _ = await self._detonate(
            monkeypatch,
            "https://entry.public.example/",
            events=[
                ("https://entry.public.example/", True),
                ("https://second.public.example/", True),
            ],
            table={
                "entry.public.example": [PUBLIC_IP],
                "second.public.example": [PUBLIC_IP_2],
            },
        )
        assert route_log == [
            ("https://entry.public.example/", "continued"),
            ("https://second.public.example/", "continued"),
        ]
        assert result["redirect"]["blocked_local_requests"] == 0
        assert result["redirect"]["hops"] == 1
        assert result["status"] == "detonated"

    async def test_unresolvable_redirect_host_aborted(self, monkeypatch):
        # DNS failure mid-chain = cannot classify → refuse (fail closed).
        result, route_log, _ = await self._detonate(
            monkeypatch,
            "https://entry.public.example/",
            events=[
                ("https://entry.public.example/", True),
                ("https://no-such-host.example/", True),
            ],
            table={"entry.public.example": [PUBLIC_IP]},  # second host NXDOMAINs
        )
        assert route_log == [
            ("https://entry.public.example/", "continued"),
            ("https://no-such-host.example/", "aborted"),
        ]
        assert result["status"] == "unavailable"
        # Refused, but not counted as private probing — a DNS failure is
        # not evidence the destination was private.
        assert result["redirect"]["blocked_local_requests"] == 0

    async def test_same_host_resolves_once_per_detonation(self, monkeypatch):
        # Navigation + subresources: repeated requests to one host reuse
        # the cached verdict instead of re-resolving.
        result, route_log, calls = await self._detonate(
            monkeypatch,
            "https://site.public.example/",
            events=[
                ("https://site.public.example/", True),
                ("https://site.public.example/app.js", False),
                ("https://cdn.public.example/x.png", False),
                ("https://cdn.public.example/y.png", False),
            ],
            table={
                "site.public.example": [PUBLIC_IP],
                "cdn.public.example": [PUBLIC_IP_3],
            },
        )
        # Entry host: 1 entry-guard lookup + 1 route-guard lookup, then
        # cached. CDN host: two subresource requests, ONE guard lookup.
        assert calls == {"site.public.example": 2, "cdn.public.example": 1}
        assert all(action == "continued" for _, action in route_log)
        assert result["redirect"]["blocked_local_requests"] == 0

    async def test_guard_error_fails_closed_never_continues(self, monkeypatch):
        # A request object that raises inside the guard must be aborted —
        # the old except-path called route.continue_() (fail OPEN).
        result, route_log, _ = await self._detonate(
            monkeypatch,
            "https://entry.public.example/",
            events=[
                ("https://entry.public.example/", True),
                ("https://exploding.object.example/", True),
            ],
            table={"entry.public.example": [PUBLIC_IP]},
            explodes=("https://exploding.object.example/",),
        )
        assert route_log == [
            ("https://entry.public.example/", "continued"),
            ("https://exploding.object.example/", "aborted"),
        ]
        assert result["status"] == "unavailable"

    async def test_websocket_to_loopback_aborted(self, monkeypatch):
        # Scheme-gate regression: the guard classifies ANY URL carrying a
        # hostname, whatever its scheme — a ws:// request to loopback must
        # abort, not fall through to continue_ (the old http(s)-only gate
        # failed open here). A WebSocket upgrade is a subresource, not a
        # navigation request, so the entry page still detonates.
        result, route_log, _ = await self._detonate(
            monkeypatch,
            "https://entry.public.example/",
            events=[
                ("https://entry.public.example/", True),
                ("ws://127.0.0.1:9999/", False),
            ],
            table={"entry.public.example": [PUBLIC_IP]},
        )
        assert route_log == [
            ("https://entry.public.example/", "continued"),
            ("ws://127.0.0.1:9999/", "aborted"),
        ]
        assert result["redirect"]["blocked_local_requests"] == 1
        assert result["status"] == "detonated"
        assert any("private/loopback" in r for r in result["reasons"])


class TestDetonationConfigValidation:
    """Finding: degenerate detonation bounds. A 0 concurrency cap hangs
    every detonation on a semaphore that never opens; a 0 total budget
    504s every request; negatives crash at first use. Both fields carry
    gt=0, so a misconfig raises a clear validation error at startup
    instead of failing at the first request."""

    def test_zero_concurrency_cap_rejected(self):
        with pytest.raises(ValidationError):
            Settings(MAX_CONCURRENT_DETONATIONS=0)
