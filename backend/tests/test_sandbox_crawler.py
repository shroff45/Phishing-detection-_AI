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

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.services.sandbox_crawler import (
    SandboxTargetError,
    _assert_public_http_target,
)

client = TestClient(app)


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
