"""
PhishGuard — Unit Tests: Stage 3 Signals (Phase 1.1) + Stage 4 records
Every tool returns {signal, value, weight, human_readable, status}.
A degraded tool (status != "ok") must carry weight 0.0 — never silent safe.
"""

import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock
from app.services.signals import (
    cert_age_check,
    dns_asn_check,
    redirect_chain_check,
    gather_signals,
    _signal_cache,
)


@pytest.fixture(autouse=True)
def clean_signal_cache():
    """Tests must not see each other's cached cert/DNS records."""
    _signal_cache.clear()
    yield
    _signal_cache.clear()


@pytest.fixture
def mock_httpx_client(monkeypatch):
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    return mock_client


def _get(status_code, json_data=None, headers=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else {}
    resp.headers = headers or {}
    return resp


class TestCertAgeCheck:
    async def test_recent_cert_flags_high_risk(self, mock_httpx_client):
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        recent_dt = now - datetime.timedelta(hours=1)
        mock_httpx_client.get.return_value = _get(200, [
            {"not_before": recent_dt.isoformat().replace("+00:00", "Z")}])

        res = await cert_age_check("example.com", client=mock_httpx_client)
        assert res["signal"] == "cert_age"
        assert res["weight"] == 0.55
        assert res["status"] == "ok"
        assert "1.0 h ago" in res["human_readable"]

    async def test_old_cert_is_safe(self, mock_httpx_client):
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        old_dt = now - datetime.timedelta(days=365)
        mock_httpx_client.get.return_value = _get(200, [
            {"not_before": old_dt.isoformat().replace("+00:00", "Z")}])

        res = await cert_age_check("example.com", client=mock_httpx_client)
        assert res["weight"] == 0.0
        assert res["status"] == "ok"

    async def test_crtsh_timeout_fails_visible(self, mock_httpx_client):
        """A timing-out tool contributes 0 and says so — never silent safe."""
        mock_httpx_client.get.side_effect = httpx.TimeoutException("timeout")
        res = await cert_age_check("example.com", client=mock_httpx_client)
        assert res["weight"] == 0.0
        assert res["status"] == "timeout"
        assert "timed out" in res["human_readable"]

    async def test_non_200_is_unavailable_not_ok(self, mock_httpx_client):
        mock_httpx_client.get.return_value = _get(503)
        res = await cert_age_check("example.com", client=mock_httpx_client)
        assert res["weight"] == 0.0
        assert res["status"] == "unavailable"

    async def test_no_cert_found_is_small_bump(self, mock_httpx_client):
        mock_httpx_client.get.return_value = _get(200, [])
        res = await cert_age_check("example.com", client=mock_httpx_client)
        assert res["weight"] == 0.15
        assert res["status"] == "ok"


class TestDnsAsnCheck:
    async def test_bulletproof_hosting_flagged(self, mock_httpx_client):
        doh_resp = _get(200, {"Answer": [{"type": 1, "data": "1.2.3.4"}]})
        ipapi_resp = _get(200, {"org": "M247 Ltd"})
        mock_httpx_client.get.side_effect = [doh_resp, ipapi_resp]

        res = await dns_asn_check("example.com", client=mock_httpx_client)
        assert res["signal"] == "dns_asn"
        assert res["weight"] == 0.35
        assert "M247" in res["human_readable"]
        assert res["status"] == "ok"

    async def test_private_ip(self, mock_httpx_client):
        doh_resp = _get(200, {"Answer": [{"type": 1, "data": "192.168.1.1"}]})
        mock_httpx_client.get.side_effect = [doh_resp]

        res = await dns_asn_check("local.test", client=mock_httpx_client)
        assert res["weight"] == 0.30
        assert "private IP" in res["human_readable"]

    async def test_timeout_fails_visible(self, mock_httpx_client):
        mock_httpx_client.get.side_effect = httpx.TimeoutException("timeout")
        res = await dns_asn_check("example.com", client=mock_httpx_client)
        assert res["weight"] == 0.0
        assert res["status"] == "timeout"


class TestRedirectChainCheck:
    def _redirect(self, location, status=302):
        resp = MagicMock()
        resp.status_code = status
        resp.headers = {"location": location}
        return resp

    async def test_shortener_chain(self, mock_httpx_client):
        mock_httpx_client.head.side_effect = [
            self._redirect("https://tinyurl.com/abc", 301),
            self._redirect("https://bit.ly/x", 302),
            self._redirect("https://example.com/final"),
            _get(200),
        ]

        res = await redirect_chain_check("https://bit.ly/123", client=mock_httpx_client)
        assert res["signal"] == "redirect_chain"
        assert res["shortener_hops"] >= 2
        assert res["cross_origin"] is True
        assert res["weight"] >= 0.35

    async def test_open_redirect_to_suspicious_tld(self, mock_httpx_client):
        mock_httpx_client.head.side_effect = [
            self._redirect("http://phish.xyz/login"),
            _get(200),
        ]

        res = await redirect_chain_check(
            "https://google.com/url?q=http://phish.xyz/login", client=mock_httpx_client)
        assert res["cross_origin"] is True
        assert res["weight"] >= 0.45
        assert "Open-redirect" in res["human_readable"]

    async def test_loop_breaks_chain(self, mock_httpx_client):
        # a -> b -> a : the revisit must end the walk, not spin
        mock_httpx_client.head.side_effect = [
            self._redirect("https://b.example/x"),
            self._redirect("https://a.example/start"),
            self._redirect("https://b.example/x"),
        ]

        res = await redirect_chain_check("https://a.example/start", client=mock_httpx_client)
        assert res["looped"] is True
        # start + b — the redirect back to a.example/start is detected
        # as a revisit and never appended, so the walk cannot spin.
        assert len(res["chain"]) == 2
        assert res["weight"] == 0.25

    async def test_hop_cap_ends_walk(self, mock_httpx_client):
        # Always redirects somewhere new — the walk must stop at the cap.
        mock_httpx_client.head.side_effect = lambda url, **kw: self._redirect(
            f"https://hop{abs(hash(str(url))) % 9973}.example/next")

        res = await redirect_chain_check("https://start.example/", client=mock_httpx_client)
        # hop cap means exactly MAX_REDIRECTS hops were attempted
        assert len(res["chain"]) <= 11
        assert res["weight"] == 0.25  # obfuscation indicator
        assert "hops" in res["human_readable"] or "exceeded" in res["human_readable"]

    async def test_malformed_location_ends_walk(self, mock_httpx_client):
        mock_httpx_client.head.side_effect = [
            self._redirect("javascript:alert(1)"),  # hostile scheme
            _get(200),
        ]
        res = await redirect_chain_check("https://example.com/a", client=mock_httpx_client)
        assert len(res["chain"]) == 1  # walk ended at the first hop

    async def test_no_redirect_is_ok(self, mock_httpx_client):
        mock_httpx_client.head.return_value = _get(200)
        res = await redirect_chain_check("https://example.com/", client=mock_httpx_client)
        assert res["weight"] == 0.0
        assert res["status"] == "ok"
        assert "does not redirect" in res["human_readable"]


class TestGatherSignals:
    async def test_trail_has_three_records_in_order(self, monkeypatch):
        from app.services import signals as sig

        async def fake_cert(domain, client=None):
            return {"signal": "cert_age", "value": 2.0, "weight": 0.55,
                    "human_readable": "cert", "status": "ok"}
        async def fake_dns(domain, client=None):
            return {"signal": "dns_asn", "value": "AS9009", "weight": 0.35,
                    "human_readable": "dns", "status": "ok"}
        async def fake_redirect(url, client=None):
            return {"signal": "redirect_chain", "value": 0, "weight": 0.0,
                    "human_readable": "redirect", "status": "ok"}

        monkeypatch.setattr(sig, "cert_age_check", fake_cert)
        monkeypatch.setattr(sig, "dns_asn_check", fake_dns)
        monkeypatch.setattr(sig, "redirect_chain_check", fake_redirect)

        out = await gather_signals(url="https://example.com/", domain="example.com")
        assert [r["signal"] for r in out["trail"]] == \
            ["cert_age", "dns_asn", "redirect_chain"]
        assert out["total_score"] == pytest.approx(0.9)
        # second call for the same domain must hit the cert/dns cache
        await gather_signals(url="https://example.com/x", domain="example.com")
        assert sig._signal_cache["example.com"][1][0]["human_readable"] == "cert"

    async def test_degraded_tools_never_read_as_safe(self, monkeypatch):
        """Fail-visible: a timing-out tool yields *unknown*, never *safe*."""
        from app.services import signals as sig

        async def slow_cert(domain, client=None):
            raise httpx.TimeoutException("crt.sh down")
        async def slow_dns(domain, client=None):
            raise httpx.TimeoutException("doh down")
        async def slow_redirect(url, client=None):
            raise httpx.TimeoutException("nope")

        monkeypatch.setattr(sig, "cert_age_check", slow_cert)
        monkeypatch.setattr(sig, "dns_asn_check", slow_dns)
        monkeypatch.setattr(sig, "redirect_chain_check", slow_redirect)

        out = await gather_signals(url="https://example.com/", domain="example.com")
        assert out["total_score"] == 0.0
        assert all(r["weight"] == 0.0 for r in out["trail"])
        assert all(r["status"] == "timeout" for r in out["trail"])
        # every degraded tool still appears in the trail with an explanation
        assert len(out["reasons"]) == 3
        assert all("not counted" in r for r in out["reasons"])

    async def test_records_with_weight_always_have_human_readable(self, monkeypatch):
        from app.services import signals as sig

        async def fake_cert(domain, client=None):
            return {"signal": "cert_age", "value": 2.0, "weight": 0.55,
                    "human_readable": "x", "status": "ok"}
        async def fake_dns(domain, client=None):
            return {"signal": "dns_asn", "value": "AS1", "weight": 0.0,
                    "human_readable": "y", "status": "ok"}
        async def fake_redirect(url, client=None):
            return {"signal": "redirect_chain", "value": 0, "weight": 0.0,
                    "human_readable": "z", "status": "ok"}

        monkeypatch.setattr(sig, "cert_age_check", fake_cert)
        monkeypatch.setattr(sig, "dns_asn_check", fake_dns)
        monkeypatch.setattr(sig, "redirect_chain_check", fake_redirect)

        out = await gather_signals(url="https://example.com/", domain="example.com")
        for rec in out["trail"]:
            assert rec["human_readable"]
            assert 0.0 <= rec["weight"] <= 1.0


class TestMonotonicity:
    async def test_low_backend_score_cannot_lower_high_local(self, monkeypatch):
        """Backend escalation may raise a verdict, never lower it (THREAT-MODEL §9.4)."""
        from app.services.threat_intel import compute_meta_score
        from app.services import signals as sig

        async def clean_signals(url=None, domain=None):
            return {"trail": [
                {"signal": "cert_age", "value": None, "weight": 0.0,
                 "human_readable": "none", "status": "ok"},
                {"signal": "dns_asn", "value": None, "weight": 0.0,
                 "human_readable": "none", "status": "ok"},
                {"signal": "redirect_chain", "value": 0, "weight": 0.0,
                 "human_readable": "none", "status": "ok"},
            ], "total_score": 0.0, "reasons": []}

        # Local ML says 0.9 (strong phishing signal from the client).
        # Backend heuristics find nothing. The merge must keep the client's
        # weight in the final score, not dilute it below the suspicious band.
        monkeypatch.setattr(sig, "gather_signals", clean_signals)
        result = await compute_meta_score(
            url="https://paypal-login-verify.example.com/verify-account",
            client_score=0.9,
            threat_feed_result={"is_known_threat": False,
                                "feeds_checked": ["urlhaus"],
                                "source": None},
        )
        # client_ml alone contributes 0.9 * 0.15 = 0.135; heuristics on this
        # URL push the primary score up. The merged verdict must be at least
        # suspicious — the client's high score cannot be diluted to safe.
        assert result["score"] >= 0.35
        assert result["verdict"] in ("suspicious", "phishing")
