"""
PhishGuard — Unit Tests: Stage 3 Signals (Phase 1.1)
"""

import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock
from app.services.signals import (
    cert_age_check,
    dns_asn_check,
    redirect_chain_check,
    gather_signals,
    SHORTENER_DOMAINS_SET,
)

@pytest.fixture
def mock_httpx_client(monkeypatch):
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    return mock_client


class TestCertAgeCheck:
    async def test_recent_cert_flags_high_risk(self, mock_httpx_client):
        # 1 hour ago
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        recent_dt = now - datetime.timedelta(hours=1)
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"not_before": recent_dt.isoformat().replace("+00:00", "Z")}]
        mock_httpx_client.get.return_value = mock_resp
        
        res = await cert_age_check("example.com", client=mock_httpx_client)
        assert res["score"] == 0.55
        assert "1.0 h ago" in res["reason"]

    async def test_old_cert_is_safe(self, mock_httpx_client):
        # 1 year ago
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        old_dt = now - datetime.timedelta(days=365)
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"not_before": old_dt.isoformat().replace("+00:00", "Z")}]
        mock_httpx_client.get.return_value = mock_resp
        
        res = await cert_age_check("example.com", client=mock_httpx_client)
        assert res["score"] == 0.0
        assert res["reason"] is None

    async def test_crtsh_timeout(self, mock_httpx_client):
        mock_httpx_client.get.side_effect = httpx.TimeoutException("timeout")
        res = await cert_age_check("example.com", client=mock_httpx_client)
        assert res["score"] == 0.0
        assert res["error"] == "crt.sh timed out"


class TestDnsAsnCheck:
    async def test_bulletproof_hosting_flagged(self, mock_httpx_client):
        # DoH response
        doh_resp = MagicMock()
        doh_resp.status_code = 200
        doh_resp.json.return_value = {"Answer": [{"type": 1, "data": "1.2.3.4"}]}
        
        # IPAPI response
        ipapi_resp = MagicMock()
        ipapi_resp.status_code = 200
        ipapi_resp.json.return_value = {"org": "M247 Ltd"}
        
        mock_httpx_client.get.side_effect = [doh_resp, ipapi_resp]
        
        res = await dns_asn_check("example.com", client=mock_httpx_client)
        assert res["score"] == 0.35
        assert "M247 Ltd" in res["reason"]

    async def test_private_ip(self, mock_httpx_client):
        doh_resp = MagicMock()
        doh_resp.status_code = 200
        doh_resp.json.return_value = {"Answer": [{"type": 1, "data": "192.168.1.1"}]}
        mock_httpx_client.get.side_effect = [doh_resp]
        
        res = await dns_asn_check("local.test", client=mock_httpx_client)
        assert res["score"] == 0.30
        assert "private IP" in res["reason"]


class TestRedirectChainCheck:
    async def test_shortener_chain(self, mock_httpx_client):
        # Hop 1: bit.ly -> Hop 2: tinyurl.com -> Hop 3: final
        resp1 = MagicMock()
        resp1.status_code = 301
        resp1.headers = {"location": "https://tinyurl.com/abc"}
        
        resp2 = MagicMock()
        resp2.status_code = 302
        resp2.headers = {"location": "https://example.com/final"}
        
        resp3 = MagicMock()
        resp3.status_code = 200
        
        mock_httpx_client.head.side_effect = [resp1, resp2, resp3]
        
        res = await redirect_chain_check("https://bit.ly/123", client=mock_httpx_client)
        assert res["shortener_hops"] >= 1
        assert res["cross_origin"] is True
        assert res["score"] >= 0.35

    async def test_open_redirect_to_suspicious_tld(self, mock_httpx_client):
        # Legitimate origin redirects to .xyz
        resp1 = MagicMock()
        resp1.status_code = 302
        resp1.headers = {"location": "http://phish.xyz/login"}
        
        resp2 = MagicMock()
        resp2.status_code = 200
        
        mock_httpx_client.head.side_effect = [resp1, resp2]
        
        res = await redirect_chain_check("https://google.com/url?q=http://phish.xyz/login", client=mock_httpx_client)
        assert res["cross_origin"] is True
        assert res["score"] >= 0.45
        assert "Open-redirect" in res["reason"]
