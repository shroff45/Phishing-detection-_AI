"""
PhishGuard — Unit Tests: Threat Intelligence & Meta-Classifier (Phase 9)
Run:  cd backend && python -m pytest tests/ -v
"""

import time

import pytest
from app.services import threat_intel
from app.services.threat_intel import compute_meta_score, _extract_url_signals

class TestUrlSignals:
    def test_safe_url(self):
        score, reasons = _extract_url_signals("https://www.google.com/search?q=hello")
        assert score < 0.3

    def test_ip_address_url(self):
        score, reasons = _extract_url_signals("http://192.168.1.1/login.php")
        assert score >= 0.3
        assert any("IP address" in r for r in reasons)

    def test_suspicious_tld(self):
        score, reasons = _extract_url_signals("http://secure-login.xyz/verify")
        assert score >= 0.2

class TestMetaClassifier:
    async def test_all_signals_safe(self):
        result = await compute_meta_score(url="https://www.google.com/", client_score=0.1, threat_feed_result={"is_known_threat": False})
        assert result["verdict"] == "safe"
        assert result["score"] < 0.4

    async def test_known_threat(self):
        result = await compute_meta_score(url="http://phishing-site.tk/login", client_score=0.8, threat_feed_result={"is_known_threat": True, "source": "urlhaus"})
        assert result["verdict"] == "phishing"
        assert result["score"] >= 0.7


class TestWhoisDegradation:
    async def test_unavailable_whois_is_surfaced_not_silent(self, monkeypatch):
        """A failed lookup must not silently add risk — THREAT-MODEL section 9.4."""
        monkeypatch.setattr(threat_intel, "WHOIS_AVAILABLE", False)
        threat_intel._whois_cache.clear()
        score, reason = await threat_intel._check_domain_age("example.com")
        assert score == 0.0
        assert reason is not None and "unavailable" in reason.lower()

    async def test_whois_timeout_does_not_raise(self, monkeypatch):
        def hang(domain):
            time.sleep(5)
            return 0.7, "should never be reached"

        monkeypatch.setattr(threat_intel, "WHOIS_AVAILABLE", True)
        monkeypatch.setattr(threat_intel, "WHOIS_TIMEOUT_SECONDS", 0.1)
        monkeypatch.setattr(threat_intel, "_whois_domain_age", hang)
        threat_intel._whois_cache.clear()
        score, reason = await threat_intel._check_domain_age("slow-whois.example")
        assert score == 0.0
        assert "timed out" in reason
