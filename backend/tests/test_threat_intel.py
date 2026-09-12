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


class TestWhitelistShortCircuit:
    """Whitelisted domains still record the raw model score — Stage 4.

    The whitelist still wins the blocking decision (is_known_threat stays
    False); raw_model_score is recorded alongside it so the agentic
    monitoring layer can detect anomalies (whitelisted domain suddenly
    scoring ~1.0 ⇒ takeover / DNS poisoning). The whitelist path is pure
    — it returns before any network I/O — so these tests are offline-safe.
    """

    async def test_whitelist_match_records_raw_score(self):
        result = await threat_intel.check_threat_feeds(
            "https://www.google.com/", client_score=0.796)
        assert result["whitelist_match"] is True
        assert result["raw_model_score"] == pytest.approx(0.796)
        assert result["is_known_threat"] is False
        assert result["source"] == "whitelist"

    async def test_subdomain_of_whitelisted_domain_matches(self):
        result = await threat_intel.check_threat_feeds(
            "https://accounts.google.com/signin", client_score=0.12)
        assert result["whitelist_match"] is True
        assert result["raw_model_score"] == pytest.approx(0.12)

    async def test_client_score_clamped_to_unit_range(self):
        result = await threat_intel.check_threat_feeds(
            "https://github.com/login", client_score=7.0)
        assert result["whitelist_match"] is True
        assert result["raw_model_score"] == 1.0

    async def test_default_client_score_is_zero_never_alarming(self):
        # No score supplied → 0.0, which can never trigger a false anomaly.
        result = await threat_intel.check_threat_feeds("https://www.google.com/")
        assert result["whitelist_match"] is True
        assert result["raw_model_score"] == 0.0

    async def test_non_whitelisted_url_has_uniform_schema(self, monkeypatch):
        # Offline: stub the three feed checks so no network I/O happens.
        async def stub(client, url):
            return {"flagged": False}

        monkeypatch.setattr(threat_intel, "_check_urlhaus", stub)
        monkeypatch.setattr(threat_intel, "_check_virustotal", stub)
        monkeypatch.setattr(threat_intel, "_check_google_safe_browsing", stub)

        result = await threat_intel.check_threat_feeds(
            "https://example.org/login", client_score=0.42)
        assert result["whitelist_match"] is False
        assert result["raw_model_score"] == pytest.approx(0.42)
        assert result["is_known_threat"] is False

    async def test_whitelist_trail_record_weight_zero(self):
        # The evidence-trail record reports the score but moves none of it.
        meta = await compute_meta_score(
            url="https://www.google.com/",
            client_score=0.1,
            threat_feed_result={
                "is_known_threat": False,
                "source": "whitelist",
                "feeds_checked": ["whitelist"],
                "feeds_flagged": [],
                "whitelist_match": True,
                "raw_model_score": 0.796,
            })
        wl = [r for r in meta["evidence_trail"] if r["signal"] == "whitelist"]
        assert len(wl) == 1
        assert wl[0]["weight"] == 0.0
        assert wl[0]["status"] == "ok"
        assert "0.80" in wl[0]["human_readable"]
