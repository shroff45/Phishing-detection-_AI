"""
PhishGuard — Integration Tests: API Endpoints (Phase 9)
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

class TestHealthEndpoint:
    def test_health_returns_200(self):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

class TestQuickAnalyze:
    def test_quick_safe_url(self):
        response = client.post("/api/v1/analyze/quick",
            json={
                "url": "https://www.google.com/",
                "client_score": 0.1,
            },
            headers={"X-API-Key": "phishguard-dev-key"}
        )
        assert response.status_code == 200
        assert "verdict" in response.json()

    def test_quick_whitelisted_url_records_raw_model_score(self):
        """Whitelist match still returns the raw calibrated score (Stage 4).

        The whitelist wins the blocking decision; raw_model_score is
        recorded alongside for anomaly monitoring. Verdict is NOT asserted
        — stage3 network signals and the client_score floor can push it
        to "suspicious", and that juxtaposition is itself the anomaly
        signal, not a bug.
        """
        response = client.post("/api/v1/analyze/quick",
            json={
                "url": "https://www.google.com/",
                "client_score": 0.796,
            },
            headers={"X-API-Key": "phishguard-dev-key"}
        )
        assert response.status_code == 200
        body = response.json()

        feed = body["threat_feed"]
        assert feed["whitelist_match"] is True
        assert feed["raw_model_score"] == pytest.approx(0.796)
        assert feed["is_known_threat"] is False

        signals = [r["signal"] for r in body.get("evidence_trail", [])]
        assert "whitelist" in signals
