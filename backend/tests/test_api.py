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


class TestFullAnalyze:
    """Stage 5: /analyze/full takes derived visual features, never pixels."""

    def _post(self, payload):
        return client.post(
            "/api/v1/analyze/full",
            json=payload,
            headers={"X-API-Key": "phishguard-dev-key"},
        )

    def test_full_without_visual_features(self):
        response = self._post({"url": "https://www.google.com/", "client_score": 0.1})
        assert response.status_code == 200
        body = response.json()
        assert body["verdict"] in ("safe", "suspicious", "phishing")
        # No features → no visual record in the trail at all
        assert response.status_code == 200

    def test_full_with_derived_features(self):
        from app.services.visual_analyzer import BRAND_PROFILES
        response = self._post({
            "url": "https://secure-paypal-verify.example.tk/",
            "client_score": 0.3,
            "visual_features": {
                "favicon_ahash": BRAND_PROFILES["paypal"]["ahash"],
                "color_summary": [[255, 255, 255], [0, 48, 135]],
                "color_source": "favicon",
            },
        })
        assert response.status_code == 200
        body = response.json()
        assert body["visual_analysis"]["is_impersonation"] is True
        assert body["visual_analysis"]["brand_detected"] == "paypal"
        # The trail must surface the visual check (fail-visible contract)
        signals = [r["signal"] for r in body.get("evidence_trail", [])]
        assert "visual_match" in signals

    def test_visual_signal_appears_in_reasons(self):
        from app.services.visual_analyzer import BRAND_PROFILES
        response = self._post({
            "url": "https://paypal-login.example.tk/signin",
            "client_score": 0.3,
            "visual_features": {
                "favicon_ahash": BRAND_PROFILES["paypal"]["ahash"],
                "color_summary": [[255, 255, 255]],
                "color_source": "favicon",
            },
        })
        body = response.json()
        assert body["visual_analysis"]["is_impersonation"] is True

    def test_oversized_color_list_rejected_422(self):
        # More than 8 colours is not a real client — hostile input.
        response = self._post({
            "url": "https://example.com/",
            "visual_features": {
                "color_summary": [[1, 2, 3]] * 9,
                "color_source": "page",
            },
        })
        assert response.status_code == 422

    def test_non_binary_hash_rejected_422(self):
        response = self._post({
            "url": "https://example.com/",
            "visual_features": {
                "favicon_ahash": "2" * 256,
                "color_source": "favicon",
            },
        })
        assert response.status_code == 422

    def test_oversized_hash_rejected_422(self):
        response = self._post({
            "url": "https://example.com/",
            "visual_features": {
                "favicon_ahash": "01" * 128 + "0",  # 257 chars
            },
        })
        assert response.status_code == 422

    def test_screenshot_field_gone_422(self):
        # The retired field must be rejected, not silently ignored — an old
        # extension build must get a loud failure, not a quiet no-op.
        response = self._post({
            "url": "https://example.com/",
            "client_score": 0.2,
            "screenshot_base64": "aGVsbG8=",
        })
        assert response.status_code == 422
