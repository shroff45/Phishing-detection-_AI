"""
Root-level twin of backend/tests/test_visual_analyzer.py.

Kept because CI runs ../tests/ from backend/ and the root suite historically
imported the analyzer with a different sys.path; it now pins the Stage-5
derived-features contract from outside the backend package to catch
import-path regressions.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

import pytest

from app.services.visual_analyzer import (
    BRAND_PROFILES,
    FAVICON_MATCH_BITS,
    HASH_BITS,
    VisualAnalyzer,
    _hamming,
)


@pytest.fixture
def analyzer():
    return VisualAnalyzer()


def _features_for(brand: str):
    return {
        "favicon_ahash": BRAND_PROFILES[brand]["ahash"],
        "color_summary": list(BRAND_PROFILES[brand]["colors"][:2]),
        "color_source": "favicon",
    }


class TestDerivedFeatureContract:
    """The cross-package contract the escalation path depends on."""

    def test_legitimate_brand_page_not_impersonation(self, analyzer):
        for brand, profile in BRAND_PROFILES.items():
            result = analyzer.analyze_features(
                _features_for(brand), f"https://{profile['domains'][0]}/"
            )
            assert result["is_impersonation"] is False, brand

    def test_brand_favicon_elsewhere_is_impersonation(self, analyzer):
        for brand in BRAND_PROFILES:
            result = analyzer.analyze_features(
                _features_for(brand), "https://login-verify.example.tk/"
            )
            assert result["is_impersonation"] is True, brand

    def test_no_pixels_accepted_anywhere(self, analyzer):
        # The API surface takes a dict of derived scalars only; this is the
        # regression pin for "no image bytes ever reach the analyzer".
        import inspect
        sig = inspect.signature(VisualAnalyzer.analyze_features)
        assert list(sig.parameters) == ["self", "features", "url"]

    def test_match_threshold_leaves_margin_for_resampling_drift(self):
        # Canvas vs reference pipelines drift <= 3 bits; inter-brand
        # separation is >= 66 bits. The threshold must sit comfortably
        # between: tight enough to not confuse brands, loose enough that a
        # legitimate icon rendered at a different size still matches.
        assert FAVICON_MATCH_BITS >= 8
        assert FAVICON_MATCH_BITS <= HASH_BITS // 10

    def test_hamming_shape(self, analyzer):
        a = BRAND_PROFILES["google"]["ahash"]
        b = BRAND_PROFILES["microsoft"]["ahash"]
        d = _hamming(a, b)
        assert 0 < d <= HASH_BITS
