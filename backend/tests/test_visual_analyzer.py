"""
PhishGuard — Unit Tests: Visual Similarity from Derived Features (Stage 5)

The analyzer receives only derived features (favicon aHash + colour summary)
— never image bytes. These tests pin the behaviour the privacy claim and the
scoring blend depend on:

  • a legitimate favicon matching a brand profile on that brand's OWN domain
    is not impersonation,
  • the same favicon on any other domain IS impersonation,
  • malformed/hostile input can never produce a match,
  • degraded input reports why, rather than silently reading as safe.
"""

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


# A well-formed feature set: the reference favicon hash of a brand, plus a
# colour summary drawn from that brand's palette.
def _features_for(brand: str):
    return {
        "favicon_ahash": BRAND_PROFILES[brand]["ahash"],
        "color_summary": list(BRAND_PROFILES[brand]["colors"][:2]),
        "color_source": "favicon",
    }


class TestCorpusIntegrity:
    """The seed corpus is the matcher's foundation — pin its invariants."""

    def test_all_reference_hashes_are_256_bits(self):
        for brand, profile in BRAND_PROFILES.items():
            h = profile["ahash"]
            assert len(h) == HASH_BITS, f"{brand}: {len(h)} bits"
            assert set(h) <= {"0", "1"}, f"{brand}: non-bit characters"

    def test_inter_brand_separation_far_exceeds_match_threshold(self):
        # Inter-brand distances measured on the seed set are >= 66 bits; the
        # threshold is 12. If a new brand profile lands within the threshold
        # of an existing one, the matcher could confuse two brands.
        names = list(BRAND_PROFILES)
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                dist = _hamming(BRAND_PROFILES[a]["ahash"], BRAND_PROFILES[b]["ahash"])
                assert dist > FAVICON_MATCH_BITS * 3, (
                    f"{a} vs {b}: {dist} bits — too close for confident separation"
                )

    def test_no_brand_profile_can_allowlist_anything(self):
        # The domains list only PREVENTS impersonation flags on the real
        # brand site. It must contain no domains whose presence could mark
        # an unrelated URL safe — enforced by construction, but pinned here
        # because the whole stage depends on it.
        for brand, profile in BRAND_PROFILES.items():
            for d in profile["domains"]:
                assert "." in d, f"{brand}: domain {d!r} is not a registered domain"
                assert not d.startswith("*"), f"{brand}: wildcard in {d!r}"


class TestLegitimateBrandPages:
    def test_brand_favicon_on_brand_domain_is_not_impersonation(self, analyzer):
        for brand, profile in BRAND_PROFILES.items():
            domain = profile["domains"][0]
            result = analyzer.analyze_features(_features_for(brand), f"https://{domain}/signin")
            assert result["is_impersonation"] is False, brand

    def test_brand_favicon_on_brand_subdomain_is_not_impersonation(self, analyzer):
        result = analyzer.analyze_features(
            _features_for("google"), "https://accounts.google.com/signin"
        )
        assert result["is_impersonation"] is False

    def test_brand_favicon_on_other_domain_is_impersonation(self, analyzer):
        result = analyzer.analyze_features(
            _features_for("paypal"), "https://secure-paypal-verify.xyz/login"
        )
        assert result["is_impersonation"] is True
        assert result["brand_detected"] == "paypal"
        assert result["similarity_score"] >= 0.5

    def test_similarity_score_bounded(self, analyzer):
        result = analyzer.analyze_features(
            _features_for("microsoft"), "https://ms-login.example.tk/"
        )
        assert 0.0 <= result["similarity_score"] <= 1.0
        assert result["is_impersonation"] is True


class TestColoursCorroborateOnly:
    def test_colours_alone_never_detect_impersonation(self, analyzer):
        # Palette match without favicon hash → no brand detected, no score.
        features = {
            "favicon_ahash": None,
            "color_summary": [(255, 255, 255), (66, 133, 244), (234, 67, 53)],
            "color_source": "page",
        }
        result = analyzer.analyze_features(features, "https://not-google.example/")
        assert result["brand_detected"] is None
        assert result["is_impersonation"] is False
        assert result["similarity_score"] == 0.0

    def test_colours_raise_similarity_when_hash_matched(self, analyzer):
        base = _features_for("google")
        with_colors = dict(base, color_summary=list(BRAND_PROFILES["google"]["colors"]))
        no_colors = dict(base, color_summary=[])
        r_with = analyzer.analyze_features(with_colors, "https://google-login.example.ru/")
        r_without = analyzer.analyze_features(no_colors, "https://google-login.example.ru/")
        assert r_with["similarity_score"] > r_without["similarity_score"]


class TestHostileAndMalformedInput:
    """Every field is attacker-controllable — none can fabricate a match."""

    def test_short_hash_never_matches(self, analyzer):
        result = analyzer.analyze_features(
            {"favicon_ahash": "0101" * 16, "color_summary": [[255, 255, 255]], "color_source": "favicon"},
            "https://evil.example/",
        )
        assert result["is_impersonation"] is False
        assert result["brand_detected"] is None

    def test_all_ones_hash_never_matches(self, analyzer):
        result = analyzer.analyze_features(
            {"favicon_ahash": "1" * HASH_BITS, "color_summary": None, "color_source": "unavailable"},
            "https://evil.example/",
        )
        assert result["is_impersonation"] is False

    def test_non_binary_hash_never_matches(self, analyzer):
        result = analyzer.analyze_features(
            {"favicon_ahash": "2" * HASH_BITS, "color_summary": None, "color_source": "favicon"},
            "https://evil.example/",
        )
        assert result["is_impersonation"] is False

    def test_hash_of_wrong_length_never_matches(self, analyzer):
        result = analyzer.analyze_features(
            {"favicon_ahash": BRAND_PROFILES["paypal"]["ahash"] + "0", "color_summary": None, "color_source": "favicon"},
            "https://evil.example/",
        )
        assert result["is_impersonation"] is False

    def test_malformed_colors_score_zero(self, analyzer):
        result = analyzer.analyze_features(
            {"favicon_ahash": BRAND_PROFILES["google"]["ahash"], "color_summary": "not-a-list", "color_source": "page"},
            "https://google.example.ru/",
        )
        # Hash still matched Google on a non-Google domain → impersonation,
        # but the malformed colours must not have crashed or inflated it.
        assert result["is_impersonation"] is True
        assert result["similarity_score"] == pytest.approx(0.5)

    def test_hash_flipped_far_from_all_brands_never_matches(self, analyzer):
        # Invert the Google reference: distance 256 from Google, still far
        # from the other brands' references.
        inverted = "".join("1" if c == "0" else "0" for c in BRAND_PROFILES["google"]["ahash"])
        result = analyzer.analyze_features(
            {"favicon_ahash": inverted, "color_summary": None, "color_source": "favicon"},
            "https://evil.example/",
        )
        assert result["is_impersonation"] is False

    def test_malformed_features_surface_markers_in_details(self, analyzer):
        """Pins the malformed-marker contract the code INTENDS to write:
        a malformed favicon hash and a malformed colour summary must each
        appear as details[...] = "malformed" in a normal (non-degraded)
        result — not silently collapse the whole check into _degraded.

        Regression pin: `details` used to be written before it was
        constructed, so these writes raised UnboundLocalError, the outer
        except swallowed it into _degraded, and the markers never
        appeared — this test fails on that old code (KeyError)."""
        result = analyzer.analyze_features(
            {
                "favicon_ahash": "not-a-256-bit-hash",
                "color_summary": "not-a-list",
                "color_source": "favicon",
            },
            "https://evil.example/",
        )
        assert result["is_impersonation"] is False
        assert result["brand_detected"] is None
        assert result["similarity_score"] == 0.0
        assert "degraded" not in result["details"]
        assert result["details"]["favicon_ahash"] == "malformed"
        assert result["details"]["color_summary"] == "malformed"


class TestDegradedInputs:
    """Fail-visible: absent features report why, never silently "safe"."""

    def test_none_features_report_degraded(self, analyzer):
        result = analyzer.analyze_features(None, "https://example.com/")
        assert result["is_impersonation"] is False
        assert result["details"].get("degraded")

    def test_unavailable_features_report_degraded(self, analyzer):
        result = analyzer.analyze_features(
            {"favicon_ahash": None, "color_summary": None, "color_source": "unavailable"},
            "https://example.com/",
        )
        assert result["is_impersonation"] is False
        assert result["details"].get("degraded")

    def test_non_dict_features_report_degraded(self, analyzer):
        result = analyzer.analyze_features(["not", "a", "dict"], "https://example.com/")
        assert result["is_impersonation"] is False
        assert result["details"].get("degraded")

    def test_empty_string_url_does_not_crash(self, analyzer):
        result = analyzer.analyze_features(_features_for("google"), "")
        assert result["is_impersonation"] is True  # "" is not a Google domain

    def test_result_shape_is_stable(self, analyzer):
        result = analyzer.analyze_features(_features_for("paypal"), "https://x.example/")
        assert set(result) == {"similarity_score", "brand_detected", "is_impersonation", "details"}
        assert isinstance(result["similarity_score"], float)
        assert isinstance(result["details"], dict)


class TestHammingDistance:
    def test_identical_hashes_distance_zero(self, analyzer):
        h = BRAND_PROFILES["google"]["ahash"]
        assert _hamming(h, h) == 0

    def test_unequal_lengths_distance_max(self, analyzer):
        assert _hamming("0101", "01010101") == HASH_BITS

    def test_empty_hash_distance_max(self, analyzer):
        assert _hamming("", BRAND_PROFILES["google"]["ahash"]) == HASH_BITS
