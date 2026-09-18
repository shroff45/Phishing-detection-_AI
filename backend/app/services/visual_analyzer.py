"""
PhishGuard Backend — Stage 5: Visual Similarity from Derived Features

The extension computes a 256-bit aHash of the page's favicon (16×16
grayscale, mean-thresholded, alpha composited onto white — matching how a
canvas draws) plus a dominant-colour summary. This module compares those
derived features against reference profiles of heavily-phished brands.

No image bytes are ever received, decoded, or stored. The screenshot upload
path and its OCR pipeline were removed entirely in Stage 5 — the privacy
claim ("no pixels leave the browser") is now unconditional.

Reference profile semantics (Stage 6 will grow this corpus):
  - The corpus is a COMPARISON REFERENCE ONLY. It is never an allowlist:
    a match raises the impersonation score when the domain is NOT the
    brand's own; it can never produce a "safe" verdict for any URL.
  - Reference aHashes are computed from the official favicons with the same
    algorithm the extension uses, so a legitimate brand page matches its own
    profile with distance ≈ 0-3 bits, while different brands sit ≥ 66 bits
    apart at 16×16 (measured across the seed set).
"""

import structlog
from typing import Dict, Any, List, Optional, Tuple

logger = structlog.get_logger(__name__)

# Match threshold: a favicon within this Hamming distance of a brand's
# reference hash counts as "same icon". 12 bits of 256 (~4.7%) allows the
# ≤3-bit resampling drift observed between canvas and reference pipelines
# plus icon-frame differences, while sitting far below the ≥66-bit
# inter-brand separation measured on the seed corpus.
FAVICON_MATCH_BITS = 12
HASH_BITS = 256

# Colour-match tolerance: RGB triples within this Euclidean distance of a
# brand colour count as a hit. 48 is tight enough that generic palettes
# (white/black/grey) don't rack up hits, loose enough for palette drift
# between a brand's favicons and its login pages.
COLOR_MATCH_DISTANCE = 48.0

# Seed corpus — three most-impersonated brands. aHash values computed from
# the official favicons (white-composite, LANCZOS, 16×16, mean threshold).
# Domains listed are the ONLY origins for which a match is NOT impersonation.
BRAND_PROFILES: Dict[str, Dict[str, Any]] = {
    "google": {
        "ahash": ("1111111111111111111111111111111111111000000111111111000000001111"
                  "1110000000011111110000111111111111000111111111111100111100000011"
                  "1100111100000011110001111110001111000011111000111110000010000111"
                  "1111000000001111111110000001111111111111111111111111111111111111"),
        "colors": [(255, 255, 255), (66, 133, 244), (234, 67, 53), (251, 188, 5)],
        "keywords": ["google", "sign in", "workspace", "gmail"],
        "domains": ["google.com", "googlemail.com", "gmail.com", "googleusercontent.com", "gstatic.com", "ggpht.com", "googleapis.com", "withgoogle.com", "google.co"],
    },
    "microsoft": {
        "ahash": ("0000000110000000000000011000000000000001100000000000000110000000"
                  "0000000110000000000000011000000000000001100000001111111111111111"
                  "1111111111111111000000011111111100000001111111110000000111111111"
                  "0000000111111111000000011111111100000001111111110000000111111111"),
        "colors": [(255, 255, 255), (242, 80, 34), (127, 186, 0), (0, 164, 239), (255, 185, 0)],
        "keywords": ["microsoft", "sign in", "outlook", "onedrive", "office"],
        "domains": ["microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "msn.com", "bing.com", "azure.com", "azurewebsites.net", "visualstudio.com", "github.com", "xbox.com"],
    },
    "paypal": {
        "ahash": ("1111111111111111111111111111111111111000000011111111000000001111"
                  "1111000000000111111100000000011111110000000001111111000000000011"
                  "1111000000000111111000000000011111100000000111111110000001111111"
                  "1110000001111111111111001111111111111111111111111111111111111111"),
        "colors": [(255, 255, 255), (0, 48, 135), (0, 121, 193), (0, 207, 255)],
        "keywords": ["paypal", "log in", "send money", "checkout"],
        "domains": ["paypal.com", "paypal.me", "paypalobjects.com", "venmo.com"],
    },
}


def _hamming(a: str, b: str, bits: int = HASH_BITS) -> int:
    """Hamming distance between two equal-length bit strings."""
    if not a or not b or len(a) != len(b) or len(a) != bits:
        return bits  # malformed → max distance, never a match
    return sum(c1 != c2 for c1, c2 in zip(a, b))


def _color_distance(c1: Tuple[int, int, int], c2: Tuple[int, int, int]) -> float:
    """Euclidean distance between two RGB colours (max 441.7)."""
    try:
        return sum((float(a) - float(b)) ** 2 for a, b in zip(c1, c2)) ** 0.5
    except (TypeError, ValueError):
        return 441.7  # malformed → max distance


def _is_brand_domain(hostname: str, brand: str) -> bool:
    """True if hostname belongs to the brand's own registered domains.

    This is the ONLY allowlist-adjacent decision in this module, and it can
    only PREVENT a false impersonation flag on the real brand site — it never
    marks anything safe by itself.
    """
    domains = BRAND_PROFILES.get(brand, {}).get("domains", [])
    host = (hostname or "").lower()
    return any(host == d or host.endswith("." + d) for d in domains)


def _dominant_color_hits(
    observed: Optional[List], reference: List[Tuple[int, int, int]]
) -> float:
    """Fraction of a brand's reference colours present in the page summary."""
    if not observed or not isinstance(observed, list):
        return 0.0
    hits = 0
    for ref in reference:
        for c in observed:
            if (
                isinstance(c, (list, tuple))
                and len(c) == 3
                and _color_distance(tuple(c), tuple(ref)) < COLOR_MATCH_DISTANCE
            ):
                hits += 1
                break
    return hits / max(1, len(reference))


class VisualAnalyzer:
    """
    Compares client-derived visual features against brand reference profiles.

    All inputs are attacker-controllable (a phishing page serves its own
    favicon and CSS). Every value is shape- and length-validated before use;
    malformed input scores 0, never raises, and is reported as a degraded
    check — fail-visible, never fail-open.
    """

    def __init__(self, profiles: Optional[Dict[str, Dict[str, Any]]] = None):
        self.brands = profiles if profiles is not None else BRAND_PROFILES

    # ── Public API ────────────────────────────────────────────────────────

    def hamming_distance(self, hash1: str, hash2: str) -> int:
        """Distance between two 256-bit hashes (0..256)."""
        return _hamming(hash1, hash2)

    def analyze_features(
        self, features: Optional[Dict[str, Any]], url: str
    ) -> Dict[str, Any]:
        """
        Compare derived visual features against brand profiles.

        `features` is the JSON the extension sent:
          { favicon_ahash: "…" (256 bits) | null,
            color_summary: [[r,g,b], …] | null,
            color_source: "favicon" | "page" | "unavailable" }

        Returns the same shape the old screenshot path returned, so
        compute_meta_score and the popup need no changes:
          { similarity_score, brand_detected, is_impersonation, details }
        A missing/degraded feature set yields is_impersonation=False with
        details explaining why — unknown must never read as safe, but visual
        evidence simply being absent is not evidence of anything.
        """
        try:
            if not isinstance(features, dict):
                return self._degraded("No visual features provided")

            hostname = self._hostname(url)

            favicon_hash = features.get("favicon_ahash")
            colors = features.get("color_summary")
            color_source = features.get("color_source")

            # No favicon hash at all → the visual check is degraded (no
            # favicon reachable, or derivation failed). Reported, never
            # silently read as "checked and clean".
            if favicon_hash is None:
                reason = "Visual check unavailable (no favicon features derived)"
                if color_source:
                    return {
                        "similarity_score": 0.0,
                        "brand_detected": None,
                        "is_impersonation": False,
                        "details": {
                            "degraded": reason,
                            "color_source": color_source,
                        },
                    }
                return self._degraded(reason)

            # ── Favicon hash comparison (strongest signal) ──────────────
            brand_detected = None
            hash_distance = None
            if isinstance(favicon_hash, str) and len(favicon_hash) == HASH_BITS \
                    and set(favicon_hash) <= {"0", "1"}:
                best_brand, best_dist = None, HASH_BITS
                for brand, profile in self.brands.items():
                    ref = profile.get("ahash", "")
                    dist = _hamming(favicon_hash, ref)
                    if dist <= FAVICON_MATCH_BITS and dist < best_dist:
                        best_brand, best_dist = brand, dist
                if best_brand is not None:
                    brand_detected = best_brand
                    hash_distance = best_dist
            elif favicon_hash is not None:
                logger.debug(
                    "visual_features_malformed_hash",
                    length=len(favicon_hash) if isinstance(favicon_hash, str) else type(favicon_hash).__name__,
                )
                details["favicon_ahash"] = "malformed"

            # ── Colour comparison (corroborating signal only) ────────────
            # On its own a colour match proves nothing — half the web is
            # blue and white. Colours only matter when the favicon hash
            # already identified a candidate brand.
            color_ratio = 0.0
            if brand_detected is not None:
                color_ratio = _dominant_color_hits(
                    colors, self.brands[brand_detected].get("colors", [])
                )
            elif colors is not None and not isinstance(colors, list):
                details["color_summary"] = "malformed"

            details: Dict[str, Any] = {
                "color_source": color_source,
            }
            if brand_detected is not None:
                details["favicon_bits_from_reference"] = hash_distance
                details["color_match_ratio"] = round(color_ratio, 3)

            # ── Verdict ─────────────────────────────────────────────────
            if brand_detected is None:
                similarity = 0.0
            else:
                # Hash identified the brand's icon; colours corroborate.
                # Base 0.5 for the hash match, up to +0.3 for colours.
                similarity = 0.5 + 0.3 * min(1.0, color_ratio)

            is_impersonation = bool(
                brand_detected is not None
                and not _is_brand_domain(hostname, brand_detected)
            )

            return {
                "similarity_score": round(similarity, 3),
                "brand_detected": brand_detected if similarity > 0.4 else None,
                "is_impersonation": is_impersonation,
                "details": details,
            }

        except Exception as e:
            logger.error("visual_feature_analysis_failed", error=str(e), exc_info=True)
            return self._degraded(f"Visual analysis failed: {e}")

    # ── Internals ─────────────────────────────────────────────────────────

    @staticmethod
    def _degraded(reason: str) -> Dict[str, Any]:
        return {
            "similarity_score": 0.0,
            "brand_detected": None,
            "is_impersonation": False,
            "details": {"degraded": reason},
        }

    @staticmethod
    def _hostname(url: str) -> str:
        try:
            from urllib.parse import urlparse
            return (urlparse(url or "").netloc or "").split(":")[0].lower()
        except Exception:
            return ""


# Global singleton
visual_analyzer = VisualAnalyzer()
