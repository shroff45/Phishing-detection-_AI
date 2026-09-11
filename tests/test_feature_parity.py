"""
tests/test_feature_parity.py

Verifies that Python and JavaScript feature extraction
produce identical results for the same URLs.

This is the MOST IMPORTANT test in the entire project.
A parity failure means the ML model will silently degrade.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ml-training"))
from build_dataset import extract_features as extract_url_features


# URLs that exercise edge cases in both parsers
PARITY_TEST_URLS = [
    "https://www.google.com/",
    "http://192.168.1.1/login/verify.php",
    "https://sub1.sub2.sub3.example.co.uk/path/to/page?q=1&r=2",
    "http://192.168.1.1:8080/paypal-login/secure/verify.php?account=victim@email.com",
    "https://xn--pple-43d.com/login",
    "https://bit.ly/abc123",
    "https://example.xyz/update/account/password",
    "http://10.0.0.1/",
    "https://a-very-long-subdomain-that-goes-on-and-on.example.com/path",
    "https://example.com/%2F%3F%3D%26/test",
    "https://user@evil.com/fake-page",
    "https://example.com:8443/login?redirect=https://other.com",
    # Edge cases
    "https://example.com/",  # minimal path
    "https://example.com",   # no trailing slash
    "http://example.com/a/b/c/d/e/f/g/h",  # deep path
]


class TestFeatureParity:
    """
    For each test URL, extract features using BOTH the Python
    function and a Node.js script that runs the JavaScript
    extractLexicalFeatures(). Compare all 30 features.
    """

    @pytest.fixture(autouse=True)
    def setup_js_extractor(self, tmp_path):
        """Create a temporary Node.js script that runs the JS extractor."""
        sw_path = Path(__file__).resolve().parent.parent / "extension" / "background" / "service-worker.js"

        if not sw_path.exists():
            pytest.skip("service-worker.js not found")

        # Probe for Node.js independently.
        # Node absent  => legitimate skip.
        # Broken JS    => hard fail (not skip).
        node_check = subprocess.run(
            ["node", "--version"],
            capture_output=True,
            text=True,
        )
        if node_check.returncode != 0:
            pytest.skip("Node.js not available (install to enable parity tests)")

        constants, func_body = self._extract_js_components(sw_path)

        if func_body is None:
            pytest.fail(
                "extractLexicalFeatures() not found in service-worker.js — "
                "the function may have been renamed or the file structure changed."
            )

        shannon_fn = self._extract_js_helper(sw_path, "function shannonEntropy(")

        # Build a self-contained Node.js script with all dependencies hoisted:
        # 1. Module-level constants the function closes over
        # 2. shannonEntropy() helper (called inside extractLexicalFeatures)
        # 3. The extractLexicalFeatures function itself
        js_script = tmp_path / "extract.js"
        js_script.write_text(
            "// --- Hoisted module-level constants ---\n"
            + constants
            + "\n\n// --- shannonEntropy helper ---\n"
            + (shannon_fn or "")
            + "\n\n// --- Feature extraction function ---\n"
            + func_body
            + """

const url = process.argv[2];
const features = extractLexicalFeatures(url);
if (!features || features.error) {
    console.log(JSON.stringify({error: true}));
} else {
    console.log(JSON.stringify(features));
}
""",
            encoding="utf-8",
        )

        # Validate the generated script actually executes before parametrized tests use it.
        probe = subprocess.run(
            ["node", str(js_script), "https://example.com/"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if probe.returncode != 0 or not probe.stdout.strip():
            pytest.fail(
                "JS extraction script crashed — this is NOT a missing Node.js issue.\n"
                f"stdout: {probe.stdout!r}\n"
                f"stderr: {probe.stderr!r}\n"
                "Fix _extract_js_components() or the service-worker constant declarations."
            )

        self.js_script = str(js_script)

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    def _extract_block(self, content: str, start_idx: int) -> str:
        """Return the balanced-brace block that starts at start_idx."""
        brace_count = 0
        found_first = False
        for i in range(start_idx, len(content)):
            if content[i] == "{":
                brace_count += 1
                found_first = True
            elif content[i] == "}":
                brace_count -= 1
            if found_first and brace_count == 0:
                return content[start_idx: i + 1]
        return ""

    def _extract_js_components(self, sw_path: Path):
        """
        Return (constants_str, function_body_str).

        constants_str holds the three const declarations that
        extractLexicalFeatures() closes over (PHISH_KEYWORDS,
        SUSPICIOUS_TLDS, SHORTENER_DOMAINS).

        function_body_str is the full function source.
        """
        content = sw_path.read_text(encoding="utf-8")

        # ── Hoist the three constants the function references ───────────
        constants_parts = []
        for const_name in ("PHISH_KEYWORDS", "SUSPICIOUS_TLDS", "SHORTENER_DOMAINS"):
            marker = f"const {const_name}"
            idx = content.find(marker)
            if idx == -1:
                continue
            bracket_depth = 0
            past_open = False
            end = idx
            for i in range(idx, len(content)):
                ch = content[i]
                if ch in ("[", "("):
                    bracket_depth += 1
                    past_open = True
                elif ch in ("]", ")"):
                    bracket_depth -= 1
                if past_open and bracket_depth == 0 and content[i] == ";":
                    end = i + 1
                    break
            constants_parts.append(content[idx:end])

        constants_str = "\n".join(constants_parts)

        # ── Extract extractLexicalFeatures ──────────────────────────────
        fn_marker = "function extractLexicalFeatures(rawUrl)"
        fn_idx = content.find(fn_marker)
        if fn_idx == -1:
            return constants_str, None

        fn_body = self._extract_block(content, fn_idx)
        return constants_str, fn_body

    def _extract_js_helper(self, sw_path: Path, fn_signature: str):
        """Extract a named helper function from service-worker.js by signature."""
        content = sw_path.read_text(encoding="utf-8")
        idx = content.find(fn_signature)
        if idx == -1:
            return None
        return self._extract_block(content, idx)

    def _run_js_extraction(self, url: str):
        """Run the JS extractor via Node.js and return the feature dict."""
        result = subprocess.run(
            ["node", self.js_script, url],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            pytest.fail(
                f"node extract.js failed for {url!r}\n"
                f"stdout: {result.stdout!r}\n"
                f"stderr: {result.stderr!r}"
            )
        try:
            return json.loads(result.stdout.strip())
        except json.JSONDecodeError as exc:
            pytest.fail(
                f"JS extractor produced non-JSON output for {url!r}: {exc}\n"
                f"raw stdout: {result.stdout!r}"
            )

    # ──────────────────────────────────────────────────────────────────────
    # Tests
    # ──────────────────────────────────────────────────────────────────────

    @pytest.mark.parametrize("url", PARITY_TEST_URLS)
    def test_feature_parity(self, url):
        """
        Core parity test: Python and JavaScript must produce
        identical feature values for the same URL.
        """
        py_features = extract_url_features(url)
        js_features = self._run_js_extraction(url)

        if js_features and js_features.get("error"):
            # Both sides agree URL is unparseable
            assert py_features is None, (
                f"JS returned {{error:true}} for {url!r} but Python returned features."
            )
            return

        assert py_features is not None, (
            f"Python returned None for {url!r} but JS extracted: {js_features}"
        )

        feature_keys = [k for k in py_features if k.startswith("f")]
        assert feature_keys, f"Python returned no 'f*' keys for {url!r}: {py_features}"

        mismatches = []
        for key in feature_keys:
            py_val = py_features.get(key, 0)
            js_val = js_features.get(key, 0)

            if isinstance(py_val, float) or isinstance(js_val, float):
                if abs(float(py_val) - float(js_val)) >= 0.001:
                    mismatches.append(f"  {key}: Python={py_val}, JS={js_val}")
            else:
                if py_val != js_val:
                    mismatches.append(f"  {key}: Python={py_val}, JS={js_val}")

        assert not mismatches, (
            f"PARITY FAILURE for {url!r} — {len(mismatches)} feature(s) differ:\n"
            + "\n".join(mismatches)
        )
