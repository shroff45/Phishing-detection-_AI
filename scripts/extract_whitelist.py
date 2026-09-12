"""
Regenerate ml-retrain/shipped_whitelist.py from the WHITELIST set in
extension/background/service-worker.js.

The golden-set evaluation must measure the operating point users actually
get — model + shipped whitelist — not the model in isolation. This script
extracts the whitelist mechanically so the two can never drift: if the
extension's whitelist changes, rerun this and commit the result.

Usage:  python scripts/extract_whitelist.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SW_PATH = ROOT / "extension" / "background" / "service-worker.js"
OUT_PATH = ROOT / "ml-retrain" / "shipped_whitelist.py"


def extract_whitelist() -> list[str]:
    content = SW_PATH.read_text(encoding="utf-8")
    idx = content.find("const WHITELIST = new Set([")
    if idx == -1:
        raise SystemExit("WHITELIST set not found in service-worker.js")
    end = content.find("]);", idx)
    if end == -1:
        raise SystemExit("WHITELIST set is malformed — missing ']);'")
    block = content[idx:end]
    return re.findall(r'"([^"]+)"', block)


def main() -> None:
    domains = extract_whitelist()
    if not domains:
        raise SystemExit("Extracted an empty whitelist — refusing to write.")

    header = '''"""
AUTO-GENERATED — do not edit by hand.
The shipped extension whitelist, extracted from
extension/background/service-worker.js WHITELIST set.

Regenerate with: python scripts/extract_whitelist.py

The golden-set evaluation measures model + shipped whitelist — the
operating point users actually get — so this file must track the
extension, not a hand-maintained copy.
"""

WHITELIST_DOMAINS = frozenset({
'''
    body = "\n".join(f'    "{d}",' for d in sorted(domains))
    footer = '''})

import re


def is_whitelisted(url: str) -> bool:
    """True if the extension would short-circuit this URL to safe."""
    m = re.match(r"^[a-zA-Z]+://([^/:?#]+)", url or "")
    if not m:
        return False
    hostname = m.group(1).lower()
    if hostname in WHITELIST_DOMAINS:
        return True
    return any(
        hostname.endswith("." + d) for d in WHITELIST_DOMAINS
    )
'''
    # newline="\n" — the CI freshness check diffs this file against a
    # regenerated copy; platform-native newlines would make it differ.
    OUT_PATH.write_text(header + body + footer, encoding="utf-8", newline="\n")
    print(f"[ok] {len(domains)} domains -> {OUT_PATH}")


if __name__ == "__main__":
    main()
