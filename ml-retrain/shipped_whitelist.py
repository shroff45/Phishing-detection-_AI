"""
AUTO-GENERATED — do not edit by hand.
The shipped extension whitelist, extracted from
extension/background/service-worker.js WHITELIST set.

Regenerate with: python scripts/extract_whitelist.py

The golden-set evaluation measures model + shipped whitelist — the
operating point users actually get — so this file must track the
extension, not a hand-maintained copy.
"""

WHITELIST_DOMAINS = frozenset({
    "adobe.com",
    "amazon.com",
    "apple.com",
    "bbc.co.uk",
    "bbc.com",
    "bing.com",
    "cnn.com",
    "dropbox.com",
    "ebay.com",
    "en.wikipedia.org",
    "facebook.com",
    "github.com",
    "google.com",
    "instagram.com",
    "linkedin.com",
    "microsoft.com",
    "microsoftonline.com",
    "netflix.com",
    "open.spotify.com",
    "paypal.com",
    "reddit.com",
    "slack.com",
    "spotify.com",
    "stackoverflow.com",
    "twitch.tv",
    "twitter.com",
    "vit.ac.in",
    "web.whatsapp.com",
    "whatsapp.com",
    "wikipedia.org",
    "www.amazon.com",
    "www.apple.com",
    "www.bing.com",
    "www.ebay.com",
    "www.facebook.com",
    "www.github.com",
    "www.google.com",
    "www.instagram.com",
    "www.linkedin.com",
    "www.microsoft.com",
    "www.netflix.com",
    "www.paypal.com",
    "www.reddit.com",
    "www.twitch.tv",
    "www.twitter.com",
    "www.yahoo.com",
    "www.youtube.com",
    "yahoo.com",
    "youtube.com",
    "zoom.us",})

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
