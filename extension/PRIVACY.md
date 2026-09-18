# PhishGuard Privacy Policy

**Last Updated:** 2026-09-12

## What PhishGuard Does

PhishGuard is a browser extension that detects phishing websites
real time using machine learning and threat intelligence.

## Data We Collect

### By Default (Local-Only Mode)
- **Zero data leaves your browser.** All URL analysis and page
  scanning happens entirely on your device using a locally
  bundled machine learning model.
- Scan results are cached in your browser's session storage
  and automatically cleared when you close the browser.
- Aggregate statistics (pages scanned, threats blocked) are
  stored locally and never transmitted.

### When Backend Escalation Is Enabled
For URLs that the local model cannot confidently classify, the
following is sent to the analysis server:
- The URL being analyzed
- Your local model's numeric score (a number, not page content)
- Derived visual features: a 256-bit hash of the page's favicon
  and a summary of its dominant colours. These are computed on
  your device from the favicon image and CSS values — **no image
  or page pixels are ever transmitted.**

A page does not have to look dangerous to be escalated. The threshold
for sending is deliberately lower than the threshold for warning you,
so some pages that we end up marking safe are still checked against the
server first.

### Screenshots — Removed
PhishGuard previously offered an opt-in screenshot upload for brand-
impersonation checks. That path was **removed entirely** (v1.1.0): it
sent an un-redacted capture of whatever was on screen. The favicon
hash and colour summary now carry the brand-similarity signal with
none of the content. There is no screenshot setting, no screenshot
code, and no consent caveat — the "no image bytes leave your browser"
claim is unconditional.

This data is:
- Used solely to determine if the page is phishing
- **Not shared** with any third party
- **Not used** for advertising, tracking, or profiling

### What We Never Collect
- Your browsing history
- Cookies or session tokens
- Form input data or passwords
- Screenshots or page images of any kind
- Page text content — the URL, a numeric score, a favicon hash,
  and dominant colours are all that is ever sent

## Third-Party Services

When backend escalation is enabled, the server may query:
- **Google Safe Browsing API** — to check if a URL is in Google's
  threat database. Only the URL is sent. Google's privacy policy
  applies to their processing.
- **VirusTotal API** — to check multi-engine scan results.
  Only the URL is sent.
- **WHOIS databases** — to check domain registration age.
  Only the domain name is queried.

## Your Controls

In the extension's settings page you can at any time:
- **Turn off "Backend Escalation"** — nothing is sent; all analysis
  stays on your device
- **Point at your own server** — set a Backend Server URL you control
- **Clear cached data** — removes stored scan results and statistics
- **Export your data** — download everything stored locally as JSON
- **Uninstall the extension** — all local data is deleted with it

## Open Source

PhishGuard is open source. You can inspect every line of code
to verify these privacy claims.

## Contact

For privacy concerns, contact: [your-email@vit.ac.in]
