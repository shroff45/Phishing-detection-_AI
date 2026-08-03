# PhishGuard Privacy Policy

**Last Updated:** 2025

## What PhishGuard Does

PhishGuard is a browser extension that detects phishing websites
in real time using machine learning and threat intelligence.

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

A page does not have to look dangerous to be escalated. The threshold
for sending is deliberately lower than the threshold for warning you,
so some pages that we end up marking safe are still checked against the
server first.

### Screenshots — Off By Default
Screenshots are **not** sent unless you explicitly enable
"Share Screenshots" in settings. That toggle is **off by default**.

If you turn it on, a JPEG of the visible page is uploaded with each
escalation so the server can check for brand impersonation. Be aware:

- **The capture is not redacted.** Whatever is on screen is included —
  if you are looking at a bank balance or an account number, that is
  in the image.
- The server runs OCR on it, which extracts on-screen text into a
  second representation.
- Escalation happens on a minority of pages, but you do not choose
  which ones.

Leave this off unless you are self-hosting the backend. A future
release will replace raw screenshots with derived features (a
perceptual hash and a layout vector) that carry the brand-similarity
signal without the pixels.

This data is:
- Used solely to determine if the page is phishing
- **Not shared** with any third party
- **Not used** for advertising, tracking, or profiling

### What We Never Collect
- Your browsing history
- Cookies or session tokens
- Form input data or passwords
- Page content — the URL and a numeric score are all that is sent
  (plus a screenshot, only if you opt in)

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
- **Turn off "Share Screenshots"** — already off unless you turned it on
- **Point at your own server** — set a Backend Server URL you control
- **Clear cached data** — removes stored scan results and statistics
- **Export your data** — download everything stored locally as JSON
- **Uninstall the extension** — all local data is deleted with it

## Open Source

PhishGuard is open source. You can inspect every line of code
to verify these privacy claims.

## Contact

For privacy concerns, contact: [your-email@vit.ac.in]
