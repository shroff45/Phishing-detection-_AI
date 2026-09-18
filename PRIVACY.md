# PhishGuard — Privacy Architecture

> **This is the engineering note.** The user-facing policy — the one shipped
> with the extension and linked from the settings page — is
> [`extension/PRIVACY.md`](extension/PRIVACY.md). If the two ever disagree,
> the extension copy is authoritative and this file is the bug.

## Design Principle

Local-first. Scoring happens on-device; data leaves the browser only on the
escalation path described below, and only when the user has left escalation
enabled. Since Stage 5, **no image bytes ever leave the browser** — the
escalation payload is URL + score + derived visual features, unconditionally.

## Data Flow

```
User navigates → 30 lexical URL features extracted   (local)
                        ↓
                 ONNX inference                      (local, in-browser)
                        ↓
                 finalScore in [0, 1]
                        ↓
       score >= 0.65 → phishing        score >= 0.35 → suspicious
                                       otherwise     → safe

       Escalation is a SEPARATE gate, not a band:
       escalate if  allowBackendEscalation
                    AND (score >= 0.25 OR brand spoofing OR suspicious hosting)
```

Two things follow from that gate, and both are easy to get wrong:

- **The escalation floor (0.25) is below the "suspicious" verdict floor
  (0.35).** Pages that end up labelled *safe* can still be escalated.
- **A confident `phishing` verdict is escalated too.** There is no upper
  cut-off. The backend can add reasons and raise the score; it can never lower
  it (verdict monotonicity — `Math.max(local, backend)`).

Thresholds live in [`extension/background/service-worker.js`](extension/background/service-worker.js).
Change them there and update this file in the same commit.

## What Is Sent on Escalation

| Field | Always? | Notes |
|---|---|---|
| URL | yes | Full URL, for threat-feed and WHOIS lookup |
| Client ML score | yes | A float, not page content |
| Visual features | when derived | 256-bit favicon aHash + ≤8 dominant RGB colours |

The visual features are computed in the content script
([`extension/content/content-script.js`](extension/content/content-script.js)):
the favicon is drawn to a 16×16 canvas and hashed with a mean-threshold aHash,
and colours are bucket-quantized from the favicon or, if unreachable, from
page computed styles. The backend compares the hash against reference
profiles of heavily-phished brands
([`backend/app/services/visual_analyzer.py`](backend/app/services/visual_analyzer.py)).
A match contributes to the score **only when the domain is not the brand's
own** — the brand domain list can prevent false flags on the real site, it can
never mark anything safe.

### Why the screenshot path had to go

The pre-Stage-5 path uploaded an un-redacted viewport JPEG when the user
opted in, and the backend ran OCR over it, producing a second copy of any
on-screen text. The capture could incidentally contain personal data (bank
balances, names, account numbers), which is exactly why the GDPR note below
carried a caveat. The derived-features path carries the same brand-similarity
signal with none of the content: a favicon hash is not meaningfully personal
data, and colour counts even less so.

## What Is Never Collected

- Browsing history
- Cookies or session tokens
- Form input (passwords, emails)
- Screenshots or page pixels — no image bytes exist anywhere in the
  escalation path, client or server
- Client IPs — the privacy middleware logs a truncated SHA-256 of the IP, not
  the address itself

## Compliance

These are the project's design intent, not the outcome of a legal review:

- **GDPR / CCPA** — no personal data is intentionally processed, and the
  one path that could incidentally capture it (opt-in screenshots) was
  removed in v1.1.0.
- **Chrome Web Store User Data Policy** — the extension declares the
  escalation path; the payload is URL + score + derived scalars, and the
  `activeTab` permission was dropped along with the capture path.
