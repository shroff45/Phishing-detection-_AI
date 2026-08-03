# PhishGuard — Privacy Architecture

> **This is the engineering note.** The user-facing policy — the one shipped
> with the extension and linked from the settings page — is
> [`extension/PRIVACY.md`](extension/PRIVACY.md). If the two ever disagree,
> the extension copy is authoritative and this file is the bug.

## Design Principle

Local-first. Scoring happens on-device; data leaves the browser only on the
escalation path described below, and only when the user has left escalation
enabled.

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
| Screenshot (JPEG q60) | **only if opted in** | `shareScreenshots`, default **off** |

The screenshot path is off by default because the capture is **not redacted**
— it is whatever is on screen — and the backend runs OCR over it, producing a
second copy of that text. It is decoded in memory, scored, and discarded; it is
never written to disk. Planned replacement: send a perceptual hash and layout
vector instead of pixels, which carries the brand-similarity signal without the
image.

## What Is Never Collected

- Browsing history
- Cookies or session tokens
- Form input (passwords, emails)
- Client IPs — the privacy middleware logs a truncated SHA-256 of the IP, not
  the address itself

## Compliance

These are the project's design intent, not the outcome of a legal review:

- **GDPR / CCPA** — no personal data is intentionally processed. Note that an
  opted-in screenshot can incidentally contain personal data, which is exactly
  why that path is off by default.
- **Chrome Web Store User Data Policy** — the extension declares the
  escalation path and gates the screenshot behind explicit consent.
