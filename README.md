# PhishGuard

A Manifest V3 Chrome extension that scores URLs for phishing on-device, and
escalates the ambiguous ones to a FastAPI backend for threat-intelligence
enrichment.

Scoring is local by default: 30 lexical features are extracted from the URL in
the service worker and run through a bundled ONNX random-forest. No network call
is needed to reach a verdict.

> **Status: research prototype.** It works end to end and the test suite is
> green, but see [What's Built vs. What's Designed](#whats-built-vs-whats-designed)
> before reading any part of this as production-ready. Do not install it as your
> only line of defence against phishing.

---

## Architecture

```
                        ┌─────────────────────────────────────────┐
                        │  Chrome Extension  (Manifest V3)        │
   navigation ────────▶ │                                         │
                        │  service-worker.js                      │
                        │    ├─ extract 30 lexical features       │
                        │    ├─ ONNX inference  (onnxruntime-web, │
                        │    │                   vendored WASM)   │
                        │    └─ finalScore ∈ [0,1]                │
                        │         >= 0.65  phishing               │
                        │         >= 0.35  suspicious             │
                        │         else     safe                   │
                        └───────────────┬─────────────────────────┘
                                        │  escalate if score >= 0.25
                                        │  OR brand spoof OR bad host
                                        │  (and user hasn't opted out)
                                        ▼
                        ┌─────────────────────────────────────────┐
                        │  FastAPI backend                        │
                        │    ├─ threat feeds (Safe Browsing, VT)  │
                        │    ├─ WHOIS domain age (5s timeout)     │
                        │    └─ visual analysis (pHash + OCR)     │
                        └───────────────┬─────────────────────────┘
                                        │
                     verdict monotonicity: max(local, backend)
                     the backend can RAISE a score, never lower it
```

**Why monotonicity matters.** A compromised or spoofed backend is a downgrade
oracle otherwise — it could mark every phishing page safe. Taking the max means
the worst a bad backend can do is create false positives, which are visible,
rather than false negatives, which are not.

**The escalation gate is not the verdict band.** Escalation starts at 0.25,
below the 0.35 "suspicious" line, and has no upper cut-off. Pages that end up
labelled *safe* are still sent, and so are confident detections. This is
deliberate — but it means "we only send ambiguous URLs" is a loose description.
See [PRIVACY.md](PRIVACY.md).

---

## Repository Layout

| Path | What it is |
|---|---|
| `extension/` | The MV3 extension. This is the product. |
| `extension/lib/` | Vendored onnxruntime-web 1.17.3, checksum-pinned |
| `extension/models/` | `model.onnx` + `model_config.json` (30 features) |
| `backend/` | FastAPI service — feeds, WHOIS, visual analysis |
| `ml-retrain/` | **The live training pipeline.** Produced the shipped model. |
| `ml-training/` | Older, divergent tree. Its `model.onnx` is *not* what ships. |
| `tests/` | Root suite — feature parity, lexical features. What CI runs. |
| `backend/tests/` | Backend service tests. Run these too; CI currently doesn't. |
| `scripts/` | `verify_vendored_ort.py` — checksum gate for the vendored WASM |

`ml-retrain/` and `ml-training/` are two answers to the same question and only
one is real: the shipped `extension/models/model.onnx` is byte-identical to
`ml-retrain/models/phishing_model_v4.onnx`. Treat `ml-training/` as history.

---

## Running It

### Extension

```bash
python scripts/verify_vendored_ort.py
```

That must pass before loading — it confirms the vendored ONNX Runtime WASM
matches its pinned SHA-256. Then load `extension/` via
`chrome://extensions` → Developer mode → **Load unpacked**.

The extension is fully functional with no backend running; escalation simply
fails open to the local verdict.

### Backend

```bash
cd backend && pip install -r requirements.txt && uvicorn app.main:app --port 7860
```

Or:

```bash
docker-compose up --build
```

Set `EXTENSION_API_KEY` in `backend/.env` and match it in the extension's
settings. **That key is a deployment gate, not authentication** — it ships
inside the extension, so anyone with the extension has it.

### Tests

```bash
cd backend && python -m pytest ../tests/ tests/ -q
```

Both paths matter. CI only runs `../tests/`, which is how assertion bugs in
`backend/tests/` went unnoticed.

---

## API

All endpoints require the `X-API-Key` header except `/health`.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness |
| `POST` | `/api/v1/analyze/quick` | URL-only reputation check |
| `POST` | `/api/v1/analyze/full` | Feeds + WHOIS + optional screenshot |
| `POST` | `/api/v1/feed/update` | Refresh threat feeds |
| `GET` | `/api/v1/feed/rules` | Fetch blocklist rules for the extension |

---

## Model

Random forest, 30 lexical URL features, exported to ONNX. Reported on
`ml-retrain`'s held-out split:

| Metric | Value |
|---|---|
| Accuracy | 0.957 |
| AUC | 0.993 |
| FPR | 0.017 |
| FNR | 0.069 |

Read these numbers with three caveats:

1. **`known_url_pass: false`** in `ml-retrain/reports/evaluation_report.json` —
   the sanity check against a list of known-good URLs did not pass. A 1.7% FPR
   on a random split can still mean visibly wrong calls on popular domains.
2. **Same-distribution split.** No temporal holdout, so this does not estimate
   performance on phishing campaigns newer than the training data.
3. **The shipped thresholds are not the model's.** `model_config.json` carries
   `optimal_threshold: 0.798`; the extension uses 0.35/0.65. The operating
   point in production was chosen by hand, so the FPR above is not the FPR you
   get.

Features are lexical only — no page content, no DOM, no redirect following. A
phishing page on a clean-looking URL is invisible to Tier 1.

---

## What's Built vs. What's Designed

Honest accounting. "Designed" means the code exists but is not load-bearing;
"planned" means it does not exist.

### Built and working
- 30-feature lexical extraction, parity-tested between JS and Python
- On-device ONNX inference with vendored, checksum-pinned runtime
- Two-tier escalation with enforced verdict monotonicity
- Threat-feed lookup, WHOIS with a real 5s timeout and visible degradation
- Backend request-size caps and correlation-ID error handling
- Screenshot sharing as explicit, revocable, default-off consent
- 34 passing tests

### Designed, not load-bearing
- **Visual brand analysis.** pHash + colour + OCR scoring works, but against a
  small hand-built brand set. Not the 500-brand corpus it is meant to be.
- **The API key.** Shipped in client code; it gates casual access, not attackers.
- **`declarativeNetRequest` blocking.** Wired up, driven by feed rules only.

### Planned, not present
- Redirect-chain following, CT-log certificate age, DNS/ASN reputation — the
  three signals that would catch what lexical features cannot
- Derived visual features (pHash + layout vector) to replace raw screenshot
  upload entirely
- An evaluation gate on **FPR at fixed recall**, run in CI, blocking merges.
  This does not exist, which is why the metrics above have caveats instead of
  a regression guard.
- Any agentic orchestration layer. The design calls for one; today the backend
  is plain async functions, which is the right starting point.

### Known gaps
- `autoScan` and `showWarningOverlay` are saved by the options page and read by
  nothing.
- `ml-training/` and `ml-retrain/` have diverged and neither is marked
  canonical in code.
- CI does not run `backend/tests/`.

---

## Security

The model ships inside the extension, so an attacker can read it and craft
URLs that score below threshold — offline, at no cost. This is inherent to
on-device inference, and it is why the backend tier exists and why the backend
may only raise scores.

`model.onnx` is deliberately **not** in `web_accessible_resources`; that would
hand the weights to any page on the internet, not just to someone who installs
the extension. Don't add it back.

## Privacy

[PRIVACY.md](PRIVACY.md) is the engineering note;
[extension/PRIVACY.md](extension/PRIVACY.md) is the user-facing policy and wins
on any disagreement. Screenshot upload is off by default and captures are not
redacted.
