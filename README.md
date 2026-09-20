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

Expect `20 passed, 15 skipped` from the root suite. Those 15 skips are the
feature-parity cases and they are a **known failure wearing a skip's clothing** —
see [Known gaps](#known-gaps).

---

## API

All endpoints require the `X-API-Key` header except `/health`.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness |
| `POST` | `/api/v1/analyze/quick` | URL-only reputation check |
| `POST` | `/api/v1/analyze/full` | Feeds + WHOIS + derived visual features |
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
- 30-feature lexical extraction in both JS and Python
- On-device ONNX inference with vendored, checksum-pinned runtime
- Two-tier escalation with enforced verdict monotonicity (both tiers —
  the service worker's max-merge and the backend's client-score floor)
- Threat-feed lookup, WHOIS with a real 5s timeout and visible degradation
- Certificate-age, DNS/ASN, and redirect-chain signals, each with its own
  timeout budget, a domain cache for stable lookups, and a hardened
  redirect walk (loop detection, cookie stripping, bodies never read)
- Evidence trail: every signal that moved the score, as a uniform
  `{signal, value, weight, human_readable, status}` record, rendered in
  the popup with degraded checks shown, never hidden
- Domain-disjoint ML splits and grouped CV (no train/test domain leakage),
  plus an evaluation gate on FPR at the shipped threshold that runs in CI
  and blocks deployment on regression
- Backend request-size caps and correlation-ID error handling
- Derived visual features: the extension computes a 256-bit favicon aHash
  and a colour summary in-page, and the backend compares them against brand
  reference profiles. No image bytes exist anywhere in the pipeline; the
  screenshot upload path (and its `shareScreenshots` opt-in, and the
  `activeTab` permission) was removed entirely in v1.1.0
- 102 passing tests

### Designed, not load-bearing
- **Visual brand analysis.** The derived-features matcher works and is
  load-bearing on the escalation path, but against a three-brand seed
  corpus. Stage 6 grows it to a proper reference corpus.
- **The API key.** Shipped in client code; it gates casual access, not attackers.
- **`declarativeNetRequest` blocking.** Wired up, driven by feed rules only.

### Planned, not present
- A 500-brand reference corpus (comparison reference only — never an allowlist)
- Adversarial-example testing against our own model (Stage 7)
- Any agentic orchestration layer. The design calls for one; today the backend
  is plain async functions, which is the right starting point.

### Known gaps
- The E2E Playwright suite has fixtures and config committed but its spec
  files are not in the repo; the fixtures' contracts (stub backend on port
  7860, X-API-Key header) are what the committed code is held to.

---

## Security

The model ships inside the extension, so an attacker can read it and craft
URLs that score below threshold — offline, at no cost. This is inherent to
on-device inference, and it is why the backend tier exists and why the backend
may only raise scores.

`model.onnx` is deliberately **not** in `web_accessible_resources`; that would
hand the weights to any page on the internet, not just to someone who installs
the extension. Don't add it back.

### Security Notes

- The `X-API-Key` header is a **development placeholder for request tracing**,
  not an authentication boundary. It ships in the extension's source code, so
  anyone who installs the extension has it.
- Backend authentication is **disabled by default** — when `EXTENSION_API_KEY`
  is empty (the default), the `verify_api_key` dependency skips validation.
  Set the key in `backend/.env` for deployment environments.
- The empty default above is a **dev-only convenience, pinned by the test
  suite**: in any non-dev deployment you MUST set `EXTENSION_API_KEY`, or
  `/api/v1/investigate/detonate` — and every other endpoint — is reachable
  with no credential at all. As noted above, even when set the key is a
  shared dev-contract marker, not a security boundary; treat "unset in a
  non-dev environment" as a misconfiguration to monitor for, not a risk the
  key itself would solve.
- **Rate limiting** is enforced per client IP, configured by `RATE_LIMIT` in
  `config.py` (default: `100/minute`). By default it runs as an in-memory
  sliding window scoped to a single process — running multiple backend
  instances (or `uvicorn --workers N`) gives each its own independent counter,
  so the effective global limit multiplies. Set `REDIS_URL` and install the
  pinned `redis` package to share counters across instances instead. If Redis
  becomes unreachable after startup, limiting degrades back to per-process
  in-memory counters rather than disabling limiting or breaking requests; that
  degraded state is per-process, so the same multiplied-limit caveat applies
  until Redis recovers. Either way this throttles abusive request volume but
  does not prevent all abuse — a distributed attacker with many IPs can still
  consume resources.
- **Per-install rate-limit keying (experimental, default off).** Setting
  `INSTALL_TOKEN_ENABLED=true` teaches the rate limiter to honour an
  `X-Install-Token` request header: when the flag is on AND the header value
  matches `^[A-Za-z0-9._-]{1,64}$`, that request is limited under
  `install:<token>` instead of its client IP — the token **replaces** the IP
  key (it is never combined with IP or path). Flag off, header missing, or
  invalid header all fall back to the existing per-IP limiting, unchanged.
  The token is **caller-supplied and freely rotatable**: this gives honest
  clients per-install fairness (one install's burst doesn't burn a shared IP
  quota), but it is **not** a security boundary or an anti-abuse wall — an
  attacker can mint a fresh token per request, so global per-IP limiting
  remains the fallback for header-less traffic, and the in-memory store caps
  its keyspace (100k distinct keys, dormant keys evicted first) so token
  churn cannot grow memory unboundedly. Leave disabled unless you
  specifically need it.
- For production deployments with external clients, consider per-install token
  issuance rather than a shared static key.
- The extension treats a backend verdict's severity as a **floor**: local boosts
  (e.g. BitB, brand impersonation) may raise it, but never lower it.
- This project is a **research prototype**. Rate limiting is a layer of defence,
  not a guarantee of safety. Do not treat it as production-ready.

## Privacy

[PRIVACY.md](PRIVACY.md) is the engineering note;
[extension/PRIVACY.md](extension/PRIVACY.md) is the user-facing policy and wins
on any disagreement. No image bytes leave the browser: escalation sends the
URL, a numeric score, and derived visual features (favicon hash + colour
summary) only.
