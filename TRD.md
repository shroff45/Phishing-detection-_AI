# PhishGuard — Technical Requirements Document

**Status:** draft for Phases 1–3
**Companion docs:** [PRD.md](PRD.md) · [IMPLEMENTATION-PLAN.md](IMPLEMENTATION-PLAN.md) · [AUDIT.md](AUDIT.md) · [THREAT-MODEL.md](THREAT-MODEL.md)

How to build what the PRD asks for. Every file path and line reference below was
verified against the repo at `security/phase-0-hardening`.

---

## 1. Current architecture

```
 Tier 1 (extension, local)                Tier 2 (backend, network)
 ─────────────────────────                ─────────────────────────
 service-worker.js
   extractLexicalFeatures(rawUrl)   ──▶  POST /api/v1/analyze/full
     30 features                            compute_meta_score()
   ONNX inference (ort-wasm)                  ├─ threat feeds
   finalScore                                 ├─ WHOIS (5s, threaded)
     >=0.65 phishing                          └─ visual (pHash+OCR)
     >=0.35 suspicious
   escalate if >=0.25 OR spoof OR bad host
     └── merge: Math.max(local, backend)   ◀── backend may only RAISE
```

Key existing call sites:

| What | Where |
|---|---|
| Feature extraction (JS) | `extension/background/service-worker.js:261` |
| Verdict thresholds | `service-worker.js:591-592` |
| Escalation gate | `service-worker.js:607` |
| Monotonic merge | `service-worker.js:619` |
| Meta scoring | `backend/app/services/threat_intel.py` → `compute_meta_score` |
| WHOIS (threaded, 5s) | `threat_intel.py` → `_check_domain_age` |
| Full analysis endpoint | `backend/app/main.py:119` |

---

## 2. TR-1 — Fix the feature-parity harness (blocking)

**This is the top technical priority and the root cause is known.**

### Diagnosis (verified, not inferred)

`tests/test_feature_parity.py:78` `_extract_js_function` locates
`function extractLexicalFeatures(rawUrl)` in `service-worker.js` and slices to
the matching closing brace. The slice is correct — 3642 chars, ending at the
function's `}`. But the function closes over module-level constants declared
*outside* that range, so the extracted JS throws at runtime:

```
ReferenceError: PHISH_KEYWORDS is not defined
    at extractLexicalFeatures (frag_probe.js:36:20)
```

`_run_js_extraction` catches the resulting non-zero exit and returns `None`, and
the test converts that into `pytest.skip("Node.js not available or JS extraction
failed")`. Node 22 is installed. **The message is misleading and the skip masks
a hard failure** — all 15 cases report as skipped.

### Constants the function needs

Declared at `service-worker.js:78-151`:

- `PHISH_KEYWORDS` (line 78) — confirmed required
- `SUSPICIOUS_TLDS` (84)
- `SHORTENER_DOMAINS` (90)

### Required fix

1. Extend the harness to hoist module-level `const` declarations the function
   references, not just the function body. Simplest robust approach: slice from
   the first needed constant through the end of the function.
2. **Change the failure mode.** A harness that cannot produce JS must `fail`,
   not `skip`. Distinguish genuinely-absent Node (legitimate skip) from
   extraction failure (bug) by probing `node --version` separately.
3. Assert all 30 features match, with a tolerance of 0 for integer features.

**Better long-term fix:** extract the shared feature logic into a single file
that both the service worker and the test import, so there is nothing to slice.
Recommend doing the harness fix now (small, unblocks measurement) and noting the
refactor as follow-up.

### Acceptance

`pytest ../tests/test_feature_parity.py -q` reports `15 passed`. Deliberately
break one JS feature and confirm the suite goes red.

---

## 3. TR-2 — The three missing signal tools

Ship as **plain async functions with no agent framework.** A deterministic
orchestrator calling all tools via `asyncio.gather` is faster, cheaper, and
more debuggable than LLM tool-selection over a fixed set.

Each tool returns the same structured record so the evidence trail is uniform:

```python
{
  "signal": "cert_age",
  "value": 4.2,                    # hours
  "weight": 0.25,                  # contribution to score
  "human_readable": "TLS certificate issued 4 hours ago",
  "status": "ok",                  # ok | timeout | unavailable
}
```

`status` is not decoration — it is what makes "fail visible" enforceable. A
tool with `status != "ok"` contributes `weight: 0.0` and still appears in the
trail.

### TR-2.1 Redirect-chain follower

- `httpx.AsyncClient(follow_redirects=False)`, walk hops manually.
- Cap at 10 hops; cap total time independently of the per-request timeout.
- Record every intermediate host.
- Flag: shortener→shortener, cross-origin hops, hop count > 3, final host ≠
  initial registrable domain.
- **Never execute page content.** `HEAD` first, fall back to `GET` with a byte
  cap on the response body. Following a redirect chain means touching
  attacker-controlled infrastructure from our server — treat every response as
  hostile input.
- Do not send cookies or credentials; disable any connection reuse across
  target hosts.

### TR-2.2 Certificate age via CT logs

- Query crt.sh for the registrable domain; take the earliest leaf issuance.
- Cache by domain for hours — CT data is stable.
- Certificates under ~24h old are a strong signal; scale the weight by age.
- crt.sh is a third-party dependency: on timeout, `status: "timeout"`, weight 0.

### TR-2.3 DNS / ASN reputation

- Resolve A/AAAA, map IP → ASN, score against known bulletproof-hosting ASNs.
- Reuse the existing `SUSPICIOUS_HOSTING` set (`service-worker.js:96`) as the
  seed list rather than inventing a second source of truth.
- DNS resolution is blocking in most Python libraries — use the same
  `anyio.to_thread.run_sync(..., abandon_on_cancel=True)` pattern already
  applied to WHOIS in `threat_intel.py`.

### TR-2.4 Orchestration

```python
async def gather_signals(url: str) -> list[dict]:
    async with anyio.create_task_group() as tg:
        # each tool wrapped in its OWN fail_after — one slow tool
        # must not consume the budget of the others
        ...
```

Per-tool timeouts, not one shared budget. Five tools behind a single 10s cap
means the slowest defines UX for all of them.

### Scoring integration

`compute_meta_score` currently does additive scoring over four feeds. Extend it
with the new signals, and keep the total bounded to `[0, 1]`. **Do not let new
signals lower an existing score** — that would breach monotonicity at the
backend layer rather than the client layer.

---

## 4. TR-3 — The evaluation gate

The gate does not exist today. Verified:

- `ml-retrain/evaluate.py:95` computes FPR, writes it to
  `evaluation_report.json`, never compares it to a baseline, never exits
  non-zero.
- `ml-retrain/deploy.py` copies the model unconditionally; never opens the
  report.
- `run_pipeline.py:42-50` swallows stage exceptions and only aborts on stages
  3–4. Evaluation is stage 5, so **it can fail outright and deploy still runs.**
- `.github/workflows/ci.yml` never invokes `evaluate.py`.

### Required

1. **`evaluate.py`** — load the incumbent's metrics, fix recall at a declared
   operating point, compare FPR, `sys.exit(1)` on regression. Write pass/fail
   into the report explicitly, not just raw metrics.
2. **`deploy.py`** — read the report; refuse to copy unless it says pass.
3. **`run_pipeline.py`** — stop swallowing exceptions; a failed evaluation stage
   must abort the pipeline.
4. **CI** — invoke the gate. Also add `backend/tests/` to the pytest
   invocation; CI currently runs only `../tests/`, which is why assertion bugs
   in the backend suite went unnoticed.
5. **Fix `known_url_pass: false`** — currently failing in
   `ml-retrain/reports/evaluation_report.json`. A 1.7% FPR on a random split can
   still mean visibly wrong calls on popular domains.
6. **Reconcile thresholds.** `model_config.json` carries
   `optimal_threshold: 0.798`; the extension uses 0.35/0.65. The gate must
   evaluate at the *shipped* operating point, or the measured FPR is not the
   FPR users get.

Treat this gate as a **security control**, not a quality gate — it is the primary
defense against retrain poisoning.

### TR-3.1 Also fix the retrain workflow

`.github/workflows/retrain.yml` is a no-op that reports success:

- Runs `ml-training/retrain_pipeline.py`, which aborts on a missing
  `data/phishing_dataset.csv` (not in the repo).
- Checks for `url_classifier.onnx` in `extension/models/` and `backend/models/`.
  Neither exists — the shipped artifact is `extension/models/model.onnx` and
  `backend/models/` is not a directory. The `git diff | grep` never matches, so
  the commit step never fires.

Point it at `ml-retrain/` (canonical — its v4 model is byte-identical to the
shipped one, verified by checksum) and archive `ml-training/`.

---

## 5. TR-4 — Derived visual features

Retires the screenshot upload path.

Client-side, in the extension: compute perceptual hash, downsampled layout
vector, colour palette summary. Send those instead of pixels. This carries the
brand-similarity signal at a fraction of the PII and makes the privacy claim
unconditional rather than consent-gated.

Note the current `visual_analyzer` uses **easyocr + heuristics, not CNN
embeddings.** If embeddings are claimed anywhere, either implement them here or
correct the claim.

---

## 6. Non-negotiables

Regressing any of these is worse than not shipping the feature:

1. **Verdict monotonicity** (`service-worker.js:619`). Escalation may raise,
   never lower.
2. **Fail visible.** Timeout → *unknown*, never *safe*. Test this path
   explicitly; it is what an attacker will target.
3. **Per-tool timeouts.**
4. **Cache by domain.** WHOIS and CT are stable for hours.
5. **No new secrets in client code.** The existing API key is already a gate
   rather than auth; do not add more.
6. **Docs stay true.** If a feature changes behaviour, the PRIVACY files and
   README change in the same commit.

---

## 7. Testing requirements

| Layer | Requirement |
|---|---|
| Feature parity | 15/15 executing; harness failure is a test failure, not a skip |
| Each new tool | Unit tests with mocked network, including timeout and malformed-response paths |
| Fail-visible | Explicit test that a timing-out tool yields *unknown* and not *safe* |
| Monotonicity | Test that a low backend score cannot lower a high local score |
| Redirect follower | Test a hostile chain: loops, >10 hops, oversized bodies |
| CI | Runs `tests/` **and** `backend/tests/`, plus the eval gate |

Current baseline: 34 passed, 15 skipped. The skips must become passes before any
new-signal work is trustworthy.
