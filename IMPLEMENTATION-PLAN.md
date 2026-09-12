# PhishGuard — Implementation Plan

**Companion docs:** [PRD.md](PRD.md) · [TRD.md](TRD.md) · [ROADMAP.md](ROADMAP.md)

Sequenced work items. Each has a definition of done that is checkable by running
something, not by reading it.

**Branch discipline:** one branch per stage off `main` in
`shroff45/Phishing-detection-_AI`. Do not push to `shroff45/Phishing_detection2.0`.
Keep `baseline-upstream` untouched as the pre-audit reference.

---

## Stage 1 — Make measurement possible · ~2 days

Nothing after this is trustworthy until this is done. If you do one stage, do this.

### 1.1 Fix the feature-parity harness

**Root cause is already diagnosed** (TRD §2): the brace-slice extracts the
function but not the module-level constants it closes over, so the JS throws
`ReferenceError: PHISH_KEYWORDS is not defined`, and the test converts that
crash into a misleading skip.

- [ ] In `tests/test_feature_parity.py`, hoist the needed constants
      (`PHISH_KEYWORDS:78`, `SUSPICIOUS_TLDS:84`, `SHORTENER_DOMAINS:90`) into
      the generated harness alongside the function body.
- [ ] Split the skip condition: probe `node --version` separately. Node absent →
      legitimate skip. Extraction produced broken JS → **fail**.
- [ ] Surface the actual stderr in the failure message.

**Done when:** `pytest ../tests/test_feature_parity.py -q` reports `15 passed`,
and deliberately breaking one JS feature turns the suite red.

### 1.2 Establish whether the extractors have drifted

- [ ] With the harness working, record which of the 30 features disagree.
- [ ] Fix each disagreement, deciding per feature which side is correct.

**Done when:** all 30 agree, and the diff explaining any changed behaviour is
committed.

> This step may be anticlimactic (they might already agree) or it may be the
> most important finding in the project. We genuinely do not know yet — that is
> the point.

### 1.3 Make CI run everything

- [ ] `.github/workflows/ci.yml` runs `pytest ../tests/ tests/` from `backend/`.
- [ ] Replace the hand-listed `py_compile` steps with a real collection run.

**Done when:** CI fails if `backend/tests/` fails.

---

## Stage 2 — The evaluation gate · ~3 days

Second because a gate over unverified features would enforce the wrong thing.

### 2.1 Pick the canonical ML tree

- [ ] Archive or delete `ml-training/`. `ml-retrain/` is canonical — its
      `phishing_model_v4.onnx` is byte-identical to the shipped model (verified
      by checksum).
- [ ] Note the decision in the README.

### 2.2 Build the gate

- [ ] `evaluate.py`: load incumbent metrics, fix recall at the **shipped**
      operating point, compare FPR, `sys.exit(1)` on regression.
- [ ] Write an explicit `pass: true/false` into `evaluation_report.json`.
- [ ] `deploy.py`: read the report, refuse to copy unless it passes.
- [ ] `run_pipeline.py`: stop swallowing stage exceptions.

### 2.3 Reconcile the operating point

- [ ] Evaluate at 0.35/0.65 (what ships), not `optimal_threshold: 0.798`.
- [ ] Either adopt the model's threshold or document why the hand-picked bands
      are better — but measure the one users get.

### 2.4 Fix `known_url_pass`

- [ ] Currently `false`. Find which known-good URLs are misclassified.
- [ ] Fix or document. A 1.7% FPR that includes popular domains is not a 1.7%
      FPR in practice.

### 2.5 Golden set

- [ ] Small, human-curated, never auto-updated. Every candidate must pass.

**Done when:** a deliberately worse model fails CI and does not deploy.

---

## Stage 3 — Signals outside attacker control · ~1 week

The difference between a URL classifier and a phishing detector.

Build in this order — each is independently shippable, so value lands
incrementally rather than at the end.

### 3.1 Shared plumbing first

- [ ] Define the signal record: `{signal, value, weight, human_readable, status}`.
- [ ] Retrofit existing feeds and WHOIS to emit it. Do this **before** adding
      tools, so there is one format rather than two.
- [ ] Per-tool timeout wrapper.
- [ ] Domain-keyed cache with TTL.

### 3.2 Certificate age (do this one first)

Cheapest, highest signal-to-effort, single dependency.

- [ ] crt.sh query for the registrable domain, earliest leaf issuance.
- [ ] Weight scaled by age; <24h is strong.
- [ ] Tests: normal, timeout, malformed response.

### 3.3 DNS / ASN reputation

- [ ] Resolve, map IP → ASN, score the provider.
- [ ] Seed from the existing `SUSPICIOUS_HOSTING` set rather than a new list.
- [ ] Blocking resolver → `anyio.to_thread.run_sync(abandon_on_cancel=True)`,
      same pattern as WHOIS.

### 3.4 Redirect-chain follower (do this one last)

Highest value, highest risk — it makes our server touch attacker
infrastructure.

- [ ] `follow_redirects=False`, manual walk, 10-hop cap, independent total-time
      cap.
- [ ] No cookies, no credentials, byte-capped response bodies.
- [ ] Flag shortener→shortener, cross-origin, registrable-domain change.
- [ ] Tests: loops, >10 hops, oversized bodies, malformed `Location` headers.

### 3.5 Parallel orchestration

- [ ] `asyncio.gather` / task group over all five tools, each with its own
      timeout.
- [ ] **No agent framework.** Deterministic first.
- [ ] Fail-visible test: a timing-out tool yields *unknown*, never *safe*.
- [ ] Monotonicity test: a low backend score cannot lower a high local score.

**Done when:** an escalated URL returns five structured signals, and killing any
one tool degrades the trail visibly without changing the verdict to safe.

---

## Stage 4 — Evidence trail UI · ~2 days

Cheap, and it is what a reviewer actually clicks on.

- [ ] Endpoint returns the full trail.
- [ ] Popup renders signal rows with human-readable text, not raw scores.
- [ ] Degraded signals shown as degraded, not hidden.

**Done when:** the popup explains a verdict without showing a single number.

---

## Stage 5 — Retire the screenshot path · ~1 week

- [ ] Compute pHash, layout vector, colour summary in the extension.
- [ ] Backend accepts derived features.
- [ ] Remove screenshot upload and the `shareScreenshots` toggle entirely.
- [ ] Update both PRIVACY files in the same commit.

**Done when:** no image bytes leave the browser and the privacy claim needs no
consent caveat.

---

## Stage 6 — Brand corpus · ~1 week

- [ ] 500 brands from Wikidata + Tranco.
- [ ] Logo embeddings, favicon hashes, DOM-structure hashes.
- [ ] Comparison reference only — **never** an allowlist.
- [ ] Cite KnowPhish for the scaling argument; do not attempt 20k.

---

## Stage 7 — Adversarial hardening · ongoing

- [ ] Move the authoritative verdict server-side.
- [ ] Adversarial examples via gradient-free search against our own model.
- [ ] Contamination audit: exclude synthetic URLs from eval, or prove
      train/test separation by template.
- [ ] **Federated sharing stays parked.** Deferred with a stated blocker reads
      as judgment; half-built reads as scope creep.

---

## Sequencing

```
Stage 1  parity + CI        ~2d   ◀── BLOCKING, do first
Stage 2  eval gate          ~3d   ◀── depends on Stage 1
Stage 3  three new tools    ~1w   ◀── the actual detection win
Stage 4  evidence trail     ~2d   ◀── cheap, high reviewer value
Stage 5  retire screenshots ~1w
Stage 6  brand corpus       ~1w
Stage 7  adversarial        ongoing
```

**Rationale for putting measurement before features:** the project is currently
a working system whose quality is unmeasured. Adding signals to an unmeasured
system produces a larger unmeasured system. Stages 1–2 are two-thirds the cost
of Stage 3 and convert every subsequent claim from asserted to demonstrated.

**If you have one week:** Stages 1, 2, and 4. Verified parity, a real gate, and
a UI that explains itself.

**If you have three:** add Stage 3. That is the point where this stops being a
URL classifier.

---

## Carried-forward items

Small, unblocked, not worth their own stage:

- [ ] `autoScan` and `showWarningOverlay` are saved by the options page and read
      by nothing. (`allowBackendEscalation` was wired up in Phase 0.)
- [ ] Fix `.github/workflows/retrain.yml` — a no-op that reports success
      (TRD §4.1). Bundle with Stage 2.
- [ ] Phase 0 item 0.9: re-tense the deck into Built / Designed / Planned.
- [ ] Decide what replaces the shipped API key, or document its limits.
