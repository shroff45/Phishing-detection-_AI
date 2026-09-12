# PhishGuard 2.0 → 3.0 — Roadmap

**Goal:** the best defensible next version — resume-grade, production-oriented, and honest about
what is built versus designed.
**Organised on the deck's own P1/P2/P3 spine (slide 13)**, because that sequencing is sound.

Read `AUDIT.md` for findings and `THREAT-MODEL.md` for the adversary analysis. This document is
the *plan*; those two are the *justification*.

---

## 0. Where you actually are

Worth stating plainly, because the gap between deck and repo is smaller than the deck-vs-repo
table alone suggests.

**The two-tier substrate is real and already wired.** `service-worker.js:585` sets a
`suspicious` verdict at `finalScore >= 0.35`; line 596 is a step labelled *"Backend escalation
with VERDICT MONOTONICITY"*; `escalateToBackend` posts to a live `POST /api/v1/analyze/full` that
fuses threat feeds, a visual path, and a client score. The confidence gate, the escalation path,
the monotonicity rule, and the async-agent socket all exist.

What does not exist is **anything agentic in that socket**. `backend/requirements.txt` contains
no agent framework, no LLM client, and no vector store — a grep for
`langchain|openai|anthropic|chromadb|faiss|qdrant|pgvector|sentence-transformers|torch|transformers`
across the repo matched only URL strings in `ml-retrain/datasets/legitimate_urls.csv`. Tier 2
today is hand-written additive scoring in `compute_meta_score` over four feeds.

**So P1 is "fill a socket that exists," not "build an architecture."** That is a much better
position than the audit's critical findings imply, and it should be how you frame the project.

---

## Phase 0 — Make it true and make it run · **1 day, do before anything else**

Nothing below matters if a reviewer clones the repo and it doesn't work, or reads the deck and
catches a claim the code contradicts. Every item here is small and unblocks credibility.

| # | Action | Why |
|---|---|---|
| 0.1 | Fix `.gitignore`: `/build/ /dist/ /lib/ !extension/lib/` and vendor `ort.min.js` + WASM with a committed SHA-256 | `AUDIT.md` C1 — fresh clone is non-functional. Do **not** fetch WASM from a CDN at runtime (`THREAT-MODEL.md` §5) |
| 0.2 | Remove `models/model.onnx` from `web_accessible_resources`; scope the WASM entries away from `<all_urls>` | `AUDIT.md` C2 / `THREAT-MODEL.md` A1 — one line, closes the #1 gap |
| 0.3 | Stop uploading raw screenshots, **or** re-tense slide 10 to *"redaction — designed, not yet shipped"* | C3. The code-vs-promise contradiction is the single most damaging thing a reviewer can find |
| 0.4 | Wrap `_check_domain_age` in `anyio.to_thread.run_sync` | H1 — `anyio` is already a dependency |
| 0.5 | Write a `README.md`: what it is, how to run it, what's built vs designed, one architecture diagram | M8. No README on a portfolio repo is a self-inflicted wound |
| 0.6 | Pin every dependency to `==` and commit a lock | M9 — an unreproducible ML pipeline is not a pipeline |
| 0.7 | Delete the orphaned static blocklist and the unreachable `extension/offscreen/`; keep the DNR **dynamic** rules path (`service-worker.js:809–813`) — that one is live | M1, M2 |
| 0.8 | Drop the redundant `<all_urls>` host permission, or justify it in the README | Store-review blocker |
| 0.9 | Re-tense the deck: **Built** / **Designed** / **Planned** on every claim | The strongest move available. "Designed, with the socket already built" reads as engineering maturity; the same claim in the present tense reads as overselling |

**On 0.9 — do it regardless of whether you build Phase 1.** A reviewer who catches one
overstated claim re-reads everything else with suspicion. A reviewer who sees an explicit
built/designed split trusts the whole document. The deck's content is genuinely strong; only the
tense is wrong.

---

## Phase 1 — The interrogation agent, for real · **~1 week**

Deck slide 5: a tool-calling agent over WHOIS · DNS · CT logs · redirect chain · Safe Browsing,
running async on borderline pages only. You have two of five tools and no agent.

### 1.1 · The three missing tools

These are the highest-value work in the entire roadmap, because each one adds a signal the
attacker **cannot cheaply control** (`THREAT-MODEL.md` §9.2) — unlike the 30 lexical features,
all of which they choose.

- **Redirect-chain follower** — `httpx.AsyncClient(follow_redirects=False)`, walk hops manually,
  cap at ~10, record every intermediate host, flag shortener→shortener and cross-origin hops.
  This is the direct answer to open-redirect abuse (`THREAT-MODEL.md` A2) and Tier 1 is
  completely blind to it.
- **CT-log / certificate age** — query crt.sh for the leaf domain. *"Certificate issued 4 hours
  ago"* is one of the strongest single indicators in phishing detection, and it is nearly free.
- **DNS / ASN reputation** — resolve, map IP → ASN, score the hosting provider. Catches the
  bulletproof-hosting cluster the deck's slide 6 evidence trail already narrates.

Each is 30–80 lines and independently testable. **Ship them as plain async functions first, with
no agent framework at all** — a deterministic orchestrator that calls all five tools in parallel
via `asyncio.gather` is faster, cheaper, more debuggable, and empirically often as accurate as
LLM tool-selection on a fixed five-tool set.

### 1.2 · Then decide whether you need an agent

Be honest with yourself here, because a reviewer will ask.

With five fixed tools and no branching, **an LLM tool-selector adds latency, cost, and
nondeterminism for no measured gain**. The agentic framing earns its keep when tool selection is
genuinely conditional — *"the redirect chain ended at a login form, so now fetch the brand
corpus and compare logos"* — or when the tool set grows past what you can hand-wire.

Two defensible positions, in order of preference:

- **Recommended:** ship the deterministic parallel orchestrator, then add LLM tool-selection
  behind a flag and A/B it against the deterministic path on the same eval set. *"I built the
  agentic version, measured it against a deterministic baseline, and shipped the one that won"*
  is a far stronger claim than *"I used LangChain."* This is also exactly what slide 11's
  "A/B each agent" methodology already commits you to.
- **Acceptable:** go straight to a tool-calling loop for the learning value, but say so, and keep
  the deterministic path as a fallback for when the LLM is slow or unavailable.

### 1.3 · Evidence-trail surface

Slide 6's evidence trail is a genuinely good UI idea and mostly a serialization problem: every
tool returns `{signal, value, weight, human_readable}`, the endpoint returns the list, the popup
renders it. Do this even if you never add an LLM — **structured evidence is what makes the
verdict trustworthy**, and it is the thing a reviewer will actually click on.

### 1.4 · Non-negotiable while doing 1.1–1.3

- Preserve **verdict monotonicity** (`service-worker.js:596`). Escalation may raise a verdict,
  never silently lower it. This is a mature instinct and already correct — do not regress it.
- **Fail visible.** On backend timeout, show *unknown*, not *safe* (`THREAT-MODEL.md` A5). Test
  this path explicitly; it is the one an attacker will target.
- Every tool gets its own timeout. Five tools behind one 10s budget means the slowest defines UX.
- Cache aggressively by domain. WHOIS and CT data are stable for hours.

---

## Phase 2 — Brand corpus and grounded explanations · **~2 weeks**

Deck slides 4, 7, 8. This is the "cannot fake what it must show the victim" thesis, and it is
the part of the deck with real research behind it.

### 2.1 · Corpus, sized honestly

The deck cites **KnowPhish (USENIX Security 2024)**: expanding a reference set from 277 to ~20k
brands roughly doubled recall for reference-based detectors. That is the right citation and the
right justification.

Slide 13 says top 500 for P2 — **keep that number.** 500 brands from Wikidata + Tranco, with
logo embeddings, favicon hashes, and DOM-structure hashes in a vector store, is a real system
with a real evaluation. 20k is a research project. Shipping 500 and *citing* the 20k result as
the scaling argument is the credible position.

### 2.2 · Privacy-first visual pipeline — resolves C3 properly

This is where the screenshot problem gets solved rather than papered over.

Send **derived features, never pixels**: perceptual hash, downsampled layout vector, colour
palette summary, edge/region statistics. These carry the brand-similarity signal at a small
fraction of the PII, they are far cheaper to transmit, and they make slide 10 literally true
instead of aspirational.

If raw pixels are ever genuinely required: redact `<input>` regions and PII-pattern text nodes
*before* encoding, downscale, use JPEG (`quality` is a no-op for PNG — `AUDIT.md` C3), require
explicit revocable opt-in defaulting **off**, and state and enforce a retention window.

Note that the current `visual_analyzer` uses **easyocr + heuristics, not CNN embeddings** —
slide 4 claims embeddings. Either implement them in this phase or re-tense the slide.

### 2.3 · Grounded narration

Slide 8's design is correct and unusually disciplined: **templated slots, the LLM never sets the
verdict, consistency check, hallucinated claim = dropped claim.** Implement it exactly as
specified. The verdict comes from the scorer; the LLM only phrases evidence that is already in
the structured trail; any sentence containing a claim not present in the trail is dropped, not
regenerated.

Keep the no-allowlist rationale from slide 7. It is correct — an allowlist is a single
high-value poisoning target, and *"a brand corpus is a reference for comparison, not a
permission list"* is the right framing.

---

## Phase 3 — Drift, retraining, adversarial hardening · **ongoing**

### 3.1 · Build the eval gate — it does not currently exist

Slide 9 promises *"deploy only if FPR improves at fixed recall"*, enforced in CI. **This was
verified against the code and the gate is not implemented.** Specifically:

- `ml-retrain/evaluate.py:95` computes `fpr` and writes it to `evaluation_report.json` — but
  never compares it against a baseline and never exits non-zero.
- `ml-retrain/deploy.py` copies the model to `extension/models/` unconditionally. It never
  opens `evaluation_report.json`.
- `run_pipeline.py:42–50` swallows every stage exception and only aborts on stages 3–4.
  Evaluation is stage 5, so **it can fail outright and deployment still runs**.
- `.github/workflows/ci.yml` never invokes `evaluate.py` or the pipeline at all.

The closest thing to a gate is `ml-training/retrain_pipeline.py:90` (`new_auc_pr >= old_auc_pr
and new_f1 >= old_f1`) — a different metric pair, in a different ML tree, and it compares
against `reports/metrics.json`, **a file that does not exist**, so `should_deploy` defaults to
`True` on the first run and every run after it.

So slide 9 must be re-tensed to future ("planned"), and building the gate is real Phase 3 work:
have `evaluate.py` load the incumbent's metrics, fix recall, compare FPR, and `sys.exit(1)` on
regression; have `deploy.py` refuse to copy unless the report says pass; and call both from CI.

Treat this gate as a **security control**, not a quality gate: it is the primary defense against
retrain poisoning (`THREAT-MODEL.md` A3).

### 3.1b · Fix the retrain workflow, which cannot currently run

`.github/workflows/retrain.yml` is broken independently of the gate — worth fixing in the same
pass since both touch the same files:

- It runs `cd ml-training && pip install -r requirements.txt && python retrain_pipeline.py`.
  That file exists, but `retrain_pipeline.py:41` then looks for `data/phishing_dataset.csv` and
  aborts if missing — the directory is not in the repo.
- Steps 32–51 check for and commit `url_classifier.onnx` in `extension/models/` and
  `backend/models/`. **Neither file exists** — the shipped artifact is `extension/models/model.onnx`,
  and `backend/models/` is not a directory at all (the backend model lives at
  `backend/app/models/`). The `git diff | grep` check therefore never matches, so the commit step
  never fires. The workflow is a no-op that reports success.

Decide which ML tree is canonical (`ml-retrain/` is the more complete one and matches the
shipped 30-feature `model_config.json`), delete or clearly archive the other, and point the
workflow at it. This overlaps AUDIT M4 (model artifact sprawl) — same root cause.

### 3.2 · Golden set

Add a small, human-curated, never-auto-updated holdout that every candidate model must pass.
Without it, a poisoned feed can shift both the training data *and* the evaluation data together
and the gate will happily approve the regression.

### 3.3 · Contamination audit

`ml-retrain/synth_generator.py` is 416 lines of synthetic URL generation. Either exclude
synthetic data from evaluation entirely, or prove train/test separation by generation template.
Real time-split evaluation on real feeds is the only number worth reporting — and slide 11
already commits to time-split testing, so this is following through, not new scope.

### 3.4 · Adversarial hardening

Assume the attacker has Tier 1 (`THREAT-MODEL.md` §9.1). Concretely: threshold jitter, model
rotation, adversarial examples in the training set generated by actual gradient-free search
against your own model, and — most importantly — **the authoritative verdict moving server-side**
where the attacker cannot iterate for free.

### 3.5 · Federated threat-sharing — keep it parked

Slide 13 holds this on a research track pending poisoned-update defense. **That is the right
call, and saying so is a signal of judgment.** Do not build it. A reviewer who sees a
deliberately deferred feature with a stated blocker reads that as engineering maturity; the same
feature half-built reads as scope creep.

---

## Sequencing, at a glance

```
Phase 0 ─── 1 day ──── correctness + honesty ─── DO THIS FIRST, UNCONDITIONALLY
   │
   ├─ Phase 1 ── ~1 week ── 3 missing tools → deterministic orchestrator
   │                        → evidence trail → A/B the agentic version
   │
   ├─ Phase 2 ── ~2 weeks ─ 500-brand corpus → derived-feature visual pipeline
   │                        → grounded narration (resolves C3 properly)
   │
   └─ Phase 3 ── ongoing ── verify eval gate → golden set → contamination audit
                            → adversarial hardening
```

**If you do only one phase, do Phase 0.** A working clone, a README, a model that isn't
world-readable, and a deck whose tense matches the code is worth more to a reviewer than a
half-built agent on top of a repo that doesn't run.

**If you do two, add Phase 1's three tools.** Redirect chain, certificate age, and ASN
reputation are the difference between a URL classifier and a phishing detector — and they are
the concrete technical answer to the question the deck's own slide 3 poses.

---

## How to talk about this

The project's genuine strengths, in the order a reviewer will care about:

1. **The two-tier architecture is real** — confidence gate, async escalation, verdict
   monotonicity, all shipping. This is the hard part and it is done.
2. **`test_feature_parity.py`** — you identified that split JS/Python inference silently
   diverges, and you wrote a test for it. That is the single most sophisticated thing in the
   repo. Lead with it.
3. **FPR-first methodology** (slide 11) — time-split, skewed base rates, calibrated categories
   over raw scores. Most student projects report accuracy on a balanced set. This does not.
4. **The no-allowlist argument** (slide 7) — a correct, well-reasoned security decision with an
   explicit threat rationale.
5. **Federated sharing deferred with a stated blocker** — knowing what *not* to build.

Frame the agentic layer as **designed, with the integration socket already built and load-bearing**.
That is accurate, verifiable from the code, and stronger than either overclaiming or omitting it.
