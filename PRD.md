# PhishGuard — Product Requirements Document

**Status:** draft for Phases 1–3
**Owner:** sasib
**Companion docs:** [TRD.md](TRD.md) · [IMPLEMENTATION-PLAN.md](IMPLEMENTATION-PLAN.md) · [AUDIT.md](AUDIT.md) · [THREAT-MODEL.md](THREAT-MODEL.md) · [ROADMAP.md](ROADMAP.md)

This PRD covers what to build next and why. It assumes Phase 0 is complete
(shipped: [PR #1](https://github.com/shroff45/Phishing-detection-_AI/pull/1)).

---

## 1. Problem

Phishing detection that relies on URL text alone loses to an attacker who
controls the URL. All 30 features currently in the model are chosen by the
adversary — hostname, path, query, TLD, length. A phishing page hosted on a
clean-looking domain with a fresh certificate is invisible to the shipped
classifier.

The system already has the right shape to fix this: a local fast path, an
escalation gate, and a backend that may only raise a verdict. What it lacks is
(a) signals the attacker cannot cheaply control, and (b) any measurement that
would tell us whether detection is actually working.

## 2. Goals

1. **Add signals outside attacker control.** Redirect chains, certificate age,
   and hosting reputation are observable properties of the delivery
   infrastructure, not of a string the attacker types.
2. **Make quality measurable.** Today we cannot answer "does this model work on
   URLs it hasn't seen" or "do the JS and Python feature extractors agree." Both
   must be answerable by a command, and enforced in CI.
3. **Make the verdict explainable.** A score is not actionable; an evidence
   trail is. Users should see *why*, and that trail is also what makes the
   verdict auditable.
4. **Keep the privacy posture honest.** Every claim in the docs stays true as
   features land.

## 3. Non-goals

- **Federated threat-sharing.** Deliberately parked pending poisoned-update
  defense. Do not build it.
- **20k-brand corpus.** 500 brands is a real system with a real evaluation;
  20k is a research project. Cite KnowPhish for the scaling argument instead.
- **An LLM in the verdict path.** The LLM may phrase evidence. It never decides.
- **Replacing the local tier.** On-device inference is the latency budget; the
  backend enriches, it does not become the primary path.

## 4. Users

| User | Needs | Current gap |
|---|---|---|
| End user browsing | To not be phished, with few false alarms | Unmeasured FPR; a false positive on a bank they use destroys trust permanently |
| Self-hoster | To run the backend without leaking data | Works, but the API key is not real auth |
| Reviewer / evaluator | To verify claims against code | Now possible for Phase 0; ML claims still unverifiable |

The reviewer is a real user here. This is a portfolio project, and "can a
skeptical engineer confirm what the docs say" is a product requirement.

## 5. Requirements

Priority: **P1** = next, **P2** = after, **P3** = opportunistic.

### 5.1 Measurement (P1 — do first)

| ID | Requirement | Acceptance |
|---|---|---|
| M-1 | The JS/Python feature-parity test must actually execute | 15/15 cases run and pass. A skip due to a broken harness fails CI rather than reporting green |
| M-2 | Evaluation must gate deployment on FPR at fixed recall | `evaluate.py` loads incumbent metrics, holds recall, compares FPR, exits non-zero on regression |
| M-3 | `deploy.py` must refuse to ship an ungated model | Deployment reads the eval report and aborts unless it says pass |
| M-4 | CI must run the gate and both test suites | `.github/workflows/ci.yml` invokes evaluation and `backend/tests/` |
| M-5 | A human-curated golden set every candidate must pass | Never auto-updated; a poisoned feed cannot move train and eval together |

**Why M-1 is first.** If the two extractors have drifted, the model scores
different features than it was trained on, and every number downstream is
meaningless. It is cheap to fix and it unblocks trusting anything else.

### 5.2 Detection signals (P1)

| ID | Requirement | Acceptance |
|---|---|---|
| D-1 | Follow redirect chains without executing them | Walks up to 10 hops, records every host, flags shortener→shortener and cross-origin hops |
| D-2 | Certificate age from CT logs | "Issued 4 hours ago" surfaces as a weighted signal |
| D-3 | DNS resolution and ASN reputation | IP → ASN → hosting-provider score |
| D-4 | All tools run concurrently, each with its own timeout | One slow tool cannot define the latency of the whole call |
| D-5 | A tool that fails degrades visibly | Contributes no score and says so in the trail — never silently reads as "safe" |

### 5.3 Explainability (P1)

| ID | Requirement | Acceptance |
|---|---|---|
| E-1 | Every signal returns a structured record | `{signal, value, weight, human_readable}` |
| E-2 | The endpoint returns the full trail | Popup renders it without needing to interpret raw scores |
| E-3 | If an LLM narrates, it may only phrase trail contents | Templated slots; any sentence containing a claim absent from the trail is dropped, not regenerated |

### 5.4 Visual / brand (P2)

| ID | Requirement | Acceptance |
|---|---|---|
| V-1 | 500-brand reference corpus | Wikidata + Tranco, with logo embeddings, favicon hashes, DOM-structure hashes |
| V-2 | Send derived features, never pixels | pHash, layout vector, colour summary. Retires the screenshot upload path entirely |
| V-3 | Brand corpus is a comparison reference, not an allowlist | No domain is trusted because it appears in the corpus |

**V-2 is the proper fix for the screenshot problem.** Phase 0 made the consent
honest; V-2 removes the need for consent.

### 5.5 Adversarial (P3)

| ID | Requirement | Acceptance |
|---|---|---|
| A-1 | Authoritative verdict moves server-side | Attacker cannot iterate against the scorer for free |
| A-2 | Adversarial examples in training | Generated by gradient-free search against our own model |
| A-3 | Contamination audit | Synthetic URLs excluded from eval, or train/test separation proven by template |

## 6. Success metrics

The honest framing: we currently have no trustworthy baseline, so the first
milestone is *having a number*, not improving one.

| Metric | Now | Target |
|---|---|---|
| Feature parity verified | No (false green) | 15/15 passing in CI |
| FPR at fixed recall, time-split | Unknown | Measured, then non-regressing |
| `known_url_pass` | `false` | `true` |
| Signals outside attacker control | 1 of 4 (WHOIS) | 4 of 4 |
| Verdicts with an evidence trail | 0% | 100% of escalated |

Deliberately **not** a metric: raw accuracy. On a skewed base rate it is
uninformative, and the existing 95.7% figure is a same-distribution number that
overstates real performance.

## 7. Constraints

- **Verdict monotonicity is load-bearing.** The backend may raise a score, never
  lower it. A compromised backend must be limited to causing false positives,
  which are visible, rather than false negatives, which are not.
- **Fail visible.** Timeout shows *unknown*, never *safe*.
- **The model ships to the client**, so it is readable. Inherent to on-device
  inference; the mitigation is that the authoritative verdict moves server-side.
- **MV3 service worker lifetime** is not guaranteed — no long-lived in-memory
  state.

## 8. Open questions

1. **Does the agentic layer earn its place?** With a fixed tool set and no
   branching, an LLM selector adds latency and nondeterminism for no measured
   gain. Recommended: ship the deterministic orchestrator, then A/B the LLM
   version against it. "I measured both and shipped the winner" is the stronger
   claim.
2. **Which ML tree is canonical?** `ml-retrain/` produced the shipped model
   (verified by checksum). Archive `ml-training/` or delete it, but stop having
   two.
3. **What replaces the API key?** It ships in client code, so it gates casual
   access only. Options: per-install token, or accept it and document the limit.
