# PhishGuard / Phishing_detection2.0 — Repository Audit

**Repo:** https://github.com/shroff45/Phishing_detection2.0
**Deck audited against:** `PhishingDetection2_Agentic.pptx` (14 slides)
**Reviewer stance:** senior AI/ML security engineer + browser-extension architect + red team
**Date:** 2026-08-01

> **Note on scope:** the original prompt contained a lettered question list (A/B/C…) that was
> lost to a context truncation. This document answers the headline task — *audit the repo and
> design the best possible next version as a resume-grade, production-oriented system*. If the
> lettered sub-questions mattered, re-paste them and I'll map answers onto them directly.

---

## 0. Verdict in one paragraph

The repo is a **competent lexical-URL classifier with a threat-feed backend**, wrapped in an
MV3 extension whose two-tier *shape* is genuinely built. The deck sells something else: a
four-signal visual/NLP/DOM/reputation fusion engine, a tool-calling investigation agent, a
brand-fingerprint vector store, guardrailed LLM narration, and a drift agent behind an FPR gate.
**None of the four agentic components exist at the dependency level.** On top of that gap sit
three shipping-blocking defects: a fresh clone produces a **non-functional extension**, the
extension **uploads un-redacted full-viewport screenshots** in direct contradiction of its own
privacy slide, and the **ONNX model is world-readable to every page you visit**, handing an
attacker a white-box target. Fix those three and close the honesty gap between deck and code,
and this becomes a strong portfolio project. Ship it as-is and a technical reviewer will find
all three inside ten minutes.

---

## 1. Critical findings

### C1 — A fresh clone yields a non-functional extension

`.gitignore` is an unedited stock **Python** template applied to a polyglot repo. Inside the
*"Distribution / packaging"* block:

```
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/          <-- unanchored: matches extension/lib/ too
lib64/
```

`extension/background/service-worker.js:15`:

```js
importScripts("../lib/ort.min.js");
```

Empirically confirmed on a clean clone:

```
$ ls extension/lib
ls: cannot access 'extension/lib': No such file or directory
```

The manifest also declares `lib/ort-wasm.wasm` and `lib/ort-wasm-simd.wasm` in
`web_accessible_resources` — both 404 in a fresh clone. The service worker throws on line 15,
so **no detection runs at all**. Anyone who clones this to evaluate it sees a dead extension.

**Fix:** anchor the rule to the repo root and negate the extension path.

```gitignore
/build/
/dist/
/lib/
!extension/lib/
```

Then vendor `ort.min.js` and the two `.wasm` files, or add a `postinstall` fetch step with a
pinned version and a SHA-256 check. Do not silently depend on a CDN — an extension that pulls
executable WASM from a third party at runtime is its own supply-chain finding.

---

### C2 — The classifier is world-readable to every page you visit

`extension/manifest.json`:

```json
"web_accessible_resources": [{
  "resources": ["lib/ort-wasm.wasm","lib/ort-wasm-simd.wasm","models/model.onnx",
                "blocked.html","icons/*"],
  "matches": ["<all_urls>"]
}]
```

`models/model.onnx` exposed to `<all_urls>` means **any page — including a phishing page —
can `fetch()` your classifier** at a known extension-scoped URL. Combined with
`extension/models/model_config.json`, which ships in the bundle and lists all 30 feature names
plus:

```json
"optimal_threshold": 0.7980721946781608
```

…an attacker gets the model weights, the exact feature extraction spec, and the decision
boundary. That is a **complete white-box evasion setup**: gradient-free search over URL strings
until the score lands under 0.798, verified offline, zero requests to you. Detection cost of
that attack is zero because it never touches your infrastructure.

**Fix, in order of preference:**

1. Remove `models/model.onnx` from `web_accessible_resources` entirely. The service worker
   loads it via `chrome.runtime.getURL()` from its own context; it does **not** need to be
   web-accessible. This is a one-line fix and should happen today.
2. Scope the WASM entries the same way — nothing in that list needs `<all_urls>`.
3. Longer term, accept that any client-side model is extractable by a determined attacker who
   installs the extension. Treat Tier 1 as a *cheap filter*, and keep the authoritative
   decision (and any model you actually care about protecting) server-side. Add threshold
   jitter and periodic model rotation so a scraped copy decays.

Two further manifest defects in the same file:

- `"host_permissions": ["http://localhost:7860/*", "<all_urls>"]` — `<all_urls>` alongside
  `activeTab` + `webNavigation` is redundant and is a Chrome Web Store review blocker on its
  own. Justify or drop it.
- A hardcoded plaintext `http://localhost:7860` shipped in a manifest marked `"version": "1.0.0"`,
  with no production origin. Screenshots would cross cleartext HTTP the moment that origin is
  anything but loopback.

---

### C3 — Un-redacted full-viewport screenshots leave the device

Deck slide 10 states: *"keystrokes, passwords, PII never leave the device"*, and lists
*"DOM & screenshot redaction — emails, names & account numbers stripped before any upload"*
as a **"(v2 upgrade)"** — i.e. self-labelled as not built.

`extension/background/service-worker.js:658–693`:

```js
async function escalateToBackend(tabId, url, clientScore) {
  let screenshotBase64 = null;
  try {
    const dataUrl = await chrome.tabs.captureVisibleTab(null, {
      format: "png",
      quality: 70,
    });
    screenshotBase64 = dataUrl; // includes data:image/png;base64, prefix
  } catch (err) { /* ... */ }
  const body = { url, client_score: clientScore, screenshot_base64: screenshotBase64 };
  const response = await fetch(`${BACKEND_URL}/api/v1/analyze/full`, { /* ... */ });
}
```

Three problems stacked:

1. **The upload is un-redacted.** Every escalation ships a pixel-accurate image of whatever the
   user is looking at. Escalation fires in the 0.35–0.75 band, which by the deck's own estimate
   is 5–15% of pages. If the user is mid-session on a bank, an insurer, or a health portal, the
   account number, balance, and full name are in that PNG. The privacy slide is not merely
   aspirational — it is **contradicted by shipping code**.
2. **`quality: 70` is a no-op.** Chrome honours `quality` only for `format: "jpeg"`. With
   `format: "png"` you get a full-size lossless capture: worst case for bandwidth, worst case
   for how much PII survives in the artifact.
3. **Retention is unspecified.** `analyze_full` decodes the image and passes it to
   `visual_analyzer` (easyocr + Pillow). There is no documented retention policy, no deletion
   path, and OCR by definition extracts the readable text — including any PII on screen — into
   a second representation.

**Fix:**

- Do not send raw pixels. Send **derived features**: a perceptual hash, a downsampled layout
  vector, and a small palette/edge summary. That is sufficient for the layout-similarity signal
  the deck describes and carries a fraction of the PII.
- If raw pixels are genuinely needed, redact **before** encoding: run a client-side pass that
  blanks `<input>` regions, elements matching common PII selectors, and any text node matching
  card/IBAN/SSN/email patterns — then downscale to the smallest resolution the model tolerates,
  and encode as JPEG so `quality` actually applies.
- Gate uploads behind explicit, revocable opt-in. Default off.
- State retention explicitly in `PRIVACY.md` and enforce it in code.
- Until redaction exists, **change the deck**. A reviewer who diffs slide 10 against
  `escalateToBackend` will read it as a credibility problem, not an engineering gap.

---

## 2. High-severity findings

### H1 — Blocking WHOIS on the async event loop

`backend/app/services/threat_intel.py:404–420`:

```python
def _check_domain_age(domain: str) -> tuple:
    if not WHOIS_AVAILABLE:
        return 0.2, None
    try:
        w = python_whois.whois(domain)          # line 411 — BLOCKING network I/O
```

Reached from `compute_meta_score`, which is **sync**, at line 466:

```python
whois_score, whois_reason = _check_domain_age(hostname)
```

…which is called from `async def analyze_full` in `backend/app/main.py`. A WHOIS lookup can take
seconds and routinely times out. While it runs, **the entire worker's event loop is stalled** —
every concurrent request, including health checks, blocks behind it. This is a
single-request-denial-of-service against your own service, and the rest of the file is
carefully written with `httpx.AsyncClient`, which makes the one sync call stand out as an
oversight rather than a choice.

**Fix:** `await anyio.to_thread.run_sync(...)` around the WHOIS call (anyio is already a
dependency), or move to an async WHOIS client. Add a hard timeout and cache results by
registrable domain with a TTL — domain age changes slowly and the same domains recur constantly.

Adjacent defect in the same function: `if not WHOIS_AVAILABLE: return 0.2, None`. When the
optional import fails, **every domain silently receives a 0.2 risk contribution**. That means
the scoring function behaves differently in environments where `python-whois` didn't install,
with no log line and no test covering it. Two deployments of the same commit produce different
verdicts. Make the degraded path explicit, logged, and reflected in the response's `reasons`.

---

### H2 — The API key is not an authentication boundary

Every backend route carries `dependencies=[Depends(verify_api_key)]`, and the extension supplies
`EXTENSION_API_KEY` from its own bundle. **Anything in an extension bundle is public.** Any user
can unzip the extension, read the key, and call your API directly — including
`/api/v1/analyze/full`, which decodes attacker-controlled base64 into an image pipeline.

The dependency isn't useless (it stops trivially unauthenticated scanning), but it must not be
described as authentication. Right now the route surface is:

```
GET  /health
POST /api/v1/analyze/quick
POST /api/v1/analyze/full
POST /api/v1/feed/update
GET  /api/v1/feed/rules
```

`POST /api/v1/feed/update` is a **state-mutating endpoint behind a public key**. That is the one
to worry about — an attacker who can trigger or influence feed updates can affect what your
users see blocked.

**Fix:** rate-limit per-IP aggressively on the analyze routes (slowapi is already installed),
move `feed/update` behind a separate server-side-only credential or make it internal/scheduled
only, and treat the extension key purely as a coarse client identifier. Document it as such.

---

### H3 — Unbounded decode and exception leakage in `analyze_full`

`backend/app/main.py:111–142`:

```python
visual_result = None
b64_data = request.screenshot_base64
if b64_data and isinstance(b64_data, str):
    if "," in b64_data:
        b64_data = b64_data.split(",", 1)[1]
    visual_result = await visual_analyzer.analyze_screenshot(base64.b64decode(b64_data), domain)
```

No size cap before `base64.b64decode`. A caller with the public key can post a
multi-hundred-megabyte string and drive the worker into memory pressure — and then hand the
decoded bytes to easyocr/Pillow, an image-parsing stack with a long CVE history. Decompression
and decoder bombs are the classic follow-up.

Same handler:

```python
except Exception as e:
    logger.error("full_analysis_failed", error=str(e), url=str(request.url))
    raise HTTPException(status_code=500, detail=str(e))
```

`detail=str(e)` returns **internal exception strings to the client** — file paths, library
internals, occasionally connection strings. Free reconnaissance.

**Fix:** enforce a `max_length` on the Pydantic field and a decoded-byte ceiling; validate image
dimensions before handing bytes to the decoder; return a generic 500 with a correlation ID and
keep the detail in the log.

---

## 3. Medium findings

| # | Finding | Evidence |
|---|---------|----------|
| M1 | **Offscreen document is unreachable dead code.** `extension/offscreen/offscreen.js` (72 lines) + `offscreen.html` exist, but a repo-wide grep for `offscreen` outside that directory returns **zero matches** — no `chrome.offscreen.createDocument()` call, no `"offscreen"` permission. It can never execute. | grep, `manifest.json` |
| M2 | **Orphaned blocklist plumbing.** `manifest.json` declares `"declarative_net_request": {"rule_resources": []}` while `extension/rules/phishing-blocklist.json` (225 bytes) sits unreferenced and contains one rule against `example-known-phishing-domain.com` — a placeholder. *Correction to an earlier read:* the `declarativeNetRequest` permission itself is **not** dead — `service-worker.js:809–813` uses the dynamic rules API. Only the static path is orphaned. | `manifest.json`, `service-worker.js:809` |
| M3 | **Manifest advertises a capability the client cannot deliver.** Description reads *"AI-powered real-time phishing detection with visual similarity analysis"*; the client model is 30 lexical URL features and does no visual analysis. | `manifest.json`, `model_config.json` |
| M4 | **Model artifact sprawl with no source of truth.** `extension/models/model.onnx`, `backend/app/models/model.onnx`, `ml-retrain/models/phishing_model_v4.onnx`, `..._v4_raw.onnx` — three-plus copies, no sync mechanism. `model_config.json` is byte-identical in two locations. `"model_version": "4.1"` while the artifacts are named `v4`. | `git ls-files` |
| M5 | **Two duplicated test trees, two `pytest.ini`.** Root `tests/` (`conftest.py`, `pytest.ini`, `test_feature_parity.py`, `test_lexical_features.py`, `test_feed_manager.py`, `test_visual_analyzer.py`) and `backend/tests/` (`test_api.py`, `test_feed_manager.py`, `test_threat_intel.py`, `test_visual_analyzer.py`), plus loose `backend/test_phishguard.py` and `backend/verify_final.py`. Which one does CI run? | `git ls-files` |
| M6 | **`.gitignore` targets a directory that doesn't exist.** Rules reference `ml-training/model.pkl`, `ml-training/dataset.csv`, `ml-training/data/` — the real directory is **`ml-retrain/`**. The rules match nothing, which is precisely why `ml-retrain/prepared/*.npy` (`X_train`, `X_val`, `X_test`, `X_cal`, `y_*`, `src_test`), dataset CSVs, and `.onnx` binaries are committed. | `.gitignore`, `git ls-files` |
| M7 | **Committed build detritus.** `pytest_final_output.txt`, `pytest_final_output_utf8.txt`, `pytest_output.txt`, `pytest_output_utf8.txt`, `pytest_results.txt`, `verify_final.py`. | `git ls-files` |
| M8 | **No README anywhere in the repo.** For a portfolio project this is the single highest-leverage omission — it is the first and often only file a reviewer opens. | `ls README*` → not found |
| M9 | **Unpinned dependencies.** `backend/requirements.txt` uses `>=` ranges throughout, with the comment *"Version ranges instead of pins — avoids conflicts with other packages"*. For an ML project this is a reproducibility defect: a future `numpy` or `scipy` silently changes preprocessing behaviour and your evaluation numbers stop being reproducible. Pin exactly; use a lockfile. | `backend/requirements.txt` |
| M10 | **Duplicated `PRIVACY.md`** at root and in `extension/`, with no canonical copy. | `git ls-files` |
| M11 | **Synthetic data as a contamination risk.** `ml-retrain/synth_generator.py` is 416 lines — the second-largest ML file. If synthetic phishing URLs appear in both train and test, reported FPR is optimistic and does not transfer. Needs an explicit statement of where synthetic data is and is not used. | line counts |
| M12 | **The weekly retrain workflow is a silent no-op.** `retrain.yml` runs `ml-training/retrain_pipeline.py`, which aborts at line 41 because `data/phishing_dataset.csv` is not in the repo. Its commit steps then `git add extension/models/url_classifier.onnx` and `backend/models/url_classifier.onnx` — **neither path exists** (the real artifact is `extension/models/model.onnx`; `backend/models/` isn't a directory — the backend model is under `backend/app/models/`). The `git diff \| grep url_classifier` guard never matches, so the commit step never fires and the job reports success having done nothing. A green weekly badge that proves nothing is worse than no badge. | `retrain.yml:24–51`, `retrain_pipeline.py:41`, `ls extension/models backend/` |
| M13 | **Two parallel, divergent ML trees.** `ml-retrain/` (v4.1, 30 features, ingest→prepare→train→evaluate→deploy, writes `model.onnx`) and `ml-training/` (writes `url_classifier.onnx`, own `requirements.txt`, own `retrain_pipeline.py`, committed `model.onnx` at 7.68 MB vs the extension's 8.82 MB — **different binaries**). CI's retrain job points at the *less* complete tree. Pick one; archive or delete the other. Root cause behind M4, M6, and M12. | `ls ml-retrain ml-training`, file sizes |

---

## 4. Deck ↔ repo gap analysis

This is the section that matters most for the "resume-grade" goal, because the deck is the
artifact a reviewer reads first and the code is what they check it against.

### 4.1 The dependency-level proof

`backend/requirements.txt` in full:

```
fastapi>=0.115.0        uvicorn[standard]>=0.24.0   pydantic>=2.5.0
pydantic-settings>=2.1.0  python-dotenv>=1.0.0      numpy>=1.24.0
structlog>=23.2.0       tldextract>=5.1.0           slowapi>=0.1.9
httpx>=0.25.0           python-whois>=0.8.0         Pillow>=10.1.0
scipy>=1.11.0           easyocr>=1.7.0              python-multipart>=0.0.6
anyio>=4.8.0            pytest>=8.0.0               pytest-asyncio>=0.23.0
```

No agent framework. No LLM SDK. No vector store. No CNN/embedding stack. A repo-wide grep for
`langchain|openai|anthropic|chromadb|faiss|qdrant|pgvector|sentence-transformers|torch|transformers`
across `backend/requirements.txt` and all of `ml-retrain/` matched **only URL strings inside
`ml-retrain/datasets/legitimate_urls.csv`** (openai.com, anthropic.com, pytorch.org,
langchain.com, qdrant.io). That is dependency-level proof, not inference.

### 4.2 Claim → evidence → verdict

| Deck claim | Slide | Evidence in repo | Verdict |
|---|---|---|---|
| Two-tier pipeline, inline Tier 1 + async Tier 2 | S5 | `service-worker.js:585` `finalScore >= 0.35`; line 596 *"Backend escalation with VERDICT MONOTONICITY"*; `escalateToBackend()` | **Partially real.** The two-tier *shape* is genuinely implemented. |
| 0.35–0.75 escalation band | S5 | `service-worker.js:585`, `:614` | **Real.** Lower bound matches exactly. |
| Four fused signals: Visual · NLP/Text · DOM · Reputation | S4 | Client model = 30 lexical URL features (`f01_urlLength` … `f30_longestSubdomainLen`). Backend adds threat feeds + WHOIS + easyocr heuristics. | **Overstated.** No CNN embeddings, no NLP model, no DOM signal in the classifier. |
| *"A phishing page can fake its URL — it cannot fake what it must show the victim"* | S3 | The client model looks at **nothing but the URL**. | **Directly contradicted by the shipped model.** This is the sharpest inconsistency in the deck. |
| Page-Interrogation Agent: tool-calling LLM over WHOIS · DNS · CT logs · redirect chain · Safe Browsing | S5, S6 | Repo has WHOIS, Safe Browsing, VirusTotal, URLhaus. **No DNS/ASN lookup, no CT-log query, no redirect follower.** Fusion is `compute_meta_score()` — a hardcoded additive scoring function. | **Not built.** Four of five tools missing; no agent, no tool-calling, no LLM. |
| Brand corpus agent: ~500 brands, logo embeddings, vector store | S7 | No scraper, no embedding model, no vector store dependency. | **Not built.** |
| LLM narration with faithfulness checking | S8 | No LLM client anywhere. | **Not built.** |
| Drift agent: distribution shift → hard-example mining → retrain | S9 | `ml-retrain/` has ingest→prepare→train→evaluate→deploy. No drift detection. | **Not built.** |
| Eval gate: *"deploy only if FPR improves at fixed recall"* | S9 | **Verified — the gate does not exist.** `ml-retrain/evaluate.py:95` computes `fpr` and writes it to `evaluation_report.json`, but never compares it to a baseline and never returns a non-zero status. `ml-retrain/deploy.py` copies the model unconditionally — it never reads `evaluation_report.json`. `run_pipeline.py:42–50` catches every stage exception and only aborts on stages 3–4, so **stage 5 (evaluation) can fail outright and stage 6 still deploys**. `ci.yml` never invokes either module. The only gate anywhere is `retrain_pipeline.py:90` — `new_auc_pr >= old && new_f1 >= old` — which is AUC-PR/F1, **not FPR at fixed recall**, and it lives in the other ML tree. | **Not built.** Re-tense slide 9. |
| *"Agent framework + vector store slot cleanly into the existing Python backend"* | S12 | Neither is present. | **Aspirational, stated in present tense.** |
| *"DOM & screenshot redaction … (v2 upgrade)"* | S10 | Correctly labelled as future. But S10 also says *"PII never leave the device"* in the present tense, while `escalateToBackend` uploads raw viewport PNGs. | **Internally inconsistent.** See C3. |
| No safe-site allowlist, by design | S7 | Consistent with code. | **Real, and a genuinely good call.** Worth keeping in the deck verbatim. |

### 4.3 What to do about the gap

You have two honest options and one dishonest one. The dishonest one — leave the deck in present
tense — is the only one that actually hurts you, because the gap is discoverable in one
`requirements.txt` read.

**Option A (recommended, low cost):** re-tense the deck. Split every slide into *Built* and
*Designed*. S5's Tier 1, the 0.35 band, and the escalation step move to *Built*. The
interrogation agent, brand corpus, narration layer, and drift agent move to *Designed — P1/P2/P3*
with the roadmap slide carrying them. You lose nothing: a clear articulation of an agentic design
you have **not yet** built, with a working two-tier substrate underneath it, reads as strong
systems thinking. A design presented as shipped and found not to be reads as the opposite.

**Option B (higher cost, higher ceiling):** build the thinnest real version of Tier 2 — see
`ROADMAP.md` P1. A tool-calling agent over five real tools with a persisted evidence trail is
roughly a week of work and converts the largest deck claim from *designed* to *built*.

Do **A immediately** regardless of whether you do B.

---

## 5. What the repo does well

Worth stating plainly, because an audit that only lists defects mis-scores the project.

- **The two-tier substrate is real.** The 0.35 threshold band, the escalation call, and the
  explicit *verdict monotonicity* merge are the hard architectural part. The agentic layer
  slots into a socket that already exists.
- **Verdict monotonicity is a genuinely good instinct.** Ensuring a backend escalation can only
  raise, never silently lower, a local verdict prevents a whole class of downgrade bugs and
  attacks. Say so explicitly in the README — it's the kind of detail that signals maturity.
- **The no-allowlist argument (S7) is correct and well-reasoned.** Top-site rankings are
  manipulable, trusted domains get hijacked via subdomain takeover, open redirects launder
  "safe" URLs. Trusting verified brand fingerprints over domain strings is the right call and
  most student projects get this wrong.
- **`test_feature_parity.py` exists.** Testing that the JS feature extractor and
  `ml-retrain/feature_extractor.py` agree is exactly the test that prevents the single nastiest
  bug class in a split-inference system. Most projects discover this the hard way.
- **The backend is mostly correct async.** `httpx.AsyncClient` throughout, structlog, slowapi,
  a middleware layer. The WHOIS call is an outlier, not the pattern.
- **FPR-first evaluation methodology (S11)** — time-split testing, realistic skewed base rates,
  A/B per agent, calibrated categories instead of raw scores. This is the correct framing and
  most portfolio projects report raw accuracy on a balanced set. **Make sure the code lives up
  to it**, then lead with it.

---

## 6. Priority-ordered fix list

**Today (under an hour, highest reviewer-visible impact):**

1. Remove `models/model.onnx` from `web_accessible_resources`. (C2)
2. Fix `.gitignore`: `/lib/` + `!extension/lib/`, and `ml-training/` → `ml-retrain/`. (C1, M6)
3. Commit `extension/lib/` contents (or add a pinned, checksummed fetch step). (C1)
4. Write a README. (M8)

**This week:**

5. Stop uploading raw screenshots — derived features or client-side redaction. (C3)
6. Re-tense the deck into *Built* / *Designed*. (§4.3 Option A)
7. `anyio.to_thread.run_sync` around WHOIS + timeout + TTL cache. (H1)
8. Size caps and generic 500s in `analyze_full`. (H3)
9. Delete the offscreen document and the placeholder blocklist, or wire them up. (M1, M2)
10. Consolidate to one test tree, one `pytest.ini`; delete committed pytest output. (M5, M7)
11. Pin dependencies exactly. (M9)

**Before calling it production-oriented:**

12. Drop `<all_urls>`, add a real production origin over HTTPS. (C2)
13. Re-scope the API key as a client identifier; harden `feed/update`. (H2)
14. Single ONNX source of truth with a build step that copies it; align version strings. (M4)
15. Build and enforce the FPR-at-fixed-recall gate in CI — **verified not to exist today**; `evaluate.py` computes FPR but never gates, `deploy.py` copies unconditionally, CI calls neither. (§4.2, M12)
16. Document synthetic-data usage and prove no train/test contamination. (M11)

See `THREAT-MODEL.md` for the adversary analysis and `ROADMAP.md` for the next-version design.
