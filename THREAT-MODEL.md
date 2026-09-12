# PhishGuard — Threat Model

**System:** Phishing_detection2.0 — MV3 extension + FastAPI backend + ML retrain pipeline
**Method:** asset-first, then per-adversary. STRIDE used as a checklist, not a structure.
**Date:** 2026-08-01

A phishing detector is an unusual system to threat-model because **the adversary is the
input**. Most systems process hostile data occasionally; this one processes it by design, on
every page load, and publishes its detection logic to the client. That inverts several normal
assumptions and is the through-line of everything below.

---

## 1. Assets

| Asset | Where | Why an adversary wants it |
|---|---|---|
| **The classifier** (`model.onnx` + `model_config.json`) | Shipped in extension; world-readable via `web_accessible_resources` | White-box evasion. Knowing the 30 features and threshold `0.798` reduces evasion to offline search. |
| **User browsing telemetry** | `POST /api/v1/analyze/full` — URL + client score + full-viewport PNG | Direct PII. Screenshots of banking/health sessions are the highest-value data this system touches. |
| **Verdict integrity** | Extension badge, `blocked.html` | Suppress a true positive → victim proceeds. Induce a false positive → block a competitor, or train users to dismiss warnings. |
| **The blocklist / DNR dynamic rules** | `service-worker.js:809–813`, `POST /api/v1/feed/update` | Write access = censorship or targeted unblocking. |
| **The training pipeline** | `ml-retrain/`, feeds, scheduled `retrain.yml` | Poison the retrain input → durable, model-level blindness. |
| **Backend availability** | FastAPI worker | If Tier 2 is down and the extension fails open, every borderline page resolves as safe. |
| **The extension's privileges** | `<all_urls>` host permission | A compromised extension with `<all_urls>` reads every page the user visits. |

---

## 2. Trust boundaries

```
 [ hostile web page ]
        │  DOM, URL, rendered pixels — FULLY ATTACKER-CONTROLLED
        ▼
 ┌─ content-script.js ───────────── runs in an attacker-influenced tab
 │        │  message passing
 │        ▼
 ├─ service-worker.js ───────────── extension-privileged, but SHIPS SECRETS
 │        │  · EXTENSION_API_KEY (public — it's in the bundle)
 │        │  · model.onnx (public — web_accessible_resources: <all_urls>)
 │        │  · plaintext http://localhost:7860
 │        ▼  HTTP
 └─ FastAPI backend ─────────────── verify_api_key is NOT an auth boundary
          │        · analyze_full decodes attacker-supplied base64 → easyocr/Pillow
          │        · compute_meta_score blocks the event loop on WHOIS
          ▼
   external feeds (URLhaus · VirusTotal · Safe Browsing · WHOIS)
          │  third-party, availability- and integrity-dependent
          ▼
   ml-retrain/ ──────────────────── scheduled, feeds-driven → poisoning surface
```

**The critical observation:** there is no boundary between "the extension" and "the web" for
anything in `web_accessible_resources`. Assets placed there are as public as if you'd posted
them to GitHub — which, for `model.onnx`, you also have.

---

## 3. Adversary A — the phisher (primary, and the one that matters)

Motivated, iterating daily, treats your detector as a fitness function.

### A1 · White-box evasion — **CRITICAL, exploitable today**

The attacker fetches `chrome-extension://<id>/models/model.onnx` from their own phishing page
(`web_accessible_resources: <all_urls>` permits it), or simply installs the extension and reads
the bundle. They now hold the model, all 30 feature names, and `optimal_threshold: 0.798`.

Evasion becomes a **local offline search**: mutate the URL string, score it against the model,
keep anything under threshold. Zero requests to your infrastructure, therefore zero detection
signal on your side. Because all 30 features are lexical and URL-only, the search space is
small and every feature is directly controllable by the attacker — they choose the hostname,
the path, the query, the TLD.

Concretely: `f24_hasSuspiciousTld`, `f26_isShortener`, `f27_keywordHits`, `f17_isIpAddress`,
`f25_hasPunycode` are all trivially set to zero. `f18_entropyUrl` / `f19_entropyHost` are tuned
by choosing dictionary-word subdomains. A URL like
`https://accounts.secure-portal.helpdesk-review.com/login` scores low on nearly every feature
while remaining perfectly usable as a phishing lure.

**Mitigations:** remove the model from `web_accessible_resources` (necessary, not sufficient);
treat Tier 1 as a cheap pre-filter rather than the decision; move the authoritative verdict
server-side where the attacker cannot iterate for free; add threshold jitter and rotation;
**add signals the attacker cannot cheaply control** — page content, redirect chain, certificate
age, hosting ASN. This is precisely the argument the deck's slide 3 makes and the shipped model
does not implement.

### A2 · Lexical mimicry without evasion effort — **HIGH, works today**

Even without extracting the model, a purely lexical detector is defeated by the current
threat landscape as described on the deck's own slide 2:

- **Hijacked subdomain of a legitimate domain** — `login.trusted-university.edu.attacker.co`,
  or a genuine subdomain takeover. The URL looks clean on nearly every lexical feature.
- **Legitimate hosting** — phishing on a compromised WordPress site, a `*.pages.dev`,
  `*.web.app`, or a shared docs host. The URL *is* legitimate.
- **Open redirect chaining** — the visible URL belongs to a real brand; the landing page does not.
  With no redirect-chain follower in the repo, this is invisible to the system.

The deck names these threats. The model cannot see any of them. This is the strongest technical
argument for building Tier 2 — not novelty, but that Tier 1 is structurally blind to the
majority of the modern threat surface.

### A3 · Poisoning the retrain loop — **MEDIUM, high durability**

`retrain.yml` runs on a schedule and consumes feed-derived data. An attacker who can get their
own benign-looking domains into a *phishing* feed, or their phishing domains into a *benign*
source (Tranco is rank-based and manipulable at the tail), shifts the decision boundary. Unlike
A1 this is **durable** — it survives model updates because it *is* the model update.

`ml-retrain/synth_generator.py` (416 lines) compounds this: if synthetic phishing URLs follow
generation templates and appear in both train and test, the evaluation reports high accuracy on
a distribution the real world does not produce, masking the drift.

**Mitigations:** the FPR-at-fixed-recall gate the deck promises is exactly the right control —
but it **does not exist in the code** (verified: `evaluate.py` computes FPR and never gates on
it; `deploy.py` copies unconditionally; CI never calls either). Until it is built, *nothing*
stands between a poisoned feed and a deployed model — this is what raises A3's durability from
theoretical to practical. Build it first (`ROADMAP.md` 3.1). Then add a held-out, human-curated,
never-auto-updated golden set that every candidate must pass. Log per-source contribution so a
single feed's influence is visible. Never evaluate on synthetic data.

### A4 · Attacking the analysis pipeline itself — **MEDIUM**

`analyze_full` decodes attacker-influenced base64 into Pillow and easyocr. Image parsers are a
well-trodden CVE surface. With no size cap before `base64.b64decode` (see `AUDIT.md` H3), and
the public API key providing no real gate, an attacker can post decompression bombs, malformed
PNGs, or pathological dimensions directly to the endpoint.

**Mitigations:** field-level `max_length`, a decoded-byte ceiling, dimension validation before
decode, pinned image libraries, and ideally decode in a subprocess with a memory cap.

### A5 · Availability as evasion — **MEDIUM**

If the backend is down or slow, what does the extension do? `escalateToBackend` uses
`AbortSignal.timeout(10000)`. On timeout, the borderline verdict falls back to the local score —
and the local score is, by definition, in the 0.35–0.75 uncertain band. **An attacker who can
stall your backend converts every borderline page into a fail-open.**

A single blocking WHOIS call (H1) stalls the whole worker's event loop, so the DoS cost is low:
a handful of requests against domains with slow WHOIS servers.

**Mitigations:** fix H1; make the fail-open/fail-closed policy explicit and tested; on timeout,
show an *unknown* state rather than *safe*; cache verdicts so a backend outage degrades
gradually.

---

## 4. Adversary B — a malicious or compromised page

Any page the user visits, including ones the extension currently rates safe.

- **Model exfiltration** — covered in A1; the `web_accessible_resources` grant makes this a
  same-page `fetch()`.
- **Extension fingerprinting** — probing for extension-scoped resources reveals PhishGuard is
  installed. That is a tracking vector, and it lets a phishing page serve a benign variant to
  protected users and the real lure to everyone else. **Cloaking against your own detector.**
  Removing resources from `web_accessible_resources` mitigates both.
- **Content-script confusion** — `content-script.js` runs at `document_idle` in a
  DOM the attacker fully controls, including elements crafted to look like whatever the
  extractor keys on. Any DOM-derived signal must be treated as adversarial input, never as
  ground truth.

---

## 5. Adversary C — a network attacker

- The manifest ships `http://localhost:7860` — plaintext. Loopback is fine; **the moment that
  origin becomes a real host, every screenshot and URL crosses the network in the clear.**
  Enforce HTTPS-only in the production build and fail closed on a plaintext origin.
- The public `EXTENSION_API_KEY` means an on-path observer who sees one request can replay it
  indefinitely.
- If `ort.min.js` or the WASM binaries were ever fetched from a CDN at runtime rather than
  vendored (a tempting "fix" for C1 in the audit), that becomes **remote code execution by
  design**. Vendor with a checksum; do not fetch executable WASM at runtime.

---

## 6. Adversary D — a curious or hostile user of the extension

The user is not the enemy, but they are a threat *source* for the assets above.

- They can read `EXTENSION_API_KEY` and call the backend directly, including
  `POST /api/v1/feed/update`. That endpoint mutates state behind a key that is, by construction,
  public. **This is the endpoint to lock down first.**
- They can extract the model. This is unavoidable for any client-side model — the mitigation is
  architectural (keep the valuable model server-side), not access-control.
- They can spoof verdicts locally. Low impact for a single user; relevant only if verdicts feed
  a shared reputation system, which they currently do not.

---

## 7. Privacy — the user as the party at risk

Distinct from the sections above: here the system is the threat.

| Risk | Status |
|---|---|
| Full-viewport PNG uploaded on every escalation (5–15% of pages), un-redacted | **Active.** `escalateToBackend`, `format: "png"` — and `quality: 70` is a no-op for PNG, so captures are full-size lossless. |
| Deck slide 10 claims *"keystrokes, passwords, PII never leave the device"* | **Contradicted by the shipping code above.** |
| OCR extracts on-screen text — including PII — into a second representation | **Active.** `visual_analyzer` runs easyocr on the uploaded image. |
| Retention and deletion policy for uploaded screenshots | **Undefined.** No policy in code or in either `PRIVACY.md`. |
| Every visited URL in the escalation band is sent to the backend | **By design**, but must be disclosed plainly. URLs alone are re-identifying. |
| Two divergent `PRIVACY.md` files, no canonical copy | **Active.** (`AUDIT.md` M10) |

**This is the finding most likely to end a conversation with a security-minded reviewer**, because
it is not a subtle bug — it is a documented promise contradicted by the function that implements
the feature. Fix the code, then fix the slide. In that order.

---

## 8. Control gaps, ranked by exploitability

| Rank | Gap | Adversary | Exploitable today? |
|---|---|---|---|
| 1 | `model.onnx` in `web_accessible_resources: <all_urls>` | A1, B | **Yes** — one `fetch()` |
| 2 | Un-redacted screenshot upload | Privacy | **Yes** — every escalation |
| 3 | Lexical-only features vs subdomain/redirect/hosted phishing | A2 | **Yes** — no effort needed |
| 4 | Sync WHOIS stalls the event loop | A5 | **Yes** — trivial DoS |
| 5 | `feed/update` mutating state behind a public key | D | **Yes** |
| 6 | No size cap before `base64.b64decode` | A4 | **Yes** |
| 7 | Exception strings returned to the client | A4 | **Yes** |
| 8 | Fail-open on backend timeout | A5 | **Likely** — needs verification |
| 9 | Feed/synthetic poisoning of retrain | A3 | Slow, durable |
| 10 | Plaintext origin in manifest | C | Only once deployed off-loopback |

---

## 9. What a hardened v2 looks like, threat-model-first

1. **Nothing valuable in the client.** Tier 1 is a cheap, disposable, deliberately-public
   pre-filter. Assume the attacker has it. The authoritative verdict is server-side, where they
   cannot iterate for free.
2. **Signals the attacker cannot cheaply control.** Certificate age, hosting ASN, redirect
   chain, CT-log recency, brand-fingerprint similarity. Each raises evasion cost in a way that
   more lexical features cannot — this is the actual security argument for the deck's Tier 2,
   stronger than the novelty argument.
3. **Derived features, never raw pixels.** Perceptual hash + layout vector carries the signal
   at a fraction of the PII, and makes slide 10 true instead of aspirational.
4. **Fail visible, never fail silent.** Backend timeout → *unknown*, not *safe*. Missing WHOIS →
   logged and surfaced in `reasons`, not a silent 0.2 score contribution.
5. **The eval gate is a security control, not a quality gate.** It is the primary defense against
   A3. It must be enforced in CI, on a golden set that never auto-updates, and never evaluated
   on synthetic data.
6. **Every input is hostile.** DOM, URL, screenshot, feed response. Size-capped, schema-validated,
   parsed in something you can kill.

See `ROADMAP.md` for how these land in sequenced work.
