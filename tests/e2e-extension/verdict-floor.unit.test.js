/**
 * Unit guard — backend verdict severity is a FLOOR (service-worker.js).
 *
 * Defense-in-depth rule (header doctrine in the SW): once a verdict is adopted
 * from the backend, local boosts (BitB +0.30, brand impersonation +0.25) may
 * RAISE it but must NEVER lower it. Pre-fix, every boost re-ran
 * `score >= 0.65 ? "phishing" : "suspicious"` and would downgrade an
 * incoherent backend response (verdict "phishing" with score < 0.65) to
 * "suspicious". The fix routes every post-merge recompute through
 * moreSevereVerdict(recomputed, floor).
 *
 * This file is intentionally NOT a Playwright spec (specs are gitignore-excluded
 * by design and need a browser); it runs with the built-in Node test runner —
 * zero added dependencies:
 *
 *   node --test tests/e2e-extension/verdict-floor.unit.test.js
 *
 * Playwright never collects it: playwright.config.js testMatch is "*.spec.js".
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const SW_PATH = path.join(
  __dirname, "..", "..", "extension", "background", "service-worker.js",
);
const src = fs.readFileSync(SW_PATH, "utf8");

// ── Load the REAL definitions out of the service worker ───────────────────
// Not a copy: if the SW's table or helper drifts, these tests test the drift.
const sevMatch = src.match(/const VERDICT_SEVERITY = \{[^}]*\};/);
const fnMatch = src.match(/function moreSevereVerdict\(a, b\) \{[\s\S]*?\n\}/);
assert.ok(sevMatch, "VERDICT_SEVERITY definition not found in service-worker.js");
assert.ok(fnMatch, "moreSevereVerdict definition not found in service-worker.js");
const { VERDICT_SEVERITY, moreSevereVerdict } = new Function(
  `${sevMatch[0]}\n${fnMatch[0]}\nreturn { VERDICT_SEVERITY, moreSevereVerdict };`,
)();

/**
 * The exact recompute+clamp expression used at all three boost sites
 * (post-merge signal re-apply in analyzeUrl; BitB and brand-impersonation
 * branches of the CONTENT_SIGNALS handler).
 */
const clampedRecompute = (score, floor) =>
  moreSevereVerdict(score >= 0.65 ? "phishing" : "suspicious", floor);

// ── Semantics of the floor ────────────────────────────────────────────────

test("severity order is safe < suspicious < phishing", () => {
  assert.ok(VERDICT_SEVERITY.safe < VERDICT_SEVERITY.suspicious);
  assert.ok(VERDICT_SEVERITY.suspicious < VERDICT_SEVERITY.phishing);
});

test("incoherent backend phishing with sub-threshold score is never downgraded", () => {
  // BitB site: backend says phishing/0.2, boost brings score to 0.5 — the
  // naive recompute would yield "suspicious"; the floor must hold. (E2E 06-A)
  assert.equal(clampedRecompute(0.2 + 0.3, "phishing"), "phishing");
  // Brand-impersonation site: phishing/0.3 + 0.25 → 0.55. (E2E 06-B)
  assert.equal(clampedRecompute(0.3 + 0.25, "phishing"), "phishing");
  // No boost at all (floor applied to the bare threshold).
  assert.equal(clampedRecompute(0.2, "phishing"), "phishing");
});

test("raises still work — boosts lift verdicts across the 0.65 threshold", () => {
  // E2E 06-C: suspicious/0.4 + BitB 0.3 → 0.7 must climb to phishing.
  assert.equal(clampedRecompute(0.4 + 0.3, "suspicious"), "phishing");
  // Backend safe + strong boost crosses threshold → phishing.
  assert.equal(clampedRecompute(0.4 + 0.3, "safe"), "phishing");
  // Backend safe + weak boost stays below threshold → legacy "suspicious".
  assert.equal(clampedRecompute(0.2 + 0.3, "safe"), "suspicious");
});

test("equal severities are stable and unknown strings rank below safe", () => {
  assert.equal(clampedRecompute(0.5, "suspicious"), "suspicious");
  assert.equal(moreSevereVerdict("unknown", "safe"), "safe");
  assert.equal(moreSevereVerdict("phishing", "unrecognised"), "phishing");
});

// ── Structural guard: every post-merge recompute stays clamped ────────────

test("source has no un-clamped post-merge verdict recompute", () => {
  // The pre-fix buggy shape must never come back at either object.
  assert.ok(
    !/(result|existing)\.verdict = (result|existing)\.score >= 0\.65/.test(src),
    "found an un-clamped `verdict = score >= 0.65 ? ...` recompute",
  );
  // Exactly three clamp call sites: one per boost recompute
  // (definition line excluded — it has no call parentheses in this match).
  const calls = src.match(/moreSevereVerdict\(\s*\n?\s*(result|existing)\.score/g) || [];
  assert.equal(calls.length, 3, `expected 3 clamped recompute sites, found ${calls.length}`);
});
