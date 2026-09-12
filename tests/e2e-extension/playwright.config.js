/**
 * Playwright config for the PhishGuard extension E2E suite.
 *
 * Headed by default (skill rule; also the most faithful MV3 target — the
 * extension runs in a real browser UI). CI opt-out: PW_HEADLESS=1 switches
 * Chromium to NEW headless (channel "chromium", set in
 * helpers/extension-context.js) — never the old headless shell, which cannot
 * load unpacked extensions at all.
 */
const { defineConfig } = require("@playwright/test");

const headless = process.env.PW_HEADLESS === "1";

module.exports = defineConfig({
  // Specs live directly in tests/e2e-extension/ (01-*.spec.js … 06-*.spec.js).
  testDir: __dirname,
  testMatch: "*.spec.js",

  // Extension boot = real Chromium + ONNX WASM session + feed sync; generous.
  timeout: 60_000,
  expect: { timeout: 10_000 },

  // STRICTLY SEQUENTIAL — the stub backend owns the FIXED port 7860 (the
  // service worker's hardcoded BACKEND_URL default), so parallel workers
  // would collide on bind. Workers:1 also gives deterministic feed-sync state.
  workers: 1,
  fullyParallel: false,
  retries: 0,

  reporter: [["list"]],
  outputDir: "test-results",
  use: {
    headless,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
