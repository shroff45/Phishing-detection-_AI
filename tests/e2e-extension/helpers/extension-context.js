/**
 * Launches the unpacked PhishGuard MV3 extension in a real Chromium.
 *
 * Uses launchPersistentContext with a FRESH temp profile per launch:
 *   - MV3 service workers only exist in persistent contexts (a plain
 *     newContext has no service worker scope the extension can register in).
 *   - A fresh profile guarantees chrome.runtime.onInstalled fires on every
 *     test run, which is what triggers syncThreatFeed → DNR rules install.
 *
 * Headed by default (skill rule; also the most faithful target). PW_HEADLESS=1
 * switches to Chromium's NEW headless via channel:'chromium' — never the
 * headless shell, which does not load extensions at all.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const { chromium } = require("@playwright/test");

// Repo's unpacked extension: <repo>/extension — three levels up from helpers/.
const EXTENSION_PATH = path.resolve(__dirname, "..", "..", "..", "extension");

/**
 * Launch Chromium with the extension loaded. Returns { context, extensionId }.
 * The caller owns closing the context (use `closeExtensionContext`).
 */
async function launchExtension({ headless = false } = {}) {
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "phishguard-e2e-"));

  const context = await chromium.launchPersistentContext(userDataDir, {
    headless,
    // New headless supports extensions; the old headless shell does not.
    ...(headless ? { channel: "chromium" } : {}),
    args: [
      `--disable-extensions-except=${EXTENSION_PATH}`,
      `--load-extension=${EXTENSION_PATH}`,
      // Don't pin a first-run flow or default-browser prompt over the test.
      "--no-first-run",
      "--no-default-browser-check",
    ],
  });

  // The SW registers on install; grab it (existing or imminent).
  const sw =
    context.serviceWorkers().find((w) => w.url().endsWith("service-worker.js")) ||
    (await context.waitForEvent("serviceworker", { timeout: 15000 }));

  const extensionId = new URL(sw.url()).host;
  return { context, sw, extensionId, userDataDir };
}

/**
 * Get the service worker for an already-launched context (e.g. after the SW
 * was stopped and restarted by Chrome — MV3 SWs are ephemeral).
 */
async function getServiceWorker(context, timeout = 15000) {
  const existing = context.serviceWorkers().find((w) =>
    w.url().endsWith("service-worker.js")
  );
  if (existing) return existing;
  return context.waitForEvent("serviceworker", { timeout });
}

/**
 * Close the context and remove its temp profile. Safe to call twice.
 */
async function closeExtensionContext(context, userDataDir) {
  await context.close();
  try {
    fs.rmSync(userDataDir, { recursive: true, force: true });
  } catch {
    // Windows can briefly hold profile locks; a leftover temp dir is harmless.
  }
}

module.exports = { launchExtension, getServiceWorker, closeExtensionContext, EXTENSION_PATH };
