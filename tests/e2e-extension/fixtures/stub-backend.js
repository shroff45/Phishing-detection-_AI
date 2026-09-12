/**
 * Stub Tier-2 backend, bound to the FIXED port 7860.
 *
 * The service worker's default BACKEND_URL is http://localhost:7860 and
 * storage seeding races SW startup, so tests must bind exactly 7860 or the
 * SW will send escalation/feed traffic to whatever happens to be listening
 * (or nothing). If 7860 is already taken, startup fails fast with a clear
 * message instead of silently testing against the real backend.
 *
 * Serves exactly the three routes the service worker calls:
 *   POST /api/v1/analyze/full  — records every request body + headers so
 *                               specs can assert the privacy contract
 *                               (screenshot_base64 null by default) and the
 *                               auth contract (X-API-Key: phishguard-dev-key).
 *   POST /api/v1/feed/update  — triggers feed sync.
 *   GET  /api/v1/feed/rules   — returns DNR dynamic-rule JSON in the same
 *                               shape feed_manager produces, so syncThreatFeed
 *                               installs real blocking rules via
 *                               chrome.declarativeNetRequest.
 *
 * Mode switching: `setMode({ verdict, score })` changes what /analyze/full
 * returns for subsequent requests — used by the monotonicity spec to prove
 * the SW honors backend upgrades but blocks downgrades.
 */
const http = require("http");

const FIXED_PORT = 7860;
const SW_API_KEY = "phishguard-dev-key"; // extension/background/service-worker.js line 75

// DNR dynamic rules in feed_manager's canonical shape (see
// backend/app/services/feed_manager.py). The blocked fixture page lives on
// 127.0.0.1 so it can never collide with the "localhost" fixture host used
// by every other spec. Blocking is scoped to the exact page path.
const FEED_RULES = [
  {
    id: 9001,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: "||127.0.0.1*/blocked-page.html",
      resourceTypes: ["main_frame"],
    },
  },
];

function startStubBackend() {
  return new Promise((resolve, reject) => {
    const state = {
      // Every /analyze/full request: { url, client_score, screenshot_base64, apiKey }
      analyzeRequests: [],
      feedUpdateCount: 0,
      feedRulesRequests: 0,
      // What /analyze/full returns for subsequent calls.
      mode: { verdict: "suspicious", score: 0.0 },
    };

    const server = http.createServer((req, res) => {
      const sendJSON = (code, obj) => {
        res.writeHead(code, { "Content-Type": "application/json" });
        res.end(JSON.stringify(obj));
      };

      // Drain body for all requests (analyze/full is the only one with one).
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const body = chunks.length ? Buffer.concat(chunks).toString("utf8") : "";
        const apiKey = req.headers["x-api-key"];

        if (req.method === "POST" && req.url === "/api/v1/analyze/full") {
          let parsed = {};
          try { parsed = body ? JSON.parse(body) : {}; } catch { parsed = {}; }
          state.analyzeRequests.push({
            url: parsed.url,
            client_score: parsed.client_score,
            screenshot_base64: parsed.screenshot_base64 ?? null,
            apiKey: apiKey ?? null,
          });
          sendJSON(200, {
            url: parsed.url,
            verdict: state.mode.verdict,
            score: state.mode.score,
            confidence: 0.9,
            reasons: [`Stub verdict: ${state.mode.verdict}`],
            source: "backend",
            feeds_checked: ["stub_feed"],
            feeds_flagged: [],
            signals: [],
            evidence_trail: [
              {
                signal: "threat_feeds",
                status: "ok",
                weight: state.mode.score,
                human_readable: "Stub feed checked (no live lookups in tests).",
              },
            ],
            threat_feed: { is_known_threat: state.mode.score >= 0.5 },
            visual_analysis: null,
          });
        } else if (req.method === "POST" && req.url === "/api/v1/feed/update") {
          state.feedUpdateCount += 1;
          sendJSON(200, { success: true, stats: { rules_loaded: FEED_RULES.length } });
        } else if (req.method === "GET" && req.url.startsWith("/api/v1/feed/rules")) {
          state.feedRulesRequests += 1;
          sendJSON(200, { rules: FEED_RULES, total: FEED_RULES.length });
        } else {
          sendJSON(404, { error: `Stub has no route for ${req.method} ${req.url}` });
        }
      });
    });

    server.once("error", (err) => {
      if (err.code === "EADDRINUSE") {
        reject(new Error(
          `Port ${FIXED_PORT} is already in use — stop the real PhishGuard backend ` +
          "(or anything else on 7860) before running the E2E suite. The service " +
          "worker hardcodes http://localhost:7860 as its default backend."
        ));
      } else {
        reject(err);
      }
    });

    server.listen(FIXED_PORT, "127.0.0.1", () => {
      resolve({
        port: FIXED_PORT,
        state,
        /** Change what /analyze/full returns from now on. */
        setMode: (mode) => { state.mode = mode; },
        /** Drop recorded requests (e.g. between assertions). */
        reset: () => {
          state.analyzeRequests.length = 0;
          state.feedUpdateCount = 0;
          state.feedRulesRequests = 0;
        },
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

module.exports = { startStubBackend, SW_API_KEY };
