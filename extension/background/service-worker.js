/**
 * PhishGuard — Service Worker (Manifest V3)
 * FIXED: Verdict monotonicity, suspicious hosting detection, path keyword boost
 * 
 * Runs in the background. Responsibilities:
 *   1. Extract 30 lexical features from every navigated URL
 *   2. Run local ONNX inference for instant scoring
 *   3. Escalate ambiguous URLs to backend with screenshot
 *   4. Update badge icon based on verdict
 *   5. Periodically sync threat feed rules from backend
 *   6. NEVER downgrade a phishing verdict from backend
 */

// ── ONNX Runtime Setup ────────────────────────────────────────────────────
importScripts("../lib/ort.min.js");

// Point ONNX Runtime at bundled WASM files
ort.env.wasm.wasmPaths = chrome.runtime.getURL("lib/");

let ortSession = null;

async function loadModel() {
  if (ortSession) return ortSession;
  try {
    const modelUrl = chrome.runtime.getURL("models/model.onnx");
    const response = await fetch(modelUrl);
    const buffer = await response.arrayBuffer();
    ortSession = await ort.InferenceSession.create(buffer, {
      executionProviders: ["wasm"],
    });
    console.log("[PhishGuard] ONNX model loaded successfully");
    return ortSession;
  } catch (err) {
    console.error("[PhishGuard] Failed to load ONNX model:", err);
    return null;
  }
}

// Load model on startup
loadModel();

// ── Constants ─────────────────────────────────────────────────────────────
let BACKEND_URL = "http://localhost:7860"; // default for first install

// Opt-in, default OFF. Screenshots are un-redacted captures of whatever the
// user is looking at; they only leave the device if the user asks for it.
let shareScreenshots = false;

// Default ON, matching the options page's `!== false` read. When off, no URL
// ever reaches the backend and scoring is local-only.
let allowBackendEscalation = true;

// Load user-configured backend URL
chrome.storage.local.get(['settings'], (result) => {
  if (result.settings?.backendUrl) {
    BACKEND_URL = result.settings.backendUrl;
    console.log('[PhishGuard] Using backend:', BACKEND_URL);
  }
  shareScreenshots = result.settings?.shareScreenshots === true;
  allowBackendEscalation = result.settings?.allowBackendEscalation !== false;
});

// Update when user changes settings
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local' || !changes.settings) return;
  const next = changes.settings.newValue;
  if (next?.backendUrl) {
    BACKEND_URL = next.backendUrl;
    console.log('[PhishGuard] Backend URL updated to:', next.backendUrl);
  }
  shareScreenshots = next?.shareScreenshots === true;
  allowBackendEscalation = next?.allowBackendEscalation !== false;
});

const EXTENSION_API_KEY = "phishguard-dev-key"; // Should match .env


const PHISH_KEYWORDS = [
  "login", "signin", "sign-in", "verify", "account",
  "update", "secure", "banking", "confirm", "password",
  "suspend", "alert", "unusual", "restore", "unlock",
];

const SUSPICIOUS_TLDS = new Set([
  ".xyz", ".icu", ".top", ".tk", ".ml", ".ga", ".cf",
  ".gq", ".buzz", ".club", ".info", ".site", ".online",
  ".website", ".link", ".click", ".surf",
]);

const SHORTENER_DOMAINS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
  "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
]);

// ── NEW: Suspicious hosting/tunnel providers ──────────────────────────────
const SUSPICIOUS_HOSTING = new Set([
  "trycloudflare.com",
  "ngrok.io", "ngrok-free.app", "ngrok.app",
  "workers.dev",
  "pages.dev",
  "netlify.app",
  "vercel.app",
  "herokuapp.com",
  "glitch.me",
  "repl.co", "replit.dev",
  "firebaseapp.com",
  "web.app",
  "onrender.com",
  "fly.dev",
  "railway.app",
  "surge.sh",
  "000webhostapp.com",
  "infinityfreeapp.com",
]);

// Top legitimate domains — skip analysis entirely
const WHITELIST = new Set([
  "google.com", "www.google.com", "youtube.com", "www.youtube.com",
  "facebook.com", "www.facebook.com", "amazon.com", "www.amazon.com",
  "wikipedia.org", "en.wikipedia.org", "twitter.com", "www.twitter.com",
  "instagram.com", "www.instagram.com", "linkedin.com", "www.linkedin.com",
  "reddit.com", "www.reddit.com", "netflix.com", "www.netflix.com",
  "microsoft.com", "www.microsoft.com", "apple.com", "www.apple.com",
  "github.com", "www.github.com", "stackoverflow.com",
  "yahoo.com", "www.yahoo.com", "bing.com", "www.bing.com",
  "twitch.tv", "www.twitch.tv", "whatsapp.com", "web.whatsapp.com",
  "zoom.us", "spotify.com", "open.spotify.com",
  "adobe.com", "dropbox.com", "slack.com", "paypal.com", "www.paypal.com",
  "ebay.com", "www.ebay.com", "cnn.com", "bbc.com", "bbc.co.uk",
  "microsoftonline.com"
]);

// ── NEW: Brand domains for spoofing detection ─────────────────────────────
const BRAND_DOMAINS = {
  paypal:    ["paypal.com"],
  google:    ["google.com", "gmail.com", "accounts.google.com"],
  microsoft: ["microsoft.com", "outlook.com", "live.com", "office.com"],
  apple:     ["apple.com", "icloud.com"],
  amazon:    ["amazon.com", "amazon.co.uk", "amazon.in"],
  facebook:  ["facebook.com", "fb.com"],
  netflix:   ["netflix.com"],
  instagram: ["instagram.com"],
  twitter:   ["twitter.com", "x.com"],
  linkedin:  ["linkedin.com"],
  chase:     ["chase.com"],
  wells:     ["wellsfargo.com"],
  bank:      ["bankofamerica.com"],
};

// ── Feature Names (must match training order exactly) ─────────────────────
const FEATURE_NAMES = [
  "f01_urlLength",
  "f02_hostnameLength",
  "f03_pathLength",
  "f04_queryLength",
  "f05_dotCountUrl",
  "f06_dotCountHost",
  "f07_hyphenCountUrl",
  "f08_hyphenCountHost",
  "f09_underscoreCount",
  "f10_atSymbolCount",
  "f11_digitCountUrl",
  "f12_digitCountHost",
  "f13_digitToLetterRatio",
  "f14_subdomainCount",
  "f15_pathDepth",
  "f16_queryParamCount",
  "f17_isIpAddress",
  "f18_entropyUrl",
  "f19_entropyHost",
  "f20_entropyPath",
  "f21_specialCharCount",
  "f22_hasPort",
  "f23_isHttps",
  "f24_hasSuspiciousTld",
  "f25_hasPunycode",
  "f26_isShortener",
  "f27_keywordHits",
  "f28_encodedCharCount",
  "f29_doubleSlashCount",
  "f30_longestSubdomainLen",
];

// ── Helper Functions ──────────────────────────────────────────────────────

function shannonEntropy(text) {
  if (!text) return 0;
  const freq = {};
  for (const ch of text) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  const len = text.length;
  let entropy = 0;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// ── NEW: Domain trust check ───────────────────────────────────────────────
function checkDomainTrust(hostname) {
  if (WHITELIST.has(hostname)) {
    return { trusted: true, reason: "Domain is in the trusted whitelist" };
  }
  
  // Also check if any trusted domain is a suffix (e.g., accounts.google.com -> .google.com)
  for (const trusted of WHITELIST) {
    if (hostname.endsWith("." + trusted)) {
      return { trusted: true, reason: "Subdomain of trusted domain" };
    }
  }
  
  return { trusted: false, reason: null };
}

// ── NEW: Brand spoofing detection ─────────────────────────────────────────
function detectBrandSpoofing(hostname) {
  const lower = hostname.toLowerCase();
  for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
    // Check if hostname contains the brand name but isn't the real domain
    if (lower.includes(brand)) {
      const isLegit = domains.some(d => lower === d || lower.endsWith("." + d));
      if (!isLegit) {
        return { isSpoofing: true, brand };
      }
    }
  }
  return { isSpoofing: false, brand: null };
}

// ── NEW: Suspicious hosting detection ─────────────────────────────────────
function isSuspiciousHosting(hostname) {
  const lower = hostname.toLowerCase();
  for (const provider of SUSPICIOUS_HOSTING) {
    if (lower.endsWith(provider) || lower.endsWith("." + provider)) {
      return provider;
    }
  }
  return null;
}

// ── NEW: Path keyword detection ───────────────────────────────────────────
function checkPathKeywords(pathname) {
  const lower = pathname.toLowerCase();
  const keywords = [
    "login", "signin", "sign-in", "log-in",
    "verify", "verification", "validate",
    "account", "myaccount", "secure", "security",
    "password", "reset", "recovery",
    "banking", "payment", "checkout", "wallet",
    "webmail", "roundcube",
  ];
  return keywords.filter(kw => lower.includes(kw));
}

/**
 * Extract 30 lexical features from a raw URL string.
 * This function MUST produce identical values to build_dataset.py's extract_features().
 */
function extractLexicalFeatures(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return null;
  }

  const hostname = parsed.hostname || "";
  const pathname = parsed.pathname || "/";
  const fullUrl = rawUrl;

  // Query length: use URL.search which includes '?' prefix
  const queryLength = parsed.search.length; // 0 if no query, else includes '?'

  // Query param count
  let queryParamCount = 0;
  if (parsed.search.length > 1) {
    const rawQuery = parsed.search.substring(1); // remove '?'
    queryParamCount = rawQuery.split("&").filter(p => p.length > 0).length;
  }

  const hostParts = hostname ? hostname.split(".") : [""];
  const subdomainCount = Math.max(0, hostParts.length - 2);
  const pathSegments = pathname.split("/").filter(s => s.length > 0);

  let digits = 0;
  let letters = 0;
  for (const ch of fullUrl) {
    if (ch >= "0" && ch <= "9") digits++;
    else if ((ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z")) letters++;
  }

  const lowerUrl = fullUrl.toLowerCase();
  let keywordHits = 0;
  for (const kw of PHISH_KEYWORDS) {
    if (lowerUrl.includes(kw)) keywordHits++;
  }

  const tld = hostParts.length > 0 ? "." + hostParts[hostParts.length - 1] : "";
  const hasSuspiciousTld = SUSPICIOUS_TLDS.has(tld.toLowerCase()) ? 1 : 0;
  const hasPunycode = hostname.toLowerCase().includes("xn--") ? 1 : 0;

  let isShortener = 0;
  for (const d of SHORTENER_DOMAINS) {
    if (hostname.toLowerCase().endsWith(d)) {
      isShortener = 1;
      break;
    }
  }

  const encodedChars = (fullUrl.match(/%[0-9a-fA-F]{2}/g) || []).length;
  const doubleSlashes = Math.max(0, (fullUrl.match(/\/\//g) || []).length - 1);
  const specialChars = (fullUrl.match(/[!$%^*()+=\{\}\[\]|;:'"<>?]/g) || []).length;

  let longestSubdomain = 0;
  if (hostParts.length > 2) {
    for (let i = 0; i < hostParts.length - 2; i++) {
      longestSubdomain = Math.max(longestSubdomain, hostParts[i].length);
    }
  }

  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const hexIp = /^0x[\da-fA-F]+$/i.test(hostname);
  const ipv6 = /^\[[\da-fA-F:]+\]$/.test(hostname);
  const isIp = (ipv4 || hexIp || ipv6) ? 1 : 0;

  let digitCountHost = 0;
  for (const ch of hostname) {
    if (ch >= "0" && ch <= "9") digitCountHost++;
  }

  return {
    f01_urlLength: fullUrl.length,
    f02_hostnameLength: hostname.length,
    f03_pathLength: pathname.length,
    f04_queryLength: queryLength,
    f05_dotCountUrl: (fullUrl.match(/\./g) || []).length,
    f06_dotCountHost: (hostname.match(/\./g) || []).length,
    f07_hyphenCountUrl: (fullUrl.match(/-/g) || []).length,
    f08_hyphenCountHost: (hostname.match(/-/g) || []).length,
    f09_underscoreCount: (fullUrl.match(/_/g) || []).length,
    f10_atSymbolCount: (fullUrl.match(/@/g) || []).length,
    f11_digitCountUrl: digits,
    f12_digitCountHost: digitCountHost,
    f13_digitToLetterRatio: letters > 0 ? digits / letters : digits,
    f14_subdomainCount: subdomainCount,
    f15_pathDepth: pathSegments.length,
    f16_queryParamCount: queryParamCount,
    f17_isIpAddress: isIp,
    f18_entropyUrl: shannonEntropy(fullUrl),
    f19_entropyHost: shannonEntropy(hostname),
    f20_entropyPath: shannonEntropy(pathname),
    f21_specialCharCount: specialChars,
    f22_hasPort: parsed.port ? 1 : 0,
    f23_isHttps: parsed.protocol === "https:" ? 1 : 0,
    f24_hasSuspiciousTld: hasSuspiciousTld,
    f25_hasPunycode: hasPunycode,
    f26_isShortener: isShortener,
    f27_keywordHits: keywordHits,
    f28_encodedCharCount: encodedChars,
    f29_doubleSlashCount: doubleSlashes,
    f30_longestSubdomainLen: longestSubdomain,
  };
}

/**
 * Run ONNX inference on a 30-feature vector.
 * Returns phishing probability (0.0 = safe, 1.0 = phishing).
 */
async function runInference(features) {
  const session = await loadModel();
  if (!session) {
    console.warn("[PhishGuard] No model session, returning 0.5");
    return 0.5;
  }

  // Build feature array in exact training order
  const featureArray = new Float32Array(FEATURE_NAMES.length);
  for (let i = 0; i < FEATURE_NAMES.length; i++) {
    const val = features[FEATURE_NAMES[i]];
    featureArray[i] = isFinite(val) ? val : 0;
  }

  const inputTensor = new ort.Tensor("float32", featureArray, [1, 30]);

  try {
    // Input name MUST be "float_input" — set in train_url_model.py
    const results = await session.run({ float_input: inputTensor });

    // Output: probabilities tensor with shape [1, 2] → [p_legit, p_phish]
    const outputNames = Object.keys(results);
    // skl2onnx with zipmap=False outputs "label" and "probabilities"
    const probKey = outputNames.find(k => k.toLowerCase().includes("probabilities")) || outputNames[1] || outputNames[0];
    const probs = results[probKey].data;

    // probs = [p_legit, p_phish]
    const phishProb = probs[1];
    return phishProb;
  } catch (err) {
    console.error("[PhishGuard] Inference failed:", err);
    return 0.5;
  }
}

// ── Badge & Icon Management ───────────────────────────────────────────────

function updateBadge(tabId, verdict, score) {
  let color, text, iconPrefix;

  if (verdict === "safe") {
    color = "#22c55e"; // green
    text = "✓";
    iconPrefix = "safe";
  } else if (verdict === "suspicious") {
    color = "#f59e0b"; // amber
    text = "!";
    iconPrefix = "warning";
  } else if (verdict === "phishing") {
    color = "#ef4444"; // red
    text = "✗";
    iconPrefix = "danger";
  } else {
    color = "#6b7280"; // gray
    text = "?";
    iconPrefix = "default";
  }

  chrome.action.setBadgeBackgroundColor({ tabId, color });
  chrome.action.setBadgeText({ tabId, text });

  // Try to set icon (may fail if icons don't exist yet)
  try {
    chrome.action.setIcon({
      tabId,
      path: {
        16: `icons/${iconPrefix}-16.png`,
        32: `icons/${iconPrefix}-32.png`,
        48: `icons/${iconPrefix}-48.png`,
        128: `icons/${iconPrefix}-128.png`,
      },
    });
  } catch (e) {
    // Icons not yet created — badge alone is fine
  }
}

// Store per-tab results for popup to read
const tabResults = new Map();

function storeResult(tabId, result) {
  tabResults.set(tabId, {
    ...result,
    timestamp: Date.now(),
  });
  // Clean old entries
  if (tabResults.size > 200) {
    const oldest = [...tabResults.entries()]
      .sort((a, b) => a[1].timestamp - b[1].timestamp)
      .slice(0, 50);
    for (const [key] of oldest) {
      tabResults.delete(key);
    }
  }
}

// ── Core Analysis Pipeline ────────────────────────────────────────────────

/**
 * Main analysis function — called on every navigation.
 * FIXED: Verdict monotonicity, suspicious hosting, path keywords.
 */
async function analyzeUrl(tabId, url) {
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    updateBadge(tabId, "safe");
    return;
  }

  let parsed;
  try { parsed = new URL(url); } catch { return; }
  if (!["http:", "https:"].includes(parsed.protocol)) return;

  const hostname = parsed.hostname.toLowerCase();

  // ── STEP 1: Domain trust check ──────────────────────────────────────
  const trust = checkDomainTrust(hostname);
  if (trust.trusted) {
    const result = {
      url, verdict: "safe", score: 0.0, source: "whitelist",
      reasons: [trust.reason],
    };
    storeResult(tabId, result);
    updateBadge(tabId, "safe");
    console.log(`[PhishGuard] TRUSTED: ${hostname}`);
    return;
  }

  // ── STEP 1b: IP Phishing block ──────────────────────────────────────
  const ipv4Match = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  if (ipv4Match) {
    const isPrivate = hostname.startsWith("127.") || 
                      hostname.startsWith("192.168.") || 
                      hostname.startsWith("10.") || 
                      hostname.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./);
    if (!isPrivate) {
      const result = {
        url, verdict: "phishing", score: 0.95, source: "ip_rule",
        reasons: ["URL uses a public IP address instead of a domain name"],
      };
      storeResult(tabId, result);
      updateBadge(tabId, "phishing");
      console.log(`[PhishGuard] IP BLOCKED: ${hostname}`);
      return;
    }
  }

  // ── STEP 2: ML inference ────────────────────────────────────────────
  const features = extractLexicalFeatures(url);
  if (!features) { updateBadge(tabId, "safe"); return; }

  const mlScore = await runInference(features);
  let finalScore = mlScore;
  const reasons = [];

  console.log(`[PhishGuard] ${hostname} — ML: ${mlScore.toFixed(3)}`);

  // ── STEP 3: Domain-level signals ────────────────────────────────────

  // 3a: Brand spoofing
  const brandCheck = detectBrandSpoofing(hostname);
  if (brandCheck.isSpoofing) {
    finalScore = Math.min(1.0, finalScore + 0.40);
    reasons.push(`Domain impersonates "${brandCheck.brand}"`);
  }

  // 3b: Suspicious hosting/tunnel provider (NEW — catches trycloudflare.com)
  const hostingProvider = isSuspiciousHosting(hostname);
  if (hostingProvider) {
    finalScore = Math.min(1.0, finalScore + 0.20);
    reasons.push(`Hosted on suspicious provider: ${hostingProvider}`);
  }

  // 3c: IP address
  if (features.f17_isIpAddress === 1) {
    finalScore = Math.min(1.0, finalScore + 0.30);
    reasons.push("URL uses IP address instead of domain");
  }

  // 3d: @ symbol
  if (features.f10_atSymbolCount > 0) {
    finalScore = Math.min(1.0, finalScore + 0.25);
    reasons.push("URL contains @ symbol (obfuscation)");
  }

  // 3e: Punycode
  if (features.f25_hasPunycode === 1) {
    finalScore = Math.min(1.0, finalScore + 0.20);
    reasons.push("Internationalized domain (homograph risk)");
  }

  // 3f: Suspicious TLD + phishing keywords
  const isSusTLD = features.f24_hasSuspiciousTld === 1;
  const hasKW = features.f27_keywordHits >= 2;

  if (isSusTLD && hasKW) {
    finalScore = Math.min(1.0, finalScore + 0.30);
    reasons.push("Suspicious TLD with phishing keywords");
  } else if (isSusTLD) {
    finalScore = Math.min(1.0, finalScore + 0.10);
    reasons.push("Suspicious top-level domain");
  }

  // 3g: Path keywords (NEW — catches /login.html, /signin, etc.)
  // Only applies when domain is ALSO suspicious
  const pathKW = checkPathKeywords(parsed.pathname);
  if (pathKW.length >= 2 && (isSusTLD || hostingProvider || brandCheck.isSpoofing)) {
    finalScore = Math.min(1.0, finalScore + 0.15);
    reasons.push(`Suspicious path: ${pathKW.slice(0, 3).join(", ")}`);
  }

  // 3h: URL shortener
  if (features.f26_isShortener === 1) {
    finalScore = Math.min(1.0, finalScore + 0.10);
    reasons.push("URL shortener — destination unknown");
  }

  // 3i: No HTTPS on suspicious domain
  if (!features.f23_isHttps && (isSusTLD || hostingProvider)) {
    finalScore = Math.min(1.0, finalScore + 0.10);
    reasons.push("No HTTPS on suspicious domain");
  }

  finalScore = Math.max(0, Math.min(1.0, finalScore));

  // ── STEP 4: Local verdict ───────────────────────────────────────────
  let localVerdict;
  if (finalScore >= 0.65) localVerdict = "phishing";
  else if (finalScore >= 0.35) localVerdict = "suspicious";
  else localVerdict = "safe";

  if (localVerdict === "safe" && reasons.length === 0) {
    reasons.push("No phishing indicators detected");
  }

  let result = { url, verdict: localVerdict, score: finalScore, source: "local_ml", reasons };

  console.log(`[PhishGuard] ${hostname} — final: ${finalScore.toFixed(3)} → ${localVerdict}`);

  // ── STEP 5: Backend escalation with VERDICT MONOTONICITY ────────────
  // Key fix: Backend can only UPGRADE the verdict, never downgrade it.
  // If local says "phishing", backend cannot flip it to "safe".

  const shouldEscalate =
    allowBackendEscalation &&
    (finalScore >= 0.25 || brandCheck.isSpoofing || hostingProvider);

  if (shouldEscalate) {
    try {
      const br = await escalateToBackend(tabId, url, finalScore);
      if (br) {
        const backendScore = br.score || 0;

        // ══════════════════════════════════════════════════════════
        // VERDICT MONOTONICITY: Take the MAXIMUM of local and backend
        // Backend can enrich with reasons but NEVER lower the score
        // ══════════════════════════════════════════════════════════
        const mergedScore = Math.max(finalScore, backendScore);
        const mergedVerdict = mergedScore >= 0.65 ? "phishing" :
                              mergedScore >= 0.35 ? "suspicious" : "safe";

        // Merge reasons (deduplicated)
        const allReasons = [...new Set([...reasons, ...(br.reasons || [])])];

        result = {
          url,
          verdict: mergedVerdict,
          score: mergedScore,
          source: "backend+local",
          reasons: allReasons,
          visual: br.visual_analysis || null,
          signals: br.signals || [],
          evidence_trail: br.evidence_trail || [],
          stage3_signals: br.stage3_signals || null,
        };

        // Log if backend tried to downgrade (for debugging)
        if (backendScore < finalScore) {
          console.log(`[PhishGuard] Backend tried to downgrade: ${backendScore.toFixed(3)} < ${finalScore.toFixed(3)} — BLOCKED`);
        }
      }
    } catch (e) {
      console.debug("[PhishGuard] Backend unavailable:", e.message);
    }
  }

  storeResult(tabId, result);
  updateBadge(tabId, result.verdict);

  if (result.verdict === "phishing") {
    try {
      chrome.notifications.create(`phish-${tabId}-${Date.now()}`, {
        type: "basic",
        iconUrl: chrome.runtime.getURL("icons/danger-128.png"),
        title: "⚠️ PhishGuard: Threat Detected",
        message: `${reasons[0] || "Phishing detected"}\n${url.substring(0, 60)}`,
        priority: 2,
      });
    } catch(e) {}
  }
}

/**
 * Escalate to backend for threat-feed and heuristic analysis.
 *
 * Screenshots are NOT sent unless the user has explicitly enabled
 * `shareScreenshots` in settings. The capture is un-redacted, so an escalation
 * on a banking or health page would otherwise upload account numbers and names.
 * Default-off keeps the privacy claim true; PRIVACY.md documents the trade-off.
 * Phase 2 replaces this with derived features (perceptual hash + layout vector).
 */
async function escalateToBackend(tabId, url, clientScore) {
  let screenshotBase64 = null;

  if (shareScreenshots) {
    try {
      // JPEG, not PNG: `quality` is silently ignored for PNG, so a PNG capture
      // is full-size lossless — the worst case for both bandwidth and PII.
      screenshotBase64 = await chrome.tabs.captureVisibleTab(null, {
        format: "jpeg",
        quality: 60,
      });
    } catch (err) {
      console.debug("[PhishGuard] Screenshot capture failed:", err.message);
    }
  }

  const body = {
    url,
    client_score: clientScore,
    screenshot_base64: screenshotBase64,
  };

  const response = await fetch(`${BACKEND_URL}/api/v1/analyze/full`, {
    method: "POST",
    headers: { 
      "Content-Type": "application/json",
      "X-API-Key": EXTENSION_API_KEY
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10000), // 10s timeout
  });

  if (!response.ok) {
    throw new Error(`Backend returned ${response.status}`);
  }

  return await response.json();
}

// ── Navigation Listener ───────────────────────────────────────────────────

chrome.webNavigation.onCompleted.addListener(
  (details) => {
    // Only analyze main frame navigations
    if (details.frameId === 0) {
      analyzeUrl(details.tabId, details.url);
    }
  },
  { url: [{ schemes: ["http", "https"] }] }
);

// Also analyze on tab activation (switching tabs)
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab.url) {
      // Check if we already have a cached result
      const cached = tabResults.get(activeInfo.tabId);
      if (cached && cached.url === tab.url) {
        updateBadge(activeInfo.tabId, cached.verdict, cached.score);
      } else {
        analyzeUrl(activeInfo.tabId, tab.url);
      }
    }
  } catch (e) {
    // Tab may have been closed
  }
});

// Clean up when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  tabResults.delete(tabId);
});

// ── Message Handler (for popup & content scripts) ─────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_RESULT") {
    const tabId = message.tabId;
    const result = tabResults.get(tabId) || {
      verdict: "unknown",
      score: 0,
      reasons: ["Page not yet analyzed"],
    };
    sendResponse(result);
    return true; // async response
  }

  if (message.type === "CONTENT_SIGNALS") {
    // Receive additional signals from content script
    const tabId = sender.tab?.id;
    if (tabId) {
      const existing = tabResults.get(tabId);
      if (existing) {
        // Merge content script signals
        if (message.signals) {
          existing.contentSignals = message.signals;
          // Boost score if content script found suspicious elements
          if (message.signals.hasBitB) {
            existing.score = Math.min(1.0, existing.score + 0.3);
            existing.reasons.push("Browser-in-the-Browser (BitB) attack detected");
            existing.verdict = existing.score >= 0.65 ? "phishing" : "suspicious";
            updateBadge(tabId, existing.verdict, existing.score);
          }
          // Boost for brand impersonation detected in content
          if (message.signals.hasBrandImpersonation) {
            existing.score = Math.min(1.0, existing.score + 0.25);
            existing.reasons.push(`Content impersonates ${message.signals.brandDetected}`);
            existing.verdict = existing.score >= 0.65 ? "phishing" : "suspicious";
            updateBadge(tabId, existing.verdict, existing.score);
          }
          storeResult(tabId, existing);
        }
      }
    }
    sendResponse({ ok: true });
    return true;
  }

  if (message.type === "REANALYZE") {
    const tabId = message.tabId;
    chrome.tabs.get(tabId, (tab) => {
      if (tab && tab.url) {
        analyzeUrl(tabId, tab.url);
      }
    });
    sendResponse({ ok: true });
    return true;
  }
});

// ── Threat Feed Sync ──────────────────────────────────────────────────────

async function syncThreatFeed() {
  try {
    // First trigger backend to update its feeds
    await fetch(`${BACKEND_URL}/api/v1/feed/update`, { 
      method: "POST",
      headers: { "X-API-Key": EXTENSION_API_KEY }
    });

    // Then fetch the generated rules
    const response = await fetch(`${BACKEND_URL}/api/v1/feed/rules`, {
      headers: { "X-API-Key": EXTENSION_API_KEY }
    });
    if (!response.ok) return;

    const data = await response.json();
    const rules = data.rules || [];

    if (rules.length === 0) return;

    // Get existing dynamic rules
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const existingIds = existing.map(r => r.id);

    // Remove old rules and add new ones
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existingIds,
      addRules: rules.slice(0, 4999), // Chrome limit is 5000
    });

    console.log(`[PhishGuard] Synced ${rules.length} threat feed rules`);
  } catch (err) {
    console.debug("[PhishGuard] Feed sync failed:", err.message);
  }
}

// Sync feeds every hour
chrome.alarms.create("syncFeeds", { periodInMinutes: 60 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "syncFeeds") {
    syncThreatFeed();
  }
});

// Initial sync on install/startup
chrome.runtime.onInstalled.addListener(() => {
  console.log("[PhishGuard] Extension installed/updated");
  syncThreatFeed();
});

chrome.runtime.onStartup.addListener(() => {
  loadModel();
  syncThreatFeed();
});
