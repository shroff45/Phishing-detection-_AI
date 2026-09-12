/**
 * PhishGuard — Content Script (Phase 7: Anti-Evasion)
 * ════════════════════════════════════════════════════
 * Runs in page context to detect:
 *   1. Browser-in-the-Browser (BitB) attacks
 *   2. Suspicious form behavior & credential harvesting
 *   3. DOM cloaking / obfuscation techniques
 *   4. Clipboard hijacking
 *   5. Rapid DOM mutation (evasion technique)
 *   6. Fake SSL indicators
 *   7. Invisible iframe overlays
 */

(function () {
  "use strict";

  if (window.__phishguard_loaded) return;
  window.__phishguard_loaded = true;

  const signals = {
    // BitB detection
    hasBitB: false,
    bitbScore: 0,
    fakeTitleBar: false,
    fakeUrlBar: false,
    fakeCloseButton: false,

    // Form analysis
    hasPasswordField: false,
    formCount: 0,
    externalFormAction: false,
    hiddenInputCount: 0,
    autoCompleteOff: false,

    // Evasion techniques
    suspiciousIframes: 0,
    invisibleOverlays: 0,
    dataUriImages: 0,
    hasClipboardHijack: false,
    rapidDomMutations: false,
    domCloaking: false,
    fakeSslIndicator: false,
    rightClickDisabled: false,
    textSelectionDisabled: false,

    // Page content
    hasLoginKeywords: false,
    hasBrandImpersonation: false,
    brandDetected: null,
  };

  // ── Brand keywords for content-level detection ────────────────────────
  const BRAND_KEYWORDS = {
    google:    ["google", "gmail", "sign in to google", "one account. all of google"],
    microsoft: ["microsoft", "outlook", "sign in to your account", "xbox", "office 365"],
    paypal:    ["paypal", "send money", "pay after delivery"],
    apple:     ["apple id", "icloud", "app store", "itunes"],
    facebook:  ["facebook", "log into facebook", "create new account"],
    amazon:    ["amazon", "sign-in", "your orders"],
    netflix:   ["netflix", "sign in", "unlimited movies"],
    instagram: ["instagram", "log in to instagram"],
    twitter:   ["twitter", "log in to x", "sign in to x"],
    linkedin:  ["linkedin", "sign in", "join now"],
  };

  // 1. BROWSER-IN-THE-BROWSER (BitB) DETECTION
  function detectBitB() {
    let score = 0;
    const allElements = document.querySelectorAll("*");
    for (const el of allElements) {
      const style = window.getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      if ((style.position === "fixed" || style.position === "absolute") && rect.height >= 20 && rect.height <= 45 && rect.top <= 10 && rect.width > window.innerWidth * 0.3) {
        const text = el.textContent || "";
        const hasControls = /[✕✖×✗☓]/.test(text) || el.querySelectorAll('[class*="close"], [class*="minimize"], [class*="maximize"]').length > 0;
        if (hasControls || style.cursor === "grab" || style.cursor === "move" || el.getAttribute("draggable") === "true") {
          signals.fakeTitleBar = true;
          score += 2;
        }
      }
      if ((el.tagName === "INPUT" || el.tagName === "DIV" || el.tagName === "SPAN") && (style.position === "absolute" || style.position === "fixed")) {
        const content = (el.textContent || el.value || "").trim();
        if (/^https?:\/\//.test(content) && rect.width > 200) {
          signals.fakeUrlBar = true;
          score += 3;
        }
      }
      if ((style.position === "absolute" || style.position === "fixed") && rect.width <= 60 && rect.height <= 40) {
        const text = (el.textContent || "").trim();
        if (/^[✕✖×✗─□☐▢]$/.test(text) || /^[xX_\-\[\]]$/.test(text)) {
          signals.fakeCloseButton = true;
          score += 1;
        }
      }
      if (el.tagName === "SVG" || el.tagName === "IMG" || el.tagName === "I") {
        const cls = (el.className || "").toString().toLowerCase();
        const src = (el.getAttribute("src") || "").toLowerCase();
        if (cls.includes("lock") || cls.includes("secure") || src.includes("lock") || src.includes("padlock")) {
          if (style.position === "absolute" || style.position === "fixed") {
            signals.fakeSslIndicator = true;
            score += 2;
          }
        }
      }
    }
    const iframes = document.querySelectorAll("iframe");
    for (const iframe of iframes) {
      const style = window.getComputedStyle(iframe);
      const rect = iframe.getBoundingClientRect();
      if ((style.position === "fixed" || style.position === "absolute") && parseInt(style.zIndex) > 999 && rect.width >= 300 && rect.height >= 400) {
        signals.suspiciousIframes++;
        score += 2;
      }
    }
    signals.bitbScore = score;
    if (score >= 4) signals.hasBitB = true;
  }

  // 2. FORM & CREDENTIAL HARVESTING ANALYSIS
  function analyzeForms() {
    const forms = document.querySelectorAll("form");
    signals.formCount = forms.length;
    for (const form of forms) {
      const pwFields = form.querySelectorAll('input[type="password"]');
      if (pwFields.length > 0) signals.hasPasswordField = true;
      const action = form.getAttribute("action");
      if (action) {
        try {
          const actionUrl = new URL(action, window.location.href);
          if (actionUrl.hostname !== window.location.hostname) signals.externalFormAction = true;
        } catch {}
      }
      signals.hiddenInputCount += form.querySelectorAll('input[type="hidden"]').length;
      for (const pw of pwFields) {
        if (pw.getAttribute("autocomplete") === "off" || pw.getAttribute("autocomplete") === "new-password") signals.autoCompleteOff = true;
      }
    }
    if (!signals.hasPasswordField) signals.hasPasswordField = document.querySelectorAll('input[type="password"]').length > 0;
  }

  // 3. DOM CLOAKING & OBFUSCATION DETECTION
  function detectDomCloaking() {
    const allElements = document.querySelectorAll("div, a, iframe");
    for (const el of allElements) {
      const style = window.getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      if ((style.position === "fixed" || style.position === "absolute") && parseFloat(style.opacity) < 0.1 && rect.width > window.innerWidth * 0.5 && rect.height > window.innerHeight * 0.5 && parseInt(style.zIndex) > 100) {
        signals.invisibleOverlays++;
      }
    }
    const images = document.querySelectorAll("img");
    for (const img of images) {
      if (img.src && img.src.startsWith("data:")) signals.dataUriImages++;
    }
    if (window.getComputedStyle(document.body).userSelect === "none") signals.textSelectionDisabled = true;
    if (document.oncontextmenu && document.oncontextmenu.toString().includes("return false")) signals.rightClickDisabled = true;
    if (signals.invisibleOverlays > 0 || signals.dataUriImages > 5) signals.domCloaking = true;
  }

  // 4. CLIPBOARD HIJACKING DETECTION
  function detectClipboardHijack() {
    const originalWriteText = navigator.clipboard?.writeText;
    if (originalWriteText) {
      navigator.clipboard.writeText = function (...args) {
        signals.hasClipboardHijack = true;
        return originalWriteText.apply(this, args);
      };
    }
  }

  // 5. RAPID DOM MUTATION DETECTION
  function monitorDomMutations() {
    let mutationCount = 0;
    const startTime = Date.now();
    const observer = new MutationObserver((mutations) => {
      mutationCount += mutations.length;
      if (Date.now() - startTime < 3000 && mutationCount > 200) {
        signals.rapidDomMutations = true;
        observer.disconnect();
      }
    });
    observer.observe(document.body || document.documentElement, { childList: true, subtree: true, attributes: true });
    setTimeout(() => observer.disconnect(), 5000);
  }

  // 6. BRAND IMPERSONATION IN CONTENT
  function detectBrandImpersonation() {
    const pageText = (document.body?.innerText || "").toLowerCase();
    const pageTitle = (document.title || "").toLowerCase();
    const combinedText = pageTitle + " " + pageText;
    const loginKeywords = ["sign in", "log in", "login", "password", "email", "username", "forgot password", "create account", "verify"];
    if (loginKeywords.filter(kw => combinedText.includes(kw)).length < 2) return;
    signals.hasLoginKeywords = true;
    const hostname = window.location.hostname.toLowerCase();
    for (const [brand, keywords] of Object.entries(BRAND_KEYWORDS)) {
      if (keywords.filter(kw => combinedText.includes(kw)).length >= 2) {
        const isLegit = hostname.includes(brand) || hostname.endsWith(`.${brand}.com`) || hostname === `${brand}.com`;
        if (!isLegit) {
          signals.hasBrandImpersonation = true;
          signals.brandDetected = brand;
          break;
        }
      }
    }
  }

  function runAnalysis() {
    try {
      detectBitB();
      analyzeForms();
      detectDomCloaking();
      detectClipboardHijack();
      monitorDomMutations();
      detectBrandImpersonation();
      setTimeout(() => {
        try {
          chrome.runtime.sendMessage({ type: "CONTENT_SIGNALS", signals: { ...signals } });
        } catch (e) {}
      }, 1500);
    } catch (err) {}
  }

  if (document.readyState === "complete") setTimeout(runAnalysis, 300);
  else window.addEventListener("load", () => setTimeout(runAnalysis, 300));

  // ── In-page warning overlay (showWarningOverlay setting) ─────────────
  // The service worker sends VERDICT_UPDATE when a page lands on a
  // phishing verdict and the user has the overlay enabled. The banner is
  // dismissible and never blocks interaction — it warns, it does not
  // gate. Previously this toggle was saved by the options page and read
  // by nothing.
  let overlayShown = false;

  chrome.runtime.onMessage.addListener((message, _sender, _sendResponse) => {
    if (message?.type !== "VERDICT_UPDATE") return;
    if (message.verdict === "phishing" && !overlayShown) {
      showWarningOverlay(message);
    }
  });

  function showWarningOverlay({ reasons }) {
    if (document.getElementById("phishguard-warning-banner")) return;
    overlayShown = true;

    const banner = document.createElement("div");
    banner.id = "phishguard-warning-banner";
    banner.setAttribute("role", "alert");
    Object.assign(banner.style, {
      position: "fixed",
      top: "0",
      left: "0",
      right: "0",
      zIndex: "2147483647",
      backgroundColor: "#93000a",
      color: "#ffffff",
      fontFamily: "system-ui, -apple-system, sans-serif",
      fontSize: "14px",
      padding: "12px 48px 12px 16px",
      borderBottom: "2px solid #690005",
      textAlign: "center",
      lineHeight: "1.4",
    });

    const strong = document.createElement("strong");
    strong.textContent = "⚠ PhishGuard: this page shows strong phishing indicators.";
    const reason = document.createElement("div");
    reason.style.cssText = "opacity:0.9;font-size:12px;margin-top:2px;";
    reason.textContent = (reasons && reasons[0]) || "Do not enter credentials or personal information.";

    const dismiss = document.createElement("button");
    dismiss.textContent = "✕";
    dismiss.setAttribute("aria-label", "Dismiss warning");
    Object.assign(dismiss.style, {
      position: "absolute",
      right: "10px",
      top: "50%",
      transform: "translateY(-50%)",
      background: "transparent",
      border: "none",
      color: "#ffffff",
      fontSize: "16px",
      cursor: "pointer",
      padding: "4px 8px",
    });
    dismiss.addEventListener("click", () => banner.remove());

    banner.appendChild(strong);
    banner.appendChild(reason);
    banner.appendChild(dismiss);
    document.documentElement.appendChild(banner);
  }
})();
