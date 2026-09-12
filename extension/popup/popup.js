/**
 * PhishGuard — Popup Script
 * Displays analysis results for the current tab.
 * Updated for Obsidian Shield UI.
 */

document.addEventListener("DOMContentLoaded", async () => {
  const loading     = document.getElementById("loading");
  const content     = document.getElementById("content");
  const statusCard  = document.getElementById("statusCard");
  const statusShield = document.getElementById("statusShield");
  const statusTitle = document.getElementById("statusTitle");
  const statusSubtitle = document.getElementById("statusSubtitle");
  const threatFill  = document.getElementById("threatFill");
  const threatValue = document.getElementById("threatValue");
  const urlDisplay  = document.getElementById("urlDisplay");
  const auditSection = document.getElementById("auditSection");
  const auditList   = document.getElementById("auditList");
  const trailSection = document.getElementById("trailSection");
  const trailList   = document.getElementById("trailList");
  const sourceLabel = document.getElementById("sourceLabel");
  const intelDot    = document.getElementById("intelDot");
  const intelValue  = document.getElementById("intelValue");
  const btnReanalyze = document.getElementById("btnReanalyze");
  const btnSettings  = document.getElementById("btnSettings");
  const settingsLink = document.getElementById("settingsLink");
  const headerIcon  = document.getElementById("headerIcon");

  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tab || !tab.id) {
    showResult({
      verdict: "unknown",
      score: 0,
      reasons: ["Unable to access current tab"],
      source: "error",
    });
    return;
  }

  // Show URL
  urlDisplay.textContent = tab.url || "Unknown URL";

  // Request result from service worker
  chrome.runtime.sendMessage(
    { type: "GET_RESULT", tabId: tab.id },
    (result) => {
      if (chrome.runtime.lastError) {
        showResult({
          verdict: "unknown",
          score: 0,
          reasons: ["Extension not ready. Try refreshing the page."],
          source: "error",
        });
        return;
      }
      showResult(result || {
        verdict: "unknown",
        score: 0,
        reasons: ["Page not yet analyzed"],
      });
    }
  );

  // Re-analyze button
  btnReanalyze.addEventListener("click", () => {
    loading.classList.remove("hidden");
    content.classList.add("hidden");

    chrome.runtime.sendMessage(
      { type: "REANALYZE", tabId: tab.id },
      () => {
        setTimeout(() => {
          chrome.runtime.sendMessage(
            { type: "GET_RESULT", tabId: tab.id },
            (result) => {
              showResult(result || { verdict: "unknown", score: 0, reasons: [] });
            }
          );
        }, 2000);
      }
    );
  });

  // Settings buttons
  const openSettings = () => {
    chrome.runtime.openOptionsPage
      ? chrome.runtime.openOptionsPage()
      : window.open(chrome.runtime.getURL("options/options.html"));
  };
  btnSettings.addEventListener("click", openSettings);
  settingsLink.addEventListener("click", (e) => {
    e.preventDefault();
    openSettings();
  });

  // ─── RENDER ───
  function showResult(result) {
    loading.classList.add("hidden");
    content.classList.remove("hidden");

    // Defensive field access to prevent UI crashes on partial APIs
    const safeResults = {
      score: result?.score ?? 0,
      verdict: result?.verdict ?? "unknown",
      reasons: result?.reasons ?? [],
      source: result?.source ?? "unknown",
      feeds_checked: result?.feeds_checked ?? [],
      feeds_flagged: result?.feeds_flagged ?? []
    };

    const verdict = safeResults.verdict;
    const score   = safeResults.score;
    const reasons = safeResults.reasons;
    const source  = safeResults.source;
    const pct     = Math.round(score * 100);

    // Status card class
    statusCard.className = `status-hero ${verdict}`;

    // Threat bar
    threatFill.className = `threat-bar-fill ${verdict}`;
    threatFill.style.width = `${pct}%`;
    threatValue.textContent = `${pct}%`;

    // Shield icon, title, subtitle
    switch (verdict) {
      case "safe":
        statusShield.textContent  = "🛡️";
        statusTitle.textContent   = "Safe Website";
        statusSubtitle.textContent = "No phishing indicators detected on this origin.";
        headerIcon.src = "../icons/safe-32.png";
        intelDot.classList.add("active");
        intelValue.textContent = "Active";
        break;

      case "suspicious":
        statusShield.textContent  = "⚠️";
        statusTitle.textContent   = "Suspicious Activity";
        statusSubtitle.textContent = "Some indicators require caution. Proceed carefully.";
        headerIcon.src = "../icons/warning-32.png";
        intelDot.classList.add("active");
        intelValue.textContent = "Monitoring";
        break;

      case "phishing":
        statusShield.textContent  = "🚫";
        statusTitle.textContent   = "High Risk: Suspected Phishing";
        statusSubtitle.textContent = "Multiple critical phishing indicators detected. Your personal information may be at risk.";
        headerIcon.src = "../icons/danger-32.png";
        intelDot.classList.remove("active");
        intelValue.textContent = "Threat Detected";
        break;

      default:
        statusShield.textContent  = "🔍";
        statusTitle.textContent   = "Unknown";
        statusSubtitle.textContent = "Unable to determine site safety.";
        headerIcon.src = "../icons/default-32.png";
        intelDot.classList.remove("active");
        intelValue.textContent = "Inactive";
    }

    // Source label
    const sourceMap = {
      whitelist:  "Trusted Domain",
      local_ml:   "Local ML Analysis",
      backend:    "PhishGuard AI Core",
      error:      "System Error",
    };
    sourceLabel.textContent = sourceMap[source] || source;

    // Intel Pipeline Chips
    const feedsChecked = result.feeds_checked || [];
    const feedsFlagged = result.feeds_flagged || [];
    
    if (feedsChecked.length > 0) {
      intelValue.textContent = feedsChecked.join(", ");
      if (feedsFlagged.length > 0) {
        intelValue.innerHTML = feedsChecked.map(f => 
          feedsFlagged.includes(f) 
            ? `<span style="color:var(--error)">${f}</span>` 
            : `<span style="color:var(--primary)">${f}</span>`
        ).join(" · ");
      }
    }

    // Audit items
    if (reasons.length > 0) {
      auditSection.classList.remove("hidden");
      auditList.innerHTML = "";

      for (const reason of reasons) {
        const li = document.createElement("li");
        li.className = `audit-item ${getAuditClass(verdict, reason)}`;

        const iconDiv = document.createElement("div");
        iconDiv.className = "audit-icon";
        iconDiv.textContent = getAuditIcon(verdict, reason);

        const bodyDiv = document.createElement("div");
        bodyDiv.className = "audit-body";

        const titleEl = document.createElement("div");
        titleEl.className = "audit-title";
        titleEl.textContent = extractTitle(reason);

        const descEl = document.createElement("div");
        descEl.className = "audit-desc";
        descEl.textContent = extractDesc(reason);

        bodyDiv.appendChild(titleEl);
        bodyDiv.appendChild(descEl);
        li.appendChild(iconDiv);
        li.appendChild(bodyDiv);
        auditList.appendChild(li);
      }
    } else {
      auditSection.classList.add("hidden");
    }

    renderTrail(result?.evidence_trail);
  }

  // ─── EVIDENCE TRAIL (Stage 4) ───
  // Each backend signal becomes one row the user can read without
  // interpreting a raw score. A degraded check (status !== "ok") is
  // shown as degraded — never hidden — because "unknown" must not read
  // as "safe".

  const TRAIL_SOURCE_NAMES = {
    client_ml:        "On-device ML",
    threat_feeds:      "Threat Feeds",
    domain_age:       "Domain Age (WHOIS)",
    cert_age:         "Certificate Age (CT Logs)",
    dns_asn:          "DNS & Hosting",
    redirect_chain:   "Redirect Chain",
  };

  const TRAIL_ICONS = {
    client_ml:        "🧠",
    threat_feeds:      "📡",
    domain_age:       "🗓️",
    cert_age:         "🔒",
    dns_asn:          "🌐",
    redirect_chain:   "↪️",
  };

  function renderTrail(trail) {
    if (!Array.isArray(trail) || trail.length === 0) {
      trailSection.classList.add("hidden");
      return;
    }

    trailSection.classList.remove("hidden");
    trailList.innerHTML = "";

    for (const rec of trail) {
      if (!rec || typeof rec !== "object") continue;

      const li = document.createElement("li");
      const status = rec.status || "ok";

      // Row severity: a weighted contribution is the row's own risk,
      // independent of the page verdict.
      const weight = Number(rec.weight) || 0;
      li.className = `trail-item ${status !== "ok" ? "degraded" : weight >= 0.35 ? "fail" : weight > 0 ? "warn" : "pass"}`;

      const iconDiv = document.createElement("div");
      iconDiv.className = "trail-icon";
      iconDiv.textContent = TRAIL_ICONS[rec.signal] || "🔍";

      const bodyDiv = document.createElement("div");
      bodyDiv.className = "trail-body";

      const titleEl = document.createElement("div");
      titleEl.className = "trail-title";
      titleEl.textContent = TRAIL_SOURCE_NAMES[rec.signal] || rec.signal;

      const descEl = document.createElement("div");
      descEl.className = "trail-desc";
      descEl.textContent = rec.human_readable || "No detail available";

      bodyDiv.appendChild(titleEl);
      bodyDiv.appendChild(descEl);

      // Degraded badge — the fail-visible contract, in the UI
      if (status !== "ok") {
        const badge = document.createElement("span");
        badge.className = "trail-badge degraded";
        badge.textContent = status === "timeout" ? "Timed out" : "Unavailable";
        bodyDiv.appendChild(badge);
      } else if (weight >= 0.35) {
        const badge = document.createElement("span");
        badge.className = "trail-badge fail";
        badge.textContent = "High impact";
        bodyDiv.appendChild(badge);
      } else if (weight > 0) {
        const badge = document.createElement("span");
        badge.className = "trail-badge warn";
        badge.textContent = "Contributed";
        bodyDiv.appendChild(badge);
      }

      li.appendChild(iconDiv);
      li.appendChild(bodyDiv);
      trailList.appendChild(li);
    }
  }

  /**
   * Determine the audit item class based on verdict.
   */
  function getAuditClass(verdict) {
    switch (verdict) {
      case "safe":       return "pass";
      case "suspicious": return "warn";
      case "phishing":   return "fail";
      default:           return "";
    }
  }

  /**
   * Determine the icon for each audit item.
   */
  function getAuditIcon(verdict) {
    switch (verdict) {
      case "safe":       return "✓";
      case "suspicious": return "⚡";
      case "phishing":   return "✕";
      default:           return "?";
    }
  }

  /**
   * Extract a short title from a reason string.
   * If the reason contains a colon, split on the first one.
   */
  function extractTitle(reason) {
    if (reason.includes(":")) {
      return reason.split(":")[0].trim();
    }
    // Handle standard reasons without colons
    if (reason.includes("phishing patterns")) return "Malicious Pattern";
    if (reason.includes("IP address")) return "IP Hosting";
    if (reason.includes("HTTPS")) return "Insecure Protocol";
    if (reason.includes("TLD")) return "Risk TLD";
    if (reason.includes("subdomains")) return "URL Structure";
    
    return reason.length > 35 ? reason.substring(0, 35) + "…" : reason;
  }

  function extractDesc(reason) {
    if (reason.includes(":")) {
      return reason.split(":").slice(1).join(":").trim();
    }
    return reason; // Use the full reason as description if no colon
  }
});
