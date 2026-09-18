/**
 * PhishGuard — Options Page Script
 * Handles loading, displaying, and saving user preferences.
 * All data stays in chrome.storage.local (never transmitted).
 */

document.addEventListener("DOMContentLoaded", async () => {
  await loadSettings();

  document.getElementById("btn-save").addEventListener("click", saveSettings);

  document.getElementById("btn-clear-cache").addEventListener("click", async () => {
    if (!confirm("Clear all cached scan results and statistics?\nThis cannot be undone.")) return;
    await chrome.storage.session.clear();
    await chrome.storage.local.set({
      stats: {
        totalScanned: 0,
        phishingBlocked: 0,
        suspiciousFlagged: 0,
        installDate: Date.now(),
        lastFeedUpdate: null,
      },
    });
    showStatus("Cache cleared successfully.");
  });

  document.getElementById("btn-export-data").addEventListener("click", async () => {
    const data = await chrome.storage.local.get(null);
    const blob = new Blob(
      [JSON.stringify(data, null, 2)],
      { type: "application/json" }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "phishguard-data-export.json";
    a.click();
    URL.revokeObjectURL(url);
    showStatus("Data exported.");
  });
});


async function loadSettings() {
  const { settings } = await chrome.storage.local.get("settings");
  if (!settings) return;

  document.getElementById("setting-auto-scan").checked =
    settings.autoScan !== false;
  document.getElementById("setting-show-overlay").checked =
    settings.showWarningOverlay !== false;
  document.getElementById("setting-backend-escalation").checked =
    settings.allowBackendEscalation !== false;
  document.getElementById("setting-backend-url").value =
    settings.backendUrl || "";
}


async function saveSettings() {
  const newSettings = {
    autoScan: document.getElementById("setting-auto-scan").checked,
    showWarningOverlay: document.getElementById("setting-show-overlay").checked,
    allowBackendEscalation: document.getElementById("setting-backend-escalation").checked,
    backendUrl: document.getElementById("setting-backend-url").value.trim(),
  };

  await chrome.storage.local.set({ settings: newSettings });
  showStatus("Settings saved successfully!");
}


function showStatus(message) {
  const el = document.getElementById("status-msg");
  el.textContent = message;
  el.style.display = "block";
  setTimeout(() => { el.style.display = "none"; }, 3000);
}
