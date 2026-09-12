"""
PhishGuard ML Pipeline v4.1 — Configuration
Central source of truth for all constants, paths, and feature definitions.

CRITICAL: The 30 feature names MUST match service-worker.js exactly.
"""

from pathlib import Path

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Paths — platform-aware
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PROJECT_ROOT = Path(__file__).parent
DATA_DIR = PROJECT_ROOT / "datasets"
SYNTH_DIR = PROJECT_ROOT / "synthetic"
PREPARED_DIR = PROJECT_ROOT / "prepared"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"

# Auto-detect extension path
_POSSIBLE_EXTENSION_PATHS = [
    PROJECT_ROOT.parent / "extension",
    Path("D:/innovation hackathon vit/phishing_detection/extension"),
    Path.home() / "phishing_detection" / "extension",
]

EXTENSION_DIR = None
for p in _POSSIBLE_EXTENSION_PATHS:
    if p.exists():
        EXTENSION_DIR = p
        break

EXTENSION_MODEL_PATH = (
    EXTENSION_DIR / "models" / "model.onnx" if EXTENSION_DIR else None
)
BACKEND_MODEL_DIR = PROJECT_ROOT.parent / "backend" / "app" / "models"

for d in [DATA_DIR, SYNTH_DIR, PREPARED_DIR, MODELS_DIR, REPORTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Feature Definition — 30 features matching service-worker.js
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NUM_FEATURES = 30

FEATURE_NAMES = [
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
]

assert len(FEATURE_NAMES) == NUM_FEATURES, (
    f"Feature count mismatch: {len(FEATURE_NAMES)} != {NUM_FEATURES}"
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Domain Knowledge
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHISH_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "account",
    "update", "secure", "banking", "confirm", "password",
    "suspend", "alert", "unusual", "restore", "unlock",
]

SUSPICIOUS_TLDS = {
    ".xyz", ".icu", ".top", ".tk", ".ml", ".ga", ".cf",
    ".gq", ".buzz", ".club", ".info", ".site", ".online",
    ".website", ".link", ".click", ".surf",
}

COMMON_TLDS = {
    ".com", ".org", ".net", ".edu", ".gov", ".io", ".co",
    ".us", ".uk", ".de", ".in", ".ac", ".au", ".ca", ".fr",
    ".jp", ".mil",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
}

TARGET_BRANDS = [
    "paypal", "google", "apple", "microsoft", "amazon",
    "netflix", "facebook", "instagram", "whatsapp", "chase",
    "wellsfargo", "bankofamerica", "citibank", "usps", "dhl",
    "fedex", "linkedin", "dropbox", "spotify", "steam",
    "ebay", "outlook", "office365", "icloud", "yahoo",
]

SUSPICIOUS_HOSTS = [
    "trycloudflare.com", "ngrok.io", "ngrok-free.app",
    "workers.dev", "pages.dev", "vercel.app",
    "netlify.app", "herokuapp.com", "glitch.me",
    "replit.dev", "github.io", "weebly.com",
    "wixsite.com", "000webhostapp.com", "firebaseapp.com",
]

LEGITIMATE_LOGIN_DOMAINS = [
    "accounts.google.com", "login.microsoftonline.com",
    "github.com", "gitlab.com", "id.apple.com",
    "facebook.com", "twitter.com", "x.com",
    "linkedin.com", "netflix.com", "spotify.com",
    "fast.com", "vtop.vit.ac.in", "vit.ac.in",
    "stackoverflow.com", "reddit.com",
]

REAL_LOGIN_PATHS = {
    "accounts.google.com": ["/signin", "/v3/signin", "/ServiceLogin"],
    "login.microsoftonline.com": ["/common/oauth2/v2.0/authorize"],
    "github.com": ["/login", "/session"],
    "facebook.com": ["/login", "/login.php"],
    "twitter.com": ["/i/flow/login"],
    "x.com": ["/i/flow/login"],
    "linkedin.com": ["/login", "/uas/login"],
    "netflix.com": ["/login", "/LoginHelp"],
    "vtop.vit.ac.in": ["/vtop/login"],
    "fast.com": ["/"],
    "spotify.com": ["/login"],
    "stackoverflow.com": ["/users/login"],
    "reddit.com": ["/login", "/account/login"],
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Training Hyperparameters
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RANDOM_STATE = 42
TEST_SIZE = 0.10
VAL_SIZE = 0.10
CALIBRATION_SIZE = 0.10
TARGET_FPR = 0.008

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Shipped operating point
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# The extension bands client scores at 0.35 (suspicious) / 0.65 (phishing)
# — service-worker.js STEP 4. Model selection and the evaluation gate
# measure at the threshold users actually get, never at a model-internal
# optimum. evaluate.py reads this so there is one source of truth.
SHIPPED_SUSPICIOUS_THRESHOLD = 0.35
SHIPPED_PHISHING_THRESHOLD = 0.65
