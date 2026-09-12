"""
PhishGuard ML v4.1 — Evaluation
Per-class evaluation, known-URL verification, and comprehensive reporting.

Stage 2: Evaluation gate
  - Evaluates at the SHIPPED operating point (thresholds 0.35 / 0.65)
    not the model's internal optimal_threshold — because that is what
    users actually get.
  - Loads baseline metrics from evaluation_report.json (if present).
  - Writes pass: true/false into the report.
  - Exits non-zero on FPR regression, blocking deployment.
"""

import json
import sys
import numpy as np
import onnxruntime as ort
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score,
)
from config import (
    PREPARED_DIR, MODELS_DIR, REPORTS_DIR,
    NUM_FEATURES, FEATURE_NAMES,
    SHIPPED_SUSPICIOUS_THRESHOLD, SHIPPED_PHISHING_THRESHOLD,
)
from feature_extractor import extract_features_array, parse_onnx_probabilities

# FPR ceiling: if we exceed this relative to baseline the gate blocks deploy.
FPR_REGRESSION_TOLERANCE = 0.001  # allow ≤ 0.1 pp degradation

# ── Shipped whitelist (extracted from service-worker.js — do not hand-edit) ─
# The golden set must measure the operating point users actually get:
# model + shipped whitelist, not the model in isolation. The extension
# whitelists these domains before inference ever runs, so scoring them
# raw-model-only measures a system nobody ships.
# Regenerate with: python scripts/extract_whitelist.py
from shipped_whitelist import is_whitelisted


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Known-URL Verification Suite
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

KNOWN_SAFE = [
    ("https://www.google.com/", "Google"),
    ("https://fast.com/", "Fast.com (Netflix)"),
    ("https://vtop.vit.ac.in/vtop/login", "VIT VTop"),
    ("https://github.com/login", "GitHub Login"),
    ("https://accounts.google.com/signin", "Google Sign-in"),
    ("https://www.amazon.com/", "Amazon"),
    ("https://stackoverflow.com/questions", "Stack Overflow"),
    ("https://login.microsoftonline.com/common/oauth2", "Microsoft Login"),
]

KNOWN_PHISHING = [
    ("http://g00gle-login.tk/verify", "Typosquatting Google"),
    ("http://45.67.89.123/login.php", "IP-based phishing"),
    ("https://paypal-verify.secure-login.xyz/account", "Subdomain abuse"),
    ("https://secure-bank.com@evil.xyz/login", "@ trick"),
    ("https://amaz0n-secure.buzz/verify", "Brand impersonation"),
    ("http://192.0.2.1:8080/signin", "Public IP phishing"),
]


def evaluate() -> None:
    """Run full evaluation suite and enforce the FPR gate.

    Exits non-zero if FPR regresses relative to the incumbent model.
    This makes the function safe to call from CI and from run_pipeline.py.
    """
    print("=" * 60)
    print("PHISHGUARD ML v4.1 — EVALUATION")
    print("=" * 60)

    # Load test data
    X_test = np.load(PREPARED_DIR / "X_test.npy")
    y_test = np.load(PREPARED_DIR / "y_test.npy")
    src_test = np.load(PREPARED_DIR / "src_test.npy", allow_pickle=True)

    # The split basis identifies which prepared/ generation the test set
    # came from — FPR is only comparable run-to-run within the same basis.
    with open(PREPARED_DIR / "metadata.json") as f:
        prepared_meta = json.load(f)
    split_basis = str(prepared_meta.get("split_strategy", "unknown"))

    # Load model
    model_path = MODELS_DIR / "phishing_model_v4.onnx"
    if not model_path.exists():
        model_path = MODELS_DIR / "phishing_model_v4_raw.onnx"
        if not model_path.exists():
            print("✗ No model found! Run train_model.py first.")
            sys.exit(1)

    session = ort.InferenceSession(str(model_path))
    print(f"Model: {model_path.name}")
    print(f"Input: {session.get_inputs()[0].name} {session.get_inputs()[0].shape}")

    # ── Load incumbent baseline (may not exist on first run) ──────────────
    # The FPR comparison is only valid when both runs evaluated on the
    # same split basis. When prepare_data.py changes the split strategy
    # (e.g. Fix 19's domain-disjoint splits), the test set itself changes
    # and the incumbent's FPR is not comparable — comparing across bases
    # would false-block an honest model or false-pass a regression.
    incumbent_report_path = REPORTS_DIR / "evaluation_report.json"
    incumbent_fpr: float | None = None
    if incumbent_report_path.exists():
        with open(incumbent_report_path) as f:
            incumbent = json.load(f)
        incumbent_basis = incumbent.get("split_basis")
        if incumbent_basis != split_basis:
            print(f"  Incumbent split basis differs ({incumbent_basis!r} vs "
                  f"{split_basis!r}) — FPR baseline reset; not comparable.")
        # Only compare if the previous run passed its own gate
        elif incumbent.get("pass", False):
            incumbent_fpr = incumbent.get("shipped_fpr")

    # ── Evaluate at SHIPPED operating point ───────────────────────────────
    # We use the threshold the extension actually ships (0.35 suspicious /
    # 0.65 hard-block), NOT the model's internal optimal_threshold.
    # The README and AUDIT both flag that the model reports optimal at 0.798
    # but the extension uses 0.35 — we measure what users see.
    shipped_threshold = SHIPPED_SUSPICIOUS_THRESHOLD

    print(f"\n{'─' * 60}")
    print(f"TEST SET EVALUATION  (shipped threshold: {shipped_threshold})")
    print(f"{'─' * 60}")

    y_prob = parse_onnx_probabilities(session, X_test)
    y_pred = (y_prob >= shipped_threshold).astype(int)

    from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

    print(classification_report(
        y_test, y_pred,
        target_names=["Legitimate", "Phishing"], digits=4,
    ))

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    shipped_fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    shipped_fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    shipped_auc = float(roc_auc_score(y_test, y_prob))

    print(f"  TN={tn:>5}  FP={fp:>5}")
    print(f"  FN={fn:>5}  TP={tp:>5}")
    print(f"\n  Shipped FPR: {shipped_fpr:.4f} ({shipped_fpr * 100:.2f}%)")
    print(f"  Shipped FNR: {shipped_fnr:.4f} ({shipped_fnr * 100:.2f}%)")
    print(f"  ROC-AUC:     {shipped_auc:.4f}")

    # Per-source evaluation
    print(f"\n{'─' * 60}")
    print("PER-SOURCE ACCURACY")
    print(f"{'─' * 60}")

    unique_sources = np.unique(src_test)
    for source in sorted(unique_sources):
        mask = src_test == source
        if mask.sum() < 5:
            continue
        src_pred = y_pred[mask]
        src_true = y_test[mask]
        acc = float(np.mean(src_pred == src_true))
        count = int(mask.sum())
        label = "phish" if src_true.mean() > 0.5 else "legit"
        print(f"  {source:<25} {acc:.4f} ({count:>5} samples, {label})")

    # ── Known-URL golden set verification ─────────────────────────────────
    print(f"\n{'─' * 60}")
    print("KNOWN-URL GOLDEN SET VERIFICATION")
    print(f"{'─' * 60}")

    known_url_pass = True

    print("\n  Known SAFE URLs  (shipped operating point: model + whitelist):")
    for url, desc in KNOWN_SAFE:
        features = extract_features_array(url)
        if features is None:
            print(f"    ✗ {desc}: parse failed")
            known_url_pass = False
            continue
        X = np.array([features], dtype=np.float32)
        prob = float(parse_onnx_probabilities(session, X)[0])
        # The extension whitelists before inference — the operating point
        # users get is model + whitelist. A whitelisted URL with a high
        # raw score still passes but is worth watching: the whitelist is
        # doing work the model should do.
        if is_whitelisted(url):
            pred = "SAFE (whitelisted)"
        else:
            pred = "SAFE" if prob < shipped_threshold else "PHISHING"
        icon = "✓" if pred.startswith("SAFE") else "✗"
        print(f"    {icon} {desc:<30} → {pred} ({prob:.4f})")
        if not pred.startswith("SAFE"):
            known_url_pass = False

    print("\n  Known PHISHING URLs:")
    for url, desc in KNOWN_PHISHING:
        features = extract_features_array(url)
        if features is None:
            print(f"    ✗ {desc}: parse failed")
            known_url_pass = False
            continue
        X = np.array([features], dtype=np.float32)
        prob = float(parse_onnx_probabilities(session, X)[0])
        pred = "PHISHING" if prob >= shipped_threshold else "SAFE"
        icon = "✓" if pred == "PHISHING" else "✗"
        print(f"    {icon} {desc:<30} → {pred} ({prob:.4f})")
        if pred != "PHISHING":
            known_url_pass = False

    print(f"\n{'=' * 60}")
    if known_url_pass:
        print("✓ ALL GOLDEN-SET CHECKS PASSED")
    else:
        print("✗ GOLDEN-SET CHECKS FAILED — some known URLs misclassified")
    print(f"{'=' * 60}")

    # ── FPR gate ─────────────────────────────────────────────────────────
    print(f"\n{'─' * 60}")
    print("FPR REGRESSION GATE")
    print(f"{'─' * 60}")

    gate_pass = True
    gate_reasons: list[str] = []

    if not known_url_pass:
        gate_pass = False
        gate_reasons.append("Golden-set verification failed")

    if incumbent_fpr is not None:
        ceiling = incumbent_fpr + FPR_REGRESSION_TOLERANCE
        print(f"  Incumbent FPR : {incumbent_fpr:.4f}")
        print(f"  Candidate FPR : {shipped_fpr:.4f}")
        print(f"  Ceiling       : {ceiling:.4f}  (tolerance +{FPR_REGRESSION_TOLERANCE})")
        if shipped_fpr > ceiling:
            gate_pass = False
            gate_reasons.append(
                f"FPR {shipped_fpr:.4f} exceeds incumbent {incumbent_fpr:.4f} "
                f"+ tolerance {FPR_REGRESSION_TOLERANCE}"
            )
        else:
            delta = shipped_fpr - incumbent_fpr
            sign = "+" if delta >= 0 else ""
            print(f"  Delta         : {sign}{delta:.4f}  ✓ within tolerance")
    else:
        print("  No passing incumbent found — first-run baseline being established.")

    print()
    if gate_pass:
        print("✓ GATE PASSED — safe to deploy")
    else:
        print("✗ GATE FAILED — deployment blocked")
        for reason in gate_reasons:
            print(f"   → {reason}")
    print(f"{'=' * 60}")

    # ── Save evaluation report ─────────────────────────────────────────────
    eval_report = {
        "shipped_threshold": shipped_threshold,
        "shipped_fpr":       shipped_fpr,
        "shipped_fnr":       shipped_fnr,
        "shipped_auc":       shipped_auc,
        "test_accuracy":     float(np.mean(y_pred == y_test)),
        "known_url_pass":    known_url_pass,
        "pass":              gate_pass,
        "gate_reasons":      gate_reasons,
        "split_basis":       split_basis,
    }
    with open(REPORTS_DIR / "evaluation_report.json", "w") as f:
        json.dump(eval_report, f, indent=2)
    print(f"\n✓ Report saved → {REPORTS_DIR / 'evaluation_report.json'}")

    # ── Exit non-zero on gate failure ─────────────────────────────────────
    if not gate_pass:
        sys.exit(1)


if __name__ == "__main__":
    evaluate()
