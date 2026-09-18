"""
PhishGuard ML v4.1 — Evaluation
Per-class evaluation, known-URL verification, and comprehensive reporting.

Stage 2: Evaluation gate
  - Evaluates at the SHIPPED operating point (thresholds 0.35 / 0.65)
    not the model's internal optimal_threshold — because that is what
    users actually get.
  - Arms the FPR ceiling from fpr_baseline.json (written only by
    gate-PASSING runs), falling back to evaluation_report.json only
    when that run passed its own gate.
  - The baseline is comparable only within the same split basis AND
    the same prepared-data fingerprint — a data refresh resets it with
    a notice instead of false-blocking an honest model.
  - Verifies domain isolation on the artifacts evaluation consumes:
    zero eTLD+1 overlap between test and train/val/cal. The gate
    blocks if the split itself leaks, no matter what the metrics say.
  - Scores the 100-URL golden set per-URL with the raw model (no
    whitelist rescue): GOOD URLs must stay unflagged, BAD URLs must
    be flagged, at least 90% on each side — so class trade-offs and
    sony.com/hulu.com-style drift cannot hide behind blended metrics.
  - Writes pass: true/false into the report.
  - Exits non-zero on FPR regression, blocking deployment.
"""

import json
import sys
from pathlib import Path
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

# Real-world holdout set for the Phase 4.2 checks. Anchored to this file so
# they work from any cwd — CI runs `cd ml-retrain && python evaluate.py`
# but local runs may invoke it from the repo root.
HOLDOUT_PATH = Path(__file__).resolve().parent / "data" / "real_world_holdout" / "README.md"

# 100-URL golden set (50 GOOD + 50 BAD): adversarial families — typosquats,
# TLD abuse, credential-embedding hosts, tunneling hosts, IP literals.
# data/ is gitignored, so a fresh checkout has no golden_set.txt;
# _load_golden_urls() falls back to the URL constants in create_golden_set.py
# (the tracked artifact of record — it regenerates the file).
GOLDEN_SET_PATH = Path(__file__).resolve().parent / "data" / "golden_set.txt"

# Per-side pass bar: the model must clear 90% on BOTH sides, so it cannot
# buy one class at the expense of the other.
GOLDEN_SET_PASS_BAR = 0.90

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


def _load_golden_urls() -> tuple[list[str], list[str]]:
    """Return (good_urls, bad_urls) from the 100-URL golden set.

    Prefers data/golden_set.txt; when absent (data/ is gitignored, so a
    fresh CI checkout has none) falls back to the URL constants in
    create_golden_set.py — the tracked artifact of record that
    regenerates the file.
    """
    lines: list[str] = []
    if GOLDEN_SET_PATH.exists():
        with open(GOLDEN_SET_PATH, encoding="utf-8-sig") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
    if not lines:
        from create_golden_set import BAD_URLS, GOOD_URLS
        lines = [f"GOOD:{u}" for u in GOOD_URLS] + [f"BAD:{u}" for u in BAD_URLS]
    good, bad = [], []
    for ln in lines:
        tag, url = ln.split(":", 1)
        (good if tag == "GOOD" else bad).append(url.strip())
    return good, bad


def check_golden_set(session, threshold: float) -> dict:
    """Score every golden-set URL per-URL with the RAW model (no whitelist).

    GOOD passes when unflagged (prob < threshold); BAD passes when flagged
    (prob >= threshold) — the shipped suspicious threshold, the same
    operating point the 14-URL suite checks, but across the full
    adversarial coverage of the 100-URL set and WITHOUT whitelist rescue,
    so a model leaning on the whitelist cannot hide behind it.

    Returns counts, per-side rates, misses (for the report) and `pass`
    (True when BOTH sides clear GOLDEN_SET_PASS_BAR).
    """
    good_urls, bad_urls = _load_golden_urls()
    n_good, n_bad = len(good_urls), len(bad_urls)

    good_misses: list[tuple[str, float | None, str]] = []  # (url, prob, note)
    bad_misses: list[tuple[str, float | None]] = []       # (url, prob)

    for url in good_urls:
        features = extract_features_array(url)
        if features is None:
            good_misses.append((url, None, ""))
            continue
        prob = float(parse_onnx_probabilities(
            session, np.array([features], dtype=np.float32))[0])
        if prob >= threshold:
            note = " — whitelist-covered in production" if is_whitelisted(url) else ""
            good_misses.append((url, prob, note))

    for url in bad_urls:
        features = extract_features_array(url)
        if features is None:
            bad_misses.append((url, None))
            continue
        prob = float(parse_onnx_probabilities(
            session, np.array([features], dtype=np.float32))[0])
        if prob < threshold:
            bad_misses.append((url, prob))

    good_ok = n_good - len(good_misses)
    bad_ok = n_bad - len(bad_misses)
    good_rate = good_ok / n_good if n_good else 0.0
    bad_rate = bad_ok / n_bad if n_bad else 0.0
    golden_pass = (good_rate >= GOLDEN_SET_PASS_BAR
                   and bad_rate >= GOLDEN_SET_PASS_BAR)

    print(f"\n{'─' * 60}")
    print(f"GOLDEN SET VERIFICATION ({n_good + n_bad} URLs, raw model — no whitelist)")
    print(f"{'─' * 60}")
    print(f"  GOOD: {good_ok}/{n_good} unflagged ({good_rate:.1%}, bar ≥{GOLDEN_SET_PASS_BAR:.0%})")
    for url, prob, note in good_misses:
        prob_s = "parse failed" if prob is None else f"p={prob:.4f}"
        print(f"    ✗ {url:<48} {prob_s}{note}")
    print(f"  BAD:  {bad_ok}/{n_bad} flagged ({bad_rate:.1%}, bar ≥{GOLDEN_SET_PASS_BAR:.0%})")
    for url, prob in bad_misses:
        prob_s = "parse failed" if prob is None else f"p={prob:.4f}"
        print(f"    ✗ {url:<48} {prob_s}")
    accuracy = (good_ok + bad_ok) / (n_good + n_bad) if (n_good + n_bad) else 0.0
    print(f"  Golden accuracy: {accuracy:.1%}  ({good_ok} + {bad_ok} of {n_good + n_bad})")
    print("  Golden-set accuracy: PASS" if golden_pass else "  Golden-set accuracy: FAIL")

    return {
        "n_good": n_good, "n_bad": n_bad,
        "good_ok": good_ok, "bad_ok": bad_ok,
        "good_rate": good_rate, "bad_rate": bad_rate,
        "accuracy": accuracy,
        "good_misses": [{"url": u, "prob": p, "note": n} for u, p, n in good_misses],
        "bad_misses": [{"url": u, "prob": p} for u, p in bad_misses],
        "pass": golden_pass,
    }


def evaluate() -> bool:
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

    # The split basis + data fingerprint identify which prepared/
    # generation the test set came from — FPR is only comparable
    # run-to-run within the same generation.
    with open(PREPARED_DIR / "metadata.json", encoding="utf-8-sig") as f:
        prepared_meta = json.load(f)
    split_basis = str(prepared_meta.get("split_strategy", "unknown"))
    # The strategy string alone cannot see a dataset refresh: a
    # regenerated prepared/ tree under the same strategy is still a
    # different test set. Fingerprint the row counts + domain count so
    # the gate notices and resets the baseline instead of comparing
    # across test sets.
    split_fingerprint = (
        f"rows={prepared_meta.get('train_size')}/{prepared_meta.get('val_size')}"
        f"/{prepared_meta.get('cal_size')}/{prepared_meta.get('test_size')}"
        f";domains={prepared_meta.get('num_unique_domains')}"
    )

    # ── Domain isolation verification (leakage check on the split) ─────────
    # The split is domain-disjoint BY CONSTRUCTION (GroupShuffleSplit on
    # eTLD+1). Trust but verify: confirm zero eTLD+1 overlap between the
    # test groups and each of train/val/cal on the artifacts evaluation
    # actually consumes — so a regenerated or hand-edited prepared/ tree
    # can never silently reintroduce leakage.
    groups = {
        split: np.load(PREPARED_DIR / f"groups_{split}.npy", allow_pickle=True)
        for split in ("train", "val", "cal", "test")
    }
    test_domains = set(groups["test"].tolist())
    overlap = {
        split: test_domains & set(groups[split].tolist())
        for split in ("train", "val", "cal")
    }
    domain_isolated = all(len(domains) == 0 for domains in overlap.values())

    print(f"\n{'─' * 60}")
    print("DOMAIN ISOLATION VERIFICATION (leakage check)")
    print(f"{'─' * 60}")
    print(f"  Test set draws from {len(test_domains):,} unique eTLD+1 domains")
    for split in ("train", "val", "cal"):
        print(f"  Shared with {split + ':':<7} {len(overlap[split])} domains")
    if domain_isolated:
        print("  ✓ ZERO domain overlap — every test URL comes from a domain the model never saw")
    else:
        print("  ✗ DOMAIN OVERLAP DETECTED — split is NOT leakage-free")

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
    # Baseline-first: fpr_baseline.json is written ONLY by gate-passing
    # runs, so a failed run can never arm the next run's ceiling.
    # evaluation_report.json is the fallback, and only counts when that
    # run passed its own gate — a pass:false report must disarm the
    # comparison, not quietly move the bar.
    # The comparison is valid only when both runs evaluated on the SAME
    # test set: same split basis AND same prepared-data fingerprint.
    # When prepare_data.py regenerates the data — a new split strategy
    # OR a dataset refresh under an unchanged strategy string — the test
    # set changes and the incumbent's FPR is not comparable. Comparing
    # across generations would false-block an honest model or
    # false-pass a regression, so the baseline resets with a notice.
    incumbent_fpr: float | None = None
    incumbent_source: str | None = None
    for incumbent_path, incumbent_name in (
        (REPORTS_DIR / "fpr_baseline.json", "fpr_baseline.json"),
        (REPORTS_DIR / "evaluation_report.json", "evaluation_report.json"),
    ):
        if not incumbent_path.exists():
            continue
        try:
            with open(incumbent_path, encoding="utf-8-sig") as f:
                incumbent = json.load(f)
        except (OSError, ValueError):
            continue  # unreadable incumbent — treat as absent; gate still runs
        if incumbent.get("split_basis") != split_basis:
            print(f"  {incumbent_name}: split basis differs "
                  f"({incumbent.get('split_basis')!r} vs {split_basis!r}) — "
                  f"FPR baseline reset; not comparable.")
            continue
        if incumbent.get("split_fingerprint") != split_fingerprint:
            print(f"  {incumbent_name}: prepared data differs "
                  f"({incumbent.get('split_fingerprint')!r} vs "
                  f"{split_fingerprint!r}) — FPR baseline reset; not comparable.")
            continue
        # Only compare if the previous run passed its own gate
        if incumbent.get("pass", False):
            incumbent_fpr = incumbent.get("shipped_fpr")
            incumbent_source = incumbent_name
            break

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

    # ── Per-domain error concentration ────────────────────────────────────
    # On a domain-disjoint test set every error is a generalization miss on
    # an UNSEEN domain. Multiple errors from one eTLD+1 point at a lexical
    # pattern the model misreads systematically; single errors are noise.
    print(f"\n{'─' * 60}")
    print("PER-DOMAIN ERROR CONCENTRATION (test errors by eTLD+1)")
    print(f"{'─' * 60}")

    error_idx = np.where(y_pred != y_test)[0]
    error_domains: dict[str, int] = {}
    for i in error_idx:
        domain = str(groups["test"][i])
        error_domains[domain] = error_domains.get(domain, 0) + 1
    multi_error = {d: c for d, c in error_domains.items() if c > 1}
    print(f"  {len(error_idx)} errors across {len(error_domains)} distinct domains "
          f"({len(multi_error)} domain(s) with more than one error)")
    if multi_error:
        for domain, count in sorted(multi_error.items(), key=lambda kv: -kv[1])[:5]:
            print(f"    {domain:<40} {count} errors")
    else:
        print("  (no domain contributed more than one error — every miss is an isolated gap)")

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
        print("✓ ALL KNOWN-URL CHECKS PASSED")
    else:
        print("✗ KNOWN-URL CHECKS FAILED — some known URLs misclassified")
    print(f"{'=' * 60}")

    # ── Golden set verification: 100 URLs, raw model, per-URL ─────────────
    # The 14-URL suite above measures the shipped operating point
    # (model + whitelist) on the TRD §11 adversarials. This one measures
    # the raw model across the full adversarial coverage with no
    # whitelist rescue, per-URL so regressions name their URL.
    golden = check_golden_set(session, shipped_threshold)

    # ── FPR gate ─────────────────────────────────────────────────────────
    print(f"\n{'─' * 60}")
    print("FPR REGRESSION GATE")
    print(f"{'─' * 60}")

    gate_pass = True
    gate_reasons: list[str] = []

    if not known_url_pass:
        gate_pass = False
        gate_reasons.append("Known-URL verification failed")

    if not golden["pass"]:
        gate_pass = False
        gate_reasons.append(
            f"Golden-set accuracy failed — GOOD {golden['good_ok']}/{golden['n_good']} "
            f"unflagged, BAD {golden['bad_ok']}/{golden['n_bad']} flagged "
            f"(bar {GOLDEN_SET_PASS_BAR:.0%} per side)"
        )

    if not domain_isolated:
        gate_pass = False
        gate_reasons.append("Domain isolation violated — test set shares domains with train/val/cal")

    if incumbent_fpr is not None:
        ceiling = incumbent_fpr + FPR_REGRESSION_TOLERANCE
        print(f"  Incumbent FPR : {incumbent_fpr:.4f}  (from {incumbent_source})")
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
        "golden_set": {
            "n_good":      golden["n_good"],
            "n_bad":       golden["n_bad"],
            "good_ok":     golden["good_ok"],
            "bad_ok":      golden["bad_ok"],
            "good_rate":   golden["good_rate"],
            "bad_rate":    golden["bad_rate"],
            "accuracy":    golden["accuracy"],
            "good_misses": golden["good_misses"],
            "bad_misses":  golden["bad_misses"],
            "pass":        golden["pass"],
        },
        "pass":              gate_pass,
        "gate_reasons":      gate_reasons,
        "split_basis":       split_basis,
        "split_fingerprint": split_fingerprint,
        "domain_isolation": {
            "test_domains":      len(test_domains),
            "shared_with_train": len(overlap["train"]),
            "shared_with_val":   len(overlap["val"]),
            "shared_with_cal":   len(overlap["cal"]),
            "isolated":          domain_isolated,
        },
        "test_error_domains": {
            "total_errors":        int(len(error_idx)),
            "distinct_domains":    len(error_domains),
            "multi_error_domains": len(multi_error),
        },
    }
    with open(REPORTS_DIR / "evaluation_report.json", "w", encoding="utf-8") as f:
        json.dump(eval_report, f, indent=2)
    print(f"\n✓ Report saved → {REPORTS_DIR / 'evaluation_report.json'}")

    # ── Persist the FPR baseline on gate-pass only ─────────────────────────
    # The next run arms its ceiling from this file. Writing only on pass
    # means a failing run can never lower the bar for its successor.
    if gate_pass:
        fpr_baseline = {
            "shipped_fpr":       shipped_fpr,
            "split_basis":       split_basis,
            "split_fingerprint": split_fingerprint,
            "pass":              True,
            "note": "last gate-passing FPR; the next run's FPR gate arms its ceiling from this file",
        }
        with open(REPORTS_DIR / "fpr_baseline.json", "w", encoding="utf-8") as f:
            json.dump(fpr_baseline, f, indent=2)
        print(f"✓ FPR baseline saved → {REPORTS_DIR / 'fpr_baseline.json'}")

    # ── Exit non-zero on gate failure ─────────────────────────────────────
    return gate_pass

def evaluate_on_holdout(model_path):
    import os
    import numpy as np
    import joblib
    from feature_extractor import extract_features_array
    
    holdout_path = HOLDOUT_PATH
    with open(holdout_path, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    good_urls = [line[5:] for line in lines if line.startswith('GOOD:')]
    bad_urls = [line[4:] for line in lines if line.startswith('BAD:')]
    
    if not good_urls or not bad_urls:
        raise ValueError("Holdout set is empty or malformed")
    
    model = joblib.load(model_path)
    
    def get_preds(urls):
        features_list = [extract_features_array(u) for u in urls]
        features_list = [f for f in features_list if f is not None]
        if not features_list:
            return np.array([])
        X = np.array(features_list, dtype=np.float32)
        return model.predict(X)
    
    good_preds = get_preds(good_urls)
    bad_preds = get_preds(bad_urls)
    
    good_acc = np.mean(good_preds == 0) if len(good_preds) > 0 else 0.0
    bad_acc = np.mean(bad_preds == 1) if len(bad_preds) > 0 else 0.0
    overall_acc = (good_acc + bad_acc) / 2
    
    return {
        "holdout_good_acc": good_acc,
        "holdout_bad_acc": bad_acc,
        "holdout_overall": overall_acc
    }

def check_synth_leakage(model_path):
    import joblib
    import numpy as np
    import os
    import pandas as pd
    model = joblib.load(model_path)
    
    from synth_generator import generate_legitimate_ip, generate_phishing_ip
    synth_urls = [generate_legitimate_ip() for _ in range(500)] + \
                 [generate_phishing_ip() for _ in range(500)]
                     
    with open(HOLDOUT_PATH, 'r', encoding='utf-8') as f:
        real_urls = [line[5:].strip() for line in f if line.startswith('GOOD:')] + \
                    [line[4:].strip() for line in f if line.startswith('BAD:')]
    
    from feature_extractor import extract_features_array
    X_synth = np.array([extract_features_array(u) for u in synth_urls if extract_features_array(u) is not None])
    X_real = np.array([extract_features_array(u) for u in real_urls if extract_features_array(u) is not None])
    
    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
    elif hasattr(model, 'coef_'):
        importances = np.abs(model.coef_[0])
    else:
        return 0.0
    
    synth_var = np.var(X_synth, axis=0)
    real_var = np.var(X_real, axis=0)
    
    # A feature is "synthetic-only" if it has variance in synthetic data but essentially zero variance in real data
    synth_only_factor = np.where((real_var < 1e-4) & (synth_var > 1e-4), 1.0, 0.0)
    
    leakage_score = np.average(synth_only_factor, weights=importances)
    return leakage_score * 100


if __name__ == "__main__":
    passed = evaluate()
    
    import os
    import sys
    print("\n=== REAL-WORLD HOLDOUT EVALUATION (SYNTHETIC-NEVER-SEEN) ===")
    for variant in ['baseline', 'standard', 'augmented']:
        model_path = MODELS_DIR / f'{variant}_model.onnx'
        if os.path.exists(model_path):
            results = evaluate_on_holdout(model_path)
            print(f"{variant.upper():<10} | Holdout Acc: {results['holdout_overall']:.1%} "
                  f"(Good: {results['holdout_good_acc']:.1%}, Bad: {results['holdout_bad_acc']:.1%})")
        else:
            print(f"{variant.upper():<10} | Model not found")

    print("\n=== SYNTHETIC FEATURE LEAKAGE CHECK ===")
    for variant in ['baseline', 'augmented']:
        model_path = MODELS_DIR / f'{variant}_model.onnx'
        if os.path.exists(model_path):
            leakage = check_synth_leakage(model_path)
            print(f"{variant.upper():<10} | Synthetic leakage: {leakage:.1f}% (<5.0% = SAFE)")
        else:
            print(f"{variant.upper():<10} | Model not found — skipping leakage check")

    sys.exit(0 if passed else 1)
