"""
PhishGuard ML v4.1 — SHAP Model Explanation
Explains the production model (calibrated RandomForest) with TreeExplainer.

Only ONNX artifacts are persisted, so this script:
  1. Deterministically retrains the RF (random_state=42, fixed prepared splits)
     and calibrates it exactly as train_model.py does.
  2. Verifies parity against the shipped ONNX model — SHAP output is only
     trusted if the reproduced model matches production.
  3. Global SHAP: beeswarm + bar (top features).
  4. Per-attack-cohort importance heatmap (typosquatting, ip_phishing, ...).
  5. Waterfall plots for every golden-set URL misclassified at the SHIPPED
     threshold (0.35) — the URLs currently failing the evaluation gate.

Outputs → reports/shap/*.png + reports/shap/shap_summary.json
"""

import json
import sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import shap

from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator

from config import (
    PREPARED_DIR, MODELS_DIR, REPORTS_DIR,
    FEATURE_NAMES, RANDOM_STATE,
)

# Same shipped threshold as evaluate.py — the boundary users actually see.
SHIPPED_SUSPICIOUS_THRESHOLD = 0.35

# Per-source cap for the SHAP subsample (keeps cohorts balanced, stays fast).
COHORT_CAP = 400

OUT_DIR = REPORTS_DIR / "shap"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Golden set copied from evaluate.py (single source of truth for the gate).
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


def reproduce_production_model() -> dict:
    """Retrain + calibrate exactly as train_model.py (deterministic)."""
    data = {}
    for name in ["X_train", "y_train", "X_cal", "y_cal", "X_test", "y_test", "src_test"]:
        data[name] = np.load(PREPARED_DIR / f"{name}.npy", allow_pickle=True)
    print(f"Loaded splits: train={data['X_train'].shape} cal={data['X_cal'].shape} "
          f"test={data['X_test'].shape}")

    print("Retraining RandomForest (n_estimators=100, max_depth=15, "
          "min_samples_leaf=2, balanced, random_state=42)...")
    rf = RandomForestClassifier(
        n_estimators=100, max_depth=15, min_samples_leaf=2,
        class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1,
    )
    rf.fit(data["X_train"], data["y_train"])

    print("Calibrating on separate calibration set (FrozenEstimator, sigmoid)...")
    calibrated = CalibratedClassifierCV(FrozenEstimator(rf))
    calibrated.fit(data["X_cal"], data["y_cal"])

    data["rf"] = rf
    data["calibrated"] = calibrated
    return data


def verify_onnx_parity(data: dict) -> dict:
    """Compare reproduced model against the shipped ONNX model.

    SHAP values are only meaningful if they explain the same decision
    function production uses, so this must agree before we proceed.
    """
    import onnxruntime as ort
    from feature_extractor import parse_onnx_probabilities

    model_path = MODELS_DIR / "phishing_model_v4.onnx"
    if not model_path.exists():
        model_path = MODELS_DIR / "phishing_model_v4_raw.onnx"
    session = ort.InferenceSession(str(model_path))

    X_test = data["X_test"].astype(np.float32)
    onnx_prob = parse_onnx_probabilities(session, X_test)
    skl_prob = data["calibrated"].predict_proba(X_test)[:, 1]

    max_diff = float(np.max(np.abs(onnx_prob - skl_prob)))
    agree = float(np.mean(
        (onnx_prob >= SHIPPED_SUSPICIOUS_THRESHOLD)
        == (skl_prob >= SHIPPED_SUSPICIOUS_THRESHOLD)
    ))

    print(f"\nParity vs {model_path.name}:")
    print(f"  max |ΔP(phish)|      : {max_diff:.6f}")
    print(f"  decision agreement   : {agree:.4%} (at shipped threshold 0.35)")

    parity = {"onnx_model": model_path.name, "max_prob_diff": max_diff,
              "decision_agreement": agree}
    if agree < 0.99:
        print("  ✗ Parity FAILED — reproduced model does not match production.")
        print("    SHAP values would explain a different decision function. Aborting.")
        sys.exit(2)
    print("  ✓ Parity OK — safe to explain the reproduced model with SHAP.")
    return parity


def build_cohort_subsample(data: dict) -> pd.DataFrame:
    """Balanced-per-source subsample of the test set for SHAP computation."""
    X_test, src_test = data["X_test"], data["src_test"]
    rng = np.random.default_rng(RANDOM_STATE)
    chosen = []
    for source in np.unique(src_test):
        idx = np.where(src_test == source)[0]
        if len(idx) > COHORT_CAP:
            idx = rng.choice(idx, COHORT_CAP, replace=False)
        chosen.extend(idx)
    chosen = np.array(sorted(chosen))

    df = pd.DataFrame(X_test[chosen], columns=FEATURE_NAMES)
    df["__src"] = src_test[chosen]
    df["__y"] = data["y_test"][chosen]
    print(f"\nSHAP subsample: {len(df)} rows "
          f"({df['__src'].nunique()} cohorts, cap {COHORT_CAP}/cohort)")
    return df


def detect_output_space(explainer, X_check: pd.DataFrame, rf) -> str:
    """Determine whether TreeExplainer values sum to P(phish) or its log-odds.

    Uses SHAP's additivity property on a small check batch.
    """
    sv = explainer(X_check)
    vals = sv.values
    if vals.ndim == 3:  # binary classifier: [n, features, 2] → phishing class
        vals = vals[..., 1]
    base = np.atleast_1d(sv.base_values)
    if base.ndim == 2 and base.shape[-1] == 2:
        base = base[..., 1]

    sums = base[0] + vals.sum(axis=1) if base.size == 1 else base + vals.sum(axis=1)
    p = rf.predict_proba(X_check.values)[:, 1]
    p = np.clip(p, 1e-9, 1 - 1e-9)
    logodds = np.log(p / (1 - p))

    err_prob = np.max(np.abs(sums - p))
    err_logodds = np.max(np.abs(sums - logodds))
    space = "probability" if err_prob <= err_logodds else "log_odds"
    print(f"\nAdditivity check: err(prob)={err_prob:.4f}  err(log-odds)={err_logodds:.4f}")
    print(f"→ TreeExplainer explains the RandomForest in {space} space.")
    return space


def shap_phishing_values(sv):
    """Extract phishing-class SHAP values + base from an Explanation."""
    vals = sv.values
    if vals.ndim == 3:
        vals = vals[..., 1]
    base = sv.base_values
    if isinstance(base, np.ndarray) and base.ndim == 2 and base.shape[-1] == 2:
        base = base[..., 1]
    return vals, base


def to_phishing_explanation(sv, X) -> shap.Explanation:
    """2D Explanation for the phishing class (beeswarm/bar/waterfall reject 3D)."""
    vals, base = shap_phishing_values(sv)
    base = np.asarray(base) if base is not None else np.zeros(len(vals))
    if base.ndim == 0:
        base = np.full(len(vals), float(base))
    return shap.Explanation(
        values=vals, base_values=base,
        data=np.asarray(X, dtype=np.float32),
        feature_names=FEATURE_NAMES,
    )


def plot_global(sv_sub, top_features: list[str]):
    """Beeswarm + bar of global feature importance."""
    ev = to_phishing_explanation(sv_sub, sv_sub.data)
    shap.plots.beeswarm(ev, max_display=15, show=False)
    plt.gcf().set_size_inches(9, 7)
    plt.savefig(OUT_DIR / "01_beeswarm.png", dpi=150, bbox_inches="tight")
    plt.close()

    shap.plots.bar(ev, max_display=15, show=False)
    plt.gcf().set_size_inches(9, 7)
    plt.savefig(OUT_DIR / "02_bar.png", dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved 01_beeswarm.png, 02_bar.png (top: {', '.join(top_features[:5])})")


def plot_cohort_heatmap(vals, srcs, feature_names):
    """Row-normalised mean |SHAP| per cohort × top-15 features."""
    mean_abs = {}
    for src in sorted(np.unique(srcs)):
        mask = srcs == src
        mean_abs[src] = np.abs(vals[mask.values if hasattr(mask, 'values') else mask]).mean(axis=0)
    overall = np.abs(vals).mean(axis=0)
    top_idx = np.argsort(overall)[::-1][:15]

    mat = np.vstack([mean_abs[src][top_idx] for src in mean_abs])
    row_max = mat.max(axis=1, keepdims=True)
    row_max[row_max == 0] = 1.0
    norm = mat / row_max  # pattern per cohort, 0..1

    fig, ax = plt.subplots(figsize=(11, 7))
    im = ax.imshow(norm, aspect="auto", cmap="Reds", vmin=0, vmax=1)
    ax.set_xticks(range(len(top_idx)))
    ax.set_xticklabels([feature_names[i] for i in top_idx], rotation=45, ha="right", fontsize=8)
    ax.set_yticks(range(len(mean_abs)))
    ax.set_yticklabels(list(mean_abs.keys()), fontsize=9)
    for i in range(mat.shape[0]):
        for j in range(mat.shape[1]):
            ax.text(j, i, f"{mat[i, j]:.3f}", ha="center", va="center", fontsize=6.5,
                    color="white" if norm[i, j] > 0.55 else "black")
    ax.set_title("Mean |SHAP| per cohort (row-normalised; raw values annotated)")
    fig.colorbar(im, ax=ax, shrink=0.8, label="relative importance within cohort")
    fig.tight_layout()
    fig.savefig(OUT_DIR / "03_cohort_heatmap.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  Saved 03_cohort_heatmap.png")


def explain_golden_set(explainer, calibrated, space: str) -> list[dict]:
    """Waterfall + table for every golden-set URL misclassified at 0.35."""
    from feature_extractor import extract

    rows, waterfalls = [], []
    for url, desc in KNOWN_SAFE + KNOWN_PHISHING:
        expected = "SAFE" if (url, desc) in KNOWN_SAFE else "PHISHING"
        feats = extract(url)
        X1 = pd.DataFrame([feats], columns=FEATURE_NAMES, dtype=np.float32)
        cal_p = float(calibrated.predict_proba(X1.values)[:, 1][0])
        pred = "PHISHING" if cal_p >= SHIPPED_SUSPICIOUS_THRESHOLD else "SAFE"
        ok = pred == expected

        row = {"url": url, "desc": desc, "expected": expected,
               "calibrated_prob": round(cal_p, 4), "pred_at_035": pred, "pass": ok}
        rows.append(row)
        icon = "✓" if ok else "✗"
        print(f"  {icon} {desc:<30} expected={expected:<8} P(cal)={cal_p:.4f} → {pred}")

        if not ok:
            sv1 = explainer(X1)
            vals, base = shap_phishing_values(sv1)
            base = np.asarray(base).ravel()
            rf_p = float(base[0] + vals[0].sum()) if space == "probability" \
                else float(calibrated.base_estimator.predict_proba(X1.values)[0, 1])
            fig_title = (f"{desc} — expected {expected}, shipped decision {pred} "
                         f"(calibrated P={cal_p:.3f}, RF P={rf_p:.3f})")
            ev1 = to_phishing_explanation(sv1, X1)
            shap.plots.waterfall(ev1[0], max_display=12, show=False)
            fig = plt.gcf()
            fig.suptitle(fig_title, fontsize=10, y=1.02)
            slug = desc.lower().replace(" ", "_").replace("/", "_").replace("@", "at_").replace(".", "_")[:40]
            fig.savefig(OUT_DIR / f"04_waterfall_{slug}.png", dpi=150, bbox_inches="tight")
            plt.close(fig)
            waterfalls.append(desc)
            print(f"     ↳ waterfall saved (RF P={rf_p:.3f})")

    return rows


def main() -> None:
    print("=" * 60)
    print("PHISHGUARD ML v4.1 — SHAP MODEL EXPLANATION")
    print("=" * 60)

    data = reproduce_production_model()
    parity = verify_onnx_parity(data)

    sub = build_cohort_subsample(data)
    X_sub = sub[FEATURE_NAMES]

    print("\nBuilding TreeExplainer for the RandomForest...")
    explainer = shap.TreeExplainer(data["rf"])
    space = detect_output_space(explainer, X_sub.iloc[:200], data["rf"])

    print("\nComputing SHAP values for the cohort subsample...")
    sv_sub = explainer(X_sub)
    vals, _ = shap_phishing_values(sv_sub)

    # Global importance table
    mean_abs = np.abs(vals).mean(axis=0)
    order = np.argsort(mean_abs)[::-1]
    print(f"\n{'─' * 60}")
    print("TOP 15 FEATURES (mean |SHAP| on test subsample)")
    print(f"{'─' * 60}")
    top_features = []
    for rank, i in enumerate(order[:15], 1):
        name = FEATURE_NAMES[i]
        top_features.append(name)
        signed = vals[:, i].mean()
        direction = "→ phishing" if signed > 0 else "→ legitimate"
        print(f"  {rank:2d}. {name:<30} {mean_abs[i]:.4f}  (mean signed {signed:+.4f}, {direction})")

    print(f"\n{'─' * 60}")
    print("PLOTS")
    print(f"{'─' * 60}")
    plot_global(sv_sub, top_features)
    plot_cohort_heatmap(vals, sub["__src"].values, FEATURE_NAMES)

    print(f"\n{'─' * 60}")
    print("GOLDEN-SET EXPLANATION (shipped threshold 0.35)")
    print(f"{'─' * 60}")
    golden_rows = explain_golden_set(explainer, data["calibrated"], space)

    n_fail = sum(1 for r in golden_rows if not r["pass"])
    summary = {
        "parity": parity,
        "shap_space": space,
        "subsample_rows": int(len(sub)),
        "top_features": [
            {"feature": FEATURE_NAMES[i], "mean_abs_shap": float(mean_abs[i]),
             "mean_signed_shap": float(vals[:, i].mean())}
            for i in order[:15]
        ],
        "golden_set": golden_rows,
        "golden_set_failures": n_fail,
        "waterfall_plots": [str(p.name) for p in OUT_DIR.glob("04_waterfall_*.png")],
    }
    with open(OUT_DIR / "shap_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n{'=' * 60}")
    print(f"✓ SHAP analysis complete → {OUT_DIR}")
    print(f"  Golden-set failures explained with waterfalls: {n_fail}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
