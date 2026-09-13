"""
PhishGuard ML v4.1 — Deployment
Copies model+config to extension and backend directories.

Stage 2: deploy() is now gated.
  - Reads evaluation_report.json written by evaluate().
  - Refuses to copy the model unless report["pass"] is True.
  - Exits non-zero if the report is missing or failed, so CI
    and run_pipeline.py both catch the failure correctly.
"""

import json
import shutil
import sys
from pathlib import Path
from config import (
    MODELS_DIR, REPORTS_DIR,
    EXTENSION_DIR, BACKEND_MODEL_DIR,
    NUM_FEATURES, FEATURE_NAMES,
)


def deploy() -> None:
    """Deploy model to extension and backend — only if evaluation passed."""
    print("=" * 60)
    print("PHISHGUARD ML v4.1 — DEPLOYMENT")
    print("=" * 60)

    # ── Gate check ─────────────────────────────────────────────────────────
    eval_report_path = REPORTS_DIR / "evaluation_report.json"
    if not eval_report_path.exists():
        print("✗ evaluation_report.json not found.")
        print("  Run evaluate.py before deploying.")
        sys.exit(1)

    # encoding="utf-8-sig": the report has been hand-restored before
    # (re-arming the incumbent gate), and a hand-edit can add a UTF-8
    # BOM that plain json.load would crash on, turning a gate check
    # into an unhandled exception.
    with open(eval_report_path, encoding="utf-8-sig") as f:
        eval_report = json.load(f)

    if not eval_report.get("pass", False):
        reasons = eval_report.get("gate_reasons", ["no reason recorded"])
        print("✗ Evaluation gate did not pass — deployment blocked.")
        for reason in reasons:
            print(f"   → {reason}")
        print("\nFix the model and re-run evaluate.py before deploying.")
        sys.exit(1)

    shipped_fpr = eval_report.get("shipped_fpr", "?")
    print(f"✓ Evaluation gate passed  (shipped FPR: {shipped_fpr})")

    # ── Find model ──────────────────────────────────────────────────────────
    model_path = MODELS_DIR / "phishing_model_v4.onnx"
    if not model_path.exists():
        model_path = MODELS_DIR / "phishing_model_v4_raw.onnx"
    if not model_path.exists():
        print("✗ No model found! Run train_model.py first.")
        sys.exit(1)

    print(f"Model: {model_path.name} ({model_path.stat().st_size / 1024:.1f} KB)")

    # ── Build model_config.json ─────────────────────────────────────────────
    # Use the shipped threshold from the evaluation report, not the model's
    # internal optimal_threshold.
    shipped_threshold = eval_report.get(
        "shipped_threshold",
        0.35,  # fallback to the known shipped value
    )
    model_config = {
        "model_version": "4.1",
        "input_name": "float_input",
        "num_features": NUM_FEATURES,
        "feature_names": FEATURE_NAMES,
        "shipped_threshold": shipped_threshold,
        "shipped_fpr": shipped_fpr,
        "output_classes": ["legitimate", "phishing"],
    }

    # ── Deploy ──────────────────────────────────────────────────────────────
    deployed = []
    if EXTENSION_DIR and EXTENSION_DIR.exists():
        ext_model_dir = EXTENSION_DIR / "models"
        ext_model_dir.mkdir(parents=True, exist_ok=True)

        target = ext_model_dir / "model.onnx"
        shutil.copy2(model_path, target)
        deployed.append(target)
        print(f"  ✓ Extension: {target}")

        config_path = ext_model_dir / "model_config.json"
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(model_config, f, indent=2)
        print(f"  ✓ Config:    {config_path}")
    else:
        print("  ⚠ Extension directory not found — skipped")

    if BACKEND_MODEL_DIR.parent.exists():
        BACKEND_MODEL_DIR.mkdir(parents=True, exist_ok=True)

        target = BACKEND_MODEL_DIR / "model.onnx"
        shutil.copy2(model_path, target)
        deployed.append(target)
        print(f"  ✓ Backend:   {target}")

        config_path = BACKEND_MODEL_DIR / "model_config.json"
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(model_config, f, indent=2)
        print(f"  ✓ Config:    {config_path}")
    else:
        print("  ⚠ Backend directory not found — skipped")

    print(f"\n{'=' * 60}")
    print(f"DEPLOYED: {len(deployed)} targets | Shipped threshold: {shipped_threshold}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    deploy()
