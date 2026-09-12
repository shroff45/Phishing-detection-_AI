"""
PhishGuard ML v4.1 — Model Training
Grouped-CV model search, calibration, FPR-constrained threshold, ONNX export.

Fixes applied:
  - Fix 2/9:  Calibrate on SEPARATE calibration set with FrozenEstimator
              (sklearn >= 1.6)
  - Fix 10:   FPR penalty in model selection (applied at VALIDATION time)
  - Fix 12:   XGBoost — no deprecated use_label_encoder
  - Fix 14/H: ONNX output parsed by name via shared utility
  - Fix 18/E: Optimal threshold via ROC curve with array alignment
  - Fix 19:   DOMAIN-DISJOINT evaluation:
              * Hyperparameter search uses GroupKFold over the eTLD+1 domain
                groups saved by prepare_data.py. KFold/StratifiedKFold would
                let URLs from the same domain land in a CV training fold AND
                its validation fold, so the search would reward configs that
                memorize domains instead of lexical signals.
              * Every candidate is Pipeline(StandardScaler, classifier):
                scaling parameters are learned inside each CV fold (never
                from the fold's validation data), and the scaler ships
                INSIDE the ONNX graph — the extension's JS feature extraction
                is unchanged.
              * CV ranks by ROC-AUC (threshold-free, stable per fold). The
                FPR penalty (Fix 10) stays at validation-time selection
                (select_best) and the evaluate.py gate, where an operating
                threshold actually exists.
"""

import json
import time
import numpy as np
from pathlib import Path
from sklearn.ensemble import (
    RandomForestClassifier,
    GradientBoostingClassifier,
    ExtraTreesClassifier,
)
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, f1_score, accuracy_score, roc_curve,
)
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import GridSearchCV, GroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from config import (
    PREPARED_DIR, MODELS_DIR, REPORTS_DIR,
    RANDOM_STATE, TARGET_FPR,
    SHIPPED_SUSPICIOUS_THRESHOLD,
)

# XGBoost / LightGBM stay deliberately EXCLUDED from candidates: skl2onnx
# cannot reliably convert their graphs, and the extension ships ONNX. The
# previous version force-disabled them via HAS_XGB/HAS_LGBM anyway.

N_SPLITS = 5  # GroupKFold folds over eTLD+1 domain groups


def load_data() -> dict:
    """Load all 4 splits + domain groups + metadata."""
    data = {}
    for name in [
        "X_train", "X_val", "X_cal", "X_test",
        "y_train", "y_val", "y_cal", "y_test", "src_test",
        "groups_train", "groups_val", "groups_cal", "groups_test",
    ]:
        path = PREPARED_DIR / f"{name}.npy"
        if path.exists():
            data[name] = np.load(path, allow_pickle=True)

    with open(PREPARED_DIR / "metadata.json") as f:
        data["meta"] = json.load(f)

    print(f"Train: {data['X_train'].shape} | Val: {data['X_val'].shape} | "
          f"Cal: {data['X_cal'].shape} | Test: {data['X_test'].shape}")
    if "groups_train" in data:
        n_domains = len(set(data["groups_train"].tolist()))
        print(f"Domain groups in train: {n_domains:,}")
    return data


def make_pipeline(clf) -> Pipeline:
    """
    Fix 19: scaler + classifier as ONE estimator.

    StandardScaler parameters are fit inside every CV fold (and inside the
    final refit) — never computed across a fold's validation rows. Tree
    ensembles are scale-invariant so this costs nothing, and skl2onnx
    guarantees conversion of StandardScaler, so the scaler rides along in
    the exported ONNX graph.
    """
    return Pipeline([("scaler", StandardScaler()), ("clf", clf)])


def build_candidates() -> dict:
    """Candidate search spaces: Pipeline + small per-model grids."""
    return {
        "random_forest": (
            make_pipeline(RandomForestClassifier(
                n_estimators=100, max_depth=15, min_samples_leaf=2,
                class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1,
            )),
            {"clf__n_estimators": [100, 200], "clf__max_depth": [12, 18]},
        ),
        "extra_trees": (
            make_pipeline(ExtraTreesClassifier(
                n_estimators=100, max_depth=15, min_samples_leaf=2,
                class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1,
            )),
            {"clf__n_estimators": [100, 200], "clf__max_depth": [12, 18]},
        ),
        "gradient_boosting": (
            make_pipeline(GradientBoostingClassifier(
                n_estimators=100, max_depth=5, learning_rate=0.1,
                min_samples_leaf=5, subsample=0.8, random_state=RANDOM_STATE,
            )),
            {"clf__n_estimators": [100, 200], "clf__max_depth": [4, 6]},
        ),
    }


def train_all_models(X_train, y_train, groups_train, X_val, y_val) -> dict:
    """
    Fix 19: GroupKFold hyperparameter search + validation scoring.

    GridSearchCV explores each grid with GroupKFold over domain groups, then
    (refit=True) refits the winning config — scaler included — on the FULL
    training split. Validation is scored once, after refit, for selection
    metrics; it is never touched by the search.
    """
    n_groups = len(set(groups_train.tolist()))
    n_splits = max(2, min(N_SPLITS, n_groups))
    gkf = GroupKFold(n_splits=n_splits)
    print(f"\nGroupKFold: {n_splits} folds over {n_groups:,} domain groups "
          f"(domain-disjoint — no domain spans a fold boundary)")

    results = {}
    for name, (pipe, grid) in build_candidates().items():
        n_configs = 1
        for values in grid.values():
            n_configs *= len(values)
        print(f"\n  Tuning {name} ({n_configs} configs × {n_splits} folds)...",
              end=" ", flush=True)

        start = time.time()
        search = GridSearchCV(
            pipe, grid, cv=gkf, scoring="roc_auc",
            n_jobs=-1, refit=True, verbose=0,
        )
        search.fit(X_train, y_train, groups=groups_train)
        elapsed = time.time() - start

        best = search.best_estimator_
        cv_mean = float(search.cv_results_["mean_test_score"][search.best_index_])
        cv_std = float(search.cv_results_["std_test_score"][search.best_index_])
        print(f"CV AUC={cv_mean:.4f}±{cv_std:.4f} ({elapsed:.1f}s)")
        print(f"    best params: {search.best_params_}")

        # Validation metrics for selection (post-refit, validation untouched
        # by the search itself)
        y_prob = best.predict_proba(X_val)[:, 1]
        y_pred = best.predict(X_val)

        cm = confusion_matrix(y_val, y_pred)
        tn, fp, fn, tp = cm.ravel()

        metrics = {
            "accuracy": float(accuracy_score(y_val, y_pred)),
            "f1": float(f1_score(y_val, y_pred)),
            "auc": float(roc_auc_score(y_val, y_prob)),
            "fpr": float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
            "fnr": float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0,
            "time": elapsed,
            "cv_auc": cv_mean,
            "cv_std": cv_std,
            "best_params": {k: (v if isinstance(v, (int, float, str, type(None)))
                                 else str(v))
                            for k, v in search.best_params_.items()},
        }

        print(f"    Val: Acc={metrics['accuracy']:.4f} F1={metrics['f1']:.4f} "
              f"AUC={metrics['auc']:.4f} FPR={metrics['fpr']:.4f}")

        results[name] = {"model": best, "metrics": metrics}

    return results


def select_best(results: dict):
    """
    Fix 10: Select best model with FPR penalty.

    Score = validation F1, penalized when validation FPR exceeds TARGET_FPR.
    CV AUC (Fix 19) is shown for context but the decision stays anchored to
    validation-set operating metrics — the FPR constraint is a property of
    a deployed threshold, not of a threshold-free CV score.
    """
    print(f"\n{'=' * 68}")
    print(f"{'Model':<22} {'CV AUC':>13} {'F1':>7} {'AUC':>7} {'FPR':>7}")
    print("-" * 68)

    best_name = None
    best_score = -1.0

    for name, info in results.items():
        m = info["metrics"]

        score = m["f1"]
        if m["fpr"] > TARGET_FPR:
            fpr_ratio = m["fpr"] / TARGET_FPR
            penalty = min(fpr_ratio * 0.1, 0.5)
            score *= (1 - penalty)
            marker = f" (penalized: {penalty:.1%})"
        else:
            marker = " ★"

        if score > best_score:
            best_score = score
            best_name = name

        print(f"  {name:<20} {m['cv_auc']:>6.4f}±{m['cv_std']:.4f} "
              f"{m['f1']:>7.4f} {m['auc']:>7.4f} {m['fpr']:>7.4f}{marker}")

    print(f"\n→ Winner: {best_name}")
    return best_name, results[best_name]["model"]


def find_optimal_threshold(model, X_val, y_val, target_fpr=TARGET_FPR) -> float:
    """
    Fix 18/E: Find threshold achieving target FPR via ROC curve.
    Handles sklearn's roc_curve sentinel correctly.
    """
    y_prob = model.predict_proba(X_val)[:, 1]
    fpr_arr, tpr_arr, thresholds = roc_curve(y_val, y_prob)

    # sklearn roc_curve: fpr_arr and tpr_arr have len(thresholds)+1
    # The first point (0, 0) has no corresponding threshold.
    # Drop it so arrays align.
    if len(fpr_arr) > len(thresholds):
        fpr_arr = fpr_arr[1:]
        tpr_arr = tpr_arr[1:]

    # Find threshold achieving target FPR with best TPR
    candidates = np.where(fpr_arr <= target_fpr * 1.5)[0]

    if len(candidates) == 0:
        print(f"  ⚠ Cannot achieve FPR ≤ {target_fpr * 1.5:.4f}")
        idx = int(np.argmin(np.abs(fpr_arr - target_fpr)))
    else:
        idx = int(candidates[np.argmax(tpr_arr[candidates])])

    idx = min(idx, len(thresholds) - 1)

    optimal = float(thresholds[idx])
    achieved_fpr = float(fpr_arr[idx])
    achieved_tpr = float(tpr_arr[idx])

    print(f"  Optimal threshold: {optimal:.4f}")
    print(f"  Achieved FPR: {achieved_fpr:.4f} (target: {target_fpr})")
    print(f"  Achieved TPR: {achieved_tpr:.4f}")

    return optimal


def _zipmap_false_options(model) -> dict:
    """
    Fix 19/P: register zipmap=False on every classifier-ish node, not just
    the top-level model. With a bare classifier, {id(model): {"zipmap": False}}
    was enough; with Pipeline / CalibratedClassifierCV containers, skl2onnx
    resolves options per sub-estimator, so the option must also reach the
    inner classifier — otherwise the output silently reverts to a zipmap of
    dicts and the shared array parser (Fix 14/H) breaks.
    """
    opts = {}
    stack = [model]
    seen = set()
    while stack:
        obj = stack.pop()
        if obj is None or id(obj) in seen:
            continue
        seen.add(id(obj))
        # Classifiers (and pipelines ending in one) — scalers are skipped
        if hasattr(obj, "predict_proba"):
            opts[id(obj)] = {"zipmap": False}
        if hasattr(obj, "named_steps"):
            stack.extend(obj.named_steps.values())
        if hasattr(obj, "estimator"):
            stack.append(obj.estimator)
        if hasattr(obj, "calibrated_classifiers_"):
            stack.extend(obj.calibrated_classifiers_)
    return opts


def export_onnx(model, num_features: int, output_path: Path) -> bool:
    """
    Export to ONNX with zipmap=False for array output.
    Fix 14/H: verify using shared parser.
    """
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    initial_type = [("float_input", FloatTensorType([None, num_features]))]

    try:
        # zipmap=False → outputs raw probability arrays, not dicts
        onnx_model = convert_sklearn(
            model, initial_types=initial_type, target_opset=12,
            options=_zipmap_false_options(model),
        )

        with open(output_path, "wb") as f:
            f.write(onnx_model.SerializeToString())

        # Verify using shared parser
        import onnxruntime as ort
        from feature_extractor import parse_onnx_probabilities

        session = ort.InferenceSession(str(output_path))
        print(f"  ONNX outputs: {[o.name for o in session.get_outputs()]}")

        test_input = np.zeros((1, num_features), dtype=np.float32)
        probs = parse_onnx_probabilities(session, test_input)
        phishing_prob = float(probs[0])

        print(f"  ✓ Zero-input phishing prob: {phishing_prob:.4f}")
        print(f"  ✓ Size: {output_path.stat().st_size / 1024:.1f} KB")

        if phishing_prob > 0.3:
            print(f"  ⚠ High zero-input bias ({phishing_prob:.2f}) — adjust threshold")

        return True

    except Exception as e:
        print(f"  ✗ ONNX export failed: {e}")
        return False


def train():
    """Complete training pipeline."""
    print("=" * 60)
    print("PHISHGUARD ML v4.1 — MODEL TRAINING")
    print("=" * 60)

    data = load_data()

    # Domain groups for leakage-free CV (Fix 19). If the prepared data
    # predates Fix 19, fall back LOUDLY to row-level pseudo-groups —
    # GroupKFold then degenerates to plain KFold and nothing is grouped.
    if "groups_train" in data:
        groups_train = data["groups_train"]
    else:
        print("\n⚠ prepared/ has no domain groups — data predates Fix 19!")
        print("  CV falls back to row-level pseudo-groups (NOT domain-disjoint).")
        print("  → Re-run prepare_data.py to regenerate domain-disjoint splits.")
        groups_train = np.array(
            [f"row-{i}" for i in range(len(data["X_train"]))], dtype=object,
        )

    # Grouped search + validation selection
    results = train_all_models(
        data["X_train"], data["y_train"], groups_train,
        data["X_val"], data["y_val"],
    )
    best_name, best_model = select_best(results)

    # Fix 2/9: Calibrate on SEPARATE calibration set with FrozenEstimator.
    # best_model is a Pipeline; FrozenEstimator wraps it whole, so the
    # scaler rides through calibration untouched.
    from sklearn.frozen import FrozenEstimator
    print(f"\nCalibrating on separate calibration set (FrozenEstimator)...")
    calibrated = CalibratedClassifierCV(FrozenEstimator(best_model))
    calibrated.fit(data["X_cal"], data["y_cal"])

    # ── Select the shipped artifact AT THE SHIPPED OPERATING POINT ────────
    # Sigmoid calibration on a domain-disjoint calibration set can compress
    # probabilities into a narrow band (observed: legit p50 0.746 vs phish
    # p50 0.912) — great ordering, useless at a fixed 0.35 threshold. The
    # extension runs at 0.35/0.65, so the shipped artifact is whichever of
    # {calibrated, raw} performs better ON VALIDATION at that threshold.
    # The raw tree ensemble spreads probabilities naturally and often wins.
    print(f"\nSELECTING SHIPPED ARTIFACT AT THE SHIPPED THRESHOLD "
          f"({SHIPPED_SUSPICIOUS_THRESHOLD})...")

    def _point_metrics(model, X, y, thr):
        prob = model.predict_proba(X)[:, 1]
        pred = (prob >= thr).astype(int)
        cm = confusion_matrix(y, pred)
        tn, fp, fn, tp = cm.ravel()
        return {
            "fpr": float(fp / (fp + tn)) if (fp + tn) else 0.0,
            "fnr": float(fn / (fn + tp)) if (fn + tp) else 0.0,
            "f1": float(f1_score(y, pred)),
            "auc": float(roc_auc_score(y, prob)),
        }

    variants = {
        "calibrated": (calibrated, _point_metrics(
            calibrated, data["X_val"], data["y_val"], SHIPPED_SUSPICIOUS_THRESHOLD)),
        "raw": (best_model, _point_metrics(
            best_model, data["X_val"], data["y_val"], SHIPPED_SUSPICIOUS_THRESHOLD)),
    }
    for vname, (_, vm) in variants.items():
        print(f"  {vname:<11} @0.35  FPR={vm['fpr']:.4f} FNR={vm['fnr']:.4f} "
              f"F1={vm['f1']:.4f} AUC={vm['auc']:.4f}")

    # Prefer the lowest FPR at the shipped threshold; break ties on F1.
    # A candidate whose FPR at 0.35 exceeds the ceiling is only shippable
    # if the other variant is even worse.
    shipped_variant = min(
        variants, key=lambda k: (variants[k][1]["fpr"], -variants[k][1]["f1"]))
    shipped_model = variants[shipped_variant][0]
    shipped_point = variants[shipped_variant][1]
    other_variant = "raw" if shipped_variant == "calibrated" else "calibrated"
    print(f"\n→ Shipped artifact: {shipped_variant} "
          f"(val FPR@0.35 = {shipped_point['fpr']:.4f})")
    if shipped_point["fpr"] > 0.10:
        print(f"  ⚠ Both variants exceed 10% FPR at the shipped threshold — "
              f"the eval gate will likely block this candidate.")

    # Fix 18: Find optimal threshold (for the report; the shipped threshold
    # is 0.35 from config, and the gate measures there).
    print("\nFinding optimal decision threshold...")
    threshold = find_optimal_threshold(shipped_model, data["X_val"], data["y_val"])

    # Final evaluation on TEST set — the SHIPPED artifact at the SHIPPED
    # threshold. The optimal threshold stays in the report for reference;
    # what users get is 0.35 (config) and this is what the gate measures.
    print(f"\n{'=' * 60}")
    print(f"FINAL TEST SET EVALUATION ({shipped_variant} artifact, "
          f"domain-disjoint test — shipped threshold {SHIPPED_SUSPICIOUS_THRESHOLD})")
    print(f"{'=' * 60}")

    y_prob = shipped_model.predict_proba(data["X_test"])[:, 1]
    y_pred = (y_prob >= SHIPPED_SUSPICIOUS_THRESHOLD).astype(int)

    print(f"\nThreshold (shipped): {SHIPPED_SUSPICIOUS_THRESHOLD}")
    print(classification_report(
        data["y_test"], y_pred,
        target_names=["Legitimate", "Phishing"], digits=4,
    ))

    cm = confusion_matrix(data["y_test"], y_pred)
    tn, fp, fn, tp = cm.ravel()
    test_fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    test_fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    print(f"  FPR: {test_fpr:.4f} ({test_fpr * 100:.2f}%) | Target: <{TARGET_FPR * 100:.1f}%")
    print(f"  FNR: {test_fnr:.4f} ({test_fnr * 100:.2f}%)")

    # Feature importance — lives on the classifier step now that the model
    # is a Pipeline (Fix 19)
    feat_names = data["meta"]["feature_names"]
    inner = (best_model.named_steps.get("clf")
             if hasattr(best_model, "named_steps") else best_model)
    if inner is not None and hasattr(inner, "feature_importances_"):
        print("\nTop 10 Features:")
        idx = np.argsort(inner.feature_importances_)[::-1]
        for rank, i in enumerate(idx[:10], 1):
            print(f"  {rank:2d}. {feat_names[i]:<30} "
                  f"{inner.feature_importances_[i]:.4f}")

    # Fix for skl2onnx: It does not recognize FrozenEstimator.
    # Unfreeze the underlying estimators before exporting. Each frozen
    # wrapper's .estimator is the Pipeline, and skl2onnx converts
    # Pipeline(StandardScaler, clf) natively — scaler stays in the graph.
    # No-op when the raw variant ships (it is already a plain Pipeline).
    if hasattr(shipped_model, "calibrated_classifiers_"):
        for clf in shipped_model.calibrated_classifiers_:
            if hasattr(clf, "estimator") and hasattr(clf.estimator, "estimator"):
                clf.estimator = clf.estimator.estimator

    # Export the shipped artifact as the primary model
    onnx_path = MODELS_DIR / "phishing_model_v4.onnx"
    print(f"\nExporting shipped artifact ({shipped_variant})...")
    export_onnx(shipped_model, data["meta"]["num_features"], onnx_path)

    # The losing variant stays on disk as the fallback
    onnx_raw = MODELS_DIR / "phishing_model_v4_raw.onnx"
    other_model = variants[other_variant][0]
    if hasattr(other_model, "calibrated_classifiers_"):
        for clf in other_model.calibrated_classifiers_:
            if hasattr(clf, "estimator") and hasattr(clf.estimator, "estimator"):
                clf.estimator = clf.estimator.estimator
    print(f"Exporting {other_variant} as fallback...")
    export_onnx(other_model, data["meta"]["num_features"], onnx_raw)

    # Save report
    win_metrics = results[best_name]["metrics"]
    report = {
        "best_model": best_name,
        "shipped_variant": shipped_variant,
        "optimal_threshold": threshold,
        "shipped_threshold": SHIPPED_SUSPICIOUS_THRESHOLD,
        "val_fpr_at_shipped": shipped_point["fpr"],
        "val_fnr_at_shipped": shipped_point["fnr"],
        "test_fpr": test_fpr,
        "test_fnr": test_fnr,
        "test_accuracy": float(accuracy_score(data["y_test"], y_pred)),
        "test_f1": float(f1_score(data["y_test"], y_pred)),
        "test_auc": float(roc_auc_score(data["y_test"], y_prob)),
        # Fix 19: audit trail
        "cv_strategy": "group_kfold_domain_disjoint",
        "cv_auc": win_metrics["cv_auc"],
        "cv_std": win_metrics["cv_std"],
        "best_params": win_metrics["best_params"],
        "pipeline": "standard_scaler+clf",
    }
    with open(REPORTS_DIR / "training_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n✓ Training complete. Model saved to {onnx_path}")


if __name__ == "__main__":
    train()
