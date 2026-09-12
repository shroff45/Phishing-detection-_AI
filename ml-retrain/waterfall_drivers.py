"""
One-off companion to shap_analysis.py — prints the numeric waterfall
breakdown (top SHAP contributors) for each golden-set failure, so the
feature-level drivers of the 3 false positives are on record in text.
"""

import numpy as np
import pandas as pd
import shap

from shap_analysis import (
    KNOWN_SAFE, reproduce_production_model, shap_phishing_values,
    SHIPPED_SUSPICIOUS_THRESHOLD,
)
from config import FEATURE_NAMES
from feature_extractor import extract

def main() -> None:
    data = reproduce_production_model()
    calibrated = data["calibrated"]
    explainer = shap.TreeExplainer(data["rf"])

    failures = []
    for url, desc in KNOWN_SAFE:
        feats = extract(url)
        X1 = pd.DataFrame([feats], columns=FEATURE_NAMES, dtype=np.float32)
        p = float(calibrated.predict_proba(X1.values)[:, 1][0])
        if p >= SHIPPED_SUSPICIOUS_THRESHOLD:
            failures.append((url, desc, p, X1))

    print(f"\n{len(failures)} SAFE URLs misclassified at 0.35:")
    for url, desc, p, X1 in failures:
        sv = explainer(X1)
        vals, base = shap_phishing_values(sv)
        vals = np.asarray(vals)[0]
        base = float(np.asarray(base).ravel()[0])
        rf_p = base + vals.sum()

        print(f"\n{'━' * 64}")
        print(f"✗ {desc}  —  {url}")
        print(f"  RF P(phish)={rf_p:.4f}   base={base:.4f}   "
              f"calibrated={p:.4f}")
        print(f"{'━' * 64}")
        order = np.argsort(np.abs(vals))[::-1][:10]
        print(f"  {'feature':<28} {'value':>8} {'SHAP':>9}   direction")
        for i in order:
            if vals[i] == 0 and abs(vals[i]) < 1e-5:
                continue
            arrow = "→ phishing" if vals[i] > 0 else "→ legitimate"
            print(f"  {FEATURE_NAMES[i]:<28} {float(X1.iloc[0, i]):>8.2f} "
                  f"{vals[i]:>+9.4f}   {arrow}")


if __name__ == "__main__":
    main()
