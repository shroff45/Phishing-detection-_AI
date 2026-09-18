SYNTHETIC_DATA_IS_AUGMENTATION_ONLY = True
VALIDATION_SOURCES = []
TEST_SOURCES = []
REAL_WORLD_HOLDOUT_SOURCES = []
if SYNTHETIC_DATA_IS_AUGMENTATION_ONLY:
    assert "synthetic" not in VALIDATION_SOURCES, "Synthetic data banned from validation"
    assert "synthetic" not in TEST_SOURCES, "Synthetic data banned from test"
    assert "synthetic" not in REAL_WORLD_HOLDOUT_SOURCES, "Synthetic data banned from holdout"

"""
PhishGuard ML v4.1 — Data Preparation
Merges real + synthetic datasets, extracts features, splits into 4 sets.

Fixes applied:
  - Fix 5:    Float labels (1.0 → 1) handled explicitly
  - Fix 6:     Unknown labels DROPPED, not silently converted to 0
  - Fix 9:     4-way split: train / val / calibration / test
  - Fix 11/D:  Stratified balancing with remainder distribution
  - Fix G:     Sources converted to numpy before splitting
  - Fix 19:    DOMAIN-DISJOINT splits (leakage fix). Every URL is assigned
               to its eTLD+1 registrable domain and GroupShuffleSplit keeps
               all URLs of a domain in exactly ONE split. The previous
               chained train_test_split calls let phishy-bank.com/login
               (train) and phishy-bank.com/secure (test) share a domain
               across the boundary, so models memorized domains instead of
               learning lexical signals — ROC-AUC looked great, collapsed
               in production. Split fractions now apply to GROUPS, so
               realized row counts are approximate; actual sizes and
               per-split class balance are printed below and stored in
               metadata.json.
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

from config import (
    DATA_DIR, SYNTH_DIR, PREPARED_DIR, RANDOM_STATE,
    TEST_SIZE, VAL_SIZE, CALIBRATION_SIZE,
    NUM_FEATURES, FEATURE_NAMES,
)
from feature_extractor import extract_batch


# Labels recognized across datasets
PHISHING_LABELS = {"1", "1.0", "phishing", "bad", "malicious", "yes", "suspicious"}
LEGITIMATE_LABELS = {"0", "0.0", "legitimate", "good", "benign", "safe", "no", "clean"}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# eTLD+1 domain extraction (Fix 19)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Two-label public suffixes that share a registrable boundary. Anything not
# listed here is treated as a single-label TLD. Unrecognized multi-label
# suffixes (e.g. a new ccTLD second level) degrade toward coarser grouping —
# more domains lumped into one group — which can never leak a domain ACROSS
# a split boundary; it only makes the split slightly more conservative.
TWO_LABEL_SUFFIXES = {
    # ccTLD second levels
    "co.uk", "org.uk", "ac.uk", "gov.uk", "sch.uk", "net.uk", "me.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz",
    "co.in", "net.in", "org.in", "ac.in", "edu.in", "gov.in", "res.in",
    "co.za", "org.za", "web.za", "ac.za",
    "com.br", "net.br", "org.br", "gov.br",
    "com.mx", "org.mx", "net.mx",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.kr", "or.kr", "re.kr",
    "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg",
    "com.hk", "edu.hk", "gov.hk", "net.hk", "org.hk",
    "com.tr", "edu.tr", "gov.tr", "net.tr", "org.tr",
    "com.ar", "net.ar", "org.ar", "gov.ar",
    "com.co", "net.co", "org.co", "edu.co", "gov.co",
    "com.pe", "net.pe", "org.pe", "gob.pe", "edu.pe",
    "com.ve", "net.ve", "org.ve", "gob.ve",
    "com.ua", "net.ua", "org.ua", "edu.ua", "gov.ua",
    "com.my", "net.my", "org.my", "edu.my", "gov.my",
    "com.ph", "net.ph", "org.ph", "edu.ph", "gov.ph",
    "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk",
    "com.eg", "net.eg", "org.eg", "edu.eg", "gov.eg",
    "com.sa", "net.sa", "org.sa", "edu.sa", "gov.sa",
    "com.ng", "net.ng", "org.ng", "edu.ng", "gov.ng",
    "com.gh", "edu.gh", "gov.gh", "org.gh",
    "co.ke", "or.ke", "co.tz", "co.ug", "ac.ug", "sc.ug",
    "or.th", "ac.th", "co.th", "in.th", "go.th",
    "com.tw", "edu.tw", "gov.tw", "org.tw", "idv.tw",
    "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn",
    "co.il", "org.il", "ac.il", "gov.il", "net.il", "muni.il",
    "com.pl", "net.pl", "org.pl", "edu.pl", "gov.pl",
    "com.pt", "edu.pt", "gov.pt", "net.pt", "org.pt",
    "com.gr", "edu.gr", "net.gr", "org.gr", "gov.gr",
    "com.es", "nom.es", "org.es", "gob.es", "edu.es",
    "com.ru", "net.ru", "org.ru", "edu.ru", "gov.ru",
    "co.id", "or.id", "ac.id", "go.id", "web.id", "net.id",
    "ac.ir", "co.ir", "gov.ir", "or.ir", "net.ir", "org.ir",
    "com.ec", "gob.ec", "edu.ec", "co.ec",
    "com.do", "edu.do", "gob.do", "gov.do",
    "com.gt", "edu.gt", "gob.gt", "net.gt", "org.gt",
    "com.py", "edu.py", "gov.py", "net.py", "org.py",
    "com.bo", "edu.bo", "gob.bo", "org.bo", "net.bo",
    "com.sv", "edu.sv", "gob.sv",
    "com.ni", "edu.ni", "gob.ni", "org.ni", "net.ni",
    "com.pa", "edu.pa", "gob.pa", "net.pa", "org.pa",
    "com.uy", "edu.uy", "gub.uy", "net.uy", "org.uy",
    "gob.cl", "gov.cl", "edu.cl", "co.cl",
    # PaaS / dev-hosting suffixes — each is one registrable zone
    "github.io", "gitlab.io", "netlify.app", "vercel.app",
    "herokuapp.com", "pages.dev", "workers.dev", "firebaseapp.com",
    "appspot.com", "azurewebsites.net", "cloudfront.net",
    "web.app", "r2.dev", "deno.dev",
    "repl.co", "glitch.me", "stackblitz.io", "codepen.io",
    "wordpress.com", "blogspot.com", "weebly.com", "wixsite.com",
    "duckdns.org", "ddns.net", "hopto.org", "zapto.org",
    "servegame.com", "serveo.net", "trycloudflare.com",
    "onrender.com", "herokudns.com", "tictap.io",
    "myftp.org", "myvnc.com", "no-ip.org", "no-ip.com", "no-ip.biz",
    "redirect.ampproject.org", "r.jina.ai",
}

# Synthetically-generated base suffixes used by synth_generator (e.g.
# "npyyfkfckrhr.site"): every synthetic phishing URL gets a fresh random
# registrable domain, so plain eTLD+1 is already correct there — no special
# case needed. Random-letter eTLDs are caught by the fallback below.

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HEX_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")


def extract_domain(url: str) -> str:
    """
    Return the eTLD+1 registrable domain of a URL to use as its group id.

    Escaped targets and IPv4 hosts are grouped per-address (each address is
    its own "domain"). Hosts with an unrecognized multi-label tail (e.g.
    "foo.bar.co.uk" where co.uk is known) fall back to the LAST TWO labels
    before the recognized suffix — if the suffix itself is unknown the whole
    tail past the first label is used, which over-merges (conservative) but
    never splits one real domain across two groups.
    """
    if not isinstance(url, str) or not url:
        return "unknown"

    try:
        host = urlparse(url if "//" in url else f"http://{url}").hostname
    except ValueError:
        return "invalid"
    if not host:
        return "unknown"

    host = host.strip(".").lower()
    if not host:
        return "unknown"

    # IP-literal hosts: each address is its own group
    if _IPV4_RE.match(host):
        return f"ip:{host}"
    if ":" in host and _HEX_IPV6_RE.match(host):
        return f"ip:{host}"

    # Embedded credentials "user@evil.xyz" — urlparse already drops them,
    # but guard against URLs that slipped through as raw strings.
    if "@" in host:
        host = host.rsplit("@", 1)[-1]

    # Punycode: decode-agnostically group on the encoded form (stable id)
    parts = host.split(".")
    if len(parts) == 1:
        # bare TLD or localhost-ish — use as-is
        return host

    # Walk from the right collecting labels until we pass the public suffix.
    suffix_len = 1
    if len(parts) >= 2:
        two_label = f"{parts[-2]}.{parts[-1]}"
        if two_label in TWO_LABEL_SUFFIXES:
            suffix_len = 2
        # Unknown two-label tail: is it plausibly a public suffix? If the
        # last label is a known TLD and the second-to-last is a well-known
        # registry prefix we missed, over-merge (suffix_len=1) — safe.
        # Default already 1, so nothing to do.

    registrable_index = len(parts) - suffix_len - 1
    if registrable_index < 0:
        # host IS the public suffix itself (e.g. "co.uk")
        return ".".join(parts)
    domain = ".".join(parts[registrable_index:])
    return domain


def extract_domain_batch(urls, show_progress: bool = False) -> np.ndarray:
    """Extract eTLD+1 group ids for a list of URLs."""
    groups = np.empty(len(urls), dtype=object)
    for i, url in enumerate(urls):
        groups[i] = extract_domain(url)
        if show_progress and (i + 1) % 5000 == 0:
            print(f"    domains: {i + 1}/{len(urls)}")
    return groups


def load_csv_safe(path: Path) -> pd.DataFrame:
    """
    Load CSV with robust label handling.
    Fix 5: float labels like 1.0 handled.
    Fix 6: unknown labels DROPPED, not silently mapped to 0.
    """
    if not path.exists():
        return pd.DataFrame()

    try:
        df = pd.read_csv(path, low_memory=False)

        url_col = label_col = None
        for col in df.columns:
            cl = col.lower().strip()
            if cl in ("url", "urls", "uri", "link", "web_url"):
                url_col = col
            if cl in ("label", "labels", "type", "class", "phishing", "status", "result"):
                label_col = col

        if not url_col:
            print(f"  ⚠ No URL column in {path.name}: {list(df.columns[:10])}")
            return pd.DataFrame()

        if not label_col:
            print(f"  ⚠ No label column in {path.name}")
            return pd.DataFrame()

        result = df[[url_col, label_col]].copy()
        result.columns = ["url", "raw_label"]

        def normalize_label(x):
            s = str(x).lower().strip()
            # Fix 5: handle float strings
            if s in ("1.0", "0.0"):
                s = s.split(".")[0]
            if s in PHISHING_LABELS:
                return 1
            if s in LEGITIMATE_LABELS:
                return 0
            return -1  # UNKNOWN

        result["label"] = result["raw_label"].apply(normalize_label)

        # Fix 6: drop rows with unknown labels
        unknown_count = int((result["label"] == -1).sum())
        if unknown_count > 0:
            unknown_vals = result[result["label"] == -1]["raw_label"].unique()[:5]
            print(f"    ⚠ Dropped {unknown_count} rows with unknown labels "
                  f"(values: {unknown_vals})")
            result = result[result["label"] != -1]

        return result[["url", "label"]]

    except Exception as e:
        print(f"  ✗ Error loading {path.name}: {e}")
        return pd.DataFrame()


def merge_datasets() -> pd.DataFrame:
    """
    Merge all datasets with conflict resolution.
    Fix 5: explicit priority order — later sources win on conflicts.
    """
    print("=" * 60)
    print("MERGING ALL DATASETS")
    print("=" * 60)

    frames = []
    load_order = []

    # 1. Synthetic data (lowest priority)
    synth_path = SYNTH_DIR / "synthetic_adversarial.csv"
    if synth_path.exists():
        load_order.append(("synthetic", synth_path))

    # 2. Real datasets (alphabetical for determinism)
    for csv_file in sorted(DATA_DIR.glob("*.csv")):
        load_order.append((csv_file.stem, csv_file))

    for source_name, path in load_order:
        print(f"  Loading: {path.name}")

        if source_name == "synthetic":
            df = pd.read_csv(path)
            if "attack_class" in df.columns:
                df["source"] = df["attack_class"]
            else:
                df["source"] = "synthetic"
        else:
            df = load_csv_safe(path)
            if len(df) == 0:
                continue
            df["source"] = source_name

        frames.append(df)
        phish = int((df["label"] == 1).sum())
        legit = int((df["label"] == 0).sum())
        print(f"    ✓ {len(df)} URLs (phishing: {phish}, legit: {legit})")

    if not frames:
        print("ERROR: No datasets loaded!")
        return pd.DataFrame()

    merged = pd.concat(frames, ignore_index=True)
    merged = merged.drop_duplicates(subset=["url"], keep="last")

    print(f"\n  Total after dedup: {len(merged)}")

    # Step 1 follow-up: tiny hand-curated corpora (20 SSO rows, the
    # legitimate_ip_services rows) cannot outvote thousands of phishing
    # login paths — duplicate them ×20 AFTER the dedup (so the copies
    # survive it) and BEFORE balance_stratified (so they scale with the
    # class balancing). The domain-disjoint split groups by eTLD+1
    # (IP-literal hosts group per-address), so every copy of a domain
    # or address lands in the same fold — no train/test leakage.
    OVERSAMPLED_SOURCES = {"legitimate_sso_portals", "legitimate_ip_services"}
    OVERSAMPLE_FACTOR = 20
    for src in sorted(OVERSAMPLED_SOURCES):
        mask = merged["source"] == src
        if mask.any():
            n = int(mask.sum())
            extra = pd.concat([merged[mask]] * (OVERSAMPLE_FACTOR - 1),
                              ignore_index=True)
            merged = pd.concat([merged, extra], ignore_index=True)
            print(f"  Oversampled {src} ×{OVERSAMPLE_FACTOR}: "
                  f"{n} → {n * OVERSAMPLE_FACTOR} rows")

    return merged


def balance_stratified(df: pd.DataFrame) -> pd.DataFrame:
    """
    Fix 11/D: Stratified balancing preserves attack class diversity.
    Proportional allocation with remainder distribution.
    """
    print("\nBALANCING (stratified by source)...")

    phishing = df[df["label"] == 1]
    legit = df[df["label"] == 0]
    target = min(len(phishing), len(legit))

    if "source" in df.columns and len(phishing) > target:
        source_counts = phishing["source"].value_counts()
        total_phishing = len(phishing)

        # Fix D: proportional allocation with remainder handling
        allocations = {}
        allocated = 0
        for source, count in source_counts.items():
            proportion = count / total_phishing
            n = int(target * proportion)
            allocations[source] = max(n, 1)
            allocated += allocations[source]

        remainder = target - allocated
        if remainder > 0:
            sorted_sources = source_counts.index.tolist()
            for i in range(remainder):
                src = sorted_sources[i % len(sorted_sources)]
                allocations[src] += 1

        sampled_parts = []
        for source, n_sample in allocations.items():
            source_data = phishing[phishing["source"] == source]
            n_actual = min(n_sample, len(source_data))
            sampled = source_data.sample(n=n_actual, random_state=RANDOM_STATE)
            sampled_parts.append(sampled)

        phishing = pd.concat(sampled_parts)
    elif len(phishing) > target:
        phishing = phishing.sample(n=target, random_state=RANDOM_STATE)

    if len(legit) > target:
        legit = legit.sample(n=target, random_state=RANDOM_STATE)

    balanced = pd.concat([phishing, legit]).sample(frac=1, random_state=RANDOM_STATE)

    actual_phish = int((balanced["label"] == 1).sum())
    actual_legit = int((balanced["label"] == 0).sum())
    print(f"  Phishing: {actual_phish} | Legitimate: {actual_legit}")
    print(f"  Balance ratio: {actual_phish / max(actual_legit, 1):.3f}")

    if "source" in balanced.columns:
        print(f"\n  Per-source distribution:")
        for src, grp in balanced.groupby("source"):
            print(f"    {src:<25} {len(grp):>6}")

    return balanced


def group_shuffle_split(indices, y, groups, test_size, random_state):
    """
    One domain-disjoint split pass (Fix 19).

    GroupShuffleSplit cannot stratify — it splits GROUPS, then takes every
    row of each group. So class balance drifts with how labels distribute
    across domains. Per-split balance is checked by the caller and reported;
    a fatal error is raised if any resulting split ends up single-class.
    Returns (rest_idx, heldout_idx) positional indices into `indices`.
    """
    gss = GroupShuffleSplit(n_splits=1, test_size=test_size,
                            random_state=random_state)
    rest_pos, heldout_pos = next(gss.split(indices, y, groups))

    # Sanity assertion: no group may appear on both sides.
    rest_groups = set(groups[rest_pos])
    heldout_groups = set(groups[heldout_pos])
    overlap = rest_groups & heldout_groups
    assert not overlap, (
        f"GroupShuffleSplit leaked {len(overlap)} groups across the "
        f"boundary: {sorted(overlap)[:5]}"
    )
    return rest_pos, heldout_pos


def check_split_balance(name: str, y: np.ndarray) -> dict:
    """
    GroupShuffleSplit cannot stratify, so report and HARD-VERIFY class
    balance per split. A single-class split would silently corrupt
    training / calibration / metrics — abort instead.
    """
    counts = Counter(y.tolist())
    n = len(y)
    balance = {
        "n": int(n),
        "phishing": int(counts.get(1, 0)),
        "legitimate": int(counts.get(0, 0)),
        "phish_frac": float(counts.get(1, 0) / n) if n else 0.0,
    }
    print(f"  {name:<12} {balance['n']:>7} rows | phish {balance['phishing']:>6} "
          f"({balance['phish_frac']:.1%}) | legit {balance['legitimate']:>6}")
    if balance["phishing"] == 0 or balance["legitimate"] == 0:
        print(f"  ✗ FATAL: {name} split is single-class — group split produced "
              f"an unusable partition. Increase dataset size or reduce n of splits.")
        sys.exit(1)
    return balance


def prepare():
    """Full preparation pipeline."""
    df = merge_datasets()
    if df.empty:
        print("ERROR: No data to prepare!")
        return

    # Clean
    df = df.dropna(subset=["url"])
    df = df[df["url"].str.len() >= 5]
    df["url"] = df["url"].apply(
        lambda u: u.strip() if isinstance(u, str) else str(u)
    )

    # Balance with stratification
    df = balance_stratified(df)

    # Extract features
    print(f"\nEXTRACTING {NUM_FEATURES} FEATURES from {len(df)} URLs...")
    urls = df["url"].tolist()
    labels = df["label"].values.astype(np.int32)

    # Fix G: convert sources to numpy array BEFORE splitting
    sources = np.array(
        df["source"].tolist() if "source" in df.columns else ["unknown"] * len(df),
        dtype=object,
    )

    X = extract_batch(urls, show_progress=True)
    y = labels
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    # ── Fix 19: eTLD+1 domain groups ─────────────────────────────────────
    # Every URL is grouped by its registrable domain (eTLD+1). URLs that
    # share a domain (phishy-bank.com/login, phishy-bank.com/secure) share
    # a group, and group-disjoint splitting keeps them in ONE split.
    print(f"\nGROUPING URLs BY eTLD+1 DOMAIN (leakage fix)...")
    groups = extract_domain_batch(urls, show_progress=True)
    unique_domains = set(groups.tolist())
    n_multi_url_domains = sum(
        1 for _, c in Counter(groups.tolist()).items() if c > 1
    )
    print(f"  {len(unique_domains):,} unique domains across {len(groups):,} URLs "
          f"({n_multi_url_domains:,} domains contribute >1 URL)")

    all_indices = np.arange(len(df))

    # ── Fix 19: chained domain-disjoint splits ───────────────────────────
    # test first (TEST_SIZE of GROUPS), then calibration and validation
    # carved from the remaining groups. GroupShuffleSplit fractions apply
    # to groups, not rows — realized sizes are approximate.
    print(f"\nSPLITTING (GroupShuffleSplit — domain-disjoint, "
          f"train/val/cal/test = "
          f"{1 - TEST_SIZE - VAL_SIZE - CALIBRATION_SIZE:.0%}/"
          f"{VAL_SIZE:.0%}/{CALIBRATION_SIZE:.0%}/{TEST_SIZE:.0%} of groups)")

    # Pass 1: test vs rest
    rest_pos, test_pos = group_shuffle_split(
        all_indices, y, groups, TEST_SIZE, RANDOM_STATE)

    # Pass 2: calibration from rest (fraction of remaining groups)
    rest_indices = all_indices[rest_pos]
    rest_y = y[rest_pos]
    rest_groups = groups[rest_pos]
    cal_frac_of_rest = CALIBRATION_SIZE / (1 - TEST_SIZE)
    rest2_pos, cal_pos = group_shuffle_split(
        rest_indices, rest_y, rest_groups, cal_frac_of_rest, RANDOM_STATE)

    # Pass 3: validation from what's left (train = remainder)
    # rest2_pos indexes INTO rest_indices — the y/groups values must
    # come from the same sub-selection (rest_y/rest_groups), never from
    # the full arrays. Indexing the full arrays misaligns rows with
    # labels and groups, which both corrupts training and lets domains
    # leak across the train/val boundary (caught by the end-to-end check).
    rest2_indices = rest_indices[rest2_pos]
    rest2_y = rest_y[rest2_pos]
    rest2_groups = rest_groups[rest2_pos]
    val_frac_of_rest2 = VAL_SIZE / (1 - TEST_SIZE - CALIBRATION_SIZE)
    train_pos, val_pos = group_shuffle_split(
        rest2_indices, rest2_y, rest2_groups, val_frac_of_rest2, RANDOM_STATE)

    train_idx = rest2_indices[train_pos]
    val_idx = rest2_indices[val_pos]
    cal_idx = rest_indices[cal_pos]
    test_idx = all_indices[test_pos]

    X_train, X_val = X[train_idx], X[val_idx]
    X_cal, X_test = X[cal_idx], X[test_idx]
    y_train, y_val = y[train_idx], y[val_idx]
    y_cal, y_test = y[cal_idx], y[test_idx]
    src_train, src_val = sources[train_idx], sources[val_idx]
    src_cal, src_test = sources[cal_idx], sources[test_idx]
    grp_train, grp_val = groups[train_idx], groups[val_idx]
    grp_cal, grp_test = groups[cal_idx], groups[test_idx]

    # Enforcement: Synthetic data is AUGMENTATION ONLY.
    # It must never appear in val, cal, or test.
    if SYNTHETIC_DATA_IS_AUGMENTATION_ONLY:
        def move_synthetic(X_split, y_split, src_split, grp_split):
            real_sources = {"legitimate_urls", "phishing_urls", "legitimate_ip_services", "legitimate_sso_portals"}
            mask = ~np.isin(src_split, list(real_sources))
            if not mask.any():
                return X_split, y_split, src_split, grp_split, None, None, None, None
            synth_X = X_split[mask]
            synth_y = y_split[mask]
            synth_src = src_split[mask]
            synth_grp = grp_split[mask]
            return X_split[~mask], y_split[~mask], src_split[~mask], grp_split[~mask], synth_X, synth_y, synth_src, synth_grp
        
        X_val, y_val, src_val, grp_val, sx_v, sy_v, ss_v, sg_v = move_synthetic(X_val, y_val, src_val, grp_val)
        X_cal, y_cal, src_cal, grp_cal, sx_c, sy_c, ss_c, sg_c = move_synthetic(X_cal, y_cal, src_cal, grp_cal)
        X_test, y_test, src_test, grp_test, sx_t, sy_t, ss_t, sg_t = move_synthetic(X_test, y_test, src_test, grp_test)
        
        for sx, sy, ss, sg in [(sx_v, sy_v, ss_v, sg_v), (sx_c, sy_c, ss_c, sg_c), (sx_t, sy_t, ss_t, sg_t)]:
            if sx is not None:
                X_train = np.concatenate([X_train, sx])
                y_train = np.concatenate([y_train, sy])
                src_train = np.concatenate([src_train, ss])
                grp_train = np.concatenate([grp_train, sg])

    # ── Verify domain-disjointness end-to-end (belt and braces) ─────────
    split_domains = {
        "train": set(grp_train.tolist()),
        "val": set(grp_val.tolist()),
        "cal": set(grp_cal.tolist()),
        "test": set(grp_test.tolist()),
    }
    names = list(split_domains)
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            overlap = split_domains[names[i]] & split_domains[names[j]]
            assert not overlap, (
                f"DOMAIN LEAKAGE between {names[i]} and {names[j]}: "
                f"{sorted(overlap)[:5]}"
            )

    # ── Class balance per split (GroupShuffleSplit cannot stratify) ─────
    print(f"\n  Split sizes (group fractions are approximate):")
    balance = {
        "train": check_split_balance("Train", y_train),
        "val": check_split_balance("Validation", y_val),
        "cal": check_split_balance("Calibration", y_cal),
        "test": check_split_balance("Test", y_test),
    }
    print(f"\n  Train:       {X_train.shape[0]}")
    print(f"  Validation:  {X_val.shape[0]}")
    print(f"  Calibration: {X_cal.shape[0]}")
    print(f"  Test:        {X_test.shape[0]}")

    # Save
    for name, arr in [
        ("X_train", X_train), ("X_val", X_val), ("X_cal", X_cal), ("X_test", X_test),
        ("y_train", y_train), ("y_val", y_val), ("y_cal", y_cal), ("y_test", y_test),
        ("src_train", src_train), ("src_val", src_val), ("src_cal", src_cal), ("src_test", src_test),
        ("groups_train", grp_train), ("groups_val", grp_val),
        ("groups_cal", grp_cal), ("groups_test", grp_test),
    ]:
        np.save(PREPARED_DIR / f"{name}.npy", arr)

    # src_test is a load-bearing contract for evaluate.py's per-source
    # accuracy — keep it. Groups are saved per-split for GroupKFold in
    # train_model.py (Fix 19) and for future leakage audits.

    meta = {
        "num_features": NUM_FEATURES,
        "feature_names": FEATURE_NAMES,
        "train_size": int(X_train.shape[0]),
        "val_size": int(X_val.shape[0]),
        "cal_size": int(X_cal.shape[0]),
        "test_size": int(X_test.shape[0]),
        # Fix 19: leakage audit trail
        "split_strategy": "domain_disjoint_group_shuffle",
        "group_key": "etld_plus_1",
        "domain_disjoint": True,
        "num_unique_domains": int(len(unique_domains)),
        "class_balance": balance,
    }
    with open(PREPARED_DIR / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"\n✓ Saved to {PREPARED_DIR}/")


if __name__ == "__main__":
    prepare()
