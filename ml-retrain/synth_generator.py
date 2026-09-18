"""
PhishGuard ML v4.1 — Synthetic Adversarial Dataset Generator

Generates realistic phishing and legitimate URLs for training.

Fixes applied:
  - Fix 3/C (rev 2): legit IP half made feature-separable (clean
    paths, no explicit port, mixed scheme) — no feature encodes IP
    range, so range-only distinction was label noise; 20% of legit
    rows kept as honest hard negatives
  - Fix 7:   Valid punycode with pre-validated homoglyphs
  - Fix 8:   Real domain+path combos for legitimate URLs
  - Fix B:   URL shortener generator REMOVED (adds noise, not signal)
"""

import random
import string
import pandas as pd
from typing import List, Tuple
from config import (
    SYNTH_DIR, TARGET_BRANDS, SUSPICIOUS_HOSTS,
    PHISH_KEYWORDS, RANDOM_STATE, REAL_LOGIN_PATHS,
)

random.seed(RANDOM_STATE)

# Suspicious TLDs for synthetic generation (without leading dot)
_SYNTH_SUSPICIOUS_TLDS = [
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click",
    "buzz", "work", "link", "surf", "rest", "fit", "icu",
    "cam", "monster", "uno", "site", "online", "live",
]

_SENSITIVE_KEYWORDS = list({
    "login", "signin", "verify", "account", "update",
    "confirm", "password", "credential", "secure", "auth",
    "bank", "payment", "billing", "checkout", "wallet",
    "suspend", "locked", "unusual", "alert", "expire",
})


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PHISHING GENERATORS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def gen_typosquatting(count: int = 30000) -> List[Tuple[str, int, str]]:
    """Attack Class 1: Typosquatting — single-char mutations of known brands."""
    urls: List[Tuple[str, int, str]] = []

    def single_char_replace(word: str, old: str, new: str) -> str:
        idx = word.find(old)
        if idx == -1:
            return word
        return word[:idx] + new + word[idx + 1:]

    mutations = [
        lambda w: single_char_replace(w, "a", "4"),
        lambda w: single_char_replace(w, "o", "0"),
        lambda w: single_char_replace(w, "l", "1"),
        lambda w: single_char_replace(w, "i", "1"),
        lambda w: single_char_replace(w, "e", "3"),
        lambda w: single_char_replace(w, "s", "5"),
        lambda w: single_char_replace(w, "a", "@"),
        lambda w: single_char_replace(w, "g", "9"),
        lambda w: (w[:1] + w[2] + w[1] + w[3:]) if len(w) > 3 else w,
        lambda w: w[:len(w) // 2] + w[len(w) // 2] + w[len(w) // 2:] if len(w) > 2 else w,
        lambda w: w[:len(w) // 2] + w[len(w) // 2 + 1:] if len(w) > 3 else w,
        lambda w: w + random.choice("sx"),
    ]

    paths = ["/login", "/signin", "/verify", "/account", "/update",
             "/secure", "/auth", "/confirm", "", "/index.html"]

    per_brand = count // len(TARGET_BRANDS)
    for brand in TARGET_BRANDS:
        for _ in range(per_brand):
            mutation = random.choice(mutations)
            mutated = mutation(brand)
            if mutated == brand:
                mutated = brand + random.choice(["1", "-secure", "-login"])

            tld = random.choice(_SYNTH_SUSPICIOUS_TLDS)
            path = random.choice(paths)
            scheme = random.choice(["http://", "https://"])

            patterns = [
                f"{scheme}{mutated}.{tld}{path}",
                f"{scheme}{mutated}-login.{tld}{path}",
                f"{scheme}secure-{mutated}.{tld}{path}",
                f"{scheme}www.{mutated}.{tld}{path}",
            ]
            urls.append((random.choice(patterns), 1, "typosquatting"))

    print(f"  ✓ Typosquatting: {len(urls)} URLs")
    return urls[:count]


def _validate_no_phish_keywords(url: str) -> None:
    PHISH_KEYWORDS = {"secure", "account", "banking", "login", "signin", "verify", "update", "confirm", "password", "suspend", "alert", "unusual", "restore", "unlock"}
    if any(kw in url.lower() for kw in PHISH_KEYWORDS):
        raise ValueError(f"SYNTHETIC DATA CONTAINS PHISH KEYWORD: {url}")


def gen_ip_based(count: int = 20000) -> List[Tuple[str, int, str]]:
    """
    Attack Class 2: IP-based hosting.

    f17_isIpAddress is a single bit set for BOTH halves and no feature
    encodes public-vs-private range, so the old "distinguish by IP
    range" design put feature-identical rows under opposite labels —
    pure label noise (~2/3 of run-2's test FPs came from it). Now the
    legit half is feature-separable: 80% draw clean device-admin paths
    (none in PHISH_KEYWORDS), carry no explicit port, and mix
    https/http scheme. The remaining 20% keep the old keyword-path
    style as honest hard negatives, so the model must tolerate private
    router/NAS admin pages instead of learning a blanket "IP + login
    path ⇒ phishing" rule. The phishing half is unchanged (public
    IPs, all 12 paths, exotic ports, http) — golden-set URLs
    45.67.89.123/login.php and 192.0.2.1:8080/signin live in that
    region and must stay classified PHISHING.
    """
    urls: List[Tuple[str, int, str]] = []

    all_paths = [
        "/login", "/admin", "/dashboard", "/", "/index.html",
        "/login.php", "/signin", "/verify", "/status", "/config",
        "/api/health", "/account",
    ]

    # Device-admin paths for the separable legit majority — none of
    # these appear in PHISH_KEYWORDS, so these rows carry keyword-free
    # signal instead of landing in the phishing path region.
    clean_paths = [
        "/", "/index.html", "/status", "/config",
        "/api/health", "/dashboard", "/admin",
    ]

    # Invariant: the clean majority's paths must never collide with
    # PHISH_KEYWORDS — that collision is the label noise this redesign
    # removes. Fail loudly if either list ever drifts.
    assert not any(
        kw in path for path in clean_paths for kw in PHISH_KEYWORDS
    ), "clean_paths must stay free of PHISH_KEYWORDS"

    phishing_count = int(count * 0.7)
    legit_count = count - phishing_count
    hard_count = legit_count // 5  # ~20% honest hard negatives

    # Phishing: PUBLIC IPs
    private_first_octets = {10, 127, 172, 192}
    for _ in range(phishing_count):
        first_octet = random.choice(
            [i for i in range(1, 224) if i not in private_first_octets]
        )
        ip = (
            f"{first_octet}.{random.randint(0, 255)}"
            f".{random.randint(0, 255)}.{random.randint(1, 254)}"
        )
        path = random.choice(all_paths)
        port = random.choice(["", ":8080", ":8443", ":3000"])
        urls.append((f"http://{ip}{port}{path}", 1, "ip_phishing"))

    # Legitimate: PRIVATE IPs (192.168.x.x, 10.x.x.x) — 80% separable
    # (clean path, no explicit port, mixed scheme), 20% honest hard
    # negatives in the old keyword-path style.
    for i in range(legit_count):
        ip_type = random.choice(["router", "nas", "internal"])
        if ip_type == "router":
            ip = random.choice(
                ["192.168.1.1", "192.168.0.1", "10.0.0.1", "10.0.1.1"]
            )
        elif ip_type == "nas":
            ip = f"192.168.1.{random.randint(2, 254)}"
        else:
            ip = (
                f"10.{random.randint(0, 255)}"
                f".{random.randint(0, 255)}.{random.randint(1, 254)}"
            )
        if i < hard_count:
            # Honest hard negative: keyword path, exotic port, http —
            # the old style, kept so the model cannot learn a blanket
            # "IP + login path ⇒ phishing" rule and must tolerate
            # private router/NAS admin pages.
            path = random.choice(all_paths)
            port = random.choice(["", ":8080", ":9090", ":3000", ":80"])
            scheme = "http://"
        else:
            # Feature-separable majority: clean path, no explicit port
            # (f22=0), mixed scheme (f23 carries real signal — the
            # phishing half is 100% http).
            path = random.choice(clean_paths)
            port = ""
            scheme = random.choice(["https://", "http://"])
        urls.append((f"{scheme}{ip}{port}{path}", 0, "ip_legitimate"))

    random.shuffle(urls)
    print(f"  ✓ IP-based: {len(urls)} URLs ({phishing_count} phish, "
          f"{legit_count} legit: {legit_count - hard_count} separable, "
          f"{hard_count} hard)")
    return urls[:count]


def gen_subdomain_abuse(count: int = 25000) -> List[Tuple[str, int, str]]:
    """Attack Class 3: Excessive subdomains hiding real domain."""
    urls: List[Tuple[str, int, str]] = []
    for _ in range(count):
        brand = random.choice(TARGET_BRANDS)
        tld = random.choice(_SYNTH_SUSPICIOUS_TLDS)
        depth = random.randint(2, 6)

        subdomains = []
        for _ in range(depth):
            sub_type = random.choice(["brand", "keyword", "random"])
            if sub_type == "brand":
                subdomains.append(brand)
            elif sub_type == "keyword":
                subdomains.append(random.choice(_SENSITIVE_KEYWORDS))
            else:
                subdomains.append(
                    "".join(random.choices(string.ascii_lowercase, k=random.randint(3, 8)))
                )

        real_domain = "".join(
            random.choices(string.ascii_lowercase, k=random.randint(5, 12))
        )
        hostname = ".".join(subdomains) + f".{real_domain}.{tld}"
        path = random.choice(["/login", "/verify", "/account", "/", "/index.html"])
        urls.append((f"https://{hostname}{path}", 1, "subdomain_abuse"))

    print(f"  ✓ Subdomain abuse: {len(urls)} URLs")
    return urls[:count]


def gen_suspicious_hosting(count: int = 20000) -> List[Tuple[str, int, str]]:
    """Attack Class 4: Free hosting/tunnel abuse."""
    urls: List[Tuple[str, int, str]] = []
    for _ in range(count):
        host = random.choice(SUSPICIOUS_HOSTS)
        brand = random.choice(TARGET_BRANDS)
        subdomain = random.choice([
            f"{brand}-login",
            f"secure-{brand}",
            f"{brand}-verify",
            "".join(random.choices(string.ascii_lowercase + string.digits, k=12)),
        ])
        path = random.choice(["/login", "/verify", "/signin", "/", "/auth"])
        urls.append((f"https://{subdomain}.{host}{path}", 1, "suspicious_hosting"))

    print(f"  ✓ Suspicious hosting: {len(urls)} URLs")
    return urls[:count]


def gen_punycode_homograph(count: int = 15000) -> List[Tuple[str, int, str]]:
    """
    Attack Class 5: Punycode/IDN Homograph attacks.
    Fix 7: Use pre-validated homoglyphs that survive IDNA encoding.
    """
    urls: List[Tuple[str, int, str]] = []

    SAFE_HOMOGLYPHS = {
        "a": "\u0430",  # Cyrillic а
        "e": "\u0435",  # Cyrillic е
        "o": "\u043e",  # Cyrillic о
        "p": "\u0440",  # Cyrillic р
        "c": "\u0441",  # Cyrillic с
        "x": "\u0445",  # Cyrillic х
        "y": "\u0443",  # Cyrillic у
    }

    tlds = ["com", "net", "org"]
    paths = ["/login", "/verify", "/account", "/", "/signin"]

    per_brand = count // len(TARGET_BRANDS)
    for brand in TARGET_BRANDS:
        replaceable = [(i, c) for i, c in enumerate(brand) if c in SAFE_HOMOGLYPHS]
        if not replaceable:
            continue

        for _ in range(per_brand):
            chars = list(brand)
            idx, char = random.choice(replaceable)
            chars[idx] = SAFE_HOMOGLYPHS[char]
            spoofed = "".join(chars)

            tld = random.choice(tlds)
            path = random.choice(paths)

            try:
                full_domain = f"{spoofed}.{tld}"
                punycode_domain = full_domain.encode("idna").decode("ascii")
                urls.append((f"https://{punycode_domain}{path}", 1, "punycode"))
            except (UnicodeError, UnicodeDecodeError):
                fake_puny = (
                    f"xn--{brand[:3]}{random.randint(10, 99)}a"
                    f"-{random.choice('bcdefg')}ua"
                )
                urls.append((f"https://{fake_puny}.{tld}{path}", 1, "punycode"))

    print(f"  ✓ Punycode/Homograph: {len(urls)} URLs")
    return urls[:count]


def gen_long_domain_obfuscation(count: int = 15000) -> List[Tuple[str, int, str]]:
    """Attack Class 6: Long domain names stuffed with keywords."""
    urls: List[Tuple[str, int, str]] = []
    for _ in range(count):
        brand = random.choice(TARGET_BRANDS)
        padding_words = random.choices(
            _SENSITIVE_KEYWORDS, k=random.randint(3, 8)
        )
        separator = random.choice(["-", "."])
        domain = separator.join([brand] + padding_words)
        tld = random.choice(_SYNTH_SUSPICIOUS_TLDS)
        path = random.choice(["/login", "/verify", "/", "/auth"])
        urls.append((f"https://{domain}.{tld}{path}", 1, "long_domain"))

    print(f"  ✓ Long domain obfuscation: {len(urls)} URLs")
    return urls[:count]


def gen_at_trick_phishing(count: int = 10000) -> List[Tuple[str, int, str]]:
    """Attack Class 7: @ symbol URL trick."""
    urls: List[Tuple[str, int, str]] = []
    fake_domains = [
        "secure-bank.com", "paypal.com", "apple.com",
        "microsoft.com", "google.com",
    ]
    for _ in range(count):
        fake_domain = random.choice(fake_domains)
        real_domain = "".join(random.choices(string.ascii_lowercase, k=8))
        tld = random.choice(_SYNTH_SUSPICIOUS_TLDS)
        path = random.choice(["/login", "/verify", "/account"])
        urls.append((
            f"http://{fake_domain}@{real_domain}.{tld}{path}",
            1,
            "at_trick",
        ))

    print(f"  ✓ @ trick phishing: {len(urls)} URLs")
    return urls[:count]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LEGITIMATE GENERATORS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def gen_legitimate_login_pages(count: int = 50000) -> List[Tuple[str, int, str]]:
    """
    Fix 8/12: Use REAL domain+path combinations.
    Only generate URLs with verified real paths.
    """
    urls: List[Tuple[str, int, str]] = []

    # Use verified real paths
    per_domain = count // (len(REAL_LOGIN_PATHS) * 3)
    for domain, paths in REAL_LOGIN_PATHS.items():
        for path in paths:
            for _ in range(per_domain):
                query = random.choice([
                    "",
                    "?next=/dashboard",
                    "?redirect_uri=https://app.example.com",
                    f"?session={random.randbytes(4).hex()}",
                ])
                urls.append((f"https://{domain}{path}{query}", 0, "legit_login"))

    # Educational institutions
    edu_domains = [
        ("vit.ac.in", ["/vtop/login", "/", "/students"]),
        ("mit.edu", ["/", "/admissions", "/courses"]),
        ("stanford.edu", ["/", "/admissions", "/login"]),
        ("iitb.ac.in", ["/", "/academics", "/login"]),
        ("ox.ac.uk", ["/", "/admissions", "/students"]),
    ]
    per_edu = count // (len(edu_domains) * 10)
    for domain, paths in edu_domains:
        for path in paths:
            for _ in range(per_edu):
                urls.append((f"https://{domain}{path}", 0, "legit_edu"))

    # Government sites
    gov_domains = [
        ("irs.gov", ["/", "/refunds", "/filing"]),
        ("usa.gov", ["/", "/services"]),
        ("india.gov.in", ["/", "/services"]),
        ("gov.uk", ["/", "/services"]),
    ]
    per_gov = count // (len(gov_domains) * 10)
    for domain, paths in gov_domains:
        for path in paths:
            for _ in range(per_gov):
                urls.append((f"https://{domain}{path}", 0, "legit_gov"))

    random.shuffle(urls)
    print(f"  ✓ Legitimate login pages: {len(urls)} URLs (real paths only)")
    return urls[:count]


def gen_legitimate_normal(count: int = 30000) -> List[Tuple[str, int, str]]:
    """Normal legitimate pages (news, tools, social media)."""
    urls: List[Tuple[str, int, str]] = []
    sites = [
        ("cnn.com", ["/news", "/politics", "/", "/world"]),
        ("bbc.com", ["/news", "/", "/sport"]),
        ("youtube.com", ["/", "/watch?v=abc123", "/channel/xyz"]),
        ("reddit.com", ["/", "/r/technology", "/r/science"]),
        ("stackoverflow.com", ["/", "/questions", "/search?q=python"]),
        ("github.com", ["/", "/trending", "/explore"]),
        ("fast.com", ["/"]),
        ("weather.com", ["/", "/forecast"]),
        ("wikipedia.org", ["/", "/wiki/Python"]),
    ]
    per_site = count // (len(sites) * 3)
    for domain, paths in sites:
        for path in paths:
            for _ in range(per_site):
                urls.append((f"https://{domain}{path}", 0, "legit_normal"))

    random.shuffle(urls)
    print(f"  ✓ Legitimate normal: {len(urls)} URLs")
    return urls[:count]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MAIN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def generate_all():
    """Generate complete synthetic dataset with attack class labels."""
    print("=" * 60)
    print("PHISHGUARD ML v4.1 — SYNTHETIC GENERATOR")
    print("=" * 60)

    all_urls: List[Tuple[str, int, str]] = []

    print("\n── Phishing Attack Classes ──")
    all_urls.extend(gen_typosquatting(30000))
    all_urls.extend(gen_ip_based(20000))
    all_urls.extend(gen_subdomain_abuse(25000))
    all_urls.extend(gen_suspicious_hosting(20000))
    all_urls.extend(gen_punycode_homograph(15000))
    all_urls.extend(gen_long_domain_obfuscation(15000))
    all_urls.extend(gen_at_trick_phishing(10000))

    print("\n── Legitimate Edge Cases ──")
    all_urls.extend(gen_legitimate_login_pages(50000))
    all_urls.extend(gen_legitimate_normal(30000))

    random.shuffle(all_urls)

    df = pd.DataFrame(all_urls, columns=["url", "label", "attack_class"])
    output = SYNTH_DIR / "synthetic_adversarial.csv"
    df.to_csv(output, index=False)

    phishing = int((df["label"] == 1).sum())
    legit = int((df["label"] == 0).sum())

    print(f"\n{'=' * 60}")
    print(f"TOTAL: {len(df)} | Phishing: {phishing} | Legit: {legit}")
    print(f"\nPer-class breakdown:")
    for cls, group in df.groupby("attack_class"):
        label = int(group["label"].iloc[0])
        print(f"  {cls:<25} {len(group):>6} ({'phishing' if label == 1 else 'legit'})")
    print(f"{'=' * 60}")

    return output


if __name__ == "__main__":
    generate_all()

def generate_legitimate_ip() -> str:
    clean_paths = ["/", "/index.html", "/status", "/config", "/api/health", "/dashboard", "/admin"]
    ip_type = random.choice(["router", "nas", "internal"])
    if ip_type == "router":
        ip = random.choice(["192.168.1.1", "192.168.0.1", "10.0.0.1", "10.0.1.1"])
    elif ip_type == "nas":
        ip = f"192.168.1.{random.randint(2, 254)}"
    else:
        ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    path = random.choice(clean_paths)
    scheme = random.choice(["https://", "http://"])
    url = f"{scheme}{ip}{path}"
    _validate_no_phish_keywords(url)
    return url

def generate_phishing_ip() -> str:
    private_first_octets = {10, 127, 172, 192}
    first_octet = random.choice([i for i in range(1, 224) if i not in private_first_octets])
    ip = f"{first_octet}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    clean_paths = ["/", "/index.html", "/status", "/config", "/api/health", "/dashboard", "/admin"]
    path = random.choice(clean_paths)
    port = random.choice(["", ":8080", ":8443", ":3000"])
    url = f"http://{ip}{port}{path}"
    _validate_no_phish_keywords(url)
    return url
