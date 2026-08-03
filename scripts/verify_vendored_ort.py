#!/usr/bin/env python3
"""Verify the vendored ONNX Runtime files against their pinned checksums.

The extension loads `extension/lib/ort.min.js` and its WASM binaries from disk.
Fetching executable WASM from a CDN at runtime would be remote code execution by
design (THREAT-MODEL.md section 5), so the files are committed and this script is
the integrity check. Run it in CI.

Pass --refetch to re-download the pinned npm tarball and rewrite the files; the
checksums are still enforced afterwards, so a tampered tarball fails loudly.
"""

import argparse
import hashlib
import io
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

ORT_VERSION = "1.17.3"
TARBALL_URL = (
    f"https://registry.npmjs.org/onnxruntime-web/-/onnxruntime-web-{ORT_VERSION}.tgz"
)
LIB_DIR = Path(__file__).resolve().parent.parent / "extension" / "lib"
CHECKSUMS = LIB_DIR / "CHECKSUMS.txt"


def read_checksums() -> dict[str, str]:
    expected = {}
    for line in CHECKSUMS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, name = line.split(None, 1)
        expected[name.strip().lstrip("*")] = digest
    return expected


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def refetch(names: list[str]) -> None:
    print(f"Fetching {TARBALL_URL}")
    with urllib.request.urlopen(TARBALL_URL, timeout=180) as resp:
        blob = resp.read()
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        for name in names:
            member = tar.getmember(f"package/dist/{name}")
            src = tar.extractfile(member)
            if src is None:
                raise SystemExit(f"{name} missing from tarball")
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                shutil.copyfileobj(src, tmp)
                tmp_path = Path(tmp.name)
            tmp_path.replace(LIB_DIR / name)
            print(f"  wrote {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refetch", action="store_true")
    args = parser.parse_args()

    expected = read_checksums()
    if args.refetch:
        refetch(list(expected))

    failed = False
    for name, want in expected.items():
        path = LIB_DIR / name
        if not path.is_file():
            print(f"MISSING  {name} — run with --refetch")
            failed = True
            continue
        got = sha256(path)
        if got != want:
            print(f"MISMATCH {name}\n  expected {want}\n  got      {got}")
            failed = True
        else:
            print(f"ok       {name}")

    if failed:
        print("\nVendored ONNX Runtime failed verification.", file=sys.stderr)
        return 1
    print(f"\nAll {len(expected)} files match onnxruntime-web {ORT_VERSION}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
