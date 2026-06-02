"""Download Practical Cryptography's English quadgrams table.

Writes data/ngrams/english_quadgrams.txt. Idempotent: if the file
already exists with the expected size, skip the download.

Usage:
    uv run python scripts/download_quadgrams.py
"""

from __future__ import annotations

import hashlib
import sys
import urllib.request
import zipfile
from io import BytesIO
from pathlib import Path

URL = "http://practicalcryptography.com/media/cryptanalysis/files/english_quadgrams.txt.zip"
TARGET = Path(__file__).resolve().parents[1] / "data" / "ngrams" / "english_quadgrams.txt"
# Approximate expected size (Practical Cryptography v1, ~389 KB).
EXPECTED_MIN_BYTES = 380_000


def main() -> int:
    if TARGET.exists() and TARGET.stat().st_size > EXPECTED_MIN_BYTES:
        print(f"already present: {TARGET} ({TARGET.stat().st_size:,} bytes)")
        return 0
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    print(f"downloading {URL} ...")
    try:
        with urllib.request.urlopen(URL, timeout=30) as r:
            data = r.read()
    except Exception as e:
        print(f"download failed: {e}", file=sys.stderr)
        print("manual fallback: download english_quadgrams.txt.zip from", file=sys.stderr)
        print(f"  {URL}", file=sys.stderr)
        print(f"and extract english_quadgrams.txt into {TARGET.parent}", file=sys.stderr)
        return 1
    sha = hashlib.sha256(data).hexdigest()
    print(f"  fetched {len(data):,} bytes; sha256={sha}")
    with zipfile.ZipFile(BytesIO(data)) as z:
        names = z.namelist()
        if "english_quadgrams.txt" not in names:
            print(f"unexpected zip contents: {names}", file=sys.stderr)
            return 2
        with z.open("english_quadgrams.txt") as src, open(TARGET, "wb") as dst:
            dst.write(src.read())
    print(f"wrote {TARGET} ({TARGET.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
