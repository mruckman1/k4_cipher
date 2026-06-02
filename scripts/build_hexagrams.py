"""Build an English hexagram count table from a corpus.

Usage:
    uv run python scripts/build_hexagrams.py \\
        --corpus data/corpora/gutenberg_english.txt \\
        --out    data/ngrams/english_hexagrams.txt \\
        [--n 6]  [--min-count 5]

Output format matches Practical Cryptography's quadgram convention so
NgramFitness.load_ngrams works directly:

    NGRAM COUNT
    NGRAM COUNT
    ...

Hexagrams (n=6) are the recommended K4 fitness function because
quadgram scores on a 73-letter string are noisy. We default to n=6
but the script handles any n.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

NON_LETTER = re.compile(r"[^A-Za-z]")


def build(corpus_path: Path, n: int, min_count: int) -> Counter[str]:
    counts: Counter[str] = Counter()
    chars_read = 0
    with open(corpus_path) as f:
        # Stream by chunks to avoid loading 100MB+ corpora at once.
        leftover = ""
        for raw in iter(lambda: f.read(1 << 20), ""):    # 1 MiB chunks
            text = NON_LETTER.sub("", (leftover + raw).upper())
            chars_read += len(text)
            for i in range(len(text) - n + 1):
                counts[text[i : i + n]] += 1
            # Keep tail of length n-1 so we don't lose n-grams across chunks.
            leftover = text[-(n - 1) :] if len(text) >= n - 1 else text
            print(f"  ... {chars_read:,} letters processed, "
                  f"{len(counts):,} distinct {n}-grams", end="\r")
    print()
    if min_count > 1:
        counts = Counter({g: c for g, c in counts.items() if c >= min_count})
        print(f"  ... pruned to {len(counts):,} {n}-grams with count >= {min_count}")
    return counts


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--corpus", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--n", type=int, default=6)
    p.add_argument("--min-count", type=int, default=5,
                   help="drop n-grams seen fewer than this many times")
    args = p.parse_args()

    if not args.corpus.exists():
        print(f"corpus not found: {args.corpus}", file=sys.stderr)
        print("see data/corpora/README.md for download pointers", file=sys.stderr)
        return 1

    counts = build(args.corpus, args.n, args.min_count)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w") as f:
        # Sort by count descending, then alphabetical.
        for ng, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
            f.write(f"{ng} {c}\n")
    print(f"wrote {args.out} ({args.out.stat().st_size:,} bytes, "
          f"{len(counts):,} {args.n}-grams)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
