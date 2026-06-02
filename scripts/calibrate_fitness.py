"""Calibrate an n-gram fitness threshold for K4-length English.

K4 has 73 unconstrained positions (97 letters minus 24 crib letters).
At that length, English log-likelihood scores have appreciable variance
and gibberish can outscore weak English. Without a calibrated threshold,
every hill-climber surfaces convincing-looking garbage you waste days
investigating.

This script:
  1. Samples N length-73 windows from a corpus.
  2. Scores each with the supplied n-gram fitness table.
  3. Samples N length-73 random-letter strings AND N length-73 letter-
     shuffled strings (preserves the corpus letter frequencies).
  4. Reports the score distribution for each population.
  5. Picks T99 = 99th percentile of the random/shuffled (null) score.
     A candidate that scores below T99 is statistically indistinguishable
     from random-letter noise -- treat it as not English.

Output: prints the threshold and the distribution summaries; optionally
plots histograms when matplotlib is available.

Usage:
    uv run python scripts/calibrate_fitness.py \\
        --corpus data/corpora/gutenberg_english.txt \\
        --ngrams data/ngrams/english_quadgrams.txt \\
        [--n 4] [--length 73] [--samples 10000] [--seed 0] [--plot out.png]
"""

from __future__ import annotations

import argparse
import random
import re
import statistics
import sys
from collections import Counter
from pathlib import Path

from kryptos.scoring.ngram_fitness import load_ngrams

NON_LETTER = re.compile(r"[^A-Za-z]")
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def sample_english_windows(corpus: str, length: int, n: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    if len(corpus) < length:
        raise ValueError("corpus too small")
    starts = [rng.randrange(0, len(corpus) - length) for _ in range(n)]
    return [corpus[s : s + length] for s in starts]


def random_letter_strings(length: int, n: int, seed: int) -> list[str]:
    rng = random.Random(seed + 1)
    return ["".join(rng.choices(ALPHABET, k=length)) for _ in range(n)]


def shuffled_english_strings(corpus: str, length: int, n: int, seed: int) -> list[str]:
    """Same letter frequencies as English, no structure."""
    rng = random.Random(seed + 2)
    out: list[str] = []
    for _ in range(n):
        start = rng.randrange(0, len(corpus) - length)
        window = list(corpus[start : start + length])
        rng.shuffle(window)
        out.append("".join(window))
    return out


def summarise(scores: list[float], label: str) -> dict:
    scores_sorted = sorted(scores)
    n = len(scores_sorted)
    mean = sum(scores_sorted) / n
    std = statistics.pstdev(scores_sorted)
    return {
        "label": label,
        "n": n,
        "mean": mean,
        "std": std,
        "p01": scores_sorted[int(0.01 * n)],
        "p05": scores_sorted[int(0.05 * n)],
        "p50": scores_sorted[int(0.50 * n)],
        "p95": scores_sorted[int(0.95 * n)],
        "p99": scores_sorted[int(0.99 * n)],
        "max": scores_sorted[-1],
        "min": scores_sorted[0],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", required=True, type=Path)
    ap.add_argument("--ngrams", required=True, type=Path)
    ap.add_argument("--n", type=int, default=4, help="n-gram length in the fitness table")
    ap.add_argument("--length", type=int, default=73, help="window length (K4 unconstrained = 73)")
    ap.add_argument("--samples", type=int, default=10_000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--plot", type=Path, default=None, help="optional output PNG of histograms")
    args = ap.parse_args()

    if not args.corpus.exists():
        print(f"corpus not found: {args.corpus}", file=sys.stderr)
        return 1
    if not args.ngrams.exists():
        print(f"ngrams not found: {args.ngrams}; run scripts/download_quadgrams.py", file=sys.stderr)
        return 1

    print(f"loading n-gram table ({args.ngrams}) ...")
    scorer = load_ngrams(args.ngrams, args.n)
    print(f"loading corpus ({args.corpus}) ...")
    corpus = NON_LETTER.sub("", args.corpus.read_text().upper())
    print(f"  corpus size = {len(corpus):,} letters")

    english = sample_english_windows(corpus, args.length, args.samples, args.seed)
    random_letters = random_letter_strings(args.length, args.samples, args.seed)
    shuffled = shuffled_english_strings(corpus, args.length, args.samples, args.seed)

    pops = {
        "english (contiguous Gutenberg windows)": [scorer(s) for s in english],
        "random A-Z (uniform letters)":           [scorer(s) for s in random_letters],
        "shuffled English (Eng frequencies)":     [scorer(s) for s in shuffled],
    }

    print(f"\n=== fitness distributions, length={args.length}, n={args.n}, samples={args.samples} ===")
    summaries = []
    for label, sc in pops.items():
        s = summarise(sc, label)
        summaries.append(s)
        print(f"\n{label}")
        print(f"  mean={s['mean']:.4f}  std={s['std']:.4f}")
        print(f"  percentiles: 1%={s['p01']:.4f}  5%={s['p05']:.4f}  "
              f"50%={s['p50']:.4f}  95%={s['p95']:.4f}  99%={s['p99']:.4f}")

    t99_random = summaries[1]["p99"]
    t99_shuffled = summaries[2]["p99"]
    print(f"\nT99 (random)   = {t99_random:.4f}  "
          f"(99% of random-letter strings score at or below this)")
    print(f"T99 (shuffled) = {t99_shuffled:.4f}  "
          f"(99% of shuffled-English strings score at or below this)")
    print("\nRecommended rule: a K4 candidate that scores BELOW T99(shuffled)")
    print("is statistically indistinguishable from random; do not treat as English.")

    eng_above_t99 = sum(1 for s in pops["english (contiguous Gutenberg windows)"]
                        if s > t99_shuffled) / args.samples
    print(f"Fraction of real Gutenberg English above T99(shuffled): {eng_above_t99:.3f}")

    if args.plot:
        try:
            import matplotlib.pyplot as plt
        except ImportError:
            print("matplotlib not available; skipping plot", file=sys.stderr)
            return 0
        fig, ax = plt.subplots(figsize=(8, 4.5))
        for label, sc in pops.items():
            ax.hist(sc, bins=60, alpha=0.5, label=label)
        ax.axvline(t99_shuffled, color="red", lw=1, label=f"T99 shuffled = {t99_shuffled:.3f}")
        ax.set_xlabel(f"{args.n}-gram log-likelihood per char")
        ax.set_ylabel("count")
        ax.set_title(f"Fitness calibration, length={args.length}, n={args.samples}")
        ax.legend(fontsize=8)
        fig.tight_layout()
        fig.savefig(args.plot, dpi=120)
        print(f"wrote {args.plot}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
