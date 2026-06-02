"""Bigram-distribution analysis on K1-K4 + synthetic null distributions.

The question this experiment asks: does K4's bigram structure look like
the K1/K2/K3 ciphertexts (single-letter polyalphabetic family) or like
something structurally different (digraph cipher, fractionated cipher,
permutation-table cipher)?

For each ciphertext (K1, K2, K3, K4) and a synthetic Quagmire-III-on-
English baseline:

  1. Compute the bigram count distribution over all 676 (A-Z, A-Z) bigrams
     for adjacency offset 1 (consecutive pairs) and for offsets 1..30
     (pairs at distance d).
  2. For each (text, offset) pair, compute:
       - chi-squared distance from uniform-random per-bigram expectation
       - bigram index-of-coincidence (analog of letter IoC)
       - distinct-bigrams count
       - max bigram count (the most-repeated digraph)
  3. Compare K4's values to the synthetic Q3 null distribution. Any
     statistic where K4 sits outside the Q3 null range at any offset is
     evidence that K4 is NOT a Quagmire III ciphertext of English.

The synthetic Q3 corpus is K1+K2+K3 plaintexts. 200 random 97-letter
substrings encrypted under random 5-10 letter KRYPTOS-keyed keys.
Same alphabet, similar plaintext domain, only the cipher class is
common.

Run:
    uv run python experiments/011_bigram_analysis.py
"""

from __future__ import annotations

import argparse
import random
import statistics
import sys
import time
from collections import Counter

from kryptos import K1, K1_PLAINTEXT, K2, K2_PLAINTEXT, K3, K3_PLAINTEXT, K4
from kryptos.alphabets import KRYPTOS_KEYED
from kryptos.ciphers.quagmire import QuagmireIII
from kryptos.experiment_logger import ExperimentLogger


ALPHA_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
N_BIGRAMS = 26 * 26


# --------------------------------------------------------------------------


def bigrams_at_offset(text: str, offset: int) -> list[str]:
    """All (text[i], text[i+offset]) pairs as 2-char strings."""
    return [text[i] + text[i + offset] for i in range(len(text) - offset)]


def chi_squared_uniform(counts: Counter[str], n_pairs: int) -> float:
    """Chi-squared distance from uniform distribution over 676 bigrams.
    Normalised by n_pairs so values are comparable across text lengths."""
    if n_pairs == 0:
        return 0.0
    expected = n_pairs / N_BIGRAMS
    chi = 0.0
    for bg in (a + b for a in ALPHA_LETTERS for b in ALPHA_LETTERS):
        observed = counts.get(bg, 0)
        chi += (observed - expected) ** 2 / expected
    return chi / n_pairs


def bigram_ioc(counts: Counter[str], n_pairs: int) -> float:
    """Bigram-level IoC analog."""
    if n_pairs < 2:
        return 0.0
    s = sum(c * (c - 1) for c in counts.values())
    return s / (n_pairs * (n_pairs - 1))


def distinct_bigrams(counts: Counter[str]) -> int:
    return len(counts)


def max_bigram_count(counts: Counter[str]) -> int:
    return max(counts.values()) if counts else 0


def analyse_text(text: str, offsets: list[int]) -> dict[int, dict]:
    out: dict[int, dict] = {}
    for d in offsets:
        bgs = bigrams_at_offset(text, d)
        counts = Counter(bgs)
        n = len(bgs)
        out[d] = {
            "n_pairs":          n,
            "chi_sq_per_pair":  chi_squared_uniform(counts, n),
            "bigram_ioc":       bigram_ioc(counts, n),
            "distinct":         distinct_bigrams(counts),
            "max_count":        max_bigram_count(counts),
        }
    return out


# --------------------------------------------------------------------------


def synthesize_q3_corpus(
    plaintext_pool: str, length: int, n_samples: int,
    key_lengths: tuple[int, ...] = (5, 6, 7, 8, 9, 10),
    rng_seed: int = 0,
) -> list[str]:
    """Generate n_samples Q3 ciphertexts of `length` from English
    sampled from `plaintext_pool` under random KRYPTOS-keyed keys."""
    rng = random.Random(rng_seed)
    out: list[str] = []
    for _ in range(n_samples):
        if len(plaintext_pool) <= length:
            raise ValueError("plaintext pool too short")
        start = rng.randrange(0, len(plaintext_pool) - length)
        pt = plaintext_pool[start : start + length]
        key_len = rng.choice(key_lengths)
        key = "".join(rng.choice(KRYPTOS_KEYED.letters) for _ in range(key_len))
        ct = QuagmireIII(key, "KRYPTOS").encrypt(pt)
        out.append(ct)
    return out


def summarise_null(synthetic_stats: list[dict[int, dict]],
                    offset: int, stat_key: str) -> dict:
    values = [s[offset][stat_key] for s in synthetic_stats]
    values_sorted = sorted(values)
    n = len(values_sorted)
    return {
        "n":     n,
        "mean":  statistics.mean(values_sorted),
        "std":   statistics.pstdev(values_sorted),
        "p01":   values_sorted[int(0.01 * n)],
        "p05":   values_sorted[int(0.05 * n)],
        "p50":   values_sorted[int(0.50 * n)],
        "p95":   values_sorted[int(0.95 * n)],
        "p99":   values_sorted[int(0.99 * n)],
    }


# --------------------------------------------------------------------------


def main(verbose: bool = False) -> int:
    OFFSETS = list(range(1, 31))
    K4_LEN = len(K4)
    plaintext_pool = K1_PLAINTEXT + K2_PLAINTEXT + K3_PLAINTEXT
    print(f"plaintext pool (K1+K2+K3) length: {len(plaintext_pool)}")
    print(f"target length (K4):               {K4_LEN}")
    print()

    t0 = time.perf_counter()

    # Direct analysis of K1-K4.
    real = {
        name: analyse_text(text, OFFSETS)
        for name, text in (("K1", K1), ("K2", K2), ("K3", K3), ("K4", K4))
    }

    # Synthetic Q3 null distribution at K4 length.
    n_syn = 500
    print(f"generating {n_syn} synthetic Q3 ciphertexts at length {K4_LEN} ...")
    synth = synthesize_q3_corpus(plaintext_pool, K4_LEN, n_syn)
    print(f"  done; analysing bigram statistics at offsets 1..{max(OFFSETS)} ...")
    synth_stats = [analyse_text(ct, OFFSETS) for ct in synth]

    # Report.
    with ExperimentLogger("011_bigram_analysis") as log:
        log.write({
            "k4_length": K4_LEN, "n_synthetic": n_syn,
            "offsets_swept": OFFSETS,
        })

        # 1. Adjacent bigram comparison (offset 1).
        print("\n=== ADJACENT BIGRAM (offset=1) ===")
        for name, stats in real.items():
            s = stats[1]
            print(f"  {name}  chi^2/pair={s['chi_sq_per_pair']:.4f}  "
                  f"bigram_IoC={s['bigram_ioc']:.6f}  "
                  f"distinct={s['distinct']:3d}/{s['n_pairs']}  "
                  f"max_count={s['max_count']}")
            log.write({"section": "adjacent_bigram", "text": name,
                       "offset": 1, **s})
        # synthetic summary
        for key in ("chi_sq_per_pair", "bigram_ioc", "distinct", "max_count"):
            null = summarise_null(synth_stats, 1, key)
            print(f"  synthetic Q3 {key:18s}: mean={null['mean']:.4f}  "
                  f"std={null['std']:.4f}  "
                  f"p01-p99 = [{null['p01']:.4f}, {null['p99']:.4f}]")
            log.write({"section": "adjacent_bigram_null",
                       "stat": key, **null})
            # Z-score K4 vs Q3 null
            k4_val = real["K4"][1][key]
            if null["std"] > 0:
                z = (k4_val - null["mean"]) / null["std"]
                print(f"    K4 z-score vs Q3 null:  {z:+.2f}")
                log.write({"section": "k4_z_score", "stat": key,
                           "offset": 1, "z": z})

        # 2. Per-offset chi-squared comparison.
        print("\n=== CHI^2/PAIR vs OFFSET (K1-K4 + Q3 null p05-p95) ===")
        print(f"  {'off':>3} " + " ".join(f"{n:>9s}" for n in ("K1","K2","K3","K4")) +
              f"  | Q3_null_p05  Q3_null_p95  K4_z")
        for d in OFFSETS:
            null = summarise_null(synth_stats, d, "chi_sq_per_pair")
            vals = " ".join(f"{real[n][d]['chi_sq_per_pair']:>9.4f}" for n in ("K1","K2","K3","K4"))
            k4 = real["K4"][d]["chi_sq_per_pair"]
            z = (k4 - null["mean"]) / null["std"] if null["std"] > 0 else 0.0
            marker = "  ***" if abs(z) > 2.0 else ("  *" if abs(z) > 1.0 else "")
            print(f"  {d:>3} {vals}  | {null['p05']:>11.4f}  {null['p95']:>11.4f}  "
                  f"{z:+5.2f}{marker}")
            log.write({"section": "chi_sq_by_offset", "offset": d,
                       "k1": real["K1"][d]["chi_sq_per_pair"],
                       "k2": real["K2"][d]["chi_sq_per_pair"],
                       "k3": real["K3"][d]["chi_sq_per_pair"],
                       "k4": k4,
                       "q3_p05": null["p05"], "q3_p95": null["p95"],
                       "k4_z": z})

        # 3. Per-offset bigram-IoC comparison.
        print("\n=== BIGRAM IoC vs OFFSET (K4 only, plus Q3 null) ===")
        for d in OFFSETS:
            null = summarise_null(synth_stats, d, "bigram_ioc")
            k4 = real["K4"][d]["bigram_ioc"]
            z = (k4 - null["mean"]) / null["std"] if null["std"] > 0 else 0.0
            marker = "  ***" if abs(z) > 2.0 else ("  *" if abs(z) > 1.0 else "")
            if abs(z) > 1.0 or d == 1:
                print(f"  off={d:>2}  K4={k4:.6f}  null_mean={null['mean']:.6f}+/-{null['std']:.6f}  "
                      f"z={z:+.2f}{marker}")

        # 4. Top-10 most frequent bigrams in K4 vs in K1-K3 (offset 1).
        print("\n=== TOP-10 ADJACENT BIGRAMS PER TEXT (offset 1) ===")
        for name, text in (("K1", K1), ("K2", K2), ("K3", K3), ("K4", K4)):
            top = Counter(bigrams_at_offset(text, 1)).most_common(10)
            top_str = " ".join(f"{bg}:{c}" for bg, c in top)
            print(f"  {name}: {top_str}")

        # 5. Sanity: K4 distinct-bigrams across offsets.
        print("\n=== K4 DISTINCT BIGRAMS / TOTAL PAIRS PER OFFSET ===")
        for d in (1, 7, 14, 21, 28):
            stats = real["K4"][d]
            print(f"  off={d:>2}  distinct={stats['distinct']:>3} of {stats['n_pairs']:>3} pairs  "
                  f"(saturation {stats['distinct'] / stats['n_pairs']:.3f}, expected for random ~{1 - (675/676)**stats['n_pairs']:.3f})")

    print(f"\nelapsed: {time.perf_counter() - t0:.1f}s")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    sys.exit(main(args.verbose))
