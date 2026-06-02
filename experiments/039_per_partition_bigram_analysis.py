"""039 — Move C: per-partition bigram analysis.

Under each candidate selection rule, partition K4 into k substrings by
color. If the rule is correct, each substring is the K4 ciphertext at
positions where ONE specific alphabet was applied — i.e., each substring
should be a monoalphabetic substitution of (some English plaintext sampled
at those positions). Its bigram statistics should look like substituted
English, not like random letters.

Compare each substring's bigram count distribution against:
  (1) random uniform 26-letter substrings of the same length
  (2) the K4 full ciphertext's overall bigram distribution
  (3) shuffled-English bigram distribution (length-matched)

Compute chi-squared distance from each baseline. If the substring's
chi-squared from baseline (1) is much higher than from baseline (3),
the substring has *more* structure than random — i.e., looks like
substituted English.

Rules tested:
  - (2*pos_mod_3 + consonant_count) mod 4  [Move B's k=4 winner]
  - position_mod_8                          [from exp 036]
  - consonant_count_mod_8
  - pos_in_w_seg_mod_8
  - dist_to_w_mod_8                         [1 violation but interesting]

Baselines: random A-Z, shuffled K4, English bigram null

Output: experiments/results/2026-05-23_039_partition_bigram.json
"""

from __future__ import annotations

import json
import random
from collections import Counter
from collections.abc import Callable
from pathlib import Path

from kryptos.constants import K1_PLAINTEXT, K2_PLAINTEXT, K3_PLAINTEXT, K4

K4_TEXT = K4
N = 97
VOWELS = set("AEIOU")
W_POSITIONS = [i for i, c in enumerate(K4_TEXT) if c == "W"]


# ----- rule functions

def rule_k4_consonant_pos_mod3(i: int) -> int:
    """(2*pos_mod_3 + consonant_count) mod 4 — Move B's k=4 winner."""
    cc = sum(1 for j in range(i + 1) if K4_TEXT[j] not in VOWELS)
    return (2 * (i % 3) + cc) % 4


def rule_position_mod_8(i: int) -> int:
    return i % 8


def rule_consonant_count_mod_8(i: int) -> int:
    return sum(1 for j in range(i + 1) if K4_TEXT[j] not in VOWELS) % 8


def rule_pos_in_w_seg_mod_8(i: int) -> int:
    boundaries = [-1] + W_POSITIONS + [N]
    for s in range(len(boundaries) - 1):
        lo, hi = boundaries[s], boundaries[s + 1]
        if lo < i < hi:
            return (i - lo - 1) % 8
    return 0


def rule_dist_to_w_mod_8(i: int) -> int:
    return min(abs(i - w) for w in W_POSITIONS) % 8


RULES = {
    "k4_winner_k4": rule_k4_consonant_pos_mod3,
    "position_mod_8": rule_position_mod_8,
    "consonant_count_mod_8": rule_consonant_count_mod_8,
    "pos_in_w_seg_mod_8": rule_pos_in_w_seg_mod_8,
    "dist_to_w_mod_8": rule_dist_to_w_mod_8,
}


# ----- bigram stats

def bigrams(text: str) -> Counter:
    return Counter(text[i:i+2] for i in range(len(text) - 1))


def bigram_chi_sq_from_uniform(text: str) -> float:
    """Chi-squared of bigram counts vs uniform expectation."""
    n = len(text) - 1
    if n < 5:
        return 0.0
    bgs = bigrams(text)
    expected = n / (26 * 26)
    chi = sum((c - expected) ** 2 / expected for c in bgs.values())
    # Plus the expected contribution from unseen bigrams
    unseen = 26 * 26 - len(bgs)
    chi += unseen * (expected) ** 2 / expected  # (0 - expected)^2 / expected
    return chi


def bigram_chi_sq_from_text(text: str, baseline_bigram_dist: Counter,
                             baseline_total: int) -> float:
    """Chi-squared of text's bigram counts against the baseline distribution."""
    n = len(text) - 1
    if n < 5 or baseline_total == 0:
        return 0.0
    bgs = bigrams(text)
    # Normalize baseline to expected counts at length n
    chi = 0.0
    seen = set()
    for bg, count in bgs.items():
        seen.add(bg)
        expected = baseline_bigram_dist.get(bg, 1) * n / baseline_total
        chi += (count - expected) ** 2 / max(expected, 1e-6)
    # Add unseen baseline bigrams
    for bg, base_count in baseline_bigram_dist.items():
        if bg in seen:
            continue
        expected = base_count * n / baseline_total
        chi += expected  # (0 - expected)^2 / expected = expected
    return chi


def normalize_alphabet(text: str) -> str:
    """Re-index a substring so its letters get relabeled by frequency rank.
    This makes a monoalphabetic-substitution of English look like English."""
    counts = Counter(text)
    most_common = counts.most_common()
    relabel = {c: chr(65 + i) for i, (c, _) in enumerate(most_common)}
    return "".join(relabel[c] for c in text)


def random_text(n: int, rng: random.Random) -> str:
    return "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(n))


def main() -> int:
    # Build the English bigram baseline from K1+K2+K3 plaintexts
    english_corpus = (K1_PLAINTEXT + K2_PLAINTEXT + K3_PLAINTEXT).upper()
    eng_bgs = bigrams(english_corpus)
    eng_total = sum(eng_bgs.values())
    print(f"English baseline (K1+K2+K3 plaintext): {eng_total} bigrams over "
          f"{len(eng_bgs)} distinct")

    # Bigram baseline for "monoalphabetic substitution of English":
    # We expect the substring to have the SAME bigram counts as English (after
    # relabeling), since substitution preserves bigram count distribution.
    # We'll relabel the substring before comparing to English.

    rng = random.Random(42)
    n_random_samples = 100

    results: dict[str, dict] = {}

    for rule_name, rule_fn in RULES.items():
        # Apply rule to all 97 positions
        colors = [rule_fn(i) for i in range(N)]
        n_colors = max(colors) + 1
        # Partition K4 by color
        partitions: list[str] = [
            "".join(K4_TEXT[i] for i in range(N) if colors[i] == c)
            for c in range(n_colors)
        ]
        partition_sizes = [len(p) for p in partitions]

        print(f"\n=== Rule: {rule_name} (k={n_colors}) ===")
        print(f"Partition sizes: {partition_sizes}")

        # For each partition, compute:
        #   - bigram chi-sq vs uniform random
        #   - bigram chi-sq vs English (after relabeling)
        #   - random baseline distribution (mean ± std)
        per_partition_stats: list[dict] = []
        for c, p in enumerate(partitions):
            if len(p) < 6:
                print(f"  Color {c}: too short (len={len(p)}), skipping")
                continue

            chi_uniform = bigram_chi_sq_from_uniform(p)

            # Relabel by frequency rank then compare to English
            relabeled = normalize_alphabet(p)
            chi_english = bigram_chi_sq_from_text(relabeled, eng_bgs, eng_total)

            # Random baseline at the same length
            rand_chi_uniform = []
            rand_chi_english = []
            for _ in range(n_random_samples):
                rtxt = random_text(len(p), rng)
                rand_chi_uniform.append(bigram_chi_sq_from_uniform(rtxt))
                rand_relab = normalize_alphabet(rtxt)
                rand_chi_english.append(
                    bigram_chi_sq_from_text(rand_relab, eng_bgs, eng_total)
                )
            mean_unif = sum(rand_chi_uniform) / len(rand_chi_uniform)
            mean_eng = sum(rand_chi_english) / len(rand_chi_english)

            # Z-score: how many SDs is the partition's chi-sq from random?
            var_unif = sum((x - mean_unif) ** 2 for x in rand_chi_uniform) / len(rand_chi_uniform)
            var_eng = sum((x - mean_eng) ** 2 for x in rand_chi_english) / len(rand_chi_english)
            sd_unif = max(var_unif ** 0.5, 1.0)
            sd_eng = max(var_eng ** 0.5, 1.0)

            z_unif = (chi_uniform - mean_unif) / sd_unif
            z_eng = (chi_english - mean_eng) / sd_eng

            print(f"  Color {c} (len={len(p)}): "
                  f"chi_uniform={chi_uniform:>6.1f} (z={z_unif:+.2f}), "
                  f"chi_eng_after_relabel={chi_english:>7.1f} (z={z_eng:+.2f})")
            print(f"    K4 substring: {p}")

            per_partition_stats.append({
                "color": c,
                "len": len(p),
                "chi_uniform": chi_uniform,
                "z_vs_random_uniform": z_unif,
                "chi_english_after_relabel": chi_english,
                "z_vs_random_english": z_eng,
                "substring": p,
            })

        # Aggregate: if ALL partitions have z_uniform > some threshold (more
        # structured than random) AND z_english < some threshold (closer to
        # English than random), that's evidence for this rule.
        good_count = sum(1 for s in per_partition_stats
                          if s["z_vs_random_english"] < -0.5)
        print(f"  Summary: {good_count}/{len(per_partition_stats)} partitions have "
              f"z_vs_english < -0.5 (closer to English than random)")

        results[rule_name] = {
            "k": n_colors,
            "partition_sizes": partition_sizes,
            "per_partition": per_partition_stats,
            "partitions_closer_to_english": good_count,
        }

    # ===== Side-by-side comparison
    print()
    print("=" * 70)
    print("=== Side-by-side ranking by partitions-closer-to-English ===")
    print("=" * 70)
    ranked = sorted(results.items(),
                    key=lambda kv: -kv[1]["partitions_closer_to_english"])
    for name, r in ranked:
        n_total = len(r["per_partition"])
        print(f"  {name:30s}  k={r['k']:>2}  "
              f"{r['partitions_closer_to_english']}/{n_total} partitions"
              f" closer to English")

    out_path = Path("experiments/results/2026-05-23_039_partition_bigram.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2, default=str))
    print(f"\nOutput: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
