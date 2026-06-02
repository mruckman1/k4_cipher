"""022: Re-gate exp 015's 215 chi-squared survivors through hexagram fitness.

Background: experiment 015 (transposition-then-Q3) found 98,218 candidate
decryptions below the chi-squared T99=95 threshold across 3.6M permutations
at W=10. The chi-squared gate is necessary (it rules out random letter
distributions) but loose (it passes any plaintext with roughly-English
letter frequencies, even gibberish like LCRWMPCFTMDWFBASOZSJ...).

This experiment re-scores the 215 best_plain entries logged in
experiments/results/2026-05-20_015_transposition_then_q3.jsonl with
hexagram log-likelihood per char. Calibration:
  real English (K1/K2/K3 plaintexts):  ~-13.0 to -13.7
  shuffled English (letter-freq only):  ~-23.7
  uniform random A-Z:                   ~-24.4
Anything > -18 is interesting; > -15 is a real lead.

Note: each logged record is the BEST candidate per (W, perm, L) triple by
chi-squared, NOT every chi-squared survivor. So 215 best-of-permutation
plaintexts. If even one scores notably above -20, that justifies
re-running exp 015 in "log all survivors" mode to surface the rest.
"""

from __future__ import annotations

import json
from pathlib import Path

from kryptos.scoring.ngram_fitness import load_ngrams


SOURCE_JSONL = Path("experiments/results/2026-05-20_015_transposition_then_q3.jsonl")
OUT_JSONL = Path("experiments/results/2026-05-22_022_regate_exp015_with_hexagrams.jsonl")
HEX_PATH = Path("data/ngrams/english_hexagrams.txt")

INTERESTING_HEX = -18.0   # well above gibberish floor
STRONG_HEX = -15.0        # near real-English


def main() -> int:
    if not SOURCE_JSONL.exists():
        print(f"missing source: {SOURCE_JSONL}")
        return 1
    if not HEX_PATH.exists():
        print(f"missing hexagrams: {HEX_PATH}")
        return 1

    print(f"loading hexagrams from {HEX_PATH} ...", flush=True)
    hex_fit = load_ngrams(HEX_PATH, 6)

    rescored: list[dict] = []
    summary_lines: list[dict] = []
    with open(SOURCE_JSONL) as f:
        for line in f:
            rec = json.loads(line)
            if rec.get("summary"):
                summary_lines.append(rec)
                continue
            if "best_plain" not in rec:
                continue
            # Replace ? padding with X (treat as wildcard non-English filler)
            pt = rec["best_plain"].replace("?", "X")
            score = hex_fit(pt)
            rescored.append({
                "W": rec.get("W"),
                "perm": rec.get("perm"),
                "L": rec.get("L"),
                "free": rec.get("free"),
                "best_chi": rec.get("best_chi"),
                "n_below_threshold_in_triple": rec.get("n_below_threshold"),
                "best_plain": rec["best_plain"],
                "hex_per_char": round(score, 4),
            })

    rescored.sort(key=lambda r: -r["hex_per_char"])

    OUT_JSONL.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_JSONL, "w") as out:
        for r in rescored:
            out.write(json.dumps(r) + "\n")
        out.write(json.dumps({
            "summary": True,
            "n_rescored": len(rescored),
            "n_above_interesting": sum(1 for r in rescored if r["hex_per_char"] > INTERESTING_HEX),
            "n_above_strong": sum(1 for r in rescored if r["hex_per_char"] > STRONG_HEX),
            "best_hex": rescored[0]["hex_per_char"] if rescored else None,
            "median_hex": rescored[len(rescored)//2]["hex_per_char"] if rescored else None,
            "worst_hex": rescored[-1]["hex_per_char"] if rescored else None,
        }) + "\n")

    n = len(rescored)
    print(f"\nRescored {n} (W, perm, L) best_plain entries from exp 015")
    if rescored:
        print(f"  best hex:     {rescored[0]['hex_per_char']:.3f}")
        print(f"  median hex:   {rescored[n//2]['hex_per_char']:.3f}")
        print(f"  worst hex:    {rescored[-1]['hex_per_char']:.3f}")
        print(f"  > -18 (interesting): "
              f"{sum(1 for r in rescored if r['hex_per_char'] > INTERESTING_HEX)}")
        print(f"  > -15 (strong lead): "
              f"{sum(1 for r in rescored if r['hex_per_char'] > STRONG_HEX)}")
        print()
        print(f"Top 25 by hexagram score:")
        print(f"  {'hex/char':>10}  {'chi':>7}  {'L':>3}  {'free':>4}  W   plaintext (97 chars; ? = unfilled)")
        print(f"  {'-'*10}  {'-'*7}  {'-'*3}  {'-'*4}  {'-'*3}  {'-'*97}")
        for r in rescored[:25]:
            print(f"  {r['hex_per_char']:>10.3f}  {r['best_chi']:>7.2f}  "
                  f"{r['L']:>3}  {r['free']:>4}  {r['W']:>3}  {r['best_plain']}")
    print()
    print(f"JSONL: {OUT_JSONL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
