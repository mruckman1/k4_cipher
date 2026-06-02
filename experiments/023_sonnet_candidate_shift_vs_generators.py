"""023: Flip the search direction. For each Sonnet candidate plaintext,
compute its implied 97-position shift sequence (in standard A-Z and
KRYPTOS-keyed alphabets), then test that full-length shift sequence
against the 20.5k-generator library from exp 006.

If any (candidate, alphabet, generator) tuple produces a long consecutive
match run at the non-crib positions, that means K4 may be encrypted by
that generator AND the candidate is plausibly the actual plaintext.

Exp 006 tested generators against the 24 known crib shifts only and
found 0 hits at >= 5 consecutive matches. That ruled out the generator
library at the crib-position granularity. This experiment tests the
generator library against full 97-position shift sequences for 5,220
candidate plaintexts that satisfy the cribs by construction.

Statistical thresholds (per-comparison random match p = 1/26):
   Across 5,220 cands x 20.5k gens x 2 alphabets = ~214M comparisons.
   Expected non-crib max-consec-run hits at threshold k:
     k=5:  ~2,300 (too noisy)
     k=6:  ~90
     k=7:  ~3.5
     k=8:  ~0.13   <- start of "real signal" zone
     k=10: ~0      <- any hit at 10+ is a real lead

Expected non-crib total matches >= 20 by chance: essentially 0
(random expectation = 73/26 = 2.8; SD = 1.6).

Inputs
------
  candidates: experiments/results/n1_claude_outputs/run_*sonnet*/
              (or --run-dir to point at any N1 output set)

Output
------
  experiments/results/2026-05-22_023_sonnet_candidate_shift_vs_generators.jsonl
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import time
from pathlib import Path

import numpy as np

from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, Alphabet
from kryptos.constants import K4
from kryptos.cribs import all_known_positions
from kryptos.generators import (
    iter_constant_keystreams,
    iter_fibonacci_keystreams,
    iter_lagged_fibonacci_keystreams,
    iter_lcg_keystreams,
    iter_mengenlehreuhr_keystreams,
    iter_sanborn_numeric_keystreams,
    iter_text_keystreams,
)


# ----- thresholds
NONCRIB_TOTAL_MIN = 18         # well above random expectation (2.8)
NONCRIB_MAX_CONSEC_MIN = 6     # ~90 expected by chance; survives modest filter
INTERESTING_NONCRIB_CONSEC = 8 # ~0.13 expected by chance
WIN_NONCRIB_CONSEC = 10        # ~0 expected by chance; real lead

CRIB_POSITIONS: list[int] = sorted(all_known_positions())   # 0-indexed
NONCRIB_POSITIONS: list[int] = [i for i in range(97) if i not in set(CRIB_POSITIONS)]

# Pathology guard: drop candidates that contain a >= 5-letter run of
# K4_ciphertext substring at non-crib positions. Sonnet occasionally
# emits the K4 ciphertext itself as a "free span" filler; that produces
# shift=0 over a long run, which trivially matches any generator with
# leading zeros and floods the result set with false positives.
K4_CIPHERTEXT = (
    "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)
PATHOLOGY_RUN_LEN = 5


def is_pathological(cand: str) -> bool:
    """Return True if candidate copies K4 ciphertext over a >=5-letter
    run at any non-crib position. Real Sanborn-register plaintexts will
    randomly match K4 at ~1/26 of positions; runs of 5+ are vanishingly
    rare under any real cipher and almost certainly indicate that the
    LM emitted ciphertext as a free-span filler."""
    crib_set = set(CRIB_POSITIONS)
    run = 0
    for i in range(97):
        if i in crib_set:
            run = 0
            continue
        if cand[i] == K4_CIPHERTEXT[i]:
            run += 1
            if run >= PATHOLOGY_RUN_LEN:
                return True
        else:
            run = 0
    return False


# ----- generator collection

def collect_generators(length: int = 97) -> tuple[list[str], np.ndarray]:
    """Concatenate every generator family into one (n_gens, 97) array."""
    print("Loading generator library ...", flush=True)
    iterators = [
        ("text",        iter_text_keystreams),
        ("constants",   iter_constant_keystreams),
        ("sanborn_num", iter_sanborn_numeric_keystreams),
        ("lcg",         iter_lcg_keystreams),
        ("fibonacci",   iter_fibonacci_keystreams),
        ("lag_fib",     iter_lagged_fibonacci_keystreams),
        ("mengen",      iter_mengenlehreuhr_keystreams),
    ]
    labels: list[str] = []
    rows: list[list[int]] = []
    family_counts: dict[str, int] = {}
    for fam, it in iterators:
        n0 = len(labels)
        for label, seq in it(length):
            if len(seq) != length:
                continue
            # Some sources emit base-10 digits (0-9); normalize all to mod 26
            seq_mod = [v % 26 for v in seq]
            labels.append(label)
            rows.append(seq_mod)
        family_counts[fam] = len(labels) - n0
        print(f"  {fam:14s}: +{family_counts[fam]:6d}  (total {len(labels)})")
    G = np.asarray(rows, dtype=np.int8)
    return labels, G


# ----- candidate loading

def load_candidates(run_dir: Path) -> list[str]:
    cands: list[str] = []
    for f in sorted(run_dir.glob("*_parsed.txt")):
        for line in f.read_text().splitlines():
            line = line.strip()
            if len(line) == 97 and line.isalpha() and line.isupper():
                cands.append(line)
    return cands


# ----- shift computation

def encode(text: str, alphabet: Alphabet) -> np.ndarray:
    return np.fromiter((alphabet.index(c) for c in text), dtype=np.int8, count=len(text))


def candidate_shifts(cand_idx: np.ndarray, k4_idx: np.ndarray, n: int) -> np.ndarray:
    """Per-position shift: plaintext_index - ciphertext_index mod N."""
    return ((cand_idx.astype(np.int16) - k4_idx.astype(np.int16)) % n).astype(np.int8)


def max_consec(bool_row: np.ndarray) -> int:
    """Max consecutive True in a 1D bool array. Fast pure-numpy approach."""
    if bool_row.size == 0:
        return 0
    if not bool_row.any():
        return 0
    # diff trick: find run boundaries
    padded = np.concatenate(([False], bool_row, [False]))
    diffs = np.diff(padded.astype(np.int8))
    starts = np.where(diffs == 1)[0]
    ends = np.where(diffs == -1)[0]
    return int((ends - starts).max())


# ----- main sweep

def sweep(
    candidates: list[str],
    labels: list[str],
    G: np.ndarray,
    out_path: Path,
) -> dict:
    n_gens = G.shape[0]
    noncrib_idx = np.array(NONCRIB_POSITIONS, dtype=np.int32)
    G_noncrib = G[:, noncrib_idx]   # (n_gens, 73)
    K4_idx_std = encode(K4, STANDARD)
    K4_idx_kk = encode(K4, KRYPTOS_KEYED)

    summary = {
        "n_candidates": len(candidates),
        "n_generators": n_gens,
        "n_alphabets": 2,
        "total_comparisons": len(candidates) * n_gens * 2,
        "n_records_logged": 0,
        "n_above_interesting": 0,
        "n_above_win": 0,
        "elapsed_s": 0.0,
    }

    t0 = time.perf_counter()
    out_f = open(out_path, "w")

    n_records = 0
    n_interesting = 0
    n_win = 0

    # For per-alphabet progress
    for c_idx, cand in enumerate(candidates):
        cand_std = encode(cand, STANDARD)
        cand_kk = encode(cand, KRYPTOS_KEYED)

        for alpha_name, cand_idx_arr, k4_idx_arr, alpha_obj in (
            ("standard", cand_std, K4_idx_std, STANDARD),
            ("kryptos_keyed", cand_kk, K4_idx_kk, KRYPTOS_KEYED),
        ):
            n = len(alpha_obj)
            shift_actual = candidate_shifts(cand_idx_arr, k4_idx_arr, n)        # (97,)
            shift_actual_noncrib = shift_actual[noncrib_idx]                     # (73,)

            # Vectorized: match matrix per gen, only at non-crib positions
            matches_nc = (G_noncrib == shift_actual_noncrib[None, :])            # (n_gens, 73)
            noncrib_totals = matches_nc.sum(axis=1).astype(np.int16)             # (n_gens,)

            # Pre-filter by total non-crib matches.
            qualify_idx = np.where(noncrib_totals >= NONCRIB_TOTAL_MIN)[0]

            for gi in qualify_idx:
                nc_mc = max_consec(matches_nc[gi])
                if nc_mc < NONCRIB_MAX_CONSEC_MIN:
                    continue
                # Optionally also compute full-97 stats (cheap)
                full_match = (G[gi] == shift_actual)
                full_total = int(full_match.sum())
                full_mc = max_consec(full_match)

                rec = {
                    "candidate_index": c_idx,
                    "alphabet": alpha_name,
                    "generator_label": labels[gi],
                    "noncrib_total": int(noncrib_totals[gi]),
                    "noncrib_max_consec": int(nc_mc),
                    "full_total": full_total,
                    "full_max_consec": full_mc,
                    "candidate": cand,
                }
                out_f.write(json.dumps(rec) + "\n")
                n_records += 1
                if nc_mc >= INTERESTING_NONCRIB_CONSEC:
                    n_interesting += 1
                if nc_mc >= WIN_NONCRIB_CONSEC:
                    n_win += 1

        if (c_idx + 1) % 500 == 0:
            elapsed = time.perf_counter() - t0
            print(f"  [{c_idx+1}/{len(candidates)}] {elapsed:.1f}s, "
                  f"records={n_records}, interesting>={INTERESTING_NONCRIB_CONSEC}={n_interesting}, "
                  f"win>={WIN_NONCRIB_CONSEC}={n_win}",
                  flush=True)

    elapsed = time.perf_counter() - t0
    summary["n_records_logged"] = n_records
    summary["n_above_interesting"] = n_interesting
    summary["n_above_win"] = n_win
    summary["elapsed_s"] = round(elapsed, 1)
    out_f.write(json.dumps({"summary": True, **summary}) + "\n")
    out_f.close()
    return summary


def report_top(jsonl_path: Path, top_k: int = 25) -> None:
    recs = []
    with open(jsonl_path) as f:
        for line in f:
            r = json.loads(line)
            if r.get("summary"):
                continue
            recs.append(r)
    recs.sort(key=lambda r: (-r["noncrib_max_consec"], -r["noncrib_total"]))
    print()
    print(f"=== TOP {min(top_k, len(recs))} by non-crib max-consecutive run ===")
    print(f"  {'nc_mc':>5} {'nc_tot':>6} {'full_mc':>7} {'full_tot':>8}  "
          f"{'alphabet':<14} generator")
    print(f"  {'-'*5} {'-'*6} {'-'*7} {'-'*8}  {'-'*14} {'-'*60}")
    for r in recs[:top_k]:
        print(f"  {r['noncrib_max_consec']:>5} {r['noncrib_total']:>6} "
              f"{r['full_max_consec']:>7} {r['full_total']:>8}  "
              f"{r['alphabet']:<14} {r['generator_label']}")
        print(f"        candidate[c={r['candidate_index']}]: {r['candidate']}")


# ----- main

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run-dir", type=Path,
                   default=None,
                   help="N1 run dir to read candidates from; default = latest sonnet run")
    p.add_argument("--out", type=Path,
                   default=Path("experiments/results")
                   / "2026-05-22_023_sonnet_candidate_shift_vs_generators.jsonl")
    args = p.parse_args()

    if args.run_dir is None:
        base = Path("experiments/results/n1_claude_outputs")
        candidates_dirs = sorted(d for d in base.iterdir() if d.is_dir() and "sonnet" in d.name)
        if not candidates_dirs:
            print(f"no sonnet run dir found under {base}")
            return 1
        args.run_dir = candidates_dirs[-1]
        print(f"Using latest sonnet run: {args.run_dir}")

    cands_all = load_candidates(args.run_dir)
    if not cands_all:
        print(f"no candidates loaded from {args.run_dir}")
        return 1
    n_path = sum(1 for c in cands_all if is_pathological(c))
    cands = [c for c in cands_all if not is_pathological(c)]
    print(f"Loaded {len(cands_all)} candidates; dropped {n_path} pathological "
          f"(K4-ciphertext copied into a free span); proceeding with {len(cands)}.")

    labels, G = collect_generators()
    print(f"Generator library: {len(labels)} generators, shape={G.shape}, dtype={G.dtype}\n")

    summary = sweep(cands, labels, G, args.out)
    print()
    print("=" * 70)
    print("Sonnet-candidate shift sequence vs generator library — summary")
    print("=" * 70)
    print(f"  candidates:               {summary['n_candidates']:,}")
    print(f"  generators:               {summary['n_generators']:,}")
    print(f"  total comparisons:        {summary['total_comparisons']:,}")
    print(f"  records logged:           {summary['n_records_logged']:,}")
    print(f"  noncrib_mc >= {INTERESTING_NONCRIB_CONSEC} (interesting): {summary['n_above_interesting']}")
    print(f"  noncrib_mc >= {WIN_NONCRIB_CONSEC} (WIN):         {summary['n_above_win']}")
    print(f"  elapsed:                  {summary['elapsed_s']}s")
    print(f"  jsonl:                    {args.out}")

    report_top(args.out, top_k=25)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
