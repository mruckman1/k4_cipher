"""034 — Shift-sequence statistics for all 23,592 N1 candidates.

For each crib-compliant Sonnet + Opus candidate plaintext, compute the
implied 97-position shift sequence in both STANDARD and KRYPTOS-keyed
alphabets and analyze its statistical structure. Goal: surface
candidates whose implied keystream is statistically unusual (low
entropy, near-periodic, etc.) even if it doesn't match any specific
generator in the 20.5k library tested in exp 023.

Statistical features per (candidate, alphabet):
  - Shannon entropy of shift distribution (max log2(26) ≈ 4.7 nats,
    real-English-against-real-cipher should be close to max if the key
    is uniform-random)
  - Maximum consecutive-same-value run length
  - Maximum arithmetic-progression run length (s_{i+1} = s_i + d for
    fixed d)
  - Chi-squared distance from uniform 1/26 distribution
  - FFT autocorrelation: highest non-trivial peak (any periodic structure)
  - Number of distinct shift values used (max 26)

For random plaintexts against an unknown cipher, we'd expect uniform
shifts → high entropy, low max-consec, no autocorrelation peak. For a
plaintext that's the TRUE plaintext and the cipher is some periodic /
near-periodic / structured construction, the shift sequence should be
non-uniform.

Ranking: candidates with notably non-uniform shift distributions (low
entropy, high consec, strong autocorrelation) are surfaced as leads.

Output: experiments/results/2026-05-23_034_candidate_shift_statistics.jsonl
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np

from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, Alphabet
from kryptos.constants import K4
from kryptos.cribs import all_known_positions

K4_TEXT = K4
N = 97
CRIB_POSITIONS = sorted(all_known_positions())
NONCRIB_POSITIONS = [i for i in range(N) if i not in set(CRIB_POSITIONS)]


def load_candidates(run_dirs: list[Path]) -> list[tuple[str, str]]:
    """Load candidates from multiple N1 run dirs. Returns list of
    (source_run_id, candidate) tuples."""
    out: list[tuple[str, str]] = []
    for rd in run_dirs:
        for f in sorted(rd.glob("*_parsed.txt")):
            run_id = rd.name
            for line in f.read_text().splitlines():
                line = line.strip()
                if len(line) == 97 and line.isalpha() and line.isupper():
                    out.append((f"{run_id}/{f.stem.replace('_parsed', '')}", line))
    return out


def encode(text: str, alphabet: Alphabet) -> np.ndarray:
    return np.fromiter((alphabet.index(c) for c in text), dtype=np.int8, count=len(text))


def candidate_shifts(cand_idx: np.ndarray, k4_idx: np.ndarray, n_letters: int) -> np.ndarray:
    """Per-position shift = plaintext_index - ciphertext_index mod N."""
    return ((cand_idx.astype(np.int16) - k4_idx.astype(np.int16)) % n_letters).astype(np.int8)


def shannon_entropy_natlog(values: np.ndarray, max_val: int = 26) -> float:
    """Shannon entropy in nats. Max for uniform over 26 values = ln(26) ≈ 3.26."""
    counts = np.bincount(values.astype(np.int32), minlength=max_val)
    probs = counts / max(counts.sum(), 1)
    nz = probs[probs > 0]
    return float(-(nz * np.log(nz)).sum())


def max_consec_same(values: np.ndarray) -> int:
    if values.size == 0:
        return 0
    max_run = 1
    run = 1
    for i in range(1, values.size):
        if values[i] == values[i-1]:
            run += 1
            if run > max_run:
                max_run = run
        else:
            run = 1
    return max_run


def max_arith_progression(values: np.ndarray) -> tuple[int, int]:
    """Find longest run where s_{i+1} = s_i + d (mod 26) for fixed d.
    Returns (max_length, d_of_max)."""
    if values.size < 2:
        return 1, 0
    best_len = 1
    best_d = 0
    for d in range(26):
        run = 1
        for i in range(1, values.size):
            if (int(values[i]) - int(values[i-1])) % 26 == d:
                run += 1
                if run > best_len:
                    best_len = run
                    best_d = d
            else:
                run = 1
    return best_len, best_d


def chisq_uniform(values: np.ndarray, max_val: int = 26) -> float:
    """Chi-squared distance from uniform 1/26 over `values`."""
    counts = np.bincount(values.astype(np.int32), minlength=max_val)
    n = counts.sum()
    expected = n / max_val
    return float(((counts - expected) ** 2 / expected).sum())


def autocorr_peak(values: np.ndarray, min_period: int = 2, max_period: int = 48) -> tuple[int, float]:
    """Compute discrete autocorrelation for periods in [min_period, max_period],
    return (best_period, normalized_peak_value)."""
    if values.size < max_period + 1:
        return 0, 0.0
    # Map values to {-12.5, ..., +12.5} centered for cleaner correlation
    centered = values.astype(np.float32) - 12.5
    var = float((centered ** 2).mean())
    if var < 1e-9:
        return 0, 1.0
    best_period = 0
    best_corr = 0.0
    for p in range(min_period, max_period + 1):
        if p >= values.size:
            break
        a = centered[: values.size - p]
        b = centered[p:]
        if a.size == 0:
            continue
        corr = float((a * b).mean()) / var
        if abs(corr) > abs(best_corr):
            best_corr = corr
            best_period = p
    return best_period, best_corr


def n_distinct(values: np.ndarray) -> int:
    return int(np.unique(values).size)


def analyze_candidate(shifts: np.ndarray) -> dict:
    """Return all statistics for one shift sequence (length 97)."""
    nc_shifts = shifts[NONCRIB_POSITIONS]
    full_ent = shannon_entropy_natlog(shifts)
    nc_ent = shannon_entropy_natlog(nc_shifts)
    consec = max_consec_same(shifts)
    arith_len, arith_d = max_arith_progression(shifts)
    chi = chisq_uniform(shifts)
    period, peak = autocorr_peak(shifts)
    distinct = n_distinct(shifts)
    return {
        "ent_full": round(full_ent, 4),
        "ent_noncrib": round(nc_ent, 4),
        "max_consec": consec,
        "max_arith_len": arith_len,
        "max_arith_d": int(arith_d),
        "chi_sq": round(chi, 2),
        "autocorr_period": period,
        "autocorr_peak": round(peak, 4),
        "n_distinct": distinct,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run-dirs", type=Path, nargs="+", default=None,
                   help="N1 run dirs to load candidates from")
    p.add_argument("--out", type=Path,
                   default=Path("experiments/results/2026-05-23_034_candidate_shift_statistics.jsonl"))
    p.add_argument("--top-k", type=int, default=25,
                   help="report top K candidates by various structure measures")
    args = p.parse_args()

    if args.run_dirs is None:
        base = Path("experiments/results/n1_claude_outputs")
        dirs = sorted([d for d in base.iterdir()
                       if d.is_dir() and "claude" in d.name and "hexfiltered" in d.name])
        # Fallback: also include the original Sonnet and Opus runs
        if not dirs:
            dirs = sorted([d for d in base.iterdir() if d.is_dir() and "claude" in d.name])
        args.run_dirs = dirs[-2:] if len(dirs) >= 2 else dirs

    print(f"Loading candidates from: {[d.name for d in args.run_dirs]}")
    candidates = load_candidates(args.run_dirs)
    print(f"Total candidates loaded: {len(candidates)}")

    K4_std = encode(K4_TEXT, STANDARD)
    K4_kk = encode(K4_TEXT, KRYPTOS_KEYED)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    records: list[dict] = []

    for ci, (source, cand) in enumerate(candidates):
        cand_std = encode(cand, STANDARD)
        cand_kk = encode(cand, KRYPTOS_KEYED)
        shifts_std = candidate_shifts(cand_std, K4_std, 26)
        shifts_kk = candidate_shifts(cand_kk, K4_kk, 26)
        stats_std = analyze_candidate(shifts_std)
        stats_kk = analyze_candidate(shifts_kk)
        records.append({
            "candidate_index": ci,
            "source": source,
            "candidate": cand,
            "shifts_std": shifts_std.tolist(),
            "stats_std": stats_std,
            "stats_kk": stats_kk,
        })
        if (ci + 1) % 5000 == 0:
            print(f"  [{ci+1}/{len(candidates)}] processed "
                  f"({time.perf_counter()-t0:.1f}s)", flush=True)

    elapsed = time.perf_counter() - t0
    print(f"\nAnalyzed {len(records)} candidates in {elapsed:.1f}s")

    # Write all records (compressed: just essential fields)
    with open(args.out, "w") as f:
        for r in records:
            # Keep shifts as a separate compact field; drop them to save space
            f.write(json.dumps({
                "candidate_index": r["candidate_index"],
                "source": r["source"],
                "stats_std": r["stats_std"],
                "stats_kk": r["stats_kk"],
            }) + "\n")
        f.write(json.dumps({
            "summary": True,
            "n_candidates": len(records),
            "elapsed_s": round(elapsed, 1),
        }) + "\n")

    # Top-K reports by various structure measures
    print(f"\n=== Top {args.top_k} by lowest shift entropy (STANDARD) ===")
    sorted_low_ent = sorted(records, key=lambda r: r["stats_std"]["ent_full"])
    for r in sorted_low_ent[:args.top_k]:
        print(f"  ent={r['stats_std']['ent_full']:.3f}  "
              f"consec={r['stats_std']['max_consec']}  "
              f"distinct={r['stats_std']['n_distinct']}  "
              f"src={r['source']}: {r['candidate'][:60]}...")

    print(f"\n=== Top {args.top_k} by longest max-consec same-shift (STANDARD) ===")
    sorted_consec = sorted(records, key=lambda r: -r["stats_std"]["max_consec"])
    for r in sorted_consec[:args.top_k]:
        print(f"  consec={r['stats_std']['max_consec']}  "
              f"ent={r['stats_std']['ent_full']:.3f}  "
              f"src={r['source']}: {r['candidate'][:60]}...")

    print(f"\n=== Top {args.top_k} by longest arithmetic-progression shift run (STANDARD) ===")
    sorted_arith = sorted(records, key=lambda r: -r["stats_std"]["max_arith_len"])
    for r in sorted_arith[:args.top_k]:
        print(f"  arith_len={r['stats_std']['max_arith_len']}  "
              f"d={r['stats_std']['max_arith_d']}  "
              f"src={r['source']}: {r['candidate'][:60]}...")

    print(f"\n=== Top {args.top_k} by autocorrelation peak (STANDARD) ===")
    sorted_auto = sorted(records, key=lambda r: -abs(r["stats_std"]["autocorr_peak"]))
    for r in sorted_auto[:args.top_k]:
        print(f"  period={r['stats_std']['autocorr_period']}  "
              f"peak={r['stats_std']['autocorr_peak']:.4f}  "
              f"src={r['source']}: {r['candidate'][:60]}...")

    print(f"\nJSONL: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
