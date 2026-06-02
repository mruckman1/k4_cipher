"""027 — Tier B: Trifid known-plaintext hill-climb against all 5,220
Sonnet candidate plaintexts.

Trifid is one of the only standard polygraphic ciphers structurally
compatible with K4: it uses a 3×3×3 = 27-cell grid (26 letters + 1
non-letter symbol), so unlike Bifid/Playfair/Four-square (all 5×5 = 25
cells with one letter merged), it has enough cells to hold every A-Z
letter without merge. Encryption can still produce the 27th symbol;
that's the structural risk a hill-climb has to navigate around.

Algorithm:
  Plaintext letter index -> (depth, row, col) in 27-cell grid.
  Per block of `period` plaintext letters, build a 3*period-long stream
  [depths..rows..cols], then re-read in triples to look up output letters.

Hill-climb (per candidate × period × random restart):
  - Score = # positions where Trifid_encrypt(candidate, grid, period) == K4
  - Random swap of two grid cells, accept if score improves
  - Many restarts because the grid permutation space has many local maxima

Numba-compiled inner loop; multiprocessing across all 16 cores for
embarrassingly parallel per-candidate jobs.

Periods tested: {5, 7, 9} (canonical Trifid period 5; periods 7 and 9
sometimes tried). Per-candidate budget: 6 restarts × 3000 iter per
restart per period.

A WIN is any (candidate, period, grid) where the encrypted candidate
matches K4 at all 97 positions byte-exact.

Output: experiments/results/2026-05-22_027_trifid_hillclimb.jsonl
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import time
from pathlib import Path

import numpy as np
from numba import njit

from kryptos.constants import K4

K4_TEXT = K4
N = 97
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ+"   # 27 symbols; '+' = separator
SEP_IDX = 26                                # the non-letter cell


# Encode a 26-letter A-Z string into 27-letter indices (0..25)
def encode_az27(s: str) -> np.ndarray:
    return np.fromiter((ord(c) - ord("A") for c in s), dtype=np.int8, count=len(s))


# ---------- Numba kernels (operate on 27-letter index space) ----------

@njit(cache=True)
def trifid_encrypt(plain_idx: np.ndarray, grid: np.ndarray, period: int) -> np.ndarray:
    """Encrypt plain_idx (length N) under Trifid with given grid permutation
    and period. grid[cell_idx] = symbol_idx (0..26)."""
    n = plain_idx.shape[0]
    # pos_of[symbol] = cell_index (inverse permutation)
    pos_of = np.empty(27, dtype=np.int8)
    for c in range(27):
        pos_of[grid[c]] = np.int8(c)

    depths = np.empty(n, dtype=np.int8)
    rows = np.empty(n, dtype=np.int8)
    cols = np.empty(n, dtype=np.int8)
    for i in range(n):
        cell = pos_of[plain_idx[i]]
        depths[i] = cell // 9
        rows[i] = (cell % 9) // 3
        cols[i] = cell % 3

    out = np.empty(n, dtype=np.int8)
    for block_start in range(0, n, period):
        block_end = block_start + period
        if block_end > n:
            block_end = n
        block_len = block_end - block_start
        for k in range(block_len):
            j0 = 3 * k
            j1 = 3 * k + 1
            j2 = 3 * k + 2
            # j0
            if j0 < block_len:
                a = depths[block_start + j0]
            elif j0 < 2 * block_len:
                a = rows[block_start + j0 - block_len]
            else:
                a = cols[block_start + j0 - 2 * block_len]
            # j1
            if j1 < block_len:
                b = depths[block_start + j1]
            elif j1 < 2 * block_len:
                b = rows[block_start + j1 - block_len]
            else:
                b = cols[block_start + j1 - 2 * block_len]
            # j2
            if j2 < block_len:
                c = depths[block_start + j2]
            elif j2 < 2 * block_len:
                c = rows[block_start + j2 - block_len]
            else:
                c = cols[block_start + j2 - 2 * block_len]
            cell = 9 * a + 3 * b + c
            out[block_start + k] = grid[cell]
    return out


@njit(cache=True)
def score_match(out_arr: np.ndarray, target_arr: np.ndarray) -> int:
    n = out_arr.shape[0]
    s = 0
    for i in range(n):
        if out_arr[i] == target_arr[i]:
            s += 1
    return s


@njit(cache=True)
def hill_climb_trifid(
    plain_idx: np.ndarray,
    target_idx: np.ndarray,
    period: int,
    n_iters: int,
    rng_seed: int,
) -> tuple:
    """Returns (best_score, best_grid) for one random-restart hill-climb."""
    np.random.seed(rng_seed)
    grid = np.arange(27).astype(np.int8)
    # Random permutation by Fisher-Yates
    for i in range(26, 0, -1):
        j = np.random.randint(0, i + 1)
        tmp = grid[i]
        grid[i] = grid[j]
        grid[j] = tmp

    out_arr = trifid_encrypt(plain_idx, grid, period)
    current = score_match(out_arr, target_idx)

    best_grid = grid.copy()
    best_score = current

    for _ in range(n_iters):
        a = np.random.randint(0, 27)
        b = np.random.randint(0, 27)
        if a == b:
            continue
        # Try swap
        grid[a], grid[b] = grid[b], grid[a]
        out_arr = trifid_encrypt(plain_idx, grid, period)
        new_score = score_match(out_arr, target_idx)
        if new_score >= current:
            current = new_score
            if new_score > best_score:
                best_score = new_score
                best_grid = grid.copy()
                if best_score == 97:
                    return best_score, best_grid
        else:
            # Revert
            grid[a], grid[b] = grid[b], grid[a]

    return best_score, best_grid


# ---------- multiprocessing worker ----------

def warmup_jit():
    """JIT-compile once per process by running a tiny hill-climb."""
    dummy_plain = np.zeros(N, dtype=np.int8)
    dummy_target = np.zeros(N, dtype=np.int8)
    hill_climb_trifid(dummy_plain, dummy_target, 5, 10, 0)


def worker_process_candidates(args: tuple) -> list[dict]:
    """Per-worker function: process a list of candidates."""
    (worker_id, cand_indices, candidates_subset, target_idx, periods,
     n_restarts, n_iters_per_restart) = args
    warmup_jit()
    results: list[dict] = []
    base_seed = worker_id * 1_000_000

    for local_idx, (global_idx, cand) in enumerate(zip(cand_indices, candidates_subset)):
        plain_idx = encode_az27(cand)
        best_overall = 0
        best_grid_arr = None
        best_period = -1
        for period in periods:
            for restart in range(n_restarts):
                seed = base_seed + global_idx * 100 + period * 10 + restart
                score, grid = hill_climb_trifid(
                    plain_idx, target_idx, period, n_iters_per_restart, seed
                )
                if score > best_overall:
                    best_overall = score
                    best_grid_arr = grid
                    best_period = period
                if best_overall == 97:
                    break
            if best_overall == 97:
                break
        rec = {
            "candidate_index": int(global_idx),
            "best_score": int(best_overall),
            "best_period": int(best_period),
            "best_grid": best_grid_arr.tolist() if best_grid_arr is not None else None,
        }
        results.append(rec)
    return results


# ---------- main ----------

def load_candidates(run_dir: Path) -> list[str]:
    out: list[str] = []
    for f in sorted(run_dir.glob("*_parsed.txt")):
        for line in f.read_text().splitlines():
            line = line.strip()
            if len(line) == 97 and line.isalpha() and line.isupper():
                out.append(line)
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run-dir", type=Path, default=None)
    p.add_argument("--out", type=Path,
                   default=Path("experiments/results/2026-05-22_027_trifid_hillclimb.jsonl"))
    p.add_argument("--periods", type=int, nargs="+", default=[5, 7, 9])
    p.add_argument("--n-restarts", type=int, default=6)
    p.add_argument("--n-iters", type=int, default=3000)
    p.add_argument("--n-workers", type=int, default=14,  # leave 2 cores free for OS
                   help="multiprocessing workers (default 14, M3 Max has 16 cores)")
    p.add_argument("--limit", type=int, default=None,
                   help="limit to first N candidates (for testing)")
    args = p.parse_args()

    if args.run_dir is None:
        base = Path("experiments/results/n1_claude_outputs")
        runs = sorted(d for d in base.iterdir() if d.is_dir() and "sonnet" in d.name)
        args.run_dir = runs[-1]

    cands = load_candidates(args.run_dir)
    if args.limit:
        cands = cands[: args.limit]
    print(f"Using {args.run_dir}")
    print(f"Candidates: {len(cands)}")
    print(f"Periods: {args.periods}")
    print(f"Restarts per period: {args.n_restarts}")
    print(f"Iter per restart: {args.n_iters}")
    print(f"Workers: {args.n_workers}")

    target_idx = encode_az27(K4_TEXT)
    n_cands = len(cands)
    # Split candidates across workers
    chunk = (n_cands + args.n_workers - 1) // args.n_workers
    worker_args = []
    for wid in range(args.n_workers):
        s = wid * chunk
        e = min((wid + 1) * chunk, n_cands)
        if s >= e:
            break
        idx_list = list(range(s, e))
        subset = cands[s:e]
        worker_args.append((wid, idx_list, subset, target_idx,
                            args.periods, args.n_restarts, args.n_iters))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()

    print(f"\nLaunching {len(worker_args)} workers ...")
    with mp.get_context("spawn").Pool(processes=len(worker_args)) as pool:
        all_results: list[dict] = []
        for i, batch in enumerate(pool.imap_unordered(worker_process_candidates, worker_args, chunksize=1)):
            all_results.extend(batch)
            elapsed = time.perf_counter() - t0
            print(f"  worker batch {i+1}/{len(worker_args)} done; "
                  f"total results so far {len(all_results)} ({elapsed:.1f}s)",
                  flush=True)

    elapsed = time.perf_counter() - t0
    # Sort by best_score descending
    all_results.sort(key=lambda r: -r["best_score"])

    n_full_solve = sum(1 for r in all_results if r["best_score"] == 97)
    n_above_50 = sum(1 for r in all_results if r["best_score"] >= 50)

    with open(args.out, "w") as f:
        for r in all_results:
            r["candidate"] = cands[r["candidate_index"]]
            f.write(json.dumps(r) + "\n")
        f.write(json.dumps({
            "summary": True,
            "n_candidates": n_cands,
            "n_full_solves": n_full_solve,
            "n_above_50": n_above_50,
            "max_score": all_results[0]["best_score"] if all_results else 0,
            "elapsed_s": round(elapsed, 1),
            "params": {
                "periods": args.periods,
                "n_restarts": args.n_restarts,
                "n_iters": args.n_iters,
            },
        }) + "\n")

    print()
    print(f"=== Trifid hill-climb summary ===")
    print(f"  candidates:         {n_cands}")
    print(f"  full solves (97):   {n_full_solve}")
    print(f"  score >= 50:        {n_above_50}")
    print(f"  max score:          {all_results[0]['best_score'] if all_results else 'N/A'}")
    print(f"  elapsed:            {elapsed:.1f}s")

    print()
    print("Top 10 by score:")
    for r in all_results[:10]:
        print(f"  c[{r['candidate_index']:4d}] score={r['best_score']:3d}/97  "
              f"period={r['best_period']}  cand={r['candidate'][:60]}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
