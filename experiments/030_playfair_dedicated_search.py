"""030 — Dedicated Playfair-variant known-plaintext search.

Closes the open Playfair gap (item 1 from the Tier B follow-up list).
Standard 5×5 Playfair with any single-letter merge is structurally
incompatible with K4 (K4 contains all 26 letters; standard Playfair
output ⊂ 25-letter set). This experiment tests three variants:

  Phase 1: Standard 5×5 Playfair with all 25 candidate merge pairs.
           Each candidate × merge: encrypt, count matches with K4.
           Confirms structural ruling mechanically and surfaces any
           candidate × merge that achieves near-maximum match count
           (= 97 − count of merged-away letter in K4).

  Phase 2: 2×13 Playfair (26-letter grid, no merge). Hill-climb grid
           permutations × 5,220 candidates. Output ⊆ 26-letter set so
           full match is possible.

  Phase 3: 13×2 Playfair (transpose of phase 2). Same compatibility.

Phases 2-3 use Numba-compiled Playfair encrypt + multiprocessing.

A WIN is any (candidate, variant, grid) where encrypt(candidate)[:97]
== K4 byte-exact.

Output: experiments/results/2026-05-22_030_playfair_dedicated_search.jsonl
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import time
from pathlib import Path

import numpy as np
from numba import njit

from kryptos.constants import K4

K4_TEXT = K4
N = 97
ALPHABET_26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# ============================ Numba kernels =================================

@njit(cache=True)
def playfair_encrypt(
    plain_idx: np.ndarray,   # (N,) int8 indices in cell-set
    grid: np.ndarray,         # (rows*cols,) int8, grid[cell] = letter_idx
    rows: int,
    cols: int,
    filler_idx: int,
) -> np.ndarray:
    """Generic NxM Playfair encrypt. Returns int8 array of length
    2*n_digrams (>= len(plain_idx))."""
    n_cells = rows * cols
    # pos_of[letter_idx] = cell_index
    pos_of = np.empty(n_cells, dtype=np.int8)
    for c in range(n_cells):
        pos_of[grid[c]] = np.int8(c)

    n = plain_idx.shape[0]
    # Worst case: every char gets a filler -> 2N digrams. Allocate generously.
    max_d = n + 1
    da = np.empty(max_d, dtype=np.int8)
    db = np.empty(max_d, dtype=np.int8)
    n_dig = 0
    i = 0
    while i < n:
        c1 = plain_idx[i]
        if i + 1 >= n:
            pad = filler_idx if c1 != filler_idx else (filler_idx + 1) % n_cells
            da[n_dig] = c1
            db[n_dig] = pad
            n_dig += 1
            i += 1
        else:
            c2 = plain_idx[i + 1]
            if c1 == c2:
                pad = filler_idx if c1 != filler_idx else (filler_idx + 1) % n_cells
                da[n_dig] = c1
                db[n_dig] = pad
                n_dig += 1
                i += 1
            else:
                da[n_dig] = c1
                db[n_dig] = c2
                n_dig += 1
                i += 2

    out = np.empty(2 * n_dig, dtype=np.int8)
    for k in range(n_dig):
        p1 = pos_of[da[k]]
        p2 = pos_of[db[k]]
        r1 = p1 // cols
        cc1 = p1 % cols
        r2 = p2 // cols
        cc2 = p2 % cols
        if r1 == r2:
            new_cc1 = (cc1 + 1) % cols
            new_cc2 = (cc2 + 1) % cols
            out[2 * k] = grid[r1 * cols + new_cc1]
            out[2 * k + 1] = grid[r2 * cols + new_cc2]
        elif cc1 == cc2:
            new_r1 = (r1 + 1) % rows
            new_r2 = (r2 + 1) % rows
            out[2 * k] = grid[new_r1 * cols + cc1]
            out[2 * k + 1] = grid[new_r2 * cols + cc2]
        else:
            out[2 * k] = grid[r1 * cols + cc2]
            out[2 * k + 1] = grid[r2 * cols + cc1]
    return out


@njit(cache=True)
def score_against_k4(out_arr: np.ndarray, k4_arr: np.ndarray) -> int:
    """Match count over first N positions of the encrypted output."""
    s = 0
    limit = min(out_arr.shape[0], k4_arr.shape[0])
    for i in range(limit):
        if out_arr[i] == k4_arr[i]:
            s += 1
    return s


@njit(cache=True)
def hill_climb_playfair(
    plain_idx: np.ndarray,
    k4_arr: np.ndarray,
    n_cells: int,
    rows: int,
    cols: int,
    filler_idx: int,
    n_iters: int,
    rng_seed: int,
) -> tuple:
    np.random.seed(rng_seed)
    grid = np.arange(n_cells).astype(np.int8)
    # Fisher-Yates shuffle
    for i in range(n_cells - 1, 0, -1):
        j = np.random.randint(0, i + 1)
        tmp = grid[i]
        grid[i] = grid[j]
        grid[j] = tmp

    out_arr = playfair_encrypt(plain_idx, grid, rows, cols, filler_idx)
    current = score_against_k4(out_arr, k4_arr)

    best_grid = grid.copy()
    best_score = current

    for _ in range(n_iters):
        a = np.random.randint(0, n_cells)
        b = np.random.randint(0, n_cells)
        if a == b:
            continue
        grid[a], grid[b] = grid[b], grid[a]
        out_arr = playfair_encrypt(plain_idx, grid, rows, cols, filler_idx)
        new_score = score_against_k4(out_arr, k4_arr)
        if new_score >= current:
            current = new_score
            if new_score > best_score:
                best_score = new_score
                best_grid = grid.copy()
                if best_score == N:
                    return best_score, best_grid
        else:
            # Revert
            grid[a], grid[b] = grid[b], grid[a]

    return best_score, best_grid


def warmup_jit():
    dummy_plain = np.zeros(N, dtype=np.int8)
    dummy_k4 = np.zeros(N, dtype=np.int8)
    hill_climb_playfair(dummy_plain, dummy_k4, 26, 2, 13, 23, 10, 0)


# ============================ encoding helpers ==============================

def make_25_alphabet(merge_pair: tuple[str, str]) -> tuple[str, dict]:
    """Build a 25-letter alphabet by dropping merge_pair[1] (merged into [0])."""
    a, b = merge_pair[0].upper(), merge_pair[1].upper()
    letters = [c for c in ALPHABET_26 if c != b]
    idx_map = {c: i for i, c in enumerate(letters)}
    idx_map[b] = idx_map[a]  # b maps to a's index
    return "".join(letters), idx_map


def encode_26(text: str) -> np.ndarray:
    return np.fromiter((ord(c) - ord("A") for c in text), dtype=np.int8, count=len(text))


def encode_with_map(text: str, idx_map: dict) -> np.ndarray:
    return np.fromiter((idx_map[c] for c in text), dtype=np.int8, count=len(text))


def load_candidates(run_dir: Path) -> list[str]:
    out: list[str] = []
    for f in sorted(run_dir.glob("*_parsed.txt")):
        for line in f.read_text().splitlines():
            line = line.strip()
            if len(line) == 97 and line.isalpha() and line.isupper():
                out.append(line)
    return out


# ============================ Phase 1: 5x5 merges ============================

def phase1_5x5_merges(cands: list[str], out_file) -> dict:
    """For each of the 26 possible 'drop' letters, test KRYPTOS-keyed
    5x5 Playfair against all candidates. Output ⊂ 25 letters → for any
    candidate K4 position whose letter is the dropped one, no match
    possible. Best possible score = 97 − count(dropped_letter in K4)."""
    k4_letter_counts = {c: K4_TEXT.count(c) for c in ALPHABET_26}
    print(f"K4 letter counts: {k4_letter_counts}")
    summary = {"phase": "1_5x5_with_merge", "merges_tested": [],
               "best_per_merge": []}

    k4_idx_26 = encode_26(K4_TEXT)
    # For each merge (drop B, keep A), encrypt with a KRYPTOS-keyed grid
    keyword = "KRYPTOS"
    for drop_letter in ALPHABET_26:
        keep_letter = "A" if drop_letter != "A" else "B"  # Just pick something to merge into
        # Build grid: KRYPTOS first, then rest excluding drop_letter
        alphabet25, idx_map = make_25_alphabet((keep_letter, drop_letter))
        seen = []
        seen_set = set()
        for c in keyword:
            if c == drop_letter:
                c = keep_letter
            if c in alphabet25 and c not in seen_set:
                seen.append(c)
                seen_set.add(c)
        for c in alphabet25:
            if c not in seen_set:
                seen.append(c)
                seen_set.add(c)
        grid = np.array([idx_map[c] for c in seen], dtype=np.int8)
        filler_idx = idx_map.get("X", 23)
        if filler_idx == idx_map[drop_letter]:
            filler_idx = idx_map.get("Q", 16)

        # Try each candidate
        best_score_for_merge = 0
        best_cand_idx = -1
        max_possible = 97 - k4_letter_counts[drop_letter]
        for ci, cand in enumerate(cands):
            try:
                p_idx = encode_with_map(cand, idx_map)
                out = playfair_encrypt(p_idx, grid, 5, 5, filler_idx)
                # Decode output back to 26-letter alphabet for K4 compare
                limit = min(out.shape[0], 97)
                n_match = sum(
                    1 for i in range(limit)
                    if alphabet25[out[i]] == K4_TEXT[i]
                )
                if n_match > best_score_for_merge:
                    best_score_for_merge = n_match
                    best_cand_idx = ci
            except Exception:
                continue
        summary["merges_tested"].append(drop_letter)
        summary["best_per_merge"].append({
            "drop_letter": drop_letter,
            "k4_drop_count": k4_letter_counts[drop_letter],
            "max_possible": max_possible,
            "best_score": best_score_for_merge,
            "best_cand_idx": best_cand_idx,
        })
        out_file.write(json.dumps({
            "phase": 1, "drop_letter": drop_letter,
            "max_possible": max_possible,
            "best_score": best_score_for_merge,
            "best_cand_idx": best_cand_idx,
        }) + "\n")
    return summary


# ============================ Phase 2/3: rectangular Playfair =================

def worker_rect_playfair(args: tuple) -> list[dict]:
    """Worker: hill-climb each candidate × variant."""
    (worker_id, cand_indices, candidates_subset, k4_arr_26, variants,
     n_restarts, n_iters_per_restart) = args
    warmup_jit()
    results: list[dict] = []
    base_seed = worker_id * 1_000_000
    for local_idx, (global_idx, cand) in enumerate(zip(cand_indices, candidates_subset)):
        plain_idx = encode_26(cand)
        for variant_name, rows, cols, filler_idx in variants:
            best_overall = 0
            best_grid_arr = None
            for restart in range(n_restarts):
                seed = base_seed + global_idx * 100 + restart
                score, grid = hill_climb_playfair(
                    plain_idx, k4_arr_26, 26, rows, cols, filler_idx,
                    n_iters_per_restart, seed
                )
                if score > best_overall:
                    best_overall = score
                    best_grid_arr = grid
                if best_overall == N:
                    break
            results.append({
                "phase": variant_name,
                "candidate_index": int(global_idx),
                "best_score": int(best_overall),
                "best_grid": best_grid_arr.tolist() if best_grid_arr is not None else None,
            })
    return results


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run-dir", type=Path, default=None)
    p.add_argument("--out", type=Path,
                   default=Path("experiments/results/2026-05-22_030_playfair_dedicated_search.jsonl"))
    p.add_argument("--n-restarts", type=int, default=4)
    p.add_argument("--n-iters", type=int, default=3000)
    p.add_argument("--n-workers", type=int, default=14)
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--skip-phase-1", action="store_true")
    p.add_argument("--skip-phase-2", action="store_true")
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

    args.out.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()

    with open(args.out, "w") as f:
        # ----- PHASE 1: 5x5 with each possible merge
        if not args.skip_phase_1:
            print()
            print("=== PHASE 1: 5x5 Playfair with each of 26 possible drop letters ===")
            t1 = time.perf_counter()
            phase1_summary = phase1_5x5_merges(cands, f)
            print(f"Phase 1 done in {time.perf_counter()-t1:.1f}s")
            print()
            print("Best score by drop letter (max_possible = 97 - K4-count of dropped letter):")
            print(f"  {'drop':>4}  {'k4_ct':>5}  {'max':>4}  {'best':>4}  {'gap':>4}  {'best_cand':>9}")
            for rec in sorted(phase1_summary["best_per_merge"],
                              key=lambda r: -r["best_score"]):
                gap = rec["max_possible"] - rec["best_score"]
                print(f"  {rec['drop_letter']:>4}  {rec['k4_drop_count']:>5}  "
                      f"{rec['max_possible']:>4}  {rec['best_score']:>4}  "
                      f"{gap:>4}  c[{rec['best_cand_idx']}]")
            best_phase1 = max(phase1_summary["best_per_merge"], key=lambda r: r["best_score"])
            print(f"\nPhase 1 overall best: {best_phase1['best_score']}/97 "
                  f"(dropping {best_phase1['drop_letter']}, c[{best_phase1['best_cand_idx']}])")

        # ----- PHASE 2/3: rectangular Playfair (2x13 and 13x2)
        if not args.skip_phase_2:
            print()
            print("=== PHASE 2/3: rectangular 2x13 and 13x2 Playfair (no merge) ===")
            t2 = time.perf_counter()
            k4_arr_26 = encode_26(K4_TEXT)
            variants = [
                ("2x13", 2, 13, ord("X") - ord("A")),   # filler X
                ("13x2", 13, 2, ord("X") - ord("A")),
            ]
            chunk = (len(cands) + args.n_workers - 1) // args.n_workers
            worker_args = []
            for wid in range(args.n_workers):
                s = wid * chunk
                e = min((wid + 1) * chunk, len(cands))
                if s >= e:
                    break
                worker_args.append((wid, list(range(s, e)), cands[s:e],
                                    k4_arr_26, variants,
                                    args.n_restarts, args.n_iters))
            print(f"Launching {len(worker_args)} workers, "
                  f"{args.n_restarts} restarts × {args.n_iters} iter per restart "
                  f"× 2 variants per candidate")
            with mp.get_context("spawn").Pool(processes=len(worker_args)) as pool:
                all_rect: list[dict] = []
                for i, batch in enumerate(
                    pool.imap_unordered(worker_rect_playfair, worker_args, chunksize=1)
                ):
                    all_rect.extend(batch)
                    print(f"  worker batch {i+1}/{len(worker_args)} done; "
                          f"total {len(all_rect)} records ({time.perf_counter()-t2:.1f}s)",
                          flush=True)

            for r in all_rect:
                f.write(json.dumps(r) + "\n")
            # Per-variant top
            for var in ("2x13", "13x2"):
                top = sorted([r for r in all_rect if r["phase"] == var],
                             key=lambda r: -r["best_score"])[:10]
                print(f"\n{var} top 10:")
                for r in top:
                    print(f"  c[{r['candidate_index']:4d}] score={r['best_score']:3d}/97")
            print(f"\nPhase 2/3 done in {time.perf_counter()-t2:.1f}s")

        elapsed = time.perf_counter() - t0
        f.write(json.dumps({"summary": True,
                            "n_candidates": len(cands),
                            "elapsed_s": round(elapsed, 1)}) + "\n")

    print()
    print(f"=== exp 030 done in {elapsed:.1f}s ===")
    print(f"JSONL: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
