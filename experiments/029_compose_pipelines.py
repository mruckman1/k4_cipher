"""029 — Compose pipeline known-plaintext attacks.

Tests 2-deep and 3-deep `Compose` pipelines against all 5,220 Sonnet
candidates as proposed plaintexts. Pipeline shapes:

  (A) Q3 ∘ remap         pipeline(plain) = Q3(remap(plain))
                         <=> Q3 known-plaintext on (remap(cand), K4)

  (B) remap ∘ Q3         pipeline(plain) = remap(Q3(plain))
                         <=> Q3 known-plaintext on (cand, remap_inv(K4))

  (C) col ∘ Q3 ∘ remap   pipeline(plain) = col(Q3(remap(plain)), perm)
                         <=> Q3 known-plaintext on (remap(cand), col_inv(K4))

The remaps tested are "Sanborn-natural" positional permutations:
  - identity (baseline; reproduces Tier A)
  - reverse (all 97 positions reversed)
  - swap_halves (positions [0..48] <-> [49..96])
  - rotate_k for k in {1, 5, 10, 24, 48}
  - bit_reverse_7 (position i -> bitreverse(i, 7 bits))
  - K3_columnar_w7 (7-column transposition with KRYPTOS-keyword column order)

The col transpositions tested are small columnar widths with all
permutations (small enough to enumerate):
  - W=3 (3! = 6 perms)
  - W=5 (5! = 120 perms)
  - W=7 (7! = 5,040 perms; matches K3's column width)

For each pipeline shape × parameter combination × 5,220 candidates ×
period L in {1..15} × {STANDARD, KRYPTOS_KEYED} × {vigenere, beaufort,
variant_beaufort}: run known-plaintext consistency check on the
appropriately-permuted (cand, target) pair.

A WIN is any tuple where a self-consistent length-L key exists across
all 97 positions; verify by re-encrypting through the full pipeline.

Output: experiments/results/2026-05-22_029_compose_pipelines.jsonl
"""

from __future__ import annotations

import argparse
import itertools
import json
import time
from pathlib import Path

import numpy as np

from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, Alphabet
from kryptos.constants import K4

K4_TEXT = K4
N = 97
MAX_PERIOD = 15


def load_candidates(run_dir: Path) -> list[str]:
    out: list[str] = []
    for f in sorted(run_dir.glob("*_parsed.txt")):
        for line in f.read_text().splitlines():
            line = line.strip()
            if len(line) == 97 and line.isalpha() and line.isupper():
                out.append(line)
    return out


def encode_array(texts: list[str], alphabet: Alphabet) -> np.ndarray:
    arr = np.empty((len(texts), N), dtype=np.int16)
    for r, t in enumerate(texts):
        for c, ch in enumerate(t):
            arr[r, c] = alphabet.index(ch)
    return arr


def encode_string(text: str, alphabet: Alphabet) -> np.ndarray:
    return np.fromiter((alphabet.index(c) for c in text), dtype=np.int16, count=len(text))


# ---------- positional remaps (returns permutation as length-97 int array)

def perm_identity() -> np.ndarray:
    return np.arange(N, dtype=np.int32)


def perm_reverse() -> np.ndarray:
    return np.arange(N - 1, -1, -1, dtype=np.int32)


def perm_swap_halves() -> np.ndarray:
    p = np.arange(N, dtype=np.int32)
    half = N // 2
    p[:half], p[half:half * 2] = np.arange(half, half * 2), np.arange(0, half)
    # position 96 stays
    return p


def perm_rotate(k: int) -> np.ndarray:
    return np.array([(i + k) % N for i in range(N)], dtype=np.int32)


def perm_bit_reverse_7() -> np.ndarray:
    """Position i -> bitreverse over 7 bits, with positions >= 97 clipped."""
    p = np.empty(N, dtype=np.int32)
    seen = set()
    # Build a permutation that's a bit-reverse on a 7-bit space, with
    # collision handling (positions >= 97 get mapped to next available).
    available = list(range(N))
    avail_set = set(available)
    for i in range(N):
        # 7-bit reverse
        b = 0
        v = i
        for _ in range(7):
            b = (b << 1) | (v & 1)
            v >>= 1
        if b >= N:
            b = b % N
        # First-come-first-served
        while b in seen:
            b = (b + 1) % N
        p[i] = b
        seen.add(b)
    return p


def perm_k3_columnar_w7() -> np.ndarray:
    """K3-style columnar transposition with KRYPTOS keyword column order
    on width-7 grid. Permutes 91 positions into the grid; positions 91-96
    occupy a partial last row and are mapped tail-on."""
    # KRYPTOS column order: derive from sorted letters
    keyword = "KRYPTOS"
    # Column index in original order vs sorted (alphabetic) order
    order = sorted(range(7), key=lambda i: keyword[i])
    # order maps [0..6] in sorted alphabetic order to original column index
    # i.e., column to read FIRST is order[0]
    grid_rows = N // 7   # 13 full rows
    rem = N - grid_rows * 7  # remainder: 6 leftover positions
    p = np.empty(N, dtype=np.int32)
    out_pos = 0
    # Read column by column in the keyword's sorted-letter order
    for col_to_read in order:
        for row in range(grid_rows):
            src = row * 7 + col_to_read
            p[out_pos] = src
            out_pos += 1
        # If this column has a partial-row entry, include it
        if col_to_read < rem:
            p[out_pos] = grid_rows * 7 + col_to_read
            out_pos += 1
    return p


def perm_columnar(width: int, col_perm: tuple) -> np.ndarray:
    """Columnar transposition with arbitrary column permutation.
    col_perm[i] = source column to read at output column i."""
    grid_rows = N // width
    rem = N - grid_rows * width
    p = np.empty(N, dtype=np.int32)
    out_pos = 0
    for col_to_read in col_perm:
        for row in range(grid_rows):
            src = row * width + col_to_read
            p[out_pos] = src
            out_pos += 1
        if col_to_read < rem:
            p[out_pos] = grid_rows * width + col_to_read
            out_pos += 1
    return p


def invert_perm(p: np.ndarray) -> np.ndarray:
    """Return the inverse permutation."""
    inv = np.empty_like(p)
    inv[p] = np.arange(p.size)
    return inv


# ---------- known-plaintext Q3 attack (vectorized)

def required_key(
    cands_idx: np.ndarray,
    cipher_idx: np.ndarray,
    convention: str,
    n_letters: int = 26,
) -> np.ndarray:
    cands = cands_idx.astype(np.int16)
    cipher = cipher_idx.astype(np.int16)[None, :]
    if convention == "vigenere":
        return ((cipher - cands) % n_letters).astype(np.int8)
    elif convention == "beaufort":
        return ((cipher + cands) % n_letters).astype(np.int8)
    elif convention == "variant_beaufort":
        return ((cands - cipher) % n_letters).astype(np.int8)
    raise ValueError(convention)


def check_slot_consistency(req_key: np.ndarray, L: int) -> np.ndarray:
    n_cands, M = req_key.shape
    ok = np.ones(n_cands, dtype=bool)
    for slot in range(L):
        positions = list(range(slot, M, L))
        if len(positions) <= 1:
            continue
        vals = req_key[:, positions]
        ref = vals[:, 0:1]
        ok &= np.all(vals == ref, axis=1)
    return ok


def kp_q3_attack(
    cand_arr: np.ndarray,
    target_arr: np.ndarray,
    alpha_name: str,
    n_letters: int = 26,
    max_L: int = MAX_PERIOD,
) -> list[tuple[int, int, str, str]]:
    """Run Q3 known-plaintext attack on (cand_arr, target_arr). Returns
    list of (candidate_index, period_L, alpha_name, convention) tuples
    where a length-L periodic key satisfies all positions."""
    hits = []
    for conv in ("vigenere", "beaufort", "variant_beaufort"):
        req = required_key(cand_arr, target_arr, conv, n_letters)
        for L in range(1, max_L + 1):
            ok = check_slot_consistency(req, L)
            for ci in np.where(ok)[0]:
                hits.append((int(ci), L, alpha_name, conv))
    return hits


# ---------- pipelines

POSITIONAL_REMAPS: dict[str, np.ndarray] = {
    "identity":         perm_identity(),
    "reverse":          perm_reverse(),
    "swap_halves":      perm_swap_halves(),
    "rotate_1":         perm_rotate(1),
    "rotate_5":         perm_rotate(5),
    "rotate_10":        perm_rotate(10),
    "rotate_24":        perm_rotate(24),
    "rotate_48":        perm_rotate(48),
    "bit_reverse_7":    perm_bit_reverse_7(),
    "k3_columnar_w7":   perm_k3_columnar_w7(),
}


def all_columnar_perms(widths: list[int]) -> list[tuple[int, tuple]]:
    """Return list of (width, permutation_tuple) for every column
    permutation of every requested width."""
    out = []
    for W in widths:
        for col_perm in itertools.permutations(range(W)):
            # Skip identity columnar
            if col_perm == tuple(range(W)):
                continue
            out.append((W, col_perm))
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run-dir", type=Path, default=None)
    p.add_argument("--out", type=Path,
                   default=Path("experiments/results/2026-05-22_029_compose_pipelines.jsonl"))
    p.add_argument("--columnar-widths", type=int, nargs="+", default=[3, 5, 7])
    p.add_argument("--max-period", type=int, default=MAX_PERIOD)
    p.add_argument("--alphabets", nargs="+", default=["standard", "kryptos_keyed"])
    args = p.parse_args()

    if args.run_dir is None:
        base = Path("experiments/results/n1_claude_outputs")
        runs = sorted(d for d in base.iterdir() if d.is_dir() and "sonnet" in d.name)
        args.run_dir = runs[-1]
    print(f"Using {args.run_dir}")

    cands = load_candidates(args.run_dir)
    print(f"Loaded {len(cands)} candidates.")

    K4_std = encode_string(K4_TEXT, STANDARD)
    K4_kk = encode_string(K4_TEXT, KRYPTOS_KEYED)
    cands_std = encode_array(cands, STANDARD)
    cands_kk = encode_array(cands, KRYPTOS_KEYED)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    total_solves = 0
    n_pipelines_tested = 0
    t0 = time.perf_counter()

    # Build the full pipeline space
    columnar_perms = all_columnar_perms(args.columnar_widths)
    print(f"\nPipeline parameters:")
    print(f"  positional remaps:        {len(POSITIONAL_REMAPS)}")
    print(f"  columnar perms:           {sum(1 for _ in columnar_perms)}")
    print(f"  pipeline shapes:          A (Q3∘remap), B (remap∘Q3), C (col∘Q3∘remap)")
    print(f"  alphabets:                {args.alphabets}")
    print(f"  conventions:              vigenere, beaufort, variant_beaufort")
    print(f"  periods:                  L=1..{args.max_period}")

    alpha_pairs = []
    if "standard" in args.alphabets:
        alpha_pairs.append(("standard", cands_std, K4_std))
    if "kryptos_keyed" in args.alphabets:
        alpha_pairs.append(("kryptos_keyed", cands_kk, K4_kk))

    with open(args.out, "w") as out_f:
        # =============== Shape A: Q3 ∘ positional remap ===============
        print()
        print("=== Shape A: Q3 ∘ positional_remap ===")
        for remap_name, perm in POSITIONAL_REMAPS.items():
            for alpha_name, cand_arr, target_arr in alpha_pairs:
                permuted_cand = cand_arr[:, perm]
                hits = kp_q3_attack(permuted_cand, target_arr, alpha_name,
                                    max_L=args.max_period)
                n_pipelines_tested += 1
                for ci, L, _alpha, conv in hits:
                    rec = {
                        "shape": "A_q3_after_remap",
                        "remap": remap_name,
                        "alphabet": alpha_name,
                        "convention": conv,
                        "period": L,
                        "candidate_index": ci,
                        "candidate": cands[ci],
                    }
                    out_f.write(json.dumps(rec) + "\n")
                    total_solves += 1
            if total_solves > 0:
                print(f"  [{remap_name:18s}] total solves so far: {total_solves}")
        print(f"  Shape A done; {total_solves} solves; "
              f"{time.perf_counter()-t0:.1f}s elapsed")

        # =============== Shape B: positional_remap ∘ Q3 ===============
        print()
        print("=== Shape B: positional_remap ∘ Q3 ===")
        t1 = time.perf_counter()
        b_solves = 0
        for remap_name, perm in POSITIONAL_REMAPS.items():
            inv_perm = invert_perm(perm)
            for alpha_name, cand_arr, target_arr in alpha_pairs:
                # remap(Q3(plain)) = K4 => Q3(plain) = remap_inv(K4)
                permuted_target = target_arr[inv_perm]
                hits = kp_q3_attack(cand_arr, permuted_target, alpha_name,
                                    max_L=args.max_period)
                n_pipelines_tested += 1
                for ci, L, _alpha, conv in hits:
                    rec = {
                        "shape": "B_remap_after_q3",
                        "remap": remap_name,
                        "alphabet": alpha_name,
                        "convention": conv,
                        "period": L,
                        "candidate_index": ci,
                        "candidate": cands[ci],
                    }
                    out_f.write(json.dumps(rec) + "\n")
                    total_solves += 1
                    b_solves += 1
        print(f"  Shape B done; {b_solves} solves; "
              f"{time.perf_counter()-t1:.1f}s elapsed")

        # =============== Shape C: columnar ∘ Q3 ∘ remap ===============
        print()
        print(f"=== Shape C: columnar(W=W,perm) ∘ Q3 ∘ positional_remap ===")
        print(f"  [{len(columnar_perms)} columnar perms × "
              f"{len(POSITIONAL_REMAPS)} remaps × {len(alpha_pairs)} alphas = "
              f"{len(columnar_perms)*len(POSITIONAL_REMAPS)*len(alpha_pairs)} pipelines]")
        t1 = time.perf_counter()
        c_solves = 0
        # For speed: cache permuted candidates per remap
        cand_remapped_cache: dict[tuple[str, str], np.ndarray] = {}
        for remap_name, perm in POSITIONAL_REMAPS.items():
            for alpha_name, cand_arr, target_arr in alpha_pairs:
                cand_remapped_cache[(remap_name, alpha_name)] = cand_arr[:, perm]

        # Run columnar shape C
        ci_done = 0
        for W, col_perm in columnar_perms:
            col_perm_full = perm_columnar(W, col_perm)
            inv_col = invert_perm(col_perm_full)
            for alpha_name, cand_arr, target_arr in alpha_pairs:
                permuted_target = target_arr[inv_col]
                for remap_name, _ in POSITIONAL_REMAPS.items():
                    permuted_cand = cand_remapped_cache[(remap_name, alpha_name)]
                    hits = kp_q3_attack(permuted_cand, permuted_target, alpha_name,
                                        max_L=args.max_period)
                    n_pipelines_tested += 1
                    for ci, L, _alpha, conv in hits:
                        rec = {
                            "shape": "C_col_after_q3_after_remap",
                            "remap": remap_name,
                            "columnar_W": int(W),
                            "columnar_perm": list(col_perm),
                            "alphabet": alpha_name,
                            "convention": conv,
                            "period": L,
                            "candidate_index": ci,
                            "candidate": cands[ci],
                        }
                        out_f.write(json.dumps(rec) + "\n")
                        total_solves += 1
                        c_solves += 1
            ci_done += 1
            if ci_done % 500 == 0:
                print(f"  [{ci_done}/{len(columnar_perms)}] col perms done; "
                      f"{c_solves} solves so far; "
                      f"{time.perf_counter()-t1:.1f}s")
        print(f"  Shape C done; {c_solves} solves; "
              f"{time.perf_counter()-t1:.1f}s elapsed")

        elapsed = time.perf_counter() - t0
        out_f.write(json.dumps({
            "summary": True,
            "n_candidates": len(cands),
            "n_pipelines_tested": n_pipelines_tested,
            "total_solves": total_solves,
            "elapsed_s": round(elapsed, 1),
        }) + "\n")

    print()
    print(f"=== TOTAL SOLVES across all Compose pipeline shapes: {total_solves} ===")
    print(f"  Pipelines tested:  {n_pipelines_tested:,}")
    print(f"  Elapsed:           {elapsed:.1f}s")
    print(f"  JSONL:             {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
