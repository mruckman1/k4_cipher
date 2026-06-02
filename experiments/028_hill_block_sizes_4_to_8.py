"""028 — Tier B: Hill cipher known-plaintext attack at block sizes 4-8.

Tier A (exp 024) covered Hill 2x2 and 3x3 with zero solves. This
extends the search to block sizes 4-8 against all 5,220 Sonnet
candidates × both alphabets.

(Originally Tier B was going to include ADFGVX. ADFGVX/ADFGX are
length-doubling ciphers — each plaintext char produces 2 substituted
chars, then columnar transposition preserves the doubled length. K4
is 97 chars; standard ADFGVX needs a 48.5-char plaintext. Structurally
ruled out. Hill at block sizes 4-8 is the natural "matrix-cipher
extension" target the matrix-encryption conjecture from Bauer/Link/
Molle 2016 explicitly addresses.)

For each Hill block size B:
  - K4 splits into ⌊97/B⌋ full blocks + a possible partial block
  - For each candidate × alphabet: try to find B consecutive blocks
    whose plaintext matrix is invertible mod 26; solve K = P⁻¹ · C;
    verify across all full blocks.

A WIN is any (candidate, B, alphabet, key_matrix) where every full
block in K4 matches the predicted cipher output.

Output: experiments/results/2026-05-22_028_hill_block_sizes_4_to_8.jsonl
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np

from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, Alphabet
from kryptos.constants import K4

K4_TEXT = K4
N = 97
BLOCK_SIZES = [4, 5, 6, 7, 8]


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


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def _modinv(a: int, m: int) -> int | None:
    a %= m
    if a == 0:
        return None
    g, x, _ = _egcd(a, m)
    if g != 1:
        return None
    return x % m


def matrix_inverse_mod(M: np.ndarray, m: int) -> np.ndarray | None:
    """Inverse of integer matrix M mod m. Returns None if not invertible."""
    n = M.shape[0]
    det = int(round(np.linalg.det(M.astype(float)))) % m
    det_inv = _modinv(det, m)
    if det_inv is None:
        return None
    if n == 1:
        return np.array([[det_inv]], dtype=int) % m
    cof = np.zeros((n, n), dtype=int)
    for i in range(n):
        for j in range(n):
            minor = np.delete(np.delete(M, i, axis=0), j, axis=1)
            cof[i, j] = ((-1) ** (i + j)) * int(round(np.linalg.det(minor.astype(float))))
    adj = cof.T % m
    return (det_inv * adj) % m


def attack_hill_block(
    cands_idx: np.ndarray,        # (n_cands, N) int16
    K4_idx: np.ndarray,           # (N,) int16
    alpha_name: str,
    n_letters: int,
    block: int,
) -> list[dict]:
    """Find any (candidate, key_matrix) such that all full Hill blocks
    of K4 are produced from the candidate's blocks."""
    n_full = N // block
    n_cands = cands_idx.shape[0]
    K4_blocks = K4_idx[: n_full * block].reshape(n_full, block).astype(int)

    solves: list[dict] = []
    for ci in range(n_cands):
        P_full = cands_idx[ci, : n_full * block].reshape(n_full, block).astype(int)
        # Try each window of `block` consecutive plaintext blocks
        for start in range(n_full - block + 1):
            P = P_full[start : start + block]
            if int(round(np.linalg.det(P.astype(float)))) % n_letters == 0:
                continue
            P_inv = matrix_inverse_mod(P, n_letters)
            if P_inv is None:
                continue
            C = K4_blocks[start : start + block]
            K = (P_inv @ C) % n_letters
            # Verify on all full blocks
            predicted = (P_full @ K) % n_letters
            if np.array_equal(predicted, K4_blocks):
                solves.append({
                    "family": f"hill_{block}x{block}",
                    "alphabet": alpha_name,
                    "candidate_index": int(ci),
                    "key_matrix": K.tolist(),
                    "window_start": int(start),
                    "n_blocks_verified": n_full,
                })
                break  # one solve per candidate per family is enough
    return solves


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run-dir", type=Path, default=None)
    p.add_argument("--out", type=Path,
                   default=Path("experiments/results/2026-05-22_028_hill_block_sizes_4_to_8.jsonl"))
    p.add_argument("--block-sizes", type=int, nargs="+", default=BLOCK_SIZES)
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

    t0 = time.perf_counter()
    with open(args.out, "w") as f:
        for B in args.block_sizes:
            print()
            print(f"=== Hill {B}x{B} ===")
            for alpha_name, ci, ki, n in (("standard", cands_std, K4_std, 26),
                                           ("kryptos_keyed", cands_kk, K4_kk, 26)):
                t1 = time.perf_counter()
                solves = attack_hill_block(ci, ki, alpha_name, n, B)
                total_solves += len(solves)
                print(f"  [{alpha_name:14s}] {len(solves):>6} solves "
                      f"({time.perf_counter()-t1:.1f}s)")
                for s in solves:
                    s["candidate"] = cands[s["candidate_index"]]
                    f.write(json.dumps(s) + "\n")
        f.write(json.dumps({
            "summary": True,
            "n_candidates": len(cands),
            "total_solves": total_solves,
            "block_sizes_tested": args.block_sizes,
            "elapsed_s": round(time.perf_counter() - t0, 1),
        }) + "\n")

    elapsed = time.perf_counter() - t0
    print()
    print(f"=== Total Hill solves across block sizes {args.block_sizes}: {total_solves} ===")
    print(f"Elapsed: {elapsed:.1f}s")
    print(f"JSONL: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
