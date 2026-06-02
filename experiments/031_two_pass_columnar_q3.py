"""031 — Two-pass columnar transposition (K3-style), optionally followed
by Quagmire III. Closes attack gap B1 + B4.

K3 actually uses TWO PASSES of columnar transposition with KRYPTOS-keyword
column ordering on a 7-wide grid. Our existing ColumnarTransposition is
single-pass. Sanborn's stated "I modified Scheidt's systems" is most
naturally read as K3's two-pass transposition followed by K1/K2's Q3 —
exactly the unexplored multistage composite.

Pipelines tested:

  Shape B1 (two-pass columnar only):
    pipeline(plain) = col2(col1(plain, kw1), kw2)
    For each candidate × (kw1, kw2): encrypt, compare to K4

  Shape B4 (two-pass columnar + Q3):
    pipeline(plain) = Q3(col2(col1(plain, kw1), kw2), q3_key)
    Equivalent to Q3 known-plaintext on (col2(col1(cand)), K4)

Keyword pool (Sanborn-natural choices): KRYPTOS, ABSCISSA, PALIMPSEST,
BERLIN, CLOCK, BERLINCLOCK, WELTZEITUHR, DYAHR, SANBORN, LANGLEY,
IQLUSION, UNDERGRUUND. Each yields a column_order tuple for its
respective width.

A WIN is any (candidate, kw1, kw2) or (candidate, kw1, kw2, q3_key, alpha,
convention) where encrypt(candidate) byte-matches K4.

Output: experiments/results/2026-05-23_031_two_pass_columnar_q3.jsonl
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np

from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, Alphabet
from kryptos.ciphers.transposition import ColumnarTransposition
from kryptos.constants import K4

K4_TEXT = K4
N = 97
MAX_PERIOD = 15


# Sanborn-natural keyword pool
KEYWORDS: list[str] = [
    "KRYPTOS",     # K1/K2 key, K3 column-order keyword
    "ABSCISSA",    # K2 key
    "PALIMPSEST",  # K1 key
    "BERLIN",
    "CLOCK",
    "BERLINCLOCK",
    "WELTZEITUHR",
    "DYAHR",       # superscript on the sculpture
    "SANBORN",
    "LANGLEY",
    "IQLUSION",    # K1's misspelled word
    "UNDERGRUUND", # K2's misspelled word
]


def keyword_column_order(keyword: str) -> tuple[int, ...]:
    """For a keyword of length W, derive a column-order tuple: the
    permutation (c_0, c_1, …, c_{W-1}) where c_k is the original column
    index whose letter has alphabetical rank k+1 in the keyword. This
    is the standard columnar-transposition convention (same as K3)."""
    indexed = list(enumerate(keyword))
    sorted_letters = sorted(indexed, key=lambda kv: (kv[1], kv[0]))
    return tuple(idx for idx, _ in sorted_letters)


def load_candidates(run_dir: Path) -> list[str]:
    out: list[str] = []
    for f in sorted(run_dir.glob("*_parsed.txt")):
        for line in f.read_text().splitlines():
            line = line.strip()
            if len(line) == 97 and line.isalpha() and line.isupper():
                out.append(line)
    return out


def encode_string(text: str, alphabet: Alphabet) -> np.ndarray:
    return np.fromiter((alphabet.index(c) for c in text), dtype=np.int16, count=len(text))


def encode_array(texts: list[str], alphabet: Alphabet) -> np.ndarray:
    arr = np.empty((len(texts), N), dtype=np.int16)
    for r, t in enumerate(texts):
        for c, ch in enumerate(t):
            arr[r, c] = alphabet.index(ch)
    return arr


def col_permutation_full(width: int, col_order: tuple[int, ...]) -> np.ndarray:
    """Build the length-N permutation array that columnar-transposes a
    97-char string with the given column_order (and padding to width)."""
    rows = (N + width - 1) // width
    rem = N - (rows - 1) * width
    perm = []
    for col_to_read in col_order:
        for row in range(rows):
            src = row * width + col_to_read
            if src < N:
                perm.append(src)
    return np.array(perm, dtype=np.int32)


def required_key(cand_idx, cipher_idx, convention, n_letters=26):
    cands = cand_idx.astype(np.int16)
    cipher = cipher_idx.astype(np.int16)[None, :]
    if convention == "vigenere":
        return ((cipher - cands) % n_letters).astype(np.int8)
    if convention == "beaufort":
        return ((cipher + cands) % n_letters).astype(np.int8)
    if convention == "variant_beaufort":
        return ((cands - cipher) % n_letters).astype(np.int8)
    raise ValueError(convention)


def check_slot_consistency(req_key, L):
    n_cands, M = req_key.shape
    ok = np.ones(n_cands, dtype=bool)
    for s in range(L):
        positions = list(range(s, M, L))
        if len(positions) <= 1:
            continue
        vals = req_key[:, positions]
        ref = vals[:, 0:1]
        ok &= np.all(vals == ref, axis=1)
    return ok


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run-dir", type=Path, default=None)
    p.add_argument("--out", type=Path,
                   default=Path("experiments/results/2026-05-23_031_two_pass_columnar_q3.jsonl"))
    p.add_argument("--keywords", nargs="*", default=None,
                   help="override the default keyword pool")
    p.add_argument("--max-period", type=int, default=MAX_PERIOD)
    p.add_argument("--shape", choices=["B1", "B4", "both"], default="both")
    args = p.parse_args()

    if args.run_dir is None:
        base = Path("experiments/results/n1_claude_outputs")
        runs = sorted(d for d in base.iterdir() if d.is_dir() and "sonnet" in d.name)
        args.run_dir = runs[-1]
    cands = load_candidates(args.run_dir)
    print(f"Using {args.run_dir}")
    print(f"Candidates: {len(cands)}")

    keywords = args.keywords or KEYWORDS

    # Precompute column-order full-length permutations for each keyword
    print(f"\nKeywords: {keywords}")
    perms: dict[str, np.ndarray] = {}
    for kw in keywords:
        if not (3 <= len(kw) <= 15):
            print(f"  skipping {kw}: width {len(kw)} out of range 3-15")
            continue
        order = keyword_column_order(kw)
        perms[kw] = col_permutation_full(len(kw), order)
        print(f"  {kw} (W={len(kw)}): column_order={order}")

    cands_std = encode_array(cands, STANDARD)
    cands_kk = encode_array(cands, KRYPTOS_KEYED)
    K4_std = encode_string(K4_TEXT, STANDARD)
    K4_kk = encode_string(K4_TEXT, KRYPTOS_KEYED)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    total_b1 = 0
    total_b4 = 0
    t0 = time.perf_counter()
    near_miss_b1 = (-1, None)  # (n_match, info)
    near_miss_b4 = (-1, None)

    with open(args.out, "w") as f:
        kw_list = list(perms.keys())

        # ----- Shape B1: pure two-pass columnar
        if args.shape in ("B1", "both"):
            print(f"\n=== Shape B1: pipeline(plain) = col2(col1(plain, kw1), kw2) ===")
            t1 = time.perf_counter()
            for i, kw1 in enumerate(kw_list):
                p1 = perms[kw1]
                # First pass: cands_std[:, p1]
                pass1 = cands_std[:, p1]
                for kw2 in kw_list:
                    p2 = perms[kw2]
                    pass2 = pass1[:, p2[:pass1.shape[1]]] if p2.shape[0] >= pass1.shape[1] else None
                    if pass2 is None or pass2.shape[1] != N:
                        continue
                    # Compare to K4 byte-by-byte
                    match_count = (pass2 == K4_std[None, :]).sum(axis=1)
                    full = np.where(match_count == N)[0]
                    for ci in full:
                        rec = {
                            "shape": "B1",
                            "kw1": kw1, "kw2": kw2,
                            "candidate_index": int(ci),
                            "candidate": cands[ci],
                            "SOLVED": True,
                        }
                        f.write(json.dumps(rec) + "\n")
                        total_b1 += 1
                        print(f"  *** B1 SOLVE: kw1={kw1}, kw2={kw2}, cand[{ci}] ***")
                    # Track best partial
                    best_idx = int(np.argmax(match_count))
                    if match_count[best_idx] > near_miss_b1[0]:
                        near_miss_b1 = (int(match_count[best_idx]),
                                        {"kw1": kw1, "kw2": kw2, "cand_idx": best_idx})
            print(f"  Shape B1 done; {total_b1} solves; best partial {near_miss_b1[0]}/97; "
                  f"{time.perf_counter()-t1:.1f}s elapsed")

        # ----- Shape B4: two-pass columnar + Q3 known-plaintext
        if args.shape in ("B4", "both"):
            print(f"\n=== Shape B4: Q3(col2(col1(plain, kw1), kw2), q3_key) ===")
            t2 = time.perf_counter()
            for kw1 in kw_list:
                p1 = perms[kw1]
                pass1_std = cands_std[:, p1]
                pass1_kk = cands_kk[:, p1]
                for kw2 in kw_list:
                    p2 = perms[kw2]
                    if p2.shape[0] < pass1_std.shape[1]:
                        continue
                    pass2_std = pass1_std[:, p2[:pass1_std.shape[1]]]
                    pass2_kk = pass1_kk[:, p2[:pass1_kk.shape[1]]]
                    if pass2_std.shape[1] != N:
                        continue
                    # For each alphabet × convention × period, KP attack
                    for alpha_name, cipher_arr, post_perm_cands in (
                        ("standard", K4_std, pass2_std),
                        ("kryptos_keyed", K4_kk, pass2_kk),
                    ):
                        for conv in ("vigenere", "beaufort", "variant_beaufort"):
                            req = required_key(post_perm_cands, cipher_arr, conv)
                            for L in range(1, args.max_period + 1):
                                ok = check_slot_consistency(req, L)
                                for ci in np.where(ok)[0]:
                                    rec = {
                                        "shape": "B4",
                                        "kw1": kw1, "kw2": kw2,
                                        "alphabet": alpha_name,
                                        "convention": conv,
                                        "period": L,
                                        "candidate_index": int(ci),
                                        "candidate": cands[ci],
                                        "SOLVED": True,
                                    }
                                    f.write(json.dumps(rec) + "\n")
                                    total_b4 += 1
            print(f"  Shape B4 done; {total_b4} solves; "
                  f"{time.perf_counter()-t2:.1f}s elapsed")

        elapsed = time.perf_counter() - t0
        f.write(json.dumps({
            "summary": True,
            "n_candidates": len(cands),
            "keywords": list(perms.keys()),
            "shape_B1_solves": total_b1,
            "shape_B4_solves": total_b4,
            "near_miss_B1": near_miss_b1,
            "elapsed_s": round(elapsed, 1),
        }) + "\n")

    print()
    print(f"=== Two-pass columnar + Q3 composite ===")
    print(f"  candidates:    {len(cands)}")
    print(f"  keywords:      {len(perms)}")
    print(f"  B1 solves:     {total_b1}")
    print(f"  B4 solves:     {total_b4}")
    print(f"  B1 best partial: {near_miss_b1[0]}/97 {near_miss_b1[1]}")
    print(f"  elapsed:       {elapsed:.1f}s")
    print(f"  JSONL:         {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
