"""026 — Tier B: composite Q3 + transforms known-plaintext attacks.

Three composite families that extend periodic Quagmire III with a
single structural modification, tested against all 5,220 Sonnet
candidate plaintexts:

  A. Arithmetic position offset (slope-a, intercept-b):
       cipher_i = plain_i + key[i mod L] + a*i + b   (mod 26)
     For each (a, b, L, alpha, conv): per-position required key
     = (cipher - plain - a*i - b) mod 26, then per-slot
     consistency check. (a=0 reduces to plain Q3 + Caesar,
     already covered by Tier A; we sweep a in 1..25.)

  B. Reversed ciphertext / plaintext direction:
       (B1) cipher = Q3(reverse(plain)), or equivalently
            reverse(cipher) = Q3(plain)
       (B2) reverse(cipher) = Q3(reverse(plain))
     Sanborn's K2 plaintext encryption had a length anomaly; this
     tests whether a directional flip is the modification.

  D. Even/odd interleaved dual-key Q3:
       positions {0, 2, 4, ...} encrypted with key_A length L_A
       positions {1, 3, 5, ...} encrypted with key_B length L_B
     For each candidate × (L_A, L_B, alpha, conv): derive both
     keys, check both for internal consistency.

(Family C: W-partition dual-key Q3 — subsumed by exp 025, which
tested W-segmented heterogeneous with up to 6 independent keys
and found 0 fully-solved candidates.)

Output: experiments/results/2026-05-22_026_composite_q3_transforms.jsonl
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
MAX_L = 15


def load_candidates(run_dir: Path) -> list[str]:
    out: list[str] = []
    for f in sorted(run_dir.glob("*_parsed.txt")):
        for line in f.read_text().splitlines():
            line = line.strip()
            if len(line) == 97 and line.isalpha() and line.isupper():
                out.append(line)
    return out


def encode_array(texts: list[str], alphabet: Alphabet) -> np.ndarray:
    arr = np.empty((len(texts), N), dtype=np.int8)
    for r, t in enumerate(texts):
        for c, ch in enumerate(t):
            arr[r, c] = alphabet.index(ch)
    return arr


def encode_string(text: str, alphabet: Alphabet) -> np.ndarray:
    return np.fromiter((alphabet.index(c) for c in text), dtype=np.int8, count=len(text))


def required_key(
    cands_idx: np.ndarray,    # (n_cands, N)
    cipher_idx: np.ndarray,   # (N,)
    convention: str,
    n_letters: int = 26,
) -> np.ndarray:
    """Return required key array shape (n_cands, N) under the given
    convention."""
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
    """For required key shape (n_cands, N), return bool array (n_cands,)
    indicating whether a length-L periodic key satisfies all positions."""
    n_cands, N = req_key.shape
    ok = np.ones(n_cands, dtype=bool)
    for slot in range(L):
        positions = list(range(slot, N, L))
        if len(positions) <= 1:
            continue
        vals = req_key[:, positions]
        ref = vals[:, 0:1]
        ok &= np.all(vals == ref, axis=1)
    return ok


# ----- Family A: Q3 with arithmetic offset

def family_A_arithmetic_offset(
    cands_idx: np.ndarray,
    cipher_idx: np.ndarray,
    alpha_name: str,
    n_letters: int,
    out_jsonl,
) -> int:
    """For a*i + b additive offset, find any (a, b, L, conv) that makes
    cribs+plaintext consistent at period L."""
    n_solves = 0
    i_arr = np.arange(N, dtype=np.int16)
    base_req = {}
    for conv in ("vigenere", "beaufort", "variant_beaufort"):
        base_req[conv] = required_key(cands_idx, cipher_idx, conv, n_letters)

    for a in range(1, n_letters):  # a=0 = plain Q3 (Tier A)
        ai = (a * i_arr) % n_letters
        for b in range(n_letters):
            ab_offset = (ai + b) % n_letters
            for conv in ("vigenere", "beaufort", "variant_beaufort"):
                # required key' = required key - (a*i + b) mod 26
                shifted = ((base_req[conv].astype(np.int16) - ab_offset[None, :]) % n_letters).astype(np.int8)
                for L in range(1, MAX_L + 1):
                    ok = check_slot_consistency(shifted, L)
                    if not ok.any():
                        continue
                    for ci in np.where(ok)[0]:
                        n_solves += 1
                        out_jsonl.write(json.dumps({
                            "family": "A_arith_offset",
                            "alphabet": alpha_name,
                            "convention": conv,
                            "slope_a": int(a),
                            "intercept_b": int(b),
                            "period": L,
                            "candidate_index": int(ci),
                        }) + "\n")
    return n_solves


# ----- Family B: reversed direction

def family_B_reversed(
    cands_idx: np.ndarray,
    cands_rev_idx: np.ndarray,
    cipher_idx: np.ndarray,
    cipher_rev_idx: np.ndarray,
    alpha_name: str,
    n_letters: int,
    out_jsonl,
) -> int:
    n_solves = 0
    variants = [
        ("B1_rev_plain", cands_rev_idx, cipher_idx),
        ("B2_rev_cipher", cands_idx, cipher_rev_idx),
        ("B3_rev_both", cands_rev_idx, cipher_rev_idx),
    ]
    for label, ci, ki in variants:
        for conv in ("vigenere", "beaufort", "variant_beaufort"):
            req = required_key(ci, ki, conv, n_letters)
            for L in range(1, MAX_L + 1):
                ok = check_slot_consistency(req, L)
                for cidx in np.where(ok)[0]:
                    n_solves += 1
                    out_jsonl.write(json.dumps({
                        "family": label,
                        "alphabet": alpha_name,
                        "convention": conv,
                        "period": L,
                        "candidate_index": int(cidx),
                    }) + "\n")
    return n_solves


# ----- Family D: even/odd interleaved dual-key

def family_D_even_odd(
    cands_idx: np.ndarray,
    cipher_idx: np.ndarray,
    alpha_name: str,
    n_letters: int,
    out_jsonl,
    max_LA: int = 10,
    max_LB: int = 10,
) -> int:
    n_solves = 0
    even_pos = np.array(list(range(0, N, 2)), dtype=np.int32)
    odd_pos = np.array(list(range(1, N, 2)), dtype=np.int32)

    for conv in ("vigenere", "beaufort", "variant_beaufort"):
        req_full = required_key(cands_idx, cipher_idx, conv, n_letters)
        req_even = req_full[:, even_pos]  # (n_cands, n_even)
        req_odd  = req_full[:, odd_pos]   # (n_cands, n_odd)
        n_even = req_even.shape[1]
        n_odd  = req_odd.shape[1]

        # Per even-period L_A, check consistency on req_even
        even_ok_by_L = {}
        for L_A in range(1, max_LA + 1):
            ok = np.ones(cands_idx.shape[0], dtype=bool)
            for slot in range(L_A):
                positions = list(range(slot, n_even, L_A))
                if len(positions) <= 1:
                    continue
                vals = req_even[:, positions]
                ref = vals[:, 0:1]
                ok &= np.all(vals == ref, axis=1)
            even_ok_by_L[L_A] = ok

        odd_ok_by_L = {}
        for L_B in range(1, max_LB + 1):
            ok = np.ones(cands_idx.shape[0], dtype=bool)
            for slot in range(L_B):
                positions = list(range(slot, n_odd, L_B))
                if len(positions) <= 1:
                    continue
                vals = req_odd[:, positions]
                ref = vals[:, 0:1]
                ok &= np.all(vals == ref, axis=1)
            odd_ok_by_L[L_B] = ok

        for L_A, eok in even_ok_by_L.items():
            for L_B, ook in odd_ok_by_L.items():
                both = eok & ook
                for ci in np.where(both)[0]:
                    n_solves += 1
                    out_jsonl.write(json.dumps({
                        "family": "D_even_odd",
                        "alphabet": alpha_name,
                        "convention": conv,
                        "L_even": int(L_A),
                        "L_odd": int(L_B),
                        "candidate_index": int(ci),
                    }) + "\n")
    return n_solves


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run-dir", type=Path, default=None)
    p.add_argument("--out", type=Path,
                   default=Path("experiments/results/2026-05-22_026_composite_q3_transforms.jsonl"))
    args = p.parse_args()

    if args.run_dir is None:
        base = Path("experiments/results/n1_claude_outputs")
        runs = sorted(d for d in base.iterdir() if d.is_dir() and "sonnet" in d.name)
        args.run_dir = runs[-1]
        print(f"Using {args.run_dir}")

    cands = load_candidates(args.run_dir)
    print(f"Loaded {len(cands)} candidates.")
    cands_rev = [c[::-1] for c in cands]

    K4_std = encode_string(K4_TEXT, STANDARD)
    K4_kk = encode_string(K4_TEXT, KRYPTOS_KEYED)
    K4_std_rev = K4_std[::-1].copy()
    K4_kk_rev = K4_kk[::-1].copy()
    cands_std = encode_array(cands, STANDARD)
    cands_kk = encode_array(cands, KRYPTOS_KEYED)
    cands_std_rev = encode_array(cands_rev, STANDARD)
    cands_kk_rev = encode_array(cands_rev, KRYPTOS_KEYED)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    total_solves = {"A": 0, "B": 0, "D": 0}

    with open(args.out, "w") as f:
        # Family A
        print()
        print("=== Family A: Q3 with arithmetic offset (a*i + b) ===")
        t0 = time.perf_counter()
        for alpha_name, ci, ki, n in (("standard", cands_std, K4_std, 26),
                                       ("kryptos_keyed", cands_kk, K4_kk, 26)):
            s = family_A_arithmetic_offset(ci, ki, alpha_name, n, f)
            total_solves["A"] += s
            print(f"  [{alpha_name:14s}] {s} solves ({time.perf_counter()-t0:.1f}s)")

        # Family B
        print()
        print("=== Family B: reversed plaintext / ciphertext ===")
        t0 = time.perf_counter()
        for alpha_name, ci, ci_rev, ki, ki_rev, n in (
            ("standard", cands_std, cands_std_rev, K4_std, K4_std_rev, 26),
            ("kryptos_keyed", cands_kk, cands_kk_rev, K4_kk, K4_kk_rev, 26),
        ):
            s = family_B_reversed(ci, ci_rev, ki, ki_rev, alpha_name, n, f)
            total_solves["B"] += s
            print(f"  [{alpha_name:14s}] {s} solves ({time.perf_counter()-t0:.1f}s)")

        # Family D
        print()
        print("=== Family D: even/odd interleaved dual-key Q3 ===")
        t0 = time.perf_counter()
        for alpha_name, ci, ki, n in (("standard", cands_std, K4_std, 26),
                                       ("kryptos_keyed", cands_kk, K4_kk, 26)):
            s = family_D_even_odd(ci, ki, alpha_name, n, f)
            total_solves["D"] += s
            print(f"  [{alpha_name:14s}] {s} solves ({time.perf_counter()-t0:.1f}s)")

        f.write(json.dumps({"summary": True, "n_candidates": len(cands),
                            "n_solves_by_family": total_solves}) + "\n")

    grand_total = sum(total_solves.values())
    print()
    print(f"=== TOTAL SOLVES across all 3 families: {grand_total} ===")
    print(f"  Family A (arithmetic offset):        {total_solves['A']}")
    print(f"  Family B (reversed direction):       {total_solves['B']}")
    print(f"  Family D (even/odd interleaved):     {total_solves['D']}")
    print(f"JSONL: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
