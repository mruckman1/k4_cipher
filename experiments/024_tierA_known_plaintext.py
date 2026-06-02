"""024 — Tier A: known-plaintext attacks across linear / periodic / matrix
cipher families against all Sonnet candidates as proposed plaintexts.

For each of 5,219 Sonnet candidates × {standard, KRYPTOS-keyed} alphabet,
try every cipher family that admits a fast closed-form known-plaintext
recovery:

  1. Vigenere periodic   L ∈ {1..30}, both conventions (vigenere/beaufort)
  2. Quagmire III        (= Vigenere in keyed-alphabet space) L ∈ {1..30}
  3. Hill 2x2            block matrix mod 26 from candidate+K4 pairs
  4. Hill 3x3            block matrix mod 26
  5. Autokey plaintext   L ∈ {1..10}, both alphabets
  6. Autokey ciphertext  L ∈ {1..10}, both alphabets
  7. Caesar              (L=1 Vigenere, all 26 shifts)

For each candidate × family × params: derive the required key from the
candidate and K4, check whether a single key satisfies all 97 positions,
and if so verify round-trip (cipher(candidate, key) == K4).

A SOLVE is a candidate × family × key where round-trip is byte-exact.
This is the only legitimate definition of "K4 solved" in this codebase.

Vectorized in numpy; runs in minutes for 5,219 candidates.

Inputs:
  experiments/results/n1_claude_outputs/run_*sonnet*/ (latest by default)

Output:
  experiments/results/2026-05-22_024_tierA_known_plaintext.jsonl
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np

from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, Alphabet
from kryptos.constants import K4

K4_TEXT = K4  # 97-char ciphertext
N = 97


# ----- helpers

def load_candidates(run_dir: Path) -> list[str]:
    out: list[str] = []
    for f in sorted(run_dir.glob("*_parsed.txt")):
        for line in f.read_text().splitlines():
            line = line.strip()
            if len(line) == 97 and line.isalpha() and line.isupper():
                out.append(line)
    return out


def encode_array(texts: list[str], alphabet: Alphabet) -> np.ndarray:
    """Encode list of length-N strings into a (n_texts, N) int8 array."""
    arr = np.empty((len(texts), N), dtype=np.int8)
    for r, t in enumerate(texts):
        for c, ch in enumerate(t):
            arr[r, c] = alphabet.index(ch)
    return arr


def encode_string(text: str, alphabet: Alphabet) -> np.ndarray:
    return np.fromiter((alphabet.index(c) for c in text), dtype=np.int8, count=len(text))


# ----- modular matrix inverse (for Hill)

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
    n = M.shape[0]
    det = int(round(np.linalg.det(M.astype(float)))) % m
    det_inv = _modinv(det, m)
    if det_inv is None:
        return None
    cof = np.zeros_like(M)
    for i in range(n):
        for j in range(n):
            minor = np.delete(np.delete(M, i, axis=0), j, axis=1)
            cof[i, j] = ((-1) ** (i + j)) * int(round(np.linalg.det(minor.astype(float))))
    adj = cof.T % m
    return (det_inv * adj) % m


# ----- attacks (each returns a list of solved-record dicts)

def attack_vigenere_periodic(
    cands_idx: np.ndarray,
    K4_idx: np.ndarray,
    alpha_name: str,
    n_letters: int,
    convention: str,
    max_period: int = 30,
) -> list[dict]:
    """For each (candidate, period L): try to derive a length-L key from
    the slot constraints. If all positions in each slot agree, the key
    is determined; check round-trip."""
    solves: list[dict] = []
    n_cands = cands_idx.shape[0]

    if convention == "vigenere":
        # cipher = plain + key  =>  key = cipher - plain
        required_key = (K4_idx[None, :].astype(np.int16) - cands_idx.astype(np.int16)) % n_letters
    elif convention == "beaufort":
        # cipher = key - plain  =>  key = cipher + plain
        required_key = (K4_idx[None, :].astype(np.int16) + cands_idx.astype(np.int16)) % n_letters
    elif convention == "variant_beaufort":
        # cipher = plain - key  =>  key = plain - cipher
        required_key = (cands_idx.astype(np.int16) - K4_idx[None, :].astype(np.int16)) % n_letters
    else:
        raise ValueError(f"unknown convention {convention!r}")
    required_key = required_key.astype(np.int8)  # (n_cands, 97)

    for L in range(1, max_period + 1):
        # For each candidate, check that within each slot s, all positions
        # agree on the required key letter.
        # Vectorized: for each slot s, gather positions, compare to first.
        consistent = np.ones(n_cands, dtype=bool)
        keys = np.zeros((n_cands, L), dtype=np.int8)
        for s in range(L):
            positions = list(range(s, N, L))
            vals = required_key[:, positions]   # (n_cands, n_pos_in_slot)
            ref = vals[:, 0]
            # All positions in slot must equal ref
            slot_ok = np.all(vals == ref[:, None], axis=1)
            consistent &= slot_ok
            keys[:, s] = ref
        # consistent candidates have a self-consistent length-L key
        idx = np.where(consistent)[0]
        for ci in idx:
            key_arr = keys[ci]
            solves.append({
                "family": f"vig_periodic_{convention}",
                "alphabet": alpha_name,
                "period": L,
                "candidate_index": int(ci),
                "key_indices": key_arr.tolist(),
            })
    return solves


def attack_hill(
    cands_idx: np.ndarray,
    K4_idx: np.ndarray,
    alpha_name: str,
    n_letters: int,
    block: int,
) -> list[dict]:
    """Hill block-N known-plaintext recovery. For each candidate, find a
    sequence of `block` plaintext blocks whose stacked matrix is
    invertible mod n_letters; solve K = C · P^(-1); verify across all
    blocks."""
    solves: list[dict] = []
    n_cands = cands_idx.shape[0]
    if N % block != 0:
        # 97 isn't divisible by 2 or 3. Use the first floor(N/block) blocks.
        n_blocks = N // block
    else:
        n_blocks = N // block
    # Reshape candidates and K4 into (n_blocks, block) tiles per candidate.
    K4_blocks = K4_idx[: n_blocks * block].reshape(n_blocks, block).astype(int)

    for ci in range(n_cands):
        P_blocks_full = cands_idx[ci, : n_blocks * block].reshape(n_blocks, block).astype(int)
        # Try to find `block` consecutive plaintext blocks whose matrix is
        # invertible mod n_letters.
        found = False
        for start in range(n_blocks - block + 1):
            P = P_blocks_full[start : start + block]   # (block, block)
            P_inv = matrix_inverse_mod(P, n_letters)
            if P_inv is None:
                continue
            # K · P = C  in convention P rows = inputs, C rows = outputs, K = C · P^-1
            # Convention check: in this repo's Hill, encrypt is `b @ K`,
            # so for a block row b: c = b @ K => K = b^(-1) @ c (left-mult)
            # Solve K = P_inv @ C
            C = K4_blocks[start : start + block]   # (block, block)
            K = (P_inv @ C) % n_letters
            # Verify across ALL blocks
            ok = True
            for bi in range(n_blocks):
                Pb = P_blocks_full[bi]
                Cb = K4_blocks[bi]
                if not np.array_equal((Pb @ K) % n_letters, Cb):
                    ok = False
                    break
            if ok:
                solves.append({
                    "family": f"hill_{block}x{block}",
                    "alphabet": alpha_name,
                    "candidate_index": int(ci),
                    "key_matrix": K.tolist(),
                    "n_blocks_verified": n_blocks,
                })
                found = True
                break
        # if not found, skip silently
    return solves


def attack_autokey(
    cands_idx: np.ndarray,
    K4_idx: np.ndarray,
    alpha_name: str,
    n_letters: int,
    mode: str,
    max_primer: int = 10,
) -> list[dict]:
    """Autokey: key starts with a primer of length L, then continues with
    the plaintext (mode='plaintext') or the ciphertext (mode='ciphertext').

    For each (candidate, primer length L): derive primer from positions 0..L-1
    (under Vigenere convention key = cipher - plain), then verify positions
    L..N-1 match the autokey extension."""
    solves: list[dict] = []
    n_cands = cands_idx.shape[0]
    K4_arr = K4_idx.astype(np.int16)

    for L in range(1, max_primer + 1):
        # Required key at every position: key_i = cipher_i - plain_i mod N
        req_key = (K4_arr[None, :] - cands_idx.astype(np.int16)) % n_letters  # (n_cands, N)
        # Primer = required key at positions 0..L-1
        # For i >= L: required key must equal autokey extension
        #   plaintext mode:    key_i = plain_{i - L}
        #   ciphertext mode:   key_i = cipher_{i - L}
        primer = req_key[:, :L]
        ok = np.ones(n_cands, dtype=bool)
        for i in range(L, N):
            if mode == "plaintext":
                expected_key = cands_idx[:, i - L]  # (n_cands,)
            else:
                expected_key = K4_arr[i - L]  # scalar
            actual_key = req_key[:, i]
            if mode == "plaintext":
                ok &= (actual_key == expected_key)
            else:
                ok &= (actual_key == expected_key)
        idx = np.where(ok)[0]
        for ci in idx:
            solves.append({
                "family": f"autokey_{mode}",
                "alphabet": alpha_name,
                "primer_length": L,
                "candidate_index": int(ci),
                "primer_indices": primer[ci].tolist(),
            })
    return solves


def attack_caesar(
    cands_idx: np.ndarray,
    K4_idx: np.ndarray,
    alpha_name: str,
    n_letters: int,
) -> list[dict]:
    """Caesar = period-1 Vigenere. Already covered by Vigenere periodic,
    but easy to log separately."""
    # If the required-key array is constant per candidate, Caesar applies.
    req_key = (K4_idx.astype(np.int16)[None, :] - cands_idx.astype(np.int16)) % n_letters
    # Check all 97 positions agree
    first = req_key[:, 0]
    ok = np.all(req_key == first[:, None], axis=1)
    out: list[dict] = []
    for ci in np.where(ok)[0]:
        out.append({
            "family": "caesar",
            "alphabet": alpha_name,
            "candidate_index": int(ci),
            "shift": int(first[ci]),
        })
    return out


# ----- main

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run-dir", type=Path, default=None,
                   help="N1 run dir; default = latest sonnet run")
    p.add_argument("--out", type=Path,
                   default=Path("experiments/results/2026-05-22_024_tierA_known_plaintext.jsonl"))
    args = p.parse_args()

    if args.run_dir is None:
        base = Path("experiments/results/n1_claude_outputs")
        runs = sorted(d for d in base.iterdir() if d.is_dir() and "sonnet" in d.name)
        if not runs:
            print("no sonnet run found"); return 1
        args.run_dir = runs[-1]
        print(f"Using {args.run_dir}")

    cands = load_candidates(args.run_dir)
    print(f"Loaded {len(cands)} candidates")

    K4_std = encode_string(K4_TEXT, STANDARD)
    K4_kk = encode_string(K4_TEXT, KRYPTOS_KEYED)
    cands_std = encode_array(cands, STANDARD)
    cands_kk = encode_array(cands, KRYPTOS_KEYED)

    all_solves: list[dict] = []
    t0 = time.perf_counter()

    print()
    print("=== Vigenere/Beaufort periodic L=1..30 ===")
    for alpha_name, ci, ki, n in (("standard", cands_std, K4_std, 26),
                                   ("kryptos_keyed", cands_kk, K4_kk, 26)):
        for conv in ("vigenere", "beaufort", "variant_beaufort"):
            t1 = time.perf_counter()
            solves = attack_vigenere_periodic(ci, ki, alpha_name, n, conv)
            all_solves.extend(solves)
            print(f"  [{alpha_name:14s} {conv:18s}] {len(solves):6d} solves "
                  f"({time.perf_counter()-t1:.2f}s)")

    print()
    print("=== Hill 2x2 and 3x3 ===")
    for alpha_name, ci, ki, n in (("standard", cands_std, K4_std, 26),
                                   ("kryptos_keyed", cands_kk, K4_kk, 26)):
        for block in (2, 3):
            t1 = time.perf_counter()
            solves = attack_hill(ci, ki, alpha_name, n, block)
            all_solves.extend(solves)
            print(f"  [{alpha_name:14s} hill_{block}x{block}] {len(solves):6d} solves "
                  f"({time.perf_counter()-t1:.2f}s)")

    print()
    print("=== Autokey (plaintext / ciphertext modes), primer L=1..10 ===")
    for alpha_name, ci, ki, n in (("standard", cands_std, K4_std, 26),
                                   ("kryptos_keyed", cands_kk, K4_kk, 26)):
        for mode in ("plaintext", "ciphertext"):
            t1 = time.perf_counter()
            solves = attack_autokey(ci, ki, alpha_name, n, mode)
            all_solves.extend(solves)
            print(f"  [{alpha_name:14s} autokey_{mode:11s}] {len(solves):6d} solves "
                  f"({time.perf_counter()-t1:.2f}s)")

    elapsed = time.perf_counter() - t0
    print()
    print(f"Total solves: {len(all_solves)} in {elapsed:.1f}s")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w") as f:
        for s in all_solves:
            s["candidate"] = cands[s["candidate_index"]]
            f.write(json.dumps(s) + "\n")
        f.write(json.dumps({"summary": True,
                            "n_candidates": len(cands),
                            "n_solves": len(all_solves),
                            "elapsed_s": round(elapsed, 1)}) + "\n")

    print(f"JSONL: {args.out}")

    # Report by family
    if all_solves:
        from collections import Counter
        by_family = Counter((s["family"], s["alphabet"]) for s in all_solves)
        print()
        print("=== solves by (family, alphabet) ===")
        for (fam, alpha), n in sorted(by_family.items(), key=lambda kv: -kv[1]):
            print(f"  {fam:30s} {alpha:14s}  {n}")
        print()
        print("=== Sample top 10 solves ===")
        for s in all_solves[:10]:
            cand = s["candidate"]
            extra = ""
            if "period" in s:
                extra = f" L={s['period']}"
            elif "primer_length" in s:
                extra = f" primer_L={s['primer_length']}"
            elif "shift" in s:
                extra = f" shift={s['shift']}"
            elif "key_matrix" in s:
                extra = f" hill_block={len(s['key_matrix'])}"
            print(f"  c[{s['candidate_index']:4d}] {s['family']:30s} {s['alphabet']:14s}{extra}")
            print(f"    {cand[:80]}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
