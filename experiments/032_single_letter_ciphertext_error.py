"""032 — Single-letter ciphertext error model + Q3/Vigenere known-plaintext.

K2 has the "IDBYROWS" anomaly: Sanborn dropped a letter at encryption time,
which mis-aligned the keystream for the rest of K2. K4 may have a
deliberate or accidental single-letter error of a different kind: a
single ciphertext letter altered (not a positional shift, but a substitution
in place).

This experiment tests EVERY (cand, ciphertext_alter_position, new_letter)
× Q3-family known-plaintext attack:

  For each candidate × each of 97 positions × each of 25 substitution letters:
    Form K4' = K4 with one letter substituted at that position
    Run Q3/Vigenere known-plaintext attack on (candidate, K4')
    If a self-consistent length-L periodic key exists for any L ∈ {1..30},
    both alphabets, both conventions → log as a potential solve.

Distinct from exp 021 (which perturbed CRIB positions/values) and exp 007
(which tested generator-shift-sequence vs single-char ciphertext edits).
Both negative. The new angle here is full Q3 KP attack with the candidate
as known plaintext and ONE letter of K4 altered.

A WIN is any (candidate, alter_pos, new_letter, key, alpha, conv, L) that
satisfies the consistency check across all 97 positions.

Output: experiments/results/2026-05-23_032_single_letter_ciphertext_error.jsonl
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
MAX_PERIOD = 30


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


def required_key_vector(cands_idx, cipher_idx, convention, n_letters=26):
    cands = cands_idx.astype(np.int16)
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
                   default=Path("experiments/results/2026-05-23_032_single_letter_ciphertext_error.jsonl"))
    p.add_argument("--max-period", type=int, default=MAX_PERIOD)
    p.add_argument("--alphabets", nargs="+", default=["standard", "kryptos_keyed"])
    p.add_argument("--positions", type=int, nargs="+", default=None,
                   help="explicit positions to alter (default = all 97)")
    args = p.parse_args()

    if args.run_dir is None:
        base = Path("experiments/results/n1_claude_outputs")
        runs = sorted(d for d in base.iterdir() if d.is_dir() and "sonnet" in d.name)
        args.run_dir = runs[-1]
    cands = load_candidates(args.run_dir)
    print(f"Using {args.run_dir}")
    print(f"Candidates: {len(cands)}")

    K4_std_orig = encode_string(K4_TEXT, STANDARD)
    K4_kk_orig = encode_string(K4_TEXT, KRYPTOS_KEYED)
    cands_std = encode_array(cands, STANDARD)
    cands_kk = encode_array(cands, KRYPTOS_KEYED)

    alpha_pairs = []
    if "standard" in args.alphabets:
        alpha_pairs.append(("standard", cands_std, K4_std_orig))
    if "kryptos_keyed" in args.alphabets:
        alpha_pairs.append(("kryptos_keyed", cands_kk, K4_kk_orig))

    positions = args.positions or list(range(N))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    total_solves = 0
    t0 = time.perf_counter()

    with open(args.out, "w") as f:
        for alpha_name, cand_arr, K4_orig in alpha_pairs:
            n_letters = 26
            for pos in positions:
                orig_letter_idx = int(K4_orig[pos])
                # Mutate this position to each of the 25 other letters
                for new_letter_idx in range(n_letters):
                    if new_letter_idx == orig_letter_idx:
                        continue
                    K4_mod = K4_orig.copy()
                    K4_mod[pos] = new_letter_idx
                    for conv in ("vigenere", "beaufort", "variant_beaufort"):
                        req = required_key_vector(cand_arr, K4_mod, conv)
                        for L in range(1, args.max_period + 1):
                            ok = check_slot_consistency(req, L)
                            for ci in np.where(ok)[0]:
                                rec = {
                                    "alphabet": alpha_name,
                                    "alter_pos": int(pos),
                                    "orig_letter": chr(ord("A") + orig_letter_idx)
                                        if alpha_name == "standard"
                                        else K4_TEXT[pos],
                                    "new_letter_idx": int(new_letter_idx),
                                    "convention": conv,
                                    "period": L,
                                    "candidate_index": int(ci),
                                    "candidate": cands[ci],
                                    "SOLVED": True,
                                }
                                f.write(json.dumps(rec) + "\n")
                                total_solves += 1
                                if total_solves <= 5:
                                    print(f"  *** SOLVE: alpha={alpha_name} pos={pos} "
                                          f"new_idx={new_letter_idx} conv={conv} L={L} c[{ci}] ***")
                if (pos + 1) % 20 == 0:
                    print(f"  [{alpha_name}] pos {pos+1}/{N} done; "
                          f"solves so far={total_solves}; "
                          f"{time.perf_counter()-t0:.1f}s", flush=True)

        elapsed = time.perf_counter() - t0
        f.write(json.dumps({
            "summary": True,
            "n_candidates": len(cands),
            "n_positions": len(positions),
            "total_solves": total_solves,
            "elapsed_s": round(elapsed, 1),
        }) + "\n")

    print()
    print(f"=== Single-letter ciphertext-error model ===")
    print(f"  candidates:    {len(cands)}")
    print(f"  positions:     {len(positions)}")
    print(f"  total solves:  {total_solves}")
    print(f"  elapsed:       {elapsed:.1f}s")
    print(f"  JSONL:         {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
