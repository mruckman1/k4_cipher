"""025 — Tier B: W-segmented heterogeneous known-plaintext attack.

The Lethuillier hypothesis (exp 020) sharpened: K4's six W-bounded
segments are independently encrypted, possibly with DIFFERENT short
keys (or different cipher conventions) per segment. Each W acts as a
boundary marker; the W positions themselves are treated as separator
characters (plaintext W -> cipher W as identity, or part of the
adjacent segment).

K4 segments (0-indexed, W-exclusive):
  seg 0: pos  0..19   (len 20)  OBKRUOXOGHULBSOLIFBB
  seg 1: pos 21..35   (len 15)  FLRVQQPRNGKSSOT     <- contains EAST+NORTHEAST cribs
  seg 2: pos 37..47   (len 11)  TQSJQSSEKZZ
  seg 3: pos 49..57   (len  9)  ATJKLUDIA
  seg 4: pos 59..73   (len 15)  INFBNYPVTTMZFPK     <- contains BERLIN+CLOCK cribs
  seg 5: pos 75..96   (len 22)  GDKZXTJCDIGKUHUAUEKCAR

For each Sonnet candidate, slice the candidate plaintext into matching
segments. For each segment × {STANDARD, KRYPTOS_KEYED} × {vigenere,
beaufort, variant_beaufort} × period L in 1..6: check whether a
consistent length-L key exists.

A candidate is FULLY SOLVED if all 6 segments simultaneously find a
consistent length-L key (potentially different (alpha, conv, L) per
segment). That's a strong claim and would mean K4 is genuinely a
W-segmented heterogeneous cipher with that candidate as the plaintext.

Per-segment "solved" = consistent key recovery exists.
Per-candidate "fully solved" = all 6 segments solved (with potentially
different params per segment).

Output:
  experiments/results/2026-05-22_025_w_segmented_heterogeneous.jsonl
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
MAX_PERIOD = 6  # Per-segment max key length

# W-exclusive segment definitions (start, end_exclusive)
SEGMENTS: list[tuple[int, int]] = [
    (0, 20),    # 20
    (21, 36),   # 15
    (37, 48),   # 11
    (49, 58),   #  9
    (59, 74),   # 15
    (75, 97),   # 22
]


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


def per_segment_consistency(
    cand_idx: np.ndarray,    # (n_cands, N)
    K4_idx: np.ndarray,      # (N,)
    seg: tuple[int, int],
    n_letters: int,
    convention: str,
    max_L: int = MAX_PERIOD,
) -> dict[int, np.ndarray]:
    """For one segment, return dict {L: bool array of size n_cands
    indicating whether a length-L key satisfies all positions in the
    segment under the given convention}.

    convention:
      vigenere:         cipher = plain + key  =>  key = cipher - plain
      beaufort:         cipher = key - plain  =>  key = cipher + plain
      variant_beaufort: cipher = plain - key  =>  key = plain - cipher
    """
    s, e = seg
    L_segment = e - s
    cand_seg = cand_idx[:, s:e].astype(np.int16)   # (n_cands, L_segment)
    cipher_seg = K4_idx[s:e].astype(np.int16)[None, :]

    if convention == "vigenere":
        req_key = (cipher_seg - cand_seg) % n_letters
    elif convention == "beaufort":
        req_key = (cipher_seg + cand_seg) % n_letters
    elif convention == "variant_beaufort":
        req_key = (cand_seg - cipher_seg) % n_letters
    else:
        raise ValueError(convention)

    out: dict[int, np.ndarray] = {}
    for L in range(1, max_L + 1):
        if L >= L_segment:
            # Not enough constraint to filter; trivially consistent
            out[L] = np.ones(cand_idx.shape[0], dtype=bool)
            continue
        # For each slot, all positions in the slot must agree
        ok = np.ones(cand_idx.shape[0], dtype=bool)
        for slot in range(L):
            positions = list(range(slot, L_segment, L))
            if len(positions) <= 1:
                continue
            vals = req_key[:, positions]
            ref = vals[:, 0:1]
            ok &= np.all(vals == ref, axis=1)
        out[L] = ok
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run-dir", type=Path, default=None)
    p.add_argument("--out", type=Path,
                   default=Path("experiments/results/2026-05-22_025_w_segmented_heterogeneous.jsonl"))
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

    # For each (candidate, segment): collect ALL (alpha, conv, L) tuples
    # under which a consistent key exists. We then ask: for each candidate,
    # is there ANY assignment of (alpha, conv, L) per segment such that
    # ALL 6 segments are simultaneously consistent (with L >= 2 to avoid
    # trivial L=1 monoalphabetic)?
    n_cands = len(cands)

    # any_consistent[candidate, segment_idx] = list of (alpha_name, conv,
    # L) tuples. We compactify by storing a 6-array of "min L" per
    # segment per candidate, conditional on at least L=2.
    print()
    print("=== Per-segment consistency sweep ===")
    t0 = time.perf_counter()

    # For each segment, gather per-(alpha, conv, L) bool arrays
    per_seg_results = []  # list of dicts {(alpha, conv, L): bool array (n_cands,)}
    for seg_idx, seg in enumerate(SEGMENTS):
        seg_results = {}
        for alpha_name, ci, ki, n in (("std", cands_std, K4_std, 26),
                                       ("kk",  cands_kk,  K4_kk,  26)):
            for conv in ("vigenere", "beaufort", "variant_beaufort"):
                consistency_by_L = per_segment_consistency(ci, ki, seg, n, conv)
                for L, ok_arr in consistency_by_L.items():
                    seg_results[(alpha_name, conv, L)] = ok_arr
        per_seg_results.append(seg_results)
        n_ok_L2plus = sum(int(arr.sum()) for (_, _, L), arr in seg_results.items() if L >= 2)
        print(f"  seg {seg_idx} ({seg[0]:2d}..{seg[1]-1:2d}, len {seg[1]-seg[0]:2d}): "
              f"sum over (alpha,conv,L>=2) of consistents = {n_ok_L2plus:,}")

    # For each candidate, check: does there exist an assignment (alpha,
    # conv, L) per segment (with L>=2) such that all 6 segments are
    # simultaneously consistent? Equivalently: for each candidate and
    # each segment, is there ANY (alpha, conv, L>=2) that passes?
    print()
    print("=== Cross-segment combination ===")
    per_cand_segments_ok = np.zeros((n_cands, 6), dtype=bool)
    per_cand_min_L = np.full((n_cands, 6), -1, dtype=np.int8)
    per_cand_best_params: list[list[tuple | None]] = [[None] * 6 for _ in range(n_cands)]

    for seg_idx, seg_results in enumerate(per_seg_results):
        seg_len = SEGMENTS[seg_idx][1] - SEGMENTS[seg_idx][0]
        for (alpha_name, conv, L), ok_arr in seg_results.items():
            # Skip trivial L (where slot positions are insufficient)
            if L < 2 or L >= seg_len:
                continue
            for ci in np.where(ok_arr)[0]:
                if per_cand_min_L[ci, seg_idx] < 0 or L < per_cand_min_L[ci, seg_idx]:
                    per_cand_min_L[ci, seg_idx] = L
                    per_cand_segments_ok[ci, seg_idx] = True
                    per_cand_best_params[ci][seg_idx] = (alpha_name, conv, L)

    n_segs_passed = per_cand_segments_ok.sum(axis=1)
    n_fully = int((n_segs_passed == 6).sum())
    print(f"  Candidates with 6/6 segments passing (any params per seg, L>=2): {n_fully}")
    print()
    print("Distribution of (n segments passed per candidate):")
    for k in range(7):
        c = int((n_segs_passed == k).sum())
        bar = "#" * min(60, c // 10)
        print(f"  {k}/6: {c:>5}  {bar}")

    elapsed = time.perf_counter() - t0
    print(f"\nTotal elapsed: {elapsed:.1f}s")

    # ----- write JSONL of fully-solved + near-misses
    args.out.parent.mkdir(parents=True, exist_ok=True)
    fully_solved_recs: list[dict] = []
    near_miss_recs: list[dict] = []
    for ci in range(n_cands):
        n_pass = int(n_segs_passed[ci])
        rec = {
            "candidate_index": int(ci),
            "candidate": cands[ci],
            "n_segments_passed": n_pass,
            "per_segment_params": [
                p if p else None for p in per_cand_best_params[ci]
            ],
            "per_segment_min_L": per_cand_min_L[ci].tolist(),
        }
        if n_pass == 6:
            fully_solved_recs.append(rec)
        elif n_pass >= 4:
            near_miss_recs.append(rec)

    with open(args.out, "w") as f:
        for r in fully_solved_recs:
            r["status"] = "FULLY_SOLVED"
            f.write(json.dumps(r) + "\n")
        for r in near_miss_recs:
            r["status"] = "NEAR_MISS"
            f.write(json.dumps(r) + "\n")
        f.write(json.dumps({
            "summary": True,
            "n_candidates": n_cands,
            "n_fully_solved": n_fully,
            "n_near_miss_4plus": len(near_miss_recs),
            "elapsed_s": round(elapsed, 1),
        }) + "\n")

    print(f"\nJSONL: {args.out}")
    print(f"  fully solved: {n_fully}")
    print(f"  near miss (>=4 segs): {len(near_miss_recs)}")

    if fully_solved_recs:
        print()
        print("=== TOP 10 FULLY-SOLVED ===")
        for r in fully_solved_recs[:10]:
            print(f"  c[{r['candidate_index']}] {r['candidate']}")
            for si, params in enumerate(r["per_segment_params"]):
                print(f"    seg {si}: {params}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
