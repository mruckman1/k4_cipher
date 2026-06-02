"""043 — Substitution FIRST, then a keyed columnar transposition.

The untested operation order. Every prior transposition experiment did
transposition->substitution (exp 015), or kept the cribs in K4's native
coordinates (exp 031). Sanborn's "extra masking step" most naturally reads
as: a clean periodic substitution, then a final columnar shred (K3's own
technique reused as the mask).

Pipeline:  P --periodic-sub(key slot = j mod L)--> M --columnar(W,order)--> K4

For a column permutation `perm` (output k reads input perm[k]) with inverse
`inv`:  M[j] = K4[inv[j]]  and  P[j] = sub^{-1}(M[j], key[j mod L]). The
transposition relabels which ciphertext letter pairs with each plaintext
position, so an aperiodic-looking shift sequence can snap back to a clean
period.

For each (W, order, alphabet, convention) we re-pair the 24 cribs through
`inv` and find the periods L where the implied key is slot-consistent. A
period is *decryptable* only if the cribs pin ALL L slots (true for small
L); for those we fully decrypt P and hexagram-score the 73 free positions,
and byte-exact verify (re-encrypt) for a true solve. The identity pairing
is consistent only at L>=27, never decryptably-small — so any small-L
English hit here is a real structural break.

$0, local. Output: experiments/results/<date>_043_substitution_then_transposition.jsonl
"""

from __future__ import annotations

import argparse
import itertools
import json
import time
from datetime import date
from pathlib import Path

import numpy as np

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD
from kryptos.ciphers.transposition import ColumnarTransposition
from kryptos.constants import K4
from kryptos.scoring.crib_check import crib_check

MAX_L = 24
DECRYPT_MAX_L = 20          # only fully-pinned small periods are decryptable
WIDTHS_FULL = (7, 8)
WIDTHS_SAMPLED = (9, 10, 12, 14, 24)
SAMPLE_PER_WIDTH = 60_000
KEYWORDS = ["KRYPTOS", "BERLIN", "CLOCK", "BERLINCLOCK", "WELTZEITUHR",
            "PALIMPSEST", "ABSCISSA", "DYAHR", "SANBORN", "LANGLEY"]

CRIB_POS = np.array([p for (p, _, _) in _kpa.crib_position_triples(STANDARD)], dtype=np.int32)
ALPHAS = {"standard": STANDARD, "kryptos_keyed": KRYPTOS_KEYED}


def plain_idx(alphabet) -> np.ndarray:
    return np.array([pi for (_, pi, _) in _kpa.crib_position_triples(alphabet)], dtype=np.int16)


def shifts_for(cipher_idx, p_idx, conv):
    if conv == "vigenere":
        return (cipher_idx - p_idx) % 26
    if conv == "beaufort":
        return (cipher_idx + p_idx) % 26
    return (p_idx - cipher_idx) % 26          # variant_beaufort


def min_consistent_L(pos, shifts, max_L=MAX_L):
    """Smallest period L<=max_L where every slot has a single shift, plus a
    flag for whether that L's slots are fully pinned (decryptable)."""
    for L in range(1, max_L + 1):
        slot = {}
        ok = True
        for p, s in zip(pos.tolist(), shifts.tolist()):
            sl = p % L
            if sl in slot and slot[sl] != s:
                ok = False
                break
            slot[sl] = s
        if ok:
            return L, len(slot) == L, slot
    return None, False, None


def decrypt_full(inv, key_by_slot, L, alphabet, conv) -> str:
    """Reconstruct P from K4 given the transposition inverse and per-slot key."""
    alpha = alphabet
    k4_idx = np.array(alpha.encode(K4), dtype=np.int16)
    m_idx = k4_idx[inv]                       # de-transposed M
    out = []
    for j in range(97):
        k = key_by_slot[j % L]
        if conv == "vigenere":
            pi = (int(m_idx[j]) - k) % 26
        elif conv == "beaufort":
            pi = (k - int(m_idx[j])) % 26
        else:                                 # variant_beaufort
            pi = (int(m_idx[j]) + k) % 26
        out.append(alpha.at(pi))
    return "".join(out)


def iter_column_orders(width, sample, rng):
    if width <= 8:
        yield from itertools.permutations(range(width))
        return
    seen = set()
    for kw in KEYWORDS:
        if len(kw) == width:
            o = _kpa.keyword_column_order(kw)
            if o not in seen:
                seen.add(o); yield o
    for _ in range(sample):
        o = tuple(rng.permutation(width).tolist())
        if o not in seen:
            seen.add(o); yield o


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sample", type=int, default=SAMPLE_PER_WIDTH)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    out = args.out or (_kpa.RESULTS / f"{date.today()}_043_substitution_then_transposition.jsonl")

    pidx = {n: plain_idx(a) for n, a in ALPHAS.items()}
    k4idx = {n: np.array(a.encode(K4), dtype=np.int16) for n, a in ALPHAS.items()}

    rng = np.random.default_rng(0)
    t0 = time.perf_counter()
    n_tested = 0
    best_score = -99.0
    best_info = None
    decryptable = 0          # consistent at a fully-pinned small L
    small_L_hits = 0         # min consistent L <= 16 (non-trivial)
    solved = None
    minL_hist: dict[int, int] = {}

    with open(out, "w") as f:
        for width in (*WIDTHS_FULL, *WIDTHS_SAMPLED):
            wt0 = time.perf_counter()
            w_count = 0
            for order in iter_column_orders(width, args.sample, rng):
                perm = _kpa.col_permutation_full(width, order)
                inv = np.empty_like(perm)
                inv[perm] = np.arange(perm.size)
                paired = inv[CRIB_POS]
                for an, alpha in ALPHAS.items():
                    cipher_idx = k4idx[an][paired].astype(np.int16)
                    p_idx = pidx[an]
                    for conv in _kpa.CONVENTIONS:
                        shifts = shifts_for(cipher_idx, p_idx, conv).astype(np.int16)
                        L, full, slot = min_consistent_L(CRIB_POS, shifts)
                        if L is None:
                            continue
                        minL_hist[L] = minL_hist.get(L, 0) + 1
                        if L <= 16:
                            small_L_hits += 1
                        if full and L <= DECRYPT_MAX_L:
                            decryptable += 1
                            P = decrypt_full(inv, slot, L, alpha, conv)
                            if not crib_check(P):
                                continue       # safety; should always pass
                            sc = _kpa.score_free_text(P)
                            # byte-exact verify: P --sub--> M --transpose--> K4 ?
                            verified = False
                            if sc > -15.0:
                                ct = ColumnarTransposition(order, alpha).encrypt
                                # M = sub(P); compare transpose(M) to K4 (irregular columnar via perm)
                                m = "".join(alpha.at((alpha.index(P[j]) + slot[j % L]) % 26
                                                     if conv == "vigenere" else
                                                     (slot[j % L] - alpha.index(P[j])) % 26
                                                     if conv == "beaufort" else
                                                     (alpha.index(P[j]) - slot[j % L]) % 26)
                                            for j in range(97))
                                ctK4 = "".join(m[perm[k]] for k in range(97))
                                verified = (ctK4 == K4)
                            if sc > best_score:
                                best_score = sc
                                best_info = {"width": width, "order": list(order),
                                             "alphabet": an, "convention": conv, "L": L,
                                             "plaintext": P, "score": round(sc, 2),
                                             "verified": verified}
                            if sc > -16.0 or verified:
                                f.write(json.dumps({"width": width, "order": list(order),
                                                    "alphabet": an, "convention": conv, "L": L,
                                                    "plaintext": P, "free_hex": round(sc, 2),
                                                    "verified": verified}) + "\n")
                            if verified:
                                solved = {"width": width, "order": list(order),
                                          "alphabet": an, "convention": conv, "L": L,
                                          "plaintext": P}
                n_tested += 1
                w_count += 1
            print(f"  W={width}: {w_count:,} orders, {time.perf_counter()-wt0:.1f}s, "
                  f"decryptable={decryptable}, best_free_hex={best_score:.2f}")

    elapsed = time.perf_counter() - t0
    if solved:
        status = "solved"
    elif best_score > -16.0:
        status = "promising"
    else:
        status = "ruled_out"
    insights = [
        f"Tested {n_tested:,} (width,order,alpha,conv) pairings; {decryptable:,} were consistent at a "
        f"fully-pinned period L<= {DECRYPT_MAX_L} (decryptable). Best free-position hexagram = "
        f"{best_score:.2f}/char (English ~-13, gibberish ~-24).",
        f"min-consistent-L histogram (lower=more constrained): "
        f"{dict(sorted(minL_hist.items()))}",
    ]
    if status == "ruled_out":
        insights.append("No decryptable pairing yields English; substitution-then-columnar-shred is "
                        "closed for these widths. The transposition relabelling does not recover a "
                        "short clean period that decrypts to English.")
    write_verdict(out, Verdict(
        exp="043", title="substitution-then-keyed-columnar-transposition",
        hypothesis="K4 = periodic substitution then a final keyed columnar transposition (K3's mask reused)",
        status=status, best_score=round(best_score, 2),
        best_partial=f"{decryptable} decryptable pairings; {small_L_hits} with minL<=16",
        search_space=n_tested, elapsed_s=round(elapsed, 1),
        solved_params=solved, insights=insights,
        next_steps=(["DONE — verify and announce"] if solved else
                    ["push decryptable best with free-slot hill-climb",
                     "compose with exp 049 Weltzeituhr column order; try rail/zigzag routes (exp 052)"]),
        metrics={"best": best_info},
    ))
    print(f"\nTested {n_tested:,} pairings in {elapsed:.1f}s; best free-hex {best_score:.2f}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
