"""092 — Identifiability / unicity-distance analysis: IS K4 cryptanalytically
solvable at all, given what we now know it must be?

After 91 experiments the per-position-substitution frame is bounded from every
side, and two facts are forced: (033/088) K4's >=3 alphabets are HAND-CRAFTED
(no natural keyword pool covers 7 of the 24 cribs, and a combined 6,689-alphabet
memorable pool cannot 3-cover them); (085) the flatten floor is k* = 4 alphabets.
This experiment asks the SOTA information-theoretic question those two facts
raise: with only 97 ciphertext letters + 24 crib letters, is the plaintext
UNIQUELY determined, or is K4 at/beyond its unicity distance -- i.e. are there
many English-consistent plaintexts, so pure cryptanalysis cannot pin THE answer?

Shannon: a cipher uniquely determines its plaintext once N >= U = H(K)/D, where
H(K) is the key entropy (bits) and D = log2(26) - r is the per-character
redundancy of English (r = its entropy rate). We MEASURE r from the corpus,
compute H(K) for each model class K4 could be, fold in how much the 24 cribs pin,
and report the residual under-determination gap as a function of the alphabet
count k. The keystone test: does the crossover from "uniquely solvable" to
"under-determined" sit at or below the flatten floor k*=4 -- which would mean the
squeeze (needs many alphabets) COLLIDES with unicity (many hand-crafted alphabets
exceed the redundancy budget), explaining 35 years of failure and reframing K4 as
a MAXIMUM-LIKELIHOOD decipherment problem, not a unique-solution one.

$0, local, pure decipherment. Output:
experiments/results/<date>_092_unicity_identifiability.jsonl
"""

from __future__ import annotations

import json
import math
import time
from collections import Counter
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.utils import clean

R0 = math.log2(26)  # 4.70 bits: max per-letter entropy
N = 97              # K4 length
CRIBS_KNOWN = 24    # known plaintext letters
CORP = clean(Path("data/corpora/buchan_39steps.txt").read_text()
             + clean(Path("data/corpora/smith_tutankhamen.txt").read_text()))


def kgram_entropy(text, k):
    c = Counter(text[i:i + k] for i in range(len(text) - k + 1))
    n = sum(c.values())
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def log2_factorial(n):
    return sum(math.log2(i) for i in range(2, n + 1))


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_092_unicity_identifiability.jsonl"
    t0 = time.perf_counter()

    # ---- measure English entropy rate r and redundancy D ----
    H = {k: kgram_entropy(CORP, k) for k in range(1, 7)}
    cond = {1: H[1]}
    for k in range(2, 7):
        cond[k] = H[k] - H[k - 1]          # H(X_k | X_1..k-1)
    r = cond[6]                            # best (order-6) estimate of the entropy rate
    D = R0 - r                             # per-character redundancy

    LOG2_26FACT = log2_factorial(26)       # 88.38 bits: entropy of one arbitrary 26-letter alphabet
    KEYWORD_BITS = 14.0                     # a memorable English keyword (~10-20 bits); K1/K2 style
    SELECTOR_BITS = 6.0                     # a simple/"memorable" position selector (~tens of options)

    # crib-pinning budget: each crib pins ONE entry of the alphabet selected at its
    # position. An arbitrary 26-perm carries log2(26!) bits; pinning m of its 26
    # entries removes ~ log2(26!/(26-m)!) bits. With 24 cribs spread over k classes,
    # each alphabet gets ~24/k pinned entries.
    def pinned_bits_per_alphabet(m_entries):
        m = min(int(round(m_entries)), 26)
        return sum(math.log2(26 - j) for j in range(m))  # log2(26*25*...*(26-m+1))

    # free-position redundancy available to disambiguate the rest of the key:
    free_positions = N - CRIBS_KNOWN       # 73
    free_redundancy_bits = free_positions * D

    rows = []
    crossover_handcrafted = None
    for k in range(1, 7):
        # model A: k arbitrary HAND-CRAFTED alphabets + simple selector (what 033/088 force)
        HK_hand = k * LOG2_26FACT + (SELECTOR_BITS if k > 1 else 0.0)
        U_hand = HK_hand / D
        pinned = k * pinned_bits_per_alphabet(CRIBS_KNOWN / k)
        residual_key_bits = max(0.0, HK_hand - pinned)
        gap = residual_key_bits - free_redundancy_bits   # >0 => under-determined
        # model B: k rotations of one keyed base alphabet (cheap) + selector
        HK_rot = LOG2_26FACT + (k * R0) + (SELECTOR_BITS if k > 1 else 0.0)
        U_rot = HK_rot / D
        rows.append({"k": k, "HK_handcrafted_bits": round(HK_hand, 1), "U_handcrafted": round(U_hand, 1),
                     "crib_pinned_bits": round(pinned, 1), "residual_key_bits": round(residual_key_bits, 1),
                     "free_redundancy_bits": round(free_redundancy_bits, 1),
                     "underdetermination_gap_bits": round(gap, 1),
                     "uniquely_solvable_handcrafted": gap <= 0,
                     "HK_rotations_bits": round(HK_rot, 1), "U_rotations": round(U_rot, 1),
                     "rotations_solvable": HK_rot / D <= N})
        if crossover_handcrafted is None and gap > 0:
            crossover_handcrafted = k

    elapsed = time.perf_counter() - t0
    with open(out, "w") as f:
        f.write(json.dumps({"entropy_rate_r": round(r, 3), "redundancy_D": round(D, 3),
                            "kgram_cond_entropy": {k: round(v, 3) for k, v in cond.items()},
                            "free_positions": free_positions,
                            "free_redundancy_bits": round(free_redundancy_bits, 1),
                            "log2_26fact": round(LOG2_26FACT, 2),
                            "crossover_k_handcrafted": crossover_handcrafted, "table": rows}) + "\n")

    flatten_floor = 4  # k* from exp 085
    collide = crossover_handcrafted is not None and crossover_handcrafted <= flatten_floor
    insights = [
        f"Measured English: order-6 conditional entropy rate r = {r:.3f} bits/char -> redundancy "
        f"D = {D:.3f} bits/char (k-gram conditional entropies: { {k: round(v,2) for k,v in cond.items()} }). "
        f"One arbitrary 26-letter alphabet carries log2(26!) = {LOG2_26FACT:.1f} bits.",
        f"UNICITY by model. Cheap 'k rotations of a keyed base' alphabets: "
        f"{[(r_['k'], r_['U_rotations']) for r_ in rows]} bits-distance vs N=97 -> all solvable (U<<97) -- but "
        f"085/088 already RULED these out (no cheap/structured alphabet set fits the cribs and flattens).",
        f"HAND-CRAFTED alphabets (what 033/088 force). Under-determination gap (residual key bits MINUS the "
        f"{free_redundancy_bits:.0f} bits of free-position English redundancy), by k: "
        f"{[(r_['k'], r_['underdetermination_gap_bits']) for r_ in rows]}. Crossover to UNDER-DETERMINED at "
        f"k = {crossover_handcrafted}.",
        (f"THE COLLISION: the flatten floor is k*=4 (exp 085) and the hand-crafted-alphabet unicity crossover is "
         f"k={crossover_handcrafted} <= 4. So the very alphabet count K4 NEEDS to flatten is the count at which "
         f"97 letters + 24 cribs STOP uniquely determining the plaintext. K4 sits at/beyond its unicity distance: "
         f"there are many English-consistent plaintexts (the exp-059 degeneracy, now explained), so pure "
         f"algebraic cryptanalysis cannot pin THE answer -- it is a MAXIMUM-LIKELIHOOD decipherment problem "
         f"(most-English + simplest-rule among crib-consistent candidates), which is the correct SOTA framing "
         f"(Knight/AZdecrypt lineage) and motivates an MDL-regularized search (proposed exp 093)."
         if collide else
         f"The hand-crafted unicity crossover (k={crossover_handcrafted}) sits ABOVE the flatten floor (k*=4), so "
         f"K4 may still be uniquely determined; an MDL search up to k* is warranted (exp 093).")
    ]

    write_verdict(out, Verdict(
        exp="092", title="unicity-distance / identifiability analysis of K4",
        hypothesis="with 97 letters + 24 cribs, K4's plaintext is uniquely determined for the hand-crafted "
                   "multi-alphabet model it is forced into",
        status="inconclusive",  # a meta-result: it characterizes solvability, it does not decrypt
        best_partial=f"measured D={round(D,2)} b/char; hand-crafted unicity crossover at k={crossover_handcrafted} "
                     f"(flatten floor k*=4); collision={collide}",
        search_space=len(rows), elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["K4 is at/beyond unicity for hand-crafted >=4 alphabets -> reframe as MAXIMUM-LIKELIHOOD "
                     "decipherment: build the MDL-regularized simulated-annealing search (exp 093) with a strong "
                     "language model, and inject the Berlin-Clock prior (exp 094) to constrain the selector"]
                    if collide else
                    ["unicity crossover above k*=4 -> a unique solution may exist; build the MDL-regularized "
                     "search (exp 093) up to k* with crib + n-gram fitness"]),
        metrics={"r": round(r, 3), "D": round(D, 3), "crossover_k": crossover_handcrafted,
                 "collision_with_flatten_floor": collide, "table": rows}),
    )
    print(f"\nr={r:.3f} D={D:.3f} b/char; hand-crafted unicity crossover k={crossover_handcrafted} "
          f"(flatten floor 4); collision={collide}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
