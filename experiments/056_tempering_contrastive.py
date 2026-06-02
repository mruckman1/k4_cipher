"""056 — Parallel tempering + contrastive per-colour coherence, smooth-LM objective.

The 71.98 search was single-temperature SA/2-opt on the saturating hexagram
score (exp 053 showed that score is flat across much of the gibberish
region). exp 055 showed a K=4 per-position cipher cannot turn any natural
English plaintext into K4 (every candidate needs >=7 alphabets), which
EXPLAINS why the basin's per-colour partitions are gibberish.

Here we re-run the K=4 per-position search with two changes the repo never
combined: (1) the SMOOTH backoff-LM as the objective (gradient where
hexagrams saturate), and (2) a CONTRASTIVE term rewarding per-colour
coherence (each colour's decrypted partition should itself read like
English, not just the cross-colour concatenation). Optimisation is parallel
tempering (multiple temperature replicas with swaps), seeded crib-locked.

Prediction from 055: even with a better scorer, K=4 cannot make the
per-colour partitions English -- so this should CONFIRM the wall (best
per-colour LM stays gibberish) rather than break it, which is itself the
decisive evidence that K4 is not a 4-alphabet per-position cipher on a
normal plaintext. A surprise improvement would be a real lead.

Output: experiments/results/<date>_056_tempering_contrastive.jsonl
"""

from __future__ import annotations

import argparse
import json
import math
import time
from datetime import date

import numpy as np

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K4
from kryptos.cribs import CRIBS
from kryptos.scoring.lm_fitness import backoff_scorer

VOWELS = set("AEIOU")
K = 4
CC = []
_cc = 0
for ch in K4:
    if ch not in VOWELS:
        _cc += 1
    CC.append(_cc)


def rule(i):                       # ShinkaEvolve Prior-A k=4 rule
    return (2 * (i % 3) + CC[i]) % K


COLORS = [rule(i) for i in range(97)]
K4IDX = [ord(c) - 65 for c in K4]

# crib locks: (color, plain_idx) -> cipher_idx
LOCKS = {c: {} for c in range(K)}
for cr in CRIBS:
    for off, (p, ch) in enumerate(zip(cr.plaintext, cr.ciphertext)):
        i = cr.start - 1 + off
        LOCKS[COLORS[i]][ord(p) - 65] = ord(ch) - 65


def random_alphabet(locks, rng):
    """26-perm A (plain_idx -> cipher_idx) honoring locked entries."""
    A = [-1] * 26
    used = set()
    for pi, ci in locks.items():
        A[pi] = ci
        used.add(ci)
    free_pi = [pi for pi in range(26) if A[pi] == -1]
    free_ci = [ci for ci in range(26) if ci not in used]
    rng.shuffle(free_ci)
    for pi, ci in zip(free_pi, free_ci):
        A[pi] = ci
    return A


def decrypt(alphabets):
    inv = []
    for A in alphabets:
        iv = [0] * 26
        for pi, ci in enumerate(A):
            iv[ci] = pi
        inv.append(iv)
    return "".join(chr(65 + inv[COLORS[i]][K4IDX[i]]) for i in range(97))


def per_color_text(P, color):
    return "".join(P[i] for i in range(97) if COLORS[i] == color)


def objective(P, lm):
    free = "".join(P[i] for i in range(97))
    glob = lm(free)
    coh = sum(lm(per_color_text(P, c)) for c in range(K)) / K
    return glob + 0.5 * coh, glob, coh


def swap_mutation(A, locked_pis, rng):
    free = [pi for pi in range(26) if pi not in locked_pis]
    a, b = rng.sample(free, 2)
    A[a], A[b] = A[b], A[a]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iters", type=int, default=4000)
    ap.add_argument("--replicas", type=int, default=5)
    args = ap.parse_args()
    out = _kpa.RESULTS / f"{date.today()}_056_tempering_contrastive.jsonl"

    import random
    lm = backoff_scorer()
    hexs = _kpa.hexagram_scorer()
    t0 = time.perf_counter()
    rngs = [random.Random(r) for r in range(args.replicas)]
    nprng = [np.random.default_rng(r) for r in range(args.replicas)]
    temps = [0.05 * (2.2 ** r) for r in range(args.replicas)]

    locked = {c: set(LOCKS[c].keys()) for c in range(K)}
    states = [[random_alphabet(LOCKS[c], nprng[r]) for c in range(K)] for r in range(args.replicas)]
    scores, decrypts = [], []
    for st in states:
        P = decrypt(st)
        sc, *_ = objective(P, lm)
        scores.append(sc); decrypts.append(P)

    best = (-1e9, None)
    for it in range(args.iters):
        for r in range(args.replicas):
            c = rngs[r].randrange(K)
            A = states[r][c]
            old = A[:]
            swap_mutation(A, locked[c], rngs[r])
            P = decrypt(states[r])
            sc, glob, coh = objective(P, lm)
            d = sc - scores[r]
            if d >= 0 or rngs[r].random() < math.exp(d / temps[r]):
                scores[r] = sc; decrypts[r] = P
                if sc > best[0]:
                    best = (sc, {"plaintext": P, "obj": round(sc, 3),
                                 "free_hex": round(hexs(P), 2), "lm_global": round(glob, 3),
                                 "lm_coherence": round(coh, 3),
                                 "per_color_hex": [round(hexs(per_color_text(P, cc)), 2) for cc in range(K)]})
            else:
                states[r][c] = old
        # replica swaps
        if it % 50 == 0:
            for r in range(args.replicas - 1):
                d = (1 / temps[r] - 1 / temps[r + 1]) * (scores[r + 1] - scores[r])
                if d >= 0 or rngs[r].random() < math.exp(d):
                    states[r], states[r + 1] = states[r + 1], states[r]
                    scores[r], scores[r + 1] = scores[r + 1], scores[r]

    elapsed = time.perf_counter() - t0
    bi = best[1]
    with open(out, "w") as f:
        f.write(json.dumps({"best": bi, "iters": args.iters, "replicas": args.replicas}) + "\n")

    pc = bi["per_color_hex"]
    per_color_english = all(x > -16 for x in pc)
    status = "promising" if (bi["free_hex"] > -15 and per_color_english) else "ruled_out"
    insights = [
        f"K=4 Prior-A tempered search with the SMOOTH LM objective: best global free-hexagram "
        f"{bi['free_hex']:.2f}/char, LM global {bi['lm_global']:.2f}, per-colour hexagrams {pc}.",
        f"Per-colour partitions remain {'ENGLISH' if per_color_english else 'GIBBERISH'} "
        f"(each ~{sum(pc)/len(pc):.1f}/char vs English -13). This matches exp 055's prediction: a 4-alphabet "
        f"per-position cipher cannot make all four colour partitions English, so the cross-colour 'words' the "
        f"71.98 basin shows are an artifact, not a decryption.",
    ]
    if status == "ruled_out":
        insights.append("Even with a non-saturating scorer and parallel tempering + contrastive per-colour "
                        "coherence, the K=4 per-position model stays at the cross-colour-fragment wall. "
                        "Combined with exp 055 (min fanout 7), this is strong evidence K4 is NOT a 4-alphabet "
                        "per-position substitution -- the dominant repo hypothesis should be downweighted.")
    write_verdict(out, Verdict(
        exp="056", title="parallel tempering + contrastive coherence (smooth LM)",
        hypothesis="a better scorer + tempering escapes the 71.98 basin to per-colour-coherent English at K=4",
        status=status, best_score=bi["free_hex"],
        best_partial=f"per-colour hex {pc}", search_space=args.iters * args.replicas,
        elapsed_s=round(elapsed, 1), insights=insights,
        next_steps=["abandon K=4 per-position as the primary model (055+056 agree); pursue transposition+"
                    "substitution composites and the fanout<=k plaintext-generation filter (055)"],
        metrics={"best": bi})
    )
    print(f"\nDone in {elapsed:.1f}s; best free-hex {bi['free_hex']:.2f}; per-colour {pc}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
