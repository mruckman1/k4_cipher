"""098 — Partial / consensus determination: which free positions ARE pinned,
even though the whole 73-char plaintext is under-determined (092/093)?

The cribs fix (cipher->plain) entries. A FREE position i is forced as soon as its
ciphertext letter C_i also appears in a crib that shares i's alphabet class:
then P_i = that crib's plaintext, regardless of the rest of the (unknown) key. The
whole plaintext is under-determined, but a SUBSET is not. This recovers that
subset -- a partial "consensus skeleton" -- which is guaranteed to yield real
information even with no full solution.

Method (model = >=3 alphabets, the proven structure):
  - CRIB DICTIONARY: cribdict[C] = the plaintext letters C maps to across cribs;
    "unambiguous" cipher letters (single target) can ONLY ever decrypt to that
    letter wherever they are pinned.
  - MONTE CARLO over the crib-valid model space: sample many proper 3-colourings
    of the chi=3 crib conflict graph (the only valid colourings) x uniform-random
    class assignments of the 73 free positions; for each, a free position is
    pinned iff its class contains a crib using C_i, forcing that crib's plaintext.
    Accumulate, per free position, the distribution over {forced letters, FREE}.
  - CONSENSUS SKELETON: free positions whose dominant forced letter holds across a
    large fraction of valid models -- recovered with that confidence.

Honest scope: determination is conditional on the (unknown) selector; we
marginalise over it uniformly, so the skeleton is "what holds under maximal
selector uncertainty", an honest partial result, not a full decryption.

$0, local, pure decipherment. Output:
experiments/results/<date>_098_consensus_determination.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import random
import time
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K4
from kryptos.cribs import CRIBS

e035 = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
    "e035", str(Path(__file__).parent / "035_minimum_alphabet_analysis.py")))
e035.__spec__.loader.exec_module(e035)

N = 97
CRIB_TRIPLES = [(c.start - 1 + off, p, ch)
                for c in CRIBS for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext))]
CRIB_POS = {pos for pos, _, _ in CRIB_TRIPLES}
FREE_SET = [i for i in range(N) if i not in CRIB_POS]


def random_proper_3coloring(n, edges, rng, tries=200):
    """Sample a proper 3-colouring via randomised greedy + restart."""
    adj = defaultdict(set)
    for u, v in edges:
        adj[u].add(v); adj[v].add(u)
    for _ in range(tries):
        order = list(range(n)); rng.shuffle(order)
        colour = {}
        ok = True
        for node in order:
            used = {colour[m] for m in adj[node] if m in colour}
            avail = [c for c in (0, 1, 2) if c not in used]
            if not avail:
                ok = False; break
            colour[node] = rng.choice(avail)
        if ok:
            return [colour[i] for i in range(n)]
    return None


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_098_consensus_determination.jsonl"
    rng = random.Random(0)
    t0 = time.perf_counter()

    cribs = e035.build_crib_constraints()
    pos_of_node = [c[0] for c in cribs]
    edges = set()
    for i in range(len(cribs)):
        for j in range(i + 1, len(cribs)):
            if e035.cribs_conflict(cribs[i], cribs[j]):
                edges.add((i, j))

    # crib dictionary
    cribdict = defaultdict(set)
    for pos, p, ch in CRIB_TRIPLES:
        cribdict[ch].add(p)
    unambiguous = {ch: next(iter(ps)) for ch, ps in cribdict.items() if len(ps) == 1}
    free_with_cribletter = [i for i in FREE_SET if K4[i] in cribdict]
    free_unambiguous = [i for i in FREE_SET if K4[i] in unambiguous]

    # Monte Carlo over (proper 3-colouring x uniform free class assignment)
    M = 4000
    votes = {i: Counter() for i in FREE_SET}
    node_of_pos = {pos_of_node[n]: n for n in range(len(cribs))}
    samples = 0
    for _ in range(M):
        col = random_proper_3coloring(len(cribs), edges, rng)
        if col is None:
            continue
        samples += 1
        # per-class crib alphabets (cipher->plain) under this colouring
        cls_alpha = {0: {}, 1: {}, 2: {}}
        for pos, p, ch in CRIB_TRIPLES:
            cls_alpha[col[node_of_pos[pos]]][ch] = p
        for i in FREE_SET:
            c = rng.randrange(3)
            ch = K4[i]
            votes[i][cls_alpha[c].get(ch, "?")] += 1  # "?" = free (class has no crib for C_i)

    # consensus per free position
    def dominant(i):
        letter_votes = [(L, c) for L, c in votes[i].items() if L != "?"]
        if not letter_votes:
            return None, 0.0
        L, c = max(letter_votes, key=lambda x: x[1])
        return L, c / samples  # fraction of models forcing this letter

    skeleton = {}
    conf = {}
    for i in FREE_SET:
        L, frac = dominant(i)
        if L is not None:
            skeleton[i] = L; conf[i] = frac
    n_ge50 = sum(1 for i in skeleton if conf[i] >= 0.5)
    n_ge70 = sum(1 for i in skeleton if conf[i] >= 0.7)
    n_ge90 = sum(1 for i in skeleton if conf[i] >= 0.9)

    # render skeleton strings (cribs filled, free shown at >=0.5 / >=0.9 confidence)
    crib_letter = {pos: p for pos, p, _ in CRIB_TRIPLES}
    def render(thr):
        s = []
        for i in range(N):
            if i in crib_letter:
                s.append(crib_letter[i])
            elif i in skeleton and conf[i] >= thr:
                s.append(skeleton[i].lower())
            else:
                s.append("·")
        return "".join(s)
    skel50, skel90 = render(0.5), render(0.9)

    elapsed = time.perf_counter() - t0
    with open(out, "w") as f:
        f.write(json.dumps({"n_free": len(FREE_SET), "samples": samples,
                            "unambiguous_cipher_letters": len(unambiguous),
                            "free_with_cribletter": len(free_with_cribletter),
                            "free_unambiguous": len(free_unambiguous),
                            "consensus_ge50": n_ge50, "consensus_ge70": n_ge70, "consensus_ge90": n_ge90,
                            "skeleton_conf50": skel50, "skeleton_conf90": skel90,
                            "per_position": {str(i): [skeleton.get(i), round(conf.get(i, 0.0), 2)]
                                             for i in FREE_SET}}) + "\n")

    insights = [
        f"Crib dictionary: {len(cribdict)} distinct ciphertext letters are crib-mapped, {len(unambiguous)} "
        f"UNAMBIGUOUSLY (single plaintext target). Of the {len(FREE_SET)} free positions, "
        f"{len(free_with_cribletter)} have a ciphertext letter that appears in the cribs ({len(free_unambiguous)} "
        f"unambiguously) -- these are the only free positions that can EVER be pinned by crib-letter reuse.",
        f"CONSENSUS over {samples} crib-valid models (proper 3-colouring x uniform free class assignment): a "
        f"free position is 'consensus-determined' when one forced letter dominates. Counts -- "
        f">=50% conf: {n_ge50}; >=70%: {n_ge70}; >=90%: {n_ge90} of {len(FREE_SET)} free positions.",
        f"Skeleton (cribs UPPER, >=50%-confident free positions lower, undetermined '·'):\n  {skel50}",
        f"At >=90% confidence the determined free letters are essentially only those whose ciphertext letter is "
        f"pinned in EVERY class it appears in -- {n_ge90} positions. The remaining {len(FREE_SET) - n_ge90} free "
        f"positions are genuinely under-determined (consistent with 092/093): no amount of cribs + selector "
        f"marginalisation fixes them. This is the honest partial recovery -- a real skeleton, far short of the "
        f"plaintext, and a quantified floor on how little the cribs alone determine.",
    ]

    # this is a knowledge/partial-recovery result, not a solve
    write_verdict(out, Verdict(
        exp="098", title="partial / consensus determination of free positions",
        hypothesis="some free positions are pinned by crib-letter reuse and recoverable even though the whole "
                   "plaintext is under-determined",
        status="inconclusive",
        best_partial=f"{n_ge50} free positions consensus-determined at >=50% ({n_ge90} at >=90%) of "
                     f"{len(FREE_SET)}; {len(free_with_cribletter)} free positions even contain a crib letter",
        search_space=samples, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=["the consensus skeleton is a quantified partial recovery; combine with a register prior "
                    "(097) to constrain the undetermined positions, or accept it as the determinable floor. "
                    "Remaining mechanism probe: the interruptor keystream (exp 099)"],
        metrics={"n_free": len(FREE_SET), "consensus_ge50": n_ge50, "consensus_ge70": n_ge70,
                 "consensus_ge90": n_ge90, "free_with_cribletter": len(free_with_cribletter),
                 "unambiguous_cipher_letters": len(unambiguous)}),
    )
    print(f"\nfree={len(FREE_SET)}; consensus >=50%:{n_ge50} >=70%:{n_ge70} >=90%:{n_ge90}; "
          f"free-with-crib-letter {len(free_with_cribletter)}. -> {out}")
    print(f"skeleton(>=50%): {skel50}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
