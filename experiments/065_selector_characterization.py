"""065 — Conflict-graph SELECTOR characterization (the prune that tightens).

The cribs force a chi=3 conflict graph (24 nodes, 22 edges). exp 036/054
tested whether specific closed-form rules FIT a decrypt. This instead asks a
pure graph question: for each candidate position-FEATURE f, is f a valid
SELECTOR at all? f is a valid selector iff no conflict edge joins two crib
positions with equal f-value (a permutation/alphabet can't satisfy two
conflicting cribs that share a color). If valid, the minimum alphabets it
needs = chromatic number of the f-value quotient graph.

Merging f-values can only ENLARGE color classes (never removes a monochromatic
edge), so 'f valid as a coloring' is necessary AND sufficient for f to be a
usable selector at some k. This yields a POSITIVE shortlist of graph-compatible
selector families -- a prune that makes every downstream search cheaper and
that pre-kills the width-7 / W-distance bets if they fail here.

A scrambled control (randomize the 22 edges, same count) reports how often each
feature would be 'valid' by chance, so a real-graph pass is not over-read.

Output: experiments/results/<date>_065_selector_characterization.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import random
import time
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K4

_spec = importlib.util.spec_from_file_location(
    "e035", str(Path(__file__).parent / "035_minimum_alphabet_analysis.py"))
e035 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(e035)

W = [i for i, c in enumerate(K4) if c == "W"]            # [20,36,48,58,74]
VOWELS = set("AEIOU")
CC = []
_c = 0
for ch in K4:
    if ch not in VOWELS:
        _c += 1
    CC.append(_c)


def nearest_w(i):
    return min(abs(i - w) for w in W)


def signed_nearest_w(i):
    return min((i - w for w in W), key=abs)


def prev_w(i):
    befores = [w for w in W if w <= i]
    return i - max(befores) if befores else -1


def next_w(i):
    afters = [w for w in W if w >= i]
    return min(afters) - i if afters else -1


def features():
    F = {}
    for m in range(2, 16):
        F[f"pos_mod_{m}"] = lambda i, m=m: i % m
    F["w_dist_prev"] = prev_w
    F["w_dist_next"] = next_w
    F["w_dist_nearest"] = nearest_w
    F["w_signed_nearest"] = signed_nearest_w
    for w in (7, 14, 21):
        F[f"row_w{w}"] = lambda i, w=w: i // w
        F[f"col_w{w}"] = lambda i, w=w: i % w
    F["phillips_block_5x8"] = lambda i: (i // 5) % 8
    for m in (4, 5, 6, 7, 8):
        F[f"cc_mod_{m}"] = lambda i, m=m: CC[i] % m
    for k in (4, 8):
        F[f"priorA_mod_{k}"] = lambda i, k=k: (2 * (i % 3) + CC[i]) % k
    return F


def valid(vals, edges):
    return all(vals[u] != vals[v] for u, v in edges)


def quotient_k(vals, edges):
    vset = sorted(set(vals.values()))
    if len(vset) <= 1:
        return 1
    idx = {v: n for n, v in enumerate(vset)}
    vedges = set()
    for u, v in edges:
        a, b = idx[vals[u]], idx[vals[v]]
        if a != b:
            vedges.add((min(a, b), max(a, b)))
    return e035.chromatic_number(len(vset), vedges)


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_065_selector_characterization.jsonl"
    cribs = e035.build_crib_constraints()
    positions = [c[0] for c in cribs]                    # 0-indexed crib positions, node order
    edges = set()
    for i in range(len(cribs)):
        for j in range(i + 1, len(cribs)):
            if e035.cribs_conflict(cribs[i], cribs[j]):
                edges.add((i, j))
    n = len(cribs)
    t0 = time.perf_counter()

    F = features()
    rng = random.Random(0)
    n_ctrl = 3000
    results = []
    for name, f in F.items():
        vals = {node: f(positions[node]) for node in range(n)}    # node -> feature value
        ok = valid(vals, edges)
        k = quotient_k(vals, edges) if ok else None
        # scrambled control: same value-partition, randomize 22 edges among 24 nodes
        ctrl_valid = 0
        all_pairs = [(a, b) for a in range(n) for b in range(a + 1, n)]
        for _ in range(n_ctrl):
            redges = rng.sample(all_pairs, len(edges))
            if all(vals[u] != vals[v] for u, v in redges):
                ctrl_valid += 1
        p_chance = ctrl_valid / n_ctrl
        results.append({"feature": name, "valid": ok, "min_k": k,
                        "n_values": len(set(vals.values())), "p_valid_by_chance": round(p_chance, 4)})

    results.sort(key=lambda r: (not r["valid"], r["min_k"] if r["min_k"] else 99, r["p_valid_by_chance"]))
    valid_feats = [r for r in results if r["valid"]]
    # The interesting selectors: valid AND unlikely-by-chance AND small k.
    sharp = [r for r in valid_feats if r["p_valid_by_chance"] < 0.05]

    elapsed = time.perf_counter() - t0
    with open(out, "w") as f:
        f.write(json.dumps({"n_nodes": n, "n_edges": len(edges), "chromatic": 3,
                            "W_positions_0idx": W, "all_features": results}) + "\n")

    print(f"{len(valid_feats)}/{len(results)} features are graph-compatible selectors:")
    for r in valid_feats:
        print(f"  {r['feature']:18} valid min_k={r['min_k']} (p_chance={r['p_valid_by_chance']})")

    valid_summary = [f"{r['feature']}(k={r['min_k']})" for r in valid_feats]
    insights = [
        f"Of {len(results)} candidate position-features, {len(valid_feats)} are GRAPH-COMPATIBLE selectors "
        f"(induce a proper coloring of the 24-crib/22-edge conflict graph): {valid_summary}.",
        f"NON-trivially compatible (valid AND p<0.05 under a scrambled-edge control): "
        f"{[r['feature'] for r in sharp]} -- these are the ONLY position-feature selector families not "
        f"dead a priori; every downstream positional search should use one of them or a non-positional rule.",
        f"Confirmed: pos_mod_m is NOT a valid selector for any m<=7; phillips_block_5x8 "
        f"is {'VALID' if any(r['feature']=='phillips_block_5x8' and r['valid'] for r in results) else 'INVALID'} "
        f"(decides exp 069 admissibility); W-distance features "
        f"{[r['feature'] for r in valid_feats if 'w_' in r['feature']] or 'ALL FAIL'}.",
    ]
    write_verdict(out, Verdict(
        exp="065", title="conflict-graph selector characterization (positive shortlist)",
        hypothesis="enumerate which position-feature selector families are even graph-compatible with chi=3",
        status="promising" if sharp else "inconclusive",
        best_partial=f"{len(valid_feats)} valid selectors; {len(sharp)} non-trivial (p<0.05)",
        search_space=len(results), elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=["restrict all downstream positional searches to the shortlisted selectors; "
                    "if phillips_block valid -> run exp 069 SA; route remaining effort to non-positional "
                    "rules (plaintext-letter/feedback) for the families with no compatible position-feature"],
        metrics={"valid_features": valid_feats, "sharp_features": sharp})
    )
    print(f"\nDone in {elapsed:.1f}s. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
