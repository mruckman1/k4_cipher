"""120 — T2-D diagnostic gate: the cheap structural numbers that re-price every
other homophonic attack (build this FIRST).

The frontier (sharpened from 117-119): decryption is P_i = chart[S_i][C_i]; the
73 free positions split into 30 "selector-locked" (cipher letter crib-pinned ->
only the selector bit is free -> 0.50 coin-flip; needs a selector-COUPLED fact)
and 43 "prior-determined" (cipher letter never in cribs -> both chart entries free
-> decided by a deterministic plaintext prior). This experiment computes the three
quantities that tell every downstream idea whether it can possibly work:

  (A) COLOURING-PASS / false-positive rate: probability a random 97-bit selector
      mask properly 2-colours the b-graph (exact, per-component) -> the Bonferroni
      mask budget N_max for the T1-B selector-mask harness, so a colouring-pass is
      not mistaken for signal.
  (B) FREE-CELL COUPLING: the 73 free positions grouped by ciphertext letter into
      decryption "cells" (chart, cipher-letter); distinct free cells, tying, and
      singleton count -> the joint-decode dimension and its ceiling (T1-A/C, T2-E).
  (C) The exact 30/43 selector-locked / prior-determined split + per-letter
      clustering, and a decidability proxy for the 43 (singletons decided by
      n-gram context alone vs tied groups decided jointly).

$0, local, deterministic, no LLM, no K5, no plaintext. Output:
experiments/results/<date>_120_diagnostic_gate.jsonl
"""

from __future__ import annotations

import json
import math
import time
from collections import Counter, defaultdict, deque
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K4
from kryptos.cribs import CRIBS

CRIB = [(c.start - 1 + off, p, ch)
        for c in CRIBS for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext))]
N = len(CRIB)
CRIB_POS = {pos for pos, _, _ in CRIB}
FREE = [i for i in range(97) if i not in CRIB_POS]
CRIB_CIPHER_LETTERS = {ch for _, _, ch in CRIB}


def b_conf(x, y):
    return x[2] == y[2] and x[1] != y[1]


def components_of(adj, nodes):
    seen, comps = set(), []
    for s in nodes:
        if s in seen:
            continue
        q, comp = deque([s]), []
        seen.add(s)
        while q:
            u = q.popleft(); comp.append(u)
            for w in adj[u]:
                if w not in seen:
                    seen.add(w); q.append(w)
        comps.append(comp)
    return comps


def count_proper_2col_component(comp, adj):
    """Number of proper 2-colourings of one component (0 if not bipartite)."""
    base = {comp[0]: 0}
    q = deque([comp[0]])
    ok = True
    while q and ok:
        u = q.popleft()
        for w in adj[u]:
            if w not in base:
                base[w] = 1 - base[u]; q.append(w)
            elif base[w] == base[u]:
                ok = False; break
    if not ok:
        return 0
    return 2  # connected bipartite component -> exactly 2 (swap)


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_120_diagnostic_gate.jsonl"
    t0 = time.perf_counter()

    # b-graph
    adj = defaultdict(set)
    n_edges = 0
    for i in range(N):
        for j in range(i + 1, N):
            if b_conf(CRIB[i], CRIB[j]):
                adj[i].add(j); adj[j].add(i); n_edges += 1
    comps = components_of(adj, range(N))
    edge_comps = [c for c in comps if len(c) > 1]
    isolated = [c[0] for c in comps if len(c) == 1]

    # ---- (A) colouring-pass / FP rate, per component (exact) ----
    # A random assignment of the 24 crib bits is a proper 2-colouring with
    # probability prod_components (proper / 2^size). Isolated: 2/2=1. Edge comp:
    # (#proper)/2^size.
    per_comp_pass = []
    fp_rate = 1.0
    for c in comps:
        size = len(c)
        proper = 2 if size == 1 else count_proper_2col_component(c, adj)
        total = 2 ** size
        p = proper / total
        per_comp_pass.append({"positions": sorted(CRIB[i][0] + 1 for i in c),
                              "size": size, "proper": proper, "total": total, "p_pass": p})
        fp_rate *= p
    # sanity: fp_rate should equal 16384 / 2^24
    n_2col = 1
    for c in comps:
        n_2col *= (2 if len(c) == 1 else count_proper_2col_component(c, adj))
    fp_check = n_2col / (2 ** N)
    # mask budget: largest N s.t. family-wise colouring-pass FP stays under 5%
    # P(>=1 of M random masks 2-colours) = 1-(1-fp)^M < 0.05
    n_max_5pct = int(math.log(1 - 0.05) / math.log(1 - fp_rate)) if fp_rate > 0 else 0

    # ---- (B) free-cell coupling ----
    free_by_letter = defaultdict(list)
    for i in FREE:
        free_by_letter[K4[i]].append(i)
    free_letters = sorted(free_by_letter)
    group_sizes = {L: len(ps) for L, ps in free_by_letter.items()}
    singleton_letters = [L for L, ps in free_by_letter.items() if len(ps) == 1]
    # a free position's cell = (chart in {0,1}, cipher letter). Positions with the
    # same letter assigned the same chart are TIED. Max distinct free cells:
    max_free_cells = sum(min(2, len(ps)) for ps in free_by_letter.values())
    # joint-decode dimension lower bound = #distinct free cipher letters (each needs
    # >=1 free chart entry); upper bound = max_free_cells.
    n_free_letters = len(free_letters)

    # ---- (C) the 30/43 split + decidability proxy ----
    selector_locked = [i for i in FREE if K4[i] in CRIB_CIPHER_LETTERS]   # crib-pinned letter
    prior_determined = [i for i in FREE if K4[i] not in CRIB_CIPHER_LETTERS]
    # within prior-determined, singletons (no tying, decided by n-gram context only)
    pd_by_letter = defaultdict(list)
    for i in prior_determined:
        pd_by_letter[K4[i]].append(i)
    pd_singletons = [L for L, ps in pd_by_letter.items() if len(ps) == 1]
    pd_tied_groups = {L: ps for L, ps in pd_by_letter.items() if len(ps) > 1}
    # selector-locked clustering by letter (these share cells too, but one cell is
    # crib-pinned so the freedom is the selector bit)
    sl_by_letter = defaultdict(list)
    for i in selector_locked:
        sl_by_letter[K4[i]].append(i)

    elapsed = time.perf_counter() - t0
    with open(out, "w") as f:
        f.write(json.dumps({
            "n_b_edges": n_edges, "n_2colorings": n_2col,
            "colouring_pass_fp_rate": fp_rate, "fp_rate_check_16384_over_2^24": fp_check,
            "fp_rate_as_2^-k": round(math.log2(fp_rate), 3),
            "mask_budget_N_max_fwer5pct": n_max_5pct,
            "per_component_pass": per_comp_pass,
            "n_free": len(FREE), "n_selector_locked": len(selector_locked),
            "n_prior_determined": len(prior_determined),
            "n_distinct_free_cipher_letters": n_free_letters,
            "max_free_cells_joint_decode_dim": max_free_cells,
            "free_group_sizes": group_sizes,
            "n_singleton_free_letters": len(singleton_letters),
            "prior_determined_singletons": len(pd_singletons),
            "prior_determined_tied_groups": {L: ps for L, ps in pd_tied_groups.items()},
            "selector_locked_by_letter": {L: ps for L, ps in sl_by_letter.items()}}) + "\n")

    insights = [
        f"(A) COLOURING-PASS FP RATE = {fp_rate:.6g} = 2^{math.log2(fp_rate):.1f} "
        f"(check 16384/2^24 = {fp_check:.6g}). Per-component: eight 2-cliques at p=1/2, one 3-node path at "
        f"p=1/4, five isolated at p=1. => A random selector mask 2-colours the cribs ~0.1% of the time. MASK "
        f"BUDGET: testing up to N_max={n_max_5pct} structured masks keeps the family-wise colouring-pass false "
        f"positive under 5% -- beyond that, a colouring-pass is expected by chance and must clear the decrypt "
        f"null (106/111), not just the colouring test.",
        f"(B) FREE-CELL COUPLING: the {len(FREE)} free positions use {n_free_letters} distinct ciphertext letters; "
        f"the joint chart-aware decode therefore has at most {max_free_cells} free cells (chart x cipher-letter) "
        f"-- NOT 73 independent letters. {len(singleton_letters)} ciphertext letter(s) occur once among free "
        f"positions. This {max_free_cells}-cell space (vs 73) is the true dimension of T1-A/T2-E and the ceiling "
        f"on what a joint n-gram decode can resolve.",
        f"(C) THE SPLIT (exact): {len(selector_locked)} SELECTOR-LOCKED free positions (ciphertext letter is "
        f"crib-pinned -> chart entry known -> only the selector bit free -> 0.50 coin-flip; movable ONLY by a "
        f"selector-coupled M1/M2 fact) and {len(prior_determined)} PRIOR-DETERMINED (ciphertext letter never in "
        f"cribs -> both chart entries free -> decided by the deterministic plaintext prior). Path A owns the "
        f"{len(prior_determined)}; Path B (selector-coupled) owns the {len(selector_locked)}.",
        f"(C-proxy) Of the {len(prior_determined)} prior-determined positions, {len(pd_singletons)} are singletons "
        f"(unique free cipher letter -> decided by n-gram CONTEXT alone, no cross-position tie) and the rest fall "
        f"in {len(pd_tied_groups)} tied groups (decided JOINTLY -- repeated cipher letter forces equal plaintext "
        f"within a chart). Tied groups are where the homophonic structure adds decode leverage beyond a plain "
        f"per-position n-gram.",
    ]

    # gate is a knowledge/tooling result: it re-prices, does not solve
    write_verdict(out, Verdict(
        exp="120", title="diagnostic gate -- FP/mask-budget, free-cell coupling, 30/43 split",
        hypothesis="cheap structural diagnostics re-price the homophonic attack menu: the mask budget, the "
                   "joint-decode cell dimension, and the exact selector-locked/prior-determined split",
        status="inconclusive",
        best_partial=f"FP/mask-pass 2^{math.log2(fp_rate):.0f} (N_max={n_max_5pct}); {max_free_cells} free cells "
                     f"(not 73); split {len(selector_locked)} selector-locked / {len(prior_determined)} "
                     f"prior-determined",
        search_space=n_2col, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=["T1-B selector-mask harness must cap at N_max masks and clear the decrypt null, not just the "
                    "colouring test (122)",
                    "T1-A chart-tie + T2-E joint decode operate over the "
                    f"{max_free_cells}-cell space, not 73 letters (121/124)",
                    "Path A (plaintext prior) targets the 43 prior-determined; Path B (selector-coupled) targets "
                    "the 30 selector-locked -- build both, they are disjoint"],
        metrics={"colouring_pass_fp_rate": fp_rate, "mask_budget_N_max": n_max_5pct,
                 "max_free_cells": max_free_cells, "n_selector_locked": len(selector_locked),
                 "n_prior_determined": len(prior_determined),
                 "prior_determined_singletons": len(pd_singletons)}),
    )
    print(f"\nFP/mask-pass={fp_rate:.6g} (2^{math.log2(fp_rate):.1f}); N_max={n_max_5pct}; "
          f"free cells={max_free_cells} (vs 73); split {len(selector_locked)} locked / "
          f"{len(prior_determined)} prior; pd-singletons={len(pd_singletons)}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
