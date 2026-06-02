"""117 — Enumerate the ACTUAL proper 2-colourings of the b-conflict graph
(move 1 of the homophonic thread).

114 proved chi_b = 2 (a homophonic decryption chart needs only the b-conflict
constraint, same-cipher->different-plaintext); 116 found NO *simple* 2-class
selector 2-colours it. But the bijective analysis (106: 0 simple selectors
3-colour the full graph) never asked how many proper colourings the graph
*admits* -- the selector only has to AGREE with some proper colouring on the
crib positions. The decisive structural question: how many crib-feasible 2-chart
partitions exist (the homophonic model's whole crib-selector freedom on the
pinned positions), and is that space genuinely SMALLER than the bijective
3-colouring space -- a narrowing the bijective view could not see?

A proper 2-colouring of the b-graph IS a crib-feasible assignment of the 24
crib positions to 2 homophonic charts (within each chart no cipher letter maps
to two plaintexts). This enumerates them exactly (factored over connected
components -- a bipartite graph's count is 2^(#edge-bearing comps) x 2^(#isolated)),
dedups the distinct pinned chart-pairs, and counts the bijective graph's proper
3-colourings the same way for a head-to-head comparison.

$0, local, deterministic, no LLM, no K5, no plaintext. Output:
experiments/results/<date>_117_homophonic_2coloring_enumeration.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import time
from collections import defaultdict, deque
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.cribs import CRIBS

e035 = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
    "e035", str(Path(__file__).parent / "035_minimum_alphabet_analysis.py")))
e035.__spec__.loader.exec_module(e035)

# CRIB[i] = (position, plain_letter, cipher_letter)  -- 116's convention
CRIB = [(c.start - 1 + off, p, ch)
        for c in CRIBS for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext))]
N = len(CRIB)


def b_conf(x, y):
    return x[2] == y[2] and x[1] != y[1]   # same cipher, different plaintext


def full_conf(x, y):
    # bijective conflict (035): same plain->diff cipher OR same cipher->diff plain
    return (x[1] == y[1] and x[2] != y[2]) or (x[2] == y[2] and x[1] != y[1])


def build_edges(conf):
    e = set()
    for i in range(N):
        for j in range(i + 1, N):
            if conf(CRIB[i], CRIB[j]):
                e.add((i, j))
    return e


def adjacency(edges):
    adj = defaultdict(set)
    for u, v in edges:
        adj[u].add(v); adj[v].add(u)
    return adj


def components(adj):
    seen, comps = set(), []
    for s in range(N):
        if s in seen:
            continue
        q, comp = deque([s]), []
        seen.add(s)
        while q:
            u = q.popleft(); comp.append(u)
            for w in adj[u]:
                if w not in seen:
                    seen.add(w); q.append(w)
        comps.append(sorted(comp))
    return comps


def count_colorings_component(comp, adj, k):
    """Exact count of proper k-colourings of one component (DFS)."""
    color = {}

    def rec(idx):
        if idx == len(comp):
            return 1
        v = comp[idx]
        used = {color[u] for u in adj[v] if u in color}
        total = 0
        for c in range(k):
            if c in used:
                continue
            color[v] = c
            total += rec(idx + 1)
        color.pop(v, None)
        return total

    return rec(0)


def count_colorings(adj, k):
    """Total proper k-colourings = product over connected components."""
    total = 1
    per_comp = []
    for comp in components(adj):
        c = count_colorings_component(comp, adj, k)
        per_comp.append((len(comp), c))
        total *= c
    return total, per_comp


def enumerate_2colorings_edgecomps(adj):
    """Enumerate the proper 2-colourings of the EDGE-BEARING components only
    (the constrained crib nodes). Returns list of {node: colour} restricted to
    those nodes. Count = 2^(#edge-bearing comps)."""
    edge_comps = [c for c in components(adj) if len(c) > 1]
    colourings = [{}]
    for comp in edge_comps:
        # one bipartition (BFS 2-colour) then its swap = the 2 colourings of this comp
        base = {}
        root = comp[0]
        base[root] = 0
        q = deque([root])
        while q:
            u = q.popleft()
            for w in adj[u]:
                if w not in base:
                    base[w] = 1 - base[u]; q.append(w)
        swap = {n: 1 - c for n, c in base.items()}
        new = []
        for partial in colourings:
            for variant in (base, swap):
                m = dict(partial); m.update(variant); new.append(m)
        colourings = new
    return colourings, edge_comps


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_117_homophonic_2coloring_enumeration.jsonl"
    t0 = time.perf_counter()

    b_edges = build_edges(b_conf)
    f_edges = build_edges(full_conf)
    b_adj, f_adj = adjacency(b_edges), adjacency(f_edges)

    b_comps = components(b_adj)
    b_edge_comps = [c for c in b_comps if len(c) > 1]
    b_isolated = [c[0] for c in b_comps if len(c) == 1]

    # exact colouring counts (factored over components)
    n_2col, b_per_comp = count_colorings(b_adj, 2)         # includes isolated freedom
    n_3col_full, f_per_comp = count_colorings(f_adj, 3)    # bijective space
    # structural 2-colourings = only the forced splits (edge-bearing comps); /2 for global swap
    n_2col_structural = 2 ** len(b_edge_comps)
    essentially_distinct = max(1, n_2col_structural // 2)

    # enumerate the edge-component 2-colourings and dedup the pinned chart pairs
    colourings, edge_comps = enumerate_2colorings_edgecomps(b_adj)
    distinct_charts = {}
    for col in colourings:
        charts = {0: {}, 1: {}}
        ok = True
        for n, (pos, p, ch) in enumerate(CRIB):
            if n not in col:
                continue   # isolated node: unconstrained here (handled in 118)
            c = col[n]
            if ch in charts[c] and charts[c][ch] != p:
                ok = False; break
            charts[c][ch] = p
        if not ok:
            continue
        key = (tuple(sorted(charts[0].items())), tuple(sorted(charts[1].items())))
        # canonicalise under chart-swap so A|B and B|A count once
        key_sw = (tuple(sorted(charts[1].items())), tuple(sorted(charts[0].items())))
        distinct_charts[min(key, key_sw)] = (len(charts[0]), len(charts[1]))

    elapsed = time.perf_counter() - t0
    narrows = n_2col_structural < n_3col_full

    with open(out, "w") as f:
        f.write(json.dumps({
            "n_b_edges": len(b_edges), "n_full_edges": len(f_edges),
            "b_components": [len(c) for c in b_comps],
            "b_edge_bearing_components": [sorted([CRIB[i][0] + 1 for i in c]) for c in b_edge_comps],
            "b_isolated_count": len(b_isolated),
            "n_2colorings_total_incl_isolated": n_2col,
            "n_2colorings_structural": n_2col_structural,
            "essentially_distinct_2colorings": essentially_distinct,
            "n_distinct_pinned_chart_pairs": len(distinct_charts),
            "n_3colorings_full_bijective": n_3col_full,
            "homophonic_narrows_crib_space": narrows,
            "chart_pin_sizes": sorted(distinct_charts.values())}) + "\n")

    insights = [
        f"b-conflict graph: {len(b_edges)} edges over {N} crib nodes. Connected structure: "
        f"{len([c for c in b_comps if len(c) > 1])} edge-bearing component(s) "
        f"(sizes {[len(c) for c in b_edge_comps]}) + {len(b_isolated)} isolated nodes. A proper 2-colouring is a "
        f"crib-feasible split of the 24 crib positions into 2 homophonic charts.",
        f"COUNT (exact, factored over components): the forced splits give {n_2col_structural} structural "
        f"2-colourings ({essentially_distinct} up to chart-swap); {len(distinct_charts)} DISTINCT pinned "
        f"chart-pairs. With the {len(b_isolated)} isolated crib nodes free to sit in either chart, the full "
        f"2-colouring count is {n_2col:,}. The bijective full graph admits {n_3col_full:,} proper 3-colourings.",
        (f"HOMOPHONIC NARROWS THE CRIB SPACE: the homophonic model's forced crib-split space "
         f"({n_2col_structural} structural 2-colourings) is SMALLER than the bijective 3-colouring space "
         f"({n_3col_full:,}). The cribs pin the 2-chart partition far more tightly than the bijective view could "
         f"see -- the structural opening 116 hinted at, made quantitative."
         if narrows else
         f"NO NARROWING ON THE CRIB AXIS: the structural 2-colouring count ({n_2col_structural}) is not smaller "
         f"than the bijective 3-colouring count ({n_3col_full:,}); the homophonic relaxation does not tighten the "
         f"crib-partition space."),
        "SCOPE: this counts crib-feasible CHART PARTITIONS, not decryptions -- the 73 free positions still need a "
        "selector value and the charts' free (non-crib) entries are open (092/093 under-determination). 118 does "
        "the exact forced/free entry accounting per partition; 119 the determinacy floor + decrypt census.",
    ]

    status = "promising" if narrows else "inconclusive"
    write_verdict(out, Verdict(
        exp="117", title="enumerate proper 2-colourings of the b-conflict graph (homophonic crib-split space)",
        hypothesis="the homophonic b-graph admits FAR FEWER crib-feasible colourings than the bijective "
                   "3-colouring space, narrowing the selector's crib-position freedom",
        status=status,
        best_partial=f"{n_2col_structural} structural 2-colourings ({len(distinct_charts)} distinct chart-pairs) "
                     f"vs {n_3col_full} bijective 3-colourings; narrows={narrows}",
        search_space=n_2col, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=["118: under each distinct 2-colouring, count cipher->plain entries forced vs free per chart, "
                    "and the selector-independent forced free-position set (exact, supersedes 098's sampling)",
                    "119: homophonic determinacy floor + decrypt census over the enumerated 2-colourings"],
        metrics={"n_b_edges": len(b_edges), "n_2colorings_structural": n_2col_structural,
                 "n_distinct_chart_pairs": len(distinct_charts), "n_3colorings_full": n_3col_full,
                 "b_isolated": len(b_isolated), "narrows": narrows}),
    )
    print(f"\nb-edges={len(b_edges)}; edge-comps={[len(c) for c in b_edge_comps]}; isolated={len(b_isolated)}; "
          f"structural 2-col={n_2col_structural} (distinct charts {len(distinct_charts)}); "
          f"bijective 3-col={n_3col_full}; narrows={narrows}; status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
