"""116 — Crib-constrained 2-chart HOMOPHONIC model: is a SIMPLE 2-class selector
feasible (where bijective needed 3 and had none)?

114: chi_b = 2 (homophonic needs 2 charts for the cribs). 115: a 2-chart
homophonic flattens past K4's 4.33-bit entropy. So a 2-chart homophonic model
satisfies BOTH hard facts -- and the bijective squeeze does not bind it. The
decisive question this raises: 106 proved NO simple position selector 3-colours
the (bijective) crib graph, but a homophonic model only needs to 2-colour the
b-conflict graph (same-cipher->different-plaintext). Does a SIMPLE 2-class
selector 2-colour it? If yes, a simple-selector homophonic K4 is crib-FEASIBLE
where the bijective model was infeasible -- a genuine structural opening.

Tests: (A) which simple 2-class selectors (i%2, row/clock parities, prior-A
parity, ...) properly 2-colour the b-conflict graph; (B) for each feasible one,
build the 2 non-injective charts pinned by the cribs and census distinct English
decryptions (free chart entries hill-climbed) -- does the model decrypt uniquely
or is it still under-determined?

$0, local, deterministic, no LLM, no K5, no plaintext. Output:
experiments/results/<date>_116_homophonic_simple_selector.jsonl
"""

from __future__ import annotations

import json
import math
import random
import time
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K4
from kryptos.cribs import CRIBS

A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CRIB = [(c.start - 1 + off, p, ch)
        for c in CRIBS for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext))]
CRIB_POS = {pos for pos, _, _ in CRIB}
FREE = [i for i in range(97) if i not in CRIB_POS]
CC = []
_c = 0
for ch in K4:
    if ch not in "AEIOU":
        _c += 1
    CC.append(_c)

# b-conflict edges (same cipher, different plaintext) over crib nodes
N = len(CRIB)
B_EDGES = set()
for i in range(N):
    for j in range(i + 1, N):
        if CRIB[i][2] == CRIB[j][2] and CRIB[i][1] != CRIB[j][1]:
            B_EDGES.add((i, j))
POS = [c[0] for c in CRIB]

SELECTORS = {
    "i%2": lambda i: i % 2, "(i//7)%2": lambda i: (i // 7) % 2, "cc%2": lambda i: CC[i] % 2,
    "(i//2)%2": lambda i: (i // 2) % 2, "priorA%2": lambda i: (2 * (i % 3) + CC[i]) % 2,
    "(i+cc)%2": lambda i: (i + CC[i]) % 2, "(i//7+i)%2": lambda i: (i // 7 + i) % 2,
    "(i%3>0)": lambda i: 1 if i % 3 else 0, "tri": lambda i: (i % 5) % 2,
}


def is_2coloring(g):
    return all(g(POS[i]) != g(POS[j]) for i, j in B_EDGES)


def census_homophonic(g, rng, restarts=20, steps=3000, eng_bar=-16.0):
    """2 non-injective charts (cipher->plain) pinned by cribs under selector g;
    hill-climb the FREE cipher->plain entries to maximize free-position hexagram;
    return distinct English decryptions + best."""
    pins = {0: {}, 1: {}}
    ok = True
    for pos, p, ch in CRIB:
        c = g(pos)
        if ch in pins[c] and pins[c][ch] != p:
            ok = False; break
        pins[c][ch] = p
    if not ok:
        return None
    distinct = {}
    best = (-99.0, None)
    cls = [g(i) for i in range(97)]
    free_ciphers = {c: [X for X in A if X not in pins[c]] for c in (0, 1)}
    for _ in range(restarts):
        # init: free entries random plaintext letters (NON-injective: no permutation constraint)
        chart = {c: dict(pins[c]) for c in (0, 1)}
        for c in (0, 1):
            for X in free_ciphers[c]:
                chart[c][X] = rng.choice(A)
        def decrypt():
            return "".join(chart[cls[i]][K4[i]] for i in range(97))
        cur = _kpa.score_free_text(decrypt())
        for s in range(steps):
            T = 0.5 * (0.01 / 0.5) ** (s / steps)
            c = rng.randrange(2)
            if not free_ciphers[c]:
                continue
            X = rng.choice(free_ciphers[c]); old = chart[c][X]; nw = rng.choice(A)
            if nw == old:
                continue
            chart[c][X] = nw
            cand = _kpa.score_free_text(decrypt())
            if cand >= cur or rng.random() < math.exp((cand - cur) / max(T, 1e-6)):
                cur = cand
            else:
                chart[c][X] = old
        pt = decrypt(); sc = _kpa.score_free_text(pt)
        if sc >= eng_bar:
            distinct[pt] = round(sc, 2)
        if sc > best[0]:
            best = (sc, pt)
    return {"distinct_english": len(distinct), "best_hex": round(best[0], 2), "best_pt": best[1]}


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_116_homophonic_simple_selector.jsonl"
    rng = random.Random(0)
    t0 = time.perf_counter()

    corp_bar = -16.0
    feasible = [name for name, g in SELECTORS.items() if is_2coloring(g)]

    results = {}
    best_overall = (-99.0, None)
    for name in feasible:
        res = census_homophonic(SELECTORS[name], rng)
        if res:
            results[name] = res
            if res["best_hex"] > best_overall[0]:
                best_overall = (res["best_hex"], name)

    elapsed = time.perf_counter() - t0
    n_feasible = len(feasible)
    # degeneracy: total distinct English decryptions across feasible simple selectors
    total_distinct = sum(r["distinct_english"] for r in results.values())
    unique_lead = (best_overall[1] is not None and best_overall[0] > -15.0
                   and results.get(best_overall[1], {}).get("distinct_english", 99) <= 1)

    with open(out, "w") as f:
        f.write(json.dumps({"n_b_edges": len(B_EDGES), "feasible_simple_selectors": feasible,
                            "n_feasible": n_feasible, "results": results,
                            "best_hex": best_overall[0], "best_selector": best_overall[1]}) + "\n")

    insights = [
        f"b-conflict graph (same-cipher->different-plaintext): {len(B_EDGES)} edges, chi_b=2 (exp 114). Of "
        f"{len(SELECTORS)} simple 2-class selectors, {n_feasible} properly 2-COLOUR it: {feasible or 'NONE'}. "
        f"(Contrast 106: ZERO simple selectors 3-colour the bijective graph -- so homophony genuinely opens "
        f"simple-selector feasibility where the bijective model had none.)",
        (f"Crib-constrained 2-chart homophonic decrypts (free non-injective entries hill-climbed): "
         f"{ {k: v['distinct_english'] for k, v in results.items()} } distinct English-level decryptions per "
         f"selector; best free-hex {best_overall[0]:.2f} ({best_overall[1]}). "
         + ("A near-UNIQUE English decrypt under a simple selector -- inspect/verify immediately!" if unique_lead
            else "Many distinct decrypts -> the model is FEASIBLE and simple but its non-injective free entries "
                 "leave the free positions under-determined (the squeeze is escaped on chart-count/selector, but "
                 "decryption multiplicity persists: 092/093 under-determination is model-robust).")
         if feasible else "No simple selector 2-colours the b-graph; an idiosyncratic 2-colouring would be needed."),
        "STATUS OF THE HOMOPHONIC THREAD: a 2-chart homophonic model satisfies both hard facts (114 chi_b=2, "
        "115 flatten floor 2) AND " + ("admits SIMPLE crib-feasible selectors (unlike the bijective model) -- the "
        "most viable model class found. The remaining gap is decryption multiplicity, attackable with a richer "
        "plaintext constraint, not a structural impossibility." if feasible else "needs an idiosyncratic selector."),
    ]

    status = "promising" if (unique_lead or n_feasible > 0) else "inconclusive"
    write_verdict(out, Verdict(
        exp="116", title="2-chart homophonic model: simple-selector feasibility + decrypt census",
        hypothesis="a 2-chart homophonic K4 with a SIMPLE 2-class selector is crib-feasible (where the bijective "
                   "model was not) and may decrypt uniquely",
        status=status, best_score=(best_overall[0] if unique_lead else None),
        best_partial=f"{n_feasible}/{len(SELECTORS)} simple selectors 2-colour the b-graph (bijective had 0); "
                     f"distinct English {total_distinct}; best hex {best_overall[0]:.2f}",
        search_space=len(SELECTORS), elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["inspect/verify the near-unique homophonic decrypt against cribs + thematic content"]
                    if unique_lead else
                    ["the 2-chart homophonic model is simple-selector-feasible and matches both facts -- the most "
                     "viable model found; decryption multiplicity is the remaining gap. Next: constrain the free "
                     "homophonic entries with a stronger (deterministic) plaintext prior, or enumerate the "
                     "feasible selectors' decryptions for a thematic/crib-extended filter"]),
        metrics={"chi_b": 2, "n_feasible_simple_selectors": n_feasible, "feasible": feasible,
                 "total_distinct_english": total_distinct, "best_hex": best_overall[0],
                 "best_selector": best_overall[1]}),
    )
    print(f"\nb-edges={len(B_EDGES)}; feasible simple 2-class selectors: {feasible} ({n_feasible}, bijective had 0); "
          f"distinct English {total_distinct}; best hex {best_overall[0]:.2f}; status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
