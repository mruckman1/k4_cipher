"""046 — Tableau-route alphabets vs the χ=3 crib-satisfaction problem.

exp 035 proved K4 needs >=3 distinct alphabet permutations (chromatic
number 3); exps 036/037 proved they are NOT keyword-derived and left open
"no algorithm yet to enumerate hand-crafts without exhaustive 26! search".

Hypothesis: the hand-crafted alphabets are geometric reading-paths through
the physical 26x26 KRYPTOS Vigenere tableau (rows/cols/diagonals/columnar/
boustrophedon) -- non-keyword yet non-arbitrary. `kryptos.alphabets_routes`
enumerates ~230 such permutations.

Question: does some small set of route alphabets jointly satisfy ALL 24
cribs (23 distinct plain->cipher constraints)? Each crib is assigned to one
covering alphabet; because a permutation is single-valued, any alphabet
covering two cribs proves they don't conflict, so a cover automatically
respects the χ=3 colouring. This is exact SET COVER.

If a 3-cover exists -> the route family supplies K4's alphabets and the
remaining job is the selection rule (exps 054/055). If not, we report the
minimum k a greedy cover needs (upper bound) vs the χ=3 lower bound, and
the best partial cover at k=3.

$0, local. Output: experiments/results/<date>_046_tableau_route_alphabets.jsonl
"""

from __future__ import annotations

import json
import time
from datetime import date
from pathlib import Path

import _crib_sat as cs
import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets_routes import route_alphabets


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_046_tableau_route_alphabets.jsonl"
    pool = route_alphabets()
    cons = cs.crib_constraints()
    t0 = time.perf_counter()

    print(f"Route-alphabet pool: {len(pool)}   distinct crib constraints: {len(cons)}")

    # Exact 3-cover (χ=3 lower bound).
    cover3 = cs.find_cover(pool, 3)
    # Greedy upper bound on minimum k.
    gk, glabels, gcov, gtot = cs.greedy_cover(pool)
    # Best partial cover at k=3 (how many of 23 can 3 route alphabets reach?).
    bp_n, bp_tot, bp_labels = cs.best_partial_cover(pool, 3)

    elapsed = time.perf_counter() - t0

    with open(out, "w") as f:
        f.write(json.dumps({
            "pool_size": len(pool), "n_constraints": len(cons),
            "exact_3_cover": cover3[0] if cover3 else None,
            "greedy_k": gk, "greedy_labels": glabels,
            "greedy_covered": gcov, "greedy_total": gtot,
            "best_partial_k3": bp_n, "best_partial_labels": bp_labels,
        }) + "\n")

    if cover3:
        labels, assignment = cover3
        status = "promising"
        insights = [f"A 3-set of ROUTE alphabets {labels} satisfies all {len(cons)} crib constraints -- "
                    f"route alphabets are sufficient for K4's χ=3 requirement WITHOUT any keyword. "
                    f"This is the first non-keyword source for the proven-mandatory hand-crafted alphabets."]
        nexts = ["recover the selection rule with exp 054 (EM) / exp 055 (CP-SAT) using these 3 alphabets; "
                 "then decrypt all 97 and hexagram-verify"]
        best_partial = f"3-cover FOUND: {labels}"
    else:
        status = "ruled_out"
        insights = [
            f"No 3 route alphabets cover all {len(cons)} crib constraints (χ=3 lower bound NOT met by routes).",
            f"Greedy needs k={gk} route alphabets to cover {gcov}/{gtot}; best 3 route alphabets cover only "
            f"{bp_n}/{bp_tot} constraints. Tableau-route alphabets alone do not realize K4's 3-colouring.",
        ]
        nexts = ["expand the route family (knight walks on a Quagmire tableau; mixed-base routes), or "
                 "combine routes with compass-seeded alphabets (exp 047) and the Sanborn-typo family (exp 048)"]
        best_partial = f"best 3 routes cover {bp_n}/{bp_tot}; greedy needs k={gk}"

    write_verdict(out, Verdict(
        exp="046", title="tableau-route alphabets vs χ=3 crib cover",
        hypothesis="K4's >=3 hand-crafted alphabets are geometric routes through the KRYPTOS tableau",
        status=status, best_partial=best_partial, search_space=len(pool),
        elapsed_s=round(elapsed, 1), insights=insights, next_steps=nexts,
        metrics={"greedy_k": gk, "greedy_labels": glabels,
                 "best_partial_k3": bp_n, "exact_3_cover": bool(cover3)},
    ))
    print(f"\nGreedy min-k upper bound: {gk} (covers {gcov}/{gtot}); "
          f"best 3 routes cover {bp_n}/{bp_tot}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
