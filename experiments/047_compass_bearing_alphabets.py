"""047 — Compass/lodestone-bearing-seeded alphabets vs the χ=3 cribs.

data/physical/compass_bearings.txt records two hard physical numbers: the
lodestone-deflected bearing 248deg and the sculpture->USGS-marker bearing
45deg (the NORTHEAST direction). Reduced mod 26: 248->14, 45->19. (14 is
also the first BERLINCLOCK shift.) A bearing is a memorable, hand-executable
seed -- exactly the kind of non-keyword generator that could produce the
proven-mandatory hand-crafted alphabets (exp 037 only exhausted KEYWORD
alphabets and natural position rules).

We enumerate alphabets seeded by {0, 248, 45} and their mod-26 reductions
{0, 14, 19}: rotations, affine x->(a*x+b) and decimation, over STANDARD and
KRYPTOS-keyed bases, then test exact 3-cover / greedy-k / best-3-partial
against the 23 crib constraints (same machinery as exp 046).

$0, local. Output: experiments/results/<date>_047_compass_bearing_alphabets.jsonl
"""

from __future__ import annotations

import json
import time
from datetime import date
from math import gcd

import _crib_sat as cs
import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD

SEEDS = [0, 248, 45]
RED = sorted({s % 26 for s in SEEDS})            # {0, 14, 19}
COPRIME = [a for a in range(1, 26) if gcd(a, 26) == 1]


def build_pool() -> list[tuple[str, str]]:
    bases = [("STD", STANDARD.letters), ("KEYED", KRYPTOS_KEYED.letters)]
    bases += [("REVSTD", STANDARD.letters[::-1]), ("REVKEYED", KRYPTOS_KEYED.letters[::-1])]
    pool: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(label, s):
        if len(set(s)) == 26 and s not in seen:
            seen.add(s); pool.append((label, s))

    for bname, base in bases:
        # rotations by the bearing reductions
        for r in RED:
            add(f"rot{r}[{bname}]", base[r:] + base[:r])
        # affine x -> (a*x+b) % 26, with a from bearing-derived coprimes
        a_candidates = sorted({19, 45 % 26, *(a for a in COPRIME if a in (RED[1] if len(RED) > 1 else 1, 19, 21, 25, 7, 9, 11))})
        for a in a_candidates:
            if gcd(a, 26) != 1:
                continue
            for b in RED:
                s = "".join(base[(a * x + b) % 26] for x in range(26))
                add(f"aff(a{a},b{b})[{bname}]", s)
        # decimation by bearing coprimes
        for a in (19, 45 % 26):
            if gcd(a, 26) == 1:
                s = "".join(base[(a * x) % 26] for x in range(26))
                add(f"dec{a}[{bname}]", s)
    return pool


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_047_compass_bearing_alphabets.jsonl"
    pool = build_pool()
    cons = cs.crib_constraints()
    t0 = time.perf_counter()
    print(f"Compass-seeded pool: {len(pool)} alphabets (seeds {SEEDS} -> mod26 {RED})")

    cover3 = cs.find_cover(pool, 3)
    gk, glabels, gcov, gtot = cs.greedy_cover(pool)
    bp_n, bp_tot, bp_labels = cs.best_partial_cover(pool, 3)
    elapsed = time.perf_counter() - t0

    with open(out, "w") as f:
        f.write(json.dumps({"pool_size": len(pool), "exact_3_cover": bool(cover3),
                            "greedy_k": gk, "greedy_labels": glabels,
                            "best_partial_k3": bp_n}) + "\n")

    if cover3:
        status = "promising"
        insights = [f"A 3-set of compass-bearing alphabets {cover3[0]} satisfies all {len(cons)} crib "
                    f"constraints -- first non-keyword physical source for K4's hand-crafted alphabets."]
        nexts = ["recover the selection rule (exp 054/055) with these alphabets and decrypt+verify"]
    else:
        status = "ruled_out"
        insights = [f"No 3 compass-seeded alphabets cover the {len(cons)} crib constraints; greedy needs "
                    f"k={gk} ({gcov}/{gtot}), best 3 cover {bp_n}/{bp_tot}. Bearing 248/45 (mod26 14/19) "
                    f"seeded affine/rotation/decimation alphabets do not realize K4's 3-colouring."]
        nexts = ["combine compass alphabets with route (exp 046) + Sanborn-typo (exp 048) pools in one cover"]

    write_verdict(out, Verdict(
        exp="047", title="compass/lodestone bearing-seeded alphabets vs χ=3",
        hypothesis="K4's hand-crafted alphabets are seeded by the 248deg/45deg physical bearings",
        status=status, best_partial=f"best 3 cover {bp_n}/{bp_tot}; greedy k={gk}",
        search_space=len(pool), elapsed_s=round(elapsed, 1),
        insights=insights, next_steps=nexts,
        metrics={"greedy_k": gk, "exact_3_cover": bool(cover3), "best_partial_k3": bp_n})
    )
    print(f"\nGreedy k={gk} ({gcov}/{gtot}); best 3 cover {bp_n}/{bp_tot}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
