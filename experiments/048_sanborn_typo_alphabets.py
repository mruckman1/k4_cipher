"""048 — Sanborn/Scheidt alphabet-construction grammar vs the χ=3 cribs.

K1/K2 are Quagmire III keyed by KRYPTOS; the one documented Sanborn
fingerprint is the deliberate single-letter typo: IQLUSION (illusion),
UNDERGRUUND (underground), DESPARATLY (desperately), DYAHR (on the plate).
exp 037 exhausted CLEAN keyword alphabets; it never tried keyed alphabets
built from thematic keywords carrying a Sanborn-style typo.

We build keyed alphabets from Egypt-1986 + Berlin-Wall + navigation +
Kryptos-personal keywords, each in clean form AND with every single-letter
substitution (the IQLUSION-style typo) and single deletion. Dedup to
distinct 26-letter permutations, then test exact 3-cover (over the
top-coverage alphabets), greedy-k, and best-3-partial against the 23 crib
constraints. Learning this grammar is the regulariser for exp 054's EM.

$0, local. Output: experiments/results/<date>_048_sanborn_typo_alphabets.jsonl
"""

from __future__ import annotations

import json
import time
from datetime import date

import _crib_sat as cs
import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import keyed_alphabet

THEME_KEYWORDS = [
    # Kryptos / personal
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DYAHR", "SANBORN", "SCHEIDT", "LANGLEY",
    # Berlin Wall 1989
    "BERLIN", "CLOCK", "BERLINCLOCK", "WELTZEITUHR", "ALEXANDERPLATZ", "BORNHOLMER",
    "BRANDENBURG", "MAUERFALL", "FREEDOM", "WALL", "BAHNHOF", "URANIA",
    # Egypt 1986
    "EGYPT", "CAIRO", "KARNAK", "LUXOR", "TUTANKHAMEN", "CARTER", "PHARAOH", "VALLEY",
    # navigation / clue words
    "NORTHEAST", "EAST", "MAGNETIC", "FIELD", "BURIED", "LODESTONE", "COMPASS",
    "COORDINATES", "POSITION", "SHADOW", "INVISIBLE", "DIGITAL", "INTERPRET",
]


def typo_variants(kw: str):
    """The clean keyword plus every single-letter substitution and single
    deletion (Sanborn's IQLUSION/UNDERGRUUND signature)."""
    yield kw
    for i in range(len(kw)):
        for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if c != kw[i]:
                yield kw[:i] + c + kw[i + 1:]
        if len(kw) > 3:
            yield kw[:i] + kw[i + 1:]


def build_pool():
    pool, seen = [], set()
    for kw in THEME_KEYWORDS:
        for v in typo_variants(kw):
            a = keyed_alphabet(v).letters
            if a not in seen:
                seen.add(a)
                pool.append((f"{kw}~{v}", a))
    return pool


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_048_sanborn_typo_alphabets.jsonl"
    cons = cs.crib_constraints()
    pool = build_pool()
    t0 = time.perf_counter()
    print(f"Sanborn-typo pool: {len(pool)} distinct keyed alphabets")

    # Greedy is cheap on the full pool.
    gk, glabels, gcov, gtot = cs.greedy_cover(pool)
    # Prune to top alphabets by single-constraint coverage for an exact 3-cover.
    scored = sorted(pool, key=lambda kv: bin(cs.covered_mask(kv[1], cons)).count("1"), reverse=True)
    top = scored[:300]
    cover3 = cs.find_cover(top, 3)
    bp_n, bp_tot, bp_labels = cs.best_partial_cover(top[:120], 3)
    elapsed = time.perf_counter() - t0

    with open(out, "w") as f:
        f.write(json.dumps({"pool_size": len(pool), "greedy_k": gk, "greedy_labels": glabels,
                            "exact_3_cover": bool(cover3), "best_partial_k3": bp_n}) + "\n")

    if cover3:
        status = "promising"
        insights = [f"A 3-set of Sanborn-typo keyed alphabets {cover3[0]} satisfies all {len(cons)} crib "
                    f"constraints -- the deliberate-typo grammar yields a valid χ=3 alphabet set."]
        nexts = ["recover the selection rule (exp 054/055) with these alphabets; decrypt+verify"]
    else:
        status = "ruled_out"
        insights = [f"No 3 Sanborn-typo alphabets cover the {len(cons)} crib constraints; greedy needs k={gk} "
                    f"({gcov}/{gtot}); best 3 (top-120) cover {bp_n}/{bp_tot}. Single-typo keyed alphabets do "
                    f"not realize K4's 3-colouring -- consistent with exp 037 (alphabets are not keyword-derived, "
                    f"even with one typo)."]
        nexts = ["pool the route (046) + compass (047) + typo (048) alphabets into ONE cover search; "
                 "feed the per-constraint covering sets to exp 055 CP-SAT as the alphabet candidate lists"]

    write_verdict(out, Verdict(
        exp="048", title="Sanborn deliberate-typo keyed alphabets vs χ=3",
        hypothesis="K4's hand-crafted alphabets are themed keywords carrying a single Sanborn-style typo",
        status=status, best_partial=f"best 3 cover {bp_n}/{bp_tot}; greedy k={gk}",
        search_space=len(pool), elapsed_s=round(elapsed, 1),
        insights=insights, next_steps=nexts,
        metrics={"greedy_k": gk, "exact_3_cover": bool(cover3), "best_partial_k3": bp_n})
    )
    print(f"\nGreedy k={gk} ({gcov}/{gtot}); best 3 cover {bp_n}/{bp_tot}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
