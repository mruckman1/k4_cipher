"""055 — Structural admissibility filter: how many alphabets does each
candidate plaintext FORCE for a per-position substitution to K4?

exp 035 computed chi=3 for the 24-CRIB conflict graph (a lower bound). This
pushes it to the FULL 97 positions of each N1 candidate. Key fact: for a
per-position substitution with k alphabets, each plaintext LETTER can map to
at most k distinct ciphertext letters across the message. So

    chi(candidate)  >=  fanout(candidate)
        := max over letters L of  |{ K4[i] : P[i] == L }|

is a hard, cheap LOWER BOUND on the alphabets needed, and CP-SAT gives the
exact chromatic number of the conflict graph. Any candidate with chi > k is
structurally IMPOSSIBLE for a k-alphabet K4 under ANY selection rule.

Consequence: ShinkaEvolve's K=4 model demands a plaintext in which EVERY
letter maps to <=4 distinct K4 letters -- a very repetition-constrained
text. English plaintexts (E ~12x) blow past that. This experiment measures
the fanout/chi distribution of the 23,592-candidate prior and reports how
many (if any) are admissible at k<=4/5/6, and the best admissible by
hexagram.

Requires ortools (free, installed).
Output: experiments/results/<date>_055_cpsat_structural.jsonl
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from datetime import date
from pathlib import Path

from ortools.sat.python import cp_model

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K1_PLAINTEXT, K4

K4U = K4


def fanout(P: str) -> int:
    """Max over plaintext letters of #distinct K4 letters it maps to.
    A hard lower bound on the alphabets a per-position cipher needs."""
    by_letter: dict[str, set] = {}
    for p, c in zip(P, K4U):
        by_letter.setdefault(p, set()).add(c)
    return max(len(s) for s in by_letter.values())


def conflict_edges(P: str):
    edges = []
    n = len(P)
    for i in range(n):
        for j in range(i + 1, n):
            if (P[i] == P[j]) != (K4U[i] == K4U[j]):
                edges.append((i, j))
    return edges


def exact_chromatic(P: str, kmax=14, time_limit=3.0) -> int:
    edges = conflict_edges(P)
    lb = fanout(P)
    for k in range(lb, kmax + 1):
        m = cp_model.CpModel()
        col = [m.NewIntVar(0, k - 1, f"c{i}") for i in range(97)]
        for u, v in edges:
            m.Add(col[u] != col[v])
        m.Add(col[0] == 0)
        s = cp_model.CpSolver()
        s.parameters.max_time_in_seconds = time_limit
        s.parameters.num_search_workers = 4
        if s.Solve(m) in (cp_model.OPTIMAL, cp_model.FEASIBLE):
            return k
    return kmax + 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--exact-sample", type=int, default=40,
                    help="how many candidates get exact CP-SAT chromatic number")
    ap.add_argument("--run-dir", type=Path, default=None)
    args = ap.parse_args()
    out = _kpa.RESULTS / f"{date.today()}_055_cpsat_structural.jsonl"

    run_dir = args.run_dir or _kpa.latest_run_dir("sonnet")
    cands = _kpa.load_candidates(run_dir)
    print(f"Loaded {len(cands)} candidates from {run_dir.name}")

    t0 = time.perf_counter()
    # 1) cheap fanout lower bound for ALL candidates
    fan = [(fanout(P), P) for P in cands]
    fan_dist = Counter(f for f, _ in fan)
    adm4 = [(_kpa.score_free_text(P), P, f) for f, P in fan if f <= 4]
    adm5 = sum(1 for f, _ in fan if f <= 5)
    adm6 = sum(1 for f, _ in fan if f <= 6)
    adm4.sort(reverse=True)

    # 2) exact chromatic number on a sample (lowest-fanout first -- most admissible)
    fan_sorted = sorted(fan, key=lambda x: x[0])
    exact = []
    for f, P in fan_sorted[:args.exact_sample]:
        chi = exact_chromatic(P)
        exact.append((chi, f, round(_kpa.score_free_text(P), 2)))
    exact_dist = Counter(chi for chi, _, _ in exact)

    # calibration: fanout of a real English text (K1 plaintext) vs K4 (meaningless
    # mapping, just to show English forces a high fanout against a random target)
    k1_fan = fanout((K1_PLAINTEXT + K1_PLAINTEXT)[:97])

    elapsed = time.perf_counter() - t0
    with open(out, "w") as f:
        f.write(json.dumps({
            "fanout_distribution": {str(k): v for k, v in sorted(fan_dist.items())},
            "min_fanout": min(fan_dist), "n_candidates": len(cands),
            "n_fanout<=4": len(adm4), "n_fanout<=5": adm5, "n_fanout<=6": adm6,
            "exact_chromatic_distribution_lowfanout_sample":
                {str(k): v for k, v in sorted(exact_dist.items())},
            "k1_english_fanout_vs_k4": k1_fan,
        }) + "\n")
        for s, P, fo in adm4[:30]:
            f.write(json.dumps({"fanout": fo, "free_hex": round(s, 2), "plaintext": P}) + "\n")

    min_fan = min(fan_dist)
    best = adm4[0] if adm4 else None
    insights = [
        f"Fanout lower-bound distribution over {len(cands)} N1 candidates: "
        f"{dict(sorted(fan_dist.items()))}. Minimum fanout = {min_fan} "
        f"(=> EVERY candidate needs >= {min_fan} alphabets for a per-position cipher to K4).",
        f"Admissible at k<=4: {len(adm4)}; k<=5: {adm5}; k<=6: {adm6} (out of {len(cands)}).",
        f"Exact CP-SAT chromatic number on the {args.exact_sample} lowest-fanout candidates: "
        f"{dict(sorted(exact_dist.items()))}.",
        f"STRUCTURAL RULING: a K=4 per-position substitution requires a plaintext where every letter maps "
        f"to <=4 distinct K4 letters. The minimum any N1 candidate achieves is {min_fan}. Real English "
        f"(K1 plaintext) fanout vs a random target is {k1_fan}. => the true K4 plaintext (if K<=4) is "
        f"FAR more repetition-constrained than any natural-English N1 candidate -- strong evidence that "
        f"either the prior misses the real plaintext OR K4 is NOT a low-k per-position cipher.",
    ]
    write_verdict(out, Verdict(
        exp="055", title="CP-SAT chromatic / fanout structural filter on N1 candidates",
        hypothesis="K4 is a k-alphabet per-position substitution; candidate plaintexts with fanout>k are impossible",
        status="promising" if best else "ruled_out",
        best_score=round(best[0], 2) if best else None,
        best_partial=f"min fanout {min_fan}; {len(adm4)} candidates admissible at k<=4",
        search_space=len(cands), elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=["the fanout result is a HARD constraint on the true plaintext: search/generate ONLY "
                    "plaintexts with per-letter fanout<=4 against K4 (a strong new N1 filter); feed those to exp 054",
                    "if no plausible English has fanout<=4, that argues K4's masking is NOT per-position "
                    "substitution -- revisit transposition-composite families"],
        metrics={"fanout_distribution": {str(k): v for k, v in sorted(fan_dist.items())},
                 "min_fanout": min_fan, "best_plaintext": best[1] if best else None})
    )
    print(f"\nDone in {elapsed:.1f}s; min fanout {min_fan}; fanout<=4: {len(adm4)}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
