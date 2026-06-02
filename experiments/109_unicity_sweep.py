"""109 — Unicity sensitivity sweep over the redundancy D, and Antipodes note.

exp 092 used a single measured prose redundancy D=3.62; exp 097 measured a
telegraphic D_tele=4.0. The review's sharpest (non-K5) attack on the unicity
conclusion is that D is genre-dependent and a higher D (terse/topical register)
makes K4 MORE solvable. This makes the dependence explicit: re-derive the
hand-crafted-alphabet under-determination crossover for D across [3.4, 4.3], and
report the k=4 margin per D and the crossover k per D, so the conclusion's
sensitivity is on the record.

(Antipodes byte-level transcription diff: SKIPPED -- data/ciphertexts/antipodes.txt
is an un-populated placeholder; no verified Antipodes K4 transcription is on disk
to diff against, so the 101-flagged two-letter variants cannot be cross-checked
here. Documented honestly rather than fabricated.)

$0, local, deterministic. Output: experiments/results/<date>_109_unicity_sweep.jsonl
"""

from __future__ import annotations

import json
import math
import time
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict

R0 = math.log2(26)
N, CRIBS_KNOWN, FREE = 97, 24, 73
LOG2_26FACT = sum(math.log2(i) for i in range(2, 27))   # 88.38
SELECTOR_BITS = 6.0
FLATTEN_FLOOR = 4   # k* from exp 085


def pinned_bits(m):
    m = min(int(round(m)), 26)
    return sum(math.log2(26 - j) for j in range(m))


def crossover_for_D(D):
    rows = []
    cross = None
    for k in range(1, 7):
        HK = k * LOG2_26FACT + (SELECTOR_BITS if k > 1 else 0.0)
        residual = max(0.0, HK - k * pinned_bits(CRIBS_KNOWN / k))
        gap = residual - FREE * D   # >0 => under-determined
        rows.append((k, round(gap, 1)))
        if cross is None and gap > 0:
            cross = k
    k4gap = dict(rows)[4]
    return cross, k4gap, rows


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_109_unicity_sweep.jsonl"
    t0 = time.perf_counter()

    Ds = [round(3.4 + 0.1 * i, 1) for i in range(10)]   # 3.4 .. 4.3
    sweep = []
    for D in Ds:
        cross, k4gap, rows = crossover_for_D(D)
        sweep.append({"D": D, "crossover_k": cross, "k4_gap_bits": k4gap,
                      "k4_determined": k4gap <= 0, "gaps": rows})

    elapsed = time.perf_counter() - t0
    # at every D in the plausible English range, where is the crossover?
    crossovers = {s["D"]: s["crossover_k"] for s in sweep}
    k4_always_determined = all(s["k4_determined"] for s in sweep)
    crossover_ever_le_flatten = any((s["crossover_k"] or 99) <= FLATTEN_FLOOR for s in sweep)

    with open(out, "w") as f:
        f.write(json.dumps({"D_sweep": sweep, "crossover_by_D": crossovers,
                            "k4_determined_for_all_D": k4_always_determined,
                            "crossover_at_or_below_flatten_floor_for_any_D": crossover_ever_le_flatten,
                            "antipodes_diff": "skipped (placeholder data, no verified transcription)"}) + "\n")

    insights = [
        f"Unicity sensitivity over D in [3.4, 4.3] (Shannon's English-redundancy range). Hand-crafted-alphabet "
        f"under-determination crossover k by D: {crossovers}. The crossover is k=5 for D>=3.5 and drops to k=4 "
        f"only at the extreme low end D=3.4. For ALL MEASURED redundancies -- prose D=3.62 (exp 092) and "
        f"telegraphic D=4.0 (exp 097) -- the crossover is k=5.",
        f"k=4 margin (gap bits, negative=determined) by D: "
        f"{[(s['D'], s['k4_gap_bits']) for s in sweep]}. Higher D makes k=4 MORE determined (the review is "
        f"right that a terse/topical register helps solvability) -- and it moves the crossover UP, not down, so "
        f"the review's 'may not survive D>=4.0' is INCORRECT: at D=4.0 the crossover is k=5 (conclusion holds). "
        f"The only sensitivity is at the lowest D=3.4, where the crossover touches the flatten floor k*=4. So "
        f"for realistic English D the conclusion is ROBUST: at k>=5 K4 is under-determined, and at k=4 it is "
        f"analytically determined yet empirically degenerate (093) -- the analytic-vs-n-gram-realisability gap "
        f"the prior must close (108), not the redundancy estimate.",
        "ANTIPODES DIFF: skipped -- data/ciphertexts/antipodes.txt is an un-populated placeholder, so the "
        "101-flagged two-letter transcription variants cannot be cross-checked against an Antipodes rubbing "
        "here. (Honest gap, not a result.)",
    ]

    write_verdict(out, Verdict(
        exp="109", title="unicity sensitivity sweep over redundancy D (+ Antipodes note)",
        hypothesis="a higher genre-specific redundancy D flips K4's under-determination crossover below the "
                   "flatten floor, making the public data sufficient",
        status="ruled_out",   # the sensitivity does NOT flip the conclusion
        best_partial=f"crossover k=5 for D>=3.5 (incl. measured 3.62 & 4.0), k=4 only at D=3.4; review's "
                     f"'D>=4.0 flips it' is false; conclusion robust for realistic D",
        search_space=len(Ds), elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=["the unicity conclusion is robust to D in the full English range; the residual gap is "
                    "analytic-determinacy-vs-n-gram-realisability at k=4 (exp 108), not the redundancy estimate"],
        metrics={"crossover_by_D": crossovers, "k4_determined_for_all_D": k4_always_determined,
                 "crossover_le_flatten_any_D": crossover_ever_le_flatten}),
    )
    print(f"\ncrossover by D: {crossovers}; never<=4: {not crossover_ever_le_flatten}; "
          f"antipodes skipped (placeholder). -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
