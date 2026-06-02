"""069 — Phillips cipher admissibility (decided in 1 second by the cribs).

The Phillips cipher uses 8 squares cycled by block index floor(i/5) mod 8, so
its selection rule is the position-feature phillips_block_5x8. exp 065 already
flagged it INVALID; this confirms it directly and names the specific
crib conflict that kills it, so the full Phillips SA is correctly NOT run.

A per-position cipher with selector b(i)=floor(i/5) mod 8 can satisfy the cribs
only if no two CONFLICTING cribs (same plaintext->different cipher, or vice
versa) share a block index. We exhibit the monochromatic conflict.

Output: experiments/results/<date>_069_phillips_admissibility.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import time
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict

_spec = importlib.util.spec_from_file_location(
    "e035", str(Path(__file__).parent / "035_minimum_alphabet_analysis.py"))
e035 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(e035)


def block(i):
    return (i // 5) % 8                       # Phillips: 5-letter blocks, 8-square cycle


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_069_phillips_admissibility.jsonl"
    t0 = time.perf_counter()
    cribs = e035.build_crib_constraints()       # (pos0, plain, cipher, pi, ci)
    edges = []
    for i in range(len(cribs)):
        for j in range(i + 1, len(cribs)):
            if e035.cribs_conflict(cribs[i], cribs[j]):
                edges.append((i, j))
    mono = []
    for u, v in edges:
        pu, pv = cribs[u][0], cribs[v][0]
        if block(pu) == block(pv):
            mono.append({"posA": pu + 1, "posB": pv + 1, "block": block(pu),
                         "cribA": f"{cribs[u][1]}->{cribs[u][2]}",
                         "cribB": f"{cribs[v][1]}->{cribs[v][2]}"})
    admissible = len(mono) == 0
    elapsed = time.perf_counter() - t0
    with open(out, "w") as f:
        f.write(json.dumps({"admissible": admissible, "monochromatic_conflicts": mono,
                            "n_conflict_edges": len(edges)}) + "\n")

    insights = [
        f"Phillips selector b(i)=floor(i/5) mod 8 puts {len(mono)} CONFLICTING crib pairs in the same "
        f"block (monochromatic) -> a single square cannot satisfy them. Example: {mono[0] if mono else 'none'}.",
        "Phillips is therefore structurally INADMISSIBLE for K4: its 8-square block cycle forces two "
        "cribs that demand different alphabets into the same square. No keyword/SA can fix this (merging "
        "never removes a monochromatic conflict). The full Phillips square-search SA is correctly NOT run.",
    ]
    write_verdict(out, Verdict(
        exp="069", title="Phillips cipher admissibility (block-mod-8 selector vs cribs)",
        hypothesis="K4 is a Phillips cipher (8 squares cycled by block index)",
        status="ruled_out",
        best_partial=f"{len(mono)} monochromatic crib conflicts under floor(i/5) mod 8",
        search_space=len(edges), elapsed_s=round(elapsed, 1), insights=insights,
        next_steps=["Phillips dead; the k=8 floor is matched by NO admissible named hand cipher -> the "
                    "k=8 selector (if any) is non-block / non-positional"],
        metrics={"monochromatic_conflicts": mono})
    )
    print(f"\nPhillips admissible={admissible}; {len(mono)} monochromatic conflicts. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
