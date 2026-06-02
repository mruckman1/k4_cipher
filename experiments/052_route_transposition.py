"""052 — Ragged / route transposition (rail-fence, zigzag, ragged rows).

Idea #14 was "write K4 into its actual engraved line lengths and read by
columns". The exact per-line layout of the K4 panel could not be verified
to the character this session, so we test the honest, fabrication-free
CORE of the idea: NON-rectangular, length-preserving route transpositions
that every prior sweep (uniform columnar widths 3-10) skipped --

  - rail-fence (zigzag) at depths 2-24,
  - ragged-row layouts (write into rows of width w, read columns, but with
    the short last row handled as a true ragged grid -- already covered by
    043's irregular columnar, so here we add the genuinely new rail/route
    geometries),
  - simple route reads (spiral-ish boustrophedon at several widths).

Each route gives a length-97 permutation fed to the exp-043
de-transpose -> short-period KPA -> decrypt -> hexagram pipeline.

To slot in the REAL engraving layout: append its column permutation to
ROUTES and re-run.

$0, local. Output: experiments/results/<date>_052_route_transposition.jsonl
"""

from __future__ import annotations

import json
import time
from datetime import date

import numpy as np

import _kpa
from _verdict import Verdict, write_verdict

N = 97


def rail_fence_perm(depth: int) -> np.ndarray:
    """Zigzag write across `depth` rails, read row by row. perm[k] = input
    index of the k-th read cell."""
    rails = [[] for _ in range(depth)]
    r, step = 0, 1
    for i in range(N):
        rails[r].append(i)
        if r == 0:
            step = 1
        elif r == depth - 1:
            step = -1
        r += step
    order = [i for rail in rails for i in rail]
    return np.array(order, dtype=np.int32)


def boustrophedon_perm(width: int) -> np.ndarray:
    rows = (N + width - 1) // width
    order = []
    for col in range(width):
        col_cells = [row * width + col for row in range(rows) if row * width + col < N]
        if col % 2 == 1:
            col_cells = col_cells[::-1]
        order.extend(col_cells)
    return np.array(order, dtype=np.int32)


def ragged_columnar_perm(line_lengths, n=N) -> np.ndarray:
    """Write K4 into ragged rows (row r has line_lengths[r] cells), read by
    columns top-to-bottom, left-to-right. perm[k] = source index of k-th cell."""
    assert sum(line_lengths) == n, f"line lengths sum to {sum(line_lengths)}, need {n}"
    rows, pos = [], 0
    for L in line_lengths:
        rows.append(list(range(pos, pos + L)))
        pos += L
    width = max(line_lengths)
    order = [row[col] for col in range(width) for row in rows if col < len(row)]
    return np.array(order, dtype=np.int32)


# K4's physical engraving on Panel 2 (Elonka transcript + Wikipedia, verified
# 2026-05-28): K4 = "OBKR" (tail of K3's last engraved row "...VDOHW?OBKR")
# then three rows of 31. NOTE: OBKR shares its physical row with K3 text, so
# [4,31,31,31] models K4 transposed within its own line-spans (a choice, not a
# pure whole-panel transposition). Sum = 97.
K4_LINE_LENGTHS = [4, 31, 31, 31]


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_052_route_transposition.jsonl"
    routes: dict[str, np.ndarray] = {}
    for d in range(2, 25):
        routes[f"railfence_d{d}"] = rail_fence_perm(d)
    for w in range(3, 25):
        routes[f"boustrophedon_w{w}"] = boustrophedon_perm(w)
    # verified physical K4 engraving layout (Elonka/Wikipedia)
    routes["engraved_K4_4_31_31_31"] = ragged_columnar_perm(K4_LINE_LENGTHS)
    routes["engraved_K4_4_31_31_31_rev"] = ragged_columnar_perm(K4_LINE_LENGTHS)[::-1]

    t0 = time.perf_counter()
    best_score, best_info, solved = -99.0, None, None
    total_decryptable = 0
    with open(out, "w") as f:
        for name, perm in routes.items():
            # sanity: perm must be a permutation of 0..96
            if sorted(perm.tolist()) != list(range(N)):
                continue
            res = _kpa.best_over_transposition(perm)
            total_decryptable += res["decryptable"]
            f.write(json.dumps({"route": name, "best_free_hex": res["best_score"],
                                "min_L": res["min_L"], "decryptable": res["decryptable"],
                                "params": res["params"]}) + "\n")
            if res["best_score"] > best_score:
                best_score = res["best_score"]
                best_info = {"route": name, **(res["params"] or {}),
                             "plaintext": res["best_plaintext"]}

    elapsed = time.perf_counter() - t0
    status = "promising" if best_score > -16.0 else "ruled_out"
    insights = [
        f"Tested {len(routes)} non-rectangular route transpositions (rail-fence d2-24, boustrophedon "
        f"w3-24, AND the verified physical K4 engraving layout [4,31,31,31] fwd+rev); "
        f"{total_decryptable} decryptable short-period pairings; best free hexagram {best_score:.2f}/char.",
    ]
    if status == "ruled_out":
        insights.append("No route -- including the VERIFIED K4 engraved line layout (OBKR + 3x31, from the "
                        "Elonka/Wikipedia transcript) -- re-pairs the cribs into a short periodic substitution "
                        "that decrypts to English. The engraving-as-transposition hypothesis is now CLOSED "
                        "(no longer data-blocked). Consistent with 043/049: route geometry is not K4's masking.")
    write_verdict(out, Verdict(
        exp="052", title="rail-fence / route / engraved-layout transposition masking",
        hypothesis="K4's masking is a non-rectangular route transposition (incl. the physical engraving layout)",
        status=status, best_score=round(best_score, 2),
        best_partial=f"{total_decryptable} decryptable; engraving [4,31,31,31] tested", search_space=len(routes),
        elapsed_s=round(elapsed, 1), solved_params=solved, insights=insights,
        next_steps=["engraving layout now closed; whole-panel transposition (K3 tail + K4 sharing rows) "
                    "remains the only untested geometric variant -- low prior"],
        metrics={"best": best_info})
    )
    print(f"\nTested {len(routes)} routes in {elapsed:.1f}s; best {best_score:.2f}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
