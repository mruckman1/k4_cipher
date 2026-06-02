"""049 — Weltzeituhr 24-column ordering as a TRANSPOSITION key.

exp 003 tested the Weltzeituhr only as a keystream source (ruled out).
But the clock's salient structural feature is a fixed, publicly-readable
PERMUTATION of 24 city columns ordered by UTC offset. Sanborn's Nov-2025
clarification specifically picked this clock. A columnar/route transposition
keyed by that 24-element order is a "technique not used in K1-K3", is
hand-executable ("stand at the clock, read the column order"), and Berlin
(col 14) and Cairo (col 15) sit ADJACENT -- linking K4's two thematic
anchors (Egypt 1986 + Berlin Wall) inside one structure.

We build several 24-element permutations from data/physical/weltzeituhr_zones.csv
(sort by utc_offset asc/desc, physical column index, boustrophedon) and run
the substitution-then-transposition KPA from exp 043 (de-transpose, re-pair
cribs, find a short consistent period, decrypt, hexagram-score, verify).

$0, local. Output: experiments/results/<date>_049_weltzeituhr_transposition.jsonl
"""

from __future__ import annotations

import csv
import json
import time
from datetime import date
from pathlib import Path

import numpy as np

import _kpa
from _verdict import Verdict, write_verdict

ZONES = Path("data/physical/weltzeituhr_zones.csv")


def load_orders() -> dict[str, tuple[int, ...]]:
    data_lines = [ln for ln in ZONES.read_text().splitlines() if ln and not ln.startswith("#")]
    rows = list(csv.DictReader(data_lines))
    # columns: column (1-24), utc_offset, city, zone_marker
    def col(r):
        return int(r["column"]) - 1
    def utc(r):
        return int(float(r["utc_offset"]))
    by_col = sorted(rows, key=col)
    n = len(by_col)
    orders: dict[str, tuple[int, ...]] = {}
    orders["physical_col"] = tuple(range(n))
    orders["physical_col_rev"] = tuple(range(n - 1, -1, -1))
    asc = sorted(range(n), key=lambda i: (utc(by_col[i]), i))
    orders["utc_offset_asc"] = tuple(asc)
    orders["utc_offset_desc"] = tuple(reversed(asc))
    # boustrophedon over physical columns
    bous = []
    rows_grid = [list(range(0, n))]
    # simple serpentine on the 24-vector split into rows of 6
    w = 6
    grid = [list(range(r * w, min((r + 1) * w, n))) for r in range((n + w - 1) // w)]
    for r, gr in enumerate(grid):
        bous.extend(gr[::-1] if r % 2 else gr)
    orders["boustrophedon6"] = tuple(bous)
    return orders


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_049_weltzeituhr_transposition.jsonl"
    orders = load_orders()
    t0 = time.perf_counter()
    print(f"Weltzeituhr 24-column orders: {list(orders)}")

    best_score, best_info, solved = -99.0, None, None
    total_decryptable = 0
    with open(out, "w") as f:
        for name, order in orders.items():
            perm = _kpa.col_permutation_full(len(order), order)
            res = _kpa.best_over_transposition(perm)
            total_decryptable += res["decryptable"]
            rec = {"order_name": name, "order": list(order),
                   "best_free_hex": res["best_score"], "min_L": res["min_L"],
                   "decryptable": res["decryptable"], "params": res["params"]}
            f.write(json.dumps(rec) + "\n")
            print(f"  {name:18} minL={res['min_L']} decryptable={res['decryptable']} "
                  f"best_free_hex={res['best_score']:.2f}")
            if res["best_score"] > best_score:
                best_score = res["best_score"]
                best_info = {"order_name": name, **(res["params"] or {}),
                             "plaintext": res["best_plaintext"]}

    elapsed = time.perf_counter() - t0
    status = "promising" if best_score > -16.0 else "ruled_out"
    insights = [
        f"Tested {len(orders)} physical Weltzeituhr column orders as transposition keys; "
        f"{total_decryptable} decryptable short-period pairings; best free-position hexagram "
        f"{best_score:.2f}/char.",
    ]
    if status == "ruled_out":
        insights.append("No Weltzeituhr-derived 24-column transposition re-pairs the cribs into a short "
                        "periodic substitution that decrypts to English. The clock order is not the "
                        "transposition key (consistent with exp 043's general columnar ruling).")
    write_verdict(out, Verdict(
        exp="049", title="Weltzeituhr 24-column order as transposition key",
        hypothesis="K4's masking step is a columnar transposition keyed by the Weltzeituhr UTC-column order",
        status=status, best_score=round(best_score, 2),
        best_partial=f"{total_decryptable} decryptable", search_space=len(orders),
        elapsed_s=round(elapsed, 1), solved_params=solved, insights=insights,
        next_steps=(["push best with free-slot hill-climb"] if status == "promising" else
                    ["try the clock order as an ALPHABET selection rule (24->k) rather than a transposition; "
                     "feed to exp 055 CP-SAT"]),
        metrics={"best": best_info})
    )
    print(f"\nDone in {elapsed:.1f}s; best {best_score:.2f}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
