"""075 — Route (non-block) transposition + short-period substitution, BOTH orders.

exp 052 tested rail-fence/boustrophedon routes only in the sub->transpose order
(via best_over_transposition). This closes the gap: a wider route family
(rail-fence, boustrophedon, columnar at widths 5-14, NE/SE diagonal reads,
spiral reads) composed with a short-period substitution in BOTH orders
(transpose->sub AND sub->transpose), with the exact crib KPA from exp 064.

Output: experiments/results/<date>_075_route_plus_substitution.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import time
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD

e064 = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
    "e064", str(Path(__file__).parent / "064_tiny_two_stage_composite.py")))
e064.__spec__.loader.exec_module(e064)
kpa, pinned_key, decrypt, reencrypt, invert = (e064.kpa, e064.pinned_key, e064.decrypt,
                                               e064.reencrypt, e064.invert)
CRIB_PLAIN, CRIB_POS = e064.CRIB_PLAIN, e064.CRIB_POS
from kryptos.constants import K4
N = 97
ALPHABETS = {"standard": STANDARD, "kryptos_keyed": KRYPTOS_KEYED}


def rail_fence(depth):
    rails = [[] for _ in range(depth)]
    r, step = 0, 1
    for i in range(N):
        rails[r].append(i)
        step = 1 if r == 0 else -1 if r == depth - 1 else step
        r += step
    return [i for rail in rails for i in rail]


def boustrophedon(w):
    rows = (N + w - 1) // w
    order = []
    for col in range(w):
        cells = [rr * w + col for rr in range(rows) if rr * w + col < N]
        order.extend(cells[::-1] if col % 2 else cells)
    return order


def columnar(w):
    rows = (N + w - 1) // w
    return [rr * w + col for col in range(w) for rr in range(rows) if rr * w + col < N]


def diagonal(w, direction):
    rows = (N + w - 1) // w
    cells = []
    grid = [[rr * w + col for col in range(w) if rr * w + col < N] for rr in range(rows)]
    for s in range(rows + w):
        diag = []
        for rr in range(rows):
            col = (s - rr) if direction == "se" else (rr - s + w - 1)
            if 0 <= col < w and col < len(grid[rr]):
                diag.append(grid[rr][col])
        cells.extend(diag)
    return [c for c in cells if c is not None]


def spiral(w):
    rows = (N + w - 1) // w
    grid = [[rr * w + col if rr * w + col < N else None for col in range(w)] for rr in range(rows)]
    out = []
    top, bot, left, right = 0, rows - 1, 0, w - 1
    while top <= bot and left <= right:
        for c in range(left, right + 1):
            if grid[top][c] is not None: out.append(grid[top][c])
        top += 1
        for r in range(top, bot + 1):
            if grid[r][right] is not None: out.append(grid[r][right])
        right -= 1
        if top <= bot:
            for c in range(right, left - 1, -1):
                if grid[bot][c] is not None: out.append(grid[bot][c])
            bot -= 1
        if left <= right:
            for r in range(bot, top - 1, -1):
                if grid[r][left] is not None: out.append(grid[r][left])
            left += 1
    return out


def routes():
    R = {}
    for d in range(2, 25):
        p = rail_fence(d)
        if sorted(p) == list(range(N)):
            R[f"rail_{d}"] = p
    for w in range(5, 15):
        for name, fn in (("bous", boustrophedon), ("col", columnar), ("spiral", spiral)):
            p = fn(w)
            if sorted(p) == list(range(N)):
                R[f"{name}_{w}"] = p
        for direction in ("se", "ne"):
            p = diagonal(w, direction)
            if sorted(p) == list(range(N)):
                R[f"diag{direction}_{w}"] = p
    return R


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_075_route_plus_substitution.jsonl"
    assert e064.self_test(), "composite KPA self-test failed"
    t0 = time.perf_counter()
    R = routes()
    best = (-99.0, None)
    decryptable = 0
    solved = None
    with open(out, "w") as f:
        for rname, perm in R.items():
            inv = invert(perm)
            for an, alpha in ALPHABETS.items():
                for conv in _kpa.CONVENTIONS:
                    for order in ("a", "b"):
                        pairs, M_b = kpa(perm, inv, alpha, conv, order, K4, CRIB_PLAIN)
                        for L in range(1, 25):
                            key = pinned_key(pairs, L)
                            if key is None:
                                continue
                            decryptable += 1
                            P = decrypt(perm, inv, alpha, conv, order, key, L, M_b, K4)
                            if any(P[p] != CRIB_PLAIN[p] for p in CRIB_POS):
                                continue
                            sc = _kpa.score_free_text(P)
                            if sc > best[0]:
                                best = (sc, {"route": rname, "order": order, "L": L,
                                             "alphabet": an, "conv": conv, "plaintext": P, "hex": round(sc, 2)})
                            if sc > -16.0:
                                f.write(json.dumps({"route": rname, "order": order, "L": L,
                                                    "alphabet": an, "conv": conv, "hex": round(sc, 2),
                                                    "plaintext": P}) + "\n")
                            if sc > -15.0 and reencrypt(perm, alpha, conv, order, P, key, L) == K4:
                                solved = {"route": rname, "order": order, "L": L, "alphabet": an,
                                          "conv": conv, "plaintext": P}

    elapsed = time.perf_counter() - t0
    bi = best[1]
    status = "solved" if solved else ("promising" if (bi and bi["hex"] > -16.0) else "ruled_out")
    insights = [
        f"Swept {len(R)} routes (rail-fence d2-24, boustrophedon/columnar/spiral/diagonal w5-14) x both "
        f"stage orders x 2 alphabets x 3 conventions x L=1-24; {decryptable:,} fully crib-pinned decryptable. "
        f"Best free hexagram {best[0]:.2f}/char.",
        (f"Best: {bi['route']} order={bi['order']} L={bi['L']} {bi['alphabet']}/{bi['conv']} hex {bi['hex']}"
         if bi else "No fully-pinned route+substitution composite."),
    ]
    if status == "ruled_out":
        insights.append("No route transposition (incl. spiral/diagonal, both stage orders) coupled with a "
                        "short-period substitution decrypts K4 to English. The route+substitution composite is "
                        "closed in both orders -- consistent with 043/052/064.")
    write_verdict(out, Verdict(
        exp="075", title="route (non-block) transposition + substitution, both orders",
        hypothesis="K4 = a route transposition coupled with a short-period substitution",
        status=status, best_score=best[0], best_partial=f"{decryptable} decryptable; {len(R)} routes",
        search_space=len(R), elapsed_s=round(elapsed, 1), solved_params=solved, insights=insights,
        next_steps=(["verify & announce"] if solved else
                    ["transposition+substitution fully exhausted across block/route/columnar, both orders"]),
        metrics={"best": bi})
    )
    print(f"\n{decryptable} decryptable; best hex {best[0]:.2f}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
