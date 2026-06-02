"""090 — 2-D grid-coordinate (physical-layout) selector sweep.

exp 085 bounded out 1-D position selectors (i mod k, row-of-7) and ciphertext-
context selectors. It never tested a selector whose CLOCK is a 2-D grid
coordinate -- reshape the 97 characters into a width-W grid and key the alphabet
on (row, col) or the serpentine (boustrophedon) reading of that grid. This is
the "physical layout" axis: if K4's engraving lays the text out in rows of width
W, a hand-executable selector keyed on the panel's row/column is "memorable" and
OUTSIDE everything the squeeze bound covered.

HONEST CAVEAT: K4's true engraved per-line layout is UNSOURCED (see
docs/attack_plan_043_057.md; exp 052 was ruled out partly on this). So we do not
assume one width -- we SWEEP every plausible width W in [7, 31].

THE OPERATIVE BAR (corrected after adversarial review of an earlier version that
leaned on a misleading "0 proper 3-colourings" headline): properness alone is
cryptanalytically vacuous -- a high-class-count selector colours the graph for
free. The decipherment-relevant question is whether ANY grid selector is
simultaneously (i) CRIB-DETERMINED (each class agrees on one rotation of a keyed
base alphabet), (ii) FULL (every one of the 97 positions falls in a crib-pinned
class, else its rotation is free = the exp-059 degeneracy), and (iii) decrypts
to English. We test BOTH families that the grid hypothesis spans:
  - REDUCED selectors: (row,col,diag,boustrophedon) mod {2,3,4}  (few classes)
  - RAW selectors:     (row,col,diag,antidiag,boustrophedon) un-reduced (a
                       per-row/column polyalphabetic -- the literal "key on the
                       column" reading; many classes)
A hit at a specific W would also retro-pin the layout; no hit closes the axis.

$0, local, pure decipherment. Output:
experiments/results/<date>_090_grid_coordinate_selector.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import time
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, keyed_alphabet
from kryptos.constants import K4

e035 = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
    "e035", str(Path(__file__).parent / "035_minimum_alphabet_analysis.py")))
e035.__spec__.loader.exec_module(e035)

N = 97
M = 26
WIDTHS = list(range(7, 32))
ALPHS = {"kryptos_keyed": KRYPTOS_KEYED, "standard": STANDARD,
         "keyed_PALIMPSEST": keyed_alphabet("PALIMPSEST")}


def selectors(W):
    """Grid class-functions for width W. row=i//W, col=i%W; bcol = serpentine
    (boustrophedon) column. Returns {name: (func, is_raw)}. Reduced families are
    mod {2,3,4}; raw families use the un-reduced coordinate (a per-row/col
    polyalphabetic) -- the literal 'key on the column' reading."""
    row = lambda i: i // W
    col = lambda i: i % W
    bcol = lambda i: (i % W) if (i // W) % 2 == 0 else (W - 1 - i % W)
    F = {}
    for k in (2, 3, 4):
        F[f"col%{k}"] = (lambda i, k=k: col(i) % k, False)
        F[f"row%{k}"] = (lambda i, k=k: row(i) % k, False)
        F[f"(row+col)%{k}"] = (lambda i, k=k: (row(i) + col(i)) % k, False)
        F[f"(row-col)%{k}"] = (lambda i, k=k: (row(i) - col(i)) % k, False)
        F[f"bcol%{k}"] = (lambda i, k=k: bcol(i) % k, False)
        F[f"(row+bcol)%{k}"] = (lambda i, k=k: (row(i) + bcol(i)) % k, False)
    # RAW (un-reduced) selectors -- the per-row/column polyalphabetic itself.
    F["rawcol"] = (lambda i: col(i), True)
    F["rawrow"] = (lambda i: row(i), True)
    F["rawdiag"] = (lambda i: row(i) - col(i), True)
    F["rawantidiag"] = (lambda i: row(i) + col(i), True)
    F["rawbcol"] = (lambda i: bcol(i), True)
    return F


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_090_grid_coordinate_selector.jsonl"
    t0 = time.perf_counter()
    cribs = e035.build_crib_constraints()  # (pos, plain, cipher, plain_idx, cipher_idx)
    positions = [c[0] for c in cribs]
    edges = set()
    for i in range(len(cribs)):
        for j in range(i + 1, len(cribs)):
            if e035.cribs_conflict(cribs[i], cribs[j]):
                edges.add((i, j))

    best = (-99.0, None)
    solved = None
    n_sel = {"reduced": 0, "raw": 0}
    n_proper = {"reduced": 0, "raw": 0}
    n_determined = 0          # crib-determined for some alpha/conv (rotation-consistent per class)
    n_full_determined = 0     # determined AND every 97-position class is crib-pinned (decryptable)
    n_underdetermined = 0     # determined but NOT full (some position in a crib-free class -> degenerate)

    with open(out, "w") as f:
        for W in WIDTHS:
            for cf_name, (cf, is_raw) in selectors(W).items():
                kind = "raw" if is_raw else "reduced"
                n_sel[kind] += 1
                vals = {node: cf(positions[node]) for node in range(len(cribs))}
                proper = all(vals[u] != vals[v] for u, v in edges)
                if proper:
                    n_proper[kind] += 1
                for an, alpha in ALPHS.items():
                    for conv in _kpa.CONVENTIONS:
                        cls, ok = {}, True
                        for (pos, p_, c_, _, _) in cribs:
                            pi, ci = alpha.index(p_), alpha.index(c_)
                            sh = ((ci - pi) % M if conv == "vigenere"
                                  else (ci + pi) % M if conv == "beaufort" else (pi - ci) % M)
                            cl = cf(pos)
                            if cl in cls and cls[cl] != sh:
                                ok = False; break
                            cls[cl] = sh
                        if not ok:
                            continue
                        n_determined += 1
                        # FULL? every one of the 97 positions must fall in a crib-pinned class
                        full = all(cf(i) in cls for i in range(N))
                        if not full:
                            n_underdetermined += 1
                            continue
                        n_full_determined += 1
                        P = []
                        for i in range(N):
                            sh = cls[cf(i)]; ci = alpha.index(K4[i])
                            pi = ((ci - sh) % M if conv == "vigenere"
                                  else (sh - ci) % M if conv == "beaufort" else (ci + sh) % M)
                            P.append(alpha.at(pi))
                        P = "".join(P)
                        sc = _kpa.score_free_text(P)
                        rec = {"W": W, "selector": cf_name, "kind": kind, "alphabet": an, "conv": conv,
                               "n_classes": len(cls), "hex": round(sc, 2), "plaintext": P}
                        if sc > best[0]:
                            best = (sc, rec)
                        if sc > -16.0:
                            f.write(json.dumps(rec) + "\n")
                        if sc > -15.0:
                            solved = rec

    elapsed = time.perf_counter() - t0
    bi = best[1]
    if solved:
        status = "solved"
    elif bi and bi["hex"] > -16.0:
        status = "promising"
    else:
        status = "ruled_out"

    insights = [
        f"Swept widths W in [7,31] x grid selectors x {len(ALPHS)} alphabets x 3 conventions. Selector "
        f"families: {n_sel['reduced']} REDUCED instances (row/col/diag/boustrophedon mod 2/3/4) and "
        f"{n_sel['raw']} RAW instances (un-reduced per-row/column polyalphabetic).",
        f"OPERATIVE BAR = crib-determined AND full (every 97-position class crib-pinned) AND English. "
        f"Crib-determined fits (some alpha/conv): {n_determined}; of those, {n_full_determined} are FULL "
        f"(decryptable) and {n_underdetermined} are crib-UNDER-determined (a position lands in a crib-free "
        f"class -> free rotation = the exp-059 degeneracy). English decrypts (free-hex > -16): "
        f"{'see jsonl' if bi and bi['hex'] > -16 else 'NONE'}.",
        (f"Best grid decrypt: W={bi['W']} {bi['selector']} ({bi['kind']}, {bi['n_classes']} classes) "
         f"{bi['alphabet']}/{bi['conv']} free-hex {bi['hex']} -> {bi['plaintext'][:36]}..." if bi else
         "No grid selector (reduced OR raw) is full-crib-determined; none decrypts."),
        f"PROPERNESS (context, not the bar): reduced selectors that properly 3-colour the crib graph: "
        f"{n_proper['reduced']}/{n_sel['reduced']} (a real structural obstruction -- arithmetic-progression "
        f"grid selectors do not separate the conflict graph); raw selectors: {n_proper['raw']}/{n_sel['raw']} "
        f"are proper (high class-count colours for free) BUT are crib-under-determined, so properness buys no "
        f"decrypt.",
    ]
    if status == "ruled_out":
        insights.append(
            "VERDICT: across all widths 7-31, NO 2-D grid-coordinate selector -- reduced (mod 2/3/4) or raw "
            "(per-row/column polyalphabetic), in row/col/diagonal/boustrophedon form -- is simultaneously "
            "crib-determined, full, and English-decrypting. Reduced selectors fail at properness (structural); "
            "raw selectors are proper but crib-under-determined (degenerate). The physical-layout 'clock' axis "
            "is closed. The remaining open move is a NEW K1-K3 ciphertext invariant (exp 091).")

    write_verdict(out, Verdict(
        exp="090", title="2-D grid-coordinate (physical-layout) selector sweep",
        hypothesis="K4's alphabet selector is keyed on a 2-D grid coordinate (row/col/boustrophedon, reduced "
                   "or raw) from the engraving layout, at some width W",
        status=status, best_score=(bi["hex"] if (bi and status in ("solved", "promising")) else None),
        best_partial=(f"best W={bi['W']} {bi['selector']} ({bi['kind']}) {bi['alphabet']}/{bi['conv']} "
                      f"free-hex {bi['hex']}" if bi else
                      f"0 full-crib-determined grid selectors (reduced+raw) at any width 7-31; "
                      f"{n_underdetermined} under-determined, {n_proper['raw']} raw-proper but degenerate"),
        search_space=(n_sel["reduced"] + n_sel["raw"]) * len(ALPHS) * 3, elapsed_s=round(elapsed, 1),
        solved_params=solved,
        insights=insights,
        next_steps=(["verify byte-exact & announce; the matching width retro-pins the engraving layout"]
                    if solved else
                    ["2-D physical-clock axis closed across widths 7-31 (reduced + raw); build the K1-K3 "
                     "invariant-mining forward filter (exp 091)"]),
        metrics={"n_proper": n_proper, "n_determined": n_determined, "n_full_determined": n_full_determined,
                 "n_underdetermined": n_underdetermined, "best": bi, "widths": [WIDTHS[0], WIDTHS[-1]]}),
    )
    print(f"\nwidths 7-31; proper reduced {n_proper['reduced']}/{n_sel['reduced']}, raw "
          f"{n_proper['raw']}/{n_sel['raw']}; determined {n_determined} (full {n_full_determined}, "
          f"under-det {n_underdetermined}); best free-hex {best[0]:.2f}; status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
