"""127 — Engraving-layout selector under the VERIFIED continuous-panel geometry
(the variant 052/090/126 missed).

Web verification (2026-05-30) of the canonical Elonka/Doug-Gwyn transcript showed
the repo's [4,31,31,31] "standalone block" framing is WRONG: K4's first 4 chars
(OBKR) are the LAST 4 columns (27-30) of the 31-wide transcript row that ENDS K3
(...DOHW?OBKR); the remaining 93 chars then fill three full rows of 31. So K4 does
NOT start at column 0 of its own block -- it is OFFSET by 27 columns into a row
shared with K3. 126 swept row/column parities but treated K4 as a standalone block
starting at column 0, never applying this offset. This re-tests the engraving-grid
selector hypothesis with the CORRECTED panel geometry: position i -> (row, col)
under OBKR-at-end-of-row, then binary masks (column parity/half, row parity with
phase, checkerboard) tested in the homophonic 2-colouring model + decrypt vs the
random-selector null. Widths swept W in 29-33 (physical copper rows vary; "31" is a
transcript-grid width, not a measured fact -- see exp 104 correction).

HONEST SCOPE: this rests on a TRANSCRIPT convention, not a measured physical
engraving layout (none is publicly certified). A hit is a lead pending physical
confirmation; a null closes the verified-geometry engraving-column-selector family.

$0, local, deterministic, no LLM, no K5, no plaintext. Output:
experiments/results/<date>_127_engraving_selector_corrected.jsonl
"""

from __future__ import annotations

import json
import math
import random
import time
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K4
from kryptos.cribs import CRIBS

A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CRIB = [(c.start - 1 + off, p, ch)
        for c in CRIBS for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext))]
N = len(CRIB)
CRIB_POS = {pos for pos, _, _ in CRIB}
FREE = [i for i in range(97) if i not in CRIB_POS]
ENGLISH_BAR = -15.0
B_EDGES = [(i, j) for i in range(N) for j in range(i + 1, N)
           if CRIB[i][2] == CRIB[j][2] and CRIB[i][1] != CRIB[j][1]]


def panel_coords(i, W, lead=4):
    """Verified geometry: K4's first `lead` chars (OBKR) are the LAST `lead` columns
    of row 0 (the row that ends K3); the rest fill rows of width W from row 1, col 0."""
    if i < lead:
        return 0, (W - lead) + i
    k = i - lead
    return 1 + k // W, k % W


def build_masks():
    masks = {}
    for W in range(29, 34):
        rc = [panel_coords(i, W) for i in range(97)]
        masks[f"col_parity_W{W}"] = [c % 2 for _r, c in rc]
        masks[f"col_half_W{W}"] = [1 if c >= W // 2 else 0 for _r, c in rc]
        masks[f"row_parity_ph0_W{W}"] = [r % 2 for r, _c in rc]
        masks[f"row_parity_ph1_W{W}"] = [(r + 1) % 2 for r, _c in rc]
        masks[f"checker_W{W}"] = [(r + c) % 2 for r, c in rc]
        masks[f"col_third_W{W}"] = [1 if c >= W - W // 3 else 0 for _r, c in rc]
    return masks


def two_colours(mask):
    return all(mask[CRIB[i][0]] != mask[CRIB[j][0]] for i, j in B_EDGES)


def decrypt_score(mask, rng, restarts=10, steps=2000):
    pins = {0: {}, 1: {}}
    for pos, p, ch in CRIB:
        pins[mask[pos]][ch] = p
    free_ciphers = {c: [X for X in A if X not in pins[c]] for c in (0, 1)}
    best = -99.0
    for _ in range(restarts):
        chart = {c: dict(pins[c]) for c in (0, 1)}
        for c in (0, 1):
            for X in free_ciphers[c]:
                chart[c][X] = rng.choice(A)
        dec = lambda: "".join(chart[mask[i]][K4[i]] for i in range(97))
        cur = _kpa.score_free_text(dec())
        for s in range(steps):
            T = 0.5 * (0.01 / 0.5) ** (s / steps)
            c = rng.randrange(2)
            if not free_ciphers[c]:
                continue
            X = rng.choice(free_ciphers[c]); old = chart[c][X]; nw = rng.choice(A)
            if nw == old:
                continue
            chart[c][X] = nw
            cand = _kpa.score_free_text(dec())
            if cand >= cur or rng.random() < math.exp((cand - cur) / max(T, 1e-6)):
                cur = cand
            else:
                chart[c][X] = old
        best = max(best, _kpa.score_free_text(dec()))
    return best


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_127_engraving_selector_corrected.jsonl"
    rng = random.Random(0)
    t0 = time.perf_counter()

    masks = build_masks()
    n_masks = len(masks)
    passers = [name for name, m in masks.items() if two_colours(m)]

    best_pass = (-99.0, None)
    pass_results = {}
    for name in passers:
        sc = decrypt_score(masks[name], rng)
        pass_results[name] = round(sc, 2)
        if sc > best_pass[0]:
            best_pass = (sc, name)
    null_best = -99.0
    npass = tries = 0
    while npass < 8 and tries < 4000:
        tries += 1
        rm = [rng.randrange(2) for _ in range(97)]
        if two_colours(rm):
            npass += 1
            null_best = max(null_best, decrypt_score(rm, rng, restarts=5, steps=1200))

    # sanity: confirm the geometry reassembles K4 and OBKR sits at cols 27-30 for W=31
    geo_ok = all(panel_coords(i, 31)[1] == 27 + i for i in range(4)) and panel_coords(4, 31) == (1, 0)

    elapsed = time.perf_counter() - t0
    signal = best_pass[1] is not None and best_pass[0] >= ENGLISH_BAR and best_pass[0] > null_best + 1.0
    status = "promising" if signal else "ruled_out"

    with open(out, "w") as f:
        f.write(json.dumps({
            "geometry": "verified continuous-panel: OBKR at cols W-4..W-1 of K3's last row, then rows of W",
            "geometry_self_check_W31": geo_ok, "widths_swept": list(range(29, 34)),
            "n_masks": n_masks, "mask_budget_N_max": 52, "n_passers": len(passers), "passers": passers,
            "passer_results": pass_results, "best_pass_hex": round(best_pass[0], 2),
            "best_pass_mask": best_pass[1], "random_null_hex": round(null_best, 2),
            "english_bar": ENGLISH_BAR, "signal": signal,
            "scope": "rests on a TRANSCRIPT convention (W~31), NOT a measured physical engraving layout; "
                     "no certified per-line copper layout is publicly published"}) + "\n")

    insights = [
        f"Geometry self-check (W=31): OBKR maps to columns 27-30 of row 0 and K4[4] to (row1,col0): {geo_ok}. "
        f"This is the CORRECTED continuous-panel layout 052/090/126 missed (they put K4 at column 0). Swept "
        f"{n_masks} binary masks (column parity/half/third, row parity x2 phases, checkerboard) over widths "
        f"29-33.",
        f"{len(passers)} of {n_masks} masks properly 2-COLOUR the b-graph: {passers or 'NONE'}. "
        + (f"Best passer decrypt {best_pass[0]:.2f} ({best_pass[1]}) vs random-selector null {null_best:.2f}. "
           + ("SIGNAL: a corrected-geometry engraving selector beats the null -- inspect/verify (and seek a "
              "physical-layout confirmation)." if signal else
              "no passer beats the null (the 116/122 degeneracy: hill-climbing free cells reaches the floor under "
              "any 2-colouring selector).") if passers else
           "NO corrected-geometry engraving selector 2-colours the cribs either -- the offset OBKR / continuous-"
           "panel framing does not rescue the engraving-grid hypothesis that 126 closed for the standalone "
           "framing. The chart selector is not a row/column parity of the engraving grid under EITHER geometry."),
        "SCOPE/HONESTY: this uses the web-verified TRANSCRIPT geometry (OBKR offset, ~31-wide rows), not a "
        "measured physical engraving (none is publicly certified; exp 104 correction). So this closes the "
        "engraving-grid SELECTOR family under the best-available layout convention; a genuinely physical layout "
        "(from a high-res photo/rubbing measurement) could differ and is the only un-obtained variant. Combined "
        "with 121-126: no chart-tie, clock, autokey, or engraving-grid selector (standalone OR corrected) breaks "
        "the 30 selector-locked positions.",
    ]

    write_verdict(out, Verdict(
        exp="127", title="engraving-layout selector under the verified continuous-panel geometry (OBKR offset)",
        hypothesis="the per-position chart selector is a row/column parity of K4's engraving grid under the "
                   "CORRECTED geometry (OBKR at cols 27-30 of K3's row, then rows of 31) that 052/090/126 missed",
        status=status, best_score=(best_pass[0] if signal else None),
        best_partial=f"{len(passers)}/{n_masks} corrected-geometry masks 2-colour; best {best_pass[0]:.2f} vs "
                     f"null {null_best:.2f}; signal={signal}",
        search_space=n_masks, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["inspect/verify the corrected-geometry selector decrypt; seek physical-layout confirmation "
                     "from a high-res photo/rubbing"] if signal else
                    ["engraving-grid selector closed under BOTH the standalone (126) and corrected (127) "
                     "transcript geometries; the only un-tested variant needs a MEASURED physical line-layout "
                     "(not publicly available). The 30 selector-locked positions remain blocked"]),
        metrics={"n_masks": n_masks, "n_passers": len(passers), "best_pass_hex": round(best_pass[0], 2),
                 "random_null_hex": round(null_best, 2), "signal": signal, "geometry_ok": geo_ok}),
    )
    print(f"\ngeo_ok={geo_ok}; {len(passers)}/{n_masks} corrected-geometry masks 2-colour; best "
          f"{best_pass[0]:.2f} vs null {null_best:.2f}; signal={signal}; status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
