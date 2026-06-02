"""122 — T1-B: external selector-mask harness in the HOMOPHONIC reframe (mechanism
M1). The Sanborn-confirmed Urania Weltzeituhr as a per-position 2-CLASS selector.

exp 094 tested the Weltzeituhr selector only in the BIJECTIVE model (does it
properly 3-colour the chi=3 graph + crib-determine + decrypt) -> empty support.
The homophonic reframe (114-119) needs only a 2-colouring of the b-graph, a far
weaker bar, AND a passing mask supplies the FULL 97-position selector at once -- so
the cribs pin the charts and the 73 free positions decrypt under the mask (free
chart entries hill-climbed). This is mechanism M1, the only family that can pin all
the selector-locked positions simultaneously, and it has never been run as a
homophonic 2-class selector.

Masks (deterministic readings of the confirmed 24-column world clock, swept over
all 24 phases -- which city aligns to position 1): (a) UTC SIGN (west/negative vs
east/non-negative of Greenwich -- resonates with the EAST/NORTHEAST cribs);
(b) UTC offset PARITY. 48 masks total, within the exp-120 budget N_max=52, so a
colouring-pass is interpretable; passers must ALSO clear the English/decrypt bar
(not just the colouring test) to count.

$0, local, deterministic, no LLM, no K5, no plaintext. Output:
experiments/results/<date>_122_selector_mask_harness.jsonl
"""

from __future__ import annotations

import csv
import json
import math
import random
import time
from collections import defaultdict
from datetime import date
from pathlib import Path

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
ENGLISH_BAR = -15.0   # K1-segment calibration floor (free-hex/char)

# b-edges over crib nodes (for the 2-colouring test)
B_EDGES = [(i, j) for i in range(N) for j in range(i + 1, N)
           if CRIB[i][2] == CRIB[j][2] and CRIB[i][1] != CRIB[j][1]]


def load_zones():
    lines = [ln for ln in Path("data/physical/weltzeituhr_zones.csv").read_text().splitlines()
             if ln and not ln.startswith("#")]
    rows = list(csv.DictReader(lines))
    rows.sort(key=lambda r: int(r["column"]))
    return rows  # 24 rows, ordered by column (UTC offset ascending)


def make_masks(zones):
    """Return {name: [class in {0,1} for each of 97 positions]} for each phase &
    reading of the world clock."""
    offsets = [int(r["utc_offset"]) for r in zones]   # length 24
    masks = {}
    for phase in range(24):
        sign = []
        par = []
        for i in range(97):
            off = offsets[(i + phase) % 24]
            sign.append(0 if off < 0 else 1)        # west vs east of Greenwich
            par.append(off % 2)                     # offset parity
        masks[f"utc_sign_ph{phase}"] = sign
        masks[f"utc_parity_ph{phase}"] = par
    return masks


def two_colours(mask):
    return all(mask[CRIB[i][0]] != mask[CRIB[j][0]] for i, j in B_EDGES)


def decrypt_score(mask, rng, restarts=12, steps=2500):
    """mask passes 2-colouring: pin charts from cribs, hill-climb free chart
    entries to maximise free-position hexagram. Return best free-hex + distinct
    English count."""
    pins = {0: {}, 1: {}}
    for pos, p, ch in CRIB:
        pins[mask[pos]][ch] = p
    free_ciphers = {c: [X for X in A if X not in pins[c]] for c in (0, 1)}
    cls = mask
    best = (-99.0, None)
    distinct = {}
    for _ in range(restarts):
        chart = {c: dict(pins[c]) for c in (0, 1)}
        for c in (0, 1):
            for X in free_ciphers[c]:
                chart[c][X] = rng.choice(A)

        def decrypt():
            return "".join(chart[cls[i]][K4[i]] for i in range(97))

        cur = _kpa.score_free_text(decrypt())
        for s in range(steps):
            T = 0.5 * (0.01 / 0.5) ** (s / steps)
            c = rng.randrange(2)
            if not free_ciphers[c]:
                continue
            X = rng.choice(free_ciphers[c]); old = chart[c][X]; nw = rng.choice(A)
            if nw == old:
                continue
            chart[c][X] = nw
            cand = _kpa.score_free_text(decrypt())
            if cand >= cur or rng.random() < math.exp((cand - cur) / max(T, 1e-6)):
                cur = cand
            else:
                chart[c][X] = old
        pt = decrypt(); sc = _kpa.score_free_text(pt)
        if sc >= ENGLISH_BAR:
            distinct[pt] = round(sc, 2)
        if sc > best[0]:
            best = (sc, pt)
    return best, len(distinct)


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_122_selector_mask_harness.jsonl"
    rng = random.Random(0)
    t0 = time.perf_counter()
    zones = load_zones()
    masks = make_masks(zones)

    passers = [name for name, m in masks.items() if two_colours(m)]
    n_masks = len(masks)

    # decrypt the passers (and a random-selector null for calibration)
    results = {}
    best_overall = (-99.0, None, None)
    for name in passers:
        best, ndist = decrypt_score(masks[name], rng)
        results[name] = {"best_hex": round(best[0], 2), "distinct_english": ndist}
        if best[0] > best_overall[0]:
            best_overall = (best[0], name, best[1])

    # random-selector null: random 97-bit masks that happen to 2-colour, decrypted
    null_best = -99.0
    null_pass = 0
    tries = 0
    while null_pass < 8 and tries < 4000:
        tries += 1
        rm = [rng.randrange(2) for _ in range(97)]
        if two_colours(rm):
            null_pass += 1
            b, _ = decrypt_score(rm, rng, restarts=6, steps=1500)
            null_best = max(null_best, b[0])

    elapsed = time.perf_counter() - t0
    # signal = a clock mask passes AND decrypts above the English bar AND beats the null
    solved = best_overall[0] >= ENGLISH_BAR and best_overall[0] > null_best + 1.0
    status = "promising" if solved else ("ruled_out" if not passers or best_overall[0] < null_best + 1.0
                                         else "inconclusive")

    with open(out, "w") as f:
        f.write(json.dumps({
            "n_masks": n_masks, "mask_budget_N_max": 52, "n_passers": len(passers),
            "passers": passers, "passer_results": results,
            "best_clock_hex": round(best_overall[0], 2), "best_mask": best_overall[1],
            "random_selector_null_best_hex": round(null_best, 2), "english_bar": ENGLISH_BAR,
            "signal": solved}) + "\n")

    insights = [
        f"Tested {n_masks} deterministic Weltzeituhr 2-class selector masks (UTC sign + UTC parity x 24 phases), "
        f"within the exp-120 budget N_max=52. {len(passers)} properly 2-COLOUR the b-graph (homophonic feasible): "
        f"{passers or 'NONE'}. (exp 094 found the clock gives no proper 3-colouring in the bijective model; this "
        f"is the weaker homophonic 2-colouring bar.)",
        (f"A clock mask 2-colours AND decrypts: best free-hex {best_overall[0]:.2f} ({best_overall[1]}) vs random-"
         f"selector null {null_best:.2f} and English bar {ENGLISH_BAR}. " +
         ("SIGNAL: the confirmed Weltzeituhr UTC selector clears the bar and beats the null -- inspect/verify the "
          "decryption immediately." if solved else
          "Passers decrypt no better than a random 2-colouring selector (hill-climbing free chart entries reaches "
          "the same ~floor for ANY selector -- the 116 degeneracy). The clock 2-class selector does not encode "
          "the plaintext above chance.")) if passers else
        "NO Weltzeituhr mask 2-colours the cribs as a binary selector -- the confirmed clock is not the homophonic "
        "selector either (closes the last clock-as-selector role, complementing 094's bijective negative).",
        "INTERPRETATION: a passing colouring is cheap (~0.1% per mask, exp 120); the decisive test is the decrypt "
        "clearing the null, not the colouring. Hill-climbing free chart entries can reach the English floor under "
        "ANY 2-colouring selector (092/093/116 under-determination), so only a mask whose FIXED decrypt (no "
        "free-entry tuning) reads as English would be a real hit.",
    ]

    write_verdict(out, Verdict(
        exp="122", title="Weltzeituhr 2-class selector-mask harness (homophonic M1)",
        hypothesis="the Sanborn-confirmed Weltzeituhr, as a 2-class (UTC sign/parity) per-position selector, "
                   "2-colours the b-graph and decrypts K4's free positions to English",
        status=status, best_score=(best_overall[0] if best_overall[0] > -90 else None),
        best_partial=f"{len(passers)}/{n_masks} masks 2-colour; best clock hex {best_overall[0]:.2f} "
                     f"vs null {null_best:.2f}; signal={solved}",
        search_space=n_masks, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["inspect/verify the clock-selector decryption against thematic content + cribs"] if solved else
                    ["the Weltzeituhr 2-class selector does not beat a random-selector null; the selector is not "
                     "the clock's UTC sign/parity. Remaining M1 readings (engraving layout, Morse) need the "
                     "physical line layout; the self-referential/autokey selector (123) is the next lever"]),
        metrics={"n_masks": n_masks, "n_passers": len(passers), "best_clock_hex": round(best_overall[0], 2),
                 "random_null_best": round(null_best, 2), "signal": solved}),
    )
    print(f"\nmasks={n_masks}; passers={len(passers)} ({passers}); best clock hex {best_overall[0]:.2f} "
          f"vs null {null_best:.2f}; signal={solved}; status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
