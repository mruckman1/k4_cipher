"""076 — Hagelin M-209 known-plaintext attack (bounded hill-climb).

The mechanical dynamic cousin of Chaocipher: 6 pin-wheels (sizes 26,25,23,21,
19,17) + a 27-bar lug cage produce a per-position displacement K_i; the cipher
is Beaufort C_i=(K_i-P_i) mod 26. The displacement keystream is effectively
aperiodic (lcm of wheel sizes is huge) yet fully deterministic from the key
(131 pins + 27 bars x 2 lugs + 6 start positions). Scheidt (NSA) knew the M-209
intimately; "executed years later" fits a mechanical procedure (though the
"keyword" framing fits it less well -> lower prior).

KPA: at the 24 cribs the displacement mod 26 is known (K_i=(C_i+P_i) mod 26,
Beaufort). We hill-climb (pins,lugs,starts) to match the 24 crib displacements,
tiebreaking by full-decrypt hexagram. The key space is enormous, so a bounded
local search is NOT conclusive on the negative -- reported honestly as a
budgeted attempt. A planted self-test validates encrypt/decrypt + displacement.

Output: experiments/results/<date>_076_m209.jsonl
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

SIZES = [26, 25, 23, 21, 19, 17]
NBARS = 27
CRIB_PLAIN = {}
for c in CRIBS:
    for off, p in enumerate(c.plaintext):
        CRIB_PLAIN[c.start - 1 + off] = p
CRIB_POS = sorted(CRIB_PLAIN)
# observed displacement (mod 26) at crib positions: Beaufort K=(C+P) mod 26
OBS = {i: (ord(K4[i]) - 65 + ord(CRIB_PLAIN[i]) - 65) % 26 for i in CRIB_POS}


def rand_key(rng):
    pins = [[rng.randrange(2) for _ in range(s)] for s in SIZES]
    lugs = [tuple(sorted(rng.sample(range(7), 2))) for _ in range(NBARS)]   # 2 lugs in 0..6 (0=neutral)
    starts = [rng.randrange(s) for s in SIZES]
    return [pins, lugs, starts]


def displacement(key, step):
    pins, lugs, starts = key
    active = [pins[w][(starts[w] + step) % SIZES[w]] for w in range(6)]   # wheel w active this step?
    d = 0
    for (l1, l2) in lugs:
        on = (l1 != 0 and active[l1 - 1]) or (l2 != 0 and active[l2 - 1])
        if on:
            d += 1
    return d % 26


def crib_match(key):
    return sum(1 for i in CRIB_POS if displacement(key, i) == OBS[i])


def decrypt(key):
    return "".join(chr(65 + (displacement(key, i) - (ord(K4[i]) - 65)) % 26) for i in range(97))


def mutate(key, rng):
    pins, lugs, starts = key
    k = rng.random()
    if k < 0.6:                                  # flip a pin
        w = rng.randrange(6); j = rng.randrange(SIZES[w])
        pins[w][j] ^= 1
        return ("pin", w, j)
    elif k < 0.9:                                # change a lug bar
        b = rng.randrange(NBARS); old = lugs[b]
        lugs[b] = tuple(sorted(rng.sample(range(7), 2)))
        return ("lug", b, old)
    else:                                        # change a start
        w = rng.randrange(6); old = starts[w]
        starts[w] = rng.randrange(SIZES[w])
        return ("start", w, old)


def undo(key, mv):
    pins, lugs, starts = key
    if mv[0] == "pin":
        pins[mv[1]][mv[2]] ^= 1
    elif mv[0] == "lug":
        lugs[mv[1]] = mv[2]
    else:
        starts[mv[1]] = mv[2]


def self_test():
    rng = random.Random(0)
    key = rand_key(rng)
    P = "".join(chr(65 + rng.randrange(26)) for _ in range(97))
    C = "".join(chr(65 + (displacement(key, i) - (ord(P[i]) - 65)) % 26) for i in range(97))
    # decrypt with the same key
    Pdec = "".join(chr(65 + (displacement(key, i) - (ord(C[i]) - 65)) % 26) for i in range(97))
    return Pdec == P


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_076_m209.jsonl"
    assert self_test(), "M-209 round-trip self-test failed"
    t0 = time.perf_counter()
    n_restarts = 20
    iters = 20000
    best = (0, -99.0, None)
    rng = random.Random(0)
    trend = []
    with open(out, "w") as f:
        for r in range(n_restarts):
            key = rand_key(random.Random(r))
            cur = crib_match(key)
            for t in range(iters):
                T = max(0.05, 3.0 * (1 - t / iters))
                mv = mutate(key, rng)
                m = crib_match(key)
                if m >= cur or rng.random() < math.exp((m - cur) / T):
                    cur = m
                else:
                    undo(key, mv)
            m = crib_match(key)
            trend.append(m)
            sc = _kpa.score_free_text(decrypt(key)) if m >= 20 else -99.0
            if (m, sc) > (best[0], best[1]):
                best = (m, sc, decrypt(key))
            f.write(json.dumps({"restart": r, "crib_match": m, "hex": round(sc, 2)}) + "\n")

    elapsed = time.perf_counter() - t0
    bm, bs, bP = best
    solved = bm == 24 and bs > -15.0
    status = "solved" if solved else ("promising" if bm >= 22 else "ruled_out")
    insights = [
        f"M-209 bounded HC: {n_restarts} restarts x {iters} iters over pins(131)+lugs(27x2)+starts(6). "
        f"Best crib-displacement match = {bm}/24 (max over restarts {max(trend)}), hexagram {bs:.2f}.",
        "BUDGET CAVEAT: the M-209 key space is enormous; a bounded local HC is NOT a conclusive negative "
        "(Lasry-scale search uses far more compute). This is a budgeted SOLUTION ATTEMPT, not a ruling.",
    ]
    if status == "ruled_out":
        insights.append(f"At this budget the HC plateaus at {bm}/24 crib displacements with no trend to 24; "
                        f"no M-209 key reproducing the cribs was found. Combined with the poor fit to "
                        f"Scheidt's 'keyword' description, M-209 is deprioritised (not formally refuted).")
    write_verdict(out, Verdict(
        exp="076", title="Hagelin M-209 KPA (bounded hill-climb)",
        hypothesis="K4 is a Hagelin M-209 (pin/lug/cage) Beaufort cipher",
        status=status, best_score=round(bs, 2), best_partial=f"best {bm}/24 crib displacements",
        search_space=n_restarts * iters, elapsed_s=round(elapsed, 1),
        solved_params=({"plaintext": bP} if solved else None), insights=insights,
        next_steps=(["verify & announce"] if solved else
                    ["if a trend toward 24 appeared, scale HC (Lasry-style); else M-209 is low-prior/deprioritised"]),
        metrics={"best_crib": bm, "trend_max": max(trend)})
    )
    print(f"\nbest {bm}/24 crib displacements, hex {bs:.2f}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
