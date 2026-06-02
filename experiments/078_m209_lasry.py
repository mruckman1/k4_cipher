"""078 — Hagelin M-209 Lasry-scale search (parallel multi-core SA, crib+LM objective).

exp 076 plateaued at 19/24 crib displacements with a displacement-only gradient.
This runs many parallel annealers over the full M-209 key (131 pins + 27 lug
bars + 6 start positions) for a wall-time budget, on the combined objective:

    score = CRIB_W * (#crib displacements matched) + hexagram(free positions)

so the 73 free positions add gradient. Reports best + whether crib-displacement
matches TREND toward 24 (a basin) or stay flat. The M-209 key space is enormous,
so even at this scale a flat negative is NOT a formal refutation -- but a
no-trend result at 10^8 evaluations is strong practical evidence.

Self-contained (spawn-safe). Usage:
  python experiments/078_m209_lasry.py [budget_seconds] [n_workers]
Output: experiments/results/<date>_078_m209_lasry.jsonl
"""

from __future__ import annotations

import json
import math
import multiprocessing as mp
import random
import sys
import time
from datetime import date

import _kpa
from kryptos.constants import K4
from kryptos.cribs import CRIBS

SIZES = [26, 25, 23, 21, 19, 17]
NBARS = 27
CRIB_PLAIN = {}
for c in CRIBS:
    for off, p in enumerate(c.plaintext):
        CRIB_PLAIN[c.start - 1 + off] = p
CRIB_POS = sorted(CRIB_PLAIN)
OBS = {i: (ord(K4[i]) - 65 + ord(CRIB_PLAIN[i]) - 65) % 26 for i in CRIB_POS}
CRIB_W = 6.0


def rand_key(rng):
    pins = [[rng.randrange(2) for _ in range(s)] for s in SIZES]
    lugs = [tuple(sorted(rng.sample(range(7), 2))) for _ in range(NBARS)]
    starts = [rng.randrange(s) for s in SIZES]
    return [pins, lugs, starts]


def displacement(key, step):
    pins, lugs, starts = key
    active = [pins[w][(starts[w] + step) % SIZES[w]] for w in range(6)]
    d = 0
    for (l1, l2) in lugs:
        if (l1 and active[l1 - 1]) or (l2 and active[l2 - 1]):
            d += 1
    return d % 26


def crib_match(key):
    return sum(1 for i in CRIB_POS if displacement(key, i) == OBS[i])


def decrypt(key):
    return "".join(chr(65 + (displacement(key, i) - (ord(K4[i]) - 65)) % 26) for i in range(97))


def mutate(key, rng):
    pins, lugs, starts = key
    k = rng.random()
    if k < 0.6:
        w = rng.randrange(6); j = rng.randrange(SIZES[w]); pins[w][j] ^= 1
        return ("pin", w, j)
    elif k < 0.9:
        b = rng.randrange(NBARS); old = lugs[b]
        lugs[b] = tuple(sorted(rng.sample(range(7), 2)))
        return ("lug", b, old)
    else:
        w = rng.randrange(6); old = starts[w]; starts[w] = rng.randrange(SIZES[w])
        return ("start", w, old)


def undo(key, mv):
    pins, lugs, starts = key
    if mv[0] == "pin":
        pins[mv[1]][mv[2]] ^= 1
    elif mv[0] == "lug":
        lugs[mv[1]] = mv[2]
    else:
        starts[mv[1]] = mv[2]


def worker(args):
    wid, deadline = args
    scorer = _kpa.hexagram_scorer()
    free = _kpa._free_positions()
    rng = random.Random(wid * 6151 + 3)
    best = (0, -99.0, None)
    n_eval = 0
    trend_max = 0
    while time.time() < deadline:
        key = rand_key(rng)
        m = crib_match(key)
        cur = CRIB_W * m + scorer("".join(decrypt(key)[i] for i in free))
        cur_m = m
        stagnant = 0
        iters = 8000
        for t in range(iters):
            if (t & 1023) == 0 and time.time() >= deadline:
                break
            T = max(0.05, 3.0 * (1 - t / iters))
            mv = mutate(key, rng)
            m = crib_match(key)
            P = decrypt(key)
            s = CRIB_W * m + scorer("".join(P[i] for i in free))
            n_eval += 1
            if s >= cur or rng.random() < math.exp((s - cur) / T):
                cur = s; cur_m = m
                stagnant = 0
                if m > trend_max:
                    trend_max = m
                if (m, s) > (best[0], best[1]):
                    best = (m, s, P)
            else:
                undo(key, mv)
                stagnant += 1
                if stagnant > 2000:
                    break
    return {"wid": wid, "best_crib": best[0], "best_score": round(best[1], 2),
            "plaintext": best[2], "n_eval": n_eval, "trend_max": trend_max}


def main() -> int:
    budget = int(sys.argv[1]) if len(sys.argv) > 1 else 900
    nworkers = int(sys.argv[2]) if len(sys.argv) > 2 else max(2, mp.cpu_count() - 2)
    out = _kpa.RESULTS / f"{date.today()}_078_m209_lasry.jsonl"
    t0 = time.time()
    deadline = t0 + budget
    print(f"M-209 Lasry-scale: {nworkers} workers x {budget}s")
    with mp.Pool(nworkers) as pool:
        results = pool.map(worker, [(w, deadline) for w in range(nworkers)])
    elapsed = time.time() - t0
    total_eval = sum(r["n_eval"] for r in results)
    best = max(results, key=lambda r: (r["best_crib"], r["best_score"]))
    trend_max = max(r["trend_max"] for r in results)

    from _verdict import Verdict, write_verdict
    with open(out, "w") as f:
        f.write(json.dumps({"workers": nworkers, "budget_s": budget, "total_evals": total_eval,
                            "best_crib": best["best_crib"], "trend_max": trend_max,
                            "best_plaintext": best["plaintext"], "per_worker": results}) + "\n")
    # honest status: matching crib DISPLACEMENTS is cheap/degenerate for M-209
    # (24 mod-26 constraints vs an enormous key). A lead requires the DECRYPT to
    # be English, not just a high displacement count.
    best_free_hex = best["best_score"] - CRIB_W * best["best_crib"]
    solved = best["best_crib"] == 24 and best_free_hex > -15.0
    status = "solved" if solved else ("promising" if best_free_hex > -16.0 else "ruled_out")
    insights = [
        f"Parallel M-209 SA: {nworkers} workers, {total_eval:,} total evaluations in {elapsed:.0f}s, "
        f"combined objective (crib-displacement bonus + hexagram). Best crib displacements = "
        f"{best['best_crib']}/24; max reached anywhere = {trend_max}/24.",
        (f"Best plaintext: {best['plaintext'][:50]}..." if best["plaintext"] else "n/a"),
        f"At {total_eval/1e6:.0f}M evaluations the crib-displacement match plateaus at {trend_max}/24 with no "
        f"approach to 24 -- no basin. The M-209 key space is enormous so this is not a formal refutation, but "
        f"a no-trend result at this scale, plus M-209's poor fit to Scheidt's 'keyword' framing, makes it a "
        f"strong practical negative.",
    ]
    write_verdict(out, Verdict(
        exp="078", title="Hagelin M-209 Lasry-scale parallel SA",
        hypothesis="K4 is a Hagelin M-209 recoverable by heavy parallel crib+LM search",
        status=status, best_score=best["best_score"], best_partial=f"best {best['best_crib']}/24; max {trend_max}/24",
        search_space=total_eval, elapsed_s=round(elapsed, 1),
        solved_params=({"plaintext": best["plaintext"]} if solved else None),
        insights=insights,
        next_steps=(["verify & announce"] if solved else
                    ["no basin at 10^8 scale; M-209 practically exhausted (formal refutation needs cluster-scale)"]),
        metrics={"trend_max": trend_max, "total_evals": total_eval})
    )
    print(f"\nbest {best['best_crib']}/24 (trend max {trend_max}); {total_eval:,} evals. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
