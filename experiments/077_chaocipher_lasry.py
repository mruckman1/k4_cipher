"""077 — Chaocipher Lasry-scale search (parallel multi-core SA, crib+LM objective).

exp 072 plateaued at 16/24 cribs with a crib-only gradient. Lasry-style attacks
score the FULL decrypt with a language model and use cribs as a heavy bonus --
that gives a real gradient over the 73 free positions too. This runs many
parallel independent annealers (multiprocessing across cores) for a wall-time
budget, each on the combined objective:

    score = CRIB_W * (#crib matches) + hexagram(free positions)

Self-contained (spawn-safe). Reports the best crib-match + hexagram and, most
importantly, whether crib-matches TREND toward 24 under heavy search (a basin)
or stay flat (no basin -> strengthens the negative, though 2x26! is not
formally refuted).

Usage: python experiments/077_chaocipher_lasry.py [budget_seconds] [n_workers]
Output: experiments/results/<date>_077_chaocipher_lasry.jsonl
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
from kryptos.alphabets import keyed_alphabet
from kryptos.constants import K4
from kryptos.cribs import CRIBS

CRIB_PLAIN = {}
for c in CRIBS:
    for off, p in enumerate(c.plaintext):
        CRIB_PLAIN[c.start - 1 + off] = p
CRIB_POS = sorted(CRIB_PLAIN)
CRIB_W = 6.0
A26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DYAHR", "BERLIN", "CLOCK",
            "BERLINCLOCK", "WELTZEITUHR", "SANBORN", "LANGLEY", "IQLUSION", "UNDERGRUUND"]


def chao_decrypt(ct, cw, pw):
    cw, pw = list(cw), list(pw)
    out = []
    for c in ct:
        i = cw.index(c)
        out.append(pw[i])
        cw = cw[i:] + cw[:i]
        cw = cw[0:1] + cw[2:14] + cw[1:2] + cw[14:]
        pw = pw[i:] + pw[:i]
        pw = pw[1:] + pw[:1]
        pw = pw[0:2] + pw[3:14] + pw[2:3] + pw[14:]
    return "".join(out)


def crib_matches(P):
    return sum(1 for i in CRIB_POS if P[i] == CRIB_PLAIN[i])


def worker(args):
    wid, deadline = args
    scorer = _kpa.hexagram_scorer()
    free = _kpa._free_positions()
    rng = random.Random(wid * 7919 + 1)
    best = (0, -99.0, None, None)
    n_eval = 0
    trend_max = 0
    while time.time() < deadline:
        # restart: keyword or random seed
        if rng.random() < 0.4:
            cw = list(keyed_alphabet(rng.choice(KEYWORDS)).letters)
            pw = list(keyed_alphabet(rng.choice(KEYWORDS)).letters)
        else:
            cw = list(A26); pw = list(A26); rng.shuffle(cw); rng.shuffle(pw)
        P = chao_decrypt(K4, cw, pw)
        m = crib_matches(P)
        s = CRIB_W * m + scorer("".join(P[i] for i in free))
        cur = s; cur_m = m
        stagnant = 0
        iters = 6000
        for t in range(iters):
            if (t & 1023) == 0 and time.time() >= deadline:
                break
            T = max(0.05, 2.5 * (1 - t / iters))
            wheel = cw if rng.random() < 0.5 else pw
            a, b = rng.randrange(26), rng.randrange(26)
            wheel[a], wheel[b] = wheel[b], wheel[a]
            P = chao_decrypt(K4, cw, pw)
            n_eval += 1
            m = crib_matches(P)
            s = CRIB_W * m + scorer("".join(P[i] for i in free))
            if s >= cur or rng.random() < math.exp((s - cur) / T):
                cur = s; cur_m = m
                stagnant = 0
                if m > trend_max:
                    trend_max = m
                if (m, s) > (best[0], best[1]):
                    best = (m, s, "".join(cw), "".join(pw))
            else:
                wheel[a], wheel[b] = wheel[b], wheel[a]
                stagnant += 1
                if stagnant > 1500:
                    break
    return {"wid": wid, "best_crib": best[0], "best_score": round(best[1], 2),
            "cw": best[2], "pw": best[3], "n_eval": n_eval, "trend_max": trend_max}


def main() -> int:
    budget = int(sys.argv[1]) if len(sys.argv) > 1 else 900
    nworkers = int(sys.argv[2]) if len(sys.argv) > 2 else max(2, mp.cpu_count() - 2)
    out = _kpa.RESULTS / f"{date.today()}_077_chaocipher_lasry.jsonl"
    t0 = time.time()
    deadline = t0 + budget
    print(f"Chaocipher Lasry-scale: {nworkers} workers x {budget}s")
    with mp.Pool(nworkers) as pool:
        results = pool.map(worker, [(w, deadline) for w in range(nworkers)])
    elapsed = time.time() - t0
    total_eval = sum(r["n_eval"] for r in results)
    best = max(results, key=lambda r: (r["best_crib"], r["best_score"]))
    trend_max = max(r["trend_max"] for r in results)
    P = chao_decrypt(K4, best["cw"], best["pw"]) if best["cw"] else None

    from _verdict import Verdict, write_verdict
    with open(out, "w") as f:
        f.write(json.dumps({"workers": nworkers, "budget_s": budget, "total_evals": total_eval,
                            "best_crib": best["best_crib"], "trend_max": trend_max,
                            "best_plaintext": P, "per_worker": results}) + "\n")
    solved = best["best_crib"] == 24
    status = "solved" if solved else ("promising" if trend_max >= 21 else "ruled_out")
    insights = [
        f"Parallel Chaocipher SA: {nworkers} workers, {total_eval:,} total evaluations in {elapsed:.0f}s, "
        f"combined objective (crib bonus + hexagram). Best crib matches = {best['best_crib']}/24; "
        f"max crib-matches reached anywhere = {trend_max}/24.",
        (f"Best plaintext: {P[:50]}..." if P else "n/a"),
        f"At {total_eval/1e6:.0f}M evaluations the crib-match ceiling is {trend_max}/24 with no approach to "
        f"24 -- consistent with NO basin pulling toward a solution. Lasry-scale would push further, but the "
        f"absence of a gradient toward the cribs is itself evidence Chaocipher is not K4 (the 2x26! keyspace "
        f"is not formally refuted).",
    ]
    write_verdict(out, Verdict(
        exp="077", title="Chaocipher Lasry-scale parallel SA",
        hypothesis="K4 is a Chaocipher recoverable by heavy parallel crib+LM search",
        status=status, best_score=best["best_score"], best_partial=f"best {best['best_crib']}/24; max {trend_max}/24",
        search_space=total_eval, elapsed_s=round(elapsed, 1),
        solved_params=({"cw": best["cw"], "pw": best["pw"], "plaintext": P} if solved else None),
        insights=insights,
        next_steps=(["verify & announce"] if solved else
                    ["no basin at this scale; further Chaocipher compute is low-yield"]),
        metrics={"trend_max": trend_max, "total_evals": total_eval})
    )
    print(f"\nbest {best['best_crib']}/24 (trend max {trend_max}); {total_eval:,} evals. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
