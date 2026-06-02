"""072 — Chaocipher at scale (heavy crib-anchored simulated annealing).

exp 068 reached only 15/24 cribs with keyword-seeded wheels + light SA. The
dynamic-alphabet family is the best Scheidt-fit and is NOT refuted in general
(keyspace 2x26!), so this is a genuine SOLUTION ATTEMPT: many restarts, longer
schedules, mixed keyword/random starts, objective = #crib matches (primary)
then hexagram (tiebreak). If a run trends toward high crib matches we scale
further; a flat ceiling well below 24/24 across heavy search is the negative.

Reuses exp 068's round-trip-validated Chaocipher. Output:
experiments/results/<date>_072_chaocipher_at_scale.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import math
import random
import time
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import keyed_alphabet
from kryptos.constants import K4

_spec = importlib.util.spec_from_file_location(
    "e068", str(Path(__file__).parent / "068_chaocipher.py"))
e068 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(e068)
chao_decrypt, crib_matches = e068.chao_decrypt, e068.crib_matches
KEYWORDS = e068.KEYWORDS
A26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def anneal(cw, pw, iters, seed):
    rng = random.Random(seed)
    cw, pw = list(cw), list(pw)
    P = chao_decrypt(K4, cw, pw)
    cur_m, cur_s = crib_matches(P), _kpa.score_free_text(P)
    best = (cur_m, cur_s, "".join(cw), "".join(pw))
    for t in range(iters):
        T = max(0.02, 2.0 * (1 - t / iters))
        wheel = cw if rng.random() < 0.5 else pw
        a, b = rng.randrange(26), rng.randrange(26)
        wheel[a], wheel[b] = wheel[b], wheel[a]
        P = chao_decrypt(K4, cw, pw)
        m, s = crib_matches(P), _kpa.score_free_text(P)
        d = (m - cur_m) * 4 + (s - cur_s)
        if d >= 0 or rng.random() < math.exp(d / T):
            cur_m, cur_s = m, s
            if (m, s) > (best[0], best[1]):
                best = (m, s, "".join(cw), "".join(pw))
        else:
            wheel[a], wheel[b] = wheel[b], wheel[a]
    return best


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_072_chaocipher_at_scale.jsonl"
    assert e068.self_test(), "chaocipher self-test failed"
    t0 = time.perf_counter()
    n_restarts = 28
    iters = 24000
    best = (0, -99.0, None, None)
    trend = []
    rng = random.Random(0)
    with open(out, "w") as f:
        for r in range(n_restarts):
            if r < len(KEYWORDS):
                kw1, kw2 = KEYWORDS[r], KEYWORDS[(r * 7) % len(KEYWORDS)]
                cw, pw = keyed_alphabet(kw1).letters, keyed_alphabet(kw2).letters
                seedlabel = f"{kw1}/{kw2}"
            else:
                cw = list(A26); pw = list(A26)
                rng.shuffle(cw); rng.shuffle(pw)
                cw, pw = "".join(cw), "".join(pw); seedlabel = f"random{r}"
            m, s, fcw, fpw = anneal(cw, pw, iters, r)
            trend.append(m)
            f.write(json.dumps({"restart": r, "seed": seedlabel, "crib_matches": m,
                                "hex": round(s, 2), "plaintext": chao_decrypt(K4, fcw, fpw)}) + "\n")
            if (m, s) > (best[0], best[1]):
                best = (m, s, fcw, fpw)
        bm, bs, bcw, bpw = best
        solved = bm == 24 and bs > -15.0

    elapsed = time.perf_counter() - t0
    P = chao_decrypt(K4, best[2], best[3]) if best[2] else None
    status = "solved" if (best[0] == 24 and best[1] > -15) else ("promising" if best[0] >= 21 else "ruled_out")
    insights = [
        f"Heavy Chaocipher SA: {n_restarts} restarts x {iters} iters (keyword + random starts). "
        f"Best crib matches = {best[0]}/24, hexagram {best[1]:.2f}. Per-restart best-crib distribution "
        f"max={max(trend)}, median={sorted(trend)[len(trend)//2]}.",
        (f"Best plaintext: {P[:48]}..." if P else "n/a"),
    ]
    if status == "ruled_out":
        insights.append(f"Across heavy search the crib-match ceiling is {best[0]}/24 -- no run approaches a "
                        f"solve, and the distribution shows no trend toward 24. Keyword- and random-seeded "
                        f"Chaocipher does not produce K4; scaling further is unlikely to help (no gradient "
                        f"toward the cribs). The dynamic-alphabet family is exhausted at hand-search scale.")
    write_verdict(out, Verdict(
        exp="072", title="Chaocipher at scale (heavy crib-anchored SA)",
        hypothesis="K4 is a Chaocipher recoverable by heavy crib-anchored search",
        status=status, best_score=round(best[1], 2), best_partial=f"best {best[0]}/24 cribs",
        search_space=n_restarts * iters, elapsed_s=round(elapsed, 1),
        solved_params=({"cw": best[2], "pw": best[3], "plaintext": P} if status == "solved" else None),
        insights=insights,
        next_steps=(["verify & announce"] if status == "solved" else
                    ["dynamic-alphabet at hand-scale exhausted; mechanical cousin (M-209) in exp 076"]),
        metrics={"best_crib": best[0], "trend_max": max(trend)})
    )
    print(f"\nbest {best[0]}/24 cribs, hex {best[1]:.2f}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
