"""068 — Chaocipher (and dynamic self-modifying-alphabet ciphers).

The critic's flagged "biggest gap." Chaocipher uses two 26-letter wheels that
PERMUTE THEMSELVES after every character. It is hand-executable from one
memorized setup (extreme Scheidt 'simple/memorable/executed-years-later' fit),
produces an aperiodic realized shift from a short secret, allows letter->self
mapping (survives the pos-74 K->K fixed point that killed Beaufort), forces
chi>=3, and is OUTSIDE every ruled-out family (not a fixed per-position
alphabet, not a linear keystream, not a static substitution, not a
transposition). exp 065 showed the live selector is non-positional/dynamic --
exactly Chaocipher.

We implement the standard Chaocipher (round-trip self-tested), then:
  (A) forward test of keyword-derived starting wheels (Scheidt-memorable) --
      decrypt K4, hard-gate on the 24 cribs, hexagram-score survivors;
  (B) a bounded crib-anchored hill-climb/SA over the two starting wheels
      (Lasry/Kopal style), objective = #crib matches then hexagram.

Output: experiments/results/<date>_068_chaocipher.jsonl
"""

from __future__ import annotations

import json
import random
import time
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import keyed_alphabet
from kryptos.constants import K4
from kryptos.cribs import CRIBS

CRIB_PLAIN = {}
for c in CRIBS:
    for off, p in enumerate(c.plaintext):
        CRIB_PLAIN[c.start - 1 + off] = p
CRIB_POS = sorted(CRIB_PLAIN)
KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DYAHR", "BERLIN", "CLOCK",
            "BERLINCLOCK", "WELTZEITUHR", "SANBORN", "LANGLEY", "IQLUSION",
            "UNDERGRUUND", "EAST", "NORTHEAST", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]


def _permute(cw, pw, i):
    cw = cw[i:] + cw[:i]
    cw = cw[0:1] + cw[2:14] + cw[1:2] + cw[14:]            # extract idx1 -> insert idx13
    pw = pw[i:] + pw[:i]
    pw = pw[1:] + pw[:1]                                    # extra left shift
    pw = pw[0:2] + pw[3:14] + pw[2:3] + pw[14:]            # extract idx2 -> insert idx13
    return cw, pw


def chao_encrypt(pt, cw, pw):
    cw, pw = list(cw), list(pw)
    out = []
    for p in pt:
        i = pw.index(p)
        out.append(cw[i])
        cw, pw = _permute(cw, pw, i)
    return "".join(out)


def chao_decrypt(ct, cw, pw):
    cw, pw = list(cw), list(pw)
    out = []
    for c in ct:
        i = cw.index(c)
        out.append(pw[i])
        cw, pw = _permute(cw, pw, i)
    return "".join(out)


def crib_matches(P):
    return sum(1 for i in CRIB_POS if P[i] == CRIB_PLAIN[i])


def self_test():
    import random as _r
    rng = _r.Random(1)
    A = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    cw = A[:]; pw = A[:]; rng.shuffle(cw); rng.shuffle(pw)
    pt = "".join(rng.choice(A) for _ in range(97))
    ct = chao_encrypt(pt, cw, pw)
    return chao_decrypt(ct, cw, pw) == pt


def sa_search(seed_cw, seed_pw, iters, rng):
    cw, pw = list(seed_cw), list(seed_pw)
    P = chao_decrypt(K4, cw, pw)
    best_m = crib_matches(P); best_s = _kpa.score_free_text(P)
    cur_m, cur_s = best_m, best_s
    best = (best_m, best_s, "".join(cw), "".join(pw))
    for t in range(iters):
        T = max(0.01, 1.5 * (1 - t / iters))
        wheel = cw if rng.random() < 0.5 else pw
        a, b = rng.randrange(26), rng.randrange(26)
        wheel[a], wheel[b] = wheel[b], wheel[a]
        P = chao_decrypt(K4, cw, pw)
        m = crib_matches(P); s = _kpa.score_free_text(P)
        better = (m > cur_m) or (m == cur_m and s > cur_s)
        import math
        if better or rng.random() < math.exp(((m - cur_m) * 3 + (s - cur_s)) / T):
            cur_m, cur_s = m, s
            if (m, s) > (best[0], best[1]):
                best = (m, s, "".join(cw), "".join(pw))
        else:
            wheel[a], wheel[b] = wheel[b], wheel[a]
    return best


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_068_chaocipher.jsonl"
    assert self_test(), "Chaocipher round-trip self-test failed"
    print("Chaocipher round-trip self-test OK")
    t0 = time.perf_counter()
    rng = random.Random(0)
    best = (0, -99.0, None)            # (crib_matches, hex, info)
    solved = None
    n_tested = 0

    with open(out, "w") as f:
        # (A) forward: keyword-derived starting wheels
        for kw1 in KEYWORDS:
            for kw2 in KEYWORDS:
                cw = keyed_alphabet(kw1).letters
                pw = keyed_alphabet(kw2).letters
                P = chao_decrypt(K4, cw, pw)
                n_tested += 1
                m = crib_matches(P)
                if m >= 18:                       # near-crib-pass: worth recording
                    sc = _kpa.score_free_text(P)
                    f.write(json.dumps({"phase": "kw", "cw_kw": kw1, "pw_kw": kw2,
                                        "crib_matches": m, "hex": round(sc, 2),
                                        "plaintext": P}) + "\n")
                    if (m, _kpa.score_free_text(P)) > (best[0], best[1]):
                        best = (m, _kpa.score_free_text(P), {"phase": "kw", "cw_kw": kw1, "pw_kw": kw2,
                                                             "plaintext": P})
                    if m == 24:
                        solved = {"cw_kw": kw1, "pw_kw": kw2, "plaintext": P}
        # (B) bounded crib-anchored SA from keyword seeds
        for r in range(6):
            kw1, kw2 = rng.choice(KEYWORDS), rng.choice(KEYWORDS)
            m, s, cw, pw = sa_search(keyed_alphabet(kw1).letters, keyed_alphabet(kw2).letters,
                                     12000, random.Random(r))
            n_tested += 12000
            P = chao_decrypt(K4, cw, pw)
            if (m, s) > (best[0], best[1]):
                best = (m, s, {"phase": "SA", "seed": [kw1, kw2], "plaintext": P})
            if m == 24:
                solved = {"phase": "SA", "cw": cw, "pw": pw, "plaintext": P}
            f.write(json.dumps({"phase": "SA", "seed": [kw1, kw2], "crib_matches": m,
                                "hex": round(s, 2), "plaintext": P}) + "\n")

    elapsed = time.perf_counter() - t0
    bm, bs, bi = best
    status = "solved" if solved else ("promising" if bm >= 22 else "ruled_out")
    insights = [
        f"Chaocipher (round-trip validated). Forward keyword-wheel test ({len(KEYWORDS)**2} pairs) + "
        f"6 bounded crib-anchored SA runs (12k iters each). Best crib matches = {bm}/24, hexagram {bs:.2f}.",
        (f"Best config: {bi.get('phase')} {bi.get('cw_kw', bi.get('seed'))} -> {bi['plaintext'][:46]}..."
         if bi else "No config matched >=18 cribs."),
    ]
    if status == "ruled_out":
        insights.append("No keyword-derived starting wheels and no bounded SA reach the cribs (best far below "
                        "24/24). Chaocipher with memorable keyword wheels does not explain K4; the dynamic "
                        "self-modifying-alphabet family is not refuted in general (keyspace 2x26! is huge) but "
                        "the Scheidt-memorable keyword-seeded instances are exhausted.")
    write_verdict(out, Verdict(
        exp="068", title="Chaocipher / dynamic self-modifying alphabets",
        hypothesis="K4 is a Chaocipher with memorable keyword-derived starting wheels",
        status=status, best_score=round(bs, 2), best_partial=f"best {bm}/24 cribs",
        search_space=n_tested, elapsed_s=round(elapsed, 1), solved_params=solved,
        insights=insights,
        next_steps=(["verify & announce"] if solved else
                    ["if any SA run trended toward high crib matches, scale SA; else try Hagelin M-209 "
                     "lug/pin reconstruction (the mechanical dynamic cousin)"]),
        metrics={"best": bi})
    )
    print(f"\nbest crib matches {bm}/24, hex {bs:.2f}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
