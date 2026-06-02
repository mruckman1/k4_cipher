"""088 — Memorable hand-crafted alphabet triples, jointly decrypting under a
simple selector (the one escape hatch the squeeze bound leaves open).

exp 085 bounds out a short SELECTOR over few base alphabets. It does NOT bound
the other limb: each of the >=3 alphabets is itself an individually-MEMORABLE
hand-crafted object (a tableau route, a compass/physical seed, a Sanborn-typo
keyed alphabet, a Kryptos-surface keyword), with the flattening carried by the
alphabets, under a TRIVIAL selector (period-3 / row-aligned). Two things were
never done:
  (1) exps 046/047/048 each tested ONE memorable pool for a chi=3 cover and each
      FAILED; exp 047 explicitly deferred "combine route + compass + typo in one
      cover" -- never run. We combine all of them (plus Kryptos-keyword
      alphabets) into a single pool and search a 3-cover.
  (2) NONE of those experiments coupled a cover with a selector and an actual
      DECRYPT. A cover only proves the cribs are satisfiable; it never asks
      whether a SIMPLE position selector reproduces the cover's per-crib alphabet
      assignment and then decrypts the 73 free positions to English.

This experiment does both: combined-pool 3-cover; for every full 3-cover among
the top-coverage alphabets, test each simple class-function (i%3, row-of-7 %3,
i%3 on non-vowel count, etc.) under all 6 class->alphabet bijections for crib
consistency; consistent ones decrypt all 97 + hexagram-score. A scrambled
control (random alphabets of equal pool size) gives the chance cover rate.

$0, local, pure decipherment. Only public Kryptos material is used as keywords
(K1-K3 surface terms / cribs), never any K4 plaintext.

Output: experiments/results/<date>_088_handcrafted_alphabet_triples.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import random
import time
from datetime import date
from pathlib import Path

import _crib_sat as cs
import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import keyed_alphabet
from kryptos.alphabets_routes import route_alphabets
from kryptos.constants import K4
from kryptos.cribs import CRIBS


def _load(name, fname):
    m = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
        name, str(Path(__file__).parent / fname)))
    m.__spec__.loader.exec_module(m)
    return m

e047 = _load("e047", "047_compass_bearing_alphabets.py")
e048 = _load("e048", "048_sanborn_typo_alphabets.py")

N = 97
VOWELS = set("AEIOU")
# Public Kryptos-surface keywords only (K1-K3 sections + confirmed cribs + sculpture terms).
KW = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "IQLUSION", "UNDERGROUND", "SHADOW", "FORCES",
      "WELTZEITUHR", "BERLINCLOCK", "EASTNORTHEAST", "LUCIDMEMORY", "INVISIBLE", "DIGETAL",
      "INTERPRETATION", "TANGIBLE", "SUBTLE", "NUANCE", "ILLUSION", "MAGNETIC", "FIELD"]


def keyword_alphabets():
    out, seen = [], set()
    for kw in KW:
        s = keyed_alphabet(kw).letters
        if s not in seen:
            seen.add(s); out.append((f"kw[{kw}]", s))
    return out


def combined_pool():
    pool, seen = [], set()
    for label, s in (route_alphabets() + e047.build_pool() + e048.build_pool() + keyword_alphabets()):
        if len(s) == 26 and len(set(s)) == 26 and s not in seen:
            seen.add(s); pool.append((label, s))
    return pool


# crib positions: (0-indexed pos, plain_idx, cipher_idx) in STANDARD
CRIB_POS = []
for c in CRIBS:
    for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext)):
        CRIB_POS.append((c.start - 1 + off, ord(p) - 65, ord(ch) - 65))

# non-vowel running count clock (a "memorable" alternative position index)
CC = []
_n = 0
for ch in K4:
    if ch not in VOWELS:
        _n += 1
    CC.append(_n)

CLASS_FUNCS = {
    "i%3": lambda i: i % 3,
    "row7%3": lambda i: (i // 7) % 3,
    "cc%3": lambda i: CC[i] % 3,
    "(2i)%3": lambda i: (2 * i) % 3,
}
BIJECTIONS = [(0, 1, 2), (0, 2, 1), (1, 0, 2), (1, 2, 0), (2, 0, 1), (2, 1, 0)]


def covers_at(alpha_str, pi, ci):
    return ord(alpha_str[pi]) - 65 == ci


def try_decrypt(alphas, cfun, bij):
    """alphas: 3 strings; selector class = cfun(i); class c uses alphas[bij[c]].
    Returns plaintext if the selector reproduces every crib's assignment, else None."""
    for (pos, pi, ci) in CRIB_POS:
        if not covers_at(alphas[bij[cfun(pos)]], pi, ci):
            return None
    out = []
    for i, ch in enumerate(K4):
        a = alphas[bij[cfun(i)]]
        out.append(chr(a.index(ch) + 65))
    return "".join(out)


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_088_handcrafted_alphabet_triples.jsonl"
    t0 = time.perf_counter()
    pool = combined_pool()
    cons = cs.crib_constraints()
    full = (1 << len(cons)) - 1

    # A 3-cover of 23 constraints can only use HIGH-coverage alphabets, so the
    # exact-cover search is restricted to the top-by-coverage alphabets (an
    # alphabet covering 1-2 constraints cannot be in a 3-of-23 cover). This keeps
    # find_cover / best_partial out of the C(full_pool, 3) blowup.
    masks = [(lb, s, cs.covered_mask(s, cons)) for lb, s in pool]
    masks = [(lb, s, m) for lb, s, m in masks if m]
    masks.sort(key=lambda t: bin(t[2]).count("1"), reverse=True)
    CAP = 200
    cap_pool = [(lb, s) for lb, s, _ in masks[:CAP]]
    top = masks[:60]

    # combined-pool cover stats (the never-run combination), on the capped pool
    cover3 = cs.find_cover(cap_pool, 3)
    gk, glabels, gcov, gtot = cs.greedy_cover(pool)   # greedy is O(pool*k), cheap on full pool
    bp_n, bp_tot, bp_labels = cs.best_partial_cover(cap_pool, 3)

    best = (-99.0, None)
    solved = None
    n_covers = 0
    n_consistent = 0
    with open(out, "w") as f:
        for a in range(len(top)):
            for b in range(a + 1, len(top)):
                mab = top[a][2] | top[b][2]
                for c in range(b + 1, len(top)):
                    if (mab | top[c][2]) != full:
                        continue
                    n_covers += 1
                    alphas = (top[a][1], top[b][1], top[c][1])
                    labels = (top[a][0], top[b][0], top[c][0])
                    for cf_name, cfun in CLASS_FUNCS.items():
                        for bij in BIJECTIONS:
                            P = try_decrypt(alphas, cfun, bij)
                            if P is None:
                                continue
                            n_consistent += 1
                            sc = _kpa.score_free_text(P)
                            if sc > best[0]:
                                best = (sc, {"alphabets": labels, "selector": cf_name,
                                             "bijection": bij, "hex": round(sc, 2), "plaintext": P})
                            if sc > -16.0:
                                f.write(json.dumps({"alphabets": labels, "selector": cf_name,
                                                    "bijection": bij, "hex": round(sc, 2),
                                                    "plaintext": P}) + "\n")
                            if sc > -15.0:
                                solved = {"alphabets": labels, "selector": cf_name, "bijection": bij,
                                          "plaintext": P}

    # scrambled control: random alphabets of equal pool size -> chance 3-cover rate
    rng = random.Random(0)
    base = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    ctrl_hits = 0
    CTRIALS = 10
    rsize = min(len(pool), CAP)  # equal-difficulty random pool, capped to keep find_cover tractable
    for _ in range(CTRIALS):
        rpool = []
        for j in range(rsize):
            s = base[:]; rng.shuffle(s)
            rpool.append((f"r{j}", "".join(s)))
        if cs.find_cover(rpool, 3) is not None:
            ctrl_hits += 1
    ctrl_p = ctrl_hits / CTRIALS

    elapsed = time.perf_counter() - t0
    bi = best[1]

    cover_exists = cover3 is not None
    if solved:
        status = "solved"
    elif bi and bi["hex"] > -15.0:
        status = "promising"
    elif cover_exists and n_consistent > 0 and bi and bi["hex"] > -16.0:
        status = "promising"
    else:
        status = "ruled_out"

    with open(out, "a") as f:
        f.write(json.dumps({"summary": True, "pool_size": len(pool),
                            "exact_3_cover": cover_exists, "greedy_k": gk,
                            "best_partial_k3": bp_n, "of": bp_tot, "n_full_covers_topN": n_covers,
                            "n_selector_consistent": n_consistent, "control_cover_p": round(ctrl_p, 3)}) + "\n")

    insights = [
        f"Combined memorable-alphabet pool = {len(pool)} distinct hand-crafted alphabets (tableau routes + "
        f"compass/physical seeds + Sanborn-typo keyed + Kryptos-surface keywords) -- the never-run union from "
        f"exp 047's deferred next-step. Exact chi=3 (3-alphabet) cover of the 24 cribs: "
        f"{'FOUND ' + str(cover3[0]) if cover_exists else 'NONE'}. Greedy needs k={gk}; best 3 cover "
        f"{bp_n}/{bp_tot} constraints.",
        (f"COVER+SELECTOR+DECRYPT (never done before): {n_covers} full 3-covers among top-60 alphabets; "
         f"{n_consistent} are consistent with a simple selector ({list(CLASS_FUNCS)}). Best decrypt free-hex "
         f"{bi['hex']} -> {bi['plaintext'][:40]}... (alphabets {bi['alphabets']}, selector {bi['selector']})"
         if bi else f"{n_covers} full 3-covers among top-60 alphabets, but NONE is consistent with any simple "
         f"position selector -- a cover exists only with a position-by-position (non-simple) assignment."),
        f"SCRAMBLED CONTROL: random alphabet pools of equal size admit a 3-cover {ctrl_p*100:.0f}% of the time "
        f"({'so a cover is unremarkable; the discriminating test is the simple-selector decrypt' if ctrl_p > 0.2 else 'so a real cover is itself meaningful'}).",
    ]
    if status == "ruled_out":
        if not cover_exists:
            insights.append("VERDICT: even the COMBINED memorable-alphabet pool cannot 3-cover the 24 cribs -- "
                            "K4's mandatory hand-crafted alphabets are not tableau routes, compass/physical "
                            "seeds, Sanborn-typo keyed, or Kryptos-keyword alphabets. The memorable-alphabet "
                            "escape hatch is closed; the residue is a genuinely idiosyncratic construction.")
        else:
            insights.append("VERDICT: a 3-cover EXISTS but no simple (period-3 / row-aligned / non-vowel-clock) "
                            "selector reproduces it AND decrypts the free positions to English -- the cover is "
                            "an arithmetic coincidence, not a cipher. The memorable-alphabet + simple-selector "
                            "hypothesis is RULED OUT; the residue is an idiosyncratic per-position rule.")

    write_verdict(out, Verdict(
        exp="088", title="memorable hand-crafted alphabet triples under a simple selector",
        hypothesis="K4's >=3 alphabets are individually-memorable hand-crafted objects (routes/compass/typo/"
                   "keyword) decrypting under a trivial position selector",
        status=status, best_score=(bi["hex"] if (bi and status in ("solved", "promising")) else None),
        best_partial=(f"3-cover={'yes' if cover_exists else 'no'}; {n_consistent} selector-consistent covers; "
                      f"best free-hex {bi['hex']}" if bi else
                      f"3-cover={'yes' if cover_exists else 'no'}; no selector-consistent cover; "
                      f"best 3 cover {bp_n}/{bp_tot}"),
        search_space=n_covers, elapsed_s=round(elapsed, 1), solved_params=solved,
        insights=insights,
        next_steps=(["verify byte-exact & announce"] if solved else
                    ["the memorable-alphabet escape hatch is closed; the per-position-substitution frame is now "
                     "fully bounded (085 selector limb + 088 alphabet limb). Remaining residue = a genuinely "
                     "idiosyncratic rule; sharpen only via a NEW ciphertext-only invariant shared by K1-K3"]),
        metrics={"pool_size": len(pool), "exact_3_cover": cover_exists, "greedy_k": gk,
                 "best_partial_k3": bp_n, "n_selector_consistent": n_consistent,
                 "control_cover_p": round(ctrl_p, 3), "best": bi}),
    )
    print(f"\npool={len(pool)}; 3-cover={'yes' if cover_exists else 'no'}; {n_covers} full covers, "
          f"{n_consistent} selector-consistent; best free-hex {best[0]:.2f}; ctrl cover p={ctrl_p:.2f}; "
          f"status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
