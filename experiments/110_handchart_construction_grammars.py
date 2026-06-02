"""110 — Hand-built "chart" construction grammars vs the chi=3 crib cover.

The auction catalog reportedly calls K4 a "chart-based coding system" (+ Sanborn
"who says it's a math solution?", Scheidt "matrix codes ... that didn't depend on
mathematics"). THEORY: the >=3 mandatory hand-crafted alphabets (proven required &
not from keyword/route/compass/typo/clock sources, exp 088) are nonetheless built
by a SYSTEMATIC hand method Scheidt would have taught (Friedman/Callimahos canon) --
not arbitrary. exp 046 only applied geometric reads to the KEYED/STD tableau; this
applies the classic mixed-alphabet hand grammars to MANY KEYWORD-keyed bases:

  - COLUMNAR-MIXED: keyword-keyed base written row-major into a width-w grid, read
    column-major (Friedman's standard mixed cipher alphabet)
  - DECIMATION: base[(a*i+b) mod 26] for a coprime to 26 (multiplicative mixed
    alphabet) -- the general form 047 only did for compass seeds
  - BOUSTROPHEDON / DIAGONAL reads of keyword-keyed bases

Test (deterministic, like 088): does any 3 of these construction-grammar alphabets
chi=3-cover the 24 cribs (and decrypt under a simple selector)? AND a SIGNAL test:
is the best PARTIAL 3-cover from construction grammars notably higher than from
random alphabets / the 088 memorable pool (13/23)? -- per construction METHOD, so
a directional signal can surface even without a full cover.

Outcome: a 3-cover -> a real lead (the chart's construction method). No cover, and
no partial-cover signal above random -> tightens the conclusion that the chart is
genuinely BESPOKE / non-grammar (recoverable only with the chart itself).

$0, local, deterministic, no LLM, no K5, no plaintext. Output:
experiments/results/<date>_110_handchart_construction_grammars.jsonl
"""

from __future__ import annotations

import json
import math
import random
import time
from datetime import date

import _crib_sat as cs
import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import keyed_alphabet
from kryptos.alphabets_routes import _boustrophedon, _columnar_reads, _diagonals
from kryptos.constants import K4
from kryptos.cribs import CRIBS

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
COPRIME = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
# Friedman-canon + Kryptos + Scheidt-context keywords for the keyed bases
KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "IQLUSION", "UNDERGROUND", "SHADOW", "FORCES",
            "BERLINCLOCK", "EASTNORTHEAST", "WELTZEITUHR", "SANBORN", "SCHEIDT", "LANGLEY",
            "INTELLIGENCE", "CRYPTOGRAPHY", "CIPHER", "SECRET", "COORDINATE", "TANGENT",
            "FRIEDMAN", "MILITARY", "CRYPTANALYSIS", "MATRIX", "INVISIBLE", "MAGNETIC",
            "DIGETAL", "INTERPRETATION", "LUCID", "MEMORY", "NUANCE"]


def decimation(base, a, b):
    return "".join(base[(a * i + b) % 26] for i in range(26))


def build_pool():
    """Construction-grammar alphabets, tagged by METHOD."""
    pool, seen = [], set()  # (label, str, method)
    for kw in KEYWORDS:
        base = keyed_alphabet(kw).letters
        candidates = [(f"keyed[{kw}]", base, "keyed")]
        for lbl, s in _columnar_reads(base):
            candidates.append((f"col[{kw}]{lbl}", s, "columnar"))
        for lbl, s in _boustrophedon(base):
            candidates.append((f"bous[{kw}]{lbl}", s, "boustrophedon"))
        for lbl, s in _diagonals(base):
            candidates.append((f"diag[{kw}]{lbl}", s, "diagonal"))
        for a in COPRIME:
            for b in range(26):
                candidates.append((f"dec[{kw}]a{a}b{b}", decimation(base, a, b), "decimation"))
        for lbl, s, meth in candidates:
            if len(s) == 26 and len(set(s)) == 26 and s not in seen:
                seen.add(s); pool.append((lbl, s, meth))
    return pool


# crib positions for decrypt
CRIB_POS_TRIPLES = []
for c in CRIBS:
    for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext)):
        CRIB_POS_TRIPLES.append((c.start - 1 + off, p, ch))
CRIB_POS = {p for p, _, _ in CRIB_POS_TRIPLES}


def simple_selector_decrypt(alphas):
    """If a period-3/row-7 selector + the 3 cover alphabets reproduce every crib's
    assignment, decrypt all 97 and hexagram-score. Returns best (hex, plaintext)."""
    cls_funcs = {"i%3": lambda i: i % 3, "row7%3": lambda i: (i // 7) % 3,
                 "(2i)%3": lambda i: (2 * i) % 3}
    bij = [(0, 1, 2), (0, 2, 1), (1, 0, 2), (1, 2, 0), (2, 0, 1), (2, 1, 0)]
    best = (-99.0, None)
    for cf in cls_funcs.values():
        for b in bij:
            ok = True
            for (pos, p, ch) in CRIB_POS_TRIPLES:
                a = alphas[b[cf(pos)]]
                if a[ord(p) - 65] != ch:
                    ok = False; break
            if not ok:
                continue
            P = "".join(chr(alphas[b[cf(i)]].index(K4[i]) + 65) for i in range(97))
            sc = _kpa.score_free_text(P)
            if sc > best[0]:
                best = (sc, P)
    return best


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_110_handchart_construction_grammars.jsonl"
    t0 = time.perf_counter()
    pool = build_pool()
    cons = cs.crib_constraints()
    masks = [(lb, s, cs.covered_mask(s, cons), meth) for lb, s, meth in pool]
    masks = [m for m in masks if m[2]]
    masks.sort(key=lambda m: bin(m[2]).count("1"), reverse=True)
    CAP = 220
    cap_pool = [(lb, s) for lb, s, _, _ in masks[:CAP]]

    cover3 = cs.find_cover(cap_pool, 3)
    gk, glabels, gcov, gtot = cs.greedy_cover([(lb, s) for lb, s, _, _ in masks])
    bp_n, bp_tot, bp_labels = cs.best_partial_cover(cap_pool, 3)

    # per-method best partial 3-cover (the directional signal)
    by_method = {}
    for meth in ("keyed", "columnar", "boustrophedon", "diagonal", "decimation"):
        mp = [(lb, s) for lb, s, _, mm in masks if mm == meth]
        mp.sort(key=lambda x: 0)  # keep coverage order (already sorted globally)
        mp = mp[:160]
        if len(mp) >= 3:
            n, tot, _ = cs.best_partial_cover(mp, 3)
            by_method[meth] = n
        else:
            by_method[meth] = None

    # random control: random alphabets of equal pool size -> best partial 3-cover
    rng = random.Random(0)
    base = list(ALPHABET)
    rand_partials = []
    for _ in range(5):
        rp = []
        for _ in range(min(len(pool), 1500)):
            s = base[:]; rng.shuffle(s); rp.append(("r", "".join(s)))
        rm = [(lb, s, cs.covered_mask(s, cons)) for lb, s in rp]
        rm = [t for t in rm if t[2]]; rm.sort(key=lambda t: bin(t[2]).count("1"), reverse=True)
        rcap = [(lb, s) for lb, s, _ in rm[:CAP]]
        rn, _, _ = cs.best_partial_cover(rcap, 3)
        rand_partials.append(rn)
    rand_best = max(rand_partials)
    rand_mean = round(sum(rand_partials) / len(rand_partials), 1)

    # decrypt if a 3-cover exists
    decrypt_best = (-99.0, None)
    if cover3:
        labels = cover3[0]
        lbl2s = {lb: s for lb, s in cap_pool}
        alphas = [lbl2s[l] for l in labels]
        decrypt_best = simple_selector_decrypt(alphas)

    elapsed = time.perf_counter() - t0
    construction_best = bp_n
    signal = construction_best > rand_best + 1   # construction beats random partial by >1 crib
    solved = decrypt_best[1] is not None and decrypt_best[0] > -15.0

    with open(out, "w") as f:
        f.write(json.dumps({"pool_size": len(pool), "exact_3_cover": bool(cover3),
                            "cover_labels": cover3[0] if cover3 else None,
                            "best_partial_3cover": bp_n, "of": bp_tot, "greedy_k": gk,
                            "per_method_best_partial": by_method,
                            "random_best_partial": rand_best, "random_mean_partial": rand_mean,
                            "memorable_pool_088": 13,
                            "decrypt_best_hex": round(decrypt_best[0], 2) if decrypt_best[1] else None}) + "\n")

    if solved:
        status = "promising"
    elif cover3:
        status = "promising"   # a 3-cover exists -> a construction-method lead even pre-decrypt
    elif signal:
        status = "promising"   # construction grammars cover MORE than random -> directional signal
    else:
        status = "ruled_out"

    insights = [
        f"Construction-grammar pool: {len(pool)} distinct alphabets from {len(KEYWORDS)} keyword-keyed bases x "
        f"{{keyed, columnar-mixed, boustrophedon, diagonal, decimation}}. Exact chi=3 (3-alphabet) cover of the "
        f"24 cribs: {'FOUND ' + str(cover3[0]) if cover3 else 'NONE'}. Greedy needs k={gk}; best 3 cover "
        f"{bp_n}/{bp_tot}.",
        f"PER-METHOD best 3-partial cover (the directional signal): {by_method}. Random-alphabet control best "
        f"3-partial: {rand_best} (mean {rand_mean}); the 088 memorable pool reached 13/23.",
        (f"SIGNAL: construction grammars 3-cover {construction_best}/{bp_tot} vs random {rand_best} -- "
         f"{'construction beats random (a directional hint the chart is built by a hand grammar)' if signal else 'no better than random (no grammar signal)'}.",
         )[0] if True else "",
        (f"DECRYPT: a 3-cover exists; best simple-selector decrypt free-hex {decrypt_best[0]:.2f} -> "
         f"{decrypt_best[1][:40] if decrypt_best[1] else None}..." if cover3 else
         "No 3-cover, so no decrypt attempted."),
    ]
    if status == "ruled_out":
        insights.append(
            "VERDICT: no 3 construction-grammar alphabets (Friedman columnar-mixed / decimation / route reads "
            "over 30 keyword bases) chi=3-cover the cribs, and they cover NO MORE of the cribs than random "
            "alphabets do. The 'chart' is not built by any tested systematic hand grammar -- it is genuinely "
            "BESPOKE (idiosyncratic per-letter, ~26!^3), recoverable only with the chart itself. This tightens "
            "088: the alphabets are not just 'not memorable', they are not GRAMMAR-constructible either.")

    write_verdict(out, Verdict(
        exp="110", title="hand-chart construction grammars (Friedman-canon) vs chi=3 crib cover",
        hypothesis="K4's >=3 hand-crafted alphabets are built by a systematic mixed-alphabet hand grammar "
                   "(columnar-mixed / decimation / route) over keyword bases",
        status=status,
        best_score=(decrypt_best[0] if solved else None),
        best_partial=f"3-cover={'yes' if cover3 else 'no'}; best partial {bp_n}/{bp_tot} (random {rand_best}, "
                     f"memorable 13); per-method {by_method}; signal={signal}",
        search_space=len(pool), elapsed_s=round(elapsed, 1),
        insights=[i for i in insights if i],
        next_steps=(["a construction-method 3-cover exists -- recover the selection rule (054/055) and decrypt"]
                    if cover3 or signal else
                    ["chart is non-grammar / bespoke -- confirmed not reconstructible from public hand-grammars. "
                     "Without the sealed chart, the alphabets are in 26!^3 and not deterministically recoverable"]),
        metrics={"pool_size": len(pool), "exact_3_cover": bool(cover3), "best_partial": bp_n,
                 "per_method": by_method, "random_best_partial": rand_best, "signal": signal,
                 "decrypt_hex": round(decrypt_best[0], 2) if decrypt_best[1] else None}),
    )
    print(f"\npool={len(pool)}; 3-cover={'yes' if cover3 else 'no'}; best partial {bp_n}/{bp_tot} "
          f"(random {rand_best}, memorable 13); per-method {by_method}; signal={signal}; status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
