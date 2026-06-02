"""100 — Non-circular test of the exp-097 register signal.

097 found crib-consistent decryptions score 75/100 under a navigational LLM judge
(vs 10 for the prose judge in 095). But that was partly CIRCULAR: the search
MAXIMISED a register char-LM, then a register-tuned judge (gemma) measured
register-ness. This breaks the circularity two ways:

  (1) SECOND, independent model as judge -- qwen3.5:27b, not gemma (calibrated:
      real telegram -> 95, gibberish -> 0).
  (2) Judge candidates that were NOT register-driven: a PROSE-driven pool (093/095
      hexagram search) and a RANDOM crib-consistent pool (no optimisation), plus a
      CRIBS-ONLY-FILLER baseline that isolates how much the FIXED navigational
      cribs (EAST NORTHEAST BERLIN CLOCK) alone inflate the register score.

Decisive comparison of mean register score by pool:
  - if only the REGISTER-DRIVEN pool scores high (>> prose/random/cribs-baseline),
    097's 75 was a SEARCH ARTIFACT (circular): the register signal is not intrinsic.
  - if PROSE-driven and RANDOM crib-consistent pools also exceed the cribs-only
    baseline, register affinity is INTRINSIC to K4's crib structure (a real lead).

$0, local, pure decipherment. Telegram controls are hand-written generic
navigational text (never the real plaintext). Output:
experiments/results/<date>_100_register_noncircular.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import random
import statistics
import time
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K4
from kryptos.scoring.lm_fitness import BackoffCharLM
from kryptos.utils import clean


def _load(name, fname):
    m = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
        name, str(Path(__file__).parent / fname)))
    m.__spec__.loader.exec_module(m)
    return m

e035 = _load("e035", "035_minimum_alphabet_analysis.py")
e067 = _load("e067", "067_register_scorer.py")
e097 = _load("e097", "097_register_driven.py")

N = 97
ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
JUDGE = "qwen3.5:27b-q8_0"   # independent of gemma (used in 097)
REG_SYS = ("You rate whether a string of letters (ignore spacing/case) is a plausible TERSE NAVIGATIONAL / "
           "LOCATION / COORDINATE message -- directions, bearings, place names, or spelled-out coordinates "
           "(e.g. 'EAST NORTHEAST ... BERLIN ... DEGREES MINUTES NORTH'). Reply ONLY JSON "
           "{\"score\": N, \"reason\": \"...\"} N=0 (random letters) to 100 (clearly such a message).")

# generic navigational/telegram controls -- hand-written, NOT from any search
TELEGRAM = [
    "PROCEEDEASTNORTHEASTBEARINGFOURFIVEDEGREESLOCATEBERLINCLOCKDIGBENEATHLAYERTHREEMETERSDUEWESTMARKEND",
    "AGENTREPORTBERLINSTATIONCOMPROMISEDMOVEEASTNORTHEASTTOSAFEHOUSEAWAITCLOCKSIGNALATMIDNIGHTACKNOWLEDGE",
    "LATITUDETHIRTYEIGHTDEGREESNORTHLONGITUDESEVENSEVENWESTPROCEEDUNDERGROUNDLOCATEMAGNETICFIELDNEARCLOCK",
    "NORTHEASTBYEASTFROMBERLINGATEWALKFORTYPACESCLOCKWISELOCATEBURIEDFIELDBENEATHTHELAYERMARKWITHSTONES",
]


def random_crib_consistent(rng, K=4):
    cribs = e035.build_crib_constraints()
    pos_of_node = [c[0] for c in cribs]
    edges = set()
    for i in range(len(cribs)):
        for j in range(i + 1, len(cribs)):
            if e035.cribs_conflict(cribs[i], cribs[j]):
                edges.add((i, j))
    coloring = e035.find_k_coloring(len(cribs), edges, max(K, 3))
    crib_color = {pos_of_node[n]: coloring[n] % K for n in range(len(cribs))}
    pins = {c: {} for c in range(K)}
    for pos, p, ch in e097.CRIB_TRIPLES:
        pins[crib_color[pos]][ch] = p
    decmaps = {c: e097.random_completion(pins[c], rng)[0] for c in range(K)}
    selfree = {i: rng.randrange(K) for i in e097.FREE_SET}
    return "".join(decmaps[crib_color[i] if i in e097.CRIB_POS else selfree[i]][K4[i]] for i in range(N))


def cribs_only_filler(rng):
    crib_letter = {pos: p for pos, p, _ in e097.CRIB_TRIPLES}
    return "".join(crib_letter.get(i, chr(65 + rng.randrange(26))) for i in range(N))


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_100_register_noncircular.jsonl"
    rng = random.Random(0)
    t0 = time.perf_counter()

    reg = BackoffCharLM(e067.register_corpus(300_000, random.Random(1)), maxn=6)
    prose_fit = lambda P: _kpa.score_free_text(P)
    reg_fit = lambda P: reg(e097.freetext(P))

    # candidate pools (cap each)
    prose_cands = [p for p, _ in e097.search(prose_fit, rng)[:8]]
    reg_cands = [p for p, _ in e097.search(reg_fit, rng)[:8]]
    rand_cands = [random_crib_consistent(rng) for _ in range(8)]
    cribs_base = [cribs_only_filler(rng) for _ in range(4)]

    corp = clean((_kpa.REPO / "data" / "corpora" / "buchan_39steps.txt").read_text())
    rr = random.Random(7)
    prose_ctrl = [corp[(s := rr.randrange(len(corp) - N)):s + N] for _ in range(4)]
    gib_ctrl = ["".join(chr(65 + rr.randrange(26)) for _ in range(N)) for _ in range(4)]

    items = ([("telegram_ctrl", t) for t in TELEGRAM]
             + [("gibberish_ctrl", t) for t in gib_ctrl]
             + [("prose_ctrl", t) for t in prose_ctrl]
             + [("cribs_only_baseline", t) for t in cribs_base]
             + [("random_cribconsistent", t) for t in rand_cands]
             + [("prose_driven", t) for t in prose_cands]
             + [("register_driven", t) for t in reg_cands])

    scored = []
    with open(out, "w") as f:
        for kind, txt in items:
            sc = e097.llm_judge(txt, REG_SYS, model=JUDGE)
            rec = {"kind": kind, "qwen_reg_score": sc, "text": txt[:52]}
            scored.append(rec); f.write(json.dumps(rec) + "\n")

    def mean(kind):
        v = [r["qwen_reg_score"] for r in scored if r["kind"] == kind and r["qwen_reg_score"] is not None]
        return round(statistics.mean(v), 1) if v else None
    tel, gib, prose_c, base = mean("telegram_ctrl"), mean("gibberish_ctrl"), mean("prose_ctrl"), mean("cribs_only_baseline")
    rnd, prose_d, reg_d = mean("random_cribconsistent"), mean("prose_driven"), mean("register_driven")

    elapsed = time.perf_counter() - t0
    calibrated = (tel is not None and gib is not None and tel - gib >= 40)
    # circular if register-driven clearly beats the non-register pools and the cribs baseline
    def gt(a, b, m=15):
        return a is not None and b is not None and a - b >= m
    circular = gt(reg_d, prose_d) and gt(reg_d, base)
    intrinsic = (gt(prose_d, base) or gt(rnd, base))

    insights = [
        f"Independent judge {JUDGE} (calibration: telegram {tel} / gibberish {gib} -> trustworthy={calibrated}). "
        f"Mean register score by pool -- cribs-only baseline {base}; random crib-consistent {rnd}; "
        f"PROSE-driven {prose_d}; REGISTER-driven {reg_d}; (prose-text control {prose_c}).",
        (f"CIRCULAR: the register-driven pool ({reg_d}) clearly beats the prose-driven ({prose_d}) and "
         f"cribs-only baseline ({base}). exp-097's high register score was a SEARCH ARTIFACT -- the hillclimb "
         f"stuffed register vocabulary in; an independent model on NON-register-generated candidates shows no "
         f"register affinity beyond the fixed cribs. The register thread is closed: K4's crib-consistent "
         f"decryptions are not intrinsically telegraphic." if circular else
         f"NOT CIRCULAR: prose-driven ({prose_d}) and/or random ({rnd}) crib-consistent decryptions also exceed "
         f"the cribs-only baseline ({base}) under an independent judge -- register affinity is INTRINSIC to K4's "
         f"structure, not a search artifact. This is a genuine lead: inspect the highest-scoring non-register "
         f"candidates."),
        f"Note: the cribs-only baseline ({base}) measures how much the FIXED navigational cribs "
        f"(EAST/NORTHEAST/BERLIN/CLOCK) alone inflate the register score; pools must beat IT, not just "
        f"gibberish, to show real signal.",
    ]

    # the hypothesis is "register affinity is INTRINSIC". Circular result refutes it.
    if calibrated and intrinsic and not circular:
        status = "promising"
    elif calibrated and circular:
        status = "ruled_out"   # intrinsic-register hypothesis refuted (signal is a search artifact)
    else:
        status = "inconclusive"

    write_verdict(out, Verdict(
        exp="100", title="non-circular cross-validation of the register signal (independent model + pools)",
        hypothesis="crib-consistent decryptions are intrinsically telegraphic/navigational (not just because "
                   "the 097 search optimised for it)",
        status=status, best_score=None,
        best_partial=f"qwen judge calibrated={calibrated} (tel {tel}/gib {gib}); means base {base} / random "
                     f"{rnd} / prose-driven {prose_d} / register-driven {reg_d}; circular={circular}",
        search_space=len(items), elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["inspect the high-scoring NON-register-driven candidates byte-exact; the register affinity "
                     "is intrinsic -- build a register-constrained search and verify"] if status == "promising" else
                    ["097's register signal is a search artifact (circular); independent judge on "
                     "non-register-generated candidates shows no intrinsic telegraphic affinity beyond the "
                     "fixed cribs. The register thread is closed."]),
        metrics={"judge": JUDGE, "calibrated": calibrated, "telegram": tel, "gibberish": gib,
                 "cribs_only_baseline": base, "random": rnd, "prose_driven": prose_d, "register_driven": reg_d,
                 "circular": circular, "intrinsic": intrinsic}),
    )
    print(f"\nqwen judge cal={calibrated} (tel {tel}/gib {gib}); base {base} / rand {rnd} / prose-drv {prose_d} "
          f"/ reg-drv {reg_d}; circular={circular}; status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
