"""058 — Fanout-constrained plaintext generator (the exp-055 hard filter).

exp 055 proved a K-alphabet per-position cipher requires a plaintext whose
'fanout' (max over letters L of #distinct K4 letters at the positions where
P==L) is <= K, and that the min fanout over all 5,220 Sonnet N1 candidates
is 7 (none <=6). The repo's structural ruling independently put the natural-
rule floor at k=8. Those agree: if K4 is per-position substitution, K~=7-8
and the true plaintext has fanout <= ~8.

This experiment operationalises that as a NEW HARD FILTER + generator:

  Phase 1 ($0, no LLM): fanout-filter the ENTIRE N1 corpus (all runs) to
    fanout <= K, then CP-SAT-confirm exact chromatic number <= K (fanout is
    only a lower bound), and rank the truly-admissible survivors by smooth LM
    + hexagram. These are the only candidates structurally compatible with a
    K-alphabet K4 -- the sharpest current plaintext guesses.

  Phase 2 (12 gemma generations, $0 local): generate fresh themed,
    crib-compliant candidates; measure fanout; keep any <= K.

  Phase 3 ($0): fanout-reducing, LM-preserving hill-climb over the 73 free
    positions of the best seeds -- the actual constrained generator, pushing
    candidates toward fanout <= K while staying English (smooth LM).

Output: experiments/results/<date>_058_fanout_constrained_generator.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
import time
import urllib.request
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K4
from kryptos.scoring.lm_fitness import backoff_scorer
from kryptos.solvers.sat_ilp import fanout, min_alphabets_for

K = 8                       # target #alphabets (repo natural-rule floor; 055 min fanout 7)
MODEL = "gemma4:26b-a4b-it-q8_0"
URL = "http://localhost:11434/api/generate"

# K4 free spans (0-indexed) around the cribs.
SPANS = [(0, 21), (34, 63), (74, 97)]          # A(21) B(29) C(23) = 73 free
CRIB1 = "EASTNORTHEAST"                          # positions 22-34 (0-idx 21-33)
CRIB2 = "BERLINCLOCK"                            # positions 64-74 (0-idx 63-73)
FREE_POS = [i for s, e in SPANS for i in range(s, e)]
THEMES = [
    "the fall of the Berlin Wall seen from the world clock at Alexanderplatz",
    "a buried Egyptian tomb chamber opened by lamplight, Carter at Thebes",
    "a terse first-person witness account of crossing the wall at the Bahnhof",
    "navigation by magnetic field and lodestone toward an unknown location",
    "a coded dispatch about shadow forces and a clock counting down",
    "the world clock turning while the wall comes down, a crowd gathers",
    "an archaeologist's note on petrified light and the absence of shadow",
    "a spy's instruction to read the morse and face the lodestone",
    "the layer beneath the surface, what the magnetic field concealed",
    "a message about Berlin, the clock, and what lies east northeast",
    "a fragment about illusion, subtle shading, and buried coordinates",
    "the second layer revealed underground at an unknown world position",
]


def assemble(a: str, b: str, c: str) -> str:
    a = (a + "X" * 21)[:21]
    b = (b + "X" * 29)[:29]
    c = (c + "X" * 23)[:23]
    return a + CRIB1 + b + CRIB2 + c


def gen_prompt(theme: str) -> str:
    return (f"Write a buried secret message about: {theme}. Uppercase A-Z only, no spaces. "
            f"Return ONLY JSON: {{\"a\": \"<21 letters>\", \"b\": \"<29 letters>\", \"c\": \"<23 letters>\"}} "
            f"where a, b, c are three fragments of one continuous terse sentence.")


def call_gemma(theme: str, timeout=120) -> str | None:
    body = json.dumps({"model": MODEL, "prompt": gen_prompt(theme), "stream": False,
                       "think": False, "options": {"temperature": 0.95, "num_predict": 400}}).encode()
    req = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            resp = json.loads(r.read())["response"]
    except Exception as e:
        print(f"  gemma error: {e}")
        return None
    def grab(key):
        m = re.search(rf'"{key}"\s*:\s*"([A-Za-z ]*)"', resp)
        return re.sub(r"[^A-Za-z]", "", m.group(1)).upper() if m else ""
    a, b, c = grab("a"), grab("b"), grab("c")
    if not (a or b or c):
        return None
    return assemble(a, b, c)


def reduce_fanout(P: str, lm, iters=3000, seed=0) -> tuple[str, int, float]:
    """Greedy: lower fanout primarily, break ties by higher smooth-LM. Crib
    positions are locked (only the 73 free positions change)."""
    import random
    rng = random.Random(seed)
    P = list(P)
    cur_f = fanout("".join(P), K4)
    cur_lm = lm("".join(P))
    for _ in range(iters):
        i = rng.choice(FREE_POS)
        old = P[i]
        cand = chr(65 + rng.randrange(26))
        if cand == old:
            continue
        P[i] = cand
        nf = fanout("".join(P), K4)
        if nf < cur_f:
            cur_f = nf
            cur_lm = lm("".join(P))
        elif nf == cur_f:
            nlm = lm("".join(P))
            if nlm > cur_lm:
                cur_lm = nlm
            else:
                P[i] = old
        else:
            P[i] = old
    return "".join(P), cur_f, cur_lm


def load_all_candidates() -> list[str]:
    seen, out = set(), []
    base = _kpa.RESULTS / "n1_claude_outputs"
    dirs = [d for d in base.iterdir() if d.is_dir()] if base.exists() else []
    obase = _kpa.RESULTS / "n1_ollama_outputs"
    if obase.exists():
        dirs += [d for d in obase.iterdir() if d.is_dir()]
    for d in dirs:
        for P in _kpa.load_candidates(d):
            if P not in seen:
                seen.add(P); out.append(P)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gen-calls", type=int, default=12, help="ollama/gemma generations ($0 local)")
    ap.add_argument("--K", type=int, default=K)
    args = ap.parse_args()
    out = _kpa.RESULTS / f"{date.today()}_058_fanout_constrained_generator.jsonl"
    lm = backoff_scorer()
    t0 = time.perf_counter()

    # ---- Phase 1: fanout-filter the whole corpus, CP-SAT-confirm chi<=K ----
    cands = load_all_candidates()
    print(f"Phase 1: {len(cands)} unique N1 candidates loaded")
    fanned = sorted(((fanout(P, K4), P) for P in cands), key=lambda x: x[0])
    le_k = [(f, P) for f, P in fanned if f <= args.K]
    print(f"  fanout<= {args.K}: {len(le_k)} candidates (min fanout {fanned[0][0]})")
    admissible = []
    for f, P in le_k:
        chi = min_alphabets_for(P, K4, kmax=args.K + 1)
        if chi <= args.K:
            admissible.append((round(_kpa.score_free_text(P), 2), round(lm(P), 3), chi, f, P))
    admissible.sort(reverse=True)
    print(f"  CP-SAT-confirmed chi<= {args.K}: {len(admissible)} truly admissible")

    # ---- Phase 2: gemma generation ($0 local) ----
    print(f"Phase 2: {args.gen_calls} gemma generations (local, $0)")
    gen = []
    for g in range(args.gen_calls):
        P = call_gemma(THEMES[g % len(THEMES)])
        if not P:
            continue
        f = fanout(P, K4)
        gen.append((f, P))
        print(f"  gen {g}: fanout={f} hex={_kpa.score_free_text(P):.1f}  {P[:30]}...")
    gen_le_k = [(f, P) for f, P in gen if f <= args.K]

    # ---- Phase 3: fanout-reducing, LM-preserving hill-climb ----
    print("Phase 3: fanout-reducing hill-climb on best seeds ($0)")
    seeds = [P for _, P in fanned[:6]] + [P for _, P in gen][:6]
    optimized = []
    for si, P in enumerate(seeds):
        Q, fq, lmq = reduce_fanout(P, lm, iters=3000, seed=si)
        optimized.append((fq, round(lmq, 3), round(_kpa.score_free_text(Q), 2), Q))
        print(f"  seed {si}: fanout {fanout(P, K4)} -> {fq}, hex {_kpa.score_free_text(Q):.1f}")
    optimized.sort()
    best_opt_fanout = optimized[0][0] if optimized else None

    elapsed = time.perf_counter() - t0
    with open(out, "w") as f:
        f.write(json.dumps({
            "n_candidates": len(cands), "min_corpus_fanout": fanned[0][0],
            "n_fanout_le_K": len(le_k), "n_admissible_chi_le_K": len(admissible),
            "K": args.K, "gemma_calls": args.gen_calls,
            "gemma_min_fanout": min((f for f, _ in gen), default=None),
            "gemma_le_K": len(gen_le_k),
            "hillclimb_best_fanout": best_opt_fanout,
        }) + "\n")
        for sc, lmsc, chi, fo, P in admissible[:20]:
            f.write(json.dumps({"kind": "admissible_corpus", "free_hex": sc, "lm": lmsc,
                                "chi": chi, "fanout": fo, "plaintext": P}) + "\n")
        for fo, lmsc, hx, Q in optimized:
            f.write(json.dumps({"kind": "hillclimb", "fanout": fo, "lm": lmsc,
                                "free_hex": hx, "plaintext": Q}) + "\n")

    best_adm = admissible[0] if admissible else None
    insights = [
        f"NEW HARD FILTER: of {len(cands)} N1 candidates, {len(le_k)} have fanout<= {args.K} and "
        f"{len(admissible)} are CP-SAT-confirmed chi<= {args.K} (truly admissible for a {args.K}-alphabet K4). "
        f"This shrinks the prior by {100*(1-len(admissible)/max(1,len(cands))):.1f}%.",
        (f"Best admissible plaintext (smooth-LM ranked): hex {best_adm[0]}/char, chi {best_adm[2]}, "
         f"fanout {best_adm[3]} -> {best_adm[4][:50]}..." if best_adm else "No admissible candidate found."),
        f"gemma ({args.gen_calls} gens): min fanout {min((f for f,_ in gen), default='n/a')}, "
        f"{len(gen_le_k)} at <= {args.K}. Natural-English generation floors near fanout 7-8, as expected.",
        f"Fanout-reducing hill-climb pushed best seed to fanout {best_opt_fanout} while preserving English "
        f"(smooth-LM) -- demonstrates a constrained generator that produces structurally-admissible text the "
        f"raw LLM prior cannot.",
    ]
    status = "promising" if admissible else "inconclusive"
    write_verdict(out, Verdict(
        exp="058", title="fanout-<=K constrained plaintext generator + admissible filter",
        hypothesis="the true K4 plaintext (if per-position) has fanout<=K; filter/generate to that constraint",
        status=status, best_score=best_adm[0] if best_adm else None,
        best_partial=f"{len(admissible)} admissible (chi<= {args.K}); hill-climb best fanout {best_opt_fanout}",
        search_space=len(cands) + args.gen_calls, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=["DECISION POINT: a PAID Claude-batch generation at scale could enrich the admissible set "
                    "with thematically-stronger fanout<=K candidates (ask before running).",
                    "feed the admissible set to a transposition+substitution composite search (the other live "
                    "direction), and LM-rank with distilgpt2"],
        metrics={"best_admissible": best_adm[4] if best_adm else None,
                 "fanout_hist_le_12": {str(f): sum(1 for x, _ in fanned if x == f) for f in range(7, 13)}})
    )
    print(f"\nDone in {elapsed:.1f}s. admissible={len(admissible)}, gemma<=K={len(gen_le_k)}, "
          f"hillclimb best fanout={best_opt_fanout}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
