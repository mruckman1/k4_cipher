"""096 — MaxSAT/SMT (Z3) global max-likelihood decryption: is the 093/095
degeneracy a true global property, or just annealing stuck in local optima?

093 (annealing) and 095 (LLM re-rank) both relied on a stochastic local search.
A skeptic could argue the meaningless decryptions are an artifact of weak search,
and that a GLOBAL optimizer would find the real English plaintext. This rules
that out: encode the per-position substitution exactly as a weighted MaxSAT and
let Z3's optimizer (nuZ) find the provably/best-effort GLOBAL optimum.

Model (k=3, a fixed proper 3-colouring of the cribs, as in 093 Part B): three
decryption alphabets dec_c (cipher->plain), each a bijection (Distinct). Hard
constraints: the 24 cribs. Each plaintext position P[i] = dec_{colour(i)}[C_i] is
exactly ONE Z3 integer variable (colour(i) and C_i are constants) -- so no array
theory is needed. Soft constraints reward common English BIGRAMS: for every
adjacent pair and every top English bigram (X,Y), a soft clause AND(P[i]=X,
P[i+1]=Y) with weight ~ bigram frequency. Z3 maximises total satisfied weight =
the most-English decryption the k=3 model can produce.

If Z3's global optimum is still sub-English / meaningless (low hexagram, low LLM
score), the degeneracy/under-determination is a TRUE property of the model, not a
search artifact -- the cleanest possible confirmation of 092/093/095. If Z3 finds
a dramatically more English decryption than annealing, that is itself important.

$0, local, pure decipherment. Output:
experiments/results/<date>_096_maxsat_global_optimum.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import re
import time
import urllib.request
from collections import Counter
from datetime import date
from pathlib import Path

import z3

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K4
from kryptos.cribs import CRIBS
from kryptos.utils import clean

e035 = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
    "e035", str(Path(__file__).parent / "035_minimum_alphabet_analysis.py")))
e035.__spec__.loader.exec_module(e035)

N = 97
K = 3
CIDX = lambda ch: ord(ch) - 65

CRIB_TRIPLES = [(c.start - 1 + off, p, ch)
                for c in CRIBS for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext))]
CRIB_POS = {pos for pos, _, _ in CRIB_TRIPLES}


def top_bigrams(n_top=40):
    corp = clean((_kpa.REPO / "data" / "corpora" / "buchan_39steps.txt").read_text())
    bc = Counter(corp[i:i + 2] for i in range(len(corp) - 1))
    tot = sum(bc.values())
    common = bc.most_common(n_top)
    return [((CIDX(b[0]), CIDX(b[1])), round(1000 * cnt / tot)) for b, cnt in common]


def llm_score(text, model="gemma4:31b-it-q8_0"):
    sys = ("You rate whether a string of letters (ignore spacing/case) is a MEANINGFUL, grammatical "
           "English message. Reply ONLY with JSON: {\"score\": N, \"reason\": \"...\"} N=0..100.")
    body = {"model": model, "messages": [{"role": "system", "content": sys}, {"role": "user", "content": text}],
            "stream": False, "think": False, "options": {"num_predict": 120, "temperature": 0}}
    try:
        req = urllib.request.Request("http://localhost:11434/api/chat", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        r = json.loads(urllib.request.urlopen(req, timeout=240).read())
        c = re.sub(r"<think>.*?</think>", "", r.get("message", {}).get("content", ""), flags=re.S)
        m = re.search(r'"score"\s*:\s*(\d+)', c)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_096_maxsat_global_optimum.jsonl"
    t0 = time.perf_counter()

    cribs = e035.build_crib_constraints()
    pos_of_node = [c[0] for c in cribs]
    edges = set()
    for i in range(len(cribs)):
        for j in range(i + 1, len(cribs)):
            if e035.cribs_conflict(cribs[i], cribs[j]):
                edges.add((i, j))
    coloring = e035.find_k_coloring(len(cribs), edges, 3)
    colour = {pos_of_node[n]: coloring[n] % K for n in range(len(cribs))}
    # extend colour to all 97 positions: free positions get a fixed colour by i%K
    # (a concrete, simple completion; the optimiser still has full alphabet freedom)
    full_colour = {i: (colour[i] if i in CRIB_POS else i % K) for i in range(N)}

    def build_dec(solver):
        d = [[z3.Int(f"d_{c}_{j}") for j in range(26)] for c in range(K)]
        for c in range(K):
            for j in range(26):
                solver.add(d[c][j] >= 0, d[c][j] <= 25)
            solver.add(z3.Distinct(d[c]))
        for pos, p, ch in CRIB_TRIPLES:
            solver.add(d[colour[pos]][CIDX(ch)] == CIDX(p))
        return d

    def extract(model, d):
        decsol = [[model.evaluate(d[c][j]).as_long() for j in range(26)] for c in range(K)]
        return "".join(chr(decsol[full_colour[i]][CIDX(K4[i])] + 65) for i in range(N))

    # (1) fast SAT pre-check: do crib-consistent decryptions exist at all?
    s = z3.Solver(); s.set("timeout", 20000)
    dsat = build_dec(s)
    sat_res = s.check()
    sat_example = extract(s.model(), dsat) if sat_res == z3.sat else None

    # (2) leaner global optimisation: top bigrams, FREE-touching pairs only
    opt = z3.Optimize()
    opt.set("timeout", 280000)  # ms
    dec = build_dec(opt)
    P = [dec[full_colour[i]][CIDX(K4[i])] for i in range(N)]
    bigrams = top_bigrams(12)
    nsoft = 0
    for i in range(N - 1):
        if i in CRIB_POS and (i + 1) in CRIB_POS:
            continue  # crib-internal bigram is fixed by the cribs -> no freedom to reward
        for (x, y), w in bigrams:
            opt.add_soft(z3.And(P[i] == x, P[i + 1] == y), w)
            nsoft += 1

    res = opt.check()
    plaintext = None
    completed = res == z3.sat
    try:                          # best-effort model even on 'unknown' (timeout)
        plaintext = extract(opt.model(), dec)
    except Exception:
        plaintext = None

    elapsed = time.perf_counter() - t0
    hexs = _kpa.score_free_text(plaintext) if plaintext else None
    sat_hex = _kpa.score_free_text(sat_example) if sat_example else None
    corp = clean((_kpa.REPO / "data" / "corpora" / "buchan_39steps.txt").read_text())
    import random
    rr = random.Random(7)
    es = sorted(_kpa.score_free_text(corp[(s2 := rr.randrange(len(corp) - N)):s2 + N]) for _ in range(300))
    eng_bar = es[int(0.05 * len(es))]
    llm = llm_score(plaintext) if plaintext else None
    # Z3 objective bounds (even without a full model, these bound the optimum)
    try:
        obj_lo = str(opt.lower(opt.objectives()[0])) if opt.objectives() else None
        obj_hi = str(opt.upper(opt.objectives()[0])) if opt.objectives() else None
    except Exception:
        obj_lo = obj_hi = None

    # honest case analysis
    if completed:
        mode = "global_optimum_proven"
    elif plaintext is not None:
        mode = "best_effort_partial"   # timed out, but a (non-proven-optimal) model was returned
    else:
        mode = "no_model_timeout"       # optimization intractable in budget

    with open(out, "w") as f:
        f.write(json.dumps({"z3_opt_result": str(res), "mode": mode, "n_soft": nsoft,
                            "sat_precheck": str(sat_res), "sat_example_hex": (round(sat_hex, 2) if sat_hex else None),
                            "plaintext": plaintext, "free_hexagram": (round(hexs, 2) if hexs is not None else None),
                            "english_bar": round(eng_bar, 2), "llm_score": llm,
                            "obj_lower": obj_lo, "obj_upper": obj_hi,
                            "annealing_k3_best_hex": -15.88}) + "\n")

    reaches_english = hexs is not None and hexs >= eng_bar
    meaningful = (llm is not None and llm >= 60)
    lead = reaches_english and meaningful
    status = "promising" if lead else "inconclusive"

    insights = [
        f"SAT pre-check (hard cribs + 3 bijective alphabets, no objective): {sat_res} -- crib-consistent "
        f"decryptions {'EXIST (many; e.g. free-hex ' + str(round(sat_hex,2)) + ')' if sat_res == z3.sat else 'NONE'}. "
        f"This alone re-confirms the model is satisfiable with large solution multiplicity (cf. 092/093).",
        f"Z3 Optimize (k=3, {nsoft} soft top-bigram rewards on free-touching pairs, 280s budget): result {res}, "
        f"mode '{mode}', runtime {elapsed:.1f}s. Objective bounds [{obj_lo}, {obj_hi}].",
    ]
    if mode == "no_model_timeout":
        insights.append(
            "HONEST RESULT: the SMT MaxSAT optimisation did NOT complete and returned no model in budget -- the "
            "Distinct + thousands-of-soft-clauses MaxSAT is intractable for Z3 at this scale. This is a "
            "statement about SOLVER SCALING, NOT about the optimum. So 096 does not add a clean global-optimum "
            "confirmation. The under-determination conclusion rests on 092 (analytic), 093 (multi-restart "
            "annealing: degeneracy turns on at k=4) and 095 (a 31B LLM rates all crib-consistent decryptions "
            "meaningless) -- all of which already establish it without needing the global optimum.")
        nxt = ["MaxSAT route is solver-limited; do NOT over-invest. The bound is established by 092/093/095. "
               "Honest endpoint: write up the bounded/under-determined negative."]
    elif mode == "best_effort_partial":
        insights.append(
            f"Z3 returned a best-effort (NOT proven-optimal) decryption on timeout: free-hex {hexs:.2f} (bar "
            f"{eng_bar:.2f}), LLM {llm}/100 -- {'MEANINGLESS' if not meaningful else 'meaningful (verify!)'}. As a "
            f"lower bound this is consistent with 093 annealing (-15.88) and 095 (meaningless); it does not "
            f"overturn the under-determination, and is not a proven global optimum.")
        nxt = ["best-effort only; the under-determination stands on 092/093/095. Write up the bounded negative."]
    else:  # proven optimum
        insights.append(
            f"Z3 GLOBAL optimum (k=3, this objective): free-hex {hexs:.2f} (bar {eng_bar:.2f}), LLM {llm}/100 -- "
            f"{'MEANINGLESS -> the degeneracy is a TRUE global property, not an annealing artifact (cf. 093 best -15.88)' if not meaningful else 'MEANINGFUL -> a genuine candidate the stochastic searches missed; verify byte-exact'}.")
        nxt = (["verify the global optimum byte-exact against the cribs; cross-check LLM with a 2nd model"]
               if lead else
               ["global optimization confirms 093/095: cipher + language prior is exhausted (n-gram, LLM, and "
                "global MaxSAT all agree). Honest endpoint: the bounded/under-determined writeup."])

    write_verdict(out, Verdict(
        exp="096", title="Z3 MaxSAT global max-likelihood decryption (k=3)",
        hypothesis="a global optimizer (not stochastic search) finds a meaningful English decryption the "
                   "annealing in 093/095 missed",
        status=status, best_score=(hexs if lead else None),
        best_partial=f"SAT precheck {sat_res}; Optimize {res} (mode {mode}); "
                     + (f"free-hex {round(hexs,2)}, LLM {llm}" if hexs is not None else "no model in budget")
                     + f"; vs annealing -15.88",
        search_space=nsoft, elapsed_s=round(elapsed, 1),
        insights=insights, next_steps=nxt,
        metrics={"z3_opt_result": str(res), "mode": mode, "sat_precheck": str(sat_res),
                 "free_hexagram": (round(hexs, 2) if hexs is not None else None), "llm_score": llm,
                 "english_bar": round(eng_bar, 2), "annealing_k3_best": -15.88, "n_soft": nsoft}),
    )
    print(f"\nSAT precheck {sat_res}; Optimize {res} mode={mode} ({elapsed:.1f}s); "
          f"{'free-hex '+str(round(hexs,2))+' LLM '+str(llm) if hexs is not None else 'no model'}; "
          f"status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
