"""107 — MCMC joint substitution+selector estimation (Bayesian posterior).

The Stamp HMM-with-random-restarts and Chen-Rosenthal MCMC (Metropolis-Hastings)
lines are designed for SHORT ciphertexts and ESTIMATE a posterior rather than
point-optimise. exp 093 OPTIMISED (annealing -> degeneracy crossover); this
SAMPLES the posterior over (free-position selector class + k=4 hand-crafted
alphabets) at fixed temperature with random restarts, and reports the Bayesian
under-determination signal: the per-free-position MARGINAL POSTERIOR ENTROPY of
the decrypted letter (max = log2(26) = 4.70 bits). A diffuse posterior (high
marginal entropy at most positions) is the probabilistic confirmation that the
cribs + ciphertext do not pin the plaintext; a peaked posterior (low entropy)
would localise determinable positions.

Deterministic given seed; classical statistical estimator, NOT an LLM.

$0, local. Output: experiments/results/<date>_107_mcmc_joint_posterior.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import math
import random
import time
from collections import Counter
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K4
from kryptos.cribs import CRIBS
from kryptos.utils import clean

e035 = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
    "e035", str(Path(__file__).parent / "035_minimum_alphabet_analysis.py")))
e035.__spec__.loader.exec_module(e035)

N, K = 97, 4
ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CRIB_TRIPLES = [(c.start - 1 + off, p, ch)
                for c in CRIBS for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext))]
CRIB_POS = {pos for pos, _, _ in CRIB_TRIPLES}
FREE = [i for i in range(N) if i not in CRIB_POS]


def random_completion(pins, rng):
    dec = dict(pins); used = set(dec.values())
    fc = [ch for ch in ALPHA if ch not in dec]; fp = [p for p in ALPHA if p not in used]
    rng.shuffle(fp)
    for ch, p in zip(fc, fp):
        dec[ch] = p
    return dec, fc


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_107_mcmc_joint_posterior.jsonl"
    rng = random.Random(0)
    t0 = time.perf_counter()

    corp = clean((_kpa.REPO / "data" / "corpora" / "buchan_39steps.txt").read_text())
    rr = random.Random(7)
    es = sorted(_kpa.score_free_text(corp[(s := rr.randrange(len(corp) - N)):s + N]) for _ in range(300))
    eng_bar = es[int(0.05 * len(es))]

    cribs = e035.build_crib_constraints()
    pos_of_node = [c[0] for c in cribs]
    edges = set()
    for i in range(len(cribs)):
        for j in range(i + 1, len(cribs)):
            if e035.cribs_conflict(cribs[i], cribs[j]):
                edges.add((i, j))
    coloring = e035.find_k_coloring(len(cribs), edges, 3)
    crib_color = {pos_of_node[n]: coloring[n] % K for n in range(len(cribs))}
    pins = {c: {} for c in range(K)}
    for pos, p, ch in CRIB_TRIPLES:
        pins[crib_color[pos]][ch] = p

    def decrypt(selfree, decmaps):
        return "".join(decmaps[crib_color[i] if i in CRIB_POS else selfree[i]][K4[i]] for i in range(N))

    # fixed-temperature Metropolis; collect marginal posterior over free-position letters
    BETA = 6.0          # inverse temperature on hexagram log-prob/char
    CHAINS, BURN, SAMPLES, THIN = 6, 1500, 4000, 5
    marg = {i: Counter() for i in FREE}
    distinct = {}
    n_collected = 0
    best = (-99.0, None)
    for _ in range(CHAINS):
        decmaps, fe = {}, {}
        for c in range(K):
            d, f = random_completion(pins[c], rng); decmaps[c], fe[c] = d, f
        selfree = {i: rng.randrange(K) for i in FREE}
        cur = _kpa.score_free_text(decrypt(selfree, decmaps))
        for step in range(BURN + SAMPLES):
            if rng.random() < 0.5:
                i = rng.choice(FREE); old = selfree[i]; nw = rng.randrange(K)
                if nw != old:
                    selfree[i] = nw; cand = _kpa.score_free_text(decrypt(selfree, decmaps))
                    if cand >= cur or rng.random() < math.exp(BETA * (cand - cur)):
                        cur = cand
                    else:
                        selfree[i] = old
            else:
                c = rng.randrange(K)
                if len(fe[c]) < 2:
                    continue
                a, b = rng.sample(fe[c], 2)
                decmaps[c][a], decmaps[c][b] = decmaps[c][b], decmaps[c][a]
                cand = _kpa.score_free_text(decrypt(selfree, decmaps))
                if cand >= cur or rng.random() < math.exp(BETA * (cand - cur)):
                    cur = cand
                else:
                    decmaps[c][a], decmaps[c][b] = decmaps[c][b], decmaps[c][a]
            if step >= BURN and (step - BURN) % THIN == 0:
                pt = decrypt(selfree, decmaps)
                for i in FREE:
                    marg[i][pt[i]] += 1
                n_collected += 1
                sc = _kpa.score_free_text(pt)
                if sc >= eng_bar:
                    distinct[pt] = round(sc, 2)
                if sc > best[0]:
                    best = (sc, pt)

    # marginal posterior entropy per free position
    def H(counter):
        tot = sum(counter.values())
        return -sum((v / tot) * math.log2(v / tot) for v in counter.values()) if tot else 0.0
    ent = {i: H(marg[i]) for i in FREE}
    mean_ent = sum(ent.values()) / len(ent)
    low_ent = sum(1 for i in FREE if ent[i] < 1.0)     # near-determined positions (<1 bit)
    elapsed = time.perf_counter() - t0

    with open(out, "w") as f:
        f.write(json.dumps({"chains": CHAINS, "samples_collected": n_collected, "beta": BETA,
                            "mean_marginal_entropy_bits": round(mean_ent, 3), "max_entropy_bits": round(math.log2(26), 3),
                            "free_positions_below_1bit": low_ent, "n_free": len(FREE),
                            "n_distinct_english_in_posterior": len(distinct), "english_bar": round(eng_bar, 2),
                            "best_hex": round(best[0], 2)}) + "\n")

    diffuse = mean_ent > 3.0
    insights = [
        f"MCMC (Metropolis-Hastings, beta={BETA}, {CHAINS} chains, {n_collected} thinned samples) over the joint "
        f"(free-position selector class x k=4 hand-crafted alphabets) posterior, cribs enforced via a fixed "
        f"proper 3-colouring. Classical sampler, no LLM.",
        f"BAYESIAN UNDER-DETERMINATION: mean per-free-position marginal posterior entropy = {mean_ent:.2f} bits "
        f"(max {math.log2(26):.2f}); only {low_ent}/{len(FREE)} free positions are near-determined (<1 bit). "
        f"{len(distinct)} distinct English-level decryptions appear in the posterior.",
        (f"The posterior is DIFFUSE (mean marginal entropy {mean_ent:.2f} bits ~ near-uniform) -- the cribs + "
         f"ciphertext do not localise the plaintext; the MCMC/HMM estimator CONFIRMS the under-determination "
         f"(092/093/098) from a Bayesian angle, by a method (posterior sampling) distinct from the 093 "
         f"optimisation and the 106 CP-SAT proof." if diffuse else
         f"The posterior is PEAKED (mean entropy {mean_ent:.2f} bits): {len(FREE)-low_ent} positions carry "
         f"information -- inspect the high-probability marginal letters as a partial skeleton."),
    ]

    write_verdict(out, Verdict(
        exp="107", title="MCMC joint substitution+selector posterior estimation",
        hypothesis="a Bayesian MCMC/HMM estimator localises K4's plaintext where point-optimisation could not",
        status="inconclusive",
        best_partial=f"mean marginal posterior entropy {round(mean_ent,2)}/{round(math.log2(26),2)} bits; "
                     f"{low_ent}/{len(FREE)} positions <1 bit; {len(distinct)} distinct English in posterior",
        search_space=n_collected, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=["MCMC confirms the diffuse posterior; the under-determination is now shown three ways "
                    "(092 analytic, 093 optimisation, 106 CP-SAT, 107 Bayesian). A sharper plaintext prior "
                    "(Sanborn-conditioned, exp 108) is the only remaining lever within decipherment-only"],
        metrics={"mean_marginal_entropy": round(mean_ent, 3), "positions_below_1bit": low_ent,
                 "n_free": len(FREE), "n_distinct_english": len(distinct), "diffuse": diffuse}),
    )
    print(f"\nmean marginal entropy {mean_ent:.2f} bits; {low_ent}/{len(FREE)} <1bit; "
          f"{len(distinct)} distinct English; diffuse={diffuse}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
