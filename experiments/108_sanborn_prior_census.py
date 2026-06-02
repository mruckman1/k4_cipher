"""108 — Sanborn-conditioned n-gram prior fed into the k=4 degeneracy census.

092/097 say k=4 is ANALYTICALLY determinable (the unicity gap is negative there),
yet exp 093 found 10 distinct crib-consistent decryptions reaching the generic
hexagram bar -> the generic n-gram prior is too weak to realise the determination.
This tests whether a stronger AUTHOR-SPECIFIC prior closes the gap: build a
deterministic char n-gram LM from Sanborn's ACTUAL K1-K3 plaintexts (his diction,
telegraphic register, intentional misspellings) and ask:
  (1) re-ranked by the Sanborn-LM, does ONE of the k=4 census decryptions stand
      sharply above the others (a lead), or are they flat (prior-robust)?
  (2) re-running the census while MAXIMISING the Sanborn-LM, do FEWER distinct
      decryptions survive than under the generic hexagram (degeneracy reduced)?
Deterministic n-gram model, NOT an LLM.

$0, local. Output: experiments/results/<date>_108_sanborn_prior_census.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import math
import random
import statistics
import time
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K4
from kryptos.cribs import CRIBS
from kryptos.scoring.lm_fitness import BackoffCharLM
from kryptos.utils import clean

e035 = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
    "e035", str(Path(__file__).parent / "035_minimum_alphabet_analysis.py")))
e035.__spec__.loader.exec_module(e035)

N, K = 97, 4
ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
FREE = list(_kpa._free_positions())
CRIB_TRIPLES = [(c.start - 1 + off, p, ch)
                for c in CRIBS for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext))]
CRIB_POS = {pos for pos, _, _ in CRIB_TRIPLES}
FREE_SET = [i for i in range(N) if i not in CRIB_POS]


def sanborn_corpus():
    parts = []
    for fn in ("k1.txt", "k2.txt", "k3.txt"):
        p = _kpa.REPO / "data" / "plaintexts" / fn
        if p.exists():
            parts.append(clean(p.read_text()))
    return "".join(parts)


def random_completion(pins, rng):
    dec = dict(pins); used = set(dec.values())
    fc = [ch for ch in ALPHA if ch not in dec]; fp = [p for p in ALPHA if p not in used]
    rng.shuffle(fp)
    for ch, p in zip(fc, fp):
        dec[ch] = p
    return dec, fc


def census(fitness, rng, restarts=24, steps=4000):
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

    pool = {}
    for _ in range(restarts):
        decmaps, fe = {}, {}
        for c in range(K):
            d, f = random_completion(pins[c], rng); decmaps[c], fe[c] = d, f
        selfree = {i: rng.randrange(K) for i in FREE_SET}
        cur = fitness(decrypt(selfree, decmaps))
        for s in range(steps):
            T = 0.5 * (0.01 / 0.5) ** (s / steps)
            if rng.random() < 0.5:
                i = rng.choice(FREE_SET); old = selfree[i]; nw = rng.randrange(K)
                if nw == old:
                    continue
                selfree[i] = nw; cand = fitness(decrypt(selfree, decmaps))
                if cand >= cur or rng.random() < math.exp((cand - cur) / max(T, 1e-6)):
                    cur = cand
                else:
                    selfree[i] = old
            else:
                c = rng.randrange(K)
                if len(fe[c]) < 2:
                    continue
                a, b = rng.sample(fe[c], 2)
                decmaps[c][a], decmaps[c][b] = decmaps[c][b], decmaps[c][a]
                cand = fitness(decrypt(selfree, decmaps))
                if cand >= cur or rng.random() < math.exp((cand - cur) / max(T, 1e-6)):
                    cur = cand
                else:
                    decmaps[c][a], decmaps[c][b] = decmaps[c][b], decmaps[c][a]
        pt = decrypt(selfree, decmaps)
        pool[pt] = round(fitness(pt), 3)
    return pool


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_108_sanborn_prior_census.jsonl"
    rng = random.Random(0)
    t0 = time.perf_counter()

    sanborn = sanborn_corpus()
    san_lm = BackoffCharLM(sanborn, maxn=4)
    san_free = lambda P: san_lm("".join(P[i] for i in FREE))

    # (1) generate the generic-hexagram k=4 census, re-score with the Sanborn-LM
    hex_pool = census(_kpa.score_free_text, rng)
    corp = clean((_kpa.REPO / "data" / "corpora" / "buchan_39steps.txt").read_text())
    rr = random.Random(7)
    es = sorted(_kpa.score_free_text(corp[(s := rr.randrange(len(corp) - N)):s + N]) for _ in range(300))
    eng_bar = es[int(0.05 * len(es))]
    hex_candidates = [pt for pt, sc in hex_pool.items() if sc >= eng_bar]
    san_scores = sorted(((san_free(pt), pt) for pt in hex_candidates), reverse=True)
    san_vals = [s for s, _ in san_scores]
    # separation: is the top Sanborn-score a clear outlier?
    sep = (san_vals[0] - statistics.mean(san_vals[1:])) / (statistics.pstdev(san_vals[1:]) or 1e-9) \
        if len(san_vals) >= 3 else 0.0

    # (2) re-run the census MAXIMISING the Sanborn-LM; count distinct above a Sanborn bar
    san_pool = census(san_free, rng)
    # Sanborn bar: 5th pct of the Sanborn-LM on its own held-out-ish 73-char windows
    sb = sorted(san_lm(sanborn[(s := rr.randrange(max(1, len(sanborn) - 73))):s + 73]) for _ in range(200)) \
        if len(sanborn) > 80 else [0.0]
    san_bar = sb[int(0.05 * len(sb))]
    san_distinct = sum(1 for sc in san_pool.values() if sc >= san_bar)

    elapsed = time.perf_counter() - t0
    with open(out, "w") as f:
        f.write(json.dumps({"sanborn_chars": len(sanborn), "n_hex_candidates": len(hex_candidates),
                            "sanborn_rescore_top": round(san_vals[0], 3) if san_vals else None,
                            "sanborn_rescore_separation_sigma": round(sep, 2),
                            "san_census_distinct_above_bar": san_distinct, "san_bar": round(san_bar, 3),
                            "hexagram_k4_distinct_was": 10}) + "\n")

    # HONEST gate: a 768-char order-4 LM is data-starved; a "separation" over a
    # handful of candidates is unreliable. Require BOTH a real separation AND
    # enough candidates for the sigma to mean anything; and treat census-distinct=0
    # as the LM's bar being UNREACHABLE (an artifact), not as determination.
    sharp = sep >= 3.0 and len(san_vals) >= 8
    cut = 1 <= san_distinct <= 4
    insights = [
        f"Built a deterministic char n-gram LM from Sanborn's ACTUAL K1-K3 plaintexts ({len(sanborn)} chars, "
        f"order-4 backoff). CAVEAT: ~768 chars is severely data-starved for a char-LM -- it is spiky and "
        f"overfits coincidental n-grams, so apparent 'signal' from it is unreliable (the only Sanborn plaintext "
        f"available is K1-K3; no larger author corpus exists under decipherment-only).",
        f"(1) RE-RANK: re-scored the {len(hex_candidates)} generic-hexagram k=4 census decryptions with the "
        f"Sanborn-LM; top-vs-rest separation = {sep:.2f} sigma over only {len(san_vals)} candidates. With so few "
        f"points and a 768-char LM this sigma is NOT statistically meaningful -> treated as no reliable signal.",
        f"(2) SANBORN-DRIVEN CENSUS: maximising the Sanborn-LM yields {san_distinct} distinct decryptions above "
        f"its own 5th-pct bar (generic hexagram gave 10 at k=4). san_distinct={san_distinct}: the bar is "
        f"{'UNREACHABLE (the spiky tiny-corpus LM bar is an artifact, not determination)' if san_distinct == 0 else 'reached by a few'} -- not evidence of reduced degeneracy.",
        ("VERDICT: the Sanborn-conditioned prior is DATA-LIMITED and does not resolve k=4: the best "
         "author-specific n-gram prior buildable from the only available Sanborn text (K1-K3, 768 chars) is too "
         "starved to single out the plaintext or to be trusted. The under-determination is PRIOR-ROBUST to the "
         "realisable author prior. Consistent with 092/093/107." if not (sharp or cut)
         else "The Sanborn prior shows a (caveated) signal -- inspect the top candidate, but discount the "
         "768-char LM heavily."),
    ]

    write_verdict(out, Verdict(
        exp="108", title="Sanborn-conditioned n-gram prior on the k=4 degeneracy census",
        hypothesis="an author-specific (K1-K3) n-gram prior tightens the k=4 census toward a unique decryption",
        status="promising" if (sharp or cut) else "inconclusive",
        best_partial=f"Sanborn re-rank separation {round(sep,2)} sigma; Sanborn-census distinct {san_distinct} "
                     f"(vs hexagram 10); prior-robust={not (sharp or cut)}",
        search_space=len(hex_candidates), elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["inspect the Sanborn-preferred candidate; cross-check against cribs and thematic content"]
                    if (sharp or cut) else
                    ["under-determination is prior-robust to an author-specific n-gram prior. Within "
                     "decipherment-only and no-LLM, the data does not single out the plaintext."]),
        metrics={"sanborn_chars": len(sanborn), "rerank_separation_sigma": round(sep, 2),
                 "sanborn_census_distinct": san_distinct, "hexagram_distinct": 10,
                 "prior_robust": not (sharp or cut)}),
    )
    print(f"\nSanborn re-rank sep {sep:.2f} sigma; Sanborn-census distinct {san_distinct} (vs hex 10); "
          f"prior_robust={not (sharp or cut)}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
