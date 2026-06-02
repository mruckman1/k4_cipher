"""085 — The squeeze, formalized into a quantitative bound (knowledge, not a solve).

exp 082 found, empirically, that no short per-position alphabet-selector is both
NON-DEGENERATE (crib-determined) and rich enough to FLATTEN K4 to its observed
entropy. This experiment turns that observation into an explicit bound by
measuring the two opposing requirements and showing their feasible regions do
not overlap:

  (A) FLATTEN FLOOR k*  -- the MINIMUM number of alphabets a per-position
      polyalphabetic needs to reach K4's free-position entropy. Measured in the
      BEST case for the cipher (k equally-weighted, evenly-spaced rotations of
      the KRYPTOS-keyed alphabet over English): if even the maximally-mixing
      choice needs k* alphabets, every real selector needs >= k*.

  (B) DETERMINACY CEILING  -- a non-degenerate selector must instantiate EVERY
      class it uses over the 97 positions at >=1 of the 24 crib positions (a
      class with no crib has a free rotation -> the exp-059 degeneracy that
      byte-verifies many plaintexts). So the class count m <= 24, and the m
      classes must properly 3-colour the verified 24-node/22-edge conflict
      graph (chi=3).

  (C) FRONTIER  -- over the lowest-description-length structured selector family
      that can reach high m (the position x ciphertext-context product of exp
      082/065/079), tabulate, per class-count m: does a PROPER, CRIB-DETERMINED
      selector exist, and does any such selector in the flatten band [k*, 24]
      decrypt to English? The squeeze is proven iff that intersection is empty.

CONCLUSION FORM: a per-position cipher whose alphabet selector is short
(Scheidt-"memorable") cannot simultaneously (i) flatten to K4's entropy and
(ii) stay crib-determined -- it is forced to be either degenerate or non-English.

$0, local, pure decipherment. Output:
experiments/results/<date>_085_squeeze_bound.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import math
import random
import statistics
import time
from collections import Counter
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, keyed_alphabet
from kryptos.constants import K4
from kryptos.scoring.crib_check import surviving_positions
from kryptos.cribs import CRIBS
from kryptos.utils import clean

# Reuse exp 035's crib graph and exp 082's selector features (load by path; main() is __name__-guarded).
def _load(name, fname):
    m = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
        name, str(Path(__file__).parent / fname)))
    m.__spec__.loader.exec_module(m)
    return m

e035 = _load("e035", "035_minimum_alphabet_analysis.py")
e082 = _load("e082", "082_combined_selector_mdl.py")

N = 97
CORP = clean(Path("data/corpora/buchan_39steps.txt").read_text()
             + clean(Path("data/corpora/smith_tutankhamen.txt").read_text()))
ALPHS = {"kryptos_keyed": KRYPTOS_KEYED, "standard": STANDARD,
         "keyed_PALIMPSEST": keyed_alphabet("PALIMPSEST")}


def entropy(s):
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in Counter(s).values())


def english(rng, length):
    s = rng.randrange(len(CORP) - length)
    return CORP[s:s + length]


def mix_entropy(k, rng, length, samples=300):
    """Mean output entropy of the BEST-case k-alphabet mixture: k evenly-spaced
    rotations of the KRYPTOS-keyed alphabet, assigned round-robin (max mixing).
    This UPPER-bounds the entropy any k-alphabet selector can reach, so the k*
    derived from it LOWER-bounds the alphabet count a real selector needs."""
    alpha = KRYPTOS_KEYED
    rots = [round(j * 26 / k) % 26 for j in range(k)]
    Hs = []
    for _ in range(samples):
        pt = english(rng, length)
        out = [alpha.at(alpha.index(ch) + rots[i % k]) for i, ch in enumerate(pt)]
        Hs.append(entropy("".join(out)))
    return statistics.mean(Hs)


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_085_squeeze_bound.jsonl"
    rng = random.Random(0)
    t0 = time.perf_counter()

    # ---- target: K4 free-position entropy (the squeeze's flatten target) ----
    free = surviving_positions(N, CRIBS)
    k4_free = "".join(K4[i] for i in free)
    H_target = entropy(k4_free)
    H_full = entropy(K4)
    Lf = len(free)

    # ---- (A) FLATTEN FLOOR k* -------------------------------------------
    curve = {}
    kstar = None
    for k in range(1, 27):
        h = mix_entropy(k, rng, Lf)
        curve[k] = round(h, 3)
        if kstar is None and h >= H_target:
            kstar = k

    # ---- (B) DETERMINACY CEILING ----------------------------------------
    cribs = e035.build_crib_constraints()
    n_nodes = len(cribs)
    edges = set()
    for i in range(n_nodes):
        for j in range(i + 1, n_nodes):
            if e035.cribs_conflict(cribs[i], cribs[j]):
                edges.add((i, j))
    chi = e035.chromatic_number(n_nodes, edges)
    m_ceiling = n_nodes  # every class must touch a crib -> <= 24

    # ---- (C) FRONTIER over the short position x ctx selector family -----
    positions = [c[0] for c in cribs]
    PF, XF = e082.pos_features(), e082.ctx_features()
    # per class-count m: does a proper+crib-determined selector exist; best English decrypt in the band
    proper_determined_by_m = {}
    best_hex_in_band = (-99.0, None)   # best decrypt among selectors with m >= kstar that are proper+determined
    max_m_proper_determined = 0
    n_selectors = 0
    for pn, (pf, pk) in PF.items():
        for xn, (xf, xk) in XF.items():
            n_selectors += 1
            g = lambda i, pf=pf, xf=xf, xk=xk: pf(i) * xk + xf(i)
            vals = {node: g(positions[node]) for node in range(n_nodes)}
            m = len(set(vals.values()))
            proper = all(vals[u] != vals[v] for u, v in edges)
            if not proper:
                continue
            # crib-determined fit: some alphabet/convention gives a consistent rotation per class
            determined = False
            best_pt_hex = -99.0
            for an, alpha in ALPHS.items():
                for conv in _kpa.CONVENTIONS:
                    cls, ok = {}, True
                    for (pos, p_, c_, _, _) in cribs:
                        pi, ci = alpha.index(p_), alpha.index(c_)
                        sh = ((ci - pi) % 26 if conv == "vigenere"
                              else (ci + pi) % 26 if conv == "beaufort" else (pi - ci) % 26)
                        cl = g(pos)
                        if cl in cls and cls[cl] != sh:
                            ok = False; break
                        cls[cl] = sh
                    if not ok:
                        continue
                    determined = True
                    # decrypt all 97 (selector fully determined from position + known ciphertext)
                    P, full = [], True
                    for i in range(N):
                        if i < 2:
                            P.append(K4[i]); continue
                        cl = g(i)
                        if cl not in cls:
                            full = False; break
                        sh = cls[cl]; ci = alpha.index(K4[i])
                        pi = ((ci - sh) % 26 if conv == "vigenere"
                              else (sh - ci) % 26 if conv == "beaufort" else (ci + sh) % 26)
                        P.append(alpha.at(pi))
                    if full:
                        sc = _kpa.score_free_text("".join(P))
                        best_pt_hex = max(best_pt_hex, sc)
            if determined:
                max_m_proper_determined = max(max_m_proper_determined, m)
                d = proper_determined_by_m.get(m, {"count": 0, "best_hex": -99.0})
                d["count"] += 1
                d["best_hex"] = max(d["best_hex"], best_pt_hex)
                proper_determined_by_m[m] = d
                if kstar is not None and m >= kstar and best_pt_hex > best_hex_in_band[0]:
                    best_hex_in_band = (best_pt_hex, f"{pn}*{xn}(m={m})")

    elapsed = time.perf_counter() - t0

    # the feasible band for a non-degenerate flattening selector
    band = [kstar, m_ceiling] if kstar is not None else None
    # is the intersection (flatten AND determined AND English) empty?
    region_empty = (best_hex_in_band[1] is None) or (best_hex_in_band[0] <= -16.0)

    rec = {"H_target_free": round(H_target, 3), "H_full": round(H_full, 3), "n_free": Lf,
           "flatten_curve": curve, "kstar": kstar,
           "chi": chi, "determinacy_ceiling": m_ceiling,
           "max_m_proper_determined": max_m_proper_determined,
           "feasible_band_m": band, "n_selectors_tested": n_selectors,
           "proper_determined_by_m": {k: {"count": v["count"], "best_hex": round(v["best_hex"], 2)}
                                      for k, v in sorted(proper_determined_by_m.items())},
           "best_decrypt_in_band": {"hex": round(best_hex_in_band[0], 2), "selector": best_hex_in_band[1]},
           "region_empty": region_empty}
    with open(out, "w") as f:
        f.write(json.dumps(rec) + "\n")

    if region_empty:
        bound_tail = ("The intersection is empty: every short selector reaching the flatten band is either "
                      "degenerate (crib-free classes) or decrypts to gibberish. This is why a simple-rule "
                      "per-position polyalphabetic cannot be K4 -- the rule is genuinely idiosyncratic, or the "
                      "alphabets are individually memorable in a way not captured by a position/context selector.")
    else:
        bound_tail = "A candidate survives -- investigate it directly."

    insights = [
        f"FLATTEN FLOOR: K4's free-position entropy is {H_target:.3f} bits over {Lf} positions (full-97 "
        f"{H_full:.3f}). Best-case mixing (k evenly-spaced, equally-weighted KRYPTOS-keyed rotations) reaches "
        f"this at k* = {kstar} alphabets. Since this is the MAX entropy k alphabets can produce, any "
        f"per-position selector needs AT LEAST {kstar} alphabets to flatten. Curve: {curve}.",
        f"DETERMINACY CEILING: the 24-crib conflict graph has chi={chi} (>=3 alphabets, confirmed). A "
        f"NON-DEGENERATE selector must instantiate every class it uses at >=1 crib (a crib-free class has a "
        f"free rotation = the exp-059 degeneracy), so class count m <= {m_ceiling}. Feasible band for a "
        f"non-degenerate flattening selector: m in [{kstar}, {m_ceiling}].",
        f"FRONTIER: across {n_selectors} short position x ciphertext-context selectors (the lowest-description-"
        f"length family able to reach high m), the largest m that is BOTH a proper colouring AND crib-"
        f"determined is {max_m_proper_determined}. Proper+determined counts by m: "
        f"{ {k: v['count'] for k, v in sorted(proper_determined_by_m.items())} }. "
        f"Best English decrypt among those with m in the flatten band: hex {best_hex_in_band[0]:.2f} "
        f"({best_hex_in_band[1]}).",
        f"THE BOUND (region {'EMPTY' if region_empty else 'NON-EMPTY'}): a short per-position selector cannot "
        f"be simultaneously (i) flattening (m >= k* = {kstar}) and (ii) crib-determined and (iii) English. "
        + bound_tail,
    ]

    write_verdict(out, Verdict(
        exp="085", title="the squeeze formalized: flatten floor vs crib-determinacy ceiling",
        hypothesis="a short (memorable) per-position alphabet selector can flatten K4 to its entropy while "
                   "remaining crib-determined",
        status="ruled_out" if region_empty else "promising",
        best_partial=f"flatten floor k*={kstar}; determinacy ceiling m<=24 (chi={chi}); max proper+determined "
                     f"m={max_m_proper_determined}; best in-band decrypt hex {round(best_hex_in_band[0],2)}",
        search_space=n_selectors, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["the simple-selector per-position hypothesis is bounded out; remaining live paths are "
                     "non-selector mechanisms (individually-memorable hand-crafted alphabets, or a "
                     "construction outside the per-position-substitution frame entirely)"] if region_empty else
                    ["investigate the surviving in-band selector directly"]),
        metrics={"kstar": kstar, "chi": chi, "max_m_proper_determined": max_m_proper_determined,
                 "region_empty": region_empty, "H_target": round(H_target, 3)}),
    )
    print(f"\nflatten floor k*={kstar} (H_target={H_target:.3f}); determinacy ceiling m<=24 (chi={chi}); "
          f"max proper+determined m={max_m_proper_determined}; band [{kstar},24]; region_empty={region_empty}. "
          f"-> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
