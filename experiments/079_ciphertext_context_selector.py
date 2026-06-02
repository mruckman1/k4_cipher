"""079 — Ciphertext-context (self-synchronizing) selector: the unexplored frame.

The likely-false assumption behind all 78 prior experiments: the alphabet
SELECTOR is a function of POSITION (exp 065 closed that) or of PLAINTEXT
(autokey, exp 060). Untested: a selector that is a function of the PRECEDING
CIPHERTEXT, g(C_{i-1}, C_{i-2}, ...). This is hand-executable (you read the
ciphertext as you decrypt), aperiodic, and -- crucially -- DECRYPTABLE, because
the ciphertext is fully known, so the class of every one of the 97 positions is
determined with no plaintext input.

Two stages:
  (A) FILTER (degeneracy-immune, zero plaintext): for each ciphertext-context
      selector g, is g a PROPER coloring of the verified chi=3 / 24-node /
      22-edge crib conflict graph (no conflict edge monochromatic) at <=k
      classes? A scrambled-edge control reports chance-proper probability; a
      proper coloring with p<0.05 among the composite selectors is the signal.
  (B) FIT (few-parameter, non-degenerate) for survivors: model = one keyed base
      alphabet + ONE rotation r_c per selector class. Each class's crib shifts
      must agree (single rotation); if so, recover {r_c}, decrypt all 97 (class
      from ciphertext context), hexagram-score, byte-verify.

Output: experiments/results/<date>_079_ciphertext_context_selector.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import random
import time
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, keyed_alphabet
from kryptos.constants import K4

e035 = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
    "e035", str(Path(__file__).parent / "035_minimum_alphabet_analysis.py")))
e035.__spec__.loader.exec_module(e035)

VOWELS = set("AEIOU")
KRYP = set("KRYPTOS")
SI = lambda ch: ord(ch) - 65          # standard index
KI = lambda ch: KRYPTOS_KEYED.index(ch)


def context_features():
    """Selector functions g(i) over the PRECEDING ciphertext at position i (0-idx)."""
    F = {}
    for k in range(2, 9):
        F[f"prevC_mod_{k}"] = lambda i, k=k: SI(K4[i - 1]) % k
        F[f"prev2C_mod_{k}"] = lambda i, k=k: SI(K4[i - 2]) % k
        F[f"sumC_mod_{k}"] = lambda i, k=k: (SI(K4[i - 1]) + SI(K4[i - 2])) % k
        F[f"diffC_mod_{k}"] = lambda i, k=k: (SI(K4[i - 1]) - SI(K4[i - 2])) % k
        F[f"prevCk_mod_{k}"] = lambda i, k=k: KI(K4[i - 1]) % k
    F["prevC_vowel"] = lambda i: 1 if K4[i - 1] in VOWELS else 0
    F["prevC_kryptos"] = lambda i: 1 if K4[i - 1] in KRYP else 0
    # 2-feature products (4-6 classes) -- the composite selectors nobody enumerated
    F["prevC2_prev2C2"] = lambda i: (SI(K4[i - 1]) % 2) * 2 + (SI(K4[i - 2]) % 2)
    F["prevC2_vowel"] = lambda i: (SI(K4[i - 1]) % 2) * 2 + (1 if K4[i - 1] in VOWELS else 0)
    F["prevC3_prev2C2"] = lambda i: (SI(K4[i - 1]) % 3) * 2 + (SI(K4[i - 2]) % 2)
    F["prevCk2_prev2Ck2"] = lambda i: (KI(K4[i - 1]) % 2) * 2 + (KI(K4[i - 2]) % 2)
    F["vowel_pair"] = lambda i: (1 if K4[i - 1] in VOWELS else 0) * 2 + (1 if K4[i - 2] in VOWELS else 0)
    return F


def proper(vals, edges):
    return all(vals[u] != vals[v] for u, v in edges)


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_079_ciphertext_context_selector.jsonl"
    cribs = e035.build_crib_constraints()
    positions = [c[0] for c in cribs]
    edges = set()
    for i in range(len(cribs)):
        for j in range(i + 1, len(cribs)):
            if e035.cribs_conflict(cribs[i], cribs[j]):
                edges.add((i, j))
    n = len(cribs)
    t0 = time.perf_counter()
    rng = random.Random(0)
    all_pairs = [(a, b) for a in range(n) for b in range(a + 1, n)]
    N_CTRL = 3000

    F = context_features()
    valid = []
    with open(out, "w") as f:
        for name, g in F.items():
            vals = {node: g(positions[node]) for node in range(n)}
            ok = proper(vals, edges)
            kcls = len(set(vals.values()))
            ctrl = sum(1 for _ in range(N_CTRL)
                       if all(vals[u] != vals[v] for u, v in rng.sample(all_pairs, len(edges))))
            p = ctrl / N_CTRL
            rec = {"selector": name, "proper": ok, "k_classes": kcls, "p_chance": round(p, 4)}
            f.write(json.dumps(rec) + "\n")
            if ok and kcls >= 3:
                valid.append(rec)

        # ---- (B) rotation-per-class fit for proper, low-chance selectors ----
        best = (-99.0, None)
        solved = None
        sharp = [v for v in valid if v["p_chance"] < 0.10]
        ALPHS = {"kryptos_keyed": KRYPTOS_KEYED, "standard": STANDARD,
                 "keyed_PALIMPSEST": keyed_alphabet("PALIMPSEST"),
                 "keyed_ABSCISSA": keyed_alphabet("ABSCISSA")}
        for v in sharp:
            g = F[v["selector"]]
            for an, alpha in ALPHS.items():
                for conv in _kpa.CONVENTIONS:
                    # per-class required rotation from cribs
                    cls_shift = {}
                    ok = True
                    for (pos, p_, c_, _, _) in cribs:
                        cl = g(pos)
                        pi, ci = alpha.index(p_), alpha.index(c_)
                        sh = ((ci - pi) % 26 if conv == "vigenere"
                              else (ci + pi) % 26 if conv == "beaufort" else (pi - ci) % 26)
                        if cl in cls_shift and cls_shift[cl] != sh:
                            ok = False; break
                        cls_shift[cl] = sh
                    if not ok:
                        continue
                    # decrypt full: class from ciphertext context at every position
                    P = []
                    full = True
                    for i in range(97):
                        if i < 2:
                            P.append(K4[i]); continue
                        cl = g(i)
                        if cl not in cls_shift:
                            full = False; break
                        sh = cls_shift[cl]; ci = alpha.index(K4[i])
                        pi = ((ci - sh) % 26 if conv == "vigenere"
                              else (sh - ci) % 26 if conv == "beaufort" else (ci + sh) % 26)
                        P.append(alpha.at(pi))
                    if not full:
                        continue
                    P = "".join(P)
                    sc = _kpa.score_free_text(P)
                    if sc > best[0]:
                        best = (sc, {"selector": v["selector"], "alphabet": an, "conv": conv,
                                     "plaintext": P, "hex": round(sc, 2)})
                    if sc > -16.0:
                        f.write(json.dumps({"fit": True, "selector": v["selector"], "alphabet": an,
                                            "conv": conv, "hex": round(sc, 2), "plaintext": P}) + "\n")
                    if sc > -15.0:
                        solved = {"selector": v["selector"], "alphabet": an, "conv": conv, "plaintext": P}

    elapsed = time.perf_counter() - t0
    bi = best[1]
    status = "solved" if solved else ("promising" if (sharp and bi and bi["hex"] > -16.0) else
                                      ("promising" if sharp else "ruled_out"))
    insights = [
        f"Tested {len(F)} ciphertext-context selectors g(C_(i-1),C_(i-2)) against the chi=3 24-node/22-edge "
        f"crib conflict graph. PROPER colorings (k>=3): {[v['selector'] for v in valid]}.",
        f"Non-trivially proper (p_chance<0.10 under scrambled-edge control): "
        f"{[(v['selector'], v['p_chance']) for v in sharp] or 'NONE'}.",
        (f"Rotation-per-class fit best: {bi['selector']} {bi['alphabet']}/{bi['conv']} free-hex {bi['hex']} -> "
         f"{bi['plaintext'][:46]}..." if bi else "No proper context-selector admitted a consistent per-class "
         "rotation fit."),
    ]
    if not sharp:
        insights.append("No ciphertext-context selector is a non-chance proper coloring -- the "
                        "'selector = preceding ciphertext' door (left ajar by 060/065/066) is now CLOSED for "
                        "1-2-letter context functions. Combined with exp 065 (position selectors), the only "
                        "graph-special selector remains the degenerate Prior-A rule.")
    write_verdict(out, Verdict(
        exp="079", title="ciphertext-context (self-synchronizing) selector filter + rotation fit",
        hypothesis="K4's alphabet selector is a function of the preceding ciphertext (self-synchronizing)",
        status=status, best_score=bi["hex"] if bi else None,
        best_partial=f"{len(valid)} proper colorings, {len(sharp)} non-chance (p<0.10)",
        search_space=len(F), elapsed_s=round(elapsed, 1), solved_params=solved,
        insights=insights,
        next_steps=(["verify & announce"] if solved else
                    (["push the surviving context selector(s): widen base alphabets, per-class FULL alphabet "
                      "(not just rotation), 3-letter context"] if sharp else
                     ["context-selector door closed; attack the OTHER frames -- key-phase offset sweep and "
                      "transposed read-order re-indexing of the chi=3 graph (the false-assumption attack)"])),
        metrics={"valid_selectors": valid, "sharp_selectors": sharp, "best": bi})
    )
    print(f"\n{len(valid)} proper, {len(sharp)} non-chance; best hex {best[0]:.2f}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
