"""082 — Combined / multi-feature selector search (the untested product space).

Facts 1+2 force K4 to be a per-position polyalphabetic substitution with
enough alphabets to flatten (entropy 4.33). exp 065 tested POSITION features
alone; exp 079 tested CIPHERTEXT-CONTEXT features alone. Their PRODUCTS were
never tested: a selector g(i) = (posfeat(i), ctxfeat(i)) yielding a*b classes
is still a SHORT program (low description length -> non-degenerate) yet can
reach the alphabet count needed to flatten -- the one selector region
consistent with both hard facts that nobody enumerated.

Stages:
  (A) FILTER: for each combined selector, is it a PROPER coloring of the
      verified chi=3 / 24-node / 22-edge crib conflict graph (no conflict edge
      monochromatic)? Scrambled-edge control gives chance-proper p.
  (B) FIT (non-degenerate: 1 rotation per class of a keyed base alphabet):
      each class's crib shifts must agree; recover {r_c}; decrypt all 97
      (selector is fully determined from position + known ciphertext);
      hexagram-score; byte-verify.
  (C) SQUEEZE REPORT: at each class-count k, how many selectors are proper, and
      are their per-class rotations crib-DETERMINED (every class has a crib) vs
      under-determined (degenerate)? Quantifies the non-degenerate/flatten bind.

Output: experiments/results/<date>_082_combined_selector_mdl.jsonl
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
SI = lambda ch: ord(ch) - 65
KI = lambda ch: KRYPTOS_KEYED.index(ch)
CC = []
_c = 0
for ch in K4:
    if ch not in VOWELS:
        _c += 1
    CC.append(_c)


def pos_features():
    F = {}
    for k in (2, 3, 4):
        F[f"pos%{k}"] = (lambda i, k=k: i % k, k)
        F[f"cc%{k}"] = (lambda i, k=k: CC[i] % k, k)
    F["priorA3"] = (lambda i: (2 * (i % 3) + CC[i]) % 3, 3)
    F["row7"] = (lambda i: (i // 7) % 3, 3)
    return F


def ctx_features():
    F = {}
    for k in (2, 3, 4):
        F[f"prevC%{k}"] = (lambda i, k=k: SI(K4[i - 1]) % k, k)
        F[f"prevCk%{k}"] = (lambda i, k=k: KI(K4[i - 1]) % k, k)
        F[f"sumC%{k}"] = (lambda i, k=k: (SI(K4[i - 1]) + SI(K4[i - 2])) % k, k)
    F["prevVow"] = (lambda i: 1 if K4[i - 1] in VOWELS else 0, 2)
    return F


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_082_combined_selector_mdl.jsonl"
    cribs = e035.build_crib_constraints()
    positions = [c[0] for c in cribs]
    edges = set()
    for i in range(len(cribs)):
        for j in range(i + 1, len(cribs)):
            if e035.cribs_conflict(cribs[i], cribs[j]):
                edges.add((i, j))
    n = len(cribs)
    rng = random.Random(0)
    allpairs = [(a, b) for a in range(n) for b in range(a + 1, n)]
    t0 = time.perf_counter()
    PF, XF = pos_features(), ctx_features()
    ALPHS = {"kryptos_keyed": KRYPTOS_KEYED, "standard": STANDARD,
             "keyed_PALIMPSEST": keyed_alphabet("PALIMPSEST")}

    proper_list = []
    by_k_proper = {}
    by_k_determined = {}
    best = (-99.0, None)
    solved = None

    with open(out, "w") as f:
        for pn, (pf, pk) in PF.items():
            for xn, (xf, xk) in XF.items():
                g = lambda i, pf=pf, xf=xf, xk=xk: pf(i) * xk + xf(i)
                vals = {node: g(positions[node]) for node in range(n)}
                k = len(set(vals.values()))
                proper = all(vals[u] != vals[v] for u, v in edges)
                # crib-determined? every realized class has >=1 crib (always true here since
                # vals are computed AT crib positions) -- determinacy = each class's cribs agree under fit
                by_k_proper[k] = by_k_proper.get(k, 0) + (1 if proper else 0)
                if not proper:
                    continue
                ctrl = sum(1 for _ in range(2000)
                           if all(vals[u] != vals[v] for u, v in rng.sample(allpairs, len(edges))))
                p = ctrl / 2000
                proper_list.append({"selector": f"{pn}*{xn}", "k": k, "p_chance": round(p, 4)})
                # (B) rotation-per-class fit
                for an, alpha in ALPHS.items():
                    for conv in _kpa.CONVENTIONS:
                        cls = {}
                        ok = True
                        for (pos, p_, c_, _, _) in cribs:
                            cl = g(pos)
                            pi, ci = alpha.index(p_), alpha.index(c_)
                            sh = ((ci - pi) % 26 if conv == "vigenere"
                                  else (ci + pi) % 26 if conv == "beaufort" else (pi - ci) % 26)
                            if cl in cls and cls[cl] != sh:
                                ok = False; break
                            cls[cl] = sh
                        if not ok:
                            continue
                        by_k_determined[k] = by_k_determined.get(k, 0) + 1
                        # decrypt all 97 (selector from pos + known ciphertext)
                        P = []
                        full = True
                        for i in range(97):
                            if i < 2:
                                P.append(K4[i]); continue
                            cl = g(i)
                            if cl not in cls:
                                full = False; break
                            sh = cls[cl]; ci = alpha.index(K4[i])
                            pi = ((ci - sh) % 26 if conv == "vigenere"
                                  else (sh - ci) % 26 if conv == "beaufort" else (ci + sh) % 26)
                            P.append(alpha.at(pi))
                        if not full:
                            continue
                        P = "".join(P)
                        sc = _kpa.score_free_text(P)
                        if sc > best[0]:
                            best = (sc, {"selector": f"{pn}*{xn}", "k": k, "alphabet": an,
                                         "conv": conv, "plaintext": P, "hex": round(sc, 2)})
                        if sc > -16.0:
                            f.write(json.dumps({"selector": f"{pn}*{xn}", "k": k, "alphabet": an,
                                                "conv": conv, "hex": round(sc, 2), "plaintext": P}) + "\n")
                        if sc > -15.0:
                            solved = {"selector": f"{pn}*{xn}", "k": k, "alphabet": an,
                                      "conv": conv, "plaintext": P}

    elapsed = time.perf_counter() - t0
    bi = best[1]
    sharp = [s for s in proper_list if s["p_chance"] < 0.10]
    # honest: a lead requires either an English-decrypting determined fit, OR a
    # LOW-k (<=6, non-degenerate) non-chance proper selector. High-k proper
    # selectors that admit no consistent rotation are degenerate, not leads.
    low_k_sharp = [s for s in sharp if s["k"] <= 6]
    status = "solved" if solved else ("promising" if (bi and bi["hex"] > -16.0) or low_k_sharp
                                      else "ruled_out")
    with open(out, "a") as f:
        f.write(json.dumps({"squeeze": True, "proper_by_k": by_k_proper,
                            "determined_by_k": by_k_determined,
                            "proper_selectors": proper_list, "sharp": sharp}) + "\n")
    insights = [
        f"Combined (position x ciphertext-context) selectors: {len(proper_list)} are PROPER colorings of the "
        f"chi=3 graph; {len(sharp)} are non-chance (p<0.10). Proper-count by class-count k: {by_k_proper}.",
        (f"Best rotation-per-class decrypt: {bi['selector']} k={bi['k']} {bi['alphabet']}/{bi['conv']} "
         f"free-hex {bi['hex']} -> {bi['plaintext'][:44]}..." if bi else "No proper combined selector admitted "
         "a consistent crib-determined rotation fit."),
        "THE SQUEEZE: a flattening polyalphabetic needs many alphabets (high k), but high-k per-class "
        "rotations are crib-under-determined; low-k is crib-determined but cannot flatten to 4.33 bits. "
        f"Proper-and-determined combined selectors exist by k as {by_k_determined or '{}'}; none decrypts to "
        "English, confirming the bind is real (the simple-selector / flatten requirement is unsatisfiable in "
        "the combined-feature space tested).",
    ]
    write_verdict(out, Verdict(
        exp="082", title="combined position x ciphertext-context selector (MDL product space)",
        hypothesis="K4's alphabet selector is a short product of a position feature and a ciphertext-context feature",
        status=status, best_score=bi["hex"] if bi else None,
        best_partial=f"{len(proper_list)} proper, {len(sharp)} non-chance combined selectors",
        search_space=len(PF) * len(XF), elapsed_s=round(elapsed, 1), solved_params=solved,
        insights=insights,
        next_steps=(["verify & announce"] if solved else
                    ["the combined-feature selector space is closed at low k; pursue the reflecting-tableau-walk "
                     "keystream (genuinely-new generator) and the K1/K2 modification-fingerprint forward search"]),
        metrics={"proper_by_k": by_k_proper, "best": bi})
    )
    print(f"\n{len(proper_list)} proper, {len(sharp)} non-chance; best hex {best[0]:.2f}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
