"""114 — Homophonic loophole: re-derive the chromatic number for a NON-bijective
(homophonic) chart, which is allowed to repeat ciphers per plaintext.

A foundational re-examination. exp 035's chi=3 used BOTH crib-conflict types:
  (a) same plaintext -> different cipher   (forbidden for a BIJECTION)
  (b) same cipher    -> different plaintext (forbidden for ANY decryption map)
But a HOMOPHONIC cipher (one plaintext letter -> several cipher letters,
decryption many-to-one) is *allowed* type-(a): a letter legitimately has multiple
ciphertext homophones. Only type-(b) binds a homophonic DECRYPTION chart. So the
homophonic chromatic number chi_b (b-conflicts only) could be < 3 -- fewer charts
than the 3 proven for bijective alphabets. And homophonic substitution is the
classic way to FLATTEN letter frequency (our Fact 2, 4.33-bit entropy) WITHOUT
needing many alphabets. This tests whether the chart-based system might be
homophonic, a model our bijective per-position analysis never isolated.

Computes chi_full, chi_a, chi_b; if chi_b < 3, tests a k=chi_b homophonic
per-position model (non-injective decryption charts, simple selector) for
crib-consistency + decrypt, and checks whether homophony eases the squeeze.

$0, local, deterministic, no LLM, no K5, no plaintext. Output:
experiments/results/<date>_114_homophonic_chromatic.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import time
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K4
from kryptos.cribs import CRIBS

e035 = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
    "e035", str(Path(__file__).parent / "035_minimum_alphabet_analysis.py")))
e035.__spec__.loader.exec_module(e035)

CRIB = [(c.start - 1 + off, p, ch)
        for c in CRIBS for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext))]
N = len(CRIB)


def chromatic(conflict_fn):
    edges = set()
    for i in range(N):
        for j in range(i + 1, N):
            if conflict_fn(CRIB[i], CRIB[j]):
                edges.add((i, j))
    return e035.chromatic_number(N, edges), edges


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_114_homophonic_chromatic.jsonl"
    t0 = time.perf_counter()

    def a_conf(x, y):  # same plaintext -> different cipher
        return x[1] == y[1] and x[2] != y[2]

    def b_conf(x, y):  # same cipher -> different plaintext (binds ANY decryption map)
        return x[2] == y[2] and x[1] != y[1]

    def both(x, y):
        return a_conf(x, y) or b_conf(x, y)

    chi_full, e_full = chromatic(both)
    chi_a, e_a = chromatic(a_conf)
    chi_b, e_b = chromatic(b_conf)

    # how much does homophony relax things?
    homophonic_helps = chi_b < chi_full

    # If chi_b < 3, test the homophonic model: k=chi_b decryption charts (non-injective
    # allowed) selected per position by a proper b-colouring; decrypt + score + degeneracy.
    decrypt_info = None
    if chi_b < 3:
        coloring = e035.find_k_coloring(N, e_b, chi_b)
        # build per-class decryption charts pinned by cribs (cipher_idx -> plain_letter)
        charts = {c: {} for c in range(chi_b)}
        consistent = True
        for n, (pos, p, ch) in enumerate(CRIB):
            c = coloring[n]
            if ch in charts[c] and charts[c][ch] != p:
                consistent = False; break
            charts[c][ch] = p
        decrypt_info = {"chi_b": chi_b, "consistent": consistent,
                        "pinned_entries": {c: len(charts[c]) for c in range(chi_b)},
                        "note": ("a homophonic decryption chart is NON-injective, so its free (non-crib) cipher "
                                 "entries are unconstrained -> the free 73 positions are under-determined exactly "
                                 "as in the bijective case; homophony reduces the CHART COUNT but not the "
                                 "under-determination.")}

    elapsed = time.perf_counter() - t0
    with open(out, "w") as f:
        f.write(json.dumps({"chi_full": chi_full, "chi_a_only": chi_a, "chi_b_only": chi_b,
                            "homophonic_helps": homophonic_helps, "n_a_edges": len(e_a),
                            "n_b_edges": len(e_b), "n_both_edges": len(e_full),
                            "homophonic_model": decrypt_info}) + "\n")

    insights = [
        f"Crib conflict chromatic numbers: chi_full (both conflict types, the published bound) = {chi_full}; "
        f"chi_a (same-plaintext->diff-cipher only) = {chi_a}; chi_b (same-cipher->diff-plaintext only, the ONLY "
        f"constraint on a homophonic decryption chart) = {chi_b}. Edge counts: a={len(e_a)}, b={len(e_b)}, "
        f"both={len(e_full)}.",
        (f"HOMOPHONIC LOOPHOLE OPEN: chi_b={chi_b} < chi_full={chi_full} -- a homophonic cipher (which is allowed "
         f"the {len(e_a)} 'same-plaintext->different-cipher' conflicts as legitimate homophones) needs only "
         f"{chi_b} decryption charts, FEWER than the 3 proven for bijective alphabets. AND homophonic "
         f"substitution flattens frequency (our Fact 2) by design. So K4 could be a {chi_b}-chart homophonic "
         f"'chart-based coding system' -- a model the bijective analysis (035/085/106) over-constrained."
         if homophonic_helps else
         f"NO HOMOPHONIC RELIEF: chi_b={chi_b} equals chi_full={chi_full} -- the same-cipher->different-plaintext "
         f"conflicts ALONE force {chi_b} charts, so allowing homophones (relaxing the same-plaintext->diff-cipher "
         f"constraint) does NOT reduce the chart count. A homophonic chart is just as constrained as a bijective "
         f"one here; the >=3-chart bound holds for homophonic ciphers too."),
        (decrypt_info["note"] if decrypt_info else
         "Since chi_b is not below 3, the homophonic model offers no reduction; the >=3 hand-crafted charts "
         "remain required and bespoke (088/110/113), and the under-determination (092/093) stands."),
    ]

    # knowledge result: it either opens a genuinely new (homophonic) model or tightens the bound
    status = "promising" if homophonic_helps else "ruled_out"

    write_verdict(out, Verdict(
        exp="114", title="homophonic chromatic number (chi_b) -- does a non-bijective chart need fewer alphabets?",
        hypothesis="K4 is a homophonic chart cipher needing fewer than 3 decryption charts (chi_b < 3), which "
                   "would also explain the frequency flattening",
        status=status,
        best_partial=f"chi_full={chi_full}, chi_a={chi_a}, chi_b={chi_b}; homophonic_helps={homophonic_helps}",
        search_space=1, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=([f"chi_b={chi_b}<3 -- build the homophonic {chi_b}-chart per-position model with a simple "
                     "selector and test decrypt (note: free chart entries are still under-determined)"]
                    if homophonic_helps else
                    ["homophonic offers no chart-count reduction (chi_b == chi_full); the >=3-chart bound is "
                     "model-robust (bijective OR homophonic). Flattening (Fact 2) is NOT explained by homophony "
                     "alone -- it still requires >=3 charts"]),
        metrics={"chi_full": chi_full, "chi_a": chi_a, "chi_b": chi_b, "homophonic_helps": homophonic_helps}),
    )
    print(f"\nchi_full={chi_full}, chi_a={chi_a}, chi_b={chi_b}; homophonic_helps={homophonic_helps}; "
          f"status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
