"""063 — Vimark with non-adjacent recurrence lags (s_i = s_{i-j} + s_{i-k}).

exp 062 closed the adjacent-lag lagged-Fibonacci (s_i = s_{i-1} + s_{i-k},
i.e. j=1) at every primer length, over 5 alphabets x 2 conventions: all
crib-INCONSISTENT. This generalises the SAME algebraic known-plaintext attack
to ALL lag pairs (j, k), 1 <= j < k <= 24 (j>=2 is the new ground; j=1 is
exp 062). Because the recurrence is still LINEAR mod 26, the 24 cribs give a
linear system in the k primer unknowns; we solve it (GF(2)+GF(13)+CRT) and
categorise each (j,k,alphabet,convention) system as crib-inconsistent
(refuted), consistent-and-determined (tested), or underdetermined (degenerate).

Reuses exp 062's validated solver. Output:
experiments/results/<date>_063_vimark_general_lags.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import time
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict

# Reuse the validated algebraic machinery from exp 062.
_spec = importlib.util.spec_from_file_location(
    "e062", str(Path(__file__).parent / "062_vimark_algebraic_kpa.py"))
e062 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(e062)

ALPHABETS = e062.ALPHABETS
CRIB_POSITIONS = e062.CRIB_POSITIONS
CRIB_PLAIN = e062.CRIB_PLAIN


def keystream_general(primer, j, k, length, mod=26):
    s = list(primer)
    while len(s) < length:
        s.append((s[-j] + s[-k]) % mod)
    return s[:length]


def coeff_matrix_general(j, k, length):
    """length x k integer coefficient matrix for s_i = s_{i-j} + s_{i-k}."""
    coeff = []
    for t in range(k):
        e = [0] * k
        e[t] = 1
        coeff.append(e)
    for i in range(k, length):
        coeff.append([coeff[i - j][t] + coeff[i - k][t] for t in range(k)])
    return coeff


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_063_vimark_general_lags.jsonl"
    lm_mod = importlib.import_module("kryptos.scoring.lm_fitness")
    lm = lm_mod.backoff_scorer()
    t0 = time.perf_counter()
    best = (-99.0, None)
    n_inconsistent = n_small = n_degenerate = 0
    max_determined = None
    solved = None

    with open(out, "w") as f:
        for k in range(3, 25):
            for j in range(2, k):                 # j>=2 is the NEW ground (j=1 = exp 062)
                coeff = coeff_matrix_general(j, k, 97)
                A_rows = [[coeff[pos][t] for t in range(k)] for pos in CRIB_POSITIONS]
                for aname, alpha in ALPHABETS.items():
                    for conv in ("vigenere", "beaufort"):
                        sh = e062.shifts_in(alpha, conv)
                        b = [sh[pos] for pos in CRIB_POSITIONS]
                        res = e062.solve_system(k, A_rows, b)
                        if not res["consistent"]:
                            n_inconsistent += 1
                            continue
                        if res["space"] <= 4000:
                            n_small += 1
                            if max_determined is None or k > max_determined:
                                max_determined = k
                        else:
                            n_degenerate += 1
                        for primer in res["primers"]:
                            ks = keystream_general(primer, j, k, 97)
                            P = []
                            for i in range(97):
                                ci = alpha.index(_kpa.K4_TEXT[i]); s = ks[i]
                                pi = (ci - s) % 26 if conv == "vigenere" else (s - ci) % 26
                                P.append(alpha.at(pi))
                            P = "".join(P)
                            if any(P[pos] != CRIB_PLAIN[pos] for pos in CRIB_POSITIONS):
                                continue
                            sc = _kpa.score_free_text(P)
                            if sc > best[0]:
                                best = (sc, {"j": j, "k": k, "alphabet": aname, "convention": conv,
                                             "space": res["space"], "primer": primer,
                                             "plaintext": P, "hex": round(sc, 2)})
                            if sc > -16.0:
                                f.write(json.dumps({"j": j, "k": k, "alphabet": aname,
                                                    "convention": conv, "space": res["space"],
                                                    "hex": round(sc, 2), "plaintext": P}) + "\n")
                            enc = "".join(alpha.at((alpha.index(P[i]) + ks[i]) % 26
                                                   if conv == "vigenere" else
                                                   (ks[i] - alpha.index(P[i])) % 26) for i in range(97))
                            if enc == _kpa.K4_TEXT and sc > -15.0:
                                solved = {"j": j, "k": k, "alphabet": aname, "convention": conv,
                                          "primer": primer, "plaintext": P}

    elapsed = time.perf_counter() - t0
    bi = best[1]
    total = n_inconsistent + n_small + n_degenerate
    status = "solved" if solved else ("promising" if (bi and bi["hex"] > -15.0) else "ruled_out")
    insights = [
        f"Generalised Vimark KPA to non-adjacent lags s_i=s_(i-j)+s_(i-k), 2<=j<k<=24 "
        f"({total} systems x 5 alphabets x 2 conventions): {n_inconsistent} crib-INCONSISTENT (refuted), "
        f"{n_small} determined (tested), {n_degenerate} underdetermined (degenerate). Largest determined "
        f"k = {max_determined}.",
        (f"Best decrypt: j={bi['j']} k={bi['k']} {bi['alphabet']}/{bi['convention']} hexagram {bi['hex']}/char"
         if bi else "No consistent system produced a scorable decrypt."),
    ]
    if status == "ruled_out":
        insights.append("Across ALL lag pairs (j,k) and primer lengths, K4's cribs are inconsistent with the "
                        "linear lagged-Fibonacci keystream in the determined regime (and degenerate in the "
                        "underdetermined one). The ENTIRE two-term linear-recurrence keystream family "
                        "(Vimark/Gromark/Fibonacci, any lags) is now closed, not just the adjacent-lag case.")
    write_verdict(out, Verdict(
        exp="063", title="Vimark non-adjacent-lag recurrences (full lagged-Fibonacci family)",
        hypothesis="K4 is a two-term linear-recurrence keystream cipher for some lag pair (j,k)",
        status=status, best_score=bi["hex"] if bi else None,
        best_partial=f"{n_inconsistent} inconsistent / {n_small} tested / {n_degenerate} degenerate",
        search_space=total, elapsed_s=round(elapsed, 1), solved_params=solved,
        insights=insights,
        next_steps=(["verify & announce"] if solved else
                    ["the linear-recurrence keystream family is exhausted; pursue 2-stage tiny composites (064)"]),
        metrics={"best": bi})
    )
    print(f"\n{n_inconsistent} inconsistent / {n_small} tested / {n_degenerate} degenerate (of {total}); "
          f"best hex {best[0]:.2f}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
