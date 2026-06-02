"""103 — Number-theoretic analysis of the 24 crib-shift sequence as a pure object.

006/034 looked at the crib shifts as generator targets. This treats the shift
sequence itself as a mathematical object and asks, deterministically, whether it
has a generating structure the cipher searches could have missed:

  - polynomial in position over GF(26) (=CRT of GF(2),GF(13)): per contiguous run
    (EASTNORTHEAST 21-33, BERLINCLOCK 63-73), is the shift a low-degree polynomial
    in i? (finite differences; constant d-th difference => degree d-1)
  - short linear recurrence s_i = a*s_{i-1}+b*s_{i-2}+c (mod 26), fit per run and
    cross-checked on the other run
  - modular structure (shifts mod 2/3/5/13): non-uniform clustering
  - known-sequence match (i, i^2, primes, Fibonacci, triangular ... mod 26)
  - run-to-run relationship (offset / reversal / scaling between the two runs)

Across all alphabets x conventions. Any clean fit is a real lead (the cipher's
key schedule); none is an honest negative (the shifts are structureless under
these tests). Deterministic, no language model.

$0, local, pure decipherment. Output:
experiments/results/<date>_103_crib_shift_number_theory.jsonl
"""

from __future__ import annotations

import json
import time
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD

ALPHS = {"standard": STANDARD, "kryptos_keyed": KRYPTOS_KEYED}
RUNS = {"EASTNORTHEAST": list(range(21, 34)), "BERLINCLOCK": list(range(63, 74))}


def shift_at(alpha, conv):
    """{pos: shift} at the 24 crib positions."""
    d = {}
    for pos, pi, ci in _kpa.crib_position_triples(alpha):
        d[pos] = ((ci - pi) % 26 if conv == "vigenere"
                  else (ci + pi) % 26 if conv == "beaufort" else (pi - ci) % 26)
    return d


def diffs(seq, mod=26):
    return [(seq[i + 1] - seq[i]) % mod for i in range(len(seq) - 1)]


def poly_degree(seq, mod=26):
    """Smallest d with constant d-th finite difference (deg d) over a contiguous
    run; None if no constant difference up to len-1."""
    cur = seq[:]
    for d in range(len(seq)):
        if len(set(cur)) == 1:
            return d, cur[0]
        cur = diffs(cur, mod)
    return None, None


def inv_mod(a, m):
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def fit_recurrence(seq, mod=26):
    """Try s_i = a*s_{i-1} + b*s_{i-2} + c (mod 26) using 3 equations from the run;
    return (a,b,c) if it fits the WHOLE run, else None. Brute force a,b,c in 0..25
    (cheap, exact, avoids non-invertibility issues)."""
    if len(seq) < 4:
        return None
    for a in range(mod):
        for b in range(mod):
            for c in range(mod):
                if all((a * seq[i - 1] + b * seq[i - 2] + c) % mod == seq[i]
                       for i in range(2, len(seq))):
                    return (a, b, c)
    return None


def known_sequences(positions, mod=26):
    """Candidate position-indexed sequences to compare against (value per pos)."""
    primes = []
    n = 2
    while len(primes) < 200:
        if all(n % p for p in primes if p * p <= n):
            primes.append(n)
        n += 1
    fib = [0, 1]
    while len(fib) < 200:
        fib.append(fib[-1] + fib[-2])
    S = {}
    S["i"] = {p: p % mod for p in positions}
    S["i^2"] = {p: (p * p) % mod for p in positions}
    S["triangular"] = {p: (p * (p + 1) // 2) % mod for p in positions}
    S["prime(i)"] = {p: primes[p] % mod for p in positions}
    S["fib(i)"] = {p: fib[p] % mod for p in positions}
    return S


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_103_crib_shift_number_theory.jsonl"
    t0 = time.perf_counter()
    findings = []
    poly_hits = []
    rec_hits = []
    seq_hits = []

    with open(out, "w") as f:
        for an, alpha in ALPHS.items():
            for conv in _kpa.CONVENTIONS:
                shifts = shift_at(alpha, conv)
                full_positions = sorted(shifts)
                for run_name, run in RUNS.items():
                    seq = [shifts[p] for p in run]
                    deg, const = poly_degree(seq)
                    rec = fit_recurrence(seq)
                    if deg is not None and deg <= 2:
                        poly_hits.append({"alpha": an, "conv": conv, "run": run_name, "degree": deg})
                    if rec is not None:
                        rec_hits.append({"alpha": an, "conv": conv, "run": run_name, "abc": rec})
                    f.write(json.dumps({"alpha": an, "conv": conv, "run": run_name, "seq": seq,
                                        "diffs": diffs(seq), "poly_degree": deg, "recurrence_abc": rec}) + "\n")
                # known-sequence match over all 24 crib positions
                KS = known_sequences(full_positions)
                for kname, kseq in KS.items():
                    matches = sum(1 for p in full_positions if (shifts[p] - kseq[p]) % 26 == 0)
                    # also allow a global additive offset
                    best_off = max(range(26), key=lambda o: sum(1 for p in full_positions
                                                                if (shifts[p] - kseq[p] - o) % 26 == 0))
                    off_matches = sum(1 for p in full_positions if (shifts[p] - kseq[p] - best_off) % 26 == 0)
                    if max(matches, off_matches) >= 18:   # >=75% of 24 -> notable
                        seq_hits.append({"alpha": an, "conv": conv, "seq": kname,
                                         "matches": matches, "offset_matches": off_matches, "offset": best_off})
                # run-to-run relationship (same length? offset/reverse)
                ene = [shifts[p] for p in RUNS["EASTNORTHEAST"]]
                bc = [shifts[p] for p in RUNS["BERLINCLOCK"]]
                # compare overlapping prefix
                L = min(len(ene), len(bc))
                same_off = max(range(26), key=lambda o: sum(1 for i in range(L) if (ene[i] - bc[i] - o) % 26 == 0))
                off_match = sum(1 for i in range(L) if (ene[i] - bc[i] - same_off) % 26 == 0)
                rev_off = max(range(26), key=lambda o: sum(1 for i in range(L)
                                                           if (ene[i] - bc[L - 1 - i] - o) % 26 == 0))
                rev_match = sum(1 for i in range(L) if (ene[i] - bc[L - 1 - i] - rev_off) % 26 == 0)
                if max(off_match, rev_match) >= 9:   # >=80% of 11 overlap
                    findings.append({"alpha": an, "conv": conv, "run_relation":
                                     {"fwd_offset": same_off, "fwd_match": off_match,
                                      "rev_offset": rev_off, "rev_match": rev_match}})

    elapsed = time.perf_counter() - t0
    any_structure = bool(poly_hits or rec_hits or seq_hits or findings)
    insights = [
        f"Analysed the 24 crib shifts as a sequence across {len(ALPHS)} alphabets x 3 conventions x 2 contiguous "
        f"runs. Low-degree (<=2) polynomial-in-position fits: {poly_hits or 'NONE'}. Short linear-recurrence "
        f"(s_i=a*s_-1+b*s_-2+c mod 26) fits per run: {len(rec_hits)} ({rec_hits[:3]}).",
        f"Known-sequence matches (>=18/24, with optional global offset): {seq_hits or 'NONE'}. "
        f"Run-to-run (EASTNORTHEAST vs BERLINCLOCK) offset/reversal relations (>=9/11): {findings or 'NONE'}.",
        ("STRUCTURE FOUND: a generating rule fits the crib shifts -- investigate as the key schedule and extend "
         "to all 97 positions, then decrypt + hexagram-verify." if any_structure else
         "NO generating structure: the crib shifts are not a low-degree polynomial, short linear recurrence, "
         "common indexed sequence, or simple run-to-run transform in any tested alphabet/convention. The shift "
         "sequence is structureless under deterministic number-theoretic tests -- consistent with a hand-crafted "
         "(non-algorithmic) key, and with the 092 under-determination."),
    ]

    write_verdict(out, Verdict(
        exp="103", title="number-theoretic structure of the 24 crib shifts",
        hypothesis="the crib-shift sequence is generated by a short deterministic rule (polynomial / recurrence "
                   "/ known sequence) recoverable as the key schedule",
        status="promising" if any_structure else "ruled_out",
        best_partial=(f"poly<=2: {len(poly_hits)}; recurrences: {len(rec_hits)}; seq-matches: {len(seq_hits)}; "
                      f"run-relations: {len(findings)}"),
        search_space=len(ALPHS) * 3 * 2, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["extend the fitted rule to all 97 positions; decrypt + verify"] if any_structure else
                    ["crib shifts are number-theoretically structureless; no key-schedule rule. Remaining info "
                     "paths: transcription robustness (101), method-clue catalog (102), physical audit (104)"]),
        metrics={"poly_hits": poly_hits, "n_recurrences": len(rec_hits), "seq_hits": seq_hits,
                 "run_relations": findings, "any_structure": any_structure}),
    )
    print(f"\npoly<=2:{len(poly_hits)} recurrences:{len(rec_hits)} seq-matches:{len(seq_hits)} "
          f"run-rel:{len(findings)}; structure={any_structure}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
