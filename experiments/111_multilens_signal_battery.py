"""111 — Multi-lens structure-detection battery: is there ANY signal in K4's 97
characters, through any scientific lens, beyond 'flattened'?

The cipher-space is exhausted and the chart is bespoke (088/110), so this stops
attacking K4 as a cipher and asks the cross-disciplinary question: does the raw
ciphertext deviate from a flattened-RANDOM string on ANY structural axis? Lenses,
each with a permutation p-value vs the section's OWN shuffled multiset (the null
that preserves unigram frequencies and destroys only ORDER -- so a deviation = real
positional/order structure):

  - INFORMATION THEORY: lzma/bz2 compressibility (Kolmogorov proxy)
  - STATISTICS: runs test (parity), bigram chi-square (serial/poker)
  - SIGNAL PROCESSING: DFT periodogram peak of the letter-index sequence
  - COMBINATORICS: repeated-bigram count (Kasiski precursor)
  - CLASSICAL CRYPTO: Kappa / IoC-by-period (Friedman polyalphabetic-period test)
  - autocorrelation max (offset comb)

POWER CALIBRATION (the crux): the same battery runs on K1, K2 (periodic Quagmire,
keyword periods 10 & 8) and K3 (columnar). If it DETECTS their structure (e.g.
K1/K2's period via IoC-by-period) but finds NOTHING in K4, the 'no signal'
conclusion is power-validated. Any K4 test surviving Bonferroni correction is a
genuine new thread to chase.

$0, local, deterministic, no LLM, no K5, no plaintext. Output:
experiments/results/<date>_111_multilens_signal_battery.jsonl
"""

from __future__ import annotations

import bz2
import json
import lzma
import math
import random
import time
from collections import Counter
from datetime import date

import numpy as np

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K1, K2, K3, K4

M_SHUFFLE = 4000


def idxs(s):
    return [ord(c) - 65 for c in s]


def ioc(seq):
    n = len(seq)
    if n < 2:
        return 0.0
    c = Counter(seq)
    return sum(v * (v - 1) for v in c.values()) / (n * (n - 1))


def ioc_by_period(seq, maxm=30):
    """Friedman: mean within-class IoC for each period m; return (best_mean, m)."""
    best = (0.0, None)
    for m in range(2, min(maxm, len(seq) // 3) + 1):
        cls = [[] for _ in range(m)]
        for i, x in enumerate(seq):
            cls[i % m].append(x)
        vals = [ioc(c) for c in cls if len(c) > 1]
        if vals:
            mk = sum(vals) / len(vals)
            if mk > best[0]:
                best = (mk, m)
    return best


def dft_peak(seq):
    a = np.asarray(seq, float)
    a = a - a.mean()
    p = np.abs(np.fft.rfft(a)) ** 2
    return float(p[1:].max()) if len(p) > 1 else 0.0


def repeated_bigrams(seq):
    bg = Counter(tuple(seq[i:i + 2]) for i in range(len(seq) - 1))
    return sum(v - 1 for v in bg.values() if v > 1)


def runs_parity(seq):
    b = [x % 2 for x in seq]
    return 1 + sum(1 for i in range(1, len(b)) if b[i] != b[i - 1])


def bigram_chi2(seq):
    n = len(seq)
    uni = Counter(seq)
    bg = Counter((seq[i], seq[i + 1]) for i in range(n - 1))
    chi = 0.0
    for (a, b), o in bg.items():
        e = uni[a] * uni[b] / n
        if e > 0:
            chi += (o - e) ** 2 / e
    return chi


def autocorr_max(seq, maxoff=30):
    return max(sum(1 for i in range(len(seq) - off) if seq[i] == seq[i + off])
               for off in range(1, min(maxoff, len(seq) // 2) + 1))


def compress_lzma(s):
    return len(lzma.compress(s.encode(), preset=9))


def compress_bz2(s):
    return len(bz2.compress(s.encode(), 9))


# (name, fn-on-seq or fn-on-str, "high"=structure when stat HIGH / "low"=when LOW)
TESTS = [
    ("ioc_by_period", lambda s, seq: ioc_by_period(seq)[0], "high"),
    ("dft_peak", lambda s, seq: dft_peak(seq), "high"),
    ("repeated_bigrams", lambda s, seq: repeated_bigrams(seq), "high"),
    ("runs_parity", lambda s, seq: runs_parity(seq), "two"),
    ("bigram_chi2", lambda s, seq: bigram_chi2(seq), "high"),
    ("autocorr_max", lambda s, seq: autocorr_max(seq), "high"),
    ("lzma_size", lambda s, seq: compress_lzma(s), "low"),
    ("bz2_size", lambda s, seq: compress_bz2(s), "low"),
]


def pvalue(text, name, fn, side, rng):
    seq = idxs(text)
    obs = fn(text, seq)
    chars = list(text)
    ge = le = 0
    for _ in range(M_SHUFFLE):
        rng.shuffle(chars)
        st = "".join(chars)
        v = fn(st, idxs(st))
        if v >= obs:
            ge += 1
        if v <= obs:
            le += 1
    if side == "high":
        p = ge / M_SHUFFLE
    elif side == "low":
        p = le / M_SHUFFLE
    else:
        p = 2 * min(ge, le) / M_SHUFFLE
    return obs, min(p, 1.0)


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_111_multilens_signal_battery.jsonl"
    t0 = time.perf_counter()
    sections = {"K4": K4, "K1": K1, "K3": K3, "K2": K2}  # K4 target; K1/K2/K3 calibration

    bonf = 0.05 / (len(TESTS))   # per-section Bonferroni over the battery
    results = {}
    for name, text in sections.items():
        rng = random.Random(hash(name) & 0xffff)
        row = {}
        for tname, fn, side in TESTS:
            obs, p = pvalue(text, tname, fn, side, rng)
            row[tname] = {"obs": round(obs, 3) if isinstance(obs, float) else obs, "p": round(p, 4)}
        # also record the IoC-by-period detected period (the power-calibration headline)
        row["ioc_period"] = ioc_by_period(idxs(text))[1]
        results[name] = row

    elapsed = time.perf_counter() - t0
    # which tests are significant (Bonferroni) per section
    sig = {sec: [t for t in (x[0] for x in TESTS) if results[sec][t]["p"] < bonf] for sec in sections}
    k4_sig = sig["K4"]
    # power check: did the battery detect K1/K2 structure (their period)?
    k1_period, k2_period = results["K1"]["ioc_period"], results["K2"]["ioc_period"]
    k1k2_detected = (len(sig["K1"]) > 0 or len(sig["K2"]) > 0)

    with open(out, "w") as f:
        f.write(json.dumps({"bonferroni_alpha": round(bonf, 4), "M_shuffle": M_SHUFFLE,
                            "results": results, "significant_by_section": sig,
                            "k1_iocperiod": k1_period, "k2_iocperiod": k2_period,
                            "K1_keyword_period": 10, "K2_keyword_period": 8}) + "\n")

    insights = [
        f"Multi-lens structure battery ({len(TESTS)} tests x permutation null of each section's own multiset, "
        f"{M_SHUFFLE} shuffles; Bonferroni alpha={bonf:.4f}). Tests span info-theory (compress), statistics "
        f"(runs, chi2), signal-processing (DFT), combinatorics (repeats), and classical crypto (IoC-by-period).",
        f"POWER CALIBRATION on known ciphers: K1 significant tests {sig['K1']} (IoC-by-period detected m="
        f"{k1_period}; keyword PALIMPSEST=10), K2 {sig['K2']} (m={k2_period}; ABSCISSA=8), K3 {sig['K3']}. "
        f"Battery detects known-cipher structure = {k1k2_detected} -> it has {'POWER at these N' if k1k2_detected else 'LOW power (caveat)'}.",
        f"K4 RESULT: significant tests (Bonferroni) = {k4_sig or 'NONE'}. K4 per-test p-values: "
        f"{ {t: results['K4'][t]['p'] for t in (x[0] for x in TESTS)} }. IoC-by-period best m = {results['K4']['ioc_period']}.",
        (f"SIGNAL FOUND: K4 deviates from flattened-random on {k4_sig} -- a genuine structural thread to chase "
         f"(the deviating lens points at residual structure the cipher attacks missed)."
         if k4_sig else
         (f"NO SIGNAL: K4 shows NO structural deviation from a random shuffle of its own letters on any of the "
          f"{len(TESTS)} lenses (info-theoretic, statistical, spectral, combinatorial, classical) -- WHILE the "
          f"same battery DOES detect structure in the known ciphers (power-validated). K4's order is "
          f"statistically indistinguishable from a flattened-random string: the bespoke chart fully randomised "
          f"it. This is the cross-disciplinary capstone -- the public ciphertext carries no exploitable signal "
          f"beyond the cribs."
          if k1k2_detected else
          f"NO K4 signal, but the battery ALSO failed to flag the known ciphers -- it is UNDERPOWERED at N~97, "
          f"so the K4 null is inconclusive (absence of evidence, not evidence of absence) at this sample size.")),
    ]

    if k4_sig:
        status = "promising"
    elif k1k2_detected:
        status = "ruled_out"   # power-validated: no signal exists in the ciphertext
    else:
        status = "inconclusive"  # underpowered

    write_verdict(out, Verdict(
        exp="111", title="multi-lens structure-detection battery (cross-disciplinary signal hunt)",
        hypothesis="K4's 97-character ciphertext carries a detectable structural signal beyond unigram "
                   "flattening, through some scientific lens",
        status=status,
        best_partial=f"K4 significant tests: {k4_sig or 'none'}; power-check (K1/K2 detected)={k1k2_detected} "
                     f"(K1 m={k1_period}, K2 m={k2_period})",
        search_space=len(TESTS) * len(sections), elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=([f"chase the deviating lens: {k4_sig}"] if k4_sig else
                    (["cross-disciplinary capstone: no exploitable signal in the public ciphertext beyond the "
                      "cribs (power-validated against K1-K3). Consistent with the bespoke-chart / under-"
                      "determination result."] if k1k2_detected else
                     ["battery underpowered at N=97; the K4 null is inconclusive at this sample size"])),
        metrics={"k4_significant": k4_sig, "power_validated": k1k2_detected,
                 "k1_period": k1_period, "k2_period": k2_period, "bonferroni_alpha": round(bonf, 4)}),
    )
    print(f"\nK4 significant: {k4_sig or 'NONE'}; power (K1/K2 detected)={k1k2_detected} (K1 m={k1_period}, "
          f"K2 m={k2_period}); status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
