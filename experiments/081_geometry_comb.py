"""081 — Geometry -> coincidence-comb forward map (offset-7 tooth + doublets).

K4's single sharpest unexplained ciphertext anomaly is its autocorrelation at
offset 7 (9 coincidences; = K3's width). This is FORWARD and plaintext-free:
(1) test how significant K4's offset-7 tooth actually is (a-priori vs
max-over-30 corrected, against a permutation null); (2) ask which cipher
GEOMETRY naturally concentrates autocorrelation mass at offset 7, calibrated so
that width-7 columnar (K3) reproduces a 7-tooth and Quagmire (K1/K2) stays flat.
A geometry matching K4's comb is suggestive (not decisive -- corrected p~0.086).

Output: experiments/results/<date>_081_geometry_comb.jsonl
"""

from __future__ import annotations

import json
import random
import statistics
import time
from collections import Counter
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.ciphers.bifid import Bifid
from kryptos.ciphers.keyed_fractionation import KeyedFractionation
from kryptos.ciphers.quagmire import QuagmireIII
from kryptos.ciphers.transposition import ColumnarTransposition
from kryptos.ciphers.trifid import Trifid
from kryptos.constants import K2, K3, K4
from kryptos.utils import clean

N = 97
CORP = clean(Path("data/corpora/buchan_39steps.txt").read_text())


def autocorr(ct, maxoff=30):
    return [sum(1 for i in range(len(ct) - off) if ct[i] == ct[i + off]) for off in range(1, maxoff + 1)]


def doublet_positions(ct):
    return [i for i in range(len(ct) - 1) if ct[i] == ct[i + 1]]


def perm_null_offset7(ct, trials, rng):
    """Permutation null: shuffle ct, count offset-7 coincidences; p that >= observed."""
    obs = autocorr(ct)[6]
    chars = list(ct)
    ge = 0
    for _ in range(trials):
        rng.shuffle(chars)
        c7 = sum(1 for i in range(len(chars) - 7) if chars[i] == chars[i + 7])
        if c7 >= obs:
            ge += 1
    return obs, ge / trials


def sample_english(rng):
    s = rng.randrange(len(CORP) - N)
    return CORP[s:s + N]


def geom_comb(maker, rng, n=300):
    """Average autocorrelation comb + mean doublets over n English encryptions."""
    combs = []
    doubs = []
    for _ in range(n):
        try:
            ct = maker(sample_english(rng), rng)
        except Exception:
            continue
        if not ct or len(ct) < N:
            continue
        ct = ct[:N]
        combs.append(autocorr(ct))
        doubs.append(len(doublet_positions(ct)))
    if not combs:
        return None
    mean_comb = [statistics.mean(c[k] for c in combs) for k in range(30)]
    peak = max(range(30), key=lambda k: mean_comb[k]) + 1
    return {"mean_comb": [round(x, 2) for x in mean_comb], "peak_offset": peak,
            "ac7": round(mean_comb[6], 2), "mean_doublets": round(statistics.mean(doubs), 2)}


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_081_geometry_comb.jsonl"
    rng = random.Random(0)
    t0 = time.perf_counter()

    k4_ac = autocorr(K4)
    obs7, p7_apriori = perm_null_offset7(K4, 20000, random.Random(1))
    # corrected: P(max over offsets 1..30 >= obs) -- approximate via per-offset null
    rng2 = random.Random(2)
    chars = list(K4); maxge = 0
    for _ in range(20000):
        rng2.shuffle(chars)
        mx = max(sum(1 for i in range(N - off) if chars[i] == chars[i + off]) for off in range(1, 31))
        if mx >= obs7:
            maxge += 1
    p7_corrected = maxge / 20000

    geoms = {
        "columnar_w7": lambda pt, r: ColumnarTransposition(tuple(r.sample(range(7), 7))).encrypt(pt),
        "columnar_w8": lambda pt, r: ColumnarTransposition(tuple(r.sample(range(8), 8))).encrypt(pt),
        "quagmire_7": lambda pt, r: QuagmireIII(key="".join(chr(65 + r.randrange(26)) for _ in range(7)),
                                                alphabet_keyword="KRYPTOS").encrypt(pt),
        "bifid_7": lambda pt, r: Bifid(keyword="KRYPTOS", period=7).encrypt(pt),
        "trifid_7": lambda pt, r: Trifid(keyword="KRYPTOS", period=7).encrypt(pt),
        "fractionation_2x13": lambda pt, r: KeyedFractionation.from_keyword(
            "KRYPTOS", (2, 13), [r.randrange(2) for _ in range(r.randrange(2, 6))],
            [r.randrange(13) for _ in range(r.randrange(2, 6))]).encrypt(pt),
        "interleave7": lambda pt, r: "".join(pt[c::7] for c in range(7))[:N],
    }
    results = {g: geom_comb(maker, rng) for g, maker in geoms.items()}

    elapsed = time.perf_counter() - t0
    # which geometry's peak is at offset 7, like K4 (peak offset of K4)?
    k4_peak = max(range(30), key=lambda k: k4_ac[k]) + 1
    matches7 = [g for g, r in results.items() if r and r["peak_offset"] == 7]

    with open(out, "w") as f:
        f.write(json.dumps({"K4_ac7": obs7, "K4_peak_offset": k4_peak,
                            "p_apriori_offset7": round(p7_apriori, 4),
                            "p_corrected_maxoffset": round(p7_corrected, 4),
                            "geometry_combs": results, "geoms_peaking_at_7": matches7}) + "\n")

    insights = [
        f"K4 offset-7 autocorrelation = {obs7} coincidences. Permutation null: a-priori p(>=obs at offset 7) "
        f"= {p7_apriori:.4f}; max-over-30-offsets corrected p = {p7_corrected:.4f}. K4's overall peak offset "
        f"= {k4_peak}.",
        f"Geometries whose mean autocorrelation PEAKS at offset 7: {matches7 or 'NONE'}. "
        f"Calibration: columnar_w7 ac7={results.get('columnar_w7', {}).get('ac7')}, peak "
        f"{results.get('columnar_w7', {}).get('peak_offset')}; quagmire_7 ac7="
        f"{results.get('quagmire_7', {}).get('ac7')} (expected flat).",
        f"K4 mean-doublet comparison: K4 has {len(doublet_positions(K4))} doublets; fractionation_2x13 mean "
        f"{results.get('fractionation_2x13', {}).get('mean_doublets')}, columnar_w7 mean "
        f"{results.get('columnar_w7', {}).get('mean_doublets')}.",
    ]
    # honest status: the offset-7 tooth is only borderline after correction
    decisive = p7_corrected < 0.05 and len(matches7) == 1
    if p7_corrected >= 0.05:
        insights.append(f"VERDICT: after multiple-comparison correction the offset-7 tooth is NOT significant "
                        f"(p={p7_corrected:.3f}); it is most likely small-N noise, not a geometric signature. "
                        f"The 'offset-7 => width-7 fractionation' folk hypothesis is not supported. (Width-7 "
                        f"transposition+substitution was already exhausted in 043/052/064/075.)")
    write_verdict(out, Verdict(
        exp="081", title="geometry->coincidence-comb forward map (offset-7 significance)",
        hypothesis="K4's offset-7 autocorrelation tooth is a fractionation-geometry signature",
        status="promising" if decisive else "ruled_out",
        best_partial=f"offset7={obs7}, corrected p={round(p7_corrected,3)}, geoms@7={matches7}",
        search_space=len(geoms), elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["pin the matching geometry with a backward KPA"] if decisive else
                    ["offset-7 retired as noise; the only robust forward constraints remain entropy-flatness "
                     "(071/080): outermost stage flattens beyond one alphabet"]),
        metrics={"p_corrected": round(p7_corrected, 4), "geoms_at_7": matches7})
    )
    print(f"\noffset7={obs7}, apriori p={p7_apriori:.4f}, corrected p={p7_corrected:.4f}; geoms@7={matches7}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
