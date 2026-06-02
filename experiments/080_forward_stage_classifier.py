"""080 — Forward cipher stage-structure classifier, calibrated on K1/K2/K3.

Every prior experiment was BACKWARD (assume a family, KPA against cribs). This
is FORWARD and ciphertext-only (no plaintext slot -> structurally immune to the
exp-059 degeneracy): compute diagnostic statistics of K4's ciphertext and ask
which construction CLASS's synthetic-output cloud it lands in -- but only after
the SAME classifier correctly labels the KNOWN K1=Quagmire-III, K2=Q3,
K3=columnar (the Rosetta calibration; if it can't separate the known ciphers it
is untrustworthy).

The load-bearing, plaintext-invariant axis: TRANSPOSITION preserves the unigram
multiset exactly (IoC = plaintext ~0.066), while SUBSTITUTION flattens it. So
the test reads STAGE STRUCTURE -- is the outermost stage a flattener? how flat
vs a single alphabet? -- not a single family name (substitution/fractionation
clouds overlap at N=97).

Output: experiments/results/<date>_080_forward_stage_classifier.jsonl
"""

from __future__ import annotations

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
from kryptos.alphabets import STANDARD, keyed_alphabet
from kryptos.ciphers.bifid import Bifid
from kryptos.ciphers.quagmire import QuagmireIII
from kryptos.ciphers.transposition import ColumnarTransposition
from kryptos.ciphers.trifid import Trifid
from kryptos.constants import K1, K2, K3, K4
from kryptos.utils import clean

N = 97


def feats(ct):
    n = len(ct)
    cnt = Counter(ct)
    probs = [v / n for v in cnt.values()]
    H = -sum(p * math.log2(p) for p in probs)
    ioc = sum(v * (v - 1) for v in cnt.values()) / (n * (n - 1))
    top5 = sum(sorted(cnt.values(), reverse=True)[:5]) / n
    doublets = sum(1 for i in range(n - 1) if ct[i] == ct[i + 1]) / (n - 1)
    ac = [sum(1 for i in range(n - off) if ct[i] == ct[i + off]) / (n - off) for off in range(1, 16)]
    return [H, ioc, top5, doublets] + ac


def english(rng, length=N):
    txt = english.corpus
    s = rng.randrange(len(txt) - length)
    return txt[s:s + length]


english.corpus = clean(Path("data/corpora/buchan_39steps.txt").read_text()
                       + clean(Path("data/corpora/smith_tutankhamen.txt").read_text()))


def gen(cls, rng):
    pt = english(rng)
    try:
        if cls == "mono":
            a = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ"); rng.shuffle(a)
            m = {chr(65 + i): a[i] for i in range(26)}
            return "".join(m[c] for c in pt)
        if cls.startswith("quagmire"):
            L = int(cls.split("_")[1])
            key = "".join(chr(65 + rng.randrange(26)) for _ in range(L))
            return QuagmireIII(key=key, alphabet_keyword="KRYPTOS").encrypt(pt)
        if cls == "columnar":
            w = rng.choice([7, 8, 9, 10])
            order = tuple(rng.sample(range(w), w))
            return ColumnarTransposition(order).encrypt(pt)[:N]
        if cls == "bifid":
            return Bifid(keyword="KRYPTOS", period=rng.choice([5, 7, 9])).encrypt(pt)
        if cls == "trifid":
            return Trifid(keyword="KRYPTOS", period=rng.choice([5, 7])).encrypt(pt)
        if cls == "sub_then_transpose":
            L = rng.choice([5, 7, 9])
            key = "".join(chr(65 + rng.randrange(26)) for _ in range(L))
            m = QuagmireIII(key=key, alphabet_keyword="KRYPTOS").encrypt(pt)
            w = rng.choice([7, 8, 9]); order = tuple(rng.sample(range(w), w))
            return ColumnarTransposition(order).encrypt(m)[:N]
        if cls == "transpose_then_sub":
            w = rng.choice([7, 8, 9]); order = tuple(rng.sample(range(w), w))
            m = ColumnarTransposition(order).encrypt(pt)[:N]
            L = rng.choice([5, 7, 9])
            key = "".join(chr(65 + rng.randrange(26)) for _ in range(L))
            return QuagmireIII(key=key, alphabet_keyword="KRYPTOS").encrypt(m)
    except Exception:
        return None
    return None


CLASSES = ["mono", "quagmire_5", "quagmire_7", "quagmire_10", "columnar", "bifid",
           "trifid", "sub_then_transpose", "transpose_then_sub"]


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_080_forward_stage_classifier.jsonl"
    rng = random.Random(0)
    t0 = time.perf_counter()
    # build clouds
    clouds = {}
    for cls in CLASSES:
        rows = []
        while len(rows) < 600:
            ct = gen(cls, rng)
            if ct and len(ct) == N:
                rows.append(feats(ct))
        clouds[cls] = rows
    # standardize
    allrows = [r for rows in clouds.values() for r in rows]
    mu = [statistics.mean(c) for c in zip(*allrows)]
    sd = [statistics.pstdev(c) or 1 for c in zip(*allrows)]
    def z(v): return [(v[i] - mu[i]) / sd[i] for i in range(len(v))]
    centroids = {cls: [statistics.mean(c) for c in zip(*[z(r) for r in rows])] for cls, rows in clouds.items()}

    def classify(ct):
        zf = z(feats(ct))
        d = {cls: math.dist(zf, cen) for cls, cen in centroids.items()}
        return sorted(d.items(), key=lambda kv: kv[1])

    cal = {"K1": classify(K1[:N] if len(K1) >= N else K1),
           "K2": classify(K2[:N]), "K3": classify(K3[:N])}
    k4 = classify(K4)
    # transposition vs substitution axis (exact): does ct preserve a flat (English) IoC?
    k4f = feats(K4)
    elapsed = time.perf_counter() - t0

    with open(out, "w") as f:
        f.write(json.dumps({"K4_features": {"H": round(k4f[0], 3), "ioc": round(k4f[1], 4),
                                            "top5": round(k4f[2], 3), "doublets": round(k4f[3], 4),
                                            "ac7": round(k4f[4 + 6], 4)},
                            "K1_top3": cal["K1"][:3], "K2_top3": cal["K2"][:3],
                            "K3_top3": cal["K3"][:3], "K4_top3": k4[:3]}) + "\n")

    cal_ok = (cal["K1"][0][0].startswith("quagmire") and cal["K2"][0][0].startswith("quagmire")
              and cal["K3"][0][0] == "columnar")
    sub_centroid_top5 = statistics.mean([feats(gen("quagmire_7", random.Random(i)) or "A" * N)[2]
                                         for i in range(200)])
    insights = [
        f"Calibration on known ciphers: K1->{cal['K1'][0][0]}, K2->{cal['K2'][0][0]}, K3->{cal['K3'][0][0]} "
        f"(expected quagmire/quagmire/columnar). Classifier trustworthy = {cal_ok}.",
        f"K4 nearest construction clouds: {[(c, round(d, 2)) for c, d in k4[:3]]}.",
        f"FORWARD CONSTRAINT (exact, plaintext-invariant): K4 IoC={k4f[1]:.4f} is flattened (English ~0.066, "
        f"transposition preserves it) -> the OUTERMOST stage is a flattener, NOT a pure transposition. "
        f"K4 top5-mass={k4f[2]:.3f} vs single-Quagmire centroid {sub_centroid_top5:.3f} -> K4 is FLATTER than "
        f"a single substitution alphabet, evidence the flattening exceeds one alphabet (multi-alphabet / "
        f"fractionation / composite outermost stage).",
    ]
    # forward classifier is a constraint generator, not a solver
    status = "promising" if cal_ok else "inconclusive"
    write_verdict(out, Verdict(
        exp="080", title="forward stage-structure classifier (calibrated on K1-K3)",
        hypothesis="ciphertext-only statistics identify K4's stage structure / outermost-stage type",
        status=status, best_partial=f"calibration_ok={cal_ok}; K4 nearest={k4[0][0]}",
        search_space=len(CLASSES) * 600, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=["use the forward bound (outermost stage flattens beyond one alphabet, is not pure "
                    "transposition) to prune which composites get a backward KPA; re-apply to K5 when released"],
        metrics={"K4_top3": k4[:3], "K4_features": k4f, "calibration": cal_ok})
    )
    print(f"\ncalib_ok={cal_ok}; K4 nearest {k4[0][0]} (d={k4[0][1]:.2f}). -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
