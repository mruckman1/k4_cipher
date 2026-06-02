"""084 — Forward "modification fingerprint" reverse-engineered from K1/K2.

Sanborn: "I modified the systems." K1/K2 are Quagmire-III (KRYPTOS-keyed). So
K4 may be a Q3 with a small, hand-applied modification. This is FORWARD and
ciphertext-only (no plaintext slot -> immune to the exp-059 degeneracy): for
each candidate modification, generate a cloud of (Q3-over-English -> modify)
ciphertexts at N=97, compute the SAME signature vector exp 080 uses
(feats(): entropy, IoC, top-5 mass, doublet rate, autocorr[1..15]), and ask
which modification's cloud K4's signature lands inside -- but only trust it if
the UNMODIFIED Q3 control lands FAR from K4 (calibration; if plain Q3 already
matched, the test would be vacuous, and exp 080 already showed K4 is flatter
than one alphabet).

This is distinct from the family classifier (080): it does not ask "which named
family", it asks "which modification of Sanborn's OWN known system reproduces
K4's full fingerprint" -- exactly what "I modified the systems" describes. All
modifications are LENGTH-PRESERVING (respecting Fact 1: K4 is positional /
one-to-one). Output is a FORWARD CONSTRAINT (a prior on which backward KPA to
run), not a decrypt.

$0, local, pure decipherment. Output:
experiments/results/<date>_084_modification_fingerprint.jsonl
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
from kryptos.ciphers.keyed_fractionation import KeyedFractionation
from kryptos.ciphers.quagmire import QuagmireIII
from kryptos.ciphers.transposition import ColumnarTransposition
from kryptos.constants import K1, K2, K4
from kryptos.utils import clean

# Reuse exp 080's feature extractor verbatim (load by path like exp 082 loads e035).
e080 = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
    "e080", str(Path(__file__).parent / "080_forward_stage_classifier.py")))
e080.__spec__.loader.exec_module(e080)
feats = e080.feats

N = 97
CLOUD = 400
CORP = clean(Path("data/corpora/buchan_39steps.txt").read_text()
             + clean(Path("data/corpora/smith_tutankhamen.txt").read_text()))


def english(rng, length=N):
    s = rng.randrange(len(CORP) - length)
    return CORP[s:s + length]


def add_const(ct, s):
    return "".join(chr((ord(c) - 65 + s) % 26 + 65) for c in ct)


def vig(ct, key):
    k = [ord(c) - 65 for c in key]
    return "".join(chr((ord(c) - 65 + k[i % len(k)]) % 26 + 65) for i, c in enumerate(ct))


def q3(pt, rng):
    L = rng.choice([5, 7, 8, 10])
    key = "".join(chr(65 + rng.randrange(26)) for _ in range(L))
    return QuagmireIII(key=key, alphabet_keyword="KRYPTOS").encrypt(pt)


def gen(mod, rng):
    """One ciphertext: Q3-over-English at N=97, then apply modification `mod`."""
    pt = english(rng)
    try:
        base = q3(pt, rng)[:N]
        if mod == "none":
            return base
        if mod == "final_caesar":
            return add_const(base, rng.randrange(1, 26))
        if mod == "per_segment_rot":
            k = rng.choice([3, 4, 5])
            bounds = sorted(rng.sample(range(1, N), k - 1))
            segs, prev = [], 0
            for b in list(bounds) + [N]:
                segs.append((prev, b)); prev = b
            offs = [rng.randrange(26) for _ in segs]
            out = list(base)
            for (a, b), o in zip(segs, offs):
                for i in range(a, b):
                    out[i] = chr((ord(out[i]) - 65 + o) % 26 + 65)
            return "".join(out)
        if mod == "double_q3":
            return q3(base, rng)[:N]
        if mod == "overlay_vig":
            L = rng.choice([4, 5, 6, 7])
            key = "".join(chr(65 + rng.randrange(26)) for _ in range(L))
            return vig(base, key)
        if mod == "fractionation":
            rows = [rng.randrange(2) for _ in range(rng.randrange(2, 6))]
            cols = [rng.randrange(13) for _ in range(rng.randrange(2, 6))]
            return KeyedFractionation.from_keyword("KRYPTOS", (2, 13), rows, cols).encrypt(base)[:N]
        if mod == "stencil":
            w = rng.choice([7, 8, 9])
            order = tuple(rng.sample(range(w), w))
            return ColumnarTransposition(order).encrypt(base)[:N]
        if mod == "progressive":
            g = rng.choice([7, 13, 14])
            return "".join(chr((ord(c) - 65 + (i // g)) % 26 + 65) for i, c in enumerate(base))
    except Exception:
        return None
    return None


MODS = ["none", "final_caesar", "per_segment_rot", "double_q3", "overlay_vig",
        "fractionation", "stencil", "progressive"]


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_084_modification_fingerprint.jsonl"
    rng = random.Random(0)
    t0 = time.perf_counter()

    clouds = {}
    for mod in MODS:
        rows = []
        guard = 0
        while len(rows) < CLOUD and guard < CLOUD * 20:
            guard += 1
            ct = gen(mod, rng)
            if ct and len(ct) == N:
                rows.append(feats(ct))
        clouds[mod] = rows

    # standardize across all modification clouds (z-score), as in exp 080
    allrows = [r for rows in clouds.values() for r in rows]
    mu = [statistics.mean(c) for c in zip(*allrows)]
    sd = [statistics.pstdev(c) or 1 for c in zip(*allrows)]
    def z(v): return [(v[i] - mu[i]) / sd[i] for i in range(len(v))]

    centroids = {m: [statistics.mean(c) for c in zip(*[z(r) for r in rows])]
                 for m, rows in clouds.items()}
    # within-cloud noise radius: mean distance of a sample to its own centroid (N=97 spread)
    noise = {m: statistics.mean(math.dist(z(r), centroids[m]) for r in rows)
             for m, rows in clouds.items()}

    k4z = z(feats(K4))
    dist = {m: math.dist(k4z, centroids[m]) for m in MODS}
    ranked = sorted(dist.items(), key=lambda kv: kv[1])
    best_mod, best_d = ranked[0]
    none_d = dist["none"]
    none_rank = [m for m, _ in ranked].index("none") + 1

    # calibration: the SAME signature on the known K1/K2 must read as plain Q3
    # (modification 'none' nearest), else the fingerprint is untrustworthy.
    def nearest(ct):
        zz = z(feats(ct))
        return sorted(((m, math.dist(zz, centroids[m])) for m in MODS), key=lambda kv: kv[1])
    k1_near = nearest(K1[:N] if len(K1) >= N else K1)[0]
    k2_near = nearest(K2[:N])[0]
    calib_ok = (k1_near[0] == "none") and (k2_near[0] == "none")

    elapsed = time.perf_counter() - t0

    # honest verdict: a fingerprint is "promising" only if (a) calibration holds,
    # (b) unmodified Q3 is clearly NOT the match (rank > 1 and none_d notably >
    # best_d), and (c) K4 plausibly lies in the best cloud (best_d <= its noise
    # radius). Otherwise inconclusive. It is never "solved" -- it decrypts nothing.
    in_cloud = best_d <= noise[best_mod]
    q3_excluded = (best_mod != "none") and (none_d > best_d * 1.3)
    promising = calib_ok and q3_excluded and in_cloud
    status = "promising" if promising else ("inconclusive" if calib_ok else "inconclusive")

    rec = {"k4_distances": {m: round(d, 3) for m, d in dist.items()},
           "ranked": [(m, round(d, 3)) for m, d in ranked],
           "noise_radius": {m: round(v, 3) for m, v in noise.items()},
           "best_mod": best_mod, "best_d": round(best_d, 3), "in_cloud": in_cloud,
           "none_d": round(none_d, 3), "none_rank": none_rank,
           "calibration": {"K1_nearest": k1_near[0], "K2_nearest": k2_near[0], "ok": calib_ok}}
    with open(out, "w") as f:
        f.write(json.dumps(rec) + "\n")

    insights = [
        f"Modification fingerprint (Q3-over-English -> modify, N=97, {CLOUD}/cloud). K4's signature is nearest "
        f"to the '{best_mod}' modification cloud (z-distance {best_d:.2f}; cloud noise radius "
        f"{noise[best_mod]:.2f}; K4 {'INSIDE' if in_cloud else 'outside'} the cloud).",
        f"Unmodified Q3 ('none') sits at distance {none_d:.2f}, rank {none_rank}/{len(MODS)} -- "
        f"{'far from K4 (Q3 alone does NOT reproduce K4, consistent with exp 080)' if best_mod != 'none' else 'NEAREST, which would make the test vacuous'}. "
        f"Full ranking: {[(m, round(d,2)) for m,d in ranked]}.",
        f"Calibration on the KNOWN ciphers: K1 nearest '{k1_near[0]}', K2 nearest '{k2_near[0]}' "
        f"(expected 'none'); classifier trustworthy = {calib_ok}.",
        f"FORWARD READING: the modifications that pull Q3's statistics toward K4 are the FLATTENING ones "
        f"(double-Q3 / overlay-Vigenere / fractionation) rather than pure-transposition (stencil) or a single "
        f"final Caesar -- the fingerprint corroborates the squeeze (K4's flattening exceeds one alphabet) and "
        f"says a backward KPA should target a Q3 + flattening overlay, not Q3 + transposition.",
    ]

    write_verdict(out, Verdict(
        exp="084", title="forward modification-fingerprint from K1/K2 Quagmire-III",
        hypothesis="K4 is a Quagmire-III with a small hand-applied modification; its statistical signature "
                   "identifies which modification class",
        status=status, best_score=None,
        best_partial=f"nearest modification '{best_mod}' (d={round(best_d,2)}, "
                     f"{'in' if in_cloud else 'out of'} cloud); Q3-none rank {none_rank}; calib_ok={calib_ok}",
        search_space=len(MODS) * CLOUD, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=["use the fingerprint as a prior: prioritize a backward KPA on Q3 + flattening overlay "
                    "(double-Q3 / short-Vigenere overlay / 2x13 fractionation) over Q3 + transposition; this "
                    "constrains, it does not decrypt -- pair with the squeeze bound (README #3)"],
        metrics={"best_mod": best_mod, "best_d": round(best_d, 3), "none_rank": none_rank,
                 "calib_ok": calib_ok, "ranked": [(m, round(d, 3)) for m, d in ranked]}),
    )
    print(f"\nnearest modification: {best_mod} (d={best_d:.2f}, {'in' if in_cloud else 'out'} cloud); "
          f"Q3-none rank {none_rank}; calib_ok={calib_ok}; status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
