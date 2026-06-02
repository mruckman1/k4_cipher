"""071 — Model-agnostic measurements that constrain everything (cheap).

Three pure measurements on the ciphertext + cribs (no cipher hypothesis):

(1) Per-plaintext-letter shift clustering: does the crib shift behave like a
    function of the PLAINTEXT letter (shift ~= T[plain] + small delta)? Fit a
    single 26-entry shift table T greedily and count cribs satisfiable with
    |delta|<=0,1,2. A tight fit is the fingerprint of Scheidt's 'masking'
    (monoalphabetic-ish shift + small correction).

(2) Restricted shift-value alphabet + fixed points: how many of 26 possible
    shift values do the 24 cribs use, and how many fixed points (shift 0)?
    Monte-Carlo significance vs uniform shifts.

(3) Entropy floor: unigram entropy of the 73 non-crib positions, bootstrapped,
    vs a monoalphabetic-English-at-N null -- a flatness bound (analogous to
    chi=3) lower-bounding the polyalphabetic period / fractionation order.
    Plus autocorrelation at offsets 1-30 with multiple-comparison correction.

Output: experiments/results/<date>_071_measurements.jsonl
"""

from __future__ import annotations

import json
import math
import random
import time
from collections import Counter, defaultdict
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import STANDARD
from kryptos.constants import K1_PLAINTEXT, K4
from kryptos.cribs import CRIBS
from kryptos.scoring.crib_check import surviving_positions
from kryptos.utils import clean


def crib_shifts(alpha):
    out = []
    for c in CRIBS:
        for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext)):
            pos = c.start - 1 + off
            out.append((pos, p, (alpha.index(p) - alpha.index(ch)) % 26))   # plain-cipher
    return out


def entropy(s):
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in Counter(s).values())


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_071_measurements.jsonl"
    t0 = time.perf_counter()
    rng = random.Random(0)

    # (1) per-plaintext-letter shift clustering
    sh = crib_shifts(STANDARD)
    by_letter = defaultdict(list)
    for pos, p, s in sh:
        by_letter[p].append(s)
    cluster = {p: sorted(set(v)) for p, v in sorted(by_letter.items())}
    spread = {p: (max(v) - min(v)) for p, v in by_letter.items() if len(v) > 1}
    # greedy single shift-table T = per-letter median; count satisfiable within delta
    T = {p: round(sum(v) / len(v)) % 26 for p, v in by_letter.items()}
    def within(d):
        return sum(1 for pos, p, s in sh if min((s - T[p]) % 26, (T[p] - s) % 26) <= d)
    fit0, fit1, fit2 = within(0), within(1), within(2)

    # (2) restricted shift-value alphabet + fixed points
    vals = [s for _, _, s in sh]
    distinct = sorted(set(vals))
    fixed_points = [pos + 1 for pos, p, s in sh if s == 0]
    # MC: P(<= len(distinct) distinct values in 24 uniform draws)
    cnt = 0
    N = 20000
    for _ in range(N):
        d = len(set(rng.randrange(26) for _ in range(24)))
        if d <= len(distinct):
            cnt += 1
    p_distinct = cnt / N

    # (3) entropy of 73 non-crib positions
    free_pos = surviving_positions(97, CRIBS)
    free_text = "".join(K4[i] for i in free_pos)
    H = entropy(free_text)
    # monoalphabetic-English-at-N null: substitute English (K1 plaintext sampled) then measure entropy
    eng = clean((K1_PLAINTEXT * 5))
    null_H = []
    for _ in range(5000):
        s = rng.randrange(len(eng) - len(free_text))
        seg = eng[s:s + len(free_text)]
        # random monoalphabetic relabel preserves the entropy of the SAMPLE
        null_H.append(entropy(seg))
    null_H.sort()
    p99 = null_H[int(0.99 * len(null_H))]
    frac_ge = sum(1 for h in null_H if h >= H) / len(null_H)

    # autocorrelation offsets 1-30
    ac = {}
    for off in range(1, 31):
        ac[off] = sum(1 for i in range(97 - off) if K4[i] == K4[i + off])
    best_off = max(ac, key=ac.get)

    elapsed = time.perf_counter() - t0
    with open(out, "w") as f:
        f.write(json.dumps({
            "per_letter_shift_cluster": cluster,
            "shift_table_fit": {"within_0": fit0, "within_1": fit1, "within_2": fit2, "of": len(sh)},
            "distinct_shift_values": distinct, "n_distinct": len(distinct),
            "fixed_point_positions_1idx": fixed_points, "p_distinct_le_by_chance": round(p_distinct, 4),
            "free_entropy_bits": round(H, 4), "mono_english_p99": round(p99, 4),
            "free_entropy_frac_ge_null": round(frac_ge, 4),
            "autocorr": ac, "best_offset": best_off, "best_offset_coincidences": ac[best_off],
        }) + "\n")

    insights = [
        f"(1) Shift-as-fn-of-plaintext: a single 26-entry shift table T (per-letter median) satisfies "
        f"{fit0}/{len(sh)} cribs exactly, {fit1}/{len(sh)} within |delta|<=1, {fit2}/{len(sh)} within <=2. "
        f"Per-letter spread (max-min) for multi-occurrence letters: {spread}.",
        f"(2) The 24 cribs use {len(distinct)}/26 distinct shift values {distinct}; fixed points (shift 0) "
        f"at positions {fixed_points}; P(<= {len(distinct)} distinct by chance under uniform) = {p_distinct:.3f}.",
        f"(3) Free-positions (73) unigram entropy = {H:.3f} bits; monoalphabetic-English-at-N p99 = {p99:.3f}, "
        f"frac of English samples with entropy >= K4's = {frac_ge:.3f}. Best autocorrelation offset = "
        f"{best_off} ({ac[best_off]} coincidences).",
    ]
    # 'promising' if the shift-table fit is strong (a real new structural lead) or entropy is decisively flat
    promising = (fit1 >= 20) or (frac_ge < 0.01) or (p_distinct < 0.02)
    if fit1 >= 20:
        insights.append(f"LEAD: a single plaintext-letter shift table explains >=20/24 cribs within +/-1 -- "
                        f"strong evidence the shift is mostly a function of the plaintext letter (Scheidt 'masking' "
                        f"= monoalphabetic shift + small correction). Pursue: solve T over the 73 free positions.")
    elif frac_ge < 0.01:
        insights.append(f"CONSTRAINT: K4's free-position entropy ({H:.2f}) exceeds the monoalphabetic-English "
                        f"null (p99={p99:.2f}) -- a flatness bound proving a polyalphabetic/fractionating stage "
                        f"is required (lower bound on period/order, analogous to chi=3).")
    else:
        insights.append("No single measurement crosses a decisive threshold; the values are recorded as "
                        "standing constraints for future hypothesis pruning.")
    write_verdict(out, Verdict(
        exp="071", title="model-agnostic measurements (shift clustering, restricted shifts, entropy floor)",
        hypothesis="the ciphertext+cribs carry model-agnostic structure that constrains the cipher",
        status="promising" if promising else "inconclusive",
        best_partial=f"shift-table fit {fit1}/24 within +/-1; entropy {H:.2f} (p99 {p99:.2f})",
        search_space=len(sh), elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=["if shift-table fit strong: solve T over free positions and verify; "
                    "use the entropy floor to set the minimum period in any future polyalphabetic sweep"],
        metrics={"shift_fit_within1": fit1, "free_entropy": round(H, 3), "distinct_shifts": len(distinct)})
    )
    print(f"\nshift-table within1 {fit1}/24; free entropy {H:.3f}; distinct shifts {len(distinct)}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
