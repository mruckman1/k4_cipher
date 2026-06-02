"""115 — Does a 2-chart HOMOPHONIC cipher flatten English to K4's 4.33-bit
entropy? (the follow-up to 114's chi_b = 2)

114 found the homophonic chromatic number chi_b = 2 < chi_full = 3: a non-bijective
(homophonic) chart satisfies the cribs with only 2 charts. Homophonic substitution
also flattens frequency by design (spreading a frequent plaintext letter across
several cipher homophones). So the question that could RE-OPEN the structure: does
a k=2 homophonic cipher reach K4's free-position entropy (4.33 bits, Fact 2) while
covering all 26 plaintext letters? The bijective squeeze (085) needs k*=4 ROTATION
alphabets to flatten -- but homophonic flattening is a different mechanism and may
need far fewer charts.

Forward simulation (best case for the cipher): build k homophonic charts
(cipher->plaintext, non-injective, cipher-slots allocated to plaintext letters in
proportion to English frequency, union covering all 26), encrypt real English with
a least-used-cipher (flattening) policy, and measure the resulting CIPHER entropy.
Sweep k=1..5; find the homophonic flatten floor (min k reaching 4.33). If it is <=2
the homophonic model satisfies BOTH hard facts with 2 charts -> a simpler viable
model than the bijective >=4-alphabet one.

$0, local, deterministic, no LLM, no K5, no plaintext. Output:
experiments/results/<date>_115_homophonic_flatten_floor.jsonl
"""

from __future__ import annotations

import math
import random
import statistics
import time
from collections import Counter
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.utils import clean

N = 97
A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
K4_FREE_ENTROPY = 4.33   # Fact 2 target (exp 071)


def english_freq(corp):
    c = Counter(ch for ch in corp if ch.isalpha())
    tot = sum(c.values())
    return {ch: c.get(ch, 0) / tot for ch in A}


def allocate(freq, n_slots, min_per=0):
    """Largest-remainder allocation of n_slots cipher-slots to the 26 plaintext
    letters proportional to freq (optional min per letter)."""
    raw = {ch: freq[ch] * n_slots for ch in A}
    alloc = {ch: max(min_per, int(raw[ch])) for ch in A}
    while sum(alloc.values()) < n_slots:
        # give to the largest fractional remainder
        ch = max(A, key=lambda c: raw[c] - alloc[c])
        alloc[ch] += 1
    while sum(alloc.values()) > n_slots:
        ch = max(A, key=lambda c: alloc[c] - raw[c] if alloc[c] > min_per else -9)
        if alloc[ch] > min_per:
            alloc[ch] -= 1
        else:
            break
    return alloc


def build_charts(k, freq, rng):
    """k homophonic charts: each chart maps its 26 cipher symbols to plaintext
    letters (non-injective). Across charts the union must cover all 26 plaintext
    letters. Chart 0 flattens common letters (homophones, drops rare); later charts
    cover the dropped letters."""
    charts = []
    covered = set()
    for c in range(k):
        if c < k - 1:
            alloc = allocate(freq, 26, min_per=0)          # homophone-heavy
        else:
            # last chart: guarantee coverage of any letter not yet covered
            need = [ch for ch in A if ch not in covered and freq[ch] > 0]
            alloc = {ch: 0 for ch in A}
            for ch in need:
                alloc[ch] = 1
            rem = 26 - sum(alloc.values())
            if rem > 0:
                extra = allocate(freq, rem, min_per=0)
                for ch in A:
                    alloc[ch] += extra[ch]
        # assign 26 cipher symbols to plaintexts per alloc
        ciphers = list(range(26)); rng.shuffle(ciphers)
        chart = {}
        i = 0
        for ch in A:
            for _ in range(alloc[ch]):
                if i < 26:
                    chart[ciphers[i]] = ch; i += 1
        for X in range(26):
            if X in chart:
                covered.add(chart[X])
        charts.append(chart)
    # invert: plaintext -> list of (class, cipher) homophones
    homo = {ch: [] for ch in A}
    for c, chart in enumerate(charts):
        for X, p in chart.items():
            homo[p].append((c, X))
    return charts, homo


def cipher_entropy_of_homophonic(k, freq, corp, rng, samples=200):
    charts, homo = build_charts(k, freq, rng)
    # coverage check
    if any(len(homo[ch]) == 0 and freq[ch] > 0.001 for ch in A):
        return None, charts  # cannot encrypt some real letter
    ents = []
    for _ in range(samples):
        s = rng.randrange(len(corp) - N)
        pt = corp[s:s + N]
        used = Counter()
        ctext = []
        for ch in pt:
            opts = homo[ch]
            if not opts:
                opts = homo[max(A, key=lambda c: freq[c])]  # fallback (rare)
            # least-used cipher among homophones -> flatten
            cclass, X = min(opts, key=lambda o: used[o[1]])
            used[X] += 1
            ctext.append(X)
        cnt = Counter(ctext); n = len(ctext)
        ents.append(-sum((v / n) * math.log2(v / n) for v in cnt.values()))
    return statistics.mean(ents), charts


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_115_homophonic_flatten_floor.jsonl"
    rng = random.Random(0)
    t0 = time.perf_counter()
    corp = clean((_kpa.REPO / "data" / "corpora" / "buchan_39steps.txt").read_text())
    freq = english_freq(corp)

    curve = {}
    floor = None
    for k in range(1, 6):
        ent, _ = cipher_entropy_of_homophonic(k, freq, corp, random.Random(k))
        curve[k] = round(ent, 3) if ent is not None else None
        if ent is not None and floor is None and ent >= K4_FREE_ENTROPY:
            floor = k

    # bijective comparison (085): k*=4 for rotation mixing
    elapsed = time.perf_counter() - t0
    homophonic_floor = floor
    relief = homophonic_floor is not None and homophonic_floor <= 2

    import json
    with open(out, "w") as f:
        f.write(json.dumps({"homophonic_flatten_curve": curve, "homophonic_floor": homophonic_floor,
                            "K4_target_entropy": K4_FREE_ENTROPY, "bijective_floor_085": 4,
                            "chi_b_114": 2}) + "\n")

    insights = [
        f"Homophonic flatten curve (best-case cipher entropy by chart count k): {curve}. K4's free-position "
        f"entropy target = {K4_FREE_ENTROPY} bits (Fact 2). Homophonic flatten FLOOR (min k reaching it) = "
        f"{homophonic_floor}. Bijective-rotation floor (085) = k*=4.",
        (f"RE-OPENED: a homophonic cipher flattens to K4's entropy with only k={homophonic_floor} chart(s) -- and "
         f"114 showed the cribs are satisfiable with chi_b=2 homophonic charts. So a 2-chart HOMOPHONIC model "
         f"satisfies BOTH hard facts (cribs via chi_b=2, flattening via homophones) with FAR fewer charts than "
         f"the bijective >=4 the squeeze assumed. The squeeze (082/085/106) is a BIJECTIVE-model bound; it does "
         f"NOT bind a homophonic chart. This is a genuinely simpler, un-refuted model consistent with the "
         f"'chart-based coding system' description -- the strongest new lead since the structural bounds."
         if relief else
         f"Homophonic needs k={homophonic_floor} charts to flatten (not <=2), so it does not buy the dramatic "
         f"simplification chi_b=2 hinted; flattening still requires several charts even with homophones."),
        "CAVEAT (kept in view): a homophonic chart is still non-injective with free non-crib entries, so "
        "DECRYPTION of the 73 free positions remains under-determined (092/093). But the MODEL is simpler "
        "(2 charts, both facts) and is the right next target: a crib-constrained 2-chart homophonic KPA.",
    ]

    write_verdict(out, Verdict(
        exp="115", title="homophonic flatten floor -- does k=2 homophonic reach K4's entropy?",
        hypothesis="a homophonic cipher flattens to K4's 4.33-bit entropy with <=2 charts, so a 2-chart "
                   "homophonic model satisfies both hard facts (cribs chi_b=2 + flattening)",
        status="promising" if relief else "inconclusive",
        best_partial=f"homophonic flatten floor k={homophonic_floor} (bijective k*=4); chi_b=2; relief={relief}",
        search_space=5, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["build the crib-constrained 2-chart HOMOPHONIC KPA (exp 116): 2 non-injective charts + a "
                     "simple selector, cribs pin entries, decrypt + score -- the squeeze does not bind this model"]
                    if relief else
                    ["homophonic does not dramatically lower the flatten floor; combine chi_b=2 with the actual "
                     "homophonic floor for the true chart count"]),
        metrics={"flatten_curve": curve, "homophonic_floor": homophonic_floor, "chi_b": 2, "relief": relief}),
    )
    print(f"\nhomophonic flatten curve {curve}; floor k={homophonic_floor} (bijective 4); chi_b=2; "
          f"relief={relief}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
