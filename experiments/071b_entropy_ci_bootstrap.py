"""071b: Bootstrap CI / bias correction for K4's free-position unigram entropy.

Adjunct to exp.071 (which reports the plug-in free-position entropy 4.332 bits and
the p99 monoalphabetic-English null 3.885). Quantifies the sampling uncertainty the
paper cites: reproduces the plug-in point estimate, adds the Miller-Madow bias
correction, bootstraps the 73 free positions, and reports the homophonic flatten-floor
comparison (exp.115 curve: 1-chart 4.007, 2-chart 4.631) as margins in sampling-SD
units around the point and bias-corrected estimates.

NOTE on a subtlety: the plug-in entropy of a bootstrap resample is itself biased
downward (resampling further reduces diversity), so the bootstrap distribution centers
BELOW the point estimate (~4.10 vs 4.33). Tail fractions like P(resample <= 4.007)
are therefore NOT P(true entropy <= 4.007); they are dominated by that bias. The
honest comparison uses the point (4.33) and Miller-Madow (4.54) estimates with the
bootstrap SD (~0.10) as the sampling scale -- which is what the paper now reports.

No verdict is logged: this is a re-statistic over exp.071's sample, not a new
experiment, so the ledger counts are unchanged.
"""
import math
import random
from collections import Counter

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(CT) == 97
# 1-indexed crib spans: EAST 22-25, NORTHEAST 26-34 (=> 22-34), BERLIN 64-69, CLOCK 70-74 (=> 64-74)
CRIB = set(range(22, 35)) | set(range(64, 75))
FREE = [CT[i - 1] for i in range(1, 98) if i not in CRIB]
assert len(FREE) == 73

ONE_CHART_FLOOR = 4.007   # exp.115, 1 homophonic chart
TWO_CHART_FLOOR = 4.631   # exp.115, 2 homophonic charts


def plugin_entropy(seq):
    n = len(seq)
    counts = Counter(seq)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def main(B=20000, seed=0):
    h = plugin_entropy(FREE)
    k = len(Counter(FREE))                              # observed symbols
    mm = h + (k - 1) / (2 * len(FREE) * math.log(2))    # Miller-Madow bias correction
    rng = random.Random(seed)
    boots = sorted(plugin_entropy([rng.choice(FREE) for _ in range(73)]) for _ in range(B))
    mean = sum(boots) / B
    sd = (sum((x - mean) ** 2 for x in boots) / B) ** 0.5
    bias_corrected = 2 * h - mean                       # bootstrap bias-corrected plug-in
    pct = lambda q: boots[int(q * B)]

    print(f"plug-in H              = {h:.3f} bits  (exp.071 = 4.332)")
    print(f"observed symbols       = {k} of 26")
    print(f"Miller-Madow           = {mm:.3f} bits")
    print(f"bootstrap-bias-corr    = {bias_corrected:.3f} bits")
    print(f"bootstrap mean / SD    = {mean:.3f} / {sd:.3f}")
    print(f"resample pctiles 2.5/50/97.5 = {pct(.025):.3f} / {pct(.5):.3f} / {pct(.975):.3f}")
    print(f"uniform log2(26)       = {math.log2(26):.3f}")
    print("--- flatten-floor margins, in sampling-SD units around the proper centers ---")
    print(f"1-chart {ONE_CHART_FLOOR}: {(h-ONE_CHART_FLOOR)/sd:+.1f} SD below plug-in; "
          f"{(mm-ONE_CHART_FLOOR)/sd:+.1f} SD below Miller-Madow")
    print(f"2-chart {TWO_CHART_FLOOR}: {(TWO_CHART_FLOOR-h)/sd:+.1f} SD above plug-in; "
          f"{(TWO_CHART_FLOOR-mm)/sd:+.1f} SD above Miller-Madow")


if __name__ == "__main__":
    main()
