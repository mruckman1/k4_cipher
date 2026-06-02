"""Monte Carlo permutation tests for cipher-family hypotheses.

Bean's HistoCrypt 2021 *Cryptodiagnosis of "Kryptos K4"* uses permutation
testing to argue that K4 is consistent with a one-to-one positional cipher
(Vigenere/Quagmire/Gromark/autokey family) and inconsistent with pure
transposition. Until you have reproduced that result on your own machine
from the actual K4 ciphertext, every downstream "K4 is Gromark" assumption
is hearsay.

This module provides:

  - `permutation_test(...)`: generic two-sided MC permutation test wrapper.
  - `transposition_consistency_test(...)`: Bean's specific question.
    Under H0 = K4 is a transposition of some plaintext, the ciphertext
    letters at the EASTNORTHEAST window (positions 22-34) are a sample
    drawn (without replacement) from the K4 letter multiset. We ask: is
    the observed number of distinct letters in that window (and similar
    statistics) consistent with random draws from K4?

The output is a p-value, not a decision -- you still have to set a
threshold. Use 0.001 or stricter; Bean's published result has p well
below 0.0004 for related statistics on K4.

References:
  Bean, "Cryptodiagnosis of 'Kryptos K4'", HistoCrypt 2021.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass

from kryptos.cribs import Crib


@dataclass
class PermutationResult:
    """Output of a permutation test."""

    observed: float
    null_mean: float
    null_std: float
    n_iters: int
    p_value_one_sided_lower: float   # fraction of null samples <= observed
    p_value_one_sided_upper: float   # fraction of null samples >= observed
    p_value_two_sided: float

    def __str__(self) -> str:
        return (
            f"observed={self.observed:.4f}  "
            f"null mean={self.null_mean:.4f} +/- {self.null_std:.4f}  "
            f"n={self.n_iters}  "
            f"p(<=obs)={self.p_value_one_sided_lower:.4g}  "
            f"p(>=obs)={self.p_value_one_sided_upper:.4g}  "
            f"two-sided p={self.p_value_two_sided:.4g}"
        )


def permutation_test(
    statistic: Callable[[str], float],
    ciphertext: str,
    n_iters: int = 10_000,
    seed: int = 0,
) -> PermutationResult:
    """Generic Monte Carlo permutation test.

    Args:
        statistic: function that takes the (possibly permuted) ciphertext
                   and returns a real-valued statistic.
        ciphertext: the input string. The null distribution is built by
                    drawing random permutations of this string.
        n_iters: number of permutations to draw.
        seed: RNG seed.

    Returns:
        PermutationResult with observed statistic, null distribution
        summary, and one- and two-sided p-values.
    """
    rng = random.Random(seed)
    observed = statistic(ciphertext)
    chars = list(ciphertext)
    null_samples: list[float] = []
    for _ in range(n_iters):
        rng.shuffle(chars)
        null_samples.append(statistic("".join(chars)))
    return _summarise(observed, null_samples, n_iters)


def transposition_consistency_test(
    ciphertext: str,
    crib: Crib,
    n_iters: int = 10_000,
    seed: int = 0,
) -> PermutationResult:
    """DEPRECATED. This implementation is degenerate: the observed
    statistic is `len(target)` because the unpermuted ciphertext IS the
    target at the crib positions, and permuted ciphertexts almost never
    are. The resulting p-value of ~0 says nothing about transposition.

    Use `english_at_cribs_test()` instead, which compares the English-
    likeness of the substring at the crib positions to a null distribution
    drawn from random permutations of the ciphertext. That IS Bean's
    framing (HistoCrypt 2021): under H0 = K4 is a transposition of English,
    every position of K4 is interchangeable with every other, so a random
    permutation should produce equally-English-looking substrings.

    Kept here only so the docstring documents the mistake.
    """
    raise NotImplementedError(
        "transposition_consistency_test is degenerate; use "
        "english_at_cribs_test instead. See docstring."
    )


# A small English bigram log-probability table, fit from K1+K2+K3 plaintexts.
# Small, but the only English corpus the library is guaranteed to have
# without an external download. Build a richer model from Gutenberg via
# scripts/calibrate_fitness.py once a corpus is on disk.
def _build_default_bigram_logprobs() -> dict[str, float]:
    from kryptos.constants import K1_PLAINTEXT, K2_PLAINTEXT, K3_PLAINTEXT
    import math
    from collections import Counter
    counts: Counter[str] = Counter()
    for text in (K1_PLAINTEXT, K2_PLAINTEXT, K3_PLAINTEXT):
        for i in range(len(text) - 1):
            counts[text[i : i + 2]] += 1
    # Add-one smoothing across all 26*26 bigrams so unseen bigrams get
    # a real (finite) probability.
    vocab = 26 * 26
    total = sum(counts.values()) + vocab
    return {
        a + b: math.log((counts.get(a + b, 0) + 1) / total)
        for a in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        for b in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    }


_BIGRAM_LOGP = _build_default_bigram_logprobs()


def english_score(text: str) -> float:
    """Bigram log-likelihood per bigram. Higher = more English-like.

    Calibrated on K1+K2+K3 plaintexts -- that is ~768 letters, a small
    corpus, and the resulting table is too noisy to give significant
    p-values on the 13-letter EASTNORTHEAST or 11-letter BERLINCLOCK
    windows. When `english_at_cribs_test` reports p ~ 0.3-0.8 across
    every crib, that means CORPUS-LIMITED, not "the test is fundamentally
    degenerate". Once `scripts/build_hexagrams.py` produces a hexagram
    table from real Gutenberg English, swap that in as the scoring model
    and the same test should run with discriminating p-values.

    Good enough for a permutation test where what matters is the
    *relative* score of two strings of the same length and the corpus
    bias is constant across both.
    """
    if len(text) < 2:
        return 0.0
    return sum(_BIGRAM_LOGP[text[i : i + 2]] for i in range(len(text) - 1)) / (len(text) - 1)


def english_at_cribs_test(
    ciphertext: str,
    crib: Crib,
    n_iters: int = 10_000,
    seed: int = 0,
) -> PermutationResult:
    """Bean-style test: how English-like is the substring at the crib
    positions under the null that the ciphertext is a transposition of
    English?

    Statistic: bigram log-likelihood per bigram of `ciphertext[crib.slice0]`.
    Null distribution: same statistic computed on random permutations of
    `ciphertext`.

    Interpretation:
      - observed < null mean by many sigma  => crib-position substring is
        UNUSUALLY un-English. Random permutations of K4 produce more
        English-like fragments at the same positions, on average. Evidence
        that K4's letters at the crib positions are NOT samples from
        English letter distribution -- consistent with positional
        encryption rather than transposition.
      - observed ~ null mean => K4 at the crib positions is no more or
        less English than random rearrangement of K4. Consistent with a
        transposition of some non-English source, or with a positional
        cipher that happens to produce average-looking output.
      - observed >> null mean => crib-position substring is unusually
        English-like, which would be remarkable; would suggest the crib
        positions reveal preserved English structure (transposition
        consistent).
    """
    cstart = crib.start - 1
    cend = crib.end

    observed = english_score(ciphertext[cstart:cend])

    rng = random.Random(seed)
    chars = list(ciphertext)
    null_samples: list[float] = []
    for _ in range(n_iters):
        rng.shuffle(chars)
        null_samples.append(english_score("".join(chars[cstart:cend])))

    return _summarise(observed, null_samples, n_iters)


def positional_shift_uniformity(
    ciphertext: str,
    crib: Crib,
    alphabet_size: int = 26,
    n_iters: int = 10_000,
    seed: int = 0,
) -> PermutationResult:
    """How concentrated is the plaintext-to-ciphertext shift sequence at
    the crib positions? Statistic = number of distinct shift values.

    Under a true periodic-key Vigenere of period L, only L distinct shifts
    can appear; the EASTNORTHEAST window (length 13) has 13 distinct
    shifts at standard A-Z. That is unusually high for any periodic
    cipher -- the permutation test gives the null distribution under
    random-letter ciphertext, which provides a baseline for "how
    surprising is 13".
    """
    cstart = crib.start - 1
    cend = crib.end
    pl = crib.plaintext

    def stat(text: str) -> float:
        seg = text[cstart:cend]
        shifts = {(ord(p) - ord(c)) % alphabet_size for p, c in zip(pl, seg)}
        return float(len(shifts))

    return permutation_test(stat, ciphertext, n_iters=n_iters, seed=seed)


def _summarise(observed: float, null_samples: list[float], n_iters: int) -> PermutationResult:
    null_samples.sort()
    mean = sum(null_samples) / len(null_samples)
    var = sum((x - mean) ** 2 for x in null_samples) / len(null_samples)
    std = var ** 0.5
    n_le = sum(1 for x in null_samples if x <= observed)
    n_ge = sum(1 for x in null_samples if x >= observed)
    p_lower = n_le / len(null_samples)
    p_upper = n_ge / len(null_samples)
    p_two = 2 * min(p_lower, p_upper)
    return PermutationResult(
        observed=observed,
        null_mean=mean,
        null_std=std,
        n_iters=n_iters,
        p_value_one_sided_lower=p_lower,
        p_value_one_sided_upper=p_upper,
        p_value_two_sided=min(p_two, 1.0),
    )
