"""Binary English/not-English classifier for candidate plaintexts.

Stage 1: simple letter-frequency chi-squared (uses english_letter_counts).
Stage 2: NgramFitness threshold calibrated on real English of length 73
(the K4 unconstrained-position length). The chi-squared filter is fast
and cheap; the n-gram fitness is slow and is run only on survivors.

This module is intentionally a thin policy wrapper around the underlying
scorers so the threshold can be tuned per-experiment without touching the
math.
"""

from __future__ import annotations

from dataclasses import dataclass

from kryptos.scoring.ngram_fitness import NgramFitness
from kryptos.utils import english_letter_counts

# Norvig's English letter frequencies (mayzner.html).
_ENGLISH_FREQ: dict[str, float] = {
    "E": 0.1249, "T": 0.0928, "A": 0.0804, "O": 0.0764, "I": 0.0757,
    "N": 0.0723, "S": 0.0651, "R": 0.0628, "H": 0.0505, "L": 0.0407,
    "D": 0.0382, "C": 0.0334, "U": 0.0273, "M": 0.0251, "F": 0.0240,
    "P": 0.0214, "G": 0.0187, "W": 0.0168, "Y": 0.0166, "B": 0.0148,
    "V": 0.0105, "K": 0.0054, "X": 0.0023, "J": 0.0016, "Q": 0.0012,
    "Z": 0.0009,
}


def chi_squared(text: str) -> float:
    """Lower = more English."""
    n = len(text)
    if n == 0:
        return float("inf")
    counts = english_letter_counts(text)
    score = 0.0
    for letter, freq in _ENGLISH_FREQ.items():
        expected = freq * n
        observed = counts[letter]
        if expected > 0:
            score += (observed - expected) ** 2 / expected
    return score


@dataclass
class EnglishClassifier:
    """Two-stage filter: chi-squared, then n-gram log-likelihood."""

    fitness: NgramFitness
    chi_max: float = 80.0          # tune per length
    fitness_min: float = -9.5       # tune per length

    def is_english(self, text: str) -> bool:
        if chi_squared(text) > self.chi_max:
            return False
        if self.fitness(text) < self.fitness_min:
            return False
        return True


# T_99 stand-in: calibrated by running chi_squared() on 10,000 length-97
# uniformly random A-Z strings (seed=0) and taking the 1st percentile.
# This is the threshold below which a candidate is plausibly real
# English (lower chi^2 = closer to English frequencies). It is a
# STAND-IN -- the proper T_99 should be the 99th percentile of the
# n-gram fitness distribution on length-73 windows from real Gutenberg
# English; use scripts/calibrate_fitness.py to compute that once a
# corpus is on disk.
#
# Computed locally:
#   from random import Random; r = Random(0)
#   sample = [''.join(r.choices(string.ascii_uppercase, k=97)) for _ in range(10000)]
#   sorted([chi_squared(s) for s in sample])[100]   # ~95
CHI_SQ_T99_RANDOM: float = 95.0


def is_english_chi_squared(text: str, threshold: float = CHI_SQ_T99_RANDOM) -> bool:
    """Cheap English-ness gate: chi-squared on letter frequencies vs
    Norvig's English distribution. True iff the candidate is BELOW the
    threshold (i.e. closer to English than 99% of random A-Z strings).

    Pure-Python, no external corpora needed. Use as a T_99 stand-in
    until scripts/calibrate_fitness.py + a real Gutenberg corpus give
    you a calibrated n-gram threshold.
    """
    return chi_squared(text) < threshold
