"""Friedman test: estimate key length from the index of coincidence.

  L ~= (0.0265 * n) / ((0.065 - I) - n * (I - 0.0385))

(Friedman 1922; the constants 0.065 ~ English IoC and 0.0385 ~ random
IoC.) Estimates degrade quickly when n is small; for K4 (n=97, I~0.0361)
Friedman returns a length that exceeds the ciphertext, again consistent
with the non-periodic-keystream hypothesis.
"""

from __future__ import annotations

from kryptos.analysis.ioc import index_of_coincidence

_ENGLISH_IOC = 0.0667
_RANDOM_IOC = 0.0385


def friedman_key_length(text: str) -> float:
    n = len(text)
    if n < 2:
        return float("inf")
    I = index_of_coincidence(text)
    denom = (_ENGLISH_IOC - _RANDOM_IOC) * (n - 1) + I - _ENGLISH_IOC * n
    if abs(denom) < 1e-12:
        return float("inf")
    L = 0.0265 * n / abs(denom)
    return L
