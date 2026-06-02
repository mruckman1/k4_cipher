"""Index of Coincidence.

K4 IoC ~ 0.0361 (random ~ 0.0385, English ~ 0.0667). K1 ~ 0.0566, K2 ~
0.0473, K3 ~ 0.0420. K4 is the flattest, which is the statistical
fingerprint of Scheidt's "masking".
"""

from __future__ import annotations

from collections import Counter

from kryptos.utils import chunks


def index_of_coincidence(text: str, alphabet_size: int = 26) -> float:
    """IoC, normalised so a uniform distribution gives 1/alphabet_size."""
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    num = sum(c * (c - 1) for c in counts.values())
    return num / (n * (n - 1))


def periodic_ioc(text: str, period: int, alphabet_size: int = 26) -> float:
    """Mean IoC of the `period` columns when `text` is written into a
    grid of width `period`. A polyalphabetic with period `p` shows a
    near-English IoC for the correct `p`, a near-random IoC otherwise.
    """
    if period < 1:
        raise ValueError("period must be positive")
    cols: list[list[str]] = [[] for _ in range(period)]
    for i, c in enumerate(text):
        cols[i % period].append(c)
    iocs = [index_of_coincidence("".join(col), alphabet_size) for col in cols]
    return sum(iocs) / period


def scan_periods(text: str, max_period: int = 30) -> list[tuple[int, float]]:
    """Return [(period, periodic_ioc), ...] for period in 1..max_period."""
    return [(p, periodic_ioc(text, p)) for p in range(1, max_period + 1)]
