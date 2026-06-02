"""Kasiski examination: find repeated substrings, take their distance
spacings, factor.

Kasiski on K4 turns up effectively nothing exploitable -- consistent with
either a non-periodic keystream or a key length close to the ciphertext
length. We keep the implementation here for sanity-checking experimental
candidates and for documenting why the periodic-key hypothesis is dead.
"""

from __future__ import annotations

from collections import defaultdict
from math import gcd


def kasiski_repeats(text: str, min_len: int = 3) -> dict[str, list[int]]:
    """All substrings of length >= `min_len` that occur more than once,
    mapped to their 0-indexed starting positions."""
    positions: dict[str, list[int]] = defaultdict(list)
    for size in range(min_len, len(text) // 2 + 1):
        seen: dict[str, list[int]] = defaultdict(list)
        for i in range(len(text) - size + 1):
            seen[text[i : i + size]].append(i)
        for sub, locs in seen.items():
            if len(locs) > 1:
                positions[sub] = locs
    return dict(positions)


def kasiski_periods(text: str, min_len: int = 3, max_period: int = 30) -> dict[int, int]:
    """Approximate likely key periods.

    For every repeated substring, take pairwise distances, factor them,
    and count factors in [2, max_period]. Returns a {period: count} dict
    sorted by count descending.
    """
    repeats = kasiski_repeats(text, min_len)
    factor_votes: dict[int, int] = defaultdict(int)
    for locs in repeats.values():
        for i in range(len(locs)):
            for j in range(i + 1, len(locs)):
                d = locs[j] - locs[i]
                for p in range(2, max_period + 1):
                    if d % p == 0:
                        factor_votes[p] += 1
    return dict(sorted(factor_votes.items(), key=lambda kv: -kv[1]))


def best_period_guess(text: str, min_len: int = 3, max_period: int = 30) -> int | None:
    """Single best-guess period from Kasiski, or None if nothing repeats."""
    periods = kasiski_periods(text, min_len, max_period)
    if not periods:
        return None
    return next(iter(periods))
