"""Hard-constraint crib checking.

A bug in this file invalidates every downstream experiment, so it stays
short and is unit-tested first when you add tests/. The intended workflow:

    cribs = kryptos.cribs.CRIBS          # the four confirmed K4 cribs
    if crib_check(candidate_plaintext, cribs):
        score = ngram_fitness(candidate_plaintext)
        ...
"""

from __future__ import annotations

from collections.abc import Iterable

from kryptos.cribs import CRIBS, Crib


def crib_check(plaintext: str, cribs: Iterable[Crib] = CRIBS) -> bool:
    """True iff `plaintext` matches every crib at its 1-indexed positions."""
    for c in cribs:
        if plaintext[c.slice0] != c.plaintext:
            return False
    return True


def crib_violations(plaintext: str, cribs: Iterable[Crib] = CRIBS) -> list[tuple[Crib, str]]:
    """List of (crib, actual_plaintext_slice) for every failing crib.
    Useful when you want to know *which* crib your candidate violated.
    """
    out: list[tuple[Crib, str]] = []
    for c in cribs:
        actual = plaintext[c.slice0]
        if actual != c.plaintext:
            out.append((c, actual))
    return out


def surviving_positions(plaintext_length: int = 97, cribs: Iterable[Crib] = CRIBS) -> list[int]:
    """0-indexed positions NOT constrained by any crib. For K4 that is
    73 of the 97 positions; those are the positions where you have to
    score for English-ness, and they are noisy at quadgram resolution
    (which is why hexagrams calibrated on a Gutenberg corpus are the
    recommended fitness function for K4 candidates)."""
    pinned: set[int] = set()
    for c in cribs:
        pinned.update(range(c.start - 1, c.end))
    return [i for i in range(plaintext_length) if i not in pinned]
