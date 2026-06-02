"""Crib consistency propagator -- the cheapest possible filter for any
periodic-key cipher experiment.

For Vigenere / Quagmire I-IV with key length L over alphabet of size N,
the four K4 cribs fix specific (position mod L) -> key-letter mappings.
If two crib positions p_a and p_b satisfy (p_a mod L) == (p_b mod L)
but demand DIFFERENT key letters, then the cipher cannot be a periodic
Vigenere/Quagmire of period L. This is an O(crib_length) check and it
eliminates 90%+ of candidate key lengths before you decrypt anything.

The check is parameterised by the alphabet (standard A-Z, KRYPTOS-keyed,
extra-L variant) and the per-position shift convention (Vigenere
forward / Beaufort reciprocal). The Beaufort variant is interesting
because position 74 (K -> K) demands key letter A under standard
Beaufort, which is the trivial-key constraint that rules out most
Beaufort families immediately.

Usage:

    from kryptos.solvers.consistency import consistent_periods
    from kryptos.alphabets import STANDARD, KRYPTOS_KEYED

    # Which periods are even consistent with a Vigenere cipher over A-Z?
    ok = consistent_periods(max_period=30, alphabet=STANDARD)
    # -> e.g. [] or a small list of survivors

    # Same check for KRYPTOS-keyed alphabet:
    ok = consistent_periods(max_period=30, alphabet=KRYPTOS_KEYED)

If `ok` is empty for ALL alphabets and convention, the cipher is not a
periodic Vigenere/Quagmire at any period up to max_period -- which is
the textbook Bean / Gillogly result for K4 and the reason the field
moved on to non-periodic keystreams (Gromark, autokey).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from kryptos.alphabets import STANDARD, Alphabet
from kryptos.cribs import CRIBS, Crib


@dataclass
class ConsistencyResult:
    """One period check's verdict + the partial key it pins down."""

    period: int
    alphabet: str
    consistent: bool
    pinned_key_letters: dict[int, str]   # position-mod-period -> letter
    conflict: tuple[int, int, str, str] | None  # (pos_a, pos_b, key_letter_a, key_letter_b)

    def __str__(self) -> str:
        if self.consistent:
            slots = ", ".join(f"{k}->{v}" for k, v in sorted(self.pinned_key_letters.items()))
            return (
                f"period={self.period} ({self.alphabet}): consistent, "
                f"{len(self.pinned_key_letters)} slots pinned [{slots}]"
            )
        a, b, ka, kb = self.conflict
        return (
            f"period={self.period} ({self.alphabet}): CONFLICT at "
            f"positions {a},{b}: needs key letter {ka!r} and {kb!r}"
        )


def check_period(
    period: int,
    alphabet: Alphabet = STANDARD,
    cribs: Iterable[Crib] = CRIBS,
    convention: str = "vigenere",
) -> ConsistencyResult:
    """Check whether the cribs are consistent with a period-`period`
    periodic key under the given `convention`.

    convention:
      - "vigenere":  cipher_index = plain_index + key_index (mod N)
      - "beaufort":  cipher_index = key_index - plain_index (mod N), reciprocal

    Returns a ConsistencyResult; .consistent is True iff every crib
    position can be satisfied with a single period-`period` key.
    """
    n = len(alphabet)
    pinned: dict[int, str] = {}

    for crib in cribs:
        for offset, (p_ch, c_ch) in enumerate(zip(crib.plaintext, crib.ciphertext)):
            pos = crib.start - 1 + offset       # 0-indexed
            slot = pos % period
            p_i = alphabet.index(p_ch)
            c_i = alphabet.index(c_ch)
            if convention == "vigenere":
                k_i = (c_i - p_i) % n
            elif convention == "beaufort":
                k_i = (p_i + c_i) % n
            else:
                raise ValueError(f"unknown convention {convention!r}")
            k_letter = alphabet.at(k_i)
            if slot in pinned and pinned[slot] != k_letter:
                # Find the earlier crib position that pinned this slot.
                for c2 in cribs:
                    for o2, (p2, c2c) in enumerate(zip(c2.plaintext, c2.ciphertext)):
                        pos2 = c2.start - 1 + o2
                        if pos2 % period == slot and pos2 != pos:
                            return ConsistencyResult(
                                period=period, alphabet=alphabet.name,
                                consistent=False, pinned_key_letters=pinned,
                                conflict=(pos2, pos, pinned[slot], k_letter),
                            )
            pinned[slot] = k_letter

    return ConsistencyResult(
        period=period, alphabet=alphabet.name,
        consistent=True, pinned_key_letters=pinned, conflict=None,
    )


def consistent_periods(
    max_period: int = 30,
    alphabet: Alphabet = STANDARD,
    cribs: Iterable[Crib] = CRIBS,
    convention: str = "vigenere",
) -> list[ConsistencyResult]:
    """Return the list of periods in [1, max_period] for which the cribs
    are jointly consistent with a periodic key."""
    out = []
    for L in range(1, max_period + 1):
        r = check_period(L, alphabet=alphabet, cribs=cribs, convention=convention)
        if r.consistent:
            out.append(r)
    return out


def survey(
    max_period: int = 30,
    cribs: Iterable[Crib] = CRIBS,
    alphabets: Iterable[Alphabet] = (),
    conventions: Iterable[str] = ("vigenere", "beaufort"),
) -> dict[tuple[str, str], list[int]]:
    """Survey: for every (alphabet, convention) pair, list the surviving
    periods. The default `alphabets=()` triggers a sensible default
    (standard + KRYPTOS-keyed) inside this function so callers can
    pass `alphabets=None`-style without imports.
    """
    from kryptos.alphabets import KRYPTOS_KEYED, STANDARD
    alphabets = list(alphabets) or [STANDARD, KRYPTOS_KEYED]
    out: dict[tuple[str, str], list[int]] = {}
    for alpha in alphabets:
        for conv in conventions:
            survivors = [
                r.period
                for r in consistent_periods(
                    max_period=max_period, alphabet=alpha, cribs=cribs, convention=conv
                )
            ]
            out[(alpha.name, conv)] = survivors
    return out
