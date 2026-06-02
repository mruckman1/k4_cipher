"""Gromark (base-10) and Vimark (base-26).

Gromark: keystream is a lagged-Fibonacci sequence over Z_10 starting from
a 5-digit primer; the keystream is then added to a Gronsfeld-shifted text
under a keyword-mixed alphabet (Hall 1969, Blackman 1989).

Vimark: same construction but the lagged Fibonacci is over Z_N (typically
N=26), seeded by a letter primer.

The leading academic K4 hypothesis (Richard Bean, HistoCrypt 2021). The
DYAHR superscript on the sculpture is a 5-letter candidate Vimark primer.

This module ships a faithful implementation of the keystream and the
encryption/decryption operations. Hot loops (full primer enumeration for
crib-constrained search) belong in `solvers/crib_enumerator.py` and want
numpy or Numba vectorisation; the implementation here is pure-Python for
clarity.

References:
  Hall, "A new generation cipher", The Cryptogram 1969
  Blackman, "The Gromark Cipher", The Cryptogram 1989
  Bean, "Cryptodiagnosis of 'Kryptos K4'", HistoCrypt 2021
"""

from __future__ import annotations

from collections.abc import Iterator

from kryptos.alphabets import STANDARD, Alphabet, keyed_alphabet
from kryptos.ciphers.base import Cipher


def lagged_fibonacci(primer: list[int], modulus: int, length: int) -> list[int]:
    """Generate `length` elements of the lagged-Fibonacci sequence:
        s_i = s_{i-1} + s_{i-k}  (mod `modulus`)
    with the first k elements taken from `primer` (k = len(primer)).

    The published Gromark / Vimark convention is k = 5 (Hall 1969). We
    accept any k >= 2 so experiments can sweep adjacent primer lengths
    -- a length-6 primer is no harder to remember and no less
    "Scheidt-compatible" than length-5.
    """
    k = len(primer)
    if k < 2:
        raise ValueError("primer must have at least 2 elements")
    s = list(primer)
    while len(s) < length:
        s.append((s[-1] + s[-k]) % modulus)
    return s[:length]


class Gromark(Cipher):
    """Base-10 Gromark with a mixed (keyed) cipher alphabet.

    Default primer length is 5 (published convention). Pass any
    >=2-digit numeric primer to use a different length.
    """

    def __init__(
        self,
        primer: str,            # numeric primer, e.g. "23917" (5 digits, conventional)
        alphabet_keyword: str = "KRYPTOS",
        base_alphabet: Alphabet = STANDARD,
    ) -> None:
        alphabet = keyed_alphabet(alphabet_keyword, base_alphabet) if alphabet_keyword else base_alphabet
        super().__init__(alphabet)
        if not primer or not primer.isdigit() or len(primer) < 2:
            raise ValueError("primer must be at least 2 digits, e.g. '23917'")
        self.primer_digits = [int(d) for d in primer]
        self.alphabet_keyword = alphabet_keyword

    def keystream(self, length: int) -> list[int]:
        """Base-10 keystream of `length` digits."""
        return lagged_fibonacci(self.primer_digits, 10, length)

    def encrypt(self, plaintext: str) -> str:
        self._validate(plaintext, "plaintext")
        ks = self.keystream(len(plaintext))
        ai = self.alphabet.index
        at = self.alphabet.at
        return "".join(at(ai(p) + k) for p, k in zip(plaintext, ks))

    def decrypt(self, ciphertext: str) -> str:
        self._validate(ciphertext, "ciphertext")
        ks = self.keystream(len(ciphertext))
        ai = self.alphabet.index
        at = self.alphabet.at
        return "".join(at(ai(c) - k) for c, k in zip(ciphertext, ks))


class Vimark(Cipher):
    """Vimark: Gromark over base-26 (letter primer).

    Default primer length is 5 (parallels the conventional Gromark). Pass
    any >=2-letter primer to use a different length.
    """

    def __init__(
        self,
        primer: str,            # letter primer, e.g. "DYAHR" (5 letters, conventional)
        alphabet_keyword: str = "KRYPTOS",
        base_alphabet: Alphabet = STANDARD,
    ) -> None:
        alphabet = keyed_alphabet(alphabet_keyword, base_alphabet) if alphabet_keyword else base_alphabet
        super().__init__(alphabet)
        primer = primer.upper()
        if len(primer) < 2:
            raise ValueError("Vimark primer must be at least 2 letters")
        bad = [c for c in primer if not alphabet.contains(c)]
        if bad:
            raise ValueError(f"primer letters {sorted(set(bad))} not in alphabet")
        self.primer_letters = primer
        self.alphabet_keyword = alphabet_keyword

    def keystream(self, length: int) -> list[int]:
        primer_idx = self.alphabet.encode(self.primer_letters)
        return lagged_fibonacci(primer_idx, len(self.alphabet), length)

    def encrypt(self, plaintext: str) -> str:
        self._validate(plaintext, "plaintext")
        ks = self.keystream(len(plaintext))
        ai = self.alphabet.index
        at = self.alphabet.at
        return "".join(at(ai(p) + k) for p, k in zip(plaintext, ks))

    def decrypt(self, ciphertext: str) -> str:
        self._validate(ciphertext, "ciphertext")
        ks = self.keystream(len(ciphertext))
        ai = self.alphabet.index
        at = self.alphabet.at
        return "".join(at(ai(c) - k) for c, k in zip(ciphertext, ks))


def enumerate_numeric_primers(length: int = 5) -> Iterator[str]:
    """All 10**length numeric primers in lex order (length-digit, zero-padded).

    For Gromark crib-constrained search you iterate these and check the
    four cribs as hard constraints. length=5 (default) is the published
    convention; larger lengths blow up the search space (length=6 -> 1M,
    length=7 -> 10M).
    """
    for i in range(10 ** length):
        yield f"{i:0{length}d}"


def enumerate_letter_primers(length: int = 5, alphabet: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ") -> Iterator[str]:
    """All `len(alphabet) ** length` letter primers in lex order, used for
    Vimark crib-constrained search. length=5 over A-Z is ~12M primers."""
    from itertools import product
    for combo in product(alphabet, repeat=length):
        yield "".join(combo)
