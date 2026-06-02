"""Brute-force key enumeration over small key spaces.

For Vigenere/Quagmire III with key length L over alphabet of size N the
search space is N**L. Tractable up to L ~ 6 in pure Python, L ~ 9 with
numpy vectorisation, L ~ 12 with Numba or Rust. Beyond that, switch to
hill_climber / simulated_annealing / crib_enumerator.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from itertools import product

from kryptos.alphabets import STANDARD, Alphabet
from kryptos.ciphers.vigenere import Vigenere


def iter_keys(alphabet: Alphabet, length: int) -> Iterator[str]:
    """Lex-ordered iterator over all length-`length` keys."""
    for combo in product(alphabet.letters, repeat=length):
        yield "".join(combo)


def brute_force_vigenere(
    ciphertext: str,
    key_length: int,
    score: Callable[[str], float],
    alphabet: Alphabet = STANDARD,
    top_k: int = 10,
) -> list[tuple[float, str, str]]:
    """Enumerate every key of `key_length` over `alphabet`, decrypt the
    ciphertext, score the result, return the top `top_k` by score.

    Returns:
        list of (score, key, plaintext), sorted by score descending.
    """
    best: list[tuple[float, str, str]] = []
    for key in iter_keys(alphabet, key_length):
        plain = Vigenere(key, alphabet).decrypt(ciphertext)
        s = score(plain)
        if len(best) < top_k:
            best.append((s, key, plain))
            best.sort(reverse=True)
        elif s > best[-1][0]:
            best[-1] = (s, key, plain)
            best.sort(reverse=True)
    return best
