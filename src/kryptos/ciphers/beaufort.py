"""Beaufort cipher (reciprocal): C = (K - P) mod N.

Encryption and decryption are the same operation. Because Beaufort is
reciprocal, K4 at position 74 (K -> K) would require the key letter at
position 74 to equal A (in whatever alphabet). That is possible but
strongly constraining; combined with the rest of the BERLIN+CLOCK window
it is one of the cheaper cipher classes to rule out.
"""

from __future__ import annotations

from kryptos.alphabets import STANDARD, Alphabet
from kryptos.ciphers.base import Cipher
from kryptos.utils import repeat_to_length


class Beaufort(Cipher):
    def __init__(self, key: str, alphabet: Alphabet = STANDARD) -> None:
        super().__init__(alphabet)
        key = key.upper()
        bad = [c for c in key if not alphabet.contains(c)]
        if bad:
            raise ValueError(f"key letters {sorted(set(bad))} not in {alphabet.name}")
        self.key = key

    def encrypt(self, plaintext: str) -> str:
        self._validate(plaintext, "plaintext")
        key = repeat_to_length(self.key, len(plaintext))
        ai = self.alphabet.index
        at = self.alphabet.at
        return "".join(at(ai(k) - ai(p)) for p, k in zip(plaintext, key))

    # Beaufort is reciprocal.
    decrypt = encrypt
