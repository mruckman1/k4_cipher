"""Standard Vigenere over an arbitrary alphabet.

   cipher_i = alphabet[(plain_index + key_index) mod N]

For K1/K2 this is identical to Quagmire III with both alphabets keyed by
KRYPTOS (because Quagmire III with matching plaintext and ciphertext
alphabets reduces to Vigenere performed in keyed-alphabet index space).
That equivalence is why we have a separate `QuagmireIII` class -- it
documents the actual cipher Sanborn used -- but the wire computation is
the same as `Vigenere(alphabet=KRYPTOS_KEYED, key=...)`.
"""

from __future__ import annotations

from kryptos.alphabets import STANDARD, Alphabet
from kryptos.ciphers.base import Cipher
from kryptos.utils import repeat_to_length


class Vigenere(Cipher):
    def __init__(self, key: str, alphabet: Alphabet = STANDARD) -> None:
        super().__init__(alphabet)
        key = key.upper()
        bad = [c for c in key if not alphabet.contains(c)]
        if bad:
            raise ValueError(
                f"key contains letters not in {alphabet.name}: {sorted(set(bad))}"
            )
        self.key = key
        self._key_idx = alphabet.encode(key)

    def encrypt(self, plaintext: str) -> str:
        self._validate(plaintext, "plaintext")
        n = len(self.alphabet)
        key = repeat_to_length(self.key, len(plaintext))
        ai = self.alphabet.index
        at = self.alphabet.at
        return "".join(at(ai(p) + ai(k)) for p, k in zip(plaintext, key))

    def decrypt(self, ciphertext: str) -> str:
        self._validate(ciphertext, "ciphertext")
        n = len(self.alphabet)
        key = repeat_to_length(self.key, len(ciphertext))
        ai = self.alphabet.index
        at = self.alphabet.at
        return "".join(at(ai(c) - ai(k)) for c, k in zip(ciphertext, key))
