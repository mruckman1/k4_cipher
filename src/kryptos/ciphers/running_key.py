"""Running-key Vigenere: the key is a full English text at least as long
as the message.

For K4, the canonical running-key candidate is Howard Carter's
*The Tomb of Tut-ankh-Amen* (the confirmed source of K3's plaintext
paraphrase). Also try:
  - Schliemann's memoirs (Sanborn favorite per the 2009 Berman interview)
  - K1, K2, K3 plaintexts as the key
  - the Cyrillic Projector decrypted text
"""

from __future__ import annotations

from kryptos.alphabets import STANDARD, Alphabet
from kryptos.ciphers.base import Cipher
from kryptos.utils import clean


class RunningKey(Cipher):
    def __init__(
        self,
        key_text: str,
        alphabet: Alphabet = STANDARD,
        offset: int = 0,
    ) -> None:
        super().__init__(alphabet)
        key = clean(key_text)
        bad = [c for c in key if not alphabet.contains(c)]
        if bad:
            raise ValueError(f"key contains letters not in {alphabet.name}: {sorted(set(bad))}")
        if offset < 0 or offset >= len(key):
            raise ValueError(f"offset {offset} out of range for key of length {len(key)}")
        self.key = key
        self.offset = offset

    def _keystream(self, length: int) -> str:
        end = self.offset + length
        if end > len(self.key):
            raise ValueError(
                f"key too short: need {length} letters starting at offset "
                f"{self.offset}, but key only has {len(self.key)}"
            )
        return self.key[self.offset : end]

    def encrypt(self, plaintext: str) -> str:
        self._validate(plaintext, "plaintext")
        ks = self._keystream(len(plaintext))
        ai = self.alphabet.index
        at = self.alphabet.at
        return "".join(at(ai(p) + ai(k)) for p, k in zip(plaintext, ks))

    def decrypt(self, ciphertext: str) -> str:
        self._validate(ciphertext, "ciphertext")
        ks = self._keystream(len(ciphertext))
        ai = self.alphabet.index
        at = self.alphabet.at
        return "".join(at(ai(c) - ai(k)) for c, k in zip(ciphertext, ks))
