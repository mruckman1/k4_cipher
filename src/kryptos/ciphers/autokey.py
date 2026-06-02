"""Autokey ciphers.

`Autokey(key, mode="plaintext")` extends the keystream by appending the
*plaintext* after the primer key. `mode="ciphertext"` (less common, also
called Vigenere autokey or "ciphertext autokey") appends ciphertext.

Both behave as Vigenere for the first len(primer) positions, then diverge.
Autokey is one of the better-fitting hypotheses for K4: the shift pattern
across the EASTNORTHEAST + BERLINCLOCK windows is aperiodic over 24 known
positions, which is consistent with an autokey keystream and inconsistent
with a short-period Vigenere/Quagmire.
"""

from __future__ import annotations

from kryptos.alphabets import STANDARD, Alphabet
from kryptos.ciphers.base import Cipher


class Autokey(Cipher):
    def __init__(
        self,
        primer: str,
        alphabet: Alphabet = STANDARD,
        mode: str = "plaintext",
    ) -> None:
        super().__init__(alphabet)
        primer = primer.upper()
        bad = [c for c in primer if not alphabet.contains(c)]
        if bad:
            raise ValueError(f"primer letters {sorted(set(bad))} not in {alphabet.name}")
        if mode not in ("plaintext", "ciphertext"):
            raise ValueError(f"mode must be 'plaintext' or 'ciphertext', got {mode!r}")
        self.primer = primer
        self.mode = mode

    def encrypt(self, plaintext: str) -> str:
        self._validate(plaintext, "plaintext")
        ai = self.alphabet.index
        at = self.alphabet.at
        if self.mode == "plaintext":
            keystream = self.primer + plaintext
        else:  # ciphertext autokey -- keystream extended with cipher letters
            keystream = self.primer
        out = []
        for i, p in enumerate(plaintext):
            k = keystream[i]
            c = at(ai(p) + ai(k))
            out.append(c)
            if self.mode == "ciphertext":
                keystream += c
        return "".join(out)

    def decrypt(self, ciphertext: str) -> str:
        self._validate(ciphertext, "ciphertext")
        ai = self.alphabet.index
        at = self.alphabet.at
        keystream = self.primer
        out = []
        for i, c in enumerate(ciphertext):
            k = keystream[i]
            p = at(ai(c) - ai(k))
            out.append(p)
            if self.mode == "plaintext":
                keystream += p
            else:
                keystream += c
        return "".join(out)
