"""Columnar / route transposition. K3 is two passes of columnar
transposition with KRYPTOS column ordering on a 7-wide grid.

Sanborn confirmed at the March 2019 ACA dinner that K3 is *only*
transposition (ENDYAH does NOT positionally map to SLOWLY), in deliberate
contrast to K4 where positional cribs DO map. That contrast is one of the
strongest pieces of evidence that K4 is a one-to-one positional cipher
(Vigenere/Quagmire/Gromark family), not a transposition or composite.
"""

from __future__ import annotations

from kryptos.alphabets import STANDARD, Alphabet
from kryptos.ciphers.base import Cipher


class ColumnarTransposition(Cipher):
    """Single-pass columnar transposition.

    Writes plaintext into a grid `width` columns wide (row-major), then
    reads off the columns in the order given by `column_order`.
    """

    def __init__(
        self,
        column_order: tuple[int, ...],
        alphabet: Alphabet = STANDARD,
        pad_letter: str = "X",
    ) -> None:
        super().__init__(alphabet)
        if sorted(column_order) != list(range(len(column_order))):
            raise ValueError(
                f"column_order must be a permutation of 0..{len(column_order)-1}, "
                f"got {column_order}"
            )
        self.column_order = tuple(column_order)
        self.width = len(column_order)
        self.pad_letter = pad_letter

    def _grid_rows(self, text: str) -> list[list[str]]:
        # Pad to a multiple of `width`.
        pad = (-len(text)) % self.width
        padded = text + self.pad_letter * pad
        return [list(padded[i : i + self.width]) for i in range(0, len(padded), self.width)]

    def encrypt(self, plaintext: str) -> str:
        self._validate(plaintext, "plaintext")
        rows = self._grid_rows(plaintext)
        out: list[str] = []
        for col in self.column_order:
            for row in rows:
                out.append(row[col])
        return "".join(out)

    def decrypt(self, ciphertext: str) -> str:
        self._validate(ciphertext, "ciphertext")
        n = len(ciphertext)
        if n % self.width != 0:
            raise ValueError(
                f"ciphertext length {n} not a multiple of width {self.width}"
            )
        rows = n // self.width
        cols: dict[int, str] = {}
        for k, col in enumerate(self.column_order):
            cols[col] = ciphertext[k * rows : (k + 1) * rows]
        out: list[str] = []
        for r in range(rows):
            for c in range(self.width):
                out.append(cols[c][r])
        return "".join(out)
