"""Length-preserving keyed-coordinate fractionation cipher.

Motivation: K4's IoC (~0.0361) is BELOW the random-uniform floor (~0.0385).
Ordinary polyalphabetic substitution cannot push IoC sub-uniform; a
fractionating cipher can. The 25-cell polygraphic family (Bifid/Playfair)
is ruled out because K4 contains all 26 letters; ADFGVX is ruled out
because it doubles length. This cipher avoids both:

  - a 2x13 (or 13x2) keyed grid holds all 26 letters with NO filler and
    NO merge (2 * 13 == 26 exactly),
  - each plaintext letter -> (row, col),
  - a periodic key is added to the row stream (mod n_rows) and a separate
    periodic key to the col stream (mod n_cols),
  - recombine (row', col') -> letter.

Length is preserved (97 -> 97), every output letter is a real A-Z letter,
and the construction supplies >=3 interacting permutations (grid + two
coordinate keys) consistent with the χ=3 ruling. A genuine hand-era
technique (Nihilist / keyed-Polybius lineage).
"""

from __future__ import annotations

from kryptos.alphabets import STANDARD, Alphabet, keyed_alphabet
from kryptos.ciphers.base import Cipher


class KeyedFractionation(Cipher):
    def __init__(
        self,
        grid: str,                 # 26-char permutation, row-major fill
        n_rows: int,
        n_cols: int,
        key_row: list[int],        # ints in [0, n_rows)
        key_col: list[int],        # ints in [0, n_cols)
        alphabet: Alphabet = STANDARD,
    ) -> None:
        super().__init__(alphabet)
        if n_rows * n_cols != 26 or len(grid) != 26 or len(set(grid)) != 26:
            raise ValueError("grid must be a 26-letter permutation with n_rows*n_cols==26")
        self.grid = grid
        self.n_rows = n_rows
        self.n_cols = n_cols
        self.key_row = list(key_row)
        self.key_col = list(key_col)
        self.pos = {ch: (i // n_cols, i % n_cols) for i, ch in enumerate(grid)}

    @classmethod
    def from_keyword(cls, keyword: str, shape: tuple[int, int],
                     key_row: list[int], key_col: list[int]) -> "KeyedFractionation":
        grid = keyed_alphabet(keyword).letters
        return cls(grid, shape[0], shape[1], key_row, key_col)

    def encrypt(self, plaintext: str) -> str:
        self._validate(plaintext, "plaintext")
        out = []
        lr, lc = len(self.key_row), len(self.key_col)
        for i, ch in enumerate(plaintext):
            r, c = self.pos[ch]
            r2 = (r + self.key_row[i % lr]) % self.n_rows
            c2 = (c + self.key_col[i % lc]) % self.n_cols
            out.append(self.grid[r2 * self.n_cols + c2])
        return "".join(out)

    def decrypt(self, ciphertext: str) -> str:
        self._validate(ciphertext, "ciphertext")
        out = []
        lr, lc = len(self.key_row), len(self.key_col)
        for i, ch in enumerate(ciphertext):
            r2, c2 = self.pos[ch]
            r = (r2 - self.key_row[i % lr]) % self.n_rows
            c = (c2 - self.key_col[i % lc]) % self.n_cols
            out.append(self.grid[r * self.n_cols + c])
        return "".join(out)
