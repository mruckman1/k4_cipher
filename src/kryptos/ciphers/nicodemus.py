"""Nicodemus cipher: columnar transposition + per-column Vigenere.

Construction:
  1. Write plaintext into a grid `width` columns wide (row-major).
  2. Within each row-block of length `width`, apply Vigenere with the
     transposition KEYWORD's letters as per-column Vigenere keys
     (column 0 uses keyword[0], column 1 uses keyword[1], ...). Each
     row-block of plaintext gets the same per-column shift.
  3. Read off the columns in the order given by the keyword's
     alphabetic-rank permutation (standard ACA Nicodemus convention).

Tested on K4 in prior sweeps without success at any width; included here
so the dispatcher can sweep keyword + width combinations. Note that
Nicodemus does NOT preserve self-encryption opportunities for arbitrary
letters; check position 74 K->K is compatible with your chosen keyword.

Self-encryption: For position i with column c, the cipher applies
shift = keyword[c]. Self-encryption (pt[i] == ct[i]) requires the
shift to be 0 modulo 26, i.e. keyword[c] = 'A'. If your keyword has
no 'A' in any column that K4 position 74 (after the transposition
permutation) might map to, this cipher is structurally incompatible
with the position-74 constraint.
"""

from __future__ import annotations

from kryptos.alphabets import STANDARD, Alphabet
from kryptos.ciphers.base import Cipher
from kryptos.utils import assert_clean


def _keyword_order(keyword: str) -> tuple[int, ...]:
    """Return read-out column order from a keyword's letter ranks.
    ACA convention: rank letters A-Z, ties broken left-to-right.
    Returns the order in which columns are read OUT during encrypt.
    """
    keyword = keyword.upper()
    indexed = sorted(enumerate(keyword), key=lambda ic: (ic[1], ic[0]))
    return tuple(i for i, _ in indexed)


class Nicodemus(Cipher):
    """Nicodemus: per-column Vigenere shift + columnar read-out.

    Args:
        keyword: the cipher keyword. Length = number of columns; each
            letter both supplies its column's Vigenere shift AND
            participates in the read-out order via alphabetic rank.
        alphabet: standard 26-letter alphabet; for KRYPTOS-keyed
            arithmetic, build via kryptos.alphabets.keyed_alphabet.
        pad_letter: filler if plaintext length isn't a multiple of
            keyword length. Default 'X'.
    """

    def __init__(
        self,
        keyword: str,
        alphabet: Alphabet = STANDARD,
        pad_letter: str = "X",
    ) -> None:
        super().__init__(alphabet)
        keyword = keyword.upper()
        bad = [c for c in keyword if not alphabet.contains(c)]
        if bad:
            raise ValueError(
                f"keyword contains letters not in {alphabet.name}: {sorted(set(bad))}"
            )
        if len(keyword) < 2:
            raise ValueError(f"keyword must be >= 2 letters, got {keyword!r}")
        self.keyword = keyword
        self.width = len(keyword)
        self.column_order = _keyword_order(keyword)
        self.pad_letter = pad_letter.upper()
        # Column-shift table: column c -> alphabet index of keyword[c]
        self._shifts = [alphabet.index(c) for c in keyword]

    def _column_lengths(self, text_len: int) -> list[int]:
        """Per-column cell counts for an IRREGULAR grid (last row short).
        First `extra` columns get one more cell than the rest."""
        full_rows, extra = divmod(text_len, self.width)
        return [full_rows + (1 if c < extra else 0) for c in range(self.width)]

    def _apply_shift(self, ch: str, col: int, *, direction: int) -> str:
        n = self.alphabet.modulus
        shift = self._shifts[col] * direction
        return self.alphabet.at((self.alphabet.index(ch) + shift) % n)

    def encrypt(self, plaintext: str) -> str:
        self._validate(plaintext, "plaintext")
        # Row-major write WITH per-column Vigenere shift; output cells are
        # length-preserving (irregular grid handles non-rectangular tails).
        col_lens = self._column_lengths(len(plaintext))
        # Cells indexed by (col, row); rows for col c are 0..col_lens[c]-1
        cells: list[list[str]] = [[""] * col_lens[c] for c in range(self.width)]
        for i, ch in enumerate(plaintext):
            row, col = divmod(i, self.width)
            cells[col][row] = self._apply_shift(ch, col, direction=+1)
        # Read columns in keyword-rank order.
        out: list[str] = []
        for col in self.column_order:
            out.extend(cells[col])
        return "".join(out)

    def decrypt(self, ciphertext: str) -> str:
        self._validate(ciphertext, "ciphertext")
        col_lens = self._column_lengths(len(ciphertext))
        # Slice the ciphertext into per-column buffers using the read-out order.
        idx = 0
        cells_by_col: dict[int, list[str]] = {}
        for col in self.column_order:
            length = col_lens[col]
            cells_by_col[col] = list(ciphertext[idx : idx + length])
            idx += length
        # Read row-major and undo per-column shifts.
        out: list[str] = []
        for i in range(len(ciphertext)):
            row, col = divmod(i, self.width)
            out.append(self._apply_shift(cells_by_col[col][row], col, direction=-1))
        return "".join(out)
