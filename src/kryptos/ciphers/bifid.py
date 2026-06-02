"""Bifid: fractionate plaintext via a 5x5 Polybius square, then reorder.

Construction (Delastelle, 1895):
  1. Build a 5x5 Polybius square from a keyword on a 25-letter alphabet
     (one letter must merge with another; default merges I->J, configurable).
  2. Encrypt by replacing each plaintext letter with its (row, col)
     coordinates, then reading the coordinate stream in row-major order
     in blocks of length `period` (period of 5 is canonical; period=1
     degenerates to monoalphabetic substitution; period=len(plaintext)
     is the "full" Bifid).
  3. Decrypt is the inverse: chunk the coordinate stream by period,
     re-interleave rows and columns, look up letters from the square.

Tested on K4 with mixed Polybius squares (e.g. Please Decipher Me, 2011);
prior work has not satisfied the cribs with any keyword/period tried.
This implementation lets ShinkaEvolve sweep keyword and period.

Self-encryption: Bifid CAN allow self-encryption (depending on grid
geometry), so it is NOT structurally ruled out by K4's K->K at position
74 the way pure Beaufort is.
"""

from __future__ import annotations

from kryptos.alphabets import STANDARD, Alphabet
from kryptos.ciphers.base import Cipher
from kryptos.utils import assert_clean


def _build_square(keyword: str, merge: tuple[str, str]) -> tuple[str, dict[str, tuple[int, int]], dict[tuple[int, int], str]]:
    """Return (square_letters, letter->(r,c), (r,c)->letter).

    The square is built from `keyword` (deduplicated, uppercase) followed
    by the rest of A-Z, with `merge[0]` substituted for `merge[1]`
    everywhere so both letters share a cell.
    """
    a, b = merge[0].upper(), merge[1].upper()
    alphabet_25 = "".join(c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if c != b)
    seen: list[str] = []
    seen_set: set[str] = set()
    for c in keyword.upper():
        if c == b:
            c = a
        if c in alphabet_25 and c not in seen_set:
            seen.append(c)
            seen_set.add(c)
    for c in alphabet_25:
        if c not in seen_set:
            seen.append(c)
            seen_set.add(c)
    if len(seen) != 25:
        raise ValueError(
            f"Bifid square has {len(seen)} letters, expected 25 (check merge={merge})"
        )
    square = "".join(seen)
    coord: dict[str, tuple[int, int]] = {}
    rev: dict[tuple[int, int], str] = {}
    for i, c in enumerate(square):
        r, col = divmod(i, 5)
        coord[c] = (r, col)
        rev[(r, col)] = c
    # Merged letter b maps to a's coordinate so input b is accepted.
    coord[b] = coord[a]
    return square, coord, rev


class Bifid(Cipher):
    """Bifid cipher with configurable keyword, period, and merge pair.

    Args:
        keyword: builds the 5x5 Polybius square (deduplicated; remainder
            of A-Z follows). Default ``"KRYPTOS"``.
        period: block length for fractionation. Period 5 is canonical;
            period 7 is also commonly tried on K4 (matches K3 width).
            Period 1 reduces to monoalphabetic substitution.
        merge: pair of letters sharing a cell (canonical is ("I","J")).
            For KRYPTOS-keyed grids, ("K","Q") is sometimes tried instead
            since K is the keyword's high-frequency letter.
    """

    def __init__(
        self,
        keyword: str = "KRYPTOS",
        period: int = 5,
        merge: tuple[str, str] = ("I", "J"),
        alphabet: Alphabet = STANDARD,
    ) -> None:
        super().__init__(alphabet)
        if period < 1:
            raise ValueError(f"period must be >= 1, got {period}")
        if merge[0].upper() == merge[1].upper():
            raise ValueError(f"merge letters must differ, got {merge}")
        self.keyword = keyword.upper()
        self.period = period
        self.merge = (merge[0].upper(), merge[1].upper())
        self._square, self._coord, self._rev = _build_square(self.keyword, self.merge)

    def encrypt(self, plaintext: str) -> str:
        assert_clean(plaintext, "plaintext")
        a, b = self.merge
        rows: list[int] = []
        cols: list[int] = []
        for ch in plaintext:
            if ch == b:
                ch = a
            if ch not in self._coord:
                raise ValueError(f"letter {ch!r} not in Bifid square (alphabet={self._square!r})")
            r, c = self._coord[ch]
            rows.append(r)
            cols.append(c)

        out_chars: list[str] = []
        n = len(plaintext)
        for block_start in range(0, n, self.period):
            block_end = min(block_start + self.period, n)
            block_rows = rows[block_start:block_end]
            block_cols = cols[block_start:block_end]
            stream = block_rows + block_cols
            # Re-read as (row, col) pairs
            for i in range(0, len(stream), 2):
                if i + 1 < len(stream):
                    out_chars.append(self._rev[(stream[i], stream[i + 1])])
        return "".join(out_chars)

    def decrypt(self, ciphertext: str) -> str:
        assert_clean(ciphertext, "ciphertext")
        a, b = self.merge
        # Convert ciphertext to coord stream
        stream: list[int] = []
        for ch in ciphertext:
            if ch == b:
                ch = a
            if ch not in self._coord:
                raise ValueError(f"letter {ch!r} not in Bifid square")
            r, c = self._coord[ch]
            stream.append(r)
            stream.append(c)

        # Undo the per-block interleave: each block of `period` plaintext
        # chars produced 2*period coord ints (rows then cols). To invert,
        # take 2*period coord ints, split into rows and cols halves, then
        # zip back into (row, col) pairs.
        n = len(ciphertext)
        out_chars: list[str] = []
        idx = 0
        for block_start in range(0, n, self.period):
            block_len = min(self.period, n - block_start)
            chunk = stream[idx : idx + 2 * block_len]
            idx += 2 * block_len
            half = block_len
            rows = chunk[:half]
            cols = chunk[half:]
            for r, c in zip(rows, cols):
                out_chars.append(self._rev[(r, c)])
        return "".join(out_chars)
