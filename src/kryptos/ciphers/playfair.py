"""Playfair (digram substitution on a 5x5 keyed square).

Construction (Charles Wheatstone, 1854):
  1. Build a 5x5 grid from a keyword (deduplicated), then the rest of A-Z
     with one letter merged (canonically I/J share a cell).
  2. Encrypt by processing the plaintext in digrams:
       - If a digram has two identical letters, insert a filler (default X)
         between them and re-pair.
       - If both letters share a row: replace each with the letter to its
         right (wrapping).
       - If both share a column: replace each with the letter below (wrapping).
       - Otherwise: each letter is replaced with the letter in its own row
         at the OTHER letter's column (the "rectangle rule").

K4 length 97 is odd, so straight Playfair needs a padding letter at the
end. We expose ``merge`` so the caller can override (e.g. merge K and Q
for a KRYPTOS-keyed square that would otherwise lose K to deduplication
of the keyword).

Self-encryption: Playfair never produces self-encryption for a digram
where the two letters share a row or column (always shifts by 1).
Position 74 of K4 is K->K, which constrains valid Playfair grids:
either position 74 is the second letter of a digram whose first letter
shares K's row/column (so K shifts, but the OTHER letter ends up at
K's position), or the surrounding plaintext breaks the digram boundary
at 74 with a filler.
"""

from __future__ import annotations

from kryptos.alphabets import STANDARD, Alphabet
from kryptos.ciphers.base import Cipher
from kryptos.utils import assert_clean


def _build_grid(
    keyword: str, merge: tuple[str, str]
) -> tuple[str, dict[str, tuple[int, int]], dict[tuple[int, int], str]]:
    """Build a 25-letter 5x5 keyed grid with the merge pair sharing a cell."""
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
            f"Playfair grid has {len(seen)} letters, expected 25 (check merge={merge})"
        )
    grid = "".join(seen)
    coord: dict[str, tuple[int, int]] = {}
    rev: dict[tuple[int, int], str] = {}
    for i, c in enumerate(grid):
        r, col = divmod(i, 5)
        coord[c] = (r, col)
        rev[(r, col)] = c
    coord[b] = coord[a]  # merged letter shares a's cell
    return grid, coord, rev


class Playfair(Cipher):
    """Playfair cipher on a 5x5 keyed grid.

    Args:
        keyword: builds the grid (deduplicated, then remaining A-Z).
        merge: pair of letters sharing a cell. Canonical ("I", "J");
            ("K", "Q") is a sensible variant for KRYPTOS-keyed grids
            (so the keyword's K doesn't conflict-deduplicate Q).
        filler: letter inserted between repeated letters in a digram
            and used to pad an odd-length plaintext. Default "X".

    Encryption is length-preserving for even-length, padded-by-one input
    for odd. Decryption returns whatever length was produced; callers
    that need exactly N chars should truncate or pad before invoking.
    """

    def __init__(
        self,
        keyword: str = "KRYPTOS",
        merge: tuple[str, str] = ("I", "J"),
        filler: str = "X",
        alphabet: Alphabet = STANDARD,
    ) -> None:
        super().__init__(alphabet)
        if merge[0].upper() == merge[1].upper():
            raise ValueError(f"merge letters must differ, got {merge}")
        if len(filler) != 1 or not filler.isalpha():
            raise ValueError(f"filler must be a single letter, got {filler!r}")
        self.keyword = keyword.upper()
        self.merge = (merge[0].upper(), merge[1].upper())
        self.filler = filler.upper()
        self._grid, self._coord, self._rev = _build_grid(self.keyword, self.merge)

    def _prepare_digrams(self, text: str) -> list[tuple[str, str]]:
        """Convert plaintext to a list of digrams, inserting fillers between
        repeats and padding odd length."""
        a, b = self.merge
        clean = [b if c == b else c for c in text]
        clean = [a if c == b else c for c in clean]  # actually a if c==b
        # The list-comp above is redundant; simpler:
        clean = [a if c == b else c for c in text]

        out: list[tuple[str, str]] = []
        i = 0
        while i < len(clean):
            c1 = clean[i]
            if i + 1 >= len(clean):
                # Pad with filler
                pad = self.filler if c1 != self.filler else "Q"
                out.append((c1, pad))
                break
            c2 = clean[i + 1]
            if c1 == c2:
                pad = self.filler if c1 != self.filler else "Q"
                out.append((c1, pad))
                i += 1
            else:
                out.append((c1, c2))
                i += 2
        return out

    def _transform(self, c1: str, c2: str, direction: int) -> tuple[str, str]:
        """direction = +1 for encrypt, -1 for decrypt."""
        r1, col1 = self._coord[c1]
        r2, col2 = self._coord[c2]
        if r1 == r2:
            return self._rev[(r1, (col1 + direction) % 5)], self._rev[(r2, (col2 + direction) % 5)]
        if col1 == col2:
            return self._rev[((r1 + direction) % 5, col1)], self._rev[((r2 + direction) % 5, col2)]
        # Rectangle rule (same for encrypt/decrypt)
        return self._rev[(r1, col2)], self._rev[(r2, col1)]

    def encrypt(self, plaintext: str) -> str:
        assert_clean(plaintext, "plaintext")
        out: list[str] = []
        for c1, c2 in self._prepare_digrams(plaintext):
            e1, e2 = self._transform(c1, c2, +1)
            out.append(e1)
            out.append(e2)
        return "".join(out)

    def decrypt(self, ciphertext: str) -> str:
        assert_clean(ciphertext, "ciphertext")
        original_len = len(ciphertext)
        if len(ciphertext) % 2 != 0:
            # Pad with filler so we can decrypt; truncate the output back
            # to the input length so length-preserving callers (the K4
            # fitness function, in particular) accept the result.
            ciphertext = ciphertext + self.filler
        a, b = self.merge
        clean = [a if c == b else c for c in ciphertext]
        out: list[str] = []
        for i in range(0, len(clean), 2):
            c1, c2 = clean[i], clean[i + 1]
            d1, d2 = self._transform(c1, c2, -1)
            out.append(d1)
            out.append(d2)
        result = "".join(out)
        return result[:original_len]
