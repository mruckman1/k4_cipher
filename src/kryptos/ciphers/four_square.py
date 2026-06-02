"""Four-square cipher (Felix Delastelle, ~1902).

Construction:
  - FOUR 5x5 grids arranged in a 2x2 layout:
        upper-left:  plain grid 1 (standard A-Z minus J, in order)
        upper-right: cipher grid 1 (keyword 1)
        lower-left:  cipher grid 2 (keyword 2)
        lower-right: plain grid 2 (standard A-Z minus J, in order)
  - Encrypt by digrams (pairs):
       - Find letter 1 in upper-left at (r1, c1).
       - Find letter 2 in lower-right at (r2, c2).
       - Output: upper-right[(r1, c2)] + lower-left[(r2, c1)].
     (Output letters come from the two CIPHER grids, indexed by the
     row of one input letter and the column of the other.)

Self-encryption is possible when the cipher-grid coordinate happens
to equal the corresponding plain-grid letter; not guaranteed but not
ruled out for K4 position 74.

Two cipher keywords (top-right + bottom-left) give a large parameter
space; this implementation lets the dispatcher sweep both.
"""

from __future__ import annotations

from kryptos.alphabets import STANDARD, Alphabet
from kryptos.ciphers.base import Cipher
from kryptos.utils import assert_clean


def _build_grid(
    keyword: str, merge_drop: str = "J"
) -> tuple[dict[str, tuple[int, int]], dict[tuple[int, int], str]]:
    alphabet_25 = "".join(c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if c != merge_drop)
    seen: list[str] = []
    seen_set: set[str] = set()
    for c in keyword.upper():
        if c == merge_drop:
            c = "I" if merge_drop == "J" else "I"
        if c in alphabet_25 and c not in seen_set:
            seen.append(c)
            seen_set.add(c)
    for c in alphabet_25:
        if c not in seen_set:
            seen.append(c)
            seen_set.add(c)
    if len(seen) != 25:
        raise ValueError(f"Four-square grid has {len(seen)} letters, expected 25")
    coord: dict[str, tuple[int, int]] = {}
    rev: dict[tuple[int, int], str] = {}
    for i, c in enumerate(seen):
        r, col = divmod(i, 5)
        coord[c] = (r, col)
        rev[(r, col)] = c
    coord[merge_drop] = coord["I"]
    return coord, rev


class FourSquare(Cipher):
    """Four-square cipher with two configurable cipher-grid keywords.

    Args:
        top_right_keyword: keyword for the upper-right (cipher grid 1).
        bottom_left_keyword: keyword for the lower-left (cipher grid 2).
        merge_drop: letter dropped from the 25-cell alphabet, merged
            into 'I'. Default 'J'.
        filler: padding letter for odd-length plaintext. Default 'X'.
    """

    def __init__(
        self,
        top_right_keyword: str,
        bottom_left_keyword: str,
        merge_drop: str = "J",
        filler: str = "X",
        alphabet: Alphabet = STANDARD,
    ) -> None:
        super().__init__(alphabet)
        merge_drop = merge_drop.upper()
        if merge_drop not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" or merge_drop == "I":
            raise ValueError(f"merge_drop must be an A-Z letter != I, got {merge_drop!r}")
        if len(filler) != 1 or not filler.isalpha():
            raise ValueError(f"filler must be a single letter, got {filler!r}")
        self.top_right_keyword = top_right_keyword.upper()
        self.bottom_left_keyword = bottom_left_keyword.upper()
        self.merge_drop = merge_drop
        self.filler = filler.upper()
        # Plain grids: standard A-Z minus J in alphabetical order
        self._plain_coord, self._plain_rev = _build_grid("", merge_drop)
        self._tr_coord, self._tr_rev = _build_grid(self.top_right_keyword, merge_drop)
        self._bl_coord, self._bl_rev = _build_grid(self.bottom_left_keyword, merge_drop)

    def _digrams(self, text: str) -> list[tuple[str, str]]:
        clean = [self.merge_drop if c == self.merge_drop else c for c in text]
        if len(clean) % 2:
            clean.append(self.filler if self.filler != self.merge_drop else "X")
        return [(clean[i], clean[i + 1]) for i in range(0, len(clean), 2)]

    def encrypt(self, plaintext: str) -> str:
        self._validate(plaintext, "plaintext")
        original_len = len(plaintext)
        out: list[str] = []
        for c1, c2 in self._digrams(plaintext):
            r1, col1 = self._plain_coord[c1]
            r2, col2 = self._plain_coord[c2]
            out.append(self._tr_rev[(r1, col2)])
            out.append(self._bl_rev[(r2, col1)])
        return "".join(out)[:original_len]

    def decrypt(self, ciphertext: str) -> str:
        self._validate(ciphertext, "ciphertext")
        original_len = len(ciphertext)
        ct = ciphertext
        if len(ct) % 2:
            ct = ct + self.filler
        out: list[str] = []
        for i in range(0, len(ct), 2):
            c1, c2 = ct[i], ct[i + 1]
            r1, col1 = self._tr_coord[c1]
            r2, col2 = self._bl_coord[c2]
            out.append(self._plain_rev[(r1, col2)])
            out.append(self._plain_rev[(r2, col1)])
        return "".join(out)[:original_len]
