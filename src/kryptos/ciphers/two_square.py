"""Two-square cipher (horizontal variant).

Construction (Wheatstone-Hammond, 1850s; ACA standard variant):
  1. Build TWO 5x5 keyed Polybius squares (top + bottom by convention,
     or left + right; this implementation uses horizontal/top-bottom).
     One letter merges (canonical: I/J share a cell).
  2. Process plaintext in DIGRAMS (pairs of letters):
       - Find the first letter in the TOP square at (r1, c1).
       - Find the second letter in the BOTTOM square at (r2, c2).
       - Replace with: TOP[(r1, c2)] + BOTTOM[(r2, c1)].
     (The two letters swap columns, keeping their original rows. If
     r1 == r2, the digram is "transparent" — output equals input — which
     is the cipher's known weakness.)
  3. Odd-length input gets a filler letter padding the final digram.

Position 74's self-encryption (K -> K) IS compatible with two-square
on most grids: any digram (?, K) where the partner sits in the same
column as K in the top grid will leave K unchanged.

Tested on K4: sweeping keyword pairs from K-family vocabulary has not
historically satisfied the cribs, but the test was incomplete; the
dispatcher can sweep more keyword pairs.
"""

from __future__ import annotations

from kryptos.alphabets import STANDARD, Alphabet
from kryptos.ciphers.base import Cipher
from kryptos.utils import assert_clean


def _build_square(
    keyword: str, merge: tuple[str, str]
) -> tuple[dict[str, tuple[int, int]], dict[tuple[int, int], str]]:
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
        raise ValueError(f"Two-square grid has {len(seen)} letters, expected 25")
    coord: dict[str, tuple[int, int]] = {}
    rev: dict[tuple[int, int], str] = {}
    for i, c in enumerate(seen):
        r, col = divmod(i, 5)
        coord[c] = (r, col)
        rev[(r, col)] = c
    coord[b] = coord[a]  # merged input
    return coord, rev


class TwoSquare(Cipher):
    """Two-square (horizontal) digram cipher.

    Args:
        top_keyword: builds the TOP 5x5 grid.
        bottom_keyword: builds the BOTTOM 5x5 grid.
        merge: pair of letters sharing a cell. Default ("I","J").
        filler: letter padding an odd-length plaintext. Default "X".

    Encryption/decryption are involutory: encrypt and decrypt apply the
    same transformation (find both letters, swap their columns). Round-
    trip works exactly when the plaintext has no characters that are
    the merged letter.
    """

    def __init__(
        self,
        top_keyword: str,
        bottom_keyword: str,
        merge: tuple[str, str] = ("I", "J"),
        filler: str = "X",
        alphabet: Alphabet = STANDARD,
    ) -> None:
        super().__init__(alphabet)
        if merge[0].upper() == merge[1].upper():
            raise ValueError(f"merge letters must differ, got {merge}")
        if len(filler) != 1 or not filler.isalpha():
            raise ValueError(f"filler must be a single letter, got {filler!r}")
        self.top_keyword = top_keyword.upper()
        self.bottom_keyword = bottom_keyword.upper()
        self.merge = (merge[0].upper(), merge[1].upper())
        self.filler = filler.upper()
        self._top_coord, self._top_rev = _build_square(self.top_keyword, self.merge)
        self._bot_coord, self._bot_rev = _build_square(self.bottom_keyword, self.merge)

    def _process(self, text: str) -> str:
        a, b = self.merge
        # Map the merged letter to its `a` partner so coords are defined.
        clean = [a if c == b else c for c in text]
        # Pad odd length with filler.
        if len(clean) % 2:
            clean.append(self.filler if self.filler != self.merge[1] else self.merge[0])
        out: list[str] = []
        for i in range(0, len(clean), 2):
            c1, c2 = clean[i], clean[i + 1]
            r1, col1 = self._top_coord[c1]
            r2, col2 = self._bot_coord[c2]
            out.append(self._top_rev[(r1, col2)])
            out.append(self._bot_rev[(r2, col1)])
        return "".join(out)

    def encrypt(self, plaintext: str) -> str:
        self._validate(plaintext, "plaintext")
        original_len = len(plaintext)
        return self._process(plaintext)[:original_len]

    def decrypt(self, ciphertext: str) -> str:
        self._validate(ciphertext, "ciphertext")
        original_len = len(ciphertext)
        # Two-square is involutory: same operation, same grids
        return self._process(ciphertext)[:original_len]
