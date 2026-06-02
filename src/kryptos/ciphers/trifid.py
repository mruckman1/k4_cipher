"""Trifid: 3D Polybius fractionation (Delastelle, 1902).

Construction:
  1. Build a 3x3x3 = 27-cell cube from a keyword (deduplicated, plus the
     rest of A-Z, plus a single filler letter to make 27). Each letter
     gets coordinates ``(layer, row, col)`` with each axis in {0,1,2}.
  2. Encrypt by processing the plaintext in blocks of length ``period``:
       a. Each plaintext letter contributes 3 coord ints.
       b. The block's coordinate stream is reordered: all layers first,
          then all rows, then all columns (length 3 * period).
       c. Re-read the reordered stream in groups of 3 to get the
          ciphertext letters' coordinates.
  3. Decrypt is the inverse.

Period 5 is canonical; period 7 also common. Period 1 degenerates to
monoalphabetic substitution.

Self-encryption: Trifid CAN allow self-encryption (depends on grid
geometry), so it is NOT structurally ruled out by K4's K->K at position
74.

Filler convention: the 27th cell holds a unique non-letter sentinel
(internal symbol ``"+"``). On encrypt/decrypt, any output character
that came from that cell is substituted with ``filler`` (default
``"X"``) so the fitness scorer's 97-char A-Z contract holds.

This sentinel substitution is necessarily lossy: any 27-cell cipher
that emits into a 26-letter alphabet cannot be injective, so the
encrypt-then-decrypt round-trip differs from the input at positions
where the cipher landed on cell 27 (those output letters are
indistinguishable from real ``filler`` letters on decryption). The K4
use case is DECRYPT-only on a 26-letter A-Z ciphertext, where this
asymmetry is harmless -- the decrypted plaintext may have a few
spurious ``X``s but the fitness function only needs a 97-char A-Z
output, not a structurally round-trippable one.
"""

from __future__ import annotations

from kryptos.alphabets import STANDARD, Alphabet
from kryptos.ciphers.base import Cipher
from kryptos.utils import assert_clean


_SENTINEL = "+"  # 27th-cell marker; never a valid input letter


def _build_cube(
    keyword: str,
) -> tuple[str, dict[str, tuple[int, int, int]], dict[tuple[int, int, int], str]]:
    """Build a 27-cell cube with 26 A-Z letters + unique sentinel.

    Returns (cube_symbols, letter->coord, coord->symbol). Cube has 27
    DISTINCT symbols (cell 27 is the sentinel ``"+"``), guaranteeing the
    cipher is mathematically injective. The sentinel never appears in
    valid A-Z input; callers post-process any output sentinel to a
    chosen filler letter.
    """
    keyword = keyword.upper()
    seen: list[str] = []
    seen_set: set[str] = set()
    for c in keyword:
        if c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" and c not in seen_set:
            seen.append(c)
            seen_set.add(c)
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if c not in seen_set:
            seen.append(c)
            seen_set.add(c)
    if len(seen) != 26:
        raise ValueError(f"keyword path produced {len(seen)} letters, expected 26")
    seen.append(_SENTINEL)  # 27th cell -- unique, never collides with A-Z input
    cube = "".join(seen)

    coord: dict[str, tuple[int, int, int]] = {}
    rev: dict[tuple[int, int, int], str] = {}
    for i, c in enumerate(cube):
        layer = i // 9
        row = (i // 3) % 3
        col = i % 3
        coord[c] = (layer, row, col)
        rev[(layer, row, col)] = c
    return cube, coord, rev


class Trifid(Cipher):
    """Trifid cipher with configurable keyword, period, and filler letter.

    Args:
        keyword: builds the 27-cell cube (deduplicated, then remaining
            A-Z, then filler). Default ``"KRYPTOS"``.
        period: block length for fractionation. 5 is canonical; 7 is
            also commonly tried. Period 1 degenerates to monoalphabetic
            substitution.
        filler: letter occupying the 27th cell. Default ``"X"`` (low
            frequency in English; minimises round-trip information loss).
    """

    def __init__(
        self,
        keyword: str = "KRYPTOS",
        period: int = 5,
        filler: str = "X",
        alphabet: Alphabet = STANDARD,
    ) -> None:
        super().__init__(alphabet)
        if period < 1:
            raise ValueError(f"period must be >= 1, got {period}")
        if len(filler) != 1 or not filler.isalpha():
            raise ValueError(f"filler must be a single A-Z letter, got {filler!r}")
        self.keyword = keyword.upper()
        self.period = period
        self.filler = filler.upper()
        self._cube, self._coord, self._rev = _build_cube(self.keyword)

    def _replace_sentinels(self, text: str) -> str:
        return text.replace(_SENTINEL, self.filler) if _SENTINEL in text else text

    def encrypt(self, plaintext: str) -> str:
        assert_clean(plaintext, "plaintext")
        stream: list[int] = []
        for ch in plaintext:
            if ch not in self._coord:
                raise ValueError(f"letter {ch!r} not in Trifid cube")
            layer, row, col = self._coord[ch]
            stream.append(layer)
            stream.append(row)
            stream.append(col)

        out_chars: list[str] = []
        n = len(plaintext)
        for block_start in range(0, n, self.period):
            block_end = min(block_start + self.period, n)
            chunk = stream[block_start * 3 : block_end * 3]
            layers = chunk[0::3]
            rows = chunk[1::3]
            cols = chunk[2::3]
            reordered = layers + rows + cols
            for i in range(0, len(reordered), 3):
                if i + 2 < len(reordered):
                    out_chars.append(self._rev[
                        (reordered[i], reordered[i + 1], reordered[i + 2])
                    ])
        return self._replace_sentinels("".join(out_chars))

    def decrypt(self, ciphertext: str) -> str:
        assert_clean(ciphertext, "ciphertext")
        stream: list[int] = []
        for ch in ciphertext:
            if ch not in self._coord:
                raise ValueError(f"letter {ch!r} not in Trifid cube")
            layer, row, col = self._coord[ch]
            stream.append(layer)
            stream.append(row)
            stream.append(col)

        out_chars: list[str] = []
        n = len(ciphertext)
        for block_start in range(0, n, self.period):
            block_end = min(block_start + self.period, n)
            block_len = block_end - block_start
            chunk = stream[block_start * 3 : block_end * 3]
            third = block_len
            layers = chunk[:third]
            rows = chunk[third : 2 * third]
            cols = chunk[2 * third : 3 * third]
            for l, r, c in zip(layers, rows, cols):
                out_chars.append(self._rev[(l, r, c)])
        return self._replace_sentinels("".join(out_chars))
