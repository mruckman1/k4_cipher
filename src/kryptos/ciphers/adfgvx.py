"""ADFGVX cipher (Painvin/Nebel, German Army, 1918).

Two-stage cipher:
  STAGE 1 (substitution): a 6x6 Polybius square holds 26 letters + 10
  digits, with row+column labels chosen from {A, D, F, G, V, X}
  (chosen because they were easily distinguishable in Morse code). Each
  plaintext letter/digit is replaced by its (row_label, col_label)
  pair -- 1 letter -> 2 letters.

  STAGE 2 (transposition): the resulting double-length string is
  written into a grid with width equal to the transposition keyword's
  length, then columns are read out in keyword-rank order.

For our K4 use case (alphabet is only A-Z, no digits), the cipher is
effectively ADFGX (5x5, 25 letters with one merge — typically I/J). To
keep the name standard and avoid spec proliferation, we expose the 6x6
version but allow the 36-symbol grid to include only A-Z + 10 digit
slots populated with arbitrary fillers; for decrypting K4 (no digits)
this is functionally equivalent to ADFGX. Period sweeps and grid
keyword sweeps are the productive dispatcher mutations.

Self-encryption is possible for specific (grid, transposition-keyword)
combinations; not structurally ruled out for K4 position 74.
"""

from __future__ import annotations

from kryptos.alphabets import STANDARD, Alphabet
from kryptos.ciphers.base import Cipher
from kryptos.utils import assert_clean

_ADFGVX_LABELS = "ADFGVX"  # 6 labels
_ADFGX_LABELS = "ADFGX"    # 5 labels for the A-Z-only variant


def _build_polybius(
    keyword: str, labels: str, fillers: str = ""
) -> tuple[
    dict[str, tuple[str, str]],
    dict[tuple[str, str], str],
]:
    """Build a Polybius square of size len(labels) x len(labels).
    Filled with: keyword (dedup), then A-Z minus duplicates, then
    `fillers` if extra cells remain (length < labels^2).
    """
    size = len(labels)
    total = size * size
    seen: list[str] = []
    seen_set: set[str] = set()
    for c in (keyword + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + fillers).upper():
        if c not in seen_set and (c.isalnum()):
            seen.append(c)
            seen_set.add(c)
        if len(seen) == total:
            break
    if len(seen) != total:
        raise ValueError(
            f"Polybius needs {total} symbols; got {len(seen)} after "
            f"merging keyword '{keyword}' + A-Z + fillers '{fillers}'"
        )
    coord: dict[str, tuple[str, str]] = {}
    rev: dict[tuple[str, str], str] = {}
    for i, c in enumerate(seen):
        r, col = divmod(i, size)
        coord[c] = (labels[r], labels[col])
        rev[(labels[r], labels[col])] = c
    return coord, rev


def _column_order(keyword: str) -> tuple[int, ...]:
    """ACA convention: alphabetic rank of keyword letters, ties broken
    left-to-right; returns the order in which columns are read out."""
    indexed = sorted(enumerate(keyword.upper()), key=lambda ic: (ic[1], ic[0]))
    return tuple(i for i, _ in indexed)


class ADFGVX(Cipher):
    """ADFGVX/ADFGX two-stage substitution+transposition cipher.

    Args:
        grid_keyword: keyword for the Polybius square.
        transposition_keyword: keyword whose length gives column count
            and whose letter ranks give read-out order in stage 2.
        size: 5 for ADFGX (25 cells, A-Z-J merge) or 6 for full ADFGVX
            (36 cells, A-Z + 0-9). Default 6.
        merge_drop: letter merged into 'I' for size=5; ignored for size=6.
            Default 'J'.

    On decrypting K4 (A-Z only, length 97 = odd), the ADFGX 5x5 variant
    is the natural choice; size=6 adds digit cells that K4 inputs can
    never reach (so decryption ignores them).
    """

    def __init__(
        self,
        grid_keyword: str,
        transposition_keyword: str,
        size: int = 6,
        merge_drop: str = "J",
        alphabet: Alphabet = STANDARD,
    ) -> None:
        super().__init__(alphabet)
        if size not in (5, 6):
            raise ValueError(f"size must be 5 (ADFGX) or 6 (ADFGVX), got {size}")
        self.size = size
        self.grid_keyword = grid_keyword.upper()
        self.transposition_keyword = transposition_keyword.upper()
        self.merge_drop = merge_drop.upper()
        self.labels = _ADFGX_LABELS if size == 5 else _ADFGVX_LABELS
        # For size=5: drop merge_drop from the alphabet pool
        fillers = "" if size == 5 else "0123456789"
        # When size=5, exclude merge_drop from the seed sequence
        if size == 5:
            seed = grid_keyword.replace(merge_drop, "") + \
                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ".replace(merge_drop, "")
        else:
            seed = grid_keyword + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self._coord, self._rev = _build_polybius(seed, self.labels, fillers)
        if size == 5:
            # Map merge_drop input to 'I' coord (lossy on round-trip)
            self._coord[merge_drop] = self._coord["I"]
        self.column_order = _column_order(self.transposition_keyword)
        self.width = len(self.transposition_keyword)

    # ----- Stage 1: substitution -----
    def _substitute(self, text: str) -> str:
        out: list[str] = []
        for ch in text:
            ch_up = ch.upper()
            if self.size == 5 and ch_up == self.merge_drop:
                ch_up = "I"
            if ch_up not in self._coord:
                raise ValueError(f"letter {ch!r} not in ADFGVX grid")
            r, c = self._coord[ch_up]
            out.append(r)
            out.append(c)
        return "".join(out)

    def _unsubstitute(self, intermediate: str) -> str:
        if len(intermediate) % 2:
            raise ValueError(
                f"intermediate length {len(intermediate)} must be even "
                "for ADFGVX substitution inverse"
            )
        out: list[str] = []
        for i in range(0, len(intermediate), 2):
            pair = (intermediate[i], intermediate[i + 1])
            if pair not in self._rev:
                # Pair contains a non-label char (cipher output corrupted by
                # truncation); fill with 'X' to keep length consistent.
                out.append("X")
            else:
                out.append(self._rev[pair])
        return "".join(out)

    # ----- Stage 2: columnar transposition (irregular grid) -----
    def _column_lengths(self, n: int) -> list[int]:
        full_rows, extra = divmod(n, self.width)
        return [full_rows + (1 if c < extra else 0) for c in range(self.width)]

    def _transpose_encrypt(self, text: str) -> str:
        col_lens = self._column_lengths(len(text))
        cells: list[list[str]] = [[""] * col_lens[c] for c in range(self.width)]
        for i, ch in enumerate(text):
            row, col = divmod(i, self.width)
            cells[col][row] = ch
        out: list[str] = []
        for col in self.column_order:
            out.extend(cells[col])
        return "".join(out)

    def _transpose_decrypt(self, text: str) -> str:
        col_lens = self._column_lengths(len(text))
        idx = 0
        cells_by_col: dict[int, list[str]] = {}
        for col in self.column_order:
            length = col_lens[col]
            cells_by_col[col] = list(text[idx : idx + length])
            idx += length
        out: list[str] = []
        for i in range(len(text)):
            row, col = divmod(i, self.width)
            out.append(cells_by_col[col][row])
        return "".join(out)

    # ----- Public API -----
    def encrypt(self, plaintext: str) -> str:
        """ADFGVX encrypts to TWICE the input length (each plain char becomes
        a label pair). For a 97-char K4 plaintext this would emit 194 cipher
        letters, so ADFGVX is not directly applicable as the K4 cipher unless
        the assumed plaintext is ~48 chars and the cribs are reinterpreted.
        Implementation is correct and round-trips; K4 dispatcher must NOT
        include ADFGVX directly (call decrypt on a 194-char input only)."""
        self._validate(plaintext, "plaintext")
        intermediate = self._substitute(plaintext)  # length 2N
        return self._transpose_encrypt(intermediate)

    def decrypt(self, ciphertext: str) -> str:
        """ADFGVX decrypts to HALF the input length (label pairs collapse
        to one plain char each). Requires even-length input drawn from the
        label alphabet. For K4 use, the ciphertext would need to be 2 *
        target plaintext length AND contain only ADFGVX labels -- K4's
        97-char A-Z ciphertext satisfies neither, so this cipher is not
        a K4-decryption candidate as currently parameterized."""
        self._validate(ciphertext, "ciphertext")
        if len(ciphertext) % 2:
            raise ValueError(
                f"ADFGVX ciphertext must be even-length, got {len(ciphertext)} "
                "(each plaintext char produces 2 cipher chars; odd input is "
                "structurally impossible)"
            )
        intermediate = self._transpose_decrypt(ciphertext)
        return self._unsubstitute(intermediate)
