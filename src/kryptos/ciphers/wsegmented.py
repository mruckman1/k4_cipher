"""W-segmented cipher (Lethuillier-style).

Hypothesis underpinning this primitive:
  K4's ciphertext contains the letter ``W`` at exactly five positions
  (21, 37, 49, 59, 75 — 1-indexed). The W-segmentation hypothesis (most
  recently advanced by Lethuillier) is that ``W`` serves as a structural
  delimiter and the underlying cipher is applied INDEPENDENTLY to each
  inter-W segment, possibly with different keys/parameters per segment.

The segmentation analysis is real: K4's W positions divide the
ciphertext into segments of lengths 20, 15, 11, 9, 15, 22 which align
suggestively with the EAST/NORTHEAST and BERLIN/CLOCK crib windows
(both cribs land in single segments, not across boundaries). Earlier
work in this project concluded "the W-segmentation is REAL but the
per-segment cipher isn't short-period Q3"; the sharpening, not the
rejection, motivates this class — we want the dispatcher to be able
to sweep arbitrary per-segment ciphers.

Self-encryption: K4 position 74 (ciphertext ``K``, plaintext ``K``) is
the LAST character of the 5th segment (positions 60-74), right before
the W at position 75. That alignment is one of the more striking
structural coincidences in K4 and is one reason the W-segmentation
hypothesis has stayed alive despite null cipher-class sweeps.

Splitting is POSITION-based, not character-based: the delimiter
positions are determined from the FIRST input the cipher sees (or
provided explicitly via ``delimiter_positions``), then used for all
subsequent calls. This avoids the round-trip bug where a per-segment
cipher's output happens to contain the delimiter letter as a non-
delimiter character, which character-based splitting would mis-segment.
"""

from __future__ import annotations

from collections.abc import Sequence

from kryptos.alphabets import STANDARD, Alphabet
from kryptos.ciphers.base import Cipher
from kryptos.utils import assert_clean


class WSegmented(Cipher):
    """Apply per-segment ciphers between fixed delimiter positions.

    Args:
        segment_ciphers: either a single ``Cipher`` (applied to every
            segment) or a sequence of ``Cipher`` instances (one per
            segment in order; length must match ``n_segments``).
        delimiter: the letter inserted between segments in the output
            (and the letter the cipher looks for when auto-detecting
            positions from the first input). Default ``"W"``.
        delimiter_positions: explicit 0-indexed positions of the
            delimiter letter in the input. If ``None`` (default),
            the positions are auto-detected from the first call's
            input by scanning for ``delimiter``. Pass explicitly to
            lock the segmentation (e.g. K4's W positions
            ``(20, 36, 48, 58, 74)``) regardless of what stray
            delimiter chars may appear in cipher outputs.

    Example for K4:

        WSegmented(
            segment_ciphers=[
                QuagmireIII(key="KRYPTOS"),
                QuagmireIII(key="PALIMPSEST"),
                QuagmireIII(key="ABSCISSA"),
                QuagmireIII(key="BERLIN"),
                QuagmireIII(key="DYAHR"),
                QuagmireIII(key="LANGLEY"),
            ],
            delimiter="W",
            delimiter_positions=(20, 36, 48, 58, 74),
        )
    """

    def __init__(
        self,
        segment_ciphers: Cipher | Sequence[Cipher],
        delimiter: str = "W",
        delimiter_positions: tuple[int, ...] | None = None,
        alphabet: Alphabet = STANDARD,
    ) -> None:
        super().__init__(alphabet)
        if len(delimiter) != 1 or not delimiter.isalpha():
            raise ValueError(f"delimiter must be one letter, got {delimiter!r}")
        self.delimiter = delimiter.upper()
        if delimiter_positions is not None:
            positions = tuple(int(p) for p in delimiter_positions)
            if list(positions) != sorted(positions) or len(set(positions)) != len(positions):
                raise ValueError(
                    f"delimiter_positions must be strictly increasing, got {positions}"
                )
            self._fixed_positions: tuple[int, ...] | None = positions
        else:
            self._fixed_positions = None
        if isinstance(segment_ciphers, Cipher):
            self._uniform_cipher: Cipher | None = segment_ciphers
            self._segment_ciphers: tuple[Cipher, ...] | None = None
        else:
            self._uniform_cipher = None
            self._segment_ciphers = tuple(segment_ciphers)
            if any(not isinstance(c, Cipher) for c in self._segment_ciphers):
                raise TypeError("segment_ciphers must all be Cipher instances")

    def _positions_for(self, text: str) -> tuple[int, ...]:
        """Return the delimiter positions to use for this call."""
        if self._fixed_positions is not None:
            for p in self._fixed_positions:
                if p < 0 or p >= len(text):
                    raise ValueError(
                        f"delimiter position {p} outside text length {len(text)}"
                    )
            return self._fixed_positions
        return tuple(i for i, c in enumerate(text) if c == self.delimiter)

    def _ciphers_for(self, n_segments: int) -> tuple[Cipher, ...]:
        if self._uniform_cipher is not None:
            return tuple(self._uniform_cipher for _ in range(n_segments))
        assert self._segment_ciphers is not None
        if len(self._segment_ciphers) != n_segments:
            raise ValueError(
                f"WSegmented configured for {len(self._segment_ciphers)} segments "
                f"but input requires {n_segments} (delimiter={self.delimiter!r})"
            )
        return self._segment_ciphers

    def _segments(self, text: str, positions: tuple[int, ...]) -> list[str]:
        """Slice ``text`` into segments at the given delimiter positions.

        The positions themselves are EXCLUDED from segments (they are
        delimiter cells). Returns ``len(positions) + 1`` segments.
        """
        out: list[str] = []
        prev = 0
        for p in positions:
            out.append(text[prev:p])
            prev = p + 1
        out.append(text[prev:])
        return out

    def _apply(self, text: str, *, encrypt: bool) -> str:
        assert_clean(text, "plaintext" if encrypt else "ciphertext")
        positions = self._positions_for(text)
        segments = self._segments(text, positions)
        ciphers = self._ciphers_for(len(segments))

        out_chars: list[str] = []
        for i, (seg, cipher) in enumerate(zip(segments, ciphers)):
            if seg:
                out_chars.append(cipher.encrypt(seg) if encrypt else cipher.decrypt(seg))
            if i < len(positions):
                out_chars.append(self.delimiter)
        result = "".join(out_chars)
        # Length preservation invariant: any length-preserving per-segment
        # cipher produces output of the same length as input.
        if len(result) != len(text):
            raise ValueError(
                f"WSegmented per-segment cipher changed length "
                f"({len(text)} -> {len(result)}); use only length-preserving "
                f"per-segment ciphers (no Playfair odd-pad)."
            )
        return result

    def encrypt(self, plaintext: str) -> str:
        return self._apply(plaintext, encrypt=True)

    def decrypt(self, ciphertext: str) -> str:
        return self._apply(ciphertext, encrypt=False)
