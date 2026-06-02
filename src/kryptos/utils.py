"""Small helpers used across the library."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator


_NON_LETTER = re.compile(r"[^A-Za-z]")


def clean(text: str) -> str:
    """Uppercase, strip everything that is not an ASCII letter. Use on any
    incoming text before feeding into a cipher routine."""
    return _NON_LETTER.sub("", text).upper()


def chunks(seq: str, size: int) -> Iterator[str]:
    """Yield consecutive `size`-character chunks of `seq`. Last chunk may
    be shorter than `size`."""
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def repeat_to_length(key: str, length: int) -> str:
    """Pad/truncate `key` by repetition to exactly `length` characters."""
    if not key:
        raise ValueError("key must be non-empty")
    times, remainder = divmod(length, len(key))
    return key * times + key[:remainder]


def hamming(a: str, b: str) -> int:
    if len(a) != len(b):
        raise ValueError("hamming distance needs equal-length strings")
    return sum(x != y for x, y in zip(a, b))


def english_letter_counts(text: str) -> dict[str, int]:
    """Per-letter counts in `text`. Non-letters are ignored, output is
    keyed by uppercase A-Z."""
    counts: dict[str, int] = {c: 0 for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}
    for c in text.upper():
        if c in counts:
            counts[c] += 1
    return counts


def positions_of(text: str, letter: str) -> list[int]:
    """0-indexed positions of `letter` in `text`."""
    return [i for i, c in enumerate(text) if c == letter]


def assert_clean(text: str, label: str = "text") -> None:
    if not text:
        raise ValueError(f"{label} is empty")
    if any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" for c in text):
        bad = sorted({c for c in text if not c.isalpha() or c.islower()})
        raise ValueError(f"{label} contains non-uppercase-letter characters: {bad}")


def iter_window(seq: str, size: int) -> Iterable[str]:
    """Yield length-`size` substrings of `seq` (sliding by 1)."""
    if size <= 0:
        raise ValueError("size must be positive")
    for i in range(len(seq) - size + 1):
        yield seq[i : i + size]
