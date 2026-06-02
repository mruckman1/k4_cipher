"""Alphabet objects.

An Alphabet is an ordered sequence of distinct letters with O(1) index and
letter lookup. All cipher code in this library is alphabet-parameterised
rather than hard-wired to A-Z, because the KRYPTOS-keyed alphabet is the
correct one for K1-K3 and almost certainly relevant to K4.

The variant with an extra L (`KRYPTOSABCDEFGHIJLLMNQUVWXZ`) is the tableau
anomaly on the sculpture itself; it is intentionally non-unique and is NOT
usable as a substitution alphabet on its own. It is kept here as a 27-letter
reference for experiments that want to model the tableau row directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Alphabet:
    name: str
    letters: str
    allow_duplicates: bool = False    # True for 27-letter sculpture variants

    def __post_init__(self) -> None:
        if not self.allow_duplicates and len(set(self.letters)) != len(self.letters):
            raise ValueError(
                f"Alphabet {self.name!r} has duplicate letters: {self.letters!r}; "
                f"pass allow_duplicates=True to opt in (non-injective alphabet)"
            )

    def __len__(self) -> int:
        return len(self.letters)

    @property
    def modulus(self) -> int:
        """The mod arithmetic for any Vigenere/Quagmire arithmetic done in
        this alphabet's index space. Equivalent to len(self.letters); kept
        as a named property so callers can write `(p + k) % alpha.modulus`
        rather than the implicit `len(alpha)`."""
        return len(self.letters)

    def index(self, letter: str) -> int:
        """Index of `letter` in this alphabet (first occurrence; for
        duplicate-bearing alphabets like the 27-letter sculpture variants
        this means decryption is well-defined but is not a strict inverse
        of encryption -- encryption can produce either copy)."""
        return self.letters.index(letter)

    def at(self, i: int) -> str:
        """Letter at position `i` modulo the alphabet length."""
        return self.letters[i % len(self.letters)]

    def contains(self, letter: str) -> bool:
        return letter in self.letters

    def encode(self, text: str) -> list[int]:
        """Map each letter of `text` to its index in this alphabet."""
        idx = self.letters.index
        return [idx(c) for c in text]

    def decode(self, indices: list[int]) -> str:
        return "".join(self.letters[i % len(self.letters)] for i in indices)


STANDARD = Alphabet("standard", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
KRYPTOS_KEYED = Alphabet("kryptos_keyed", "KRYPTOSABCDEFGHIJLMNQUVWXZ")

# Three 27-letter sculpture-tableau variants. Bauer, Link & Molle (2016)
# note that "HILL" spells vertically with the doubled-L variant; that is
# the strongest evidence the doubled-L form is the intentional anomaly.
# The trailing-L and K-restored forms are kept as fallbacks: the trailing
# form models a literal "extra letter at the end of the alphabet" reading,
# and the K-restored form treats the missing K after J in the standard
# 26-letter KRYPTOS-keyed alphabet as the anomaly rather than the extra L.
KRYPTOS_WITH_EXTRA_L = Alphabet(
    "kryptos_with_extra_L", "KRYPTOSABCDEFGHIJLLMNQUVWXZ",
    allow_duplicates=True,
)

KRYPTOS_TRAILING_L = Alphabet(
    "kryptos_trailing_L", "KRYPTOSABCDEFGHIJLMNQUVWXZL",
    allow_duplicates=True,
)

KRYPTOS_K_RESTORED = Alphabet(
    "kryptos_K_restored", "KRYPTOSABCDEFGHIJKLMNQUVWXZ",
    allow_duplicates=True,
)

THREE_27_LETTER_ALPHABETS: list[Alphabet] = [
    KRYPTOS_WITH_EXTRA_L, KRYPTOS_TRAILING_L, KRYPTOS_K_RESTORED,
]


def keyed_alphabet(keyword: str, base: Alphabet = STANDARD) -> Alphabet:
    """Build a keyed alphabet: keyword letters first (dedup), then the
    remainder of `base` in its natural order. Letters not in `base` are
    silently dropped from the keyword.
    """
    keyword = keyword.upper()
    seen: list[str] = []
    seen_set: set[str] = set()
    for c in keyword:
        if c in base.letters and c not in seen_set:
            seen.append(c)
            seen_set.add(c)
    for c in base.letters:
        if c not in seen_set:
            seen.append(c)
            seen_set.add(c)
    return Alphabet(f"keyed[{keyword}]", "".join(seen))


def load_from_file(path: str | Path, name: str | None = None) -> Alphabet:
    """Load an alphabet from a single-line text file."""
    p = Path(path)
    letters = p.read_text().strip()
    return Alphabet(name or p.stem, letters)
