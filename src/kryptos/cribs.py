"""K4 crib constants in both standard and KRYPTOS-keyed index spaces.

Cribs are encoded once here and consumed everywhere else. Bugs in this file
invalidate every downstream experiment, so it is intentionally short.
"""

from __future__ import annotations

from dataclasses import dataclass

from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, Alphabet


@dataclass(frozen=True)
class Crib:
    """One contiguous known plaintext window in K4.

    Positions are 1-indexed against the 97-character ciphertext; `end` is
    inclusive (so `EAST` at 22-25 has length 4).
    """

    name: str
    start: int           # 1-indexed
    end: int             # inclusive
    plaintext: str
    ciphertext: str

    def __post_init__(self) -> None:
        length = self.end - self.start + 1
        if len(self.plaintext) != length:
            raise ValueError(
                f"{self.name}: plaintext length {len(self.plaintext)} "
                f"!= window length {length}"
            )
        if len(self.ciphertext) != length:
            raise ValueError(
                f"{self.name}: ciphertext length {len(self.ciphertext)} "
                f"!= window length {length}"
            )

    @property
    def slice0(self) -> slice:
        """0-indexed Python slice into the ciphertext string."""
        return slice(self.start - 1, self.end)

    def shifts_in(self, alphabet: Alphabet) -> list[int]:
        """plaintext_index - ciphertext_index mod len(alphabet), per position."""
        n = len(alphabet)
        return [
            (alphabet.index(p) - alphabet.index(c)) % n
            for p, c in zip(self.plaintext, self.ciphertext)
        ]


# 1-indexed crib positions, sourced from cribs.yaml. Keep in sync.
EAST       = Crib("EAST",      22, 25, "EAST",      "FLRV")
NORTHEAST  = Crib("NORTHEAST", 26, 34, "NORTHEAST", "QQPRNGKSS")
BERLIN     = Crib("BERLIN",    64, 69, "BERLIN",    "NYPVTT")
CLOCK      = Crib("CLOCK",     70, 74, "CLOCK",     "MZFPK")

# 4-tuple of confirmed cribs.
CRIBS: tuple[Crib, ...] = (EAST, NORTHEAST, BERLIN, CLOCK)

# Contiguous combined windows -- much stronger constraints than the four
# individual cribs taken separately.
EASTNORTHEAST = Crib(
    "EASTNORTHEAST", 22, 34, "EASTNORTHEAST", "FLRVQQPRNGKSS"
)
BERLINCLOCK = Crib(
    "BERLINCLOCK", 64, 74, "BERLINCLOCK", "NYPVTTMZFPK"
)

CONTIGUOUS_CRIBS: tuple[Crib, ...] = (EASTNORTHEAST, BERLINCLOCK)


def all_known_positions() -> list[int]:
    """0-indexed positions in K4 whose plaintext is known. 24 of 97."""
    out: list[int] = []
    for c in CRIBS:
        out.extend(range(c.start - 1, c.end))
    return out


def crib_shift_table(alphabet: Alphabet = STANDARD) -> dict[int, int]:
    """0-indexed position -> shift value (P - C mod N) for every known
    crib position. Used as the canonical hard constraint for cipher
    families where 'shift at position i' is the natural parameterisation
    (Vigenere, Quagmire, Gromark, autokey, running key)."""
    table: dict[int, int] = {}
    n = len(alphabet)
    for c in CRIBS:
        for offset, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext)):
            i0 = c.start - 1 + offset
            table[i0] = (alphabet.index(p) - alphabet.index(ch)) % n
    return table


# Convenience: the four cribs expressed as plaintext/ciphertext index pairs
# in each alphabet. Flip between them constantly when prototyping.
def shifts_in_standard() -> dict[str, list[int]]:
    return {c.name: c.shifts_in(STANDARD) for c in CONTIGUOUS_CRIBS}


def shifts_in_kryptos() -> dict[str, list[int]]:
    return {c.name: c.shifts_in(KRYPTOS_KEYED) for c in CONTIGUOUS_CRIBS}
