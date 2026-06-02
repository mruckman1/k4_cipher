"""Mengenlehreuhr (Set Theory Clock) lamp-state model.

Although Sanborn confirmed on 12 Nov 2025 that K4's "Berlin Clock"
REFERENT is the Weltzeituhr at Alexanderplatz, the cryptographic
generator could in principle still be the Mengenlehreuhr -- nothing in
the public record rules this out. Until tested, we keep both models.

The Mengenlehreuhr displays time in base 5 via four rows of illuminated
fields plus a seconds-blinker:

  - Row 1 (top): 4 fields, each = 5 hours  -> floor(H / 5)         in 0..4
  - Row 2:       4 fields, each = 1 hour   -> H mod 5              in 0..4
  - Row 3:      11 fields, each = 5 mins   -> floor(M / 5)         in 0..11
  - Row 4:       4 fields, each = 1 minute -> M mod 5              in 0..4

Total fields lit = r1 + r2 + r3 + r4, in 0..23. (Notice 24 possible
values -- close to the 26-shift alphabet but not identical.)

The packed integer r1 + 5*r2 + 25*r3 + 125*r4 encodes the full lamp
pattern in 0..2999 (5*5*12*5 = 1500 distinct minute-states across 24h).
Two natural ways to convert to a 0..25 keystream shift:

  - "lamp_count": just the total field count, mod 26
  - "packed_mod": packed integer mod 26
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass


@dataclass(frozen=True)
class MengenState:
    row1: int       # 0..4
    row2: int       # 0..4
    row3: int       # 0..11
    row4: int       # 0..4

    @property
    def total_fields_lit(self) -> int:
        return self.row1 + self.row2 + self.row3 + self.row4

    @property
    def packed(self) -> int:
        return self.row1 + 5 * self.row2 + 25 * self.row3 + 125 * self.row4


def state_at(when: dt.datetime) -> MengenState:
    """Lamp state at the given local-Berlin time (the clock displays
    local Berlin time)."""
    h = when.hour
    m = when.minute
    return MengenState(
        row1=h // 5,
        row2=h % 5,
        row3=m // 5,
        row4=m % 5,
    )


def lamp_count(when: dt.datetime) -> int:
    return state_at(when).total_fields_lit


def packed(when: dt.datetime) -> int:
    return state_at(when).packed
