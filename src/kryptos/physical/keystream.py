"""Keystream generators that turn Weltzeituhr state into a length-N
sequence of mod-26 shifts.

Five hypotheses, per the Week-3 brief. Each is a small, parameterised
KeystreamGenerator subclass with a `keystream(length, ...)` method
returning a list of ints in [0, 25]. The shifts are intended to be used
as Vigenere-style decryption keys:

    plaintext_i = alphabet.at(alphabet.index(ciphertext_i) - shift_i)

Each generator's `params_grid()` classmethod returns an iterable of
hyperparameter dictionaries -- this is what experiment 003 sweeps over.

Hypotheses (Sanborn 2025-11 + community speculation):

  1. ActiveZoneOffset:  shift_i = active-column-index at time_i, mod 26.
  2. ZoneNameLetter:    shift_i = k-th letter of active zone city name.
  3. ZodiacAngle:       shift_i = (zodiac angle / 360 * 26) mod 26.
  4. ZoneZodiacAutokey: ZoneOffset Vigenere + ZodiacAngle perturbation.
  5. PlanetaryKeystream: sum of planet angles -> shift; aperiodic over
     short scales (LCM of orbital periods is huge), which fits K4's
     observed shift pattern.

Search policy: pick a SEED TIME (when the clock state corresponds to
position 0 of K4) and a CHARACTER INTERVAL (how much time elapses
between positions). Sweep both.

Seed-time candidates by historical anchor:
  - 1989-11-09 23:00 Berlin time (Wall opens) -- Sanborn's stated theme
  - 1990-11-03 12:00 Berlin time (sculpture dedication)
  - 1986-10-15 00:00 UTC (Sanborn's second Egypt trip, approx)
  - 1988-11-14 12:00 UTC (Sanborn's birthday)

Character-interval candidates:
  - 1 minute  (typical clock-keystream assumption)
  - 1 hour    (alignment with the 24-zone period)
  - 15 minutes
  - 1 day     (1 hour * 24)
  - the irregular intervals between historical anchors
"""

from __future__ import annotations

import datetime as dt
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field

from kryptos.physical.weltzeituhr import (
    Planet,
    Zone,
    ZodiacSign,
    clock_state,
)


# Historical anchor times that the literature treats as plausibly relevant.
ANCHORS: dict[str, dt.datetime] = {
    "wall_falls":        dt.datetime(1989, 11, 9, 22, 0, tzinfo=dt.timezone.utc),   # 23:00 CET (round)
    "wall_falls_exact":  dt.datetime(1989, 11, 9, 22, 30, tzinfo=dt.timezone.utc),  # 23:30 CET, Bornholmer Strasse opens
    "dedication":        dt.datetime(1990, 11, 3, 17, 0, tzinfo=dt.timezone.utc),   # noon EST
    "egypt_trip":        dt.datetime(1986, 10, 15, 0, 0, tzinfo=dt.timezone.utc),
    "sanborn_birthday":  dt.datetime(1988, 11, 14, 12, 0, tzinfo=dt.timezone.utc),
    "clock_installed":   dt.datetime(1969, 6, 17, 11, 0, tzinfo=dt.timezone.utc),
    "k4_first_publication": dt.datetime(1990, 11, 3, 17, 0, tzinfo=dt.timezone.utc),
}

# Zodiac ring epoch-angle sweep: the ring's absolute phase at the
# zodiac_epoch is a free parameter (the as-built phase isn't crisply
# documented and Sanborn could have keyed against any starting angle).
# 24 values in 15-degree steps cover the full circle at 1-hour rotation
# resolution -- finer than that adds no new equivalence classes.
ZODIAC_EPOCH_ANGLES_DEG: list[float] = [15.0 * i for i in range(24)]


INTERVALS: dict[str, dt.timedelta] = {
    "1min":   dt.timedelta(minutes=1),
    "15min":  dt.timedelta(minutes=15),
    "1hour":  dt.timedelta(hours=1),
    "1day":   dt.timedelta(days=1),
    "1week":  dt.timedelta(days=7),
}


class KeystreamGenerator(ABC):
    """Abstract base. Subclasses implement `_shift_at(state, params)`."""

    name: str = ""  # overridden by subclasses

    @abstractmethod
    def _shift_at(
        self, state, params: dict
    ) -> int:
        """Compute the shift (0-25) for a single character position
        given the clock state at that position."""

    def keystream(
        self,
        length: int,
        seed_time: dt.datetime,
        interval: dt.timedelta,
        zodiac_epoch_angle_deg: float = 0.0,
        **params,
    ) -> list[int]:
        out: list[int] = []
        t = seed_time
        for _ in range(length):
            state = clock_state(t, zodiac_epoch_angle_deg=zodiac_epoch_angle_deg)
            out.append(self._shift_at(state, params) % 26)
            t = t + interval
        return out

    @classmethod
    @abstractmethod
    def params_grid(cls) -> Iterable[dict]:
        """Reasonable hyperparameter combos to sweep. Should be a
        modest list (10s of entries), not a combinatorial explosion;
        the (seed_time, interval) sweep is layered on top."""


class ActiveZoneOffset(KeystreamGenerator):
    """At each position, the active column index becomes the shift.

    `reference_local_hour` selects which zone is "active":
      - 0:  zone whose local hour equals the current UTC hour (Greenwich)
      - 1:  zone whose local hour is UTC+1 (Berlin)
      - 12: zone whose local hour is UTC+12 (international date line)

    `mapping` controls how the 0-23 column index maps to a 0-25 shift:
      - "direct":     shift = column_index (0-23; 24, 25 unused)
      - "scaled":     shift = round(column_index * 26 / 24)
      - "reverse":    shift = 23 - column_index
    """

    name = "active_zone_offset"

    def _shift_at(self, state, params):
        zone = state.active_zone(reference_local_hour=params.get("reference_local_hour", 0))
        col = zone.column_index
        mapping = params.get("mapping", "direct")
        if mapping == "direct":
            return col
        elif mapping == "scaled":
            return round(col * 26 / 24)
        elif mapping == "reverse":
            return 23 - col
        raise ValueError(f"unknown mapping {mapping!r}")

    @classmethod
    def params_grid(cls):
        for ref in (0, 1, 12):
            for mapping in ("direct", "scaled", "reverse"):
                yield {"reference_local_hour": ref, "mapping": mapping}


_ALPHABET_LOOKUP: dict[str, str] = {
    "standard":      "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "kryptos_keyed": "KRYPTOSABCDEFGHIJLMNQUVWXZ",
}


class ZoneNameLetter(KeystreamGenerator):
    """At each position, extract the k-th letter of the active zone city
    name as a Vigenere key letter. Shift = (letter_index in alphabet).

    `letter_offset` selects k (0-based; wraps if city name shorter).
    `reference_local_hour` as in ActiveZoneOffset.
    `alphabet_name` controls which alphabet the city letter is indexed in:
       - "standard":      shift = letter_index in A-Z (0-25)
       - "kryptos_keyed": shift = letter_index in KRYPTOSABCDEFGHIJLMNQUVWXZ
    """

    name = "zone_name_letter"

    def _shift_at(self, state, params):
        zone = state.active_zone(reference_local_hour=params.get("reference_local_hour", 0))
        city = "".join(c for c in zone.city.upper() if c.isalpha())
        if not city:
            return 0
        letter = city[params.get("letter_offset", 0) % len(city)]
        alpha = _ALPHABET_LOOKUP[params.get("alphabet_name", "standard")]
        return alpha.index(letter) if letter in alpha else 0

    @classmethod
    def params_grid(cls):
        for ref in (0, 1, 12):
            for k in (0, 1, 2):
                for alpha in ("standard", "kryptos_keyed"):
                    yield {"reference_local_hour": ref, "letter_offset": k,
                           "alphabet_name": alpha}


class ZodiacAngle(KeystreamGenerator):
    """At each position, the zodiac ring's rotation angle determines the
    shift. Two flavors:

      - "linear":     shift = floor(angle / 360 * 26) mod 26
      - "sign_index": shift = zodiac sign index above column at `reference_local_hour`
                      (0 = Aries .. 11 = Pisces; only 12 distinct shifts)
    """

    name = "zodiac_angle"

    def _shift_at(self, state, params):
        flavor = params.get("flavor", "linear")
        if flavor == "linear":
            return int(state.zodiac_ring_angle_deg / 360.0 * 26) % 26
        elif flavor == "sign_index":
            col = params.get("reference_local_hour", 0) % 24
            sign = state.zodiac_above[col]
            return list(ZodiacSign).index(sign)
        raise ValueError(f"unknown flavor {flavor!r}")

    @classmethod
    def params_grid(cls):
        yield {"flavor": "linear"}
        for col in (0, 1, 12, 13):
            yield {"flavor": "sign_index", "reference_local_hour": col}


class ZoneZodiacAutokey(KeystreamGenerator):
    """Compound: ActiveZoneOffset as the base Vigenere shift, then
    perturbed by the ZodiacAngle linear shift. The "masking" hypothesis
    applied physically: a periodic-looking 24-element zone signal
    masked by a slowly-varying zodiac modulation.
    """

    name = "zone_zodiac_autokey"

    def _shift_at(self, state, params):
        zone = state.active_zone(reference_local_hour=params.get("reference_local_hour", 0))
        zone_shift = zone.column_index
        zodiac_shift = int(state.zodiac_ring_angle_deg / 360.0 * 26)
        weight = params.get("zodiac_weight", 1)   # integer multiplier
        return (zone_shift + weight * zodiac_shift) % 26

    @classmethod
    def params_grid(cls):
        for ref in (0, 1, 12):
            for w in (1, 2, -1):
                yield {"reference_local_hour": ref, "zodiac_weight": w}


class PlanetaryKeystream(KeystreamGenerator):
    """Sum of selected planet heliocentric angles, mapped to mod 26.

    Aperiodic over short scales because LCM(orbital periods) is large.
    Fits K4's observed shift pattern in the sense that no short-period
    Vigenere works.

    `planets`: iterable of Planet enum values to include in the sum.
    `mapping`: how to convert a 0-360 angle to a 0-25 shift.
    """

    name = "planetary_keystream"

    def _shift_at(self, state, params):
        plist = params.get("planets") or (Planet.MERCURY, Planet.VENUS, Planet.EARTH)
        total = sum(state.planets[p] for p in plist)
        mapping = params.get("mapping", "scaled")
        if mapping == "scaled":
            return int(total / 360.0 * 26) % 26
        elif mapping == "modulo":
            return int(total) % 26
        raise ValueError(f"unknown mapping {mapping!r}")

    @classmethod
    def params_grid(cls):
        # A few interesting planet combinations.
        for plist in (
            (Planet.MERCURY,),
            (Planet.MERCURY, Planet.VENUS),
            (Planet.MERCURY, Planet.VENUS, Planet.EARTH),
            (Planet.EARTH, Planet.MARS),
            (Planet.MERCURY, Planet.VENUS, Planet.EARTH, Planet.MARS),
        ):
            for mapping in ("scaled", "modulo"):
                yield {"planets": plist, "mapping": mapping}


GENERATORS: list[type[KeystreamGenerator]] = [
    ActiveZoneOffset,
    ZoneNameLetter,
    ZodiacAngle,
    ZoneZodiacAutokey,
    PlanetaryKeystream,
]


@dataclass
class SweepConfig:
    """Configuration for one keystream sweep run."""

    seed_times: dict[str, dt.datetime] = field(default_factory=lambda: ANCHORS)
    intervals: dict[str, dt.timedelta] = field(default_factory=lambda: INTERVALS)
    generators: list[type[KeystreamGenerator]] = field(default_factory=lambda: list(GENERATORS))
    zodiac_epoch_angles_deg: list[float] = field(default_factory=lambda: [0.0])

    def total_combinations(self, length: int = 97) -> int:
        n = 0
        for g in self.generators:
            n += (
                len(list(g.params_grid()))
                * len(self.seed_times)
                * len(self.intervals)
                * len(self.zodiac_epoch_angles_deg)
            )
        return n


def iter_keystreams(
    config: SweepConfig | None = None,
    length: int = 97,
) -> Iterable[tuple[str, str, str, float, dict, list[int]]]:
    """Generator of (generator_name, anchor_name, interval_name,
    zodiac_epoch_angle_deg, params, keystream).

    Use this to drive the sweep in experiment 003; it returns every
    (generator, anchor, interval, zodiac_epoch, params) combination and
    yields the materialised keystream.
    """
    cfg = config or SweepConfig()
    for gen_cls in cfg.generators:
        gen = gen_cls()
        for params in gen_cls.params_grid():
            for anchor_name, anchor_time in cfg.seed_times.items():
                for interval_name, interval in cfg.intervals.items():
                    for zea in cfg.zodiac_epoch_angles_deg:
                        ks = gen.keystream(
                            length, anchor_time, interval,
                            zodiac_epoch_angle_deg=zea, **params,
                        )
                        yield (gen.name, anchor_name, interval_name, zea, params, ks)
