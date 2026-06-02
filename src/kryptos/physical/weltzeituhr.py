"""Weltzeituhr (Urania World Clock) physical model.

The Weltzeituhr stands at Alexanderplatz, Berlin. Designed by Erich John,
installed 17 June 1969. It is a fixed cylindrical drum displaying 24
time zones around its surface, with a rotating outer ring carrying the
12 zodiac signs, and an orbiting solar-system model on top.

This module returns the clock's complete state at any datetime. A
ClockState exposes:

  - utc_hour:                  the current UTC hour (0-23 float, can be fractional)
  - zones:                     24-entry list of Zone records
                               (city, utc_offset, current local hour)
  - zodiac_ring_angle_deg:     where the rotating zodiac ring is (0-360),
                               measured as the angle of the boundary
                               between the first and last zodiac sign
                               relative to a fixed reference column
                               (UTC=0 / Greenwich) at the front of the drum
  - zodiac_above:              24-entry list mapping each zone column to
                               the zodiac sign currently above it
  - planets:                   dict planet -> heliocentric angle (deg)
                               using sidereal orbital periods

Sources / conventions:

  - Zone table from data/physical/weltzeituhr_zones.csv (24 entries).
  - Zodiac ring assumed to rotate 360 deg per sidereal day (1x per 24h)
    eastward. Reference epoch: the clock was started at noon Berlin time
    (1969-06-17 12:00 CET = 11:00 UTC) with Aries directly above the
    Greenwich/UTC=0 column. This is a defensible default but it IS a
    free parameter -- the physical truth is that the ring's absolute
    phase depends on the original installation alignment which is not
    crisply documented. Override via clock_state(..., zodiac_epoch=...).
  - Planet positions are sidereal heliocentric, treated as uniform
    circular motion from a J2000-style reference epoch. Useful as a
    keystream signal, NOT as an ephemeris. If you want real ephemeris,
    swap in `skyfield`; for keystream search the periodicity is what
    matters.

The module is testable: see `verify_clock_state(...)` for a comparison
against a single photo-derived reference state. Future-you should add
more reference states from independently dated Weltzeituhr photos.
"""

from __future__ import annotations

import csv
import datetime as dt
import math
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

ZONES_CSV = Path(__file__).resolve().parents[3] / "data" / "physical" / "weltzeituhr_zones.csv"


class ZodiacSign(Enum):
    """The 12 zodiac signs in the order they appear on the Weltzeituhr's
    outer ring, starting from Aries and going counterclockwise (when
    viewed from above) in the conventional astronomical order."""

    ARIES       = "Aries"
    TAURUS      = "Taurus"
    GEMINI      = "Gemini"
    CANCER      = "Cancer"
    LEO         = "Leo"
    VIRGO       = "Virgo"
    LIBRA       = "Libra"
    SCORPIO     = "Scorpio"
    SAGITTARIUS = "Sagittarius"
    CAPRICORN   = "Capricorn"
    AQUARIUS    = "Aquarius"
    PISCES      = "Pisces"

    @classmethod
    def at_angle(cls, deg: float) -> "ZodiacSign":
        """Which sign occupies angle `deg` on the ring (0 = Aries start)?"""
        deg = deg % 360.0
        idx = int(deg // 30.0)
        return list(cls)[idx]


@dataclass(frozen=True)
class Zone:
    """One of the 24 time-zone columns on the Weltzeituhr cylinder."""

    column_index: int       # 0..23, position on the drum
    utc_offset: int         # whole hours; Weltzeituhr does not display 30-min zones
    city: str
    zone_marker: str        # short code from the CSV (e.g. "BE" for Berlin)

    def local_hour(self, utc_hour: float) -> float:
        """Local hour in this zone for a given UTC hour. Wraps mod 24."""
        return (utc_hour + self.utc_offset) % 24.0


class Planet(Enum):
    """Orbiting solar-system model planets. Periods in mean tropical days
    (Wikipedia sidereal periods rounded to two decimals)."""

    MERCURY = 87.97
    VENUS   = 224.70
    EARTH   = 365.26
    MARS    = 686.97
    JUPITER = 4332.59
    SATURN  = 10759.22


# Default zodiac phase reference: per the module docstring, Aries above
# the Greenwich (UTC=0) column at 1969-06-17 11:00 UTC. The rotation
# direction follows the eastern advance of the day -- one full revolution
# per 24 hours.
_ZODIAC_EPOCH_DEFAULT = dt.datetime(1969, 6, 17, 11, 0, tzinfo=dt.timezone.utc)
_ZODIAC_EPOCH_ANGLE_AT_UTC0_DEG = 0.0   # Aries at the UTC=0 column at epoch
_ZODIAC_ROTATION_DEG_PER_HOUR = 15.0    # 360 / 24

# Planet phase reference: also at the zodiac epoch, treat each planet's
# heliocentric angle as 0 deg. This is a stipulation, not an ephemeris;
# what matters for keystream search is the relative periodicity.
_PLANET_EPOCH = _ZODIAC_EPOCH_DEFAULT


def load_zones(path: Path | None = None) -> list[Zone]:
    """Load the 24 zone columns from the CSV. Skips comment lines."""
    path = path or ZONES_CSV
    out: list[Zone] = []
    with open(path) as f:
        reader = csv.DictReader(
            line for line in f
            if line.strip() and not line.lstrip().startswith("#")
        )
        for row in reader:
            out.append(Zone(
                column_index=int(row["column"]) - 1,    # CSV is 1-indexed; we use 0-indexed
                utc_offset=int(row["utc_offset"]),
                city=row["city"],
                zone_marker=row["zone_marker"],
            ))
    out.sort(key=lambda z: z.column_index)
    if len(out) != 24:
        raise ValueError(f"expected 24 Weltzeituhr zones, got {len(out)}")
    return out


ZONE_TABLE: list[Zone] = load_zones()


@dataclass(frozen=True)
class ClockState:
    """The Weltzeituhr's state at one instant in time."""

    when: dt.datetime              # always UTC
    utc_hour: float                # 0..24 fractional
    zones: list[Zone]              # length 24
    zodiac_ring_angle_deg: float   # 0..360, angle of the Aries-start mark
    zodiac_above: list[ZodiacSign] # length 24: which sign is above each column
    planets: dict[Planet, float]   # planet -> heliocentric angle deg

    def active_zone(self, reference_local_hour: int = 0) -> Zone:
        """The zone whose local hour right now matches `reference_local_hour`.

        Examples:
          - reference_local_hour=0:  the zone where it is currently local
            midnight. Rotates through all 24 columns once per UTC day.
          - reference_local_hour=12: the zone where it is currently local
            noon.
          - reference_local_hour=23: the zone whose local hour is 23.

        This is the most natural "active column" interpretation: the
        cylinder is fixed, but as UTC advances, the column whose local
        hour equals any specific value rotates through the drum.
        """
        # Need offset s.t. (utc_hour + offset) mod 24 == reference_local_hour.
        # offset = (reference_local_hour - utc_hour) mod 24, but our table
        # uses signed offsets in [-12, +11].
        target_offset = round((reference_local_hour - self.utc_hour) % 24)
        if target_offset > 12:
            target_offset -= 24
        # Find the zone whose utc_offset matches (within 1 hour, since
        # utc_hour can be fractional).
        return min(self.zones, key=lambda z: abs(z.utc_offset - target_offset))


def clock_state(
    when: dt.datetime,
    *,
    zodiac_epoch: dt.datetime = _ZODIAC_EPOCH_DEFAULT,
    zodiac_epoch_angle_deg: float = _ZODIAC_EPOCH_ANGLE_AT_UTC0_DEG,
    zones: list[Zone] | None = None,
) -> ClockState:
    """Return the Weltzeituhr state at the given datetime.

    Args:
        when: a datetime. If naive, treated as UTC; if tz-aware, converted to UTC.
        zodiac_epoch / zodiac_epoch_angle_deg: hyperparameters controlling
            the zodiac ring's absolute phase. The default places Aries at
            the UTC=0 column at the clock's first noon (1969-06-17 11:00 UTC).
        zones: override the zone table (for testing).
    """
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    else:
        when = when.astimezone(dt.timezone.utc)

    utc_hour = when.hour + when.minute / 60.0 + when.second / 3600.0
    zones_ = zones if zones is not None else ZONE_TABLE

    # Zodiac ring rotation: starts at `zodiac_epoch_angle_deg` at
    # `zodiac_epoch`, rotates 15 deg per hour.
    elapsed_hours = (when - zodiac_epoch).total_seconds() / 3600.0
    ring_angle = (zodiac_epoch_angle_deg + elapsed_hours * _ZODIAC_ROTATION_DEG_PER_HOUR) % 360.0

    # Per-column zodiac sign: for column c at UTC offset c (in "drum
    # space", which is just column_index * 15 deg around the cylinder),
    # the sign above it is determined by (ring_angle + column_angle).
    zodiac_above: list[ZodiacSign] = []
    for z in zones_:
        col_angle = z.column_index * 15.0           # 24 cols * 15 = 360
        sign = ZodiacSign.at_angle(ring_angle + col_angle)
        zodiac_above.append(sign)

    # Planet angles: heliocentric, treated as uniform circular motion
    # since the epoch.
    elapsed_days = (when - _PLANET_EPOCH).total_seconds() / 86400.0
    planets = {
        p: (elapsed_days / p.value * 360.0) % 360.0
        for p in Planet
    }

    return ClockState(
        when=when,
        utc_hour=utc_hour,
        zones=zones_,
        zodiac_ring_angle_deg=ring_angle,
        zodiac_above=zodiac_above,
        planets=planets,
    )


def verify_clock_state() -> None:
    """Sanity-check that the model is internally consistent. NOT a
    photo-anchored reference (yet); just smoke-tests so a regression
    becomes visible.

    Add a real reference state once you have a dated Weltzeituhr photo
    you trust: assert clock_state(<photo time>).zodiac_above[<Berlin col>]
    == <sign visible above Berlin in photo>.
    """
    # At the chosen epoch, the zodiac ring is at 0 deg, so Aries is at
    # column 0 (Eniwetok / UTC -12 in our table).
    s = clock_state(_ZODIAC_EPOCH_DEFAULT)
    assert abs(s.zodiac_ring_angle_deg - 0.0) < 1e-9, s.zodiac_ring_angle_deg
    assert s.zodiac_above[0] == ZodiacSign.ARIES, s.zodiac_above[0]

    # 1 hour later, the ring has advanced 15 deg; the angle above col 0
    # is now 15 deg, still inside Aries (0-30 deg).
    s = clock_state(_ZODIAC_EPOCH_DEFAULT + dt.timedelta(hours=1))
    assert abs(s.zodiac_ring_angle_deg - 15.0) < 1e-9, s.zodiac_ring_angle_deg
    assert s.zodiac_above[0] == ZodiacSign.ARIES, s.zodiac_above[0]

    # 2 hours after epoch: ring at 30 deg; above col 0 is now Taurus
    # (30-60 deg).
    s = clock_state(_ZODIAC_EPOCH_DEFAULT + dt.timedelta(hours=2))
    assert s.zodiac_above[0] == ZodiacSign.TAURUS, s.zodiac_above[0]

    # 24 hours later, full rotation, ring back to 0.
    s = clock_state(_ZODIAC_EPOCH_DEFAULT + dt.timedelta(hours=24))
    assert abs(s.zodiac_ring_angle_deg - 0.0) < 1e-6, s.zodiac_ring_angle_deg

    # Planets at epoch: all at 0 deg.
    s = clock_state(_ZODIAC_EPOCH_DEFAULT)
    for p, a in s.planets.items():
        assert abs(a - 0.0) < 1e-9, (p, a)

    # Mercury 88 days later: should be near 360 deg (full revolution).
    s = clock_state(_ZODIAC_EPOCH_DEFAULT + dt.timedelta(days=Planet.MERCURY.value))
    assert abs(s.planets[Planet.MERCURY] - 0.0) < 1e-6 or \
        abs(s.planets[Planet.MERCURY] - 360.0) < 1e-6, s.planets[Planet.MERCURY]


if __name__ == "__main__":
    verify_clock_state()
    print("Weltzeituhr clock state model: internal consistency checks pass.")
    s = clock_state(dt.datetime(1989, 11, 9, 23, 0, tzinfo=dt.timezone.utc))  # Wall falls
    print(f"\n=== 1989-11-09 23:00 UTC (Berlin Wall opens) ===")
    print(f"UTC hour: {s.utc_hour}")
    print(f"Zodiac ring angle: {s.zodiac_ring_angle_deg:.2f} deg")
    print(f"Zodiac above first 4 columns: {[z.name for z in s.zodiac_above[:4]]}")
    print(f"Berlin column (UTC+1) zodiac: {s.zodiac_above[13].name}")
    print(f"Planet angles: {{{', '.join(f'{p.name}:{a:.1f}' for p, a in s.planets.items())}}}")
