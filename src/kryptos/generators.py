"""Library of candidate keystream/shift generators.

Used by `experiments/006_shift_sequence_analysis.py`. Each generator
returns a length-97 list of integers in [0, 25], to be interpreted as
mod-26 shifts (Vigenere-style, in either standard or KRYPTOS-keyed
index space).

The generator library is a *function-space search* tool: we have 24
known plaintext-to-ciphertext shift values from the K4 cribs and want
to find any closed-form generator that reproduces 5+ consecutive
shifts at the right positions. That's a much smaller search than
"every key of every cipher" and it is wildly under-explored.

Hypothesis priority (highest prior first), per Scheidt/Sanborn design
constraints (simple, memorable, hand-executable):

  1. Vigenere-style keystreams seeded from K1-K3 plaintexts (Sanborn
     would have these memorised; they're the closest things to
     "memorable keywords" in his own work).
  2. Sanborn-personal-text keystreams (his name, sculpture name, etc.).
  3. Famous-constant digit sequences in base 26 -- Sanborn could
     write these out from a textbook by hand.
  4. Small lagged-Fibonacci recurrences mod 26 (Gromark family,
     general form).
  5. Linear congruential mod 26 (classical, parameter-sparse).
  6. Mengenlehreuhr lamp-count keystreams at Sanborn-significant dates.
  7. Weltzeituhr state keystreams (already extensively swept in 003).

We don't try every parameter of every family -- only the ones a human
artist with a primer book would plausibly reach for.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from decimal import Decimal, getcontext

from kryptos import K1_PLAINTEXT, K2_PLAINTEXT, K3_PLAINTEXT, K4


# 100-digit base-10 representations of famous constants. Source: standard
# tables; cross-check against any reference before quoting a hit.
CONSTANTS_BASE10: dict[str, str] = {
    "pi":      "3.1415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679",
    "e":       "2.7182818284590452353602874713526624977572470936999595749669676277240766303535475945713821785251664274",
    "phi":     "1.6180339887498948482045868343656381177203091798057628621354486227052604628189024497072072041893911374",
    "sqrt2":   "1.4142135623730950488016887242096980785696718753769480731766797379907324784621070388503875343276415727",
    "sqrt3":   "1.7320508075688772935274463415058723669428052538103806280558069794519330169088000370811461867572485756",
    "sqrt5":   "2.2360679774997896964091736687747626778106827502531921889470325046678438595556055720902378130497249912",
    "ln2":     "0.6931471805599453094172321214581765680755001343602552541206800094933936219696947156058633269964186875",
    "ln10":    "2.3025850929940456840179914546843642076011014886287729760333279009675726096773524802359972050895982983",
    "catalan": "0.9159655941772190150546035149323841107741493742816721342664981196217630197762547694793565129261151062",
    "apery":   "1.2020569031595942853997381615114499907649862923404988817922715553418382057863130901864558736093352581",
    "gamma":   "0.5772156649015328606065120900824024310421593359399235988057672348848677267776646709369470632917467495",
}


def constant_in_base(name: str, base: int, n_digits: int) -> list[int]:
    """First n_digits of the FRACTIONAL part of `name` in `base`.

    E.g. constant_in_base("pi", 26, 97) gives the first 97 base-26 digits
    of pi after the decimal point.
    """
    if name not in CONSTANTS_BASE10:
        raise ValueError(f"unknown constant {name!r}")
    s = CONSTANTS_BASE10[name]
    getcontext().prec = len(s) + n_digits + 10
    d = Decimal(s)
    frac = d - int(d)
    out: list[int] = []
    for _ in range(n_digits):
        frac *= base
        digit = int(frac)
        out.append(digit)
        frac -= digit
    return out


# ----------------------------- Generators ---------------------------------


def constant_keystream(name: str, base: int = 26, offset: int = 0, length: int = 97,
                        stride: int = 1) -> list[int]:
    """Read the fractional digits of `name` in `base`, starting at `offset`,
    sampled with `stride` (every k-th digit)."""
    needed = length * stride + offset + 5
    digits = constant_in_base(name, base, needed)
    return [digits[offset + i * stride] for i in range(length)]


def linear_congruential(seed: int, a: int, c: int, m: int = 26, length: int = 97) -> list[int]:
    """x_{n+1} = (a*x_n + c) mod m. Outputs are x_0, x_1, ..., x_{length-1}."""
    out = []
    x = seed % m
    for _ in range(length):
        out.append(x)
        x = (a * x + c) % m
    return out


def fibonacci_mod(seed_a: int, seed_b: int, m: int = 26, length: int = 97) -> list[int]:
    """x_0 = seed_a, x_1 = seed_b, x_n = (x_{n-1} + x_{n-2}) mod m."""
    out = [seed_a % m, seed_b % m]
    for _ in range(length - 2):
        out.append((out[-1] + out[-2]) % m)
    return out[:length]


def lagged_fibonacci_mod(primer: list[int], lag: int, m: int = 26, length: int = 97) -> list[int]:
    """x_n = (x_{n-1} + x_{n-lag}) mod m."""
    if lag < 2 or len(primer) < lag:
        raise ValueError("primer must have at least `lag` elements")
    out = [p % m for p in primer[:lag]]
    while len(out) < length:
        out.append((out[-1] + out[-lag]) % m)
    return out[:length]


def text_as_shifts(text: str, length: int = 97, offset: int = 0,
                   alphabet: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ") -> list[int]:
    """Each letter of `text` -> its position in `alphabet`. Wraps if short."""
    clean = "".join(c for c in text.upper() if c.isalpha())
    out: list[int] = []
    for i in range(length):
        j = (offset + i) % len(clean)
        ch = clean[j]
        out.append(alphabet.index(ch) if ch in alphabet else 0)
    return out


def mengenlehreuhr_keystream(
    anchor_local: dt.datetime,
    interval: dt.timedelta,
    length: int = 97,
    flavor: str = "lamp_count",
) -> list[int]:
    """Mengenlehreuhr lamp-state at `anchor + i*interval`, mod 26.

    flavor:
      - "lamp_count": total lit fields (0..23) mod 26
      - "packed_mod": packed integer (0..2999) mod 26
    """
    from kryptos.physical.mengenlehreuhr import state_at
    out = []
    t = anchor_local
    for _ in range(length):
        s = state_at(t)
        if flavor == "lamp_count":
            out.append(s.total_fields_lit % 26)
        elif flavor == "packed_mod":
            out.append(s.packed % 26)
        else:
            raise ValueError(f"unknown flavor {flavor!r}")
        t = t + interval
    return out


def k4_self_keystream(offset: int = 0, length: int = 97) -> list[int]:
    """K4 ciphertext letters as shifts (read with `offset`)."""
    return text_as_shifts(K4, length, offset)


# ------------------------------- Enumerators -------------------------------


def iter_constant_keystreams(length: int = 97) -> Iterator[tuple[str, list[int]]]:
    """All hardcoded constants × {base 10, 26} × small offsets × strides 1-3."""
    for name in CONSTANTS_BASE10:
        for base in (10, 26):
            for stride in (1, 2, 3):
                for offset in range(0, 30):
                    label = f"const:{name}_base{base}_off{offset}_str{stride}"
                    try:
                        yield label, constant_keystream(name, base, offset, length, stride)
                    except Exception:
                        continue


def iter_sanborn_numeric_keystreams(length: int = 97) -> Iterator[tuple[str, list[int]]]:
    """Number sequences from Sanborn-specific contexts: GPS coordinates
    in K2, dates of historical events, K2's omitted-letter position, etc.
    Each is treated as a numeric string sampled at a few strides.
    """
    sources: list[tuple[str, str]] = [
        # K2 plaintext coordinates: 38 deg 57' 6.5" N, 77 deg 8' 44" W
        # (writes as 38576577084 with the .5 dropped, or as 3857650770844)
        ("K2_coords_a",   "38576577084"),
        ("K2_coords_b",   "385765077084"),
        ("K2_coords_dms", "3857650770844"),
        # Dates as YYYYMMDD
        ("date_wall",     "19891109"),
        ("date_dedication", "19901103"),
        ("date_kryptos_commission", "19881101"),
        ("date_mlhr_install", "19750617"),
        ("date_sanborn_birth", "19451114"),
        # Date + time
        ("dt_wall_2330",   "198911092330"),
        # K2 cipher omitted-letter position; K3 row/col counts
        ("k2_omitted",     "338"),     # roughly where the missing X is in K2
        ("k3_grid",        "7484248"),  # 7 cols x 48 rows, 4 then 8 etc
        # Pi / e to 100+ digits in base 10 (also tried in iter_constant)
        # Phone-pad like sequences (Sanborn is American, used to a Latin keypad)
    ]
    for label, digits_str in sources:
        digits = [int(d) for d in digits_str if d.isdigit()]
        if not digits:
            continue
        for stride in (1, 2):
            # Tile the digit sequence across the 97 positions.
            for offset in range(min(len(digits), 5)):
                seq = []
                for i in range(length):
                    idx = (offset + i * stride) % len(digits)
                    seq.append(digits[idx])
                yield f"num:{label}_off{offset}_str{stride}", seq


def iter_lcg_keystreams(length: int = 97) -> Iterator[tuple[str, list[int]]]:
    """Linear congruential sweep over (a in 1-25, c in 0-25, seed in 0-25, m in 26..29)."""
    for m in (26,):              # restrict to mod 26 for the v1 sweep
        for a in range(1, 26):
            for c in range(0, 26):
                for seed in range(0, 26):
                    label = f"lcg:m{m}_a{a}_c{c}_s{seed}"
                    yield label, linear_congruential(seed, a, c, m, length)


def iter_fibonacci_keystreams(length: int = 97) -> Iterator[tuple[str, list[int]]]:
    """All 26*26 = 676 Fibonacci seed pairs mod 26, plus a few lag>2 variants."""
    for sa in range(26):
        for sb in range(26):
            yield f"fib:a{sa}_b{sb}", fibonacci_mod(sa, sb, 26, length)


def iter_lagged_fibonacci_keystreams(length: int = 97) -> Iterator[tuple[str, list[int]]]:
    """Small lagged-Fibonacci primers with lag 3-6, primer drawn from
    a few interesting seed sets."""
    seeds_pool = [
        [0, 1, 1, 2, 3, 5],          # natural Fib seed
        [1, 0, 1, 0, 1, 0],
        [11, 18, 24, 15, 19, 14],    # KRYPTOS letters as indices in keyed alphabet
        [3, 24, 0, 7, 17],           # DYAHR letters as A-Z indices
    ]
    for primer in seeds_pool:
        for lag in (2, 3, 4, 5):
            if len(primer) >= lag:
                label = f"lag-fib:primer{primer[:lag]}_lag{lag}"
                yield label, lagged_fibonacci_mod(primer, lag, 26, length)


def iter_text_keystreams(length: int = 97) -> Iterator[tuple[str, list[int]]]:
    """K1, K2, K3 plaintexts (and K4 ciphertext) as Vigenere keys at
    various starting offsets."""
    sources = [
        ("K1pt", K1_PLAINTEXT),
        ("K2pt", K2_PLAINTEXT),
        ("K3pt", K3_PLAINTEXT),
        ("K4ct", K4),
        ("KRYPTOS", "KRYPTOS"),
        ("DYAHR", "DYAHR"),
        ("PALIMPSEST", "PALIMPSEST"),
        ("ABSCISSA", "ABSCISSA"),
        ("BERLINCLOCK", "BERLINCLOCK"),
        ("BERLINUHR", "BERLINUHR"),
        ("WELTZEITUHR", "WELTZEITUHR"),
        ("JAMESSANBORN", "JAMESSANBORN"),
        ("EDWARDSCHEIDT", "EDWARDSCHEIDT"),
        ("SANBORN", "SANBORN"),
        ("LANGLEY", "LANGLEY"),
        ("IQLUSION", "IQLUSION"),
        ("UNDERGRUUND", "UNDERGRUUND"),
        ("KRYPTOSABCDEFGHIJLMNQUVWXZ", "KRYPTOSABCDEFGHIJLMNQUVWXZ"),
    ]
    KRYPTOS_KEYED = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    for label, text in sources:
        clean = "".join(c for c in text.upper() if c.isalpha())
        max_off = max(1, len(clean)) if len(clean) <= 50 else min(50, len(clean) - 25)
        # Try a small range of offsets, capped so we don't enumerate forever.
        offsets = range(min(max_off, 50))
        for off in offsets:
            yield f"vig-AZ:{label}_off{off}", text_as_shifts(text, length, off)
            yield f"vig-KK:{label}_off{off}", text_as_shifts(text, length, off, KRYPTOS_KEYED)


def iter_mengenlehreuhr_keystreams(length: int = 97) -> Iterator[tuple[str, list[int]]]:
    """Mengenlehreuhr lamp state at every hour of every Sanborn-
    significant date, with two flavors and a few intervals."""
    significant_dates = [
        ("wall_falls",       dt.datetime(1989, 11, 9)),
        ("dedication",       dt.datetime(1990, 11, 3)),
        ("mlhr_installed",   dt.datetime(1975, 6, 17)),
        ("sanborn_birthday", dt.datetime(1988, 11, 14)),
        ("egypt_trip",       dt.datetime(1986, 10, 15)),
        ("kryptos_commissioned", dt.datetime(1988, 11, 1)),
    ]
    intervals = [
        ("1min", dt.timedelta(minutes=1)),
        ("5min", dt.timedelta(minutes=5)),
        ("1hr",  dt.timedelta(hours=1)),
    ]
    for date_label, base_date in significant_dates:
        for hour in (0, 6, 12, 18, 23):
            anchor = base_date.replace(hour=hour, minute=0)
            for int_label, interval in intervals:
                for flavor in ("lamp_count", "packed_mod"):
                    label = f"mlhr:{date_label}_{hour:02d}h_{int_label}_{flavor}"
                    yield label, mengenlehreuhr_keystream(anchor, interval, length, flavor)
