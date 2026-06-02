# A systematic Weltzeituhr-keystream negative result for Kryptos K4

**Summary.** Across 85,680 Weltzeituhr keystream configurations covering
five mapping hypotheses, twenty-four zodiac-ring initial phases, seven
historical seed anchors, five character intervals, both standard A-Z
and KRYPTOS-keyed alphabets, and the per-generator parameter grids
documented below, **no configuration produces a K4 candidate satisfying
the four published cribs** (EAST at 22-25, NORTHEAST at 26-34, BERLIN
at 64-69, CLOCK at 70-74). This is strong evidence that the "Berlin
Clock" referenced in K4 is thematic (a noun in the plaintext) rather
than cryptographic (a keystream source).

## Why this matters

From 2014 until November 2025 the Kryptos community attacked the
*wrong* clock. The Mengenlehreuhr ("Set Theory Clock") was the assumed
referent of K4's "Berlin Clock" until Sanborn's 12 November 2025 talk
at the International Spy Museum, where he clarified that K4 refers to
the **Weltzeituhr (Urania World Clock) at Alexanderplatz**. Roughly
fifteen years of Mengenlehreuhr-derived keystream analysis was aimed
at the wrong device.

This report is the first systematic crib-constrained sweep against the
correct clock. Its purpose is not to claim K4 is solved — it isn't —
but to close the door on the most obvious Weltzeituhr-keystream
attacks so the field's attention can move elsewhere.

## What was tested

### Five mapping hypotheses

Each hypothesis is implemented in `src/kryptos/physical/keystream.py`
as a `KeystreamGenerator` subclass. At each of the 97 ciphertext
positions, the clock state is computed at `anchor + i * interval` and
a single shift in [0, 25] is derived from that state. The shift is
then subtracted (mod 26) from K4's ciphertext letter index.

| Generator | Per-position shift |
|-----------|--------------------|
| `ActiveZoneOffset`    | Active column index (0-23), with `reference_local_hour` ∈ {0, 1, 12} and `mapping` ∈ {direct, scaled, reverse} |
| `ZoneNameLetter`      | k-th letter of the active zone's city name, with `letter_offset` ∈ {0, 1, 2}, `reference_local_hour` ∈ {0, 1, 12}, `alphabet_name` ∈ {standard, kryptos_keyed} |
| `ZodiacAngle`         | Linear mapping of zodiac ring angle, or zodiac sign index above a chosen column; `flavor` ∈ {linear, sign_index×4 columns} |
| `ZoneZodiacAutokey`   | `ActiveZoneOffset` shift + integer multiple of `ZodiacAngle.linear` shift; `zodiac_weight` ∈ {1, 2, -1}, `reference_local_hour` ∈ {0, 1, 12} |
| `PlanetaryKeystream`  | Sum of selected planet heliocentric angles mod 26; 5 planet subsets × {scaled, modulo} mapping |

### Seven historical anchors

| Anchor | UTC moment | Significance |
|--------|------------|--------------|
| `wall_falls`           | 1989-11-09 22:00 | Fall of the Berlin Wall, round 23:00 CET |
| `wall_falls_exact`     | 1989-11-09 22:30 | 23:30 CET, Bornholmer Strasse checkpoint opens |
| `dedication`           | 1990-11-03 17:00 | Sculpture dedicated at Langley, noon EST |
| `egypt_trip`           | 1986-10-15 00:00 | Sanborn's second Egypt trip (date approximate) |
| `sanborn_birthday`     | 1988-11-14 12:00 | Sanborn's 43rd birthday |
| `clock_installed`      | 1969-06-17 11:00 | Weltzeituhr first operates, noon CET |
| `k4_first_publication` | 1990-11-03 17:00 | Same as dedication |

### Five character intervals

| Interval | Rationale |
|----------|-----------|
| 1 minute  | Natural "real-time clock" assumption |
| 15 minutes | Aligns with the 24-hour rotation × 4 per hour |
| 1 hour    | Aligns with the 24-zone period |
| 1 day     | Aligns with the zodiac ring's daily rotation |
| 1 week    | Aligns with calendar repetition |

### Twenty-four zodiac ring initial phases

The Weltzeituhr's as-built ring orientation is not crisply documented
and Sanborn could have keyed against any starting angle. We swept the
ring's epoch angle in 15° steps from 0° to 345°, covering every column
the ring could occupy at the chosen `zodiac_epoch`
(1969-06-17 11:00 UTC, the clock's first operation).

### Two alphabets

Cipher decryption was performed in:
- standard A-Z (`alphabets.STANDARD`)
- KRYPTOS-keyed A-Z (`alphabets.KRYPTOS_KEYED` = `KRYPTOSABCDEFGHIJLMNQUVWXZ`)

## Combinatorics

```
                                generators   ×  per-gen params  ×  anchors  ×  intervals  ×  zodiac angles
ActiveZoneOffset             :       1       ×       9          ×    7      ×      5      ×      24      =  7,560
ZoneNameLetter (widened)     :       1       ×      18          ×    7      ×      5      ×      24      = 15,120
ZodiacAngle                  :       1       ×       5          ×    7      ×      5      ×      24      =  4,200
ZoneZodiacAutokey            :       1       ×       9          ×    7      ×      5      ×      24      =  7,560
PlanetaryKeystream           :       1       ×      10          ×    7      ×      5      ×      24      =  8,400
-------------------------------------------------------------------------------------------------------------
per-alphabet total                                                                                      = 42,840
two alphabets                                                                                          x 2
-------------------------------------------------------------------------------------------------------------
grand total                                                                                            = 85,680
```

## Result

```
swept:               85,680   (42,840 per alphabet)
crib-survivors:           0
fitness-survivors:        0   (would have required crib-OK AND chi-squared < T99 = 95.0)
```

Full per-configuration JSONL logs are emitted to
`experiments/results/{date}_003_weltzeituhr_keystream.jsonl`.

## Reproducibility

```bash
uv sync
uv run python experiments/003_weltzeituhr_keystream.py                      # standard A-Z
uv run python experiments/003_weltzeituhr_keystream.py --alphabet kryptos   # KRYPTOS-keyed
```

Each run is fully deterministic (no RNG; the keystream generators are
functions of the swept parameters). Wall-clock runtime is a few seconds
in pure Python on a 2022 MacBook Pro.

The code that produced this result is on the `main` branch of the repo;
no external dependencies beyond numpy and PyYAML.

## What this does not show

This sweep does **not** rule out:

- Weltzeituhr-derived keystreams that depend on parameters outside the
  enumerated grid (e.g. character intervals that are functions of
  position rather than constants, anchors at moments not on the
  historical list, planetary subsets we did not try).
- Composite ciphers where the Weltzeituhr supplies one component of a
  multi-layer construction (e.g. a final Caesar shift from the clock
  layered onto a Quagmire III ciphertext).
- Weltzeituhr as a *thematic* element of the plaintext (which it almost
  certainly is, per Sanborn's own framing).

It does rule out the natural class of "the clock's state at time T,
sampled every Δt, mod 26, is the Vigenère key" attacks.

## Recommendation

The strongest reading remaining: K4 is a Quagmire-or-Gromark-family
cipher with the modifier(s) Sanborn added per his 2005 Wired interview,
with "Berlin Clock" as a *noun in the plaintext* (parallel to "EAST"
and "NORTHEAST" being directions in the plaintext, not cipher parameters).
Scheidt's design constraint — "simple, can be remembered, executed
years later when used with the correct keyword/s" (2011 Kryptos
Dinner) — is fundamentally incompatible with a physical-clock keystream
that requires the solver to know an anchor time, an increment, a zodiac
phase, and a city-letter offset. The Scheidt prior on physical-clock
keystreams was low before this sweep; the negative result raises that
prior's confidence without changing its direction.

The next experiments in this repo's queue (002 expanded with Vimark
base-26 / autokey / KRYPTOS-alphabet variants; 005 Hill 2×2/3×3 brute
force) target that remaining hypothesis space.

## Citation

If you build on this result, please cite the specific commit; the
configuration grid above is reproducible from
`src/kryptos/physical/keystream.py::SweepConfig` at that commit.
