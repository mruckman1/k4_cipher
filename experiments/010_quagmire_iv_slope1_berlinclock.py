"""Quagmire IV with slope-1 keystream over BERLINCLOCK.

The slope-1 finding from experiment 009: in three of four candidate
alphabets, the K4 shift sequence at BERLINCLOCK positions 68-71 forms
a locally-arithmetic sub-sequence. A position-indexed keystream that
produces those four shifts directly didn't surface in 006 or 009's
generator library, even with mod-27 arithmetic. But Quagmire IV
mediates a slope-1 keystream through TWO different keyed alphabets,
so a slope-1 KEYSTREAM does NOT in general produce a slope-1 SHIFT
sequence -- the shift you observe at each position depends on the
plaintext letter's index in one alphabet and the cipher letter's
index in another.

Hypothesis: K4 is Quagmire IV with some (plain_alphabet,
cipher_alphabet) pair and a keystream that is exactly
[k, k+1, k+2, ..., k+10] mod M at the BERLINCLOCK window (positions
64..74). Search:

  - For each candidate M in {26, 27}
  - For each starting keystream value k in 0..M-1
  - For each (plain_alphabet, cipher_alphabet) pair
  - Encrypt BERLINCLOCK plaintext "BERLINCLOCK" with the QuagmireIV
    construction using key = the M-character slope-1 sequence
    starting at k (each character is the letter at index k+i in the
    cipher alphabet)
  - Check whether the result equals K4[63:74] = "NYPVTTMZFPK" byte-for-byte

A full 11/11 match is the cipher hypothesis. A partial match (>= 6 of 11)
is worth reporting; under uniform random the expected count of partial-6+
matches across this search is ~0.001, so any such hit is meaningful.

Candidate alphabets (~28 distinct):
  - standard A-Z
  - KRYPTOS_KEYED (26, K1/K2 alphabet)
  - KRYPTOS_WITH_EXTRA_L (27, doubled L)
  - KRYPTOS_TRAILING_L (27, L appended)
  - KRYPTOS_K_RESTORED (27, K appears twice)
  - their reverses
  - alphabets keyed by Sanborn-related words: BERLIN, CLOCK, BERLINCLOCK,
    WELTZEITUHR, PALIMPSEST, ABSCISSA, DYAHR, IQLUSION, UNDERGRUUND,
    SANBORN, JAMESSANBORN, EDWARDSCHEIDT, LANGLEY, KRYPTOSL

Run:
    uv run python experiments/010_quagmire_iv_slope1_berlinclock.py
"""

from __future__ import annotations

import argparse
import sys
import time

from kryptos import K4
from kryptos.alphabets import (
    KRYPTOS_K_RESTORED,
    KRYPTOS_KEYED,
    KRYPTOS_TRAILING_L,
    KRYPTOS_WITH_EXTRA_L,
    STANDARD,
    Alphabet,
    keyed_alphabet,
)
from kryptos.ciphers.quagmire import QuagmireIV
from kryptos.cribs import BERLINCLOCK
from kryptos.experiment_logger import ExperimentLogger


BERLINCLOCK_PLAINTEXT = "BERLINCLOCK"          # 11 letters
BERLINCLOCK_CIPHERTEXT = K4[63:74]              # "NYPVTTMZFPK"
assert BERLINCLOCK_CIPHERTEXT == "NYPVTTMZFPK"

PARTIAL_THRESHOLD = 3                           # log >= this many positions match (low to surface any signal)
WIN_THRESHOLD = 11                              # all 11 match -> cipher found


def candidate_alphabets() -> list[tuple[str, Alphabet]]:
    """Build the alphabet pool to search."""
    out: list[tuple[str, Alphabet]] = [
        ("standard",           STANDARD),
        ("kryptos_keyed",      KRYPTOS_KEYED),
        ("kryptos_extra_L",    KRYPTOS_WITH_EXTRA_L),
        ("kryptos_trailing_L", KRYPTOS_TRAILING_L),
        ("kryptos_K_restored", KRYPTOS_K_RESTORED),
    ]
    # Reverses of each.
    for name, a in list(out):
        rev = Alphabet(f"{name}_reversed", a.letters[::-1],
                       allow_duplicates=a.allow_duplicates)
        out.append((rev.name, rev))
    # Keyed by interesting Sanborn-context words (26 letters each).
    for kw in ("BERLIN", "CLOCK", "BERLINCLOCK", "WELTZEITUHR",
               "PALIMPSEST", "ABSCISSA", "DYAHR", "IQLUSION",
               "UNDERGRUUND", "SANBORN", "JAMESSANBORN",
               "EDWARDSCHEIDT", "LANGLEY"):
        a = keyed_alphabet(kw, STANDARD)
        out.append((f"keyed_{kw}", a))
    return out


def slope1_keystream_letters(start_k: int, length: int, cipher_alphabet: Alphabet) -> str:
    """Letter-form of the slope-1 keystream (for display/logging only)."""
    m = cipher_alphabet.modulus
    return "".join(cipher_alphabet.at((start_k + i) % m) for i in range(length))


def encrypt_slope1_direct(
    plain_text: str, plain_alpha: Alphabet, cipher_alpha: Alphabet,
    start_k: int, slope: int = 1,
) -> str:
    """Q-IV encrypt with the keystream specified DIRECTLY as integer
    indices (key_idx[i] = (start_k + slope*i) mod M).

    This bypasses the letter <-> index round-trip that would otherwise
    produce wrong results on alphabets with duplicate letters (e.g. the
    27-letter doubled-L variant where the second L is unreachable via
    cipher_alpha.index(letter)). Equivalent to QuagmireIV.encrypt for
    alphabets without duplicates."""
    n = plain_alpha.modulus
    out: list[str] = []
    for i, p in enumerate(plain_text):
        plain_idx = plain_alpha.index(p)
        key_idx = (start_k + slope * i) % n
        cipher_idx = (plain_idx + key_idx) % n
        out.append(cipher_alpha.letters[cipher_idx])
    return "".join(out)


def check_one(plain_alpha: Alphabet, cipher_alpha: Alphabet,
              start_k: int, slope: int = 1) -> int:
    """Return how many of the 11 BERLINCLOCK positions match for this
    (plain_alphabet, cipher_alphabet, start_k, slope) tuple, or -1 if
    the alphabets have mismatched moduli."""
    if plain_alpha.modulus != cipher_alpha.modulus:
        return -1
    try:
        produced = encrypt_slope1_direct(
            BERLINCLOCK_PLAINTEXT, plain_alpha, cipher_alpha, start_k, slope,
        )
    except Exception:
        return -1
    return sum(a == b for a, b in zip(produced, BERLINCLOCK_CIPHERTEXT))


def main() -> int:
    alphabets = candidate_alphabets()
    print(f"alphabets in pool: {len(alphabets)}")
    print(f"target ciphertext (K4[63:74]): {BERLINCLOCK_CIPHERTEXT}")
    print(f"plaintext: {BERLINCLOCK_PLAINTEXT}")
    print()

    n_tried = 0
    n_partial = 0
    n_full = 0
    partial_hits: list[dict] = []
    t0 = time.perf_counter()

    with ExperimentLogger("010_quagmire_iv_slope1_berlinclock") as log:
        log.write({"partial_threshold": PARTIAL_THRESHOLD,
                   "win_threshold": WIN_THRESHOLD,
                   "n_alphabets": len(alphabets)})

        SLOPES = [1, -1, 2, -2, 0]
        for pl_name, pl_alpha in alphabets:
            for ci_name, ci_alpha in alphabets:
                if pl_alpha.modulus != ci_alpha.modulus:
                    continue
                m = pl_alpha.modulus
                for slope in SLOPES:
                    for k in range(m):
                        matches = check_one(pl_alpha, ci_alpha, k, slope)
                        if matches < 0:
                            continue
                        n_tried += 1
                        if matches >= PARTIAL_THRESHOLD:
                            rec = {
                                "plain_alphabet":  pl_name,
                                "cipher_alphabet": ci_name,
                                "modulus":         m,
                                "start_k":         k,
                                "slope":           slope,
                                "matches":         matches,
                                "out_of":          len(BERLINCLOCK_CIPHERTEXT),
                            }
                            partial_hits.append(rec)
                            log.write(rec)
                            n_partial += 1
                            if matches >= WIN_THRESHOLD:
                                n_full += 1
                                print(f"  FULL MATCH 11/11  pl={pl_name}  ci={ci_name}  "
                                      f"k={k}  slope={slope}")
        log.write({"summary": True, "n_tried": n_tried,
                   "n_partial_6plus": n_partial, "n_full": n_full,
                   "elapsed_s": time.perf_counter() - t0})

    dt = time.perf_counter() - t0
    print(f"=== summary ===")
    print(f"  triples tried:       {n_tried:>10,}")
    print(f"  >= {PARTIAL_THRESHOLD}/11 matches:    {n_partial:>10,}")
    print(f"  FULL 11/11 matches:  {n_full:>10,}")
    print(f"  elapsed:             {dt:.2f}s")

    if partial_hits:
        partial_hits.sort(key=lambda r: -r["matches"])
        print(f"\nTop 25 partial hits by match count:")
        for r in partial_hits[:25]:
            print(f"  {r['matches']:2d}/11  slope={r['slope']:+d}  k={r['start_k']:2d}  "
                  f"m={r['modulus']}  pl={r['plain_alphabet']:24s}  ci={r['cipher_alphabet']:24s}")
    else:
        print("\nNo partial hits at threshold. The slope-1-over-BERLINCLOCK + Quagmire IV "
              "hypothesis fails across all enumerated (plain_alphabet, cipher_alphabet) pairs.")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    args = ap.parse_args()
    sys.exit(main())
