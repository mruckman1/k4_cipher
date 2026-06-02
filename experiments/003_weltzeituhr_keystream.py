"""Weltzeituhr keystream sweep on K4.

Phase 2 / Stage 3 experiment. The community attacked the WRONG clock
(Mengenlehreuhr) for 15+ years; Sanborn confirmed in November 2025 that
the Weltzeituhr at Alexanderplatz is the actual referent. This is the
first systematic crib-constrained sweep against the correct clock.

The sweep enumerates every (generator, anchor, interval, params) tuple
defined by `kryptos.physical.SweepConfig`. For each, it:

  1. Builds the 97-character keystream from the clock state evolution
     starting at `anchor` and advancing by `interval` per character.
  2. Decrypts K4 by subtracting the keystream from K4's ciphertext
     letter indices, mod 26 (standard A-Z; the KRYPTOS-keyed variant
     is a small extension).
  3. Logs (gen, anchor, interval, params, crib_ok, fitness, plaintext)
     to JSONL.
  4. Prints any candidate that passes BOTH gates:
       - all four cribs satisfied
       - chi-squared English-ness below the T99 stand-in threshold

Default sweep size: ~1260 combinations (see SweepConfig.total_combinations).
Runtime: a few seconds in pure Python.

Two important caveats baked into the methodology:

  - The cribs are not magic. With four cribs constraining 24 of 97
    positions, you can absolutely get false-positive crib-survivors with
    garbage at the other 73 positions. The chi-squared gate is the
    second filter that distinguishes "looks like real English" from
    "happens to have BERLIN at the right spot". A crib-survivor that
    fails the chi-squared gate is noise.

  - The physical clock as a literal keystream is borderline incompatible
    with Scheidt's "simple, can be remembered, executable years later
    from a keyword" constraint. If a thorough sweep produces zero
    fitness-survivors across all five generators with reasonable
    parameter ranges, that's strong evidence the Weltzeituhr is THEMATIC
    (the plaintext is about the clock), not CRYPTOGRAPHIC (the clock
    keys the cipher). Take the hint.

Usage:
    uv run python experiments/003_weltzeituhr_keystream.py
    uv run python experiments/003_weltzeituhr_keystream.py --alphabet kryptos
"""

from __future__ import annotations

import argparse
import sys

from kryptos import K4
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, Alphabet, keyed_alphabet
from kryptos.cribs import CRIBS
from kryptos.experiment_logger import ExperimentLogger
from kryptos.physical import ZODIAC_EPOCH_ANGLES_DEG, SweepConfig, iter_keystreams
from kryptos.scoring.crib_check import crib_check
from kryptos.scoring.english_classifier import CHI_SQ_T99_RANDOM, chi_squared


def decrypt_with_shifts(ciphertext: str, shifts: list[int], alphabet: Alphabet) -> str:
    """plaintext_i = alphabet[(cipher_index_i - shift_i) mod N]."""
    ai = alphabet.index
    at = alphabet.at
    return "".join(at(ai(c) - s) for c, s in zip(ciphertext, shifts))


def main(
    alphabet_name: str = "standard",
    chi_threshold: float = CHI_SQ_T99_RANDOM,
    widened: bool = True,
) -> int:
    if alphabet_name == "standard":
        alphabet = STANDARD
    elif alphabet_name == "kryptos":
        alphabet = KRYPTOS_KEYED
    else:
        alphabet = keyed_alphabet(alphabet_name)

    # Widened sweep: sweep the zodiac ring's initial phase across all 24
    # 15-degree positions instead of fixing it at the default 0 deg.
    # That's the legitimate hole in the original sweep -- the ring's
    # as-built phase isn't crisply documented and Sanborn could have
    # keyed against any starting angle.
    if widened:
        cfg = SweepConfig(zodiac_epoch_angles_deg=list(ZODIAC_EPOCH_ANGLES_DEG))
    else:
        cfg = SweepConfig()
    total = cfg.total_combinations(len(K4))

    crib_survivors: list[dict] = []
    fitness_survivors: list[dict] = []
    n_tried = 0

    print(f"=== Weltzeituhr sweep on K4 ===")
    print(f"alphabet:           {alphabet.name}")
    print(f"widened:            {widened} ({len(cfg.zodiac_epoch_angles_deg)} zodiac epoch angles)")
    print(f"total combinations: {total}")
    print(f"chi-squared T99:    {chi_threshold:.1f}  (lower = more English)")
    print()

    with ExperimentLogger("003_weltzeituhr_keystream") as log:
        log.write({
            "alphabet": alphabet.name,
            "widened": widened,
            "total_combinations": total,
            "chi_threshold": chi_threshold,
        })
        for gen, anchor, interval, zodiac_eangle, params, ks in iter_keystreams(cfg, length=len(K4)):
            n_tried += 1
            plain = decrypt_with_shifts(K4, ks, alphabet)
            ok = crib_check(plain, CRIBS)
            chi = chi_squared(plain)
            record = {
                "gen": gen,
                "anchor": anchor,
                "interval": interval,
                "zodiac_epoch_angle_deg": zodiac_eangle,
                "params": {k: (v.name if hasattr(v, "name") else
                               [x.name for x in v] if isinstance(v, tuple) and all(hasattr(x, "name") for x in v) else
                               v) for k, v in params.items()},
                "crib_ok": ok,
                "chi_sq": round(chi, 2),
            }
            if ok:
                record["plaintext"] = plain
                crib_survivors.append(record)
                if chi < chi_threshold:
                    fitness_survivors.append(record)
            log.write(record)

        log.write({
            "summary": True,
            "n_tried": n_tried,
            "n_crib_survivors": len(crib_survivors),
            "n_fitness_survivors": len(fitness_survivors),
        })

    print(f"\nswept:                 {n_tried}")
    print(f"crib-survivors:        {len(crib_survivors)}")
    print(f"fitness-survivors:     {len(fitness_survivors)}  (crib_ok AND chi^2 < {chi_threshold:.1f})")

    if crib_survivors:
        print("\n=== crib-surviving candidates (failed fitness gate unless flagged) ===")
        for r in crib_survivors:
            flag = "  <- FITNESS SURVIVOR" if r in fitness_survivors else ""
            print(f"  {r['gen']:24s} anchor={r['anchor']:18s} interval={r['interval']:6s} "
                  f"chi^2={r['chi_sq']:6.1f}{flag}")
            print(f"    params: {r['params']}")
            print(f"    plain:  {r['plaintext']}")
    else:
        print("\nNo crib-surviving candidates across the sweep.")
        print("That is the expected outcome under H0 = clock is THEMATIC not cryptographic.")
        print("Strong evidence against any direct Weltzeituhr-keystream hypothesis at these")
        print("(generator, anchor, interval, params) settings; widen the sweep if you want")
        print("to rule it out across more parameter space, but do not escalate indefinitely.")

    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--alphabet", default="standard",
                    help="standard | kryptos | <other keyword>")
    ap.add_argument("--chi-threshold", type=float, default=CHI_SQ_T99_RANDOM)
    ap.add_argument("--no-widened", action="store_true",
                    help="disable the 24-value zodiac epoch angle sweep")
    args = ap.parse_args()
    sys.exit(main(args.alphabet, args.chi_threshold, widened=not args.no_widened))
