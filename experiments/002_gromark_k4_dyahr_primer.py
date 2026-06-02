"""Phase-2 crib-constrained sweep over the Gromark / Vimark / Autokey
families on K4.

Original sweep (Bean 2021): base-10 Gromark length-5 primers on the
standard A-Z alphabet, ~100k primers, zero crib-survivors. This
experiment reproduces that result and extends it along three axes:

  - **Vimark base-26**: primer length 4 (456,976 primers) and length 5
    (~12M primers) on KRYPTOS-keyed and standard alphabets. The
    sculpture's DYAHR superscript is one specific Vimark-length-5
    primer; the full enumeration tests every other.
  - **Autokey** (plaintext-mode and ciphertext-mode): primer length 4
    on standard and KRYPTOS-keyed alphabets.
  - **Gromark with alternate alphabet keywords**: not just KRYPTOS but
    also BERLINCLOCK, WELTZEITUHR, PALIMPSEST (K1 key), ABSCISSA (K2
    key), DYAHR, and the empty keyword (= raw A-Z).

The point isn't to find a survivor -- the prior probability of one is
low -- but to leave the literature with a *real* survey of the family
rather than just the Bean base-10 published frontier. Every crib check
runs; survivors are logged with their plaintext for manual review.

Two gates run on every candidate:
  1. crib_check: must satisfy all four published cribs.
  2. chi-squared < T99=95.0: cheap English-ness gate, T99 stand-in until
     scripts/calibrate_fitness.py + a real Gutenberg corpus gives the
     hexagram T99.

A crib-surviving candidate that fails the chi-squared gate is logged but
flagged as noise.

Default sweep size:
  - Gromark base-10 length-5, standard A-Z and KRYPTOS-keyed: ~200k
  - Gromark base-10 length-5 with alternate alphabet keywords: ~700k more
  - Vimark base-26 length-4, standard and KRYPTOS-keyed: ~914k
  - Autokey length-4 (both modes) on standard and KRYPTOS-keyed: ~1.8M
  - Total: ~3.6M decryptions

Optional --deep:
  - Vimark base-26 length-5, KRYPTOS-keyed: ~12M more
  - Vimark base-26 length-5, standard: ~12M more
  - Adds ~24M more for ~15 min total runtime

Usage:
    uv run python experiments/002_gromark_k4_dyahr_primer.py
    uv run python experiments/002_gromark_k4_dyahr_primer.py --deep
"""

from __future__ import annotations

import argparse
import sys
import time

from kryptos import K4
from kryptos.ciphers.autokey import Autokey
from kryptos.ciphers.gromark import (
    Gromark,
    Vimark,
    enumerate_letter_primers,
    enumerate_numeric_primers,
)
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD
from kryptos.cribs import CRIBS
from kryptos.experiment_logger import ExperimentLogger
from kryptos.scoring.crib_check import crib_check
from kryptos.scoring.english_classifier import CHI_SQ_T99_RANDOM, chi_squared


ALPHABET_KEYWORDS = [
    "KRYPTOS",          # the obvious one (K1, K2, K3 all use it)
    "",                 # raw A-Z (Bean's published baseline)
    "BERLINCLOCK",      # plaintext crib as key
    "WELTZEITUHR",      # Sanborn's confirmed Berlin Clock referent
    "PALIMPSEST",       # K1 key
    "ABSCISSA",         # K2 key
    "DYAHR",            # the sculpture's superscript text
]


def _params_summary(p: dict) -> str:
    return ",".join(f"{k}={v}" for k, v in sorted(p.items()))


def _run_sweep(
    name: str,
    decrypt_iter,
    *,
    log,
    chi_threshold: float,
) -> tuple[int, int, int]:
    """Run a (label, decrypt_fn) iterator, return (tried, crib_ok, fitness_ok)."""
    t0 = time.perf_counter()
    tried = 0
    crib_ok = 0
    fitness_ok = 0
    for label_params, plain in decrypt_iter:
        tried += 1
        if not crib_check(plain, CRIBS):
            continue
        crib_ok += 1
        chi = chi_squared(plain)
        record = {
            "sweep": name,
            "params": label_params,
            "chi_sq": round(chi, 2),
            "plaintext": plain,
        }
        log.write(record)
        if chi < chi_threshold:
            fitness_ok += 1
            print(f"  FITNESS-SURVIVOR  {name}  {label_params}  chi^2={chi:.1f}")
            print(f"    {plain}")
        else:
            print(f"  crib-only         {name}  {label_params}  chi^2={chi:.1f}")
    dt = time.perf_counter() - t0
    print(f"  -> {name}: {tried:>10,} tried, {crib_ok} crib-OK, {fitness_ok} fitness-OK   ({dt:.1f}s)")
    log.write({"summary": True, "sweep": name, "tried": tried,
               "crib_ok": crib_ok, "fitness_ok": fitness_ok, "elapsed_s": dt})
    return tried, crib_ok, fitness_ok


def _gromark_sweep(primer_length: int, alphabet_keyword: str):
    for primer in enumerate_numeric_primers(primer_length):
        try:
            cipher = Gromark(primer, alphabet_keyword=alphabet_keyword)
        except ValueError:
            continue
        yield {"primer": primer, "alphabet_keyword": alphabet_keyword or "STANDARD"}, cipher.decrypt(K4)


def _vimark_sweep(primer_length: int, alphabet_keyword: str):
    base_alpha = KRYPTOS_KEYED if alphabet_keyword == "KRYPTOS" else STANDARD
    primer_alphabet = base_alpha.letters
    for primer in enumerate_letter_primers(primer_length, primer_alphabet):
        try:
            cipher = Vimark(primer, alphabet_keyword=alphabet_keyword)
        except ValueError:
            continue
        yield ({"primer": primer, "alphabet_keyword": alphabet_keyword or "STANDARD",
                "primer_length": primer_length}, cipher.decrypt(K4))


def _autokey_sweep(primer_length: int, alphabet_keyword: str, mode: str):
    alpha = KRYPTOS_KEYED if alphabet_keyword == "KRYPTOS" else STANDARD
    for primer in enumerate_letter_primers(primer_length, alpha.letters):
        try:
            cipher = Autokey(primer, alphabet=alpha, mode=mode)
        except ValueError:
            continue
        yield ({"primer": primer,
                "alphabet_keyword": alphabet_keyword or "STANDARD",
                "mode": mode,
                "primer_length": primer_length}, cipher.decrypt(K4))


def main(deep: bool = False, chi_threshold: float = CHI_SQ_T99_RANDOM) -> int:
    grand_tried = 0
    grand_crib = 0
    grand_fit = 0

    print(f"=== expanded experiment 002: Gromark + Vimark + Autokey on K4 ===")
    print(f"chi-squared T99 threshold: {chi_threshold:.1f}")
    print(f"deep mode (12M+ primer Vimark sweep): {deep}")
    print()

    with ExperimentLogger("002_gromark_vimark_autokey_expanded") as log:
        log.write({"deep": deep, "chi_threshold": chi_threshold})

        # 0. The single DYAHR Vimark hypothesis (cheap, run as sanity).
        v = Vimark("DYAHR", alphabet_keyword="KRYPTOS")
        plain = v.decrypt(K4)
        ok = crib_check(plain, CRIBS)
        chi = chi_squared(plain)
        log.write({"sweep": "dyahr_vimark", "params": {"primer": "DYAHR"},
                   "crib_ok": ok, "chi_sq": round(chi, 2), "plaintext": plain})
        print(f"DYAHR Vimark / KRYPTOS-keyed: crib_ok={ok}, chi^2={chi:.1f}")
        print(f"  {plain}")
        print()

        # 1. Gromark base-10 length-5 across all alphabet keywords.
        for kw in ALPHABET_KEYWORDS:
            label = f"gromark5_{kw or 'STANDARD'}"
            t, c, f = _run_sweep(label, _gromark_sweep(5, kw),
                                  log=log, chi_threshold=chi_threshold)
            grand_tried += t; grand_crib += c; grand_fit += f

        # 2. Vimark base-26 length-4 on standard + KRYPTOS-keyed.
        for kw in ("", "KRYPTOS"):
            label = f"vimark4_{kw or 'STANDARD'}"
            t, c, f = _run_sweep(label, _vimark_sweep(4, kw),
                                  log=log, chi_threshold=chi_threshold)
            grand_tried += t; grand_crib += c; grand_fit += f

        # 3. Autokey length-4 on standard + KRYPTOS-keyed, both modes.
        for kw in ("", "KRYPTOS"):
            for mode in ("plaintext", "ciphertext"):
                label = f"autokey4_{mode}_{kw or 'STANDARD'}"
                t, c, f = _run_sweep(label, _autokey_sweep(4, kw, mode),
                                      log=log, chi_threshold=chi_threshold)
                grand_tried += t; grand_crib += c; grand_fit += f

        # 4. Optional deep sweep: Vimark length-5 (~12M each).
        if deep:
            for kw in ("KRYPTOS", ""):
                label = f"vimark5_{kw or 'STANDARD'}"
                t, c, f = _run_sweep(label, _vimark_sweep(5, kw),
                                      log=log, chi_threshold=chi_threshold)
                grand_tried += t; grand_crib += c; grand_fit += f

        log.write({"grand_summary": True, "tried": grand_tried,
                   "crib_ok": grand_crib, "fitness_ok": grand_fit})

    print()
    print(f"=== grand total ===")
    print(f"  tried:             {grand_tried:>12,}")
    print(f"  crib-survivors:    {grand_crib:>12,}")
    print(f"  fitness-survivors: {grand_fit:>12,}  (chi^2 < {chi_threshold:.1f})")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--deep", action="store_true",
                    help="add Vimark length-5 sweeps (~12M primers each, ~5 min each)")
    ap.add_argument("--chi-threshold", type=float, default=CHI_SQ_T99_RANDOM)
    args = ap.parse_args()
    sys.exit(main(args.deep, args.chi_threshold))
