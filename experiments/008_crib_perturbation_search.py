"""Crib-perturbation + generator-library search on K4.

Hypothesis: Sanborn's released cribs are slightly wrong. The K2
"...IDBYROWS" vs "...XLAYERTWO" history shows that Sanborn's stated
text has been wrong before. If a single-letter perturbation of one
crib + an unperturbed K4 produces a clean keystream signature, we
will find it.

The perturbations:
  - Position shift: each crib's 1-indexed start position shifted by
    -1, 0, +1 (3 variants per crib)
  - Letter substitution: each crib letter replaced by each of the
    other 25 letters (one substitution at a time; combinations not
    swept)

For each (crib, perturbation, alphabet, generator, window):
  - Build a perturbed target shift table
  - Score the generator against it

Win condition is the same as in 007: any (perturbation, generator)
pair producing >= 8 consecutive correct shifts is a HIT.

Run:
    uv run python experiments/008_crib_perturbation_search.py
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Iterator
from dataclasses import replace

from kryptos import K4
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, Alphabet
from kryptos.cribs import BERLIN, BERLINCLOCK, CLOCK, CRIBS, Crib, EAST, EASTNORTHEAST, NORTHEAST
from kryptos.experiment_logger import ExperimentLogger
from kryptos.generators import (
    iter_constant_keystreams,
    iter_fibonacci_keystreams,
    iter_lagged_fibonacci_keystreams,
    iter_lcg_keystreams,
    iter_mengenlehreuhr_keystreams,
    iter_sanborn_numeric_keystreams,
    iter_text_keystreams,
)

ALPHABET_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
WIN_THRESHOLD = 8
LOG_THRESHOLD = 5


def perturbed_cribs(crib: Crib) -> Iterator[tuple[str, Crib]]:
    """Yield (perturbation_label, perturbed_crib) variants for one crib.

    Variants:
      - shift the position by -1, 0, +1 (where it fits in K4)
      - substitute one letter of the plaintext with each of 25 others
        (one letter at a time)

    Cipher letters are recomputed from K4 at the new position so the
    new (plain, cipher) pair is internally consistent.
    """
    # Position shifts.
    for delta in (-1, 0, +1):
        new_start = crib.start + delta
        new_end = crib.end + delta
        if new_start < 1 or new_end > len(K4):
            continue
        new_ct = K4[new_start - 1 : new_end]
        if delta == 0:
            yield "pos_shift_0", crib
        else:
            label = f"pos_shift_{'+' if delta > 0 else ''}{delta}"
            yield label, replace(crib, start=new_start, end=new_end, ciphertext=new_ct)

    # Letter substitutions (one position at a time).
    for i, original_letter in enumerate(crib.plaintext):
        for sub in ALPHABET_LETTERS:
            if sub == original_letter:
                continue
            new_pt = crib.plaintext[:i] + sub + crib.plaintext[i + 1 :]
            label = f"letter_sub_pos{i}_{original_letter}>{sub}"
            yield label, replace(crib, plaintext=new_pt)


def perturbed_shift_targets(alphabet: Alphabet) -> Iterator[tuple[str, dict[int, int]]]:
    """Generate (label, shift_table) for every single-crib perturbation,
    leaving the other three cribs at their canonical values.
    """
    base_targets = {}
    n = len(alphabet)
    for c in CRIBS:
        for i, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext)):
            base_targets[c.start - 1 + i] = (alphabet.index(p) - alphabet.index(ch)) % n

    # Trivial case: no perturbation at all.
    yield "no_perturbation", dict(base_targets)

    for c_idx, crib in enumerate(CRIBS):
        # remove this crib's positions from the base
        base_without = dict(base_targets)
        for i in range(crib.end - crib.start + 1):
            del base_without[crib.start - 1 + i]
        for label, perturbed in perturbed_cribs(crib):
            target = dict(base_without)
            for i, (p, ch) in enumerate(zip(perturbed.plaintext, perturbed.ciphertext)):
                target[perturbed.start - 1 + i] = (alphabet.index(p) - alphabet.index(ch)) % n
            yield f"{crib.name}_{label}", target


def longest_run(generated: list[int], target: dict[int, int],
                window: list[int]) -> tuple[int, int]:
    best_run, best_start = 0, -1
    cur_run, cur_start = 0, -1
    for pos in window:
        if pos in target and pos < len(generated) and generated[pos] == target[pos]:
            if cur_run == 0:
                cur_start = pos
            cur_run += 1
            if cur_run > best_run:
                best_run, best_start = cur_run, cur_start
        else:
            cur_run, cur_start = 0, -1
    return best_run, best_start


def all_generators() -> Iterator[tuple[str, list[int]]]:
    yield from iter_text_keystreams()
    yield from iter_sanborn_numeric_keystreams()
    yield from iter_constant_keystreams()
    yield from iter_lagged_fibonacci_keystreams()
    yield from iter_fibonacci_keystreams()
    yield from iter_mengenlehreuhr_keystreams()
    yield from iter_lcg_keystreams()


def main(verbose: bool = False) -> int:
    print("materialising generator library ...")
    gens: list[tuple[str, list[int]]] = list(all_generators())
    print(f"  loaded {len(gens):,} generators")

    # Two windows (the contiguous EASTNORTHEAST and BERLINCLOCK windows).
    # We dynamically compute the actual window each time because the
    # perturbation may shift one of them.
    base_en_window = list(range(EASTNORTHEAST.start - 1, EASTNORTHEAST.end))
    base_bc_window = list(range(BERLINCLOCK.start - 1, BERLINCLOCK.end))
    windows = (("EASTNORTHEAST", base_en_window), ("BERLINCLOCK", base_bc_window))
    print(f"win threshold: >= {WIN_THRESHOLD} consecutive matches")
    print()

    hits: list[dict] = []
    notables: list[dict] = []
    n_perturbations = 0
    n_scored = 0
    t0 = time.perf_counter()

    with ExperimentLogger("008_crib_perturbation_search") as log:
        log.write({"win_threshold": WIN_THRESHOLD, "log_threshold": LOG_THRESHOLD,
                   "n_generators": len(gens), "n_alphabets": 2})
        for alpha in (STANDARD, KRYPTOS_KEYED):
            for pert_label, target in perturbed_shift_targets(alpha):
                n_perturbations += 1
                for gen_name, gen in gens:
                    n_scored += 1
                    for win_name, win in windows:
                        run, start = longest_run(gen, target, win)
                        if run >= LOG_THRESHOLD:
                            record = {
                                "perturbation": pert_label,
                                "alphabet": alpha.name,
                                "window": win_name,
                                "run_length": run, "run_start": start,
                                "generator": gen_name,
                            }
                            notables.append(record)
                            log.write(record)
                            if run >= WIN_THRESHOLD:
                                hits.append(record)
                                print(f"  HIT  pert={pert_label}  alpha={alpha.name}  "
                                      f"win={win_name}  run={run}  start={start}  "
                                      f"gen={gen_name}")
                if verbose and n_perturbations % 100 == 0:
                    dt = time.perf_counter() - t0
                    print(f"  ... {n_perturbations:,} perturbations ({dt:.1f}s), "
                          f"{len(hits)} hits, {len(notables)} notables")
        log.write({"summary": True, "n_perturbations": n_perturbations,
                   "n_scored": n_scored, "n_hits": len(hits),
                   "n_notables": len(notables),
                   "elapsed_s": time.perf_counter() - t0})

    dt = time.perf_counter() - t0
    print()
    print(f"=== summary ===")
    print(f"  perturbations:        {n_perturbations:>12,}")
    print(f"  total comparisons:    {n_scored:>12,}")
    print(f"  >= {LOG_THRESHOLD} consecutive:    {len(notables):>12,}")
    print(f"  >= {WIN_THRESHOLD} consecutive HIT: {len(hits):>12,}")
    print(f"  elapsed:              {dt:.1f}s")

    if notables:
        notables.sort(key=lambda r: -r["run_length"])
        print(f"\nTop 20 (perturbation, alphabet, generator) by run length:")
        for r in notables[:20]:
            print(f"  run={r['run_length']:2d}  start={r['run_start']:2d}  "
                  f"pert={r['perturbation']:42s}  alpha={r['alphabet']:14s}  "
                  f"win={r['window']:13s}  gen={r['generator']}")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()
    sys.exit(main(args.verbose))
