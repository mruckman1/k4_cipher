"""Function-space search: which generators reproduce the K4 crib shifts?

This experiment is a fundamentally different attack than 002/003.
There the question is "decrypt with cipher X and check if plaintext
satisfies the cribs". Here the question is "find a function whose
output at positions {21..33, 63..73} equals the known shift sequence
[25, 15, 1, 24, 23, 24, 2, 2, 20, 24, 16, 0, 1] and
[14, 6, 2, 16, 15, 20, 16, 12, 9, 13, 0]". We're searching the
generator space directly.

Win condition: any generator producing >= 5 consecutive matches in
either the EASTNORTHEAST window (positions 21-33) or the BERLINCLOCK
window (positions 63-73) is logged as a HIT and reported on stdout.

Under uniform random noise, the probability of >= 5 consecutive matches
in any single 13-position window is roughly 13 * (1/26)^5 ~= 1.1e-6.
Across the two windows and the ~10^5-generator sweep we run, the
expected number of false-positive 5-runs is well under 1. A 6-run is
~26x rarer, a 7-run another 26x. We report all runs of 3+, sort by
length, and look at the top hits.

We sweep in both the standard A-Z and KRYPTOS-keyed shift index spaces.

Run:
    uv run python experiments/006_shift_sequence_analysis.py
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Iterator

from kryptos import K4
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, Alphabet
from kryptos.cribs import BERLINCLOCK, CRIBS, EASTNORTHEAST, Crib, crib_shift_table
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


WIN_THRESHOLD = 5
LOG_THRESHOLD = 3


def crib_windows() -> list[tuple[str, list[int]]]:
    """The two contiguous crib windows as (name, list of 0-indexed positions)."""
    return [
        (EASTNORTHEAST.name, list(range(EASTNORTHEAST.start - 1, EASTNORTHEAST.end))),
        (BERLINCLOCK.name,   list(range(BERLINCLOCK.start - 1, BERLINCLOCK.end))),
    ]


def longest_run(generated: list[int], target: dict[int, int],
                window: list[int]) -> tuple[int, int]:
    """Longest run of consecutive matches in `window`. Returns
    (run_length, run_start_0indexed)."""
    best_run, best_start = 0, -1
    cur_run, cur_start = 0, -1
    for p in window:
        if generated[p] == target[p]:
            if cur_run == 0:
                cur_start = p
            cur_run += 1
            if cur_run > best_run:
                best_run, best_start = cur_run, cur_start
        else:
            cur_run, cur_start = 0, -1
    return best_run, best_start


def run_from_position(generated: list[int], target: dict[int, int],
                       start_pos: int, window: list[int]) -> int:
    """How many consecutive matches start exactly at position `start_pos`?
    Stricter than longest_run: requires alignment at the crib boundary,
    which is much rarer under random and much more meaningful when found."""
    if start_pos not in window:
        return 0
    idx = window.index(start_pos)
    n = 0
    while idx + n < len(window) and generated[window[idx + n]] == target[window[idx + n]]:
        n += 1
    return n


def score_generator(name: str, gen: list[int],
                    target_std: dict[int, int],
                    target_kk: dict[int, int]) -> dict:
    """Return one record per generator with two scores:
       - best_run: longest consecutive match anywhere in either crib window
       - boundary_run: longest match that STARTS AT the crib boundary
                       (positions 22 or 64, 1-indexed). Much stricter."""
    rec = {"generator": name,
           "best_run": 0, "best_window": None, "best_alphabet": None, "best_start": -1,
           "boundary_run": 0, "boundary_window": None, "boundary_alphabet": None}
    for target, alpha_name in ((target_std, STANDARD.name), (target_kk, KRYPTOS_KEYED.name)):
        for win_name, win in crib_windows():
            run, start = longest_run(gen, target, win)
            if run > rec["best_run"]:
                rec["best_run"] = run
                rec["best_window"] = win_name
                rec["best_alphabet"] = alpha_name
                rec["best_start"] = start
            br = run_from_position(gen, target, win[0], win)
            if br > rec["boundary_run"]:
                rec["boundary_run"] = br
                rec["boundary_window"] = win_name
                rec["boundary_alphabet"] = alpha_name
    return rec


def all_generators() -> Iterator[tuple[str, list[int]]]:
    """Concatenated stream of every generator family. Order matters for
    the priority log: highest-prior families come first."""
    yield from iter_text_keystreams()             # K1-K3 plaintexts, KRYPTOS keywords, etc.
    yield from iter_sanborn_numeric_keystreams()  # GPS, dates, K2-specific numbers
    yield from iter_constant_keystreams()         # pi, e, phi, ... in base 10 and 26
    yield from iter_lagged_fibonacci_keystreams()
    yield from iter_fibonacci_keystreams()
    yield from iter_mengenlehreuhr_keystreams()
    yield from iter_lcg_keystreams()              # largest family (~17k generators); last


def main(verbose: bool = False) -> int:
    target_std = crib_shift_table(STANDARD)
    target_kk = crib_shift_table(KRYPTOS_KEYED)

    print("Target shift sequences (0-indexed positions):")
    for crib in (EASTNORTHEAST, BERLINCLOCK):
        positions = list(range(crib.start - 1, crib.end))
        seq_std = [target_std[p] for p in positions]
        seq_kk = [target_kk[p] for p in positions]
        print(f"  {crib.name:13s}  std:    {seq_std}")
        print(f"  {' ' * 13}  kryptos: {seq_kk}")
    print(f"\nWin threshold:  {WIN_THRESHOLD} consecutive matches in either window")
    print(f"Log threshold:  {LOG_THRESHOLD} consecutive matches (all logged to JSONL)")
    print()

    hits: list[dict] = []
    top: list[dict] = []
    boundary_top: list[dict] = []
    t0 = time.perf_counter()
    n_tried = 0

    with ExperimentLogger("006_shift_sequence_analysis") as log:
        log.write({"win_threshold": WIN_THRESHOLD, "log_threshold": LOG_THRESHOLD})
        for name, gen in all_generators():
            n_tried += 1
            rec = score_generator(name, gen, target_std, target_kk)
            interesting = rec["best_run"] >= LOG_THRESHOLD or rec["boundary_run"] >= 2
            if interesting:
                log.write(rec)
                top.append(rec)
                if rec["boundary_run"] >= 2:
                    boundary_top.append(rec)
            if rec["best_run"] >= WIN_THRESHOLD or rec["boundary_run"] >= WIN_THRESHOLD:
                hits.append(rec)
                print(f"  HIT  run={rec['best_run']}  boundary_run={rec['boundary_run']}  "
                      f"start_pos={rec['best_start']:2d}  "
                      f"win={rec['best_window']:13s}  alpha={rec['best_alphabet']:14s}  "
                      f"gen={name}")
            if verbose and n_tried % 5000 == 0:
                print(f"  ... {n_tried:,} generators tried, {len(hits)} hits so far")
        log.write({"summary": True, "n_tried": n_tried, "n_hits": len(hits),
                   "elapsed_s": time.perf_counter() - t0})

    dt = time.perf_counter() - t0
    print()
    print(f"=== summary ===")
    print(f"  generators tried:  {n_tried:>10,}")
    print(f"  >= {LOG_THRESHOLD} consecutive: {len(top):>10,}")
    print(f"  >= {WIN_THRESHOLD} consecutive: {len(hits):>10,}")
    print(f"  runtime:           {dt:.1f}s")
    print()

    # Two top-N lists: one by best_run anywhere, one by boundary_run
    # (which is much stricter and more meaningful when found).
    top.sort(key=lambda r: -r["best_run"])
    print(f"Top 20 generators by longest-anywhere consecutive match:")
    for r in top[:20]:
        print(f"  run={r['best_run']:2d}  start={r['best_start']:2d}  "
              f"win={r['best_window']:13s}  alpha={r['best_alphabet']:14s}  "
              f"gen={r['generator']}")

    if boundary_top:
        boundary_top.sort(key=lambda r: -r["boundary_run"])
        print(f"\nTop 20 generators by run STARTING AT crib boundary (much stricter):")
        for r in boundary_top[:20]:
            print(f"  boundary_run={r['boundary_run']:2d}  "
                  f"win={r['boundary_window']:13s}  alpha={r['boundary_alphabet']:14s}  "
                  f"gen={r['generator']}")
    else:
        print("\nNo generator produced even a 2-letter run starting at a crib boundary.")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()
    sys.exit(main(args.verbose))
