"""Ciphertext-edit + generator-library search on K4.

Hypothesis: Sanborn made a single-character encoding error in K4 (the
same authorial signature as K2's omitted X, K3's deliberate ?,
IQLUSION, DESPARATLY, UNDERGRUUND, etc.). The actual sculpture text
differs from the "intended" ciphertext by a single edit. Under that
edit, the cribs at positions {22-34, 64-74} produce a clean shift
sequence -- which experiment 006's generator library will recognise.

The search space is small:
  - inserts:  98 positions * 26 letters = 2,548 variants
  - deletes:  97 positions               =    97 variants
  - swaps:    96 positions (swap p, p+1) =    96 variants
                                          ---------------
                                          = 2,741 variants

Each variant produces a 24-shift sequence at the canonical crib
positions (treated as positions in the EDITED ciphertext, on the
hypothesis that those are the *intended* positions Sanborn would have
hit had he not edited). The shift sequence is scored against every
generator in `kryptos.generators` exactly as in experiment 006.

Two alphabets (standard, KRYPTOS-keyed), so 2,741 * 20k * 2 ~ 110M
comparisons. Pure Python runtime: a few minutes.

Win condition: any (edit, generator) pair producing >= 8 consecutive
correct shifts in either window. Under uniform random the per-pair
probability is `(1/26)^8 ~= 2e-12`, so 110M comparisons expect ~ 2.5e-4
false positives at the 8-run threshold. Anything that hits is signal.

Run:
    uv run python experiments/007_ciphertext_edit_search.py
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Iterator

from kryptos import K4
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, Alphabet
from kryptos.cribs import BERLINCLOCK, EASTNORTHEAST
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
WIN_THRESHOLD = 8                # the user's "essentially proof" threshold
LOG_THRESHOLD = 5                # log everything interesting


def edit_variants(k4: str) -> Iterator[tuple[str, int, str, str]]:
    """Yield (edit_kind, position, letter, edited_K4) for every single-char edit."""
    n = len(k4)
    for p in range(0, n + 1):
        for letter in ALPHABET_LETTERS:
            yield ("insert", p, letter, k4[:p] + letter + k4[p:])
    for p in range(0, n):
        yield ("delete", p, "", k4[:p] + k4[p + 1:])
    for p in range(0, n - 1):
        yield ("swap", p, "", k4[:p] + k4[p + 1] + k4[p] + k4[p + 2:])


def shifts_at_cribs(ciphertext: str, alphabet: Alphabet) -> dict[int, int] | None:
    """Compute the 24-position shift table required for `ciphertext` at
    the canonical crib positions to decrypt to the crib plaintexts.
    Returns None if `ciphertext` is too short.
    """
    en = EASTNORTHEAST.plaintext       # 13 chars
    bc = BERLINCLOCK.plaintext         # 11 chars
    en_start0 = EASTNORTHEAST.start - 1
    bc_start0 = BERLINCLOCK.start - 1
    if len(ciphertext) < bc_start0 + len(bc):
        return None
    n = len(alphabet)
    table: dict[int, int] = {}
    for i, p in enumerate(en):
        c = ciphertext[en_start0 + i]
        table[en_start0 + i] = (alphabet.index(p) - alphabet.index(c)) % n
    for i, p in enumerate(bc):
        c = ciphertext[bc_start0 + i]
        table[bc_start0 + i] = (alphabet.index(p) - alphabet.index(c)) % n
    return table


def longest_run_in_window(generated: list[int], target: dict[int, int],
                          window: list[int]) -> tuple[int, int]:
    best_run, best_start = 0, -1
    cur_run, cur_start = 0, -1
    for pos in window:
        if pos < len(generated) and generated[pos] == target[pos]:
            if cur_run == 0:
                cur_start = pos
            cur_run += 1
            if cur_run > best_run:
                best_run, best_start = cur_run, cur_start
        else:
            cur_run, cur_start = 0, -1
    return best_run, best_start


def crib_windows() -> list[tuple[str, list[int]]]:
    return [
        (EASTNORTHEAST.name, list(range(EASTNORTHEAST.start - 1, EASTNORTHEAST.end))),
        (BERLINCLOCK.name, list(range(BERLINCLOCK.start - 1, BERLINCLOCK.end))),
    ]


def all_generators() -> Iterator[tuple[str, list[int]]]:
    yield from iter_text_keystreams()
    yield from iter_sanborn_numeric_keystreams()
    yield from iter_constant_keystreams()
    yield from iter_lagged_fibonacci_keystreams()
    yield from iter_fibonacci_keystreams()
    yield from iter_mengenlehreuhr_keystreams()
    yield from iter_lcg_keystreams()


def main(verbose: bool = False) -> int:
    # Pre-materialise the generator library so we don't regenerate per edit.
    print("materialising generator library ...")
    gens: list[tuple[str, list[int]]] = list(all_generators())
    print(f"  loaded {len(gens):,} generators")

    windows = crib_windows()
    print(f"crib windows: " + ", ".join(f"{name} ({len(w)} positions)" for name, w in windows))
    print(f"win threshold: >= {WIN_THRESHOLD} consecutive matches")
    print()

    n_variants = 0
    n_scored = 0
    hits: list[dict] = []
    notables: list[dict] = []
    t0 = time.perf_counter()

    with ExperimentLogger("007_ciphertext_edit_search") as log:
        log.write({"win_threshold": WIN_THRESHOLD, "log_threshold": LOG_THRESHOLD,
                   "n_generators": len(gens), "n_alphabets": 2})
        for kind, pos, letter, edited in edit_variants(K4):
            n_variants += 1
            for alpha in (STANDARD, KRYPTOS_KEYED):
                target = shifts_at_cribs(edited, alpha)
                if target is None:
                    continue
                for gen_name, gen in gens:
                    n_scored += 1
                    for win_name, win in windows:
                        run, start = longest_run_in_window(gen, target, win)
                        if run >= LOG_THRESHOLD:
                            record = {
                                "edit_kind": kind, "edit_pos": pos, "edit_letter": letter,
                                "alphabet": alpha.name, "window": win_name,
                                "run_length": run, "run_start": start,
                                "generator": gen_name,
                            }
                            notables.append(record)
                            log.write(record)
                            if run >= WIN_THRESHOLD:
                                hits.append(record)
                                print(f"  HIT  edit={kind}@{pos}/{letter!r}  "
                                      f"alpha={alpha.name}  win={win_name}  "
                                      f"run={run}  start={start}  gen={gen_name}")
            if verbose and n_variants % 200 == 0:
                dt = time.perf_counter() - t0
                print(f"  ... {n_variants:,} variants ({dt:.1f}s), "
                      f"{len(hits)} hits, {len(notables)} notables")
        log.write({"summary": True, "n_variants": n_variants, "n_scored": n_scored,
                   "n_hits": len(hits), "n_notables": len(notables),
                   "elapsed_s": time.perf_counter() - t0})

    dt = time.perf_counter() - t0
    print()
    print(f"=== summary ===")
    print(f"  variants tried:       {n_variants:>12,}")
    print(f"  total comparisons:    {n_scored:>12,}")
    print(f"  >= {LOG_THRESHOLD} consecutive:    {len(notables):>12,}")
    print(f"  >= {WIN_THRESHOLD} consecutive HIT: {len(hits):>12,}")
    print(f"  elapsed:              {dt:.1f}s")

    if notables:
        notables.sort(key=lambda r: -r["run_length"])
        print(f"\nTop 20 (edit, alphabet, generator) by run length:")
        for r in notables[:20]:
            print(f"  run={r['run_length']:2d}  start={r['run_start']:2d}  "
                  f"edit={r['edit_kind']:6s}@{r['edit_pos']:3d}/{r['edit_letter']!r:3}  "
                  f"alpha={r['alphabet']:14s}  win={r['window']:13s}  gen={r['generator']}")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()
    sys.exit(main(args.verbose))
