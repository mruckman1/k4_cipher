"""27-letter alphabet step 4b + locally-arithmetic keystream sweep.

Two checks, both cheap, both directly target signals from the step-3
inspection:

  4b. Re-run experiment 006's generator library at modulus 27 against
      the 27-letter shift tables. Experiment 006 was a negative result
      across 20k generators all producing mod-26 outputs against
      mod-26 crib shifts. If the cipher is actually 27-letter, that
      whole sweep was searching the wrong space. This re-runs every
      family with mod-27 arithmetic.

  Locally-arithmetic. The (17, 18, 19/20) sub-sequence at K4 positions
  70-72 in BERLINCLOCK suggests a *locally arithmetic* keystream --
  one whose output increments by ~1 over short windows. Generate
  keystreams of the form `k_i = floor(alpha * i + beta) mod M` for
  alpha in [0, 2] step 0.01, beta in [0, M) step 0.1, M in {26, 27}.
  ~100k generators, runs in seconds.

Primary alphabet: KRYPTOS_WITH_EXTRA_L (doubled L, the Bauer/Link/Molle
intended-anomaly reading). Also reported: KRYPTOS_TRAILING_L and
KRYPTOS_K_RESTORED, as secondary candidates.

Win condition: any generator producing >= 5 consecutive correct shifts
in either crib window. Per-generator probability under uniform random
~= 16 * (1/27)^5 ~= 1.1e-6, so across ~120k generators x 3 alphabets x
2 windows, expected false-positive 5-runs ~= 0.8. Anything that hits
is worth investigating.

Run:
    uv run python experiments/009_27letter_search.py
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Iterator

from kryptos import K4
from kryptos.alphabets import (
    KRYPTOS_K_RESTORED,
    KRYPTOS_KEYED,
    KRYPTOS_TRAILING_L,
    KRYPTOS_WITH_EXTRA_L,
    STANDARD,
    Alphabet,
)
from kryptos.cribs import BERLINCLOCK, CRIBS, EASTNORTHEAST
from kryptos.experiment_logger import ExperimentLogger
from kryptos.generators import (
    CONSTANTS_BASE10,
    constant_keystream,
    fibonacci_mod,
    iter_mengenlehreuhr_keystreams,
    iter_sanborn_numeric_keystreams,
    lagged_fibonacci_mod,
    linear_congruential,
    text_as_shifts,
)


WIN_THRESHOLD = 5
LOG_THRESHOLD = 4


# ----- target shift tables (computed per alphabet, used by scoring) -----


def crib_shift_table_for(alphabet: Alphabet) -> dict[int, int]:
    n = alphabet.modulus
    out: dict[int, int] = {}
    for c in CRIBS:
        for i, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext)):
            out[c.start - 1 + i] = (alphabet.index(p) - alphabet.index(ch)) % n
    return out


def crib_windows() -> list[tuple[str, list[int]]]:
    return [
        (EASTNORTHEAST.name, list(range(EASTNORTHEAST.start - 1, EASTNORTHEAST.end))),
        (BERLINCLOCK.name, list(range(BERLINCLOCK.start - 1, BERLINCLOCK.end))),
    ]


def longest_run(generated: list[int], target: dict[int, int],
                 window: list[int]) -> tuple[int, int]:
    best, best_start = 0, -1
    cur, cur_start = 0, -1
    for pos in window:
        if pos in target and pos < len(generated) and generated[pos] == target[pos]:
            if cur == 0:
                cur_start = pos
            cur += 1
            if cur > best:
                best, best_start = cur, cur_start
        else:
            cur, cur_start = 0, -1
    return best, best_start


# ----- 4b: mod-27 versions of the experiment-006 generator families -----


def iter_generators_at_modulus(modulus: int, alphabet_letters: str,
                                length: int = 97) -> Iterator[tuple[str, list[int]]]:
    """The 006 generator library, but with all arithmetic at `modulus`."""

    # 1. Text-as-keystream over the new alphabet
    sources = [
        ("KRYPTOS_keyword", "KRYPTOS"),
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
    ]
    # Also K1/K2/K3 plaintexts and K4 ciphertext, but lazily.
    from kryptos import K1_PLAINTEXT, K2_PLAINTEXT, K3_PLAINTEXT
    sources.extend([
        ("K1pt", K1_PLAINTEXT),
        ("K2pt", K2_PLAINTEXT),
        ("K3pt", K3_PLAINTEXT),
        ("K4ct", K4),
    ])
    for label, text in sources:
        for off in range(50):
            yield (f"vig:{label}_off{off}",
                   text_as_shifts(text, length, off, alphabet_letters))

    # 2. Sanborn numeric sources (mod doesn't change them; digits 0-9 already
    #    fit any modulus >= 10).
    yield from iter_sanborn_numeric_keystreams(length=length)

    # 3. Constants in base `modulus` (the natural base).
    for name in CONSTANTS_BASE10:
        for stride in (1, 2, 3):
            for offset in range(0, 30):
                try:
                    ks = constant_keystream(name, modulus, offset, length, stride)
                    yield f"const:{name}_base{modulus}_off{offset}_str{stride}", ks
                except Exception:
                    continue

    # 4. Lagged-Fibonacci with small primer sets.
    seeds_pool = [
        [0, 1, 1, 2, 3, 5],
        [1, 0, 1, 0, 1, 0],
        [11, 18, 24, 15, 19, 14],
        [3, 24, 0, 7, 17],
    ]
    for primer in seeds_pool:
        for lag in (2, 3, 4, 5):
            if len(primer) >= lag:
                yield (f"lag-fib:primer{primer[:lag]}_lag{lag}_m{modulus}",
                       lagged_fibonacci_mod(primer, lag, modulus, length))

    # 5. Fibonacci mod M, all (a, b) seed pairs.
    for sa in range(modulus):
        for sb in range(modulus):
            yield f"fib:a{sa}_b{sb}_m{modulus}", fibonacci_mod(sa, sb, modulus, length)

    # 6. Mengenlehreuhr (lamp counts are < 26 < 27, mod M doesn't reshape much).
    yield from iter_mengenlehreuhr_keystreams(length=length)

    # 7. LCG mod M.
    for a in range(1, modulus):
        for c in range(0, modulus):
            for seed in range(0, modulus):
                yield (f"lcg:a{a}_c{c}_s{seed}_m{modulus}",
                       linear_congruential(seed, a, c, modulus, length))


# ----- locally-arithmetic family -----


def iter_locally_arithmetic(modulus: int, length: int = 97
                              ) -> Iterator[tuple[str, list[int]]]:
    """k_i = floor(alpha * i + beta) mod M for alpha in [0, 2], beta in [0, M)."""
    for alpha_x100 in range(0, 201):
        alpha = alpha_x100 / 100.0
        for beta_x10 in range(0, modulus * 10):
            beta = beta_x10 / 10.0
            ks = [int(alpha * i + beta) % modulus for i in range(length)]
            yield f"linarith:m{modulus}_a{alpha:.2f}_b{beta:.1f}", ks


# ----- main -----


def run_sweep(label: str, gen_iter, target: dict[int, int],
              windows: list[tuple[str, list[int]]],
              log, hits_out: list[dict], notables_out: list[dict]) -> tuple[int, float]:
    """Returns (n_tried, elapsed_seconds)."""
    t0 = time.perf_counter()
    n_tried = 0
    for name, gen in gen_iter:
        n_tried += 1
        for win_name, win in windows:
            run, start = longest_run(gen, target, win)
            if run >= LOG_THRESHOLD:
                rec = {
                    "sweep": label, "generator": name,
                    "window": win_name, "run_length": run, "run_start": start,
                }
                notables_out.append(rec)
                log.write(rec)
                if run >= WIN_THRESHOLD:
                    hits_out.append(rec)
                    print(f"  HIT  sweep={label}  run={run}  start={start}  "
                          f"win={win_name}  gen={name}")
    return n_tried, time.perf_counter() - t0


def main() -> int:
    candidate_alphabets = [
        ("kryptos_keyed_26 (control)", KRYPTOS_KEYED),
        ("kryptos_with_extra_L (PRIMARY)", KRYPTOS_WITH_EXTRA_L),
        ("kryptos_trailing_L", KRYPTOS_TRAILING_L),
        ("kryptos_K_restored", KRYPTOS_K_RESTORED),
    ]
    windows = crib_windows()
    print(f"win threshold:  {WIN_THRESHOLD} consecutive matches in either window")
    print(f"log threshold:  {LOG_THRESHOLD}")
    print()

    with ExperimentLogger("009_27letter_search") as log:
        log.write({"win_threshold": WIN_THRESHOLD, "log_threshold": LOG_THRESHOLD})
        for alpha_label, alpha in candidate_alphabets:
            print(f"\n=== ALPHABET: {alpha_label}  (modulus = {alpha.modulus}) ===")
            target = crib_shift_table_for(alpha)
            log.write({"alphabet": alpha.name, "modulus": alpha.modulus})

            # 4b: generator library at this modulus
            hits: list[dict] = []
            notables: list[dict] = []
            n_tried, elapsed = run_sweep(
                f"4b_{alpha.name}",
                iter_generators_at_modulus(alpha.modulus, alpha.letters),
                target, windows, log, hits, notables,
            )
            print(f"  [4b generator library]    tried={n_tried:>7,}  "
                  f"5+_hits={len(hits)}  4_runs={len(notables)}  ({elapsed:.1f}s)")

            # locally-arithmetic family
            hits2: list[dict] = []
            notables2: list[dict] = []
            n_tried2, elapsed2 = run_sweep(
                f"linarith_{alpha.name}",
                iter_locally_arithmetic(alpha.modulus),
                target, windows, log, hits2, notables2,
            )
            print(f"  [locally-arithmetic   ]   tried={n_tried2:>7,}  "
                  f"5+_hits={len(hits2)}  4_runs={len(notables2)}  ({elapsed2:.1f}s)")

            # Report top notables for this alphabet
            all_notables = sorted(notables + notables2,
                                  key=lambda r: -r["run_length"])[:10]
            if all_notables:
                print(f"  top notables for {alpha.name}:")
                for r in all_notables:
                    print(f"    run={r['run_length']:2d}  start={r['run_start']:2d}  "
                          f"win={r['window']:13s}  sweep={r['sweep']:30s}  gen={r['generator']}")

    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    args = ap.parse_args()
    sys.exit(main())
