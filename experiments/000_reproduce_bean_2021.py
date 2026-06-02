"""Reproduce (one form of) Bean 2021 cryptodiagnosis on K4.

Treats the permutation test as a regression test for the analysis side
of the library, in the same way `001_baseline_quagmire_iii_K1_K2.py`
treats Quagmire decryption as a regression test for the cipher side.

Two questions:

1. Shift-uniformity at the cribs: K4 has 13 distinct shifts in the
   EASTNORTHEAST window (positions 22-34) and 11 distinct shifts in
   the BERLINCLOCK window (positions 64-74). Under random-letter
   ciphertext H0, how surprising is this?

2. Transposition-consistency at the cribs: under H0 = K4 is a
   transposition of some plaintext, the crib-position letters could be
   any subsample of K4's letter multiset. Observed = perfect match
   (it IS the ciphertext). The p-value here is the right-tail
   probability of seeing as many letter-position matches by chance.

Run:
    uv run python experiments/000_reproduce_bean_2021.py
"""

from __future__ import annotations

from kryptos import K4
from kryptos.analysis.permutation_test import (
    english_at_cribs_test,
    positional_shift_uniformity,
)
from kryptos.cribs import BERLINCLOCK, CRIBS, EASTNORTHEAST
from kryptos.experiment_logger import ExperimentLogger


def main(n_iters: int = 50_000, seed: int = 0) -> None:
    with ExperimentLogger("000_reproduce_bean_2021") as log:
        # Shift uniformity at the two contiguous crib windows.
        for crib in (EASTNORTHEAST, BERLINCLOCK):
            res = positional_shift_uniformity(K4, crib, n_iters=n_iters, seed=seed)
            print(f"\n[shift uniformity: {crib.name}, positions {crib.start}-{crib.end}]")
            print(f"  observed distinct shifts = {int(res.observed)}")
            print(f"  null mean = {res.null_mean:.3f} +/- {res.null_std:.3f}  (n={n_iters})")
            print(f"  p(observed >= null) = {res.p_value_one_sided_upper:.4g}")
            log.write({
                "test": "shift_uniformity",
                "crib": crib.name,
                "n_iters": n_iters,
                "observed": res.observed,
                "null_mean": res.null_mean,
                "null_std": res.null_std,
                "p_upper": res.p_value_one_sided_upper,
                "p_lower": res.p_value_one_sided_lower,
            })

        # English-at-cribs test (non-degenerate replacement for the
        # earlier `transposition_consistency_test`).
        for crib in (EASTNORTHEAST, BERLINCLOCK, *CRIBS):
            res = english_at_cribs_test(K4, crib, n_iters=n_iters, seed=seed)
            print(f"\n[english-at-cribs: {crib.name}]")
            print(f"  observed bigram logp/char = {res.observed:.4f}")
            print(f"  null mean = {res.null_mean:.4f} +/- {res.null_std:.4f}  (n={n_iters})")
            print(f"  p(null <= observed) = {res.p_value_one_sided_lower:.4g}   (left tail: cribs MORE unusual than random)")
            print(f"  p(null >= observed) = {res.p_value_one_sided_upper:.4g}   (right tail: cribs LESS English than random)")
            log.write({
                "test": "english_at_cribs",
                "crib": crib.name,
                "n_iters": n_iters,
                "observed": res.observed,
                "null_mean": res.null_mean,
                "null_std": res.null_std,
                "p_lower": res.p_value_one_sided_lower,
                "p_upper": res.p_value_one_sided_upper,
                "p_two_sided": res.p_value_two_sided,
            })


if __name__ == "__main__":
    main()
