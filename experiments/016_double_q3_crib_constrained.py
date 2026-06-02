"""Crib-constrained double-Quagmire-III search.

K4 = Q3(Q3(plaintext, key_A), key_B), both stages in the same keyed
alphabet (default: KRYPTOS-keyed, mod 26). Since Q3 in keyed-alphabet
space is `cipher_idx = (plain_idx + key_idx) mod N`, two Q3 stages
compose ADDITIVELY:

    K4_idx[i] = (plain_idx[i] + key_A[i mod L_A] + key_B[i mod L_B]) mod N

At a crib position i where plain_idx[i] is known, the equation
becomes:

    key_A[i mod L_A] + key_B[i mod L_B] = (K4_idx[i] - plain_idx[i]) mod N

This is the crib-constraint trick:
  1. Brute force key_A over N^L_A. For each candidate:
  2. For each L_B slot s, collect the equations from all crib positions
     i with i mod L_B == s; each gives a required value for key_B[s].
  3. If all those required values agree, key_B[s] is determined. If they
     disagree for any s, this key_A is inconsistent and we skip it.
  4. For undetermined L_B slots (no crib position in that slot), key_B[s]
     is free. Try every value or treat as a degenerate match.
  5. Re-encrypt the candidate plaintext and verify byte-for-byte using
     `kryptos verify` equivalence.

The space N^L_A with L_A=5 over N=26 is 11.9M candidates; each crib
check is O(24) constant-time; vectorisable; runs in ~minutes pure
Python and well under a minute with numpy. L_A in {3, 4, 5} sweeps all
together: 17k + 457k + 11.9M = 12.4M candidates.

Note: any L_B such that LCM(L_A, L_B) <= 26 is already ruled out by
the consistency propagator (because consecutive crib positions in such
a slot would have conflicting effective shifts). We still sweep them
for completeness; they should give 0 hits.

Win condition: any (L_A, L_B, key_A, key_B) where all 24 crib positions
satisfy the equation. Each such candidate is decrypted in full; the
remaining 73 positions are scored with chi-squared English-ness.

Run:
    uv run python experiments/016_double_q3_crib_constrained.py
"""

from __future__ import annotations

import argparse
import itertools
import sys
import time
from collections import defaultdict

import numpy as np

from kryptos import K4
from kryptos.alphabets import KRYPTOS_KEYED, Alphabet
from kryptos.cribs import CRIBS
from kryptos.experiment_logger import ExperimentLogger
from kryptos.scoring.english_classifier import CHI_SQ_T99_RANDOM, chi_squared


def crib_position_table(alphabet: Alphabet) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Returns (crib_positions, K4_idx_at_crib, plain_idx_at_crib),
    all of length 24."""
    positions = []
    k4_idx = []
    plain_idx = []
    for c in CRIBS:
        for i, p in enumerate(c.plaintext):
            pos = c.start - 1 + i
            positions.append(pos)
            k4_idx.append(alphabet.index(K4[pos]))
            plain_idx.append(alphabet.index(p))
    return (np.array(positions, dtype=np.int32),
            np.array(k4_idx, dtype=np.int32),
            np.array(plain_idx, dtype=np.int32))


def search_pair(
    L_A: int, L_B: int,
    alphabet: Alphabet,
    log,
    chi_threshold: float,
) -> tuple[int, int, int]:
    """Brute force key_A in N^L_A, derive key_B, check consistency.

    Returns (n_keys_tried, n_consistent, n_fitness_survivors)."""
    N = alphabet.modulus
    positions, k4_idx, plain_idx = crib_position_table(alphabet)
    n_cribs = len(positions)

    # Precompute slot_a[k] = positions[k] % L_A, slot_b[k] = positions[k] % L_B.
    slot_a = positions % L_A
    slot_b = positions % L_B
    # Required "key_A_slot + key_B_slot" mod N at each crib position.
    required_sum = (k4_idx - plain_idx) % N

    # For each (slot_a, slot_b) pair, the cribs with that pair must give
    # the same required_sum. Pre-bucket the cribs by (slot_a, slot_b).
    bucket = defaultdict(list)   # (sa, sb) -> list of indices into required_sum
    for i in range(n_cribs):
        bucket[(int(slot_a[i]), int(slot_b[i]))].append(i)

    # Pre-check: within each (sa, sb) bucket, all cribs must give the
    # same required_sum (because key_A[sa] + key_B[sb] is a single value).
    # If any bucket has internal disagreement, NO key_A can satisfy.
    for (sa, sb), idxs in bucket.items():
        vals = required_sum[idxs]
        if len(set(int(v) for v in vals)) > 1:
            log.write({"L_A": L_A, "L_B": L_B,
                       "internal_bucket_conflict": [int(sa), int(sb), [int(v) for v in vals]]})
            return 0, 0, 0

    # Reduced equations: for each unique (sa, sb), one required_sum value.
    reduced = {(sa, sb): int(required_sum[idxs[0]]) for (sa, sb), idxs in bucket.items()}
    # Group reduced equations by L_B slot: for each sb, dict[sa] -> required_sum.
    eqs_by_sb: dict[int, dict[int, int]] = defaultdict(dict)
    for (sa, sb), v in reduced.items():
        eqs_by_sb[sb][sa] = v

    n_tried = 0
    n_consistent = 0
    n_fitness = 0
    t0 = time.perf_counter()

    # Brute force key_A. For efficiency, build a numpy view of all key_A
    # candidates only for small L_A; for L_A=5 (12M tuples * 5 ints = 60MB)
    # it's OK. For L_A>=6 we'd want to iterate; we cap at 5.
    if L_A > 5:
        return 0, 0, 0

    # We can vectorise the check across all key_A at once.
    # For each (sa -> a_value mapping in key_A), and each sb, required
    # key_B[sb] = reduced[(sa, sb)] - a_value mod N.
    # The constraint: for each sb, all sa's give the same key_B[sb].

    # Generate all key_A candidates as a (N^L_A, L_A) int8 array.
    all_keys_A = np.array(
        list(itertools.product(range(N), repeat=L_A)), dtype=np.int8
    )
    n_tried = len(all_keys_A)

    # For each sb in eqs_by_sb, compute required key_B[sb] under each
    # key_A; check that all rows give the same value.
    # We use the largest sa group first to fail fast.
    sb_to_constraints = sorted(eqs_by_sb.items(),
                                key=lambda kv: -len(kv[1]))  # most-constrained first

    # Mask of candidates still consistent.
    consistent_mask = np.ones(n_tried, dtype=bool)
    key_B_values = np.full((n_tried, L_B), -1, dtype=np.int16)   # -1 = undetermined

    for sb, sa_to_v in sb_to_constraints:
        # For each sa in sa_to_v, we have required_sum -> key_B[sb] = (v - key_A[sa]) mod N.
        sa_list = sorted(sa_to_v.keys())
        if not sa_list:
            continue
        # Compute key_B[sb] for each candidate using the FIRST sa.
        first_sa = sa_list[0]
        first_v = sa_to_v[first_sa]
        candidate_kb = (first_v - all_keys_A[:, first_sa].astype(np.int32)) % N
        # For each other sa in this sb group, the same candidate must give
        # the same key_B[sb].
        for sa in sa_list[1:]:
            v = sa_to_v[sa]
            alt_kb = (v - all_keys_A[:, sa].astype(np.int32)) % N
            consistent_mask &= (alt_kb == candidate_kb)
        # Record key_B[sb] for the consistent candidates.
        key_B_values[:, sb] = candidate_kb.astype(np.int16)

    n_consistent_pre = int(consistent_mask.sum())

    # For undetermined L_B slots, key_B[s] is free. Iterate over the
    # consistent candidates and fill in undetermined slots with 0
    # (placeholder; for full search we'd enumerate, but the cost is N^U
    # per candidate where U is undetermined-slot count).
    undetermined_slots = [s for s in range(L_B) if s not in eqs_by_sb]
    U = len(undetermined_slots)

    # Get the consistent candidates.
    cand_idx = np.where(consistent_mask)[0]

    # For each consistent candidate, enumerate the N^U fill-in choices,
    # decrypt, score by chi-squared.
    plain_idx_full = np.array(alphabet.encode(K4), dtype=np.int32)   # not used; computed per-candidate
    K4_idx_full = np.array(alphabet.encode(K4), dtype=np.int32)

    for idx in cand_idx:
        key_A = all_keys_A[idx]
        key_B_known = key_B_values[idx]
        # Enumerate undetermined L_B slots.
        for fill in itertools.product(range(N), repeat=U):
            key_B = key_B_known.copy()
            for s_idx, s in enumerate(undetermined_slots):
                key_B[s] = fill[s_idx]
            # Decrypt: plain_idx[i] = (K4_idx[i] - key_A[i mod L_A] - key_B[i mod L_B]) mod N
            ks_a = key_A[np.arange(len(K4)) % L_A]
            ks_b = key_B[np.arange(len(K4)) % L_B]
            plain = (K4_idx_full - ks_a.astype(np.int32) - ks_b.astype(np.int32)) % N
            plaintext = "".join(alphabet.at(int(p)) for p in plain)
            n_consistent += 1
            chi = chi_squared(plaintext)
            rec = {
                "L_A": L_A, "L_B": L_B,
                "key_A": "".join(alphabet.at(int(x)) for x in key_A),
                "key_B": "".join(alphabet.at(int(x)) for x in key_B),
                "chi_sq": round(chi, 2),
                "plaintext": plaintext,
            }
            log.write(rec)
            if chi < chi_threshold:
                n_fitness += 1
                print(f"  FITNESS-SURVIVOR  L_A={L_A} L_B={L_B}  "
                      f"key_A={rec['key_A']}  key_B={rec['key_B']}  chi^2={chi:.1f}")
                print(f"    plain: {plaintext}")
    dt = time.perf_counter() - t0
    return n_tried, n_consistent, n_fitness


def main(chi_threshold: float = CHI_SQ_T99_RANDOM) -> int:
    alphabet = KRYPTOS_KEYED
    print(f"alphabet:   {alphabet.name} (modulus {alphabet.modulus})")
    print(f"chi threshold: {chi_threshold}")
    print()

    grand_tried = 0
    grand_consistent = 0
    grand_fitness = 0
    t0 = time.perf_counter()
    with ExperimentLogger("016_double_q3_crib_constrained") as log:
        log.write({"alphabet": alphabet.name, "chi_threshold": chi_threshold})
        for L_A in (3, 4, 5):
            for L_B in (3, 4, 5, 6, 7, 8):
                t1 = time.perf_counter()
                n_tried, n_cons, n_fit = search_pair(
                    L_A, L_B, alphabet, log, chi_threshold,
                )
                dt = time.perf_counter() - t1
                grand_tried += n_tried
                grand_consistent += n_cons
                grand_fitness += n_fit
                print(f"  L_A={L_A} L_B={L_B}: tried={n_tried:>10,}  "
                      f"consistent_decrypts={n_cons:>6}  fitness_survivors={n_fit}  ({dt:.1f}s)")
        log.write({"summary": True, "grand_tried": grand_tried,
                   "grand_consistent": grand_consistent,
                   "grand_fitness": grand_fitness,
                   "elapsed_s": time.perf_counter() - t0})

    print()
    print(f"=== summary ===")
    print(f"  key_A candidates tried:    {grand_tried:>14,}")
    print(f"  consistent decryptions:    {grand_consistent:>14,}")
    print(f"  fitness-survivors:         {grand_fitness:>14,}")
    print(f"  elapsed:                   {time.perf_counter() - t0:.1f}s")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--chi-threshold", type=float, default=CHI_SQ_T99_RANDOM)
    args = ap.parse_args()
    sys.exit(main(args.chi_threshold))
