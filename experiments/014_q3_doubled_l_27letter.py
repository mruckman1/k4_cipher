"""Q3 brute force on the doubled-L 27-letter sculpture alphabet.

The 4a we deferred from experiment 009. The 27-letter doubled-L
alphabet (`KRYPTOSABCDEFGHIJLLMNQUVWXZ`) is physically carved into the
Kryptos tableau on the sculpture; Bauer/Link/Molle (2016) noted that
HILL spells vertically when the extra L is present. K1/K2 use the
26-letter KRYPTOS-keyed alphabet; K4 might use the 27-letter variant.

Consistency-propagator output on the doubled-L 27-letter alphabet
(max_period 50, both Vigenere and Beaufort conventions): only periods
L in {27, 28, 29} survive (these are trivially consistent because their
period is greater than the longest crib span). For each surviving L,
the cribs pin some slots and leave the rest free:

  L=27:  24 of 27 slots pinned, 3 free  -> 27^3 =       19,683 keys
  L=28:  24 of 28 slots pinned, 4 free  -> 27^4 =      531,441 keys
  L=29:  24 of 29 slots pinned, 5 free  -> 27^5 =   14,348,907 keys
                                                    -----------
  total brute force                                  14,900,031 keys

For each candidate key, decrypt K4 in 27-letter Q3 space and score with
chi-squared against English letter frequency (T99 stand-in). All
crib-compatible by construction; only the fitness gate discriminates.

Win condition: any candidate whose chi-squared falls below T99=95.0
(roughly the 1st percentile of random A-Z under chi-squared) AND looks
like real English on visual inspection.

Run:
    uv run python experiments/014_q3_doubled_l_27letter.py
"""

from __future__ import annotations

import argparse
import itertools
import sys
import time

import numpy as np

from kryptos import K4
from kryptos.alphabets import KRYPTOS_WITH_EXTRA_L, Alphabet
from kryptos.cribs import CRIBS
from kryptos.experiment_logger import ExperimentLogger
from kryptos.scoring.english_classifier import CHI_SQ_T99_RANDOM, chi_squared
from kryptos.solvers.consistency import check_period


BATCH_SIZE = 50_000


def crib_shift_table(alphabet: Alphabet) -> dict[int, int]:
    """Position -> required shift (key index in alphabet)."""
    n = alphabet.modulus
    out: dict[int, int] = {}
    for c in CRIBS:
        for i, p in enumerate(c.plaintext):
            pos = c.start - 1 + i
            ci = alphabet.index(K4[pos])
            pi = alphabet.index(p)
            out[pos] = (ci - pi) % n
    return out


def search_period(L: int, alphabet: Alphabet, log,
                   chi_threshold: float = CHI_SQ_T99_RANDOM,
                   top_n: int = 25) -> tuple[int, int, list[dict]]:
    """Brute force all Q3 keys of period L over alphabet whose pinned
    slots match the cribs. Return (n_tried, n_below_threshold, top_n_records)."""
    N = alphabet.modulus
    # Pinned slots from consistency propagator.
    res = check_period(L, alphabet=alphabet, cribs=CRIBS, convention="vigenere")
    if not res.consistent:
        return 0, 0, []
    pinned: dict[int, int] = {}    # slot -> key_idx
    shift_table = crib_shift_table(alphabet)
    for pos, shift in shift_table.items():
        slot = pos % L
        pinned[slot] = shift   # consistent so all crib positions in a slot agree
    free_slots = sorted(s for s in range(L) if s not in pinned)
    n_free = len(free_slots)
    n_candidates = N ** n_free

    # Precompute K4 as 27-letter indices and the key-template positions.
    K4_idx = np.array(alphabet.encode(K4), dtype=np.int16)
    keystream_positions = np.arange(len(K4)) % L
    # Base key (with placeholders for free slots).
    base_key = np.zeros(L, dtype=np.int16)
    for slot, k_val in pinned.items():
        base_key[slot] = k_val

    # Score K4 plaintext under candidate keys; track best chi-squared.
    top: list[tuple[float, list[int], str]] = []
    n_tried = 0
    n_below = 0

    def push_top(chi: float, fill: tuple[int, ...], plain: str) -> None:
        nonlocal top
        if len(top) < top_n:
            top.append((chi, list(fill), plain))
            top.sort(key=lambda x: x[0])
        elif chi < top[-1][0]:
            top[-1] = (chi, list(fill), plain)
            top.sort(key=lambda x: x[0])

    # Batch over fills.
    fills_iter = itertools.product(range(N), repeat=n_free) if n_free > 0 else iter([()])
    batch_fills: list[tuple[int, ...]] = []

    def flush(batch: list[tuple[int, ...]]) -> None:
        nonlocal n_tried, n_below
        if not batch:
            return
        b = len(batch)
        # Build full key array (b, L) in one go.
        keys = np.tile(base_key, (b, 1))
        if n_free > 0:
            fill_arr = np.array(batch, dtype=np.int16)
            for col, slot in enumerate(free_slots):
                keys[:, slot] = fill_arr[:, col]
        # Generate keystream (b, 97) by gather.
        keystreams = keys[:, keystream_positions]
        # Decrypt.
        plain_idx = (K4_idx[None, :] - keystreams) % N
        # Score via chi-squared against English letter freq.
        # NB: alphabet letters are A-Z plus a duplicate L; we score the
        # produced PLAINTEXT (English letters) by chi-squared.
        for row in range(b):
            n_tried_local_increment = 1
            text = "".join(alphabet.at(int(plain_idx[row, i])) for i in range(len(K4)))
            chi = chi_squared(text)
            push_top(chi, batch[row], text)
            if chi < chi_threshold:
                n_below += 1
                log.write({
                    "L": L, "fill": list(batch[row]), "chi_sq": round(chi, 2),
                    "plaintext": text,
                })
        n_tried += b

    for fill in fills_iter:
        batch_fills.append(fill)
        if len(batch_fills) >= BATCH_SIZE:
            flush(batch_fills)
            batch_fills = []
    flush(batch_fills)

    top_records = [
        {"L": L, "rank": rank + 1, "chi_sq": round(chi, 2),
         "fill": fill, "plaintext": plain}
        for rank, (chi, fill, plain) in enumerate(top)
    ]
    return n_tried, n_below, top_records


def main(chi_threshold: float = CHI_SQ_T99_RANDOM) -> int:
    alphabet = KRYPTOS_WITH_EXTRA_L
    print(f"alphabet: {alphabet.name}  (modulus {alphabet.modulus})")
    print(f"letters:  {alphabet.letters}")
    print(f"chi-squared T99 threshold: {chi_threshold}")
    print()

    t0 = time.perf_counter()
    grand_tried = 0
    grand_below = 0
    with ExperimentLogger("014_q3_doubled_l_27letter") as log:
        log.write({"alphabet": alphabet.name, "chi_threshold": chi_threshold})
        for L in (27, 28, 29):
            print(f"--- L = {L} ---")
            t1 = time.perf_counter()
            n_tried, n_below, top = search_period(L, alphabet, log, chi_threshold)
            dt = time.perf_counter() - t1
            grand_tried += n_tried
            grand_below += n_below
            print(f"  tried {n_tried:>10,} keys in {dt:.1f}s  "
                  f"({n_tried / max(dt, 1e-9):.0f} keys/s)  "
                  f"below T99: {n_below}")
            print(f"  top 5 by chi-squared:")
            for r in top[:5]:
                print(f"    chi^2={r['chi_sq']:.1f}  fill={r['fill']}  {r['plaintext']}")
            if n_below:
                print(f"  THRESHOLD SURVIVORS (chi^2 < {chi_threshold}) logged to JSONL.")
        log.write({"summary": True, "grand_tried": grand_tried,
                   "grand_below": grand_below,
                   "elapsed_s": time.perf_counter() - t0})

    print()
    print(f"=== summary ===")
    print(f"  keys tried:        {grand_tried:>12,}")
    print(f"  chi^2 < {chi_threshold}:    {grand_below:>12,}")
    print(f"  elapsed:           {time.perf_counter() - t0:.1f}s")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--chi-threshold", type=float, default=CHI_SQ_T99_RANDOM)
    args = ap.parse_args()
    sys.exit(main(args.chi_threshold))
