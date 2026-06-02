"""Transposition-after-substitution search: K4 = T(Q3(plaintext, key)).

Multiprocessing + numpy-vectorised. For each columnar transposition T
(grid width W in {7..10}, all W! column orderings) and each Q3 key
period L in {14..30}:

  1. Compute the remapped crib positions in the intermediate text
     (the text after undoing T).
  2. Check shift consistency: cribs sharing the same key slot (after
     remapping) must agree.
  3. For consistent triples with at most MAX_FREE_SLOTS unconstrained
     key slots, brute-force the free slots vectorised in numpy and
     score each decrypted plaintext by chi-squared.
  4. Report any chi-squared below T99 = 95.0.

Performance: numpy-batched chi-squared + multiprocessing per W.
Hot loop is in a worker function that builds candidate keys, decrypts,
histograms letters, computes chi-squared, all as bulk numpy ops.

MAX_FREE_SLOTS = 3 means each consistent triple checks at most 17,576
keys; with numpy batching, ~50ms per triple. Triples with more free
slots are skipped (too underdetermined to score meaningfully anyway).

WIDTHS = {7, 8, 9, 10} fully enumerated. W=10 has 3.6M permutations
and dominates runtime; with 16-way parallelism this is the long pole.

Run:
    uv run python experiments/015_transposition_then_q3.py
"""

from __future__ import annotations

import argparse
import itertools
import multiprocessing as mp
import os
import sys
import time
from dataclasses import dataclass

import numpy as np

from kryptos import K4
from kryptos.alphabets import KRYPTOS_KEYED, Alphabet
from kryptos.cribs import CRIBS
from kryptos.experiment_logger import ExperimentLogger
from kryptos.scoring.english_classifier import CHI_SQ_T99_RANDOM


MAX_FREE_SLOTS = 3
PERIODS = list(range(14, 31))
WIDTHS = (7, 8, 9, 10)
CHUNK_SIZE = 5_000          # perms per worker chunk
WORKERS = max(1, os.cpu_count() or 1)

_NORVIG_EXPECTED = np.array([
    0.0804, 0.0148, 0.0334, 0.0382, 0.1249, 0.0240, 0.0187, 0.0505, 0.0757,
    0.0016, 0.0054, 0.0407, 0.0251, 0.0723, 0.0764, 0.0214, 0.0012, 0.0628,
    0.0651, 0.0928, 0.0273, 0.0105, 0.0168, 0.0023, 0.0166, 0.0009,
], dtype=np.float64)


def crib_data(alphabet: Alphabet) -> tuple[np.ndarray, np.ndarray]:
    n = alphabet.modulus
    positions = []
    shifts = []
    for c in CRIBS:
        for i, p in enumerate(c.plaintext):
            pos = c.start - 1 + i
            ci = alphabet.index(K4[pos])
            pi = alphabet.index(p)
            positions.append(pos)
            shifts.append((ci - pi) % n)
    return np.array(positions, dtype=np.int32), np.array(shifts, dtype=np.int32)


def build_az_lookup(alphabet: Alphabet) -> np.ndarray:
    """Map alphabet index -> A-Z index for chi-squared scoring."""
    return np.array(
        [ord(alphabet.letters[i]) - ord("A") for i in range(alphabet.modulus)],
        dtype=np.int32,
    )


def chi_squared_batched(az_plain: np.ndarray, length: int) -> np.ndarray:
    """Chi-squared of each row of az_plain against Norvig English."""
    n_cands = az_plain.shape[0]
    one_hot = np.zeros((n_cands, 26), dtype=np.int32)
    rows = np.broadcast_to(np.arange(n_cands)[:, None], az_plain.shape)
    np.add.at(one_hot, (rows.ravel(), az_plain.ravel()), 1)
    expected = _NORVIG_EXPECTED * length
    diff = one_hot.astype(np.float64) - expected[None, :]
    return (diff * diff / expected[None, :]).sum(axis=1)


def process_chunk(args):
    """Worker: process a chunk of (W, perm) candidates against all periods.

    Returns a list of records: (W, perm_tuple, L, free, best_chi, best_plain,
    fill, n_tried, n_below).
    """
    (
        perms_arr,       # (n_perms, W) int32
        W, R,
        positions,       # (n_cribs,) int32
        shifts,          # (n_cribs,) int32
        K4_az,           # (97,) int32 in alphabet-index space
        N,               # alphabet modulus
        az_lookup,       # (N,) int32
        alphabet_letters,
        threshold,
    ) = args
    n_perms = perms_arr.shape[0]
    n_cribs = len(positions)

    # Remap crib positions for all perms at once.
    k_mod_R = (positions % R).astype(np.int32)
    col_indices = (positions // R).astype(np.int32)
    perms_pick = perms_arr[:, col_indices]                       # (n_perms, n_cribs)
    remapped = k_mod_R[None, :] + W * perms_pick                  # (n_perms, n_cribs)

    # Build I (intermediate text) for each perm: I[m] = K4[pi_inv[m%W]*R + m//W].
    # All perms share the same length-97 m-index pattern, but pi_inv differs.
    cols_97 = np.arange(len(K4)) % W
    rows_97 = np.arange(len(K4)) // W
    # Compute pi_inv[m % W] per perm: shape (n_perms, 97)
    pi_inv = np.argsort(perms_arr, axis=1)                        # (n_perms, W)
    k_indices = pi_inv[:, cols_97] * R + rows_97[None, :]         # (n_perms, 97)
    valid = k_indices < len(K4)
    safe_k = np.where(valid, k_indices, 0)
    I_all = K4_az[safe_k]                                          # (n_perms, 97)

    records = []

    for L in PERIODS:
        slots = remapped % L                                       # (n_perms, n_cribs)

        # Consistency: for each perm, no two cribs with different shifts share a slot.
        # Build a bad-mask per perm.
        bad = np.zeros(n_perms, dtype=bool)
        for i in range(n_cribs):
            si = int(shifts[i])
            for j in range(i + 1, n_cribs):
                if int(shifts[j]) == si:
                    continue
                bad |= (slots[:, i] == slots[:, j])
                if bad.all():
                    break
            if bad.all():
                break
        consistent = ~bad
        cand_idx = np.where(consistent)[0]
        if cand_idx.size == 0:
            continue

        # For each consistent perm, compute free slot count.
        # We need unique slot count per row to know free count.
        for ci in cand_idx:
            # Pinned: dict slot -> shift
            slot_row = slots[ci]
            pinned: dict[int, int] = {}
            for i in range(n_cribs):
                pinned[int(slot_row[i])] = int(shifts[i])
            n_pinned = len(pinned)
            n_free = L - n_pinned
            if n_free > MAX_FREE_SLOTS:
                continue

            # Brute force free slots vectorised.
            free_slots = [s for s in range(L) if s not in pinned]
            n_cands = N ** n_free if n_free > 0 else 1

            base_key = np.zeros(L, dtype=np.int32)
            for s, v in pinned.items():
                base_key[s] = v
            if n_free == 0:
                fills = np.empty((1, 0), dtype=np.int32)
            else:
                # Build the (N^n_free, n_free) fill array via meshgrid-like trick.
                fills = np.array(list(itertools.product(range(N), repeat=n_free)),
                                  dtype=np.int32)
            keys = np.tile(base_key, (fills.shape[0], 1))
            for j, s in enumerate(free_slots):
                if j < fills.shape[1]:
                    keys[:, s] = fills[:, j]

            keystream_positions = np.arange(len(K4)) % L
            keystreams = keys[:, keystream_positions]               # (n_cands, 97)
            I_row = I_all[ci]                                       # (97,)
            valid_row = valid[ci]                                   # (97,)
            plain = (I_row[None, :] - keystreams) % N
            # Replace invalid positions with 0 (skipped in chi-squared by length adjust).
            # For accuracy: build az indices, count only valid positions.
            az_plain_full = az_lookup[plain]
            # We compute chi-squared over valid letters only.
            if valid_row.all():
                az_for_chi = az_plain_full
                length = len(K4)
            else:
                # Compress per row: take only valid positions.
                # Since `valid_row` is the same across all candidates, slice once.
                valid_idx = np.where(valid_row)[0]
                az_for_chi = az_plain_full[:, valid_idx]
                length = int(valid_row.sum())
            chi = chi_squared_batched(az_for_chi, length)

            best_local_idx = int(np.argmin(chi))
            best_chi = float(chi[best_local_idx])
            best_fill = tuple(int(x) for x in fills[best_local_idx]) if n_free > 0 else ()

            n_below = int((chi < threshold).sum())
            if n_below > 0 or best_chi < 110:
                # Build best plaintext string.
                az_row = az_plain_full[best_local_idx]
                best_plain = "".join(
                    chr(int(az_row[i]) + ord("A")) if valid_row[i] else "?"
                    for i in range(len(K4))
                )
                records.append({
                    "W": W, "perm": tuple(int(x) for x in perms_arr[ci]), "L": L,
                    "free": n_free, "best_chi": best_chi,
                    "best_fill": list(best_fill), "best_plain": best_plain,
                    "n_below_threshold": n_below, "n_tried": n_cands,
                })

    return records


def main(widths: tuple[int, ...] = WIDTHS,
         workers: int = WORKERS,
         threshold: float = CHI_SQ_T99_RANDOM) -> int:
    alphabet = KRYPTOS_KEYED
    positions, shifts = crib_data(alphabet)
    K4_az = np.array(alphabet.encode(K4), dtype=np.int32)
    N = alphabet.modulus
    az_lookup = build_az_lookup(alphabet)
    alpha_letters = alphabet.letters

    print(f"alphabet: {alphabet.name} (mod {N})")
    print(f"widths:   {widths}")
    print(f"periods:  {PERIODS[0]}..{PERIODS[-1]}")
    print(f"max free slots: {MAX_FREE_SLOTS}")
    print(f"workers:  {workers}")
    print(f"chi^2 threshold: {threshold}")
    print()

    t0 = time.perf_counter()
    grand_records = 0
    grand_below = 0
    best_overall = None

    with ExperimentLogger("015_transposition_then_q3") as log:
        log.write({"widths": list(widths), "periods": PERIODS,
                   "max_free_slots": MAX_FREE_SLOTS, "workers": workers,
                   "threshold": threshold})

        for W in widths:
            R = (len(K4) + W - 1) // W
            n_perms = 1
            for x in range(1, W + 1):
                n_perms *= x
            print(f"--- W={W}, R={R}, n_perms={n_perms:,} ---", flush=True)
            tW = time.perf_counter()

            # Build chunks of permutations.
            def chunks_iter():
                buf = []
                for perm in itertools.permutations(range(W)):
                    buf.append(perm)
                    if len(buf) >= CHUNK_SIZE:
                        yield np.array(buf, dtype=np.int32)
                        buf = []
                if buf:
                    yield np.array(buf, dtype=np.int32)

            def args_iter():
                for perms_arr in chunks_iter():
                    yield (perms_arr, W, R, positions, shifts, K4_az, N,
                           az_lookup, alpha_letters, threshold)

            with mp.Pool(workers) as pool:
                results_iter = pool.imap_unordered(process_chunk, args_iter(), chunksize=1)
                w_records = 0
                w_below = 0
                w_best = None
                for chunk_records in results_iter:
                    for rec in chunk_records:
                        log.write(rec)
                        w_records += 1
                        w_below += rec["n_below_threshold"]
                        if w_best is None or rec["best_chi"] < w_best["best_chi"]:
                            w_best = rec
                        if rec["n_below_threshold"] > 0:
                            print(f"  HIT  W={W} L={rec['L']} perm={rec['perm']}  "
                                  f"free={rec['free']}  below={rec['n_below_threshold']}  "
                                  f"chi={rec['best_chi']:.1f}", flush=True)

            grand_records += w_records
            grand_below += w_below
            if best_overall is None or (w_best and w_best["best_chi"] < best_overall["best_chi"]):
                best_overall = w_best
            dt = time.perf_counter() - tW
            chi_str = f"{w_best['best_chi']:.1f}" if w_best is not None else "n/a"
            print(f"  W={W}: {dt:.1f}s  records logged: {w_records:,}  "
                  f"below threshold: {w_below}  best chi^2: {chi_str}", flush=True)
            if w_best is not None:
                print(f"    best plain (W={W}): {w_best['best_plain']}", flush=True)

        log.write({"summary": True, "grand_records": grand_records,
                   "grand_below": grand_below,
                   "elapsed_s": time.perf_counter() - t0})

    print()
    print(f"=== summary ===")
    print(f"  records logged:           {grand_records:>10,}")
    print(f"  chi^2 < {threshold}:                {grand_below:>10,}")
    print(f"  elapsed:                  {time.perf_counter() - t0:.1f}s")
    if best_overall:
        print(f"  best overall chi^2:       {best_overall['best_chi']:.1f}")
        print(f"  best plaintext: {best_overall['best_plain']}")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--widths", type=int, nargs="+", default=list(WIDTHS))
    ap.add_argument("--workers", type=int, default=WORKERS)
    ap.add_argument("--threshold", type=float, default=CHI_SQ_T99_RANDOM)
    args = ap.parse_args()
    sys.exit(main(tuple(args.widths), args.workers, args.threshold))
