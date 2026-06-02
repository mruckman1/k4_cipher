"""033b — Per-position alphabet selection, state-dependent variant.

Exp 033 (basic, keyword-driven) returned a structural negative: with
an 83-alphabet pool of every Sanborn-context keyword, the pool's UNION
covers only 17 of 24 crib mappings — 7 cribs require alphabets not in
the natural pool (E→F, T→V, N→Q, O→Q, L→V, N→T, L→Z).

This extension tests STATE-DEPENDENT selection rules (the analyst's
proposed direction 1 extension): the alphabet at position i is chosen
by some property of the K4 ciphertext or position state, NOT by a
periodic keyword. Examples:

  state(i) = i mod k                            (periodic — Vigenère subset)
  state(i) = K4[i] index mod k                  (cipher-letter-dependent)
  state(i) = (cumulative vowel count in K4 prefix) mod k
  state(i) = (cumulative W count in K4 prefix) mod k
  state(i) = (cumulative position index in W-segment) mod k

For each state function R and each alphabet set of size k from the
expanded pool, check whether the cribs are jointly satisfiable: each
crib position p picks alphabet pair_R(p); that pair must encrypt
plain[p] → cipher[p].

Note: this experiment shares the structural limitation of exp 033 —
the pool itself doesn't cover 7 of the 24 cribs — so we EXPECT zero
solves regardless of how clever the state function is. But the
experiment surfaces partial-coverage results: which (alphabet_set,
state_function) combinations satisfy the MAXIMUM number of cribs.
A 22/24 or 23/24 partial-coverage with a specific state function
would be a real lead (the 1-2 missing cribs might point to a
small alphabet-pool extension).

A WIN is any (set, state_function) where ALL 24 cribs satisfied AND
decryption is sensible English.

Output: experiments/results/2026-05-23_033b_per_position_state_dependent.jsonl
"""

from __future__ import annotations

import argparse
import itertools
import json
import time
from collections.abc import Callable
from pathlib import Path

import numpy as np

from kryptos.alphabets import STANDARD, keyed_alphabet
from kryptos.constants import K4
from kryptos.cribs import CRIBS
from kryptos.scoring.ngram_fitness import load_ngrams


K4_TEXT = K4
N = 97
HEX_PATH = Path("data/ngrams/english_hexagrams.txt")
VOWELS = set("AEIOU")


def build_alphabet_pool() -> list[tuple[str, str]]:
    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DYAHR", "IQLUSION",
        "UNDERGRUUND", "DESPARATLY", "EAST", "NORTHEAST", "BERLIN",
        "CLOCK", "BERLINCLOCK", "EASTNORTHEAST",
        "BORNHOLMER", "ALEXANDERPLATZ", "WELTZEITUHR", "URANIA",
        "BRANDENBURG", "SCHABOWSKI", "JAEGER", "MAUERFALL", "FREEDOM",
        "WALL", "EGYPT", "CAIRO", "KARNAK", "LUXOR", "TUTANKHAMEN",
        "CARTER", "SPHINX", "PHARAOH", "PYRAMIDS", "VALLEY",
        "SANBORN", "JAMESSANBORN", "EDWARDSCHEIDT", "SCHEIDT",
        "LANGLEY", "CIA", "VIRGINIA", "MARYLAND",
        "MAGNETIC", "FIELD", "BURIED", "LAYER", "WW", "WEBSTER",
        "COORDINATES", "TOMB", "BREACH", "CANDLE", "CHAMBER",
        "TREMBLING", "FLAME", "DOORWAY", "ROOM", "MIST",
        "SCULPTURE", "PETRIFIED", "BRONZE", "COMPASS", "LODESTONE",
        "CIPHER", "SECRET", "MESSAGE", "HIDDEN", "PUZZLE",
        "ZERO", "ONE", "TWO", "THREE", "FOUR", "FIVE", "SIX",
        "SEVEN", "EIGHT", "NINE", "TEN",
    ]
    pool: list[tuple[str, str]] = [("STANDARD", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")]
    seen: set[str] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ"}
    for kw in keywords:
        try:
            ka = keyed_alphabet(kw)
            if ka.letters in seen:
                continue
            pool.append((kw, ka.letters))
            seen.add(ka.letters)
        except Exception:
            continue
    for kw in ["KRYPTOS", "PALIMPSEST", "BERLINCLOCK"]:
        try:
            ka = keyed_alphabet(kw)
            rev = ka.letters[::-1]
            if rev not in seen:
                pool.append((kw + "_REV", rev))
                seen.add(rev)
        except Exception:
            continue
    return pool


def crib_position_tuples() -> list[tuple[int, str, str]]:
    out: list[tuple[int, str, str]] = []
    for c in CRIBS:
        for offset, (p, c_) in enumerate(zip(c.plaintext, c.ciphertext)):
            out.append((c.start - 1 + offset, p, c_))
    return out


def encrypt_pair(plain_letter: str, cipher_alpha: str) -> str:
    """STANDARD plain → cipher_alpha-indexed cipher (Quagmire IV-like, shift=0)."""
    return cipher_alpha[ord(plain_letter) - 65]


# ---------- state functions: each returns position → state_value mapping (0..k-1) ----------

def state_position_mod(k: int):
    """Periodic period-k: state(i) = i mod k. Returns a length-N sequence."""
    return [i % k for i in range(N)]


def state_k4_letter_mod(k: int):
    """state(i) = (K4[i] - 'A') mod k. Cipher-letter-dependent."""
    return [(ord(K4_TEXT[i]) - 65) % k for i in range(N)]


def state_vowels_in_prefix(k: int):
    """state(i) = (# of vowels in K4[0..i] inclusive) mod k."""
    out: list[int] = []
    count = 0
    for i in range(N):
        if K4_TEXT[i] in VOWELS:
            count += 1
        out.append(count % k)
    return out


def state_w_count(k: int):
    """state(i) = (# of W's in K4[0..i] inclusive) mod k."""
    out: list[int] = []
    count = 0
    for i in range(N):
        if K4_TEXT[i] == "W":
            count += 1
        out.append(count % k)
    return out


def state_w_segment(k: int):
    """state(i) = which W-segment position i is in (segments are
    between W's), mod k. K4 has W's at positions 20, 36, 48, 58, 74
    (0-indexed). Six segments."""
    boundaries = [20, 36, 48, 58, 74]
    out: list[int] = []
    for i in range(N):
        seg = sum(1 for b in boundaries if i > b)
        out.append(seg % k)
    return out


def state_consonant_count(k: int):
    """state(i) = (# consonants in K4[0..i]) mod k."""
    out: list[int] = []
    count = 0
    for i in range(N):
        if K4_TEXT[i] not in VOWELS:
            count += 1
        out.append(count % k)
    return out


def state_distance_to_nearest_W(k: int):
    """state(i) = (distance to nearest W in K4) mod k."""
    w_pos = [j for j, c in enumerate(K4_TEXT) if c == "W"]
    out: list[int] = []
    for i in range(N):
        d = min(abs(i - w) for w in w_pos) if w_pos else 0
        out.append(d % k)
    return out


STATE_FUNCTIONS: list[tuple[str, Callable[[int], list[int]]]] = [
    ("position_mod_k", state_position_mod),
    ("k4_letter_mod_k", state_k4_letter_mod),
    ("vowels_in_prefix_mod_k", state_vowels_in_prefix),
    ("w_count_mod_k", state_w_count),
    ("w_segment_mod_k", state_w_segment),
    ("consonant_count_mod_k", state_consonant_count),
    ("dist_to_nearest_w_mod_k", state_distance_to_nearest_W),
]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--k-range", type=int, nargs="+", default=[2, 3, 4, 5, 6])
    p.add_argument("--report-partial-threshold", type=int, default=18,
                   help="Log any (set, state_fn) whose partial-coverage >= this many cribs")
    p.add_argument("--out", type=Path,
                   default=Path("experiments/results/2026-05-23_033b_per_position_state_dependent.jsonl"))
    args = p.parse_args()

    pool = build_alphabet_pool()
    cribs = crib_position_tuples()
    print(f"Pool: {len(pool)} alphabets")
    print(f"Cribs: {len(cribs)} positions")

    print(f"\nLoading hexagrams ...")
    hex_fit = load_ngrams(HEX_PATH, 6)

    # Precompute crib compatibility for each pool alphabet
    crib_compatible_alphas: list[set[int]] = []
    for (pos, plain, cipher) in cribs:
        compat = set()
        for idx, (_label, cipher_alpha) in enumerate(pool):
            if encrypt_pair(plain, cipher_alpha) == cipher:
                compat.add(idx)
        crib_compatible_alphas.append(compat)
    # cribs with any compatible alpha
    coverable_crib_indices = {i for i, c in enumerate(crib_compatible_alphas) if c}
    print(f"Coverable cribs in pool: {len(coverable_crib_indices)}/24")
    print(f"(7 cribs structurally uncoverable — see exp 033 for details)")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    pool_indices = list(range(len(pool)))
    total_solves = 0
    best_partial = (0, None)  # (n_cribs_satisfied, info)

    with open(args.out, "w") as out_f:
        for k in args.k_range:
            for state_name, state_fn in STATE_FUNCTIONS:
                state_seq = state_fn(k)
                # For each crib position p, the state determines which alphabet
                # index in the k-subset is used (0..k-1)
                state_at_cribs = [state_seq[pos] for (pos, _, _) in cribs]

                # Choose k-subset of pool. For each pair_idx in 0..k-1, find
                # the cribs assigned to this index (those with state==pair_idx).
                # The pair must be a single alphabet in our pool that satisfies
                # all those cribs.

                for combo in itertools.combinations(pool_indices, k):
                    # For each pair_idx, gather assigned crib_indices
                    cribs_per_pair: list[list[int]] = [[] for _ in range(k)]
                    for crib_idx, s in enumerate(state_at_cribs):
                        cribs_per_pair[s].append(crib_idx)

                    # For each pair_idx, the alphabet combo[pair_idx] must
                    # be compatible with ALL its assigned cribs.
                    all_ok = True
                    n_satisfied = 0
                    for pair_idx in range(k):
                        alpha_idx_in_pool = combo[pair_idx]
                        for crib_idx in cribs_per_pair[pair_idx]:
                            if alpha_idx_in_pool in crib_compatible_alphas[crib_idx]:
                                n_satisfied += 1
                            else:
                                all_ok = False

                    if n_satisfied > best_partial[0]:
                        best_partial = (n_satisfied, {
                            "k": k, "state_fn": state_name,
                            "combo_labels": [pool[i][0] for i in combo],
                            "n_cribs_satisfied": n_satisfied,
                        })
                    if all_ok and n_satisfied == len(cribs):
                        # Full crib satisfaction → decrypt and score
                        plain_chars = []
                        for i in range(N):
                            pair_idx = state_seq[i]
                            cipher_alpha = pool[combo[pair_idx]][1]
                            j = cipher_alpha.index(K4_TEXT[i])
                            plain_chars.append(STANDARD.letters[j])
                        pt = "".join(plain_chars)
                        score = hex_fit(pt)
                        rec = {
                            "k": k,
                            "state_fn": state_name,
                            "combo_indices": list(combo),
                            "combo_labels": [pool[i][0] for i in combo],
                            "plaintext": pt,
                            "hex_per_char": round(score, 4),
                            "all_cribs_satisfied": True,
                        }
                        out_f.write(json.dumps(rec) + "\n")
                        total_solves += 1
                        print(f"  *** FULL CRIB MATCH: k={k} state={state_name} "
                              f"combo={rec['combo_labels']} hex={score:.3f} ***")
                    elif n_satisfied >= args.report_partial_threshold:
                        out_f.write(json.dumps({
                            "k": k, "state_fn": state_name,
                            "combo_labels": [pool[i][0] for i in combo],
                            "n_cribs_satisfied": n_satisfied,
                            "partial": True,
                        }) + "\n")

            print(f"  k={k} done; total_solves so far={total_solves}; "
                  f"best partial coverage so far {best_partial[0]}/24 "
                  f"({time.perf_counter()-t0:.1f}s)")

        elapsed = time.perf_counter() - t0
        out_f.write(json.dumps({
            "summary": True,
            "n_state_functions": len(STATE_FUNCTIONS),
            "n_alphabets": len(pool),
            "total_solves": total_solves,
            "best_partial_coverage": best_partial[0],
            "best_partial_info": best_partial[1],
            "elapsed_s": round(elapsed, 1),
        }) + "\n")

    print()
    print(f"=== exp 033b (state-dependent alphabet selection) ===")
    print(f"  full crib solves: {total_solves}")
    print(f"  best partial:     {best_partial[0]}/24 cribs satisfied")
    if best_partial[1]:
        print(f"  best partial info: {best_partial[1]}")
    print(f"  elapsed: {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
