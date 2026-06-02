"""033 — Per-position alphabet selection with keyword-driven (periodic but
multi-alphabet) selection rule.

The load-bearing remaining hypothesis after the Opus expansion run:
Sanborn's "modification" of Scheidt's classical scheme is not another
periodic Vigenère/Quagmire (those are all ruled out), not a composite
of those (exp 029 closed the depth-2 case), not a polygraphic (exp 027
/ 030 closed those), and not an obvious clock-keystream or
generator-library function (003 / 006 / 023). Instead, the cipher may
be a per-position substitution where the ALPHABET in use varies by
position according to a selection rule.

The cipher model tested here:

  At each position i (0..96):
    pair_idx = effective_keyword[i mod L]    in {0..k-1}
    plain_alpha, cipher_alpha = alphabet_pair[pair_idx]
    cipher[i] = cipher_alpha[plain_alpha.index(plaintext[i])]

So at each position, ONE of k pre-defined (plain_alpha, cipher_alpha)
pairs is in effect — a direct positional substitution under that pair.
The "effective keyword" is a length-L sequence of indices in {0..k-1}
that controls which pair is selected; in practice this comes from a
keyword's letters modulo k.

For Sanborn-natural alphabet pool we use (plain = STANDARD,
cipher = keyed by one of ~12 Sanborn-relevant keywords). Each
"alphabet pair" is therefore a permutation mapping STANDARD letters to
KRYPTOS-keyed / PALIMPSEST-keyed / ABSCISSA-keyed / etc. letters.

The known-plaintext attack uses the 24 crib positions as hard
constraints:

  For each (alphabet_set of size k, period L):
    For each crib position p in {21..24, 25..33, 63..68, 69..73}:
      Determine which pair indices in 0..k-1 satisfy the crib's
      (plaintext, ciphertext) mapping at position p.
    Group crib positions by their (p mod L) slot; intersect valid pair
    indices across cribs in the same slot. If any slot has empty
    intersection, no keyword works — skip this (set, L).
    Otherwise: enumerate all keywords W ∈ ∏ slot_choices[s] for s in 0..L-1.
    For each: decrypt all 97 K4 positions, score with hexagram fitness.

This dramatically prunes the search — empirically most (set, L) tuples
get rejected at the slot-intersection check.

A WIN is any (alphabet_set, keyword) where the full K4 decryption is
crib-compliant AND has hexagram score above the English threshold (~-15).

Output: experiments/results/2026-05-23_033_per_position_alphabet_selection.jsonl
"""

from __future__ import annotations

import argparse
import itertools
import json
import time
from pathlib import Path

import numpy as np

from kryptos.alphabets import STANDARD, keyed_alphabet
from kryptos.constants import K4
from kryptos.cribs import CRIBS
from kryptos.scoring.ngram_fitness import load_ngrams


K4_TEXT = K4
N = 97
HEX_PATH = Path("data/ngrams/english_hexagrams.txt")
INTERESTING_HEX = -18.0   # well above gibberish; below this likely random
STRONG_HEX = -15.0        # real-English territory


# Alphabet pool. Each entry is (label, cipher_alphabet permutation as
# 26-char string). plain_alphabet is fixed to STANDARD.
#
# Designed to be EXHAUSTIVE for Sanborn-context keywords: every keyword
# from K1/K2/K3/K4 cribs, sculpture context, Berlin / Egypt themes,
# Sanborn/Scheidt names, plus common English words and reversed
# alphabets. The cipher must be in some specific (alphabet_set, rule)
# tuple; broadening the pool lets the crib filter eliminate or surface it.
def build_alphabet_pool() -> list[tuple[str, str]]:
    keywords = [
        # Direct Kryptos
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DYAHR", "IQLUSION",
        "UNDERGRUUND", "DESPARATLY",
        # K4 cribs
        "EAST", "NORTHEAST", "BERLIN", "CLOCK", "BERLINCLOCK",
        "EASTNORTHEAST",
        # Berlin Wall 1989
        "BORNHOLMER", "ALEXANDERPLATZ", "WELTZEITUHR", "URANIA",
        "BRANDENBURG", "SCHABOWSKI", "JAEGER", "MAUERFALL",
        "REUNIFICATION", "FREEDOM", "WALL",
        # Egypt 1986
        "EGYPT", "CAIRO", "KARNAK", "LUXOR", "TUTANKHAMEN",
        "CARTER", "SPHINX", "PHARAOH", "PYRAMIDS", "VALLEY",
        # Sanborn personal
        "SANBORN", "JAMESSANBORN", "EDWARDSCHEIDT", "SCHEIDT",
        "LANGLEY", "CIA", "VIRGINIA", "MARYLAND",
        # K2 plaintext / clue words
        "MAGNETIC", "FIELD", "BURIED", "LAYER", "WW", "WEBSTER",
        "COORDINATES",
        # K3 plaintext / Carter words
        "TOMB", "BREACH", "CANDLE", "CHAMBER", "TREMBLING", "FLAME",
        "DOORWAY", "ROOM", "MIST",
        # Sanborn-style misspellings / common cipher keywords
        "SCULPTURE", "PETRIFIED", "BRONZE", "COMPASS", "LODESTONE",
        # Common English keywords often tried
        "CIPHER", "SECRET", "MESSAGE", "HIDDEN", "PUZZLE",
        # Numbers as letters (some cipher conventions)
        "ZERO", "ONE", "TWO", "THREE", "FOUR", "FIVE", "SIX",
        "SEVEN", "EIGHT", "NINE", "TEN",
    ]
    pool: list[tuple[str, str]] = [("STANDARD", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")]
    seen_letters: set[str] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ"}
    for kw in keywords:
        try:
            ka = keyed_alphabet(kw)
            if ka.letters in seen_letters:
                continue
            pool.append((kw, ka.letters))
            seen_letters.add(ka.letters)
        except Exception:
            continue
    # Add reverse-keyed variants (also Sanborn-natural for cipher work)
    for kw in ["KRYPTOS", "PALIMPSEST", "BERLINCLOCK"]:
        try:
            ka = keyed_alphabet(kw)
            rev = ka.letters[::-1]
            if rev not in seen_letters:
                pool.append((kw + "_REV", rev))
                seen_letters.add(rev)
        except Exception:
            continue
    return pool


# Crib positions: (0-indexed pos, plain_letter, cipher_letter)
def crib_position_tuples() -> list[tuple[int, str, str]]:
    out: list[tuple[int, str, str]] = []
    for c in CRIBS:
        for offset, (p, c_) in enumerate(zip(c.plaintext, c.ciphertext)):
            out.append((c.start - 1 + offset, p, c_))
    return out


def encrypt_pair(plain_letter: str, plain_alpha: str, cipher_alpha: str) -> str:
    """Plain alpha index of letter → cipher alpha letter at that index."""
    return cipher_alpha[plain_alpha.index(plain_letter)]


def decrypt_pair(cipher_letter: str, plain_alpha: str, cipher_alpha: str) -> str:
    """Inverse."""
    return plain_alpha[cipher_alpha.index(cipher_letter)]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--k-range", type=int, nargs="+", default=[2, 3, 4, 5, 6])
    p.add_argument("--L-range", type=int, nargs="+", default=list(range(3, 13)))
    p.add_argument("--max-survivors-per-set", type=int, default=10000,
                   help="Cap on enumerated keywords per (alphabet_set, L)")
    p.add_argument("--hex-threshold", type=float, default=-18.0)
    p.add_argument("--out", type=Path,
                   default=Path("experiments/results/2026-05-23_033_per_position_alphabet_selection.jsonl"))
    args = p.parse_args()

    pool = build_alphabet_pool()
    print(f"Alphabet pool: {len(pool)} entries")
    for label, alpha in pool:
        print(f"  {label:14s}: {alpha}")
    cribs = crib_position_tuples()
    print(f"Crib positions: {len(cribs)}")

    print(f"\nLoading hexagrams from {HEX_PATH} ...")
    t_hex = time.perf_counter()
    hex_fit = load_ngrams(HEX_PATH, 6)
    print(f"  loaded in {time.perf_counter()-t_hex:.1f}s")

    # For each candidate cipher_alpha in pool, precompute encryption
    # mapping (plain_letter, position) → cipher_letter under (STANDARD, cipher_alpha).
    # Then for each crib (pos, plain, cipher), find which cipher_alphas
    # in the pool satisfy it.
    crib_compatible_alphas: list[set[int]] = []
    for (pos, plain, cipher) in cribs:
        compat = set()
        for idx, (label, cipher_alpha) in enumerate(pool):
            if encrypt_pair(plain, STANDARD.letters, cipher_alpha) == cipher:
                compat.add(idx)
        crib_compatible_alphas.append(compat)

    # Report how many cribs are satisfiable by each alphabet
    print("\nCrib satisfiability by alphabet (top 20 by # of 24 cribs satisfied):")
    alpha_coverage = []
    for idx, (label, cipher_alpha) in enumerate(pool):
        count = sum(1 for compat in crib_compatible_alphas if idx in compat)
        alpha_coverage.append((count, idx, label))
    alpha_coverage.sort(key=lambda r: -r[0])
    for count, idx, label in alpha_coverage[:20]:
        print(f"  [{idx:3d}] {label:18s}: {count}/24 cribs")

    # Report which cribs are uncovered by any alphabet in the pool
    uncovered = [i for i, compat in enumerate(crib_compatible_alphas) if not compat]
    union_covered = set()
    for compat in crib_compatible_alphas:
        union_covered.update(compat)
    pool_max_coverage = sum(1 for compat in crib_compatible_alphas if compat)
    print(f"\nUnion-coverage by full pool: {pool_max_coverage}/{len(cribs)} cribs satisfiable")
    if uncovered:
        print(f"Uncovered cribs (no alphabet in pool satisfies these):")
        for i in uncovered:
            pos, plain, cipher = cribs[i]
            print(f"  position {pos+1} (0-idx {pos}): {plain}→{cipher}")
        print(f"\nStructural finding: at least {len(uncovered)} cribs require")
        print(f"alphabets not in the current pool. Per-position alphabet")
        print(f"selection from this pool cannot encrypt K4 from any plaintext.")
        # Continue anyway — partial-coverage subsets still informative

    args.out.parent.mkdir(parents=True, exist_ok=True)
    total_checks = 0
    total_consistent = 0
    total_scored = 0
    n_above_interesting = 0
    n_above_strong = 0
    best_score = (-1e9, None)  # (score, record)
    t0 = time.perf_counter()
    pool_indices = list(range(len(pool)))

    with open(args.out, "w") as out_f:
        for k in args.k_range:
            print(f"\n=== k={k}: enumerating C({len(pool)}, {k}) = {len(list(itertools.combinations(pool_indices, k)))} alphabet sets ===")
            t_k = time.perf_counter()
            checks_k = 0
            consistent_k = 0
            scored_k = 0

            for combo in itertools.combinations(pool_indices, k):
                # combo is a tuple of k pool indices
                # For each crib position, valid pair indices into combo
                valid_per_crib: list[set[int]] = []
                for crib_idx, compat_alphas in enumerate(crib_compatible_alphas):
                    valid = set()
                    for pair_idx in range(k):
                        if combo[pair_idx] in compat_alphas:
                            valid.add(pair_idx)
                    valid_per_crib.append(valid)

                # If any crib has zero valid pair indices in this combo,
                # the cribs cannot be satisfied by any selection rule.
                if any(len(v) == 0 for v in valid_per_crib):
                    continue

                # Now for each period L, group cribs by (pos mod L) slot
                # and intersect valid sets.
                for L in args.L_range:
                    slot_choices: list[set[int] | None] = [None] * L
                    failed = False
                    for ((pos, _, _), valid) in zip(cribs, valid_per_crib):
                        s = pos % L
                        if slot_choices[s] is None:
                            slot_choices[s] = set(valid)
                        else:
                            slot_choices[s] = slot_choices[s] & valid
                            if not slot_choices[s]:
                                failed = True
                                break
                    if failed:
                        continue

                    # Slots untouched by any crib are free (can be anything 0..k-1)
                    for s in range(L):
                        if slot_choices[s] is None:
                            slot_choices[s] = set(range(k))

                    # Count enumerated keywords
                    n_kw = 1
                    for sc in slot_choices:
                        n_kw *= len(sc)
                    if n_kw > args.max_survivors_per_set:
                        # Too many; skip this (combo, L) — log it
                        out_f.write(json.dumps({
                            "skipped_too_many_keywords": True,
                            "k": k, "L": L,
                            "combo": [pool[i][0] for i in combo],
                            "n_keywords_would_enumerate": n_kw,
                        }) + "\n")
                        continue

                    # Enumerate all keywords (each is a tuple of length L,
                    # values in 0..k-1)
                    for kw in itertools.product(*[sorted(sc) for sc in slot_choices]):
                        checks_k += 1

                        # Verify crib consistency (should pass by construction
                        # but double-check)
                        ok_cribs = True
                        for (pos, plain, cipher) in cribs:
                            pair_idx = kw[pos % L]
                            cipher_alpha = pool[combo[pair_idx]][1]
                            if encrypt_pair(plain, STANDARD.letters, cipher_alpha) != cipher:
                                ok_cribs = False
                                break
                        if not ok_cribs:
                            continue
                        consistent_k += 1

                        # Decrypt all 97 positions
                        plain_chars = []
                        for i in range(N):
                            pair_idx = kw[i % L]
                            cipher_alpha = pool[combo[pair_idx]][1]
                            plain_chars.append(decrypt_pair(K4_TEXT[i], STANDARD.letters, cipher_alpha))
                        pt = "".join(plain_chars)

                        # Score with hexagrams
                        score = hex_fit(pt)
                        scored_k += 1

                        if score > best_score[0]:
                            rec = {
                                "k": k, "L": L,
                                "combo_indices": list(combo),
                                "combo_labels": [pool[i][0] for i in combo],
                                "keyword": list(kw),
                                "plaintext": pt,
                                "hex_per_char": round(score, 4),
                            }
                            best_score = (score, rec)

                        if score > args.hex_threshold:
                            n_above_interesting += 1
                            rec = {
                                "k": k, "L": L,
                                "combo_indices": list(combo),
                                "combo_labels": [pool[i][0] for i in combo],
                                "keyword": list(kw),
                                "plaintext": pt,
                                "hex_per_char": round(score, 4),
                            }
                            out_f.write(json.dumps(rec) + "\n")
                            if score > STRONG_HEX:
                                n_above_strong += 1
                                print(f"  *** STRONG: k={k} L={L} score={score:.3f} cand={pt[:70]} ***")

            print(f"  k={k}: checks={checks_k}, consistent={consistent_k}, "
                  f"scored={scored_k}, elapsed={time.perf_counter()-t_k:.1f}s")
            total_checks += checks_k
            total_consistent += consistent_k
            total_scored += scored_k

        elapsed = time.perf_counter() - t0
        out_f.write(json.dumps({
            "summary": True,
            "total_checks": total_checks,
            "total_consistent": total_consistent,
            "total_scored": total_scored,
            "n_above_interesting_-18": n_above_interesting,
            "n_above_strong_-15": n_above_strong,
            "best_score": best_score[0],
            "best_record": best_score[1],
            "elapsed_s": round(elapsed, 1),
        }) + "\n")

    print()
    print(f"=== exp 033 (per-position alphabet selection) ===")
    print(f"  total checks:          {total_checks:,}")
    print(f"  consistent at cribs:   {total_consistent:,}")
    print(f"  scored with hexagrams: {total_scored:,}")
    print(f"  hex > {INTERESTING_HEX:.0f} (interesting): {n_above_interesting}")
    print(f"  hex > {STRONG_HEX:.0f} (real-English):   {n_above_strong}")
    print(f"  best score:            {best_score[0]:.3f}")
    if best_score[1]:
        print(f"  best plaintext:        {best_score[1]['plaintext']}")
        print(f"  best params: k={best_score[1]['k']} L={best_score[1]['L']} "
              f"combo={best_score[1]['combo_labels']} keyword={best_score[1]['keyword']}")
    print(f"  elapsed:               {elapsed:.1f}s")
    print(f"  JSONL:                 {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
