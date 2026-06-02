"""021: Q3 + single positional perturbation, consistency-propagator gated.

Hypothesis (from docs/shift_sequence_hypotheses.md, flagged "build it next"):
the cipher is a Quagmire III with a single Sanborn positional perturbation
that shifts the crib alignment off the key's periodic phase by a small
amount. Without perturbation, ONLY periods 27-29 survive consistency (24
crib slots fit into 27+ unique mod-slots vacuously). For L in {2..26}, the
crib slots collide and disagree -- ruling out periodic Q3. Question: does
ANY small positional perturbation make some L in {2..26} consistent?

Perturbations swept:
  (a) shift_all_cribs in [-5..+5]    11 values  (insert/delete N letters
                                                 before EAST)
  (b) shift_berlin_clock in [-3..+3]  7 values  (insert/delete N letters
                                                 between NORTHEAST end
                                                 and BERLIN start)
  combined as a 11x7 grid = 77 perturbations.

  (c) single crib-letter substitution: each of the 24 crib plaintext
      letters swapped for one of the other 25 letters = 600 perturbations.

For each perturbation x period L in {2..26} x alphabet in {STANDARD,
KRYPTOS_KEYED} x convention in {vigenere, beaufort}: run consistency.
If consistent AND all L key slots are pinned: decrypt full K4, score
with hexagram fitness, log.

Expected outcome: a small handful of consistent (perturbation, L, alpha,
conv) tuples; almost all decrypt to gibberish (hex << -15). If any
score above -15, that's a real lead. If ALL score below -20, the Q3 +
single-positional-perturbation family is closed.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Iterable

from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, Alphabet
from kryptos.constants import K4
from kryptos.cribs import BERLIN, CLOCK, EAST, NORTHEAST, Crib
from kryptos.scoring.ngram_fitness import load_ngrams
from kryptos.solvers.consistency import check_period


# ---------------------------------------------------------------- params

ALPHABETS: list[Alphabet] = [STANDARD, KRYPTOS_KEYED]
CONVENTIONS: list[str] = ["vigenere", "beaufort"]
PERIODS: list[int] = list(range(2, 27))           # 27-29 are vacuous

# Perturbation grids
SHIFT_ALL_RANGE = list(range(-5, 6))               # 11
SHIFT_BC_RANGE  = list(range(-3, 4))               # 7

# Scoring
HEX_PATH = Path("data/ngrams/english_hexagrams.txt")

# Reporting
INTERESTING_HEX_SCORE = -18.0   # well above gibberish floor (~-24)
TOP_K = 25                       # top survivors to dump


# ---------------------------------------------------------------- pert.

def shifted_cribs(shift_all: int, shift_bc: int) -> tuple[Crib, ...] | None:
    """Return cribs with positional shifts. ``shift_all`` displaces every
    crib; ``shift_bc`` additionally displaces BERLIN+CLOCK only."""
    out: list[Crib] = []
    for c in (EAST, NORTHEAST, BERLIN, CLOCK):
        delta = shift_all + (shift_bc if c.name in ("BERLIN", "CLOCK") else 0)
        new_start = c.start + delta
        new_end = c.end + delta
        if new_start < 1 or new_end > 97:
            return None
        out.append(Crib(c.name, new_start, new_end, c.plaintext, c.ciphertext))
    return tuple(out)


def letter_swapped_cribs(swap_crib_name: str, swap_offset: int, new_letter: str) -> tuple[Crib, ...]:
    """One crib's plaintext is modified: position `swap_offset` in
    `swap_crib_name` becomes `new_letter`. Others unchanged."""
    out: list[Crib] = []
    for c in (EAST, NORTHEAST, BERLIN, CLOCK):
        if c.name == swap_crib_name:
            chars = list(c.plaintext)
            chars[swap_offset] = new_letter
            out.append(Crib(c.name, c.start, c.end, "".join(chars), c.ciphertext))
        else:
            out.append(c)
    return tuple(out)


# ---------------------------------------------------------------- decrypt

MAX_FREE_SLOTS = 4   # 26^4 = 456,976 keys per (pert, L, alpha, conv) tuple


def decrypt_with_full_key(
    alphabet: Alphabet,
    period: int,
    full_key: list[str],
    ciphertext: str,
    convention: str,
) -> str:
    """Decrypt with a complete length-`period` key (already filled)."""
    n = len(alphabet)
    out_chars: list[str] = []
    for i, ch in enumerate(ciphertext):
        k_i = alphabet.index(full_key[i % period])
        c_i = alphabet.index(ch)
        if convention == "vigenere":
            p_i = (c_i - k_i) % n
        else:  # beaufort: plain = key - cipher
            p_i = (k_i - c_i) % n
        out_chars.append(alphabet.at(p_i))
    return "".join(out_chars)


def iter_keys_with_free_slots(
    alphabet: Alphabet,
    period: int,
    pinned: dict[int, str],
):
    """Yield every possible full key consistent with `pinned`. The free
    slots are enumerated over the full alphabet."""
    free_slots = [s for s in range(period) if s not in pinned]
    alpha_letters = alphabet.letters
    if not free_slots:
        # fully pinned: yield the single key
        yield [pinned[s] for s in range(period)]
        return

    # Brute-force iteration over free slots, decoded as base-N digits.
    n = len(alpha_letters)
    n_free = len(free_slots)
    total = n ** n_free
    for idx in range(total):
        # Decode idx into n_free letters
        v = idx
        free_vals = []
        for _ in range(n_free):
            free_vals.append(alpha_letters[v % n])
            v //= n
        key = [None] * period
        for s, letter in pinned.items():
            key[s] = letter
        for slot, letter in zip(free_slots, free_vals):
            key[slot] = letter
        yield key


# ---------------------------------------------------------------- sweep

def sweep_perturbations(
    cribs_iter: Iterable[tuple[str, tuple[Crib, ...]]],
    hex_fit,
    out_jsonl,
) -> dict:
    """Iterate (perturbation_label, perturbed_cribs) tuples. For each
    period x alphabet x convention, run consistency. Write all
    consistent + fully-decryptable outcomes to JSONL with scores."""
    n_total = 0
    n_consistent = 0
    n_fully_decrypted = 0
    survivors: list[dict] = []
    t0 = time.perf_counter()

    for label, cribs in cribs_iter:
        for L in PERIODS:
            for alpha in ALPHABETS:
                for conv in CONVENTIONS:
                    n_total += 1
                    r = check_period(L, alphabet=alpha, cribs=cribs, convention=conv)
                    if not r.consistent:
                        continue
                    n_consistent += 1
                    n_pinned = len(r.pinned_key_letters)
                    n_free = L - n_pinned
                    if n_free > MAX_FREE_SLOTS:
                        # Too expensive to brute-force; log and skip.
                        out_jsonl.write(json.dumps({
                            "perturbation": label, "period": L,
                            "alphabet": alpha.name, "convention": conv,
                            "n_free_slots": n_free,
                            "n_pinned": n_pinned,
                            "skipped_too_many_free": True,
                        }) + "\n")
                        continue
                    # Brute-force the free slots; score every full key.
                    best_score = -1e9
                    best_pt = None
                    best_key = None
                    for full_key in iter_keys_with_free_slots(alpha, L, r.pinned_key_letters):
                        pt = decrypt_with_full_key(alpha, L, full_key, K4, conv)
                        score = hex_fit(pt)
                        if score > best_score:
                            best_score = score
                            best_pt = pt
                            best_key = full_key
                    n_fully_decrypted += 1
                    rec = {
                        "perturbation": label,
                        "period": L,
                        "alphabet": alpha.name,
                        "convention": conv,
                        "n_pinned": n_pinned,
                        "n_free_slots": n_free,
                        "best_key": "".join(best_key) if best_key else None,
                        "plaintext": best_pt,
                        "hex_per_char": round(best_score, 4),
                    }
                    out_jsonl.write(json.dumps(rec) + "\n")
                    survivors.append(rec)

    elapsed = time.perf_counter() - t0
    return {
        "n_total_checks": n_total,
        "n_consistent": n_consistent,
        "n_fully_decrypted": n_fully_decrypted,
        "n_survivors_above_interesting_threshold": sum(
            1 for s in survivors if s["hex_per_char"] > INTERESTING_HEX_SCORE
        ),
        "elapsed_s": round(elapsed, 1),
        "top_k_by_hex": sorted(survivors, key=lambda s: -s["hex_per_char"])[:TOP_K],
    }


# ---------------------------------------------------------------- main

def main() -> int:
    if not HEX_PATH.exists():
        print(f"missing hexagrams: {HEX_PATH}"); return 1

    print(f"loading hexagrams from {HEX_PATH} ...", flush=True)
    t0 = time.perf_counter()
    hex_fit = load_ngrams(HEX_PATH, 6)
    print(f"  loaded in {time.perf_counter()-t0:.1f}s")

    out_path = Path("experiments/results") / f"2026-05-22_021_q3_perturbation_consistency.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    summary: dict = {}

    with open(out_path, "w") as out:
        # ------- pass 1: positional shifts
        print()
        print("=== PASS 1: positional crib shifts ===")
        pos_iter = []
        for sa in SHIFT_ALL_RANGE:
            for sb in SHIFT_BC_RANGE:
                c = shifted_cribs(sa, sb)
                if c is None: continue
                pos_iter.append((f"pos_all{sa:+d}_bc{sb:+d}", c))
        print(f"  {len(pos_iter)} positional perturbations x "
              f"{len(PERIODS)} L x {len(ALPHABETS)} alpha x "
              f"{len(CONVENTIONS)} conv = "
              f"{len(pos_iter)*len(PERIODS)*len(ALPHABETS)*len(CONVENTIONS)} checks")
        s1 = sweep_perturbations(pos_iter, hex_fit, out)
        summary["positional"] = s1
        print(f"  consistent={s1['n_consistent']}, "
              f"fully_decrypted={s1['n_fully_decrypted']}, "
              f"above_-18={s1['n_survivors_above_interesting_threshold']}, "
              f"elapsed={s1['elapsed_s']}s")

        # ------- pass 2: single crib-letter substitutions
        print()
        print("=== PASS 2: single crib-letter substitutions ===")
        letter_iter = []
        for crib in (EAST, NORTHEAST, BERLIN, CLOCK):
            for offset in range(len(crib.plaintext)):
                original = crib.plaintext[offset]
                for new in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                    if new == original: continue
                    letter_iter.append((
                        f"sub_{crib.name}[{offset}]={original}->{new}",
                        letter_swapped_cribs(crib.name, offset, new),
                    ))
        print(f"  {len(letter_iter)} letter substitutions x "
              f"{len(PERIODS)*len(ALPHABETS)*len(CONVENTIONS)} (L,alpha,conv) = "
              f"{len(letter_iter)*len(PERIODS)*len(ALPHABETS)*len(CONVENTIONS)} checks")
        s2 = sweep_perturbations(letter_iter, hex_fit, out)
        summary["letter_substitution"] = s2
        print(f"  consistent={s2['n_consistent']}, "
              f"fully_decrypted={s2['n_fully_decrypted']}, "
              f"above_-18={s2['n_survivors_above_interesting_threshold']}, "
              f"elapsed={s2['elapsed_s']}s")

        # ------- summary line
        out.write(json.dumps({"summary": True, **summary}) + "\n")

    # ------- console report
    print()
    print("=" * 70)
    print("Q3 + perturbation consistency results")
    print("=" * 70)
    print(f"JSONL: {out_path}")
    print()
    print(f"PASS 1 (positional):")
    print(f"  total checks:        {summary['positional']['n_total_checks']:,}")
    print(f"  consistent:          {summary['positional']['n_consistent']:,}")
    print(f"  fully decrypted:     {summary['positional']['n_fully_decrypted']:,}")
    print(f"  hex > -18:           {summary['positional']['n_survivors_above_interesting_threshold']}")
    print()
    print(f"PASS 2 (letter sub):")
    print(f"  total checks:        {summary['letter_substitution']['n_total_checks']:,}")
    print(f"  consistent:          {summary['letter_substitution']['n_consistent']:,}")
    print(f"  fully decrypted:     {summary['letter_substitution']['n_fully_decrypted']:,}")
    print(f"  hex > -18:           {summary['letter_substitution']['n_survivors_above_interesting_threshold']}")
    print()
    all_survivors = (
        summary["positional"]["top_k_by_hex"]
        + summary["letter_substitution"]["top_k_by_hex"]
    )
    all_survivors.sort(key=lambda s: -s["hex_per_char"])
    print(f"TOP {min(TOP_K, len(all_survivors))} by hexagram score (ALL passes combined):")
    print(f"  {'hex/char':>10}  {'L':>3}  {'alpha':<14}  {'conv':<9}  {'perturbation':<30}  plaintext (first 60)")
    print(f"  {'-'*10}  {'-'*3}  {'-'*14}  {'-'*9}  {'-'*30}  {'-'*60}")
    for s in all_survivors[:TOP_K]:
        print(f"  {s['hex_per_char']:>10.3f}  {s['period']:>3}  "
              f"{s['alphabet']:<14}  {s['convention']:<9}  "
              f"{s['perturbation']:<30}  {s['plaintext'][:60]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
