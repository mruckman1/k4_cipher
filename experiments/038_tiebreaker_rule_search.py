"""038 — Move B: tiebreaker exploration on W-distance and compound rules.

Exp 036 found `dist_to_w_mod_k` has exactly 1 violation across k ∈ {6..10},
at the (pos 31, pos 65) edge: both positions have W-distance 6, plain E,
but cipher G vs Y. They need different alphabets.

This experiment exhaustively tests compound rules of the form
R(i) = combination(feature_a(i), feature_b(i)) mod k for many feature
pairs, looking for a rule that achieves 0 violations at k ∈ {3, 4, 5, 6}.

Specifically the analyst hypothesized "W-distance with segment-index
tiebreaker" — under that rule, pos 31 (seg 1) and pos 65 (seg 4) get
different colors because they're in different segments even though
they have the same W-distance.

Features tested:
  - W-distance to nearest W
  - W-segment index (which of 6 W-segments)
  - W-segment offset (how far into current segment)
  - position parity (i mod 2)
  - position mod 3, mod 5
  - signed W-distance (negative if W is ahead, positive if behind)
  - vowel count in K4 prefix
  - consonant count in K4 prefix
  - distance to nearest doubled letter

Compound rules:
  R(i) = (a*f + b*g) mod k for various (a, b)
  R(i) = (f*MAX_g + g) mod k for fixed MAX_g (lexicographic compound)
  R(i) = (f XOR g) mod k
  R(i) = f mod k_f, with g as secondary tiebreaker only at ties

Output: experiments/results/2026-05-23_038_tiebreaker_search.json
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Callable
from pathlib import Path

from kryptos.constants import K4
from kryptos.cribs import CRIBS

K4_TEXT = K4
N = 97
VOWELS = set("AEIOU")
W_POSITIONS = [i for i, c in enumerate(K4_TEXT) if c == "W"]


def crib_constraints():
    out = []
    for c in CRIBS:
        for offset, (p, c_) in enumerate(zip(c.plaintext, c.ciphertext)):
            out.append((c.start - 1 + offset, p, c_))
    return out


def cribs_conflict(c1, c2) -> bool:
    _, p1, ch1 = c1
    _, p2, ch2 = c2
    return (p1 == p2 and ch1 != ch2) or (ch1 == ch2 and p1 != p2)


# ----- Base feature functions: each maps position 0..96 → int

def f_dist_to_w(i: int) -> int:
    return min(abs(i - w) for w in W_POSITIONS)


def f_w_segment_index(i: int) -> int:
    return sum(1 for w in W_POSITIONS if i > w)


def f_w_segment_offset(i: int) -> int:
    boundaries = [-1] + W_POSITIONS + [N]
    for s in range(len(boundaries) - 1):
        lo, hi = boundaries[s], boundaries[s + 1]
        if lo < i < hi:
            return i - lo - 1
    return 0


def f_position(i: int) -> int:
    return i


def f_position_parity(i: int) -> int:
    return i % 2


def f_position_mod_3(i: int) -> int:
    return i % 3


def f_position_mod_5(i: int) -> int:
    return i % 5


def f_signed_dist_to_w(i: int) -> int:
    """Negative if nearest W is ahead, positive if behind. 0 if tied or
    at a W. We pick the nearest W; if tied, prefer the one behind."""
    best_d = N
    best_dir = 0
    for w in W_POSITIONS:
        d = abs(i - w)
        if d < best_d:
            best_d = d
            best_dir = 1 if w < i else -1  # w ahead → -1, w behind → +1
    # Map signed distance to non-negative for mod
    return best_d * best_dir + 100   # shift to ensure non-negative


def f_vowel_count(i: int) -> int:
    count = 0
    for j in range(i + 1):
        if K4_TEXT[j] in VOWELS:
            count += 1
    return count


def f_consonant_count(i: int) -> int:
    count = 0
    for j in range(i + 1):
        if K4_TEXT[j] not in VOWELS:
            count += 1
    return count


def f_dist_to_nearest_doubled(i: int) -> int:
    """Distance to nearest position with K4[j] == K4[j+1] (doubled letter)."""
    doubled = [j for j in range(N - 1) if K4_TEXT[j] == K4_TEXT[j + 1]]
    if not doubled:
        return 0
    return min(abs(i - j) for j in doubled)


def f_k4_letter_parity(i: int) -> int:
    """K4 ciphertext letter index parity at position i."""
    return (ord(K4_TEXT[i]) - 65) % 2


FEATURE_FUNCTIONS: dict[str, Callable[[int], int]] = {
    "w_dist": f_dist_to_w,
    "w_seg_idx": f_w_segment_index,
    "w_seg_offset": f_w_segment_offset,
    "position": f_position,
    "pos_parity": f_position_parity,
    "pos_mod_3": f_position_mod_3,
    "pos_mod_5": f_position_mod_5,
    "signed_w_dist": f_signed_dist_to_w,
    "vowel_count": f_vowel_count,
    "consonant_count": f_consonant_count,
    "dist_to_doubled": f_dist_to_nearest_doubled,
    "k4_letter_parity": f_k4_letter_parity,
}


def violations(rule_values: list[int], cribs, edges) -> int:
    colors = [rule_values[pos] for (pos, _, _) in cribs]
    return sum(1 for (u, v) in edges if colors[u] == colors[v])


def main() -> int:
    cribs = crib_constraints()
    edges = []
    for i in range(len(cribs)):
        for j in range(i + 1, len(cribs)):
            if cribs_conflict(cribs[i], cribs[j]):
                edges.append((i, j))

    print(f"Cribs: {len(cribs)}, conflict edges: {len(edges)}")
    print(f"Searching for compound rules R(i) → {{0..k-1}} with 0 violations")
    print()

    # Pre-evaluate each feature on all 97 positions
    feature_arrays: dict[str, list[int]] = {}
    for name, fn in FEATURE_FUNCTIONS.items():
        feature_arrays[name] = [fn(i) for i in range(N)]

    valid_rules: list[dict] = []

    # ----- Pass 1: pairwise lexicographic compound rules
    # R(i) = (f(i) * MAX + g(i)) mod k for some fixed MAX
    print("=== Pass 1: lexicographic compound rules (f, g) ===")
    for fa_name, fa_vals in feature_arrays.items():
        for fb_name, fb_vals in feature_arrays.items():
            if fa_name == fb_name:
                continue
            max_b = max(max(fb_vals) + 1, 2)
            for k in [3, 4, 5, 6, 7, 8]:
                rule_values = [(fa_vals[i] * max_b + fb_vals[i]) % k for i in range(N)]
                v = violations(rule_values, cribs, edges)
                if v == 0:
                    valid_rules.append({
                        "kind": "lex_compound",
                        "fa": fa_name, "fb": fb_name,
                        "max_b": max_b, "k": k,
                        "values_at_cribs": [rule_values[pos] for (pos, _, _) in cribs],
                        "k_used_at_cribs": len(set(rule_values[pos] for (pos, _, _) in cribs)),
                    })
                    print(f"  ✓ ({fa_name}, {fb_name}) lex-compound mod {k}: 0 violations "
                          f"(k_used={len({rule_values[pos] for (pos, _, _) in cribs})})")

    # ----- Pass 2: linear compound rules R(i) = (a*f + b*g) mod k
    print()
    print("=== Pass 2: linear compound rules (a*f + b*g) mod k ===")
    for fa_name, fa_vals in feature_arrays.items():
        for fb_name, fb_vals in feature_arrays.items():
            if fa_name == fb_name:
                continue
            for k in [3, 4, 5, 6, 7, 8]:
                for a in range(1, min(k, 7)):
                    for b in range(1, min(k, 7)):
                        rule_values = [(a * fa_vals[i] + b * fb_vals[i]) % k for i in range(N)]
                        v = violations(rule_values, cribs, edges)
                        if v == 0:
                            crib_colors = {rule_values[pos] for (pos, _, _) in cribs}
                            valid_rules.append({
                                "kind": "linear_compound",
                                "fa": fa_name, "fb": fb_name,
                                "a": a, "b": b, "k": k,
                                "k_used_at_cribs": len(crib_colors),
                            })
                            print(f"  ✓ ({a}*{fa_name} + {b}*{fb_name}) mod {k}: 0 violations "
                                  f"(k_used={len(crib_colors)})")

    # ----- Pass 3: XOR compound R(i) = (f XOR g) mod k
    print()
    print("=== Pass 3: XOR compound rules ===")
    for fa_name, fa_vals in feature_arrays.items():
        for fb_name, fb_vals in feature_arrays.items():
            if fa_name >= fb_name:  # avoid duplicates (XOR is commutative)
                continue
            for k in [3, 4, 5, 6, 7, 8]:
                rule_values = [(fa_vals[i] ^ fb_vals[i]) % k for i in range(N)]
                v = violations(rule_values, cribs, edges)
                if v == 0:
                    crib_colors = {rule_values[pos] for (pos, _, _) in cribs}
                    valid_rules.append({
                        "kind": "xor_compound",
                        "fa": fa_name, "fb": fb_name, "k": k,
                        "k_used_at_cribs": len(crib_colors),
                    })
                    print(f"  ✓ ({fa_name} XOR {fb_name}) mod {k}: 0 violations "
                          f"(k_used={len(crib_colors)})")

    # ----- Pass 4: tiebreaker-only rules (W-distance, with tiebreaker only at ties)
    print()
    print("=== Pass 4: W-distance with secondary feature as tiebreaker only at ties ===")
    fa_vals = feature_arrays["w_dist"]
    for fb_name, fb_vals in feature_arrays.items():
        if fb_name == "w_dist":
            continue
        for k in [3, 4, 5, 6, 7, 8, 9, 10]:
            # When W-distance is the same mod k, use fb as tiebreaker (mod 2 say)
            # Construct R(i) = (w_dist mod k) * 2 + (fb mod 2) mod (2k)
            # then reduce to k by another mod... actually let's just do
            # the simpler combination: w_dist mod k, but at positions where
            # multiple cribs collide, the fb-value mod 2 splits them.
            # Concretely: R(i) = ((w_dist mod k) * 2 + fb mod 2) mod K_out
            # for K_out in {k, 2k}.
            for K_out in [k, 2 * k]:
                rule_values = [(((fa_vals[i] % k) * 2) + (fb_vals[i] % 2)) % K_out
                                for i in range(N)]
                v = violations(rule_values, cribs, edges)
                if v == 0:
                    crib_colors = {rule_values[pos] for (pos, _, _) in cribs}
                    valid_rules.append({
                        "kind": "wdist_tiebreaker",
                        "tiebreaker": fb_name, "k_inner": k, "k_outer": K_out,
                        "k_used_at_cribs": len(crib_colors),
                    })
                    print(f"  ✓ (w_dist mod {k}, {fb_name} parity) mod {K_out}: 0 violations "
                          f"(k_used={len(crib_colors)})")

    # ----- Summary
    print()
    print("=" * 80)
    print(f"=== Summary: {len(valid_rules)} valid compound rules ===")
    print("=" * 80)

    if valid_rules:
        # Sort by k_used_at_cribs (smaller = tighter prior)
        valid_rules.sort(key=lambda r: r["k_used_at_cribs"])
        print(f"\nLowest k_used_at_cribs values (the tightest priors):")
        for r in valid_rules[:20]:
            print(f"  k_used={r['k_used_at_cribs']:>2}  kind={r['kind']:<20}  {r}")

        # Specifically: any rules at k_used = 3?
        k3_rules = [r for r in valid_rules if r["k_used_at_cribs"] == 3]
        print()
        print(f"Rules achieving k_used=3 at cribs: {len(k3_rules)}")
        if k3_rules:
            print("★★★ CRITICAL FINDING: natural compound rule(s) achieve k=3 ★★★")
            for r in k3_rules[:10]:
                print(f"  {r}")
    else:
        print(f"\nNo valid compound rule found across all passes.")
        print(f"This deepens the structural finding: k=8 is the floor for natural")
        print(f"(including pairwise-compound) rules. The cipher is either:")
        print(f"  (i) k=3 with a Sanborn-hand-drawn selection table, or")
        print(f"  (ii) k≥8 with a natural rule (position mod 8, W-seg-offset mod 8, etc.)")

    out_path = Path("experiments/results/2026-05-23_038_tiebreaker_search.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "n_features": len(FEATURE_FUNCTIONS),
        "n_valid_rules": len(valid_rules),
        "min_k_used_at_cribs": min((r["k_used_at_cribs"] for r in valid_rules), default=None),
        "valid_rules_top_50": valid_rules[:50],
    }, indent=2, default=str))
    print(f"\nOutput: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
