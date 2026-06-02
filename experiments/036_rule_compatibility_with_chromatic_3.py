"""036 — Test every natural rule R(i) → {0..k-1} against the conflict graph.

Exp 035 proved χ = 3 for the K4 crib conflict graph: K4's cipher must
use AT LEAST 3 distinct alphabet permutations, with a selection rule
R(i) telling us which alphabet at position i.

A natural rule R restricted to the 24 crib positions induces a coloring.
The coloring is VALID iff no two conflicting cribs share a color.

This experiment enumerates many candidate "natural" rules R and checks
which produce valid k-colorings of the conflict graph at the crib
positions. A natural rule that works = a structural prior on Sanborn's
cipher.

Rules tested (each defined for i = 0..96):
  position_mod_k for k ∈ {2..13}
  k4_letter_mod_k
  k4_letter_position_in_kryptos_alpha_mod_k
  vowel_count_in_k4_prefix_mod_k
  consonant_count_mod_k
  w_count_in_k4_prefix_mod_k
  w_segment_index_mod_k                  (Lethuillier-style)
  distance_to_nearest_w_mod_k            (Move 1 best from 033b)
  position_in_current_w_segment_mod_k
  pairwise (i // L) mod k for various L
  mengenlehreuhr-like rules (lamp count mod k)

For each (rule, k) tuple, check: at the 24 crib positions, does the
restricted coloring violate any conflict edge? If not, the rule is
COMPATIBLE with the chromatic-3 (or chromatic-k) requirement.

The most informative compatible rule is the highest-prior natural
structure that survives.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Callable
from pathlib import Path

from kryptos.alphabets import KRYPTOS_KEYED
from kryptos.constants import K4
from kryptos.cribs import CRIBS

K4_TEXT = K4
N = 97
VOWELS = set("AEIOU")
W_POSITIONS = [i for i, c in enumerate(K4_TEXT) if c == "W"]


def build_crib_constraints() -> list[tuple[int, str, str]]:
    out: list[tuple[int, str, str]] = []
    for c in CRIBS:
        for offset, (p, c_) in enumerate(zip(c.plaintext, c.ciphertext)):
            out.append((c.start - 1 + offset, p, c_))
    return out


def cribs_conflict(c1, c2) -> bool:
    _, p1, ch1 = c1
    _, p2, ch2 = c2
    if p1 == p2 and ch1 != ch2:
        return True
    if ch1 == ch2 and p1 != p2:
        return True
    return False


# ----- candidate rule families

def rule_position_mod(k: int) -> list[int]:
    return [i % k for i in range(N)]


def rule_k4_letter_mod(k: int) -> list[int]:
    return [(ord(K4_TEXT[i]) - 65) % k for i in range(N)]


def rule_k4_letter_in_kryptos_alpha_mod(k: int) -> list[int]:
    ka = KRYPTOS_KEYED.letters
    return [ka.index(K4_TEXT[i]) % k for i in range(N)]


def rule_vowel_count_mod(k: int) -> list[int]:
    out: list[int] = []
    count = 0
    for i in range(N):
        if K4_TEXT[i] in VOWELS:
            count += 1
        out.append(count % k)
    return out


def rule_consonant_count_mod(k: int) -> list[int]:
    out: list[int] = []
    count = 0
    for i in range(N):
        if K4_TEXT[i] not in VOWELS:
            count += 1
        out.append(count % k)
    return out


def rule_w_count_mod(k: int) -> list[int]:
    out: list[int] = []
    count = 0
    for i in range(N):
        if K4_TEXT[i] == "W":
            count += 1
        out.append(count % k)
    return out


def rule_w_segment_index_mod(k: int) -> list[int]:
    """Which W-segment (0..5) the position is in, mod k."""
    out: list[int] = []
    for i in range(N):
        seg = sum(1 for w in W_POSITIONS if i > w)
        out.append(seg % k)
    return out


def rule_distance_to_nearest_w_mod(k: int) -> list[int]:
    if not W_POSITIONS:
        return [0] * N
    out: list[int] = []
    for i in range(N):
        d = min(abs(i - w) for w in W_POSITIONS)
        out.append(d % k)
    return out


def rule_pos_in_current_w_segment_mod(k: int) -> list[int]:
    """How far into the current W-segment the position is, mod k."""
    out: list[int] = []
    boundaries = [-1] + W_POSITIONS + [N]
    for i in range(N):
        # find segment
        for s in range(len(boundaries) - 1):
            lo = boundaries[s]
            hi = boundaries[s + 1]
            if lo < i < hi:
                offset = i - lo - 1
                out.append(offset % k)
                break
        else:
            out.append(0)
    return out


def rule_pos_div_L_mod_k(L: int, k: int) -> list[int]:
    return [(i // L) % k for i in range(N)]


def rule_fibonacci_index_mod(k: int) -> list[int]:
    """Index of i in Fibonacci sequence (0=F1, 1=F2, etc.); else position mod 2."""
    fibs = set()
    a, b = 1, 1
    while a < N:
        fibs.add(a)
        a, b = b, a + b
    out = [(1 if i in fibs else 0) for i in range(N)]
    return [v % k for v in out]


def rule_prime_index_mod(k: int) -> list[int]:
    """Is the position a prime number?"""
    def is_prime(n):
        if n < 2:
            return False
        for d in range(2, int(n**0.5) + 1):
            if n % d == 0:
                return False
        return True
    return [(1 if is_prime(i) else 0) % k for i in range(N)]


# Build the full rule catalog
def build_rules() -> dict[str, list[int]]:
    rules: dict[str, list[int]] = {}
    for k in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]:
        rules[f"position_mod_{k}"] = rule_position_mod(k)
        rules[f"k4_letter_mod_{k}"] = rule_k4_letter_mod(k)
        rules[f"k4_letter_kryptos_mod_{k}"] = rule_k4_letter_in_kryptos_alpha_mod(k)
        rules[f"vowel_count_mod_{k}"] = rule_vowel_count_mod(k)
        rules[f"consonant_count_mod_{k}"] = rule_consonant_count_mod(k)
        rules[f"w_count_mod_{k}"] = rule_w_count_mod(k)
        rules[f"w_segment_mod_{k}"] = rule_w_segment_index_mod(k)
        rules[f"dist_to_w_mod_{k}"] = rule_distance_to_nearest_w_mod(k)
        rules[f"pos_in_w_seg_mod_{k}"] = rule_pos_in_current_w_segment_mod(k)
    for L in [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]:
        for k in [2, 3, 4, 5, 6]:
            rules[f"pos_div_{L}_mod_{k}"] = rule_pos_div_L_mod_k(L, k)
    return rules


def check_rule_validity(rule_values: list[int], cribs: list[tuple],
                         edges: set[tuple[int, int]]) -> tuple[bool, int]:
    """Return (is_valid, n_violations). is_valid iff no conflict edge connects
    two cribs with the same rule_value at their positions."""
    crib_colors = [rule_values[pos] for (pos, _, _) in cribs]
    violations = 0
    for (u, v) in edges:
        if crib_colors[u] == crib_colors[v]:
            violations += 1
    return (violations == 0, violations)


def main() -> int:
    cribs = build_crib_constraints()
    edges: set[tuple[int, int]] = set()
    for i in range(len(cribs)):
        for j in range(i + 1, len(cribs)):
            if cribs_conflict(cribs[i], cribs[j]):
                edges.add((i, j))

    print(f"K4 conflict graph: {len(cribs)} cribs, {len(edges)} conflict edges")
    print(f"Chromatic number χ = 3 (from exp 035)")
    print()

    rules = build_rules()
    print(f"Rules tested: {len(rules)}")

    # For each rule, determine k = max(rule_values)+1 (effective number of colors)
    # and check validity against conflict graph
    print()
    print("=" * 100)
    print(f"{'Rule':40s}  {'k':>3}  {'violations':>10}  valid?")
    print("=" * 100)

    valid_rules: list[tuple[str, int, list[int]]] = []
    for name, vals in rules.items():
        k_used = max(vals) + 1
        is_valid, n_viol = check_rule_validity(vals, cribs, edges)
        marker = " ✓" if is_valid else ""
        if is_valid or n_viol <= 3:
            print(f"{name:40s}  {k_used:>3}  {n_viol:>10}{marker}")
        if is_valid:
            valid_rules.append((name, k_used, vals))

    print()
    print(f"=== Found {len(valid_rules)} valid rules ===")
    if valid_rules:
        for name, k_used, vals in valid_rules:
            crib_colors = [vals[pos] for (pos, _, _) in cribs]
            # Group crib positions by color
            by_color: dict[int, list[int]] = {}
            for crib_idx, (pos, p, c) in enumerate(cribs):
                color = crib_colors[crib_idx]
                by_color.setdefault(color, []).append(pos)
            print()
            print(f"  Rule: {name} (k_effective={k_used})")
            for color in sorted(by_color):
                positions = by_color[color]
                print(f"    Color {color}: {len(positions)} crib positions: {positions}")
            print(f"    Full 97-position rule values: {vals}")

    out_path = Path("experiments/results/2026-05-23_036_rule_compatibility.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "n_cribs": len(cribs),
        "n_edges": len(edges),
        "chromatic_number": 3,
        "n_rules_tested": len(rules),
        "valid_rules": [
            {"name": name, "k_used": k, "values": vals}
            for name, k, vals in valid_rules
        ],
    }, indent=2))

    print()
    print(f"Output: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
