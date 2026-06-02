"""Crib-satisfaction set-cover solver for per-position substitution ciphers.

Given a pool of candidate alphabets (26-char permutations, exp-035
convention: plain STANDARD index pi -> cipher letter alpha[pi]) and a
budget k, decide whether some k of them jointly satisfy ALL 24 K4 cribs,
with each crib assigned to one covering alphabet.

Key observation: if a single permutation covers two cribs, those cribs
cannot conflict (a permutation is single-valued at each index), so the
χ=3 colouring constraint is satisfied automatically. The problem is
therefore exact SET COVER: choose <=k alphabets whose union of covered
distinct (plain_idx -> cipher_idx) constraints equals all of them.

Small pools (tens to low hundreds) at k<=4 are solved by direct
combinatorial search over covered-constraint bitmasks.
"""

from __future__ import annotations

from itertools import combinations

from kryptos.cribs import CRIBS


def crib_constraints() -> list[tuple[int, int]]:
    """Distinct (plain_idx, cipher_idx) constraints from the 24 cribs
    (STANDARD index space). Duplicate (pi,ci) pairs collapse; a plain
    letter mapping to two ciphers yields two constraints."""
    cons: set[tuple[int, int]] = set()
    for c in CRIBS:
        for p, ch in zip(c.plaintext, c.ciphertext):
            cons.add((ord(p) - 65, ord(ch) - 65))
    return sorted(cons)


def covered_mask(alpha: str, constraints: list[tuple[int, int]]) -> int:
    """Bitmask over `constraints` that this alphabet satisfies."""
    m = 0
    for bit, (pi, ci) in enumerate(constraints):
        if ord(alpha[pi]) - 65 == ci:
            m |= (1 << bit)
    return m


def find_cover(pool: list[tuple[str, str]], k: int):
    """Return (labels, assignment) for the first <=k alphabets covering all
    constraints, else None. `assignment` maps each constraint to a chosen
    alphabet label."""
    cons = crib_constraints()
    full = (1 << len(cons)) - 1
    masks = [(label, covered_mask(s, cons)) for label, s in pool]
    # Prune alphabets that cover nothing.
    masks = [(lb, m) for lb, m in masks if m]
    # Greedy single-alphabet shortcut.
    for size in range(1, k + 1):
        for combo in combinations(masks, size):
            union = 0
            for _, m in combo:
                union |= m
            if union == full:
                labels = [lb for lb, _ in combo]
                assignment = {}
                for bit, c in enumerate(cons):
                    for lb, m in combo:
                        if m & (1 << bit):
                            assignment[c] = lb
                            break
                return labels, assignment
    return None


def best_partial_cover(pool: list[tuple[str, str]], k: int):
    """When no exact cover exists, return the k-subset covering the most
    constraints (count, labels)."""
    cons = crib_constraints()
    masks = [(label, covered_mask(s, cons)) for label, s in pool]
    masks = [(lb, m) for lb, m in masks if m]
    best = (0, [])
    for combo in combinations(masks, min(k, len(masks))):
        union = 0
        for _, m in combo:
            union |= m
        c = bin(union).count("1")
        if c > best[0]:
            best = (c, [lb for lb, _ in combo])
    return best[0], len(cons), best[1]


def greedy_cover(pool: list[tuple[str, str]]):
    """Greedy set cover: repeatedly take the alphabet covering the most
    still-uncovered constraints. Returns (k_used, labels, covered, total).
    k_used is an UPPER BOUND on the minimum number of alphabets needed."""
    cons = crib_constraints()
    full = (1 << len(cons)) - 1
    masks = [(label, covered_mask(s, cons)) for label, s in pool]
    masks = [(lb, m) for lb, m in masks if m]
    covered = 0
    chosen: list[str] = []
    while covered != full and masks:
        lb, m = max(masks, key=lambda x: bin(x[1] & ~covered).count("1"))
        gain = bin(m & ~covered).count("1")
        if gain == 0:
            break
        covered |= m
        chosen.append(lb)
    return len(chosen), chosen, bin(covered).count("1"), len(cons)


if __name__ == "__main__":
    cons = crib_constraints()
    print(f"{len(cons)} distinct crib constraints")
