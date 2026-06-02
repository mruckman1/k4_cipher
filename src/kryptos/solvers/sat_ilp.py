"""SAT / CP formulations of cipher-structure recovery (CP-SAT, OR-Tools).

The decisive structural question for the per-position-substitution
hypothesis is: given a candidate plaintext P and the ciphertext C, what is
the minimum number of distinct alphabets (colours) a per-position cipher
needs to map P->C? That is the chromatic number of the conflict graph where
positions i,j conflict iff (P_i==P_j) XOR (C_i==C_j). A k-alphabet cipher
(under ANY selection rule) exists iff that graph is k-colourable.

`min_alphabets_for` returns the exact chromatic number (alphabets needed);
`is_k_colorable` decides a single k. Used by experiment 055 to prune the
N1 candidate prior to those structurally admissible at K4's hypothesised k.
A cheap lower bound (`fanout`) precedes the solver.
"""

from __future__ import annotations

from collections.abc import Iterable


def fanout(plaintext: str, ciphertext: str) -> int:
    """Max over plaintext letters of #distinct ciphertext letters it maps
    to. A hard lower bound on the alphabets a per-position cipher needs."""
    by_letter: dict[str, set] = {}
    for p, c in zip(plaintext, ciphertext):
        by_letter.setdefault(p, set()).add(c)
    return max((len(s) for s in by_letter.values()), default=1)


def conflict_edges(plaintext: str, ciphertext: str) -> list[tuple[int, int]]:
    edges = []
    n = min(len(plaintext), len(ciphertext))
    for i in range(n):
        for j in range(i + 1, n):
            if (plaintext[i] == plaintext[j]) != (ciphertext[i] == ciphertext[j]):
                edges.append((i, j))
    return edges


def is_k_colorable(plaintext: str, ciphertext: str, k: int, time_limit: float = 3.0) -> bool:
    """True iff a k-alphabet per-position substitution can map P->C."""
    from ortools.sat.python import cp_model
    edges = conflict_edges(plaintext, ciphertext)
    n = min(len(plaintext), len(ciphertext))
    m = cp_model.CpModel()
    col = [m.NewIntVar(0, k - 1, f"c{i}") for i in range(n)]
    for u, v in edges:
        m.Add(col[u] != col[v])
    m.Add(col[0] == 0)
    s = cp_model.CpSolver()
    s.parameters.max_time_in_seconds = time_limit
    s.parameters.num_search_workers = 4
    return s.Solve(m) in (cp_model.OPTIMAL, cp_model.FEASIBLE)


def min_alphabets_for(plaintext: str, ciphertext: str, kmax: int = 26) -> int:
    """Exact minimum alphabets (chromatic number of the conflict graph)."""
    lb = fanout(plaintext, ciphertext)
    for k in range(lb, kmax + 1):
        if is_k_colorable(plaintext, ciphertext, k):
            return k
    return kmax + 1


def recover_coloring(plaintext: str, ciphertext: str, k: int, time_limit: float = 5.0):
    """Return a valid k-colouring (list of colour per position) of the
    conflict graph, or None. Each colour is one alphabet; positions sharing
    a colour are mutually crib-consistent (extendable to one permutation)."""
    from ortools.sat.python import cp_model
    edges = conflict_edges(plaintext, ciphertext)
    n = min(len(plaintext), len(ciphertext))
    m = cp_model.CpModel()
    col = [m.NewIntVar(0, k - 1, f"c{i}") for i in range(n)]
    for u, v in edges:
        m.Add(col[u] != col[v])
    m.Add(col[0] == 0)
    s = cp_model.CpSolver()
    s.parameters.max_time_in_seconds = time_limit
    s.parameters.num_search_workers = 4
    if s.Solve(m) in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        return [s.Value(c) for c in col]
    return None


def build_vigenere_sat(ciphertext: str, key_length: int, cribs: Iterable) -> object:
    raise NotImplementedError("periodic-Vigenere SAT superseded by the consistency propagator")


def build_gromark_ilp(ciphertext: str, alphabet, cribs: Iterable) -> object:
    raise NotImplementedError("Gromark primer ILP not needed; see consistency propagator")
