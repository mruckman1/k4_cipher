"""Geometric "route" alphabets derived from the physical KRYPTOS tableau.

The χ=3 structural ruling (exp 035) proved K4 needs >=3 distinct alphabet
permutations, and exps 036/037 proved they are NOT keyword-derived. The
hypothesis here: the hand-crafted alphabets are geometric reading-paths
through the 26x26 KRYPTOS Vigenere tableau Sanborn physically built --
rows, columns, diagonals, columnar-route reads, boustrophedon -- which are
non-arbitrary yet not "keyed by a word".

A route alphabet is returned as a 26-char string `s` interpreted under the
exp-035 substitution convention: a plaintext letter with STANDARD index
`pi` encrypts to `s[pi]`. Only genuine permutations of A-Z are returned
(many tableau routes are degenerate on a circulant square and are dropped).
"""

from __future__ import annotations

from math import gcd

from kryptos.alphabets import KRYPTOS_KEYED, STANDARD

KEYED = KRYPTOS_KEYED.letters          # "KRYPTOSABCDEFGHIJLMNQUVWXZ"
STD = STANDARD.letters                  # "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
N = 26


def _is_perm(s: str) -> bool:
    return len(s) == N and len(set(s)) == N and set(s) == set(STD)


def _rotations(base: str) -> list[tuple[str, str]]:
    return [(f"rot{r}[{base[:3]}]", base[r:] + base[:r]) for r in range(N)]


def _columnar_reads(base: str) -> list[tuple[str, str]]:
    """Write `base` row-major into a width-w grid, read column-major.
    A length-preserving route transposition of the alphabet itself."""
    out: list[tuple[str, str]] = []
    for w in range(2, 14):
        rows = (N + w - 1) // w
        cells: list[str] = []
        for col in range(w):
            for row in range(rows):
                idx = row * w + col
                if idx < N:
                    cells.append(base[idx])
        s = "".join(cells)
        if _is_perm(s):
            out.append((f"col{w}[{base[:3]}]", s))
    return out


def _boustrophedon(base: str) -> list[tuple[str, str]]:
    """Write into width-w grid, read column-major but reverse alternate
    columns (a serpentine route)."""
    out: list[tuple[str, str]] = []
    for w in range(2, 14):
        rows = (N + w - 1) // w
        cells: list[str] = []
        for col in range(w):
            col_cells = [base[row * w + col] for row in range(rows) if row * w + col < N]
            if col % 2 == 1:
                col_cells = col_cells[::-1]
            cells.extend(col_cells)
        s = "".join(cells)
        if _is_perm(s):
            out.append((f"bous{w}[{base[:3]}]", s))
    return out


def _diagonals(base: str) -> list[tuple[str, str]]:
    """Broken-diagonal reads of the circulant Vigenere tableau built on
    `base` (tableau[i][j] = base[(i+j) % 26]). A slope-s diagonal is a
    permutation iff gcd(s+1, 26) == 1."""
    out: list[tuple[str, str]] = []
    for s in range(1, N):
        if gcd(s + 1, N) != 1:
            continue
        cells = [base[((k + k * s) % N)] for k in range(N)]
        st = "".join(cells)
        if _is_perm(st):
            out.append((f"diag{s}[{base[:3]}]", st))
    return out


def route_alphabets() -> list[tuple[str, str]]:
    """Full deduplicated pool of geometric route alphabets."""
    pool: list[tuple[str, str]] = []
    seen: set[str] = set()
    bases = [("KEYED", KEYED), ("STD", STD),
             ("REVKEYED", KEYED[::-1]), ("REVSTD", STD[::-1])]
    for _, base in bases:
        for gen in (_rotations, _columnar_reads, _boustrophedon, _diagonals):
            for label, s in gen(base):
                if _is_perm(s) and s not in seen:
                    seen.add(s)
                    pool.append((label, s))
    return pool


if __name__ == "__main__":
    pool = route_alphabets()
    print(f"{len(pool)} distinct route alphabets")
    for label, s in pool[:12]:
        print(f"  {label:16} {s}")
