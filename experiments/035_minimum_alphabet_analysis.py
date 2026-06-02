"""035 — Minimum-alphabet structural analysis from the 24 K4 cribs.

Goal: derive the MINIMUM number of distinct alphabet permutations that any
per-position-substitution cipher must use to satisfy all 24 cribs,
regardless of where those alphabets come from (natural keywords or
hand-crafted). This is a constraint-satisfaction / graph-coloring result.

For a per-position substitution cipher with alphabets {A_1, ..., A_k}
(each a permutation of A-Z) and a selection rule R(i) → {1..k}, the
crib at position p with plaintext P and ciphertext C requires:

    A_{R(p)}[STANDARD.index(P)] = C

Two cribs (p1, P1, C1) and (p2, P2, C2) are MUTUALLY EXCLUSIVE under
a single alphabet iff:
  - P1 == P2 and C1 != C2 (same plain index needs two different cipher letters), OR
  - C1 == C2 and P1 != P2 (same cipher letter needs to appear at two different indices)

We build the "crib conflict graph" with 24 nodes (cribs) and an edge
between any two mutually-exclusive cribs. The minimum number of
alphabets needed is the CHROMATIC NUMBER of this graph (each color =
one alphabet, no two conflicting cribs share a color).

After computing chromatic_number = k_min, we enumerate proper colorings
(partitions of 24 cribs into k_min groups). For each coloring, each
group's cribs determine a partial alphabet permutation (24/k_min ≈ 8
fixed positions per alphabet, leaving ~18 free). For each group, check
whether any NATURAL keyword in our pool produces an alphabet that
matches all the group's constraints. If yes, that group can be
realized by a known keyword. If no, the group requires a hand-crafted
alphabet (the analyst's hypothesis (ii) / (iii)).

Output:
  - conflict graph structure
  - chromatic number k_min
  - per-color partial alphabet constraints
  - per-color keyword matches (if any)
  - per-color "hand-crafted required" flag
"""

from __future__ import annotations

import json
import itertools
import time
from pathlib import Path

from kryptos.alphabets import STANDARD, keyed_alphabet
from kryptos.cribs import CRIBS


def build_crib_constraints() -> list[tuple[int, str, str, int, int]]:
    """Each crib: (pos_0idx, plain_letter, cipher_letter, plain_idx, cipher_idx)."""
    out = []
    for c in CRIBS:
        for offset, (p, c_) in enumerate(zip(c.plaintext, c.ciphertext)):
            pos = c.start - 1 + offset
            out.append((pos, p, c_, ord(p) - 65, ord(c_) - 65))
    return out


def cribs_conflict(c1, c2) -> bool:
    """Two cribs conflict iff they can't be satisfied by the same alphabet.
    A permutation has each letter exactly once → can't have:
      (a) same plain index → different cipher letters (P1==P2, C1!=C2)
      (b) different plain indices → same cipher letter (P1!=P2, C1==C2)"""
    _, p1, c1c, pi1, ci1 = c1
    _, p2, c2c, pi2, ci2 = c2
    if pi1 == pi2 and ci1 != ci2:
        return True
    if ci1 == ci2 and pi1 != pi2:
        return True
    return False


def chromatic_number(n: int, edges: set[tuple[int, int]]) -> int:
    """Smallest k such that nodes 0..n-1 can be colored with k colors
    where no two adjacent nodes share a color. Brute force over small k."""
    for k in range(1, n + 1):
        if has_k_coloring(n, edges, k):
            return k
    return n


def has_k_coloring(n: int, edges: set[tuple[int, int]], k: int) -> bool:
    """Backtracking coloring check."""
    colors = [-1] * n
    adj = [set() for _ in range(n)]
    for u, v in edges:
        adj[u].add(v)
        adj[v].add(u)

    def backtrack(i: int) -> bool:
        if i == n:
            return True
        forbidden = {colors[j] for j in adj[i] if colors[j] != -1}
        for c in range(k):
            if c not in forbidden:
                colors[i] = c
                if backtrack(i + 1):
                    return True
                colors[i] = -1
        return False

    return backtrack(0)


def find_k_coloring(n: int, edges: set[tuple[int, int]], k: int) -> list[int] | None:
    """Return ONE valid k-coloring as a list of color assignments, or None."""
    colors = [-1] * n
    adj = [set() for _ in range(n)]
    for u, v in edges:
        adj[u].add(v)
        adj[v].add(u)

    def backtrack(i: int) -> bool:
        if i == n:
            return True
        forbidden = {colors[j] for j in adj[i] if colors[j] != -1}
        for c in range(k):
            if c not in forbidden:
                colors[i] = c
                if backtrack(i + 1):
                    return True
                colors[i] = -1
        return False

    if backtrack(0):
        return colors
    return None


def build_alphabet_pool() -> list[tuple[str, str]]:
    """Larger keyword pool than exp 033's, used for matching colorings to known keywords."""
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
        "CIPHER", "SECRET", "MESSAGE", "HIDDEN", "PUZZLE", "SCHEME",
        # Numbers as letters
        "ZERO", "ONE", "TWO", "THREE", "FOUR", "FIVE", "SIX",
        "SEVEN", "EIGHT", "NINE", "TEN",
        # Sanborn-context places & ideas
        "BERLIN_REV", "EGYPT_REV", "KRYPTOS_REV",
        # Additional Cold War references
        "STASI", "GLASNOST", "PERESTROIKA", "DETENTE",
    ]
    pool: list[tuple[str, str]] = [("STANDARD", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")]
    seen: set[str] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ"}
    for kw in keywords:
        try:
            if kw.endswith("_REV"):
                base = kw[:-4]
                ka = keyed_alphabet(base)
                a = ka.letters[::-1]
                label = kw
            else:
                ka = keyed_alphabet(kw)
                a = ka.letters
                label = kw
            if a in seen:
                continue
            pool.append((label, a))
            seen.add(a)
        except Exception:
            continue
    return pool


def alphabet_satisfies(alphabet: str, cribs: list[tuple]) -> bool:
    """Check that the given alphabet satisfies all given cribs."""
    for (_pos, _p, _c, pi, ci) in cribs:
        if ord(alphabet[pi]) - 65 != ci:
            return False
    return True


def alphabet_matches_count(alphabet: str, cribs: list[tuple]) -> int:
    """Number of cribs the alphabet satisfies."""
    return sum(1 for (_, _, _, pi, ci) in cribs if ord(alphabet[pi]) - 65 == ci)


def main() -> int:
    cribs = build_crib_constraints()
    print(f"K4 cribs (24 positions):")
    for i, (pos, p, c, _pi, _ci) in enumerate(cribs):
        print(f"  [{i:2d}] pos {pos+1:>3} (0-idx {pos:>3}): {p} → {c}")

    # Build conflict graph
    edges: set[tuple[int, int]] = set()
    for i in range(len(cribs)):
        for j in range(i + 1, len(cribs)):
            if cribs_conflict(cribs[i], cribs[j]):
                edges.add((i, j))
    print(f"\nConflict graph: {len(cribs)} nodes, {len(edges)} edges")

    # Report conflict structure: which plain letters appear with multiple ciphers,
    # which cipher letters appear from multiple plain letters
    from collections import defaultdict
    plain_to_ciphers: dict[str, set[str]] = defaultdict(set)
    cipher_to_plains: dict[str, set[str]] = defaultdict(set)
    for (_pos, p, c, _, _) in cribs:
        plain_to_ciphers[p].add(c)
        cipher_to_plains[c].add(p)

    print(f"\nPlain letters with multiple cipher mappings (forces ≥ N alphabets):")
    for p in sorted(plain_to_ciphers):
        if len(plain_to_ciphers[p]) > 1:
            print(f"  {p}: {sorted(plain_to_ciphers[p])} ({len(plain_to_ciphers[p])} distinct)")

    print(f"\nCipher letters from multiple plain letters (Q letter needs N alphabets):")
    for c in sorted(cipher_to_plains):
        if len(cipher_to_plains[c]) > 1:
            print(f"  → {c}: from plain {sorted(cipher_to_plains[c])} ({len(cipher_to_plains[c])} distinct)")

    # Compute chromatic number
    print(f"\nComputing chromatic number of conflict graph ...")
    t0 = time.perf_counter()
    k_min = chromatic_number(len(cribs), edges)
    print(f"  CHROMATIC NUMBER = {k_min}  (minimum alphabets needed = {k_min})")
    print(f"  elapsed: {time.perf_counter()-t0:.2f}s")

    # Find one valid k_min-coloring
    coloring = find_k_coloring(len(cribs), edges, k_min)
    if not coloring:
        print("  ERROR: no coloring found despite chromatic number computed")
        return 1

    print(f"\nOne valid {k_min}-coloring (partitions cribs into {k_min} alphabets):")
    color_groups: dict[int, list[int]] = {}
    for i, c in enumerate(coloring):
        color_groups.setdefault(c, []).append(i)
    for color in sorted(color_groups):
        cribs_in_color = color_groups[color]
        constraints = []
        for ci in cribs_in_color:
            pos, p, c, _, _ = cribs[ci]
            constraints.append(f"pos{pos+1}:{p}→{c}")
        print(f"  Alpha {color}: {len(cribs_in_color)} cribs: {' '.join(constraints)}")

    # For each color, derive the partial alphabet constraints and check
    # if any natural keyword satisfies them
    print(f"\n=== Per-color alphabet constraints + keyword matches ===")
    pool = build_alphabet_pool()
    print(f"Pool: {len(pool)} candidate alphabets\n")

    for color in sorted(color_groups):
        cribs_in_color = [cribs[i] for i in color_groups[color]]
        # Derive constraints: alphabet[plain_idx] = cipher_letter
        constraints: dict[int, str] = {}
        for (_pos, p, c, pi, _ci) in cribs_in_color:
            constraints[pi] = c
        print(f"--- Alpha {color}: {len(cribs_in_color)} cribs, "
              f"{len(constraints)} fixed alphabet positions ---")
        for pi, c in sorted(constraints.items()):
            print(f"  alphabet[{pi:2d}] = {c}  (plain {chr(pi+65)} → cipher {c})")

        # Find keywords whose alphabet satisfies ALL constraints
        full_matches = []
        partial_matches = []
        for label, alpha in pool:
            n_match = sum(1 for pi, c in constraints.items() if alpha[pi] == c)
            if n_match == len(constraints):
                full_matches.append(label)
            elif n_match >= len(constraints) - 1 and len(constraints) > 2:
                partial_matches.append((n_match, label))
        if full_matches:
            print(f"  ★ FULL MATCH keywords: {full_matches}")
        else:
            print(f"  No natural keyword in pool fully matches this alpha's constraints.")
            print(f"  Top 5 partial matches:")
            scored = sorted(((sum(1 for pi, c in constraints.items() if alpha[pi] == c), label)
                             for label, alpha in pool), reverse=True)
            for n_match, label in scored[:5]:
                print(f"    {n_match}/{len(constraints)}: {label}")
        print()

    out_path = Path("experiments/results/2026-05-23_035_minimum_alphabet_analysis.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    summary = {
        "n_cribs": len(cribs),
        "n_conflict_edges": len(edges),
        "chromatic_number_min_alphabets": k_min,
        "coloring": coloring,
        "color_groups": {str(c): [cribs[i] for i in indices]
                         for c, indices in color_groups.items()},
        "pool_size": len(pool),
    }
    # Serialize with default=str to handle non-JSON types
    out_path.write_text(json.dumps(summary, indent=2, default=str))

    print(f"\nSummary written to {out_path}")
    print(f"\n=== Key result ===")
    print(f"K4's cipher needs AT LEAST {k_min} distinct alphabet permutations.")
    print(f"Per-group keyword matches above show which (if any) are realizable")
    print(f"by natural Sanborn keywords; the rest must be hand-crafted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
