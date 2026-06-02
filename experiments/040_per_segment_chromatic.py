"""040 — Move D: per-W-segment chromatic number analysis.

For each W-segment, compute the chromatic number of the IN-SEGMENT
conflict graph. This distinguishes:

  (i) "Global χ=3 with rotation respecting segments" — per-segment χ
       could be < 3 if segments have weaker internal constraints
  (ii) "Per-segment ≥3 alphabets each" — per-segment χ already 3 in
       at least one segment (the cipher uses all 3 alphabets within
       each cribbed segment)

Segments:
  Seg 0:  positions  0-19 (no cribs)
  Seg 1:  positions 21-35 (13 cribs: EAST + NORTHEAST)
  Seg 2:  positions 37-47 (no cribs)
  Seg 3:  positions 49-57 (no cribs)
  Seg 4:  positions 59-73 (11 cribs: BERLIN + CLOCK)
  Seg 5:  positions 75-96 (no cribs)

Output: experiments/results/2026-05-23_040_per_segment_chromatic.json
"""

from __future__ import annotations

import json
from pathlib import Path

from kryptos.constants import K4
from kryptos.cribs import CRIBS

K4_TEXT = K4
N = 97
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


def has_k_coloring(n: int, edges: set[tuple[int, int]], k: int) -> bool:
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


def chromatic_number(n: int, edges: set[tuple[int, int]]) -> int:
    if n == 0:
        return 0
    for k in range(1, n + 1):
        if has_k_coloring(n, edges, k):
            return k
    return n


def main():
    cribs = crib_constraints()

    # Define segments
    boundaries = [-1] + W_POSITIONS + [N]
    segments = []
    for s in range(len(boundaries) - 1):
        lo = boundaries[s] + 1
        hi = boundaries[s + 1]
        segments.append((s, lo, hi - 1, list(range(lo, hi))))

    print(f"K4 W-segments:")
    for (s, lo, hi, positions) in segments:
        print(f"  Seg {s}: positions {lo:>2}..{hi:>2} (len {hi-lo+1})")

    results = {}
    for (s, lo, hi, positions) in segments:
        seg_cribs = [(pos, p, c) for (pos, p, c) in cribs if lo <= pos <= hi]
        seg_n = len(seg_cribs)
        edges = set()
        for i in range(seg_n):
            for j in range(i + 1, seg_n):
                if cribs_conflict(seg_cribs[i], seg_cribs[j]):
                    edges.add((i, j))
        seg_chi = chromatic_number(seg_n, edges)
        print(f"\nSeg {s}: {seg_n} cribs, {len(edges)} internal conflict edges, χ = {seg_chi}")
        if seg_cribs:
            # Show the conflicts
            for crib_idx, (pos, p, c) in enumerate(seg_cribs):
                print(f"  [{crib_idx}] pos {pos+1:>3}: {p}→{c}")
            if edges:
                print(f"  Conflict edges (forced different alphabets):")
                for (u, v) in sorted(edges):
                    pu, ppu, cpu = seg_cribs[u]
                    pv, ppv, cpv = seg_cribs[v]
                    reason = ""
                    if ppu == ppv and cpu != cpv:
                        reason = f"same plain {ppu}, different cipher"
                    elif cpu == cpv and ppu != ppv:
                        reason = f"same cipher {cpu}, different plain"
                    print(f"    {ppu}→{cpu} (pos {pu+1}) ↔ {ppv}→{cpv} (pos {pv+1})  [{reason}]")

        results[f"seg_{s}"] = {
            "lo": lo, "hi": hi,
            "n_cribs": seg_n,
            "n_internal_conflict_edges": len(edges),
            "chromatic_number": seg_chi,
        }

    # Compare with global
    global_edges = set()
    for i in range(len(cribs)):
        for j in range(i + 1, len(cribs)):
            if cribs_conflict(cribs[i], cribs[j]):
                global_edges.add((i, j))
    global_chi = 3   # known from exp 035
    print()
    print(f"=== Summary ===")
    print(f"  Global χ:               {global_chi}")
    print(f"  Seg 1 χ (EAST+NORTH):   {results['seg_1']['chromatic_number']}")
    print(f"  Seg 4 χ (BERLIN+CLOCK): {results['seg_4']['chromatic_number']}")
    print(f"  Other segs χ:           {results['seg_0']['chromatic_number']}, "
          f"{results['seg_2']['chromatic_number']}, "
          f"{results['seg_3']['chromatic_number']}, "
          f"{results['seg_5']['chromatic_number']}  (no cribs)")
    print()
    seg1_chi = results['seg_1']['chromatic_number']
    seg4_chi = results['seg_4']['chromatic_number']
    if max(seg1_chi, seg4_chi) >= global_chi:
        print(f"FINDING: per-segment χ ≥ global χ, so cross-segment conflicts")
        print(f"add no extra constraints. The cipher uses all {global_chi} alphabets")
        print(f"WITHIN segment 1 (which needs χ={seg1_chi}); segment 4 needs only χ={seg4_chi}.")
        print(f"This means alphabets ROTATE WITHIN each cribbed segment, not")
        print(f"per-segment-locked.")
    else:
        print(f"FINDING: cross-segment conflicts increase χ from "
              f"max(seg1={seg1_chi}, seg4={seg4_chi})={max(seg1_chi, seg4_chi)} "
              f"to global={global_chi}. There exist conflict edges BETWEEN segments.")

    out_path = Path("experiments/results/2026-05-23_040_per_segment_chromatic.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "global_chromatic_number": global_chi,
        "per_segment": results,
    }, indent=2))
    print(f"\nOutput: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
