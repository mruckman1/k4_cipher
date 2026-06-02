"""Independent re-derivation of K4's load-bearing structural results.

This is the "independent re-derivation protocol" referenced in the paper's Methods
section. It recomputes, from the raw public inputs ONLY -- the K4 ciphertext and the
four released cribs, hard-coded below, with NO import of the repository's own
analysis code (in particular it re-implements the graph colouring from scratch
rather than calling experiments/035) -- every load-bearing quantity the paper relies
on, and asserts each against the value the paper claims:

  * the bijective and homophonic crib-conflict chromatic numbers (chi = 3, chi_b = 2)
    and the type-a / type-b edge counts (12 / 10);
  * the proper-colouring counts: 512 structural and 16,384 total 2-colourings of the
    type-(b) graph, and 23,887,872 proper 3-colourings of the bijective graph;
  * the selector-coupling decomposition (30 selector-locked / 43 prior-governed);
  * the under-determination consensus floor: max per-position consensus 0.50, with
    all 30 selector-locked positions at exactly 0.50, none above, and a
    guaranteed-determined floor of 0.

Run: `python scripts/rederive_load_bearing.py`  (pure stdlib, deterministic, <1s).
Exits 0 with "ALL ... RE-DERIVED AND MATCH THE PAPER." iff every assertion holds.
"""
from collections import defaultdict
from itertools import product

# ---- raw public inputs (the only inputs) ----
K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4) == 97
CRIBS = [("EAST", 22), ("NORTHEAST", 26), ("BERLIN", 64), ("CLOCK", 70)]  # (plaintext, 1-indexed start)

# ---- 24 crib nodes: (position, plaintext_letter, ciphertext_letter) ----
nodes = []
for pt, start in CRIBS:
    for i, ch in enumerate(pt):
        pos = start + i
        nodes.append((pos, ch, K4[pos - 1]))
assert len(nodes) == 24
crib_positions = {pos for pos, _, _ in nodes}
N = len(nodes)

# ---- conflict graph (disjoint edge types) ----
type_a, type_b = set(), set()  # a: same plaintext, diff ciphertext (bijection-only)
for i in range(N):                                       # b: same ciphertext, diff plaintext (any function)
    for j in range(i + 1, N):
        _, pi, ci = nodes[i]
        _, pj, cj = nodes[j]
        if pi == pj and ci != cj:
            type_a.add((i, j))
        elif ci == cj and pi != pj:
            type_b.add((i, j))
print(f"edges: type-a={len(type_a)}, type-b={len(type_b)}, total={len(type_a)+len(type_b)}")
assert len(type_a) == 12 and len(type_b) == 10 and len(type_a) + len(type_b) == 22

full_edges = type_a | type_b


def adjacency(edges):
    a = {i: set() for i in range(N)}
    for u, v in edges:
        a[u].add(v)
        a[v].add(u)
    return a


# ---- chromatic number from scratch (backtracking feasibility, most-constrained first) ----
def k_colorable(edges, k):
    a = adjacency(edges)
    color = [-1] * N
    order = sorted(range(N), key=lambda x: -len(a[x]))

    def bt(idx):
        if idx == N:
            return True
        v = order[idx]
        for c in range(k):
            if all(color[u] != c for u in a[v]):
                color[v] = c
                if bt(idx + 1):
                    return True
                color[v] = -1
        return False

    return bt(0)


def chromatic_number(edges):
    return next(k for k in range(1, N + 1) if k_colorable(edges, k))


chi_full = chromatic_number(full_edges)
chi_b = chromatic_number(type_b)
print(f"chromatic numbers: chi_full={chi_full}, chi_b={chi_b}")
assert chi_full == 3 and chi_b == 2

# ---- connected components ----
def components(edges):
    a = adjacency(edges)
    seen, comps = set(), []
    for s in range(N):
        if s in seen:
            continue
        stack, comp = [s], []
        while stack:
            x = stack.pop()
            if x in seen:
                continue
            seen.add(x)
            comp.append(x)
            stack.extend(a[x] - seen)
        comps.append(comp)
    return comps


# ---- count proper k-colourings: tree formula k(k-1)^(t-1), brute force for cyclic ----
def _brute_count(comp, ein, k):
    a = {i: set() for i in comp}
    for u, v in ein:
        a[u].add(v)
        a[v].add(u)
    color, cnt = {}, 0

    def bt(idx):
        nonlocal cnt
        if idx == len(comp):
            cnt += 1
            return
        v = comp[idx]
        for c in range(k):
            if all(color.get(u) != c for u in a[v]):
                color[v] = c
                bt(idx + 1)
                del color[v]

    bt(0)
    return cnt


def count_proper_colorings(edges, k, edge_bearing_only=False):
    eset, total = set(edges), 1
    for comp in components(edges):
        cs = set(comp)
        ein = [(u, v) for (u, v) in eset if u in cs and v in cs]
        if edge_bearing_only and not ein:
            continue
        t, m = len(comp), len(ein)
        total *= k * (k - 1) ** (t - 1) if m == t - 1 else _brute_count(comp, ein, k)
    return total


b_structural = count_proper_colorings(type_b, 2, edge_bearing_only=True)
b_total = count_proper_colorings(type_b, 2)
full_3 = count_proper_colorings(full_edges, 3)
print(f"colourings: 2-col structural={b_structural}, total={b_total}; bijective 3-col={full_3}")
assert b_structural == 512 and b_total == 16384 and full_3 == 23887872

# ---- selector-coupling decomposition ----
crib_ct = {c for _, _, c in nodes}
free_positions = [p for p in range(1, 98) if p not in crib_positions]
assert len(free_positions) == 73
locked = [p for p in free_positions if K4[p - 1] in crib_ct]
prior = [p for p in free_positions if K4[p - 1] not in crib_ct]
print(f"decomposition: selector-locked={len(locked)}, prior-governed={len(prior)}")
assert len(locked) == 30 and len(prior) == 43

# ---- consensus floor: enumerate all proper 2-colourings x both selector branches ----
def component_2colorings(comp, ein):
    a = {i: set() for i in comp}
    for u, v in ein:
        a[u].add(v)
        a[v].add(u)
    out, color = [], {}

    def bt(idx):
        if idx == len(comp):
            out.append(dict(color))
            return
        v = comp[idx]
        for c in (0, 1):
            if all(color.get(u) != c for u in a[v]):
                color[v] = c
                bt(idx + 1)
                del color[v]

    bt(0)
    return out


eset_b = set(type_b)
per_comp = [component_2colorings(comp, [(u, v) for (u, v) in eset_b if u in set(comp) and v in set(comp)])
            for comp in components(type_b)]

votes = {p: defaultdict(int) for p in free_positions}
n_col = 0
for combo in product(*per_comp):
    assign = {}
    for d in combo:
        assign.update(d)
    n_col += 1
    chart = [dict(), dict()]                       # chart[bit][ciphertext] = plaintext
    for idx, (pos, pt, ct) in enumerate(nodes):
        chart[assign[idx]][ct] = pt                # proper colouring => no same-ct/diff-pt collision in a chart
    for p in free_positions:
        ct = K4[p - 1]
        for s in (0, 1):
            if ct in chart[s]:
                votes[p][chart[s][ct]] += 1
assert n_col == 16384
denom = 2 * n_col
consensus = {p: (max(votes[p].values()) / denom if votes[p] else 0.0) for p in free_positions}
max_c = max(consensus.values())
n_half = sum(1 for p in free_positions if abs(consensus[p] - 0.5) < 1e-9)
n_above = sum(1 for p in free_positions if consensus[p] > 0.5 + 1e-9)
guaranteed = sum(1 for p in free_positions if any(v == denom for v in votes[p].values()))
print(f"consensus: max={max_c}, at 0.50={n_half}, above 0.50={n_above}, guaranteed-determined={guaranteed}")
assert abs(max_c - 0.5) < 1e-9 and n_half == 30 and n_above == 0 and guaranteed == 0

print("\nALL LOAD-BEARING QUANTITIES RE-DERIVED FROM THE RAW CRIBS AND MATCH THE PAPER.")
