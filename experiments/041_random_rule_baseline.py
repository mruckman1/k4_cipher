"""041 — Random-rule baseline calibration.

Move B (exp 038) found 1,009 valid compound rules at k ∈ {3..8} where
0 conflict edges are violated. The minimum k achievable was 4 with
`(2 × pos_mod_3 + consonant_count) mod 4`.

But: 1,009 is a count without a baseline. The relevant question for
prior calibration is HOW RARE crib-satisfying colorings actually are.
If ~10% of random k=4 colorings satisfy the cribs (because the graph
has only 22 conflict edges and χ=3 leaves slack), then the natural
compound rule is unremarkable — it just landed in a populated region.

If random k=4 colorings satisfy cribs ~0.1% of the time, then the
natural compound rule is genuinely a discovery (compound rules
concentrate in the crib-satisfying region at a rate higher than
random).

This experiment generates 10,000 truly random R(i) → {0..k-1} (each
position assigned independently uniformly) and counts the fraction
that produce 0 violations on the conflict graph.

Output: experiments/results/2026-05-23_041_random_rule_baseline.json
"""

from __future__ import annotations

import json
import random
import time
from pathlib import Path

from kryptos.constants import K4
from kryptos.cribs import CRIBS


N = 97


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


def main():
    cribs = crib_constraints()
    edges = []
    for i in range(len(cribs)):
        for j in range(i + 1, len(cribs)):
            if cribs_conflict(cribs[i], cribs[j]):
                edges.append((i, j))
    print(f"Conflict graph: {len(cribs)} cribs, {len(edges)} edges")
    print()

    # Theoretical estimate: for each edge (u,v), P(same color) = 1/k under
    # uniform random. With 22 dependent edges, exact computation is hard but
    # under approximate independence, P(no violations) ≈ (1 - 1/k)^|E|.
    print("Theoretical estimates under uniform random k-coloring (independence approx):")
    for k in range(2, 10):
        p_approx = ((k - 1) / k) ** len(edges)
        print(f"  k={k}: P(no violations) ≈ {p_approx:.6f} = {p_approx*100:.3f}%")

    # Empirical: generate random colorings at each k
    n_trials = 10000
    rng = random.Random(42)
    print()
    print(f"Empirical sampling: {n_trials} random colorings per k")
    print()

    results = {}
    for k in [3, 4, 5, 6, 7, 8]:
        t0 = time.perf_counter()
        satisfied = 0
        # Track distribution of violation counts
        viol_dist = [0] * (len(edges) + 1)
        for _ in range(n_trials):
            coloring = [rng.randrange(k) for _ in range(N)]
            crib_colors = [coloring[pos] for (pos, _, _) in cribs]
            violations = sum(1 for (u, v) in edges if crib_colors[u] == crib_colors[v])
            viol_dist[violations] += 1
            if violations == 0:
                satisfied += 1
        elapsed = time.perf_counter() - t0
        rate = satisfied / n_trials
        # SE of rate
        se = (rate * (1 - rate) / n_trials) ** 0.5
        print(f"  k={k}: {satisfied:>5}/{n_trials} ({rate*100:.3f}% ± {se*100:.3f}%) "
              f"satisfy cribs  [{elapsed:.2f}s]")
        # Median # violations
        cum = 0
        median = None
        for vc in range(len(edges) + 1):
            cum += viol_dist[vc]
            if median is None and cum >= n_trials / 2:
                median = vc
        print(f"       median # violations: {median}, "
              f"distribution head: {viol_dist[:6]}")
        results[k] = {
            "n_trials": n_trials,
            "n_satisfied": satisfied,
            "rate": rate,
            "rate_se": se,
            "median_violations": median,
            "viol_dist_head": viol_dist[:10],
        }

    # Compare against Move B's compound-rule yield
    # Move B found 1,009 valid rules. Total tested ≈ Pass1 + Pass2 + Pass3 + Pass4
    # Pass 1: 12*11*6 = 792 lex compounds
    # Pass 2: 12*11*6 * 6*6 ≈ 28k linear compounds — but actually we only test
    #         (a,b) ∈ {1..k-1}², so 6 k-values × 12*11 features × ~5x5 (a,b) = ~20k
    # Pass 3: 12*11/2 * 6 = 396 XOR compounds
    # Pass 4: 12 * 10 * 2 = 240 wdist-tiebreaker rules
    # Rough total: ~25k natural compound rules tested
    n_natural_tested_estimate = 25000
    n_natural_valid = 1009
    natural_rate = n_natural_valid / n_natural_tested_estimate

    print()
    print("=" * 70)
    print("=== Comparison: compound natural rules vs random ===")
    print("=" * 70)
    print(f"  Compound natural rules tested in Move B (rough):  ~{n_natural_tested_estimate}")
    print(f"  Compound natural rules valid in Move B:           {n_natural_valid}")
    print(f"  Natural compound rule success rate:               ~{natural_rate*100:.2f}%")
    print()
    for k in [3, 4, 5, 6, 7, 8]:
        ratio = natural_rate / results[k]["rate"] if results[k]["rate"] > 0 else float('inf')
        print(f"  k={k}: natural rate / random rate = {natural_rate*100:.2f}% / "
              f"{results[k]['rate']*100:.3f}% = {ratio:.1f}x")
    print()
    print("Interpretation:")
    print("  - ratio >> 1: compound natural rules are concentrated in the valid region")
    print("  - ratio ≈ 1: compound rules succeed only because the valid region is large")
    print("  - ratio < 1: compound rules under-perform random (unlikely)")

    out_path = Path("experiments/results/2026-05-23_041_random_rule_baseline.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "n_cribs": len(cribs),
        "n_conflict_edges": len(edges),
        "per_k": {str(k): v for k, v in results.items()},
        "natural_compound_yield_estimate": {
            "rules_tested": n_natural_tested_estimate,
            "rules_valid": n_natural_valid,
            "rate": natural_rate,
        },
    }, indent=2))
    print(f"\nOutput: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
