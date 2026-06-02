"""042 — K1-K3 alphabet structural overlap analysis under Priors A and B.

Sanborn used the same artist-and-cryptographer pair and the same cipher-
design philosophy for K1-K4. K1 and K2 use KRYPTOS-keyed alphabets. K3
uses transposition with KRYPTOS column ordering. Even if K4's alphabets
are hand-crafted, it's likely that *some* of them share structural
properties with the K1-K3 keyword-derived alphabets.

Under Prior A — (2 × pos_mod_3 + consonant_count) mod 4 — each of the 4
alphabets has 5-7 fixed positions from cribs. Under Prior B —
pos_in_w_seg_mod_8 — each of 8 alphabets has 3 fixed positions.

For each (color c, candidate_keyword_alphabet a) pair, compute:
  - How many of color c's crib-constrained alphabet positions match
    the candidate alphabet's letters
  - If overlap is high (e.g., 5/7), the candidate alphabet is plausibly
    the c-color alphabet with one modification (Sanborn-style error)

This gives Shinka concrete seed alphabets rather than random
permutations.

Output: experiments/results/2026-05-23_042_k1k3_alphabet_overlap.json
"""

from __future__ import annotations

import json
from pathlib import Path

from kryptos.alphabets import keyed_alphabet
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


def build_alphabet_pool() -> list[tuple[str, str]]:
    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DYAHR", "IQLUSION",
        "UNDERGRUUND", "DESPARATLY", "EAST", "NORTHEAST", "BERLIN",
        "CLOCK", "BERLINCLOCK", "EASTNORTHEAST", "BORNHOLMER",
        "ALEXANDERPLATZ", "WELTZEITUHR", "URANIA", "BRANDENBURG",
        "SCHABOWSKI", "JAEGER", "MAUERFALL", "REUNIFICATION",
        "FREEDOM", "WALL", "EGYPT", "CAIRO", "KARNAK", "LUXOR",
        "TUTANKHAMEN", "CARTER", "SPHINX", "PHARAOH", "PYRAMIDS",
        "VALLEY", "SANBORN", "JAMESSANBORN", "EDWARDSCHEIDT",
        "SCHEIDT", "LANGLEY", "CIA", "VIRGINIA", "MARYLAND",
        "MAGNETIC", "FIELD", "BURIED", "LAYER", "WW", "WEBSTER",
        "COORDINATES", "TOMB", "BREACH", "CANDLE", "CHAMBER",
        "TREMBLING", "FLAME", "DOORWAY", "ROOM", "MIST", "SCULPTURE",
        "PETRIFIED", "BRONZE", "COMPASS", "LODESTONE", "CIPHER",
        "SECRET", "MESSAGE", "HIDDEN", "PUZZLE", "SCHEME", "ZERO",
        "ONE", "TWO", "THREE", "FOUR", "FIVE", "SIX", "SEVEN",
        "EIGHT", "NINE", "TEN", "STASI", "GLASNOST", "PERESTROIKA",
        "DETENTE",
    ]
    pool = [("STANDARD", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")]
    seen = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ"}
    for kw in keywords:
        try:
            ka = keyed_alphabet(kw)
            if ka.letters in seen:
                continue
            pool.append((kw, ka.letters))
            seen.add(ka.letters)
        except Exception:
            continue
    for kw in ["KRYPTOS", "PALIMPSEST", "BERLINCLOCK"]:
        ka = keyed_alphabet(kw)
        rev = ka.letters[::-1]
        if rev not in seen:
            pool.append((kw + "_REV", rev))
            seen.add(rev)
    return pool


def rule_prior_A(i: int) -> int:
    """(2 × pos_mod_3 + consonant_count) mod 4"""
    cc = sum(1 for j in range(i + 1) if K4_TEXT[j] not in VOWELS)
    return (2 * (i % 3) + cc) % 4


def rule_prior_B(i: int) -> int:
    """pos_in_w_seg_mod_8"""
    boundaries = [-1] + W_POSITIONS + [N]
    for s in range(len(boundaries) - 1):
        lo, hi = boundaries[s], boundaries[s + 1]
        if lo < i < hi:
            return (i - lo - 1) % 8
    return 0


def per_color_constraints(rule_fn, n_colors: int) -> dict[int, dict[int, str]]:
    """For each color, return dict mapping plain-letter index → cipher letter
    (the alphabet positions fixed by cribs for that color)."""
    cribs = crib_constraints()
    by_color = {c: {} for c in range(n_colors)}
    for (pos, p, c) in cribs:
        color = rule_fn(pos)
        pi = ord(p) - 65
        if pi in by_color[color] and by_color[color][pi] != c:
            # Should not happen if rule is valid; would indicate inconsistency
            print(f"WARNING: color {color} has conflicting constraint at idx {pi}: "
                  f"{by_color[color][pi]} vs {c}")
        by_color[color][pi] = c
    return by_color


def alphabet_overlap(alpha: str, constraints: dict[int, str]) -> int:
    """Count how many constraint positions the alphabet satisfies."""
    return sum(1 for pi, c in constraints.items() if alpha[pi] == c)


def main():
    pool = build_alphabet_pool()
    print(f"Alphabet pool: {len(pool)} candidates")

    results = {}
    for prior_name, prior_fn, k_colors in (
        ("Prior_A_k4_consonant_pos_mod_3", rule_prior_A, 4),
        ("Prior_B_k8_pos_in_w_seg", rule_prior_B, 8),
    ):
        print()
        print("=" * 70)
        print(f"=== {prior_name} ===")
        print("=" * 70)
        constraints_by_color = per_color_constraints(prior_fn, k_colors)
        prior_results = {}
        for color in sorted(constraints_by_color):
            cs = constraints_by_color[color]
            print(f"\n--- Color {color}: {len(cs)} alphabet positions constrained ---")
            for pi in sorted(cs):
                print(f"    alpha[{pi:>2}] = {cs[pi]}  (plain {chr(pi+65)} → cipher {cs[pi]})")

            # Score each natural alphabet against these constraints
            scored = []
            for (label, alpha) in pool:
                overlap = alphabet_overlap(alpha, cs)
                scored.append((overlap, label, alpha))
            scored.sort(key=lambda r: -r[0])
            best = scored[0]
            max_possible = len(cs)

            print(f"  Top 10 natural alphabets by overlap with this color's constraints:")
            for overlap, label, _alpha in scored[:10]:
                marker = " ★" if overlap >= max_possible - 1 else (" ✓" if overlap >= max_possible // 2 + 1 else "")
                print(f"    {overlap}/{max_possible}  {label:<20s}{marker}")

            prior_results[color] = {
                "n_constraints": max_possible,
                "constraints": dict(cs),
                "top_5_keywords": [
                    {"overlap": o, "max": max_possible, "keyword": l, "alphabet": a}
                    for o, l, a in scored[:5]
                ],
                "best_keyword": best[1],
                "best_overlap": best[0],
                "near_full_count": sum(1 for o, _, _ in scored if o >= max_possible - 1),
            }
        results[prior_name] = prior_results

    # Aggregate finding
    print()
    print("=" * 70)
    print("=== Aggregate ===")
    print("=" * 70)
    for prior_name, pr in results.items():
        n_colors_with_high_overlap = 0
        for color, info in pr.items():
            best = info["best_overlap"]
            mx = info["n_constraints"]
            # "High" overlap = ≥ mx - 1 (off by at most 1) or ≥ mx/2 + 1 (most of cribs)
            if best >= mx - 1 and mx >= 3:
                n_colors_with_high_overlap += 1
                print(f"  {prior_name} color {color}: "
                      f"{info['best_keyword']} matches {best}/{mx} (off by ≤ 1)")
            elif best >= mx // 2 + 1 and mx >= 3:
                print(f"  {prior_name} color {color}: best is "
                      f"{info['best_keyword']} at {best}/{mx} (majority)")
        if n_colors_with_high_overlap == 0:
            print(f"  {prior_name}: no color has a natural alphabet matching off-by-one")

    out_path = Path("experiments/results/2026-05-23_042_k1k3_alphabet_overlap.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2, default=str))
    print(f"\nOutput: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
