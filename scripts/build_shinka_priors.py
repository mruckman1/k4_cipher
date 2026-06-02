"""Build the priors for the Shinka per-position-alphabet-selection run:

  1. Top-20 Scheidt-ranked k=4 valid compound rules from exp 038
  2. Per-color alphabet seeds (best partial-match natural keywords) from exp 042

Writes:
  shinka/problem/k4_priors.json
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Callable
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


def cribs_conflict(c1, c2):
    _, p1, ch1 = c1
    _, p2, ch2 = c2
    return (p1 == p2 and ch1 != ch2) or (ch1 == ch2 and p1 != p2)


# Feature functions identical to exp 038 (so rules generated here use the
# same primitives as Move B).

def f_dist_to_w(i): return min(abs(i - w) for w in W_POSITIONS)
def f_w_segment_index(i): return sum(1 for w in W_POSITIONS if i > w)


def f_w_segment_offset(i):
    boundaries = [-1] + W_POSITIONS + [N]
    for s in range(len(boundaries) - 1):
        lo, hi = boundaries[s], boundaries[s + 1]
        if lo < i < hi:
            return i - lo - 1
    return 0


def f_position(i): return i
def f_position_parity(i): return i % 2
def f_position_mod_3(i): return i % 3
def f_position_mod_5(i): return i % 5


def f_signed_dist_to_w(i):
    best_d, best_dir = N, 0
    for w in W_POSITIONS:
        d = abs(i - w)
        if d < best_d:
            best_d = d
            best_dir = 1 if w < i else -1
    return best_d * best_dir + 100


def f_vowel_count(i):
    return sum(1 for j in range(i + 1) if K4_TEXT[j] in VOWELS)


def f_consonant_count(i):
    return sum(1 for j in range(i + 1) if K4_TEXT[j] not in VOWELS)


def f_dist_to_nearest_doubled(i):
    doubled = [j for j in range(N - 1) if K4_TEXT[j] == K4_TEXT[j + 1]]
    return min(abs(i - j) for j in doubled) if doubled else 0


def f_k4_letter_parity(i):
    return (ord(K4_TEXT[i]) - 65) % 2


FEATURE_FUNCTIONS: dict[str, Callable[[int], int]] = {
    "position": f_position,
    "pos_parity": f_position_parity,
    "pos_mod_3": f_position_mod_3,
    "pos_mod_5": f_position_mod_5,
    "consonant_count": f_consonant_count,
    "vowel_count": f_vowel_count,
    "w_dist": f_dist_to_w,
    "w_seg_idx": f_w_segment_index,
    "w_seg_offset": f_w_segment_offset,
    "signed_w_dist": f_signed_dist_to_w,
    "dist_to_doubled": f_dist_to_nearest_doubled,
    "k4_letter_parity": f_k4_letter_parity,
}


# Scheidt-compatibility ranking. Hand-curated: a Sanborn-as-artist
# executing the cipher by hand can use these features more easily.
# Higher = more Scheidt-compatible.
SCHEIDT_FEATURE_SCORE = {
    "pos_mod_3": 9,        # trivial position arithmetic
    "pos_mod_5": 8,        # same
    "pos_parity": 9,       # trivial
    "consonant_count": 7,  # countable on a page
    "vowel_count": 7,      # countable on a page
    "position": 9,         # just the index
    "w_seg_idx": 6,        # visible on sculpture (carved letter)
    "w_seg_offset": 6,     # same
    "w_dist": 5,           # requires distance calc
    "signed_w_dist": 4,    # signed = even more arithmetic
    "k4_letter_parity": 3, # requires looking at ciphertext as you go
    "dist_to_doubled": 2,  # implausible — no hand-executable rule
}


# Operation scores (Scheidt-compatible operations)
OPERATION_SCORES = {
    "linear_compound": 7,    # a*f + b*g mod k — feasible with small a,b
    "lex_compound": 4,       # f * MAX + g mod k — MAX awkward to compute
    "xor_compound": 2,       # XOR by hand is awkward
    "wdist_tiebreaker": 5,   # W-distance + parity tiebreaker
}


def coefficient_score(rule: dict) -> int:
    """Smaller coefficients are more Scheidt-compatible."""
    if rule["kind"] == "linear_compound":
        a, b = rule.get("a", 1), rule.get("b", 1)
        max_coef = max(a, b)
        if max_coef <= 2: return 4
        if max_coef <= 3: return 3
        if max_coef <= 4: return 2
        return 1
    if rule["kind"] == "lex_compound":
        return 1   # all multipliers awkward
    return 2


def scheidt_score(rule: dict) -> float:
    """Composite Scheidt-compatibility score for a compound rule."""
    fa = rule.get("fa", "")
    fb = rule.get("fb", "")
    fa_s = SCHEIDT_FEATURE_SCORE.get(fa, 1)
    fb_s = SCHEIDT_FEATURE_SCORE.get(fb, 1)
    op_s = OPERATION_SCORES.get(rule["kind"], 1)
    coef_s = coefficient_score(rule)
    k_s = max(1, 10 - rule.get("k", 4))   # prefer small k
    return fa_s + fb_s + op_s + coef_s + k_s


def rule_to_callable(rule: dict) -> Callable[[int], int]:
    """Return a function R(i) → int from a rule spec."""
    fa = FEATURE_FUNCTIONS[rule["fa"]]
    fb = FEATURE_FUNCTIONS[rule["fb"]]
    k = rule["k"]
    if rule["kind"] == "lex_compound":
        max_b = rule["max_b"]
        return lambda i: (fa(i) * max_b + fb(i)) % k
    if rule["kind"] == "linear_compound":
        a = rule["a"]; b = rule["b"]
        return lambda i: (a * fa(i) + b * fb(i)) % k
    if rule["kind"] == "xor_compound":
        return lambda i: (fa(i) ^ fb(i)) % k
    raise ValueError(rule["kind"])


def violations(rule_fn: Callable[[int], int], cribs, edges) -> int:
    crib_colors = [rule_fn(pos) for (pos, _, _) in cribs]
    return sum(1 for (u, v) in edges if crib_colors[u] == crib_colors[v])


# Replay Move B's rule generation to get the valid rule pool
def generate_valid_compound_rules(cribs, edges) -> list[dict]:
    valid = []
    feature_names = list(FEATURE_FUNCTIONS)

    # Pass 1: lex compounds
    feature_arrays = {n: [FEATURE_FUNCTIONS[n](i) for i in range(N)] for n in feature_names}
    for fa_name, fb_name in itertools.product(feature_names, feature_names):
        if fa_name == fb_name:
            continue
        fa_vals = feature_arrays[fa_name]
        fb_vals = feature_arrays[fb_name]
        max_b = max(max(fb_vals) + 1, 2)
        for k in [3, 4, 5, 6, 7, 8]:
            vals = [(fa_vals[i] * max_b + fb_vals[i]) % k for i in range(N)]
            v = sum(1 for (u, v_) in edges if vals[cribs[u][0]] == vals[cribs[v_][0]])
            if v == 0:
                valid.append({
                    "kind": "lex_compound", "fa": fa_name, "fb": fb_name,
                    "max_b": max_b, "k": k,
                    "k_used": len({vals[pos] for (pos, _, _) in cribs}),
                })

    # Pass 2: linear compounds
    for fa_name, fb_name in itertools.product(feature_names, feature_names):
        if fa_name == fb_name:
            continue
        fa_vals = feature_arrays[fa_name]
        fb_vals = feature_arrays[fb_name]
        for k in [3, 4, 5, 6, 7, 8]:
            for a in range(1, min(k, 7)):
                for b in range(1, min(k, 7)):
                    vals = [(a * fa_vals[i] + b * fb_vals[i]) % k for i in range(N)]
                    v = sum(1 for (u, v_) in edges if vals[cribs[u][0]] == vals[cribs[v_][0]])
                    if v == 0:
                        valid.append({
                            "kind": "linear_compound", "fa": fa_name, "fb": fb_name,
                            "a": a, "b": b, "k": k,
                            "k_used": len({vals[pos] for (pos, _, _) in cribs}),
                        })

    # Pass 3: XOR compounds
    for fa_name, fb_name in itertools.product(feature_names, feature_names):
        if fa_name >= fb_name:
            continue
        fa_vals = feature_arrays[fa_name]
        fb_vals = feature_arrays[fb_name]
        for k in [3, 4, 5, 6, 7, 8]:
            vals = [(fa_vals[i] ^ fb_vals[i]) % k for i in range(N)]
            v = sum(1 for (u, v_) in edges if vals[cribs[u][0]] == vals[cribs[v_][0]])
            if v == 0:
                valid.append({
                    "kind": "xor_compound", "fa": fa_name, "fb": fb_name, "k": k,
                    "k_used": len({vals[pos] for (pos, _, _) in cribs}),
                })

    return valid


def build_alphabet_pool() -> list[tuple[str, str]]:
    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DYAHR", "IQLUSION",
        "UNDERGRUUND", "DESPARATLY", "EAST", "NORTHEAST", "BERLIN",
        "CLOCK", "BERLINCLOCK", "EASTNORTHEAST", "BORNHOLMER",
        "ALEXANDERPLATZ", "WELTZEITUHR", "URANIA", "BRANDENBURG",
        "SCHABOWSKI", "JAEGER", "MAUERFALL", "REUNIFICATION", "FREEDOM",
        "WALL", "EGYPT", "CAIRO", "KARNAK", "LUXOR", "TUTANKHAMEN",
        "CARTER", "SPHINX", "PHARAOH", "PYRAMIDS", "VALLEY", "SANBORN",
        "JAMESSANBORN", "EDWARDSCHEIDT", "SCHEIDT", "LANGLEY", "CIA",
        "VIRGINIA", "MARYLAND", "MAGNETIC", "FIELD", "BURIED", "LAYER",
        "WW", "WEBSTER", "COORDINATES", "TOMB", "BREACH", "CANDLE",
        "CHAMBER", "TREMBLING", "FLAME", "DOORWAY", "ROOM", "MIST",
        "SCULPTURE", "PETRIFIED", "BRONZE", "COMPASS", "LODESTONE",
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
    return pool


def main():
    cribs = crib_constraints()
    edges = []
    for i in range(len(cribs)):
        for j in range(i + 1, len(cribs)):
            if cribs_conflict(cribs[i], cribs[j]):
                edges.append((i, j))

    print(f"Crib graph: {len(cribs)} cribs, {len(edges)} conflict edges")
    print()

    # Find valid rules
    print("Generating valid compound rules...")
    valid_rules = generate_valid_compound_rules(cribs, edges)
    print(f"  Total valid rules: {len(valid_rules)}")

    # Filter to k=4 (Prior A target)
    k4_rules = [r for r in valid_rules if r["k"] == 4 and r["k_used"] == 4]
    print(f"  k=4, k_used=4 rules: {len(k4_rules)}")

    # Score each rule by Scheidt-compatibility
    for r in k4_rules:
        r["scheidt_score"] = scheidt_score(r)

    # Top 20 by Scheidt score
    k4_rules.sort(key=lambda r: -r["scheidt_score"])
    top20 = k4_rules[:20]
    print(f"\nTop 20 Scheidt-ranked k=4 rules:")
    for i, r in enumerate(top20):
        if r["kind"] == "linear_compound":
            desc = f"({r['a']}*{r['fa']} + {r['b']}*{r['fb']}) mod {r['k']}"
        elif r["kind"] == "lex_compound":
            desc = f"({r['fa']}*{r['max_b']} + {r['fb']}) mod {r['k']}"
        elif r["kind"] == "xor_compound":
            desc = f"({r['fa']} XOR {r['fb']}) mod {r['k']}"
        print(f"  [{i:2d}] sch={r['scheidt_score']:>2}  {desc}")

    # For each of the top 20 rules, compute the per-color partial best
    # matches against natural alphabets
    print("\nBuilding alphabet seeds per top-20 rule...")
    pool = build_alphabet_pool()
    rule_seeds = []
    for rule_idx, rule in enumerate(top20):
        rule_fn = rule_to_callable(rule)
        # Partition cribs by color
        by_color: dict[int, dict[int, str]] = {}
        for (pos, p, c) in cribs:
            color = rule_fn(pos)
            pi = ord(p) - 65
            by_color.setdefault(color, {})[pi] = c

        seeds_per_color = []
        for color in sorted(by_color):
            constraints = by_color[color]
            scored = []
            for (label, alpha) in pool:
                overlap = sum(1 for pi, c in constraints.items() if alpha[pi] == c)
                scored.append((overlap, label, alpha))
            scored.sort(key=lambda r: -r[0])
            best_3 = [{"keyword": l, "overlap": o, "max": len(constraints), "alphabet": a}
                       for (o, l, a) in scored[:3]]
            seeds_per_color.append({
                "color": color,
                "n_constraints": len(constraints),
                "constraints": {str(k): v for k, v in constraints.items()},
                "best_seeds": best_3,
            })
        rule_seeds.append({"rule_idx": rule_idx, "rule": rule,
                            "seeds_per_color": seeds_per_color})

    # Print summary for Prior A (top rule)
    print(f"\nDefault Prior A rule (rank 0): "
          f"{top20[0]['kind']} {top20[0].get('a','')}*{top20[0]['fa']} + "
          f"{top20[0].get('b','')}*{top20[0].get('fb','')} mod {top20[0]['k']}")
    print(f"Per-color alphabet seeds for Prior A:")
    for c in rule_seeds[0]["seeds_per_color"]:
        print(f"  Color {c['color']} ({c['n_constraints']} constraints): "
              f"best seed = {c['best_seeds'][0]['keyword']} "
              f"({c['best_seeds'][0]['overlap']}/{c['best_seeds'][0]['max']})")

    out_path = Path("shinka/problem/k4_priors.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "top_20_rules": top20,
        "rule_seeds": rule_seeds,
        "n_valid_rules_total": len(valid_rules),
        "n_k4_rules": len(k4_rules),
    }, indent=2))
    print(f"\nWrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
