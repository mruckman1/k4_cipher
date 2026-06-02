"""037 — Sharpen the chromatic-coloring finding by:

  1. Computing violation counts for low-k natural rules (mod 2..7) — verify
     that k=8 is a hard floor for natural rules
  2. For position_mod_8 (the simplest valid natural rule), determine
     which natural keyed alphabets in our 88-keyword pool are compatible
     with each of the 8 slot's crib constraints
  3. If any slot has zero compatible natural keywords → that slot
     requires a hand-crafted alphabet (consistent with exp 035's finding)
  4. If all 8 slots have compatible keywords → a specific 8-alphabet
     periodic Quagmire-IV-style cipher is the candidate structure

Output: experiments/results/2026-05-23_037_position_mod_8_search.json
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


def cribs_conflict(c1, c2) -> bool:
    _, p1, ch1 = c1
    _, p2, ch2 = c2
    return (p1 == p2 and ch1 != ch2) or (ch1 == ch2 and p1 != p2)


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
    pool: list[tuple[str, str]] = [("STANDARD", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")]
    seen: set[str] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ"}
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


def rule_position_mod(k: int):
    return [i % k for i in range(N)]


def rule_consonant_count_mod(k: int):
    out = []
    count = 0
    for i in range(N):
        if K4_TEXT[i] not in VOWELS:
            count += 1
        out.append(count % k)
    return out


def rule_vowel_count_mod(k: int):
    out = []
    count = 0
    for i in range(N):
        if K4_TEXT[i] in VOWELS:
            count += 1
        out.append(count % k)
    return out


def rule_pos_in_w_seg_mod(k: int):
    out = []
    boundaries = [-1] + W_POSITIONS + [N]
    for i in range(N):
        for s in range(len(boundaries) - 1):
            lo = boundaries[s]
            hi = boundaries[s + 1]
            if lo < i < hi:
                out.append((i - lo - 1) % k)
                break
        else:
            out.append(0)
    return out


def rule_w_segment_index_mod(k: int):
    out = []
    for i in range(N):
        seg = sum(1 for w in W_POSITIONS if i > w)
        out.append(seg % k)
    return out


def rule_dist_to_w_mod(k: int):
    out = []
    for i in range(N):
        d = min(abs(i - w) for w in W_POSITIONS)
        out.append(d % k)
    return out


RULES_TO_CHECK = {
    "position_mod": rule_position_mod,
    "consonant_count_mod": rule_consonant_count_mod,
    "vowel_count_mod": rule_vowel_count_mod,
    "pos_in_w_seg_mod": rule_pos_in_w_seg_mod,
    "w_segment_index_mod": rule_w_segment_index_mod,
    "dist_to_w_mod": rule_dist_to_w_mod,
}


def violations_for_rule(rule_values, cribs, edges):
    crib_colors = [rule_values[pos] for (pos, _, _) in cribs]
    count = 0
    for (u, v) in edges:
        if crib_colors[u] == crib_colors[v]:
            count += 1
    return count


def main():
    cribs = crib_constraints()
    edges = set()
    for i in range(len(cribs)):
        for j in range(i + 1, len(cribs)):
            if cribs_conflict(cribs[i], cribs[j]):
                edges.add((i, j))

    print(f"K4 conflict graph: {len(cribs)} cribs, {len(edges)} edges")
    print(f"Chromatic number χ = 3 (proven in exp 035)")
    print()

    # Part 1: violation counts for k=2..13 across all rule families
    print("Part 1: violation counts (0 = valid coloring)")
    print(f"{'rule':>30s}  {'k=2':>4} {'k=3':>4} {'k=4':>4} {'k=5':>4} {'k=6':>4} {'k=7':>4} {'k=8':>4} {'k=9':>4} {'k=10':>5}")
    for rule_name, rule_fn in RULES_TO_CHECK.items():
        row = [f"{rule_name:>30s}"]
        for k in range(2, 11):
            rv = rule_fn(k)
            viol = violations_for_rule(rv, cribs, edges)
            marker = "✓" if viol == 0 else ""
            row.append(f"{viol:>3}{marker}" if k <= 10 else f"{viol:>4}{marker}")
        print(" ".join(row))

    # Part 2: For position_mod_8 (and pos_in_w_seg_mod_8 and consonant_count_mod_8),
    # find which natural keyed alphabets are compatible with each slot
    print()
    print("=" * 80)
    print("Part 2: per-slot alphabet compatibility under k=8 valid rules")
    print("=" * 80)
    pool = build_alphabet_pool()
    print(f"\nNatural alphabet pool: {len(pool)} entries")

    for rule_name, rule_fn in [("position_mod_8", lambda: rule_position_mod(8)),
                                ("consonant_count_mod_8", lambda: rule_consonant_count_mod(8)),
                                ("pos_in_w_seg_mod_8", lambda: rule_pos_in_w_seg_mod(8))]:
        rv = rule_fn()
        # Group crib positions by slot
        slot_to_cribs = {}
        for (pos, p, c) in cribs:
            slot = rv[pos]
            slot_to_cribs.setdefault(slot, []).append((pos, p, c))

        print()
        print(f"--- Rule: {rule_name} ---")
        for slot in sorted(slot_to_cribs):
            slot_cribs = slot_to_cribs[slot]
            print(f"  Slot {slot}: {len(slot_cribs)} cribs: "
                  + " ".join(f"pos{p+1}:{pl}→{ct}" for (p, pl, ct) in slot_cribs))
            # Check natural alphabets
            compat = []
            for label, alpha in pool:
                ok = all(alpha[ord(pl) - 65] == ct for (_, pl, ct) in slot_cribs)
                if ok:
                    compat.append(label)
            if compat:
                print(f"    Compatible natural alphabets ({len(compat)}): {compat[:10]}")
            else:
                # Find best partial matches
                scored = []
                for label, alpha in pool:
                    n_match = sum(1 for (_, pl, ct) in slot_cribs if alpha[ord(pl) - 65] == ct)
                    scored.append((n_match, label))
                scored.sort(reverse=True)
                top = scored[:5]
                print(f"    NO fully compatible natural alphabet. Top partials: "
                      + ", ".join(f"{n}/{len(slot_cribs)} {l}" for n, l in top))

    out_path = Path("experiments/results/2026-05-23_037_position_mod_8_search.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"status": "computed"}, indent=2))
    print(f"\nOutput: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
