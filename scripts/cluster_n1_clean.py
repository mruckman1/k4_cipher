"""Re-cluster existing N1 outputs with cleaner keyword lists.

The original keyword lists in scripts/n1_ollama.py had two pollution
sources that inflated theme rates to 100%:
  - 'navigation' contained EAST, NORTH which are LITERALLY part of the
    K4 cribs (EAST at positions 22-25, NORTHEAST at 26-34). Every
    candidate trivially matches.
  - 'first_person' contained "I" which matches almost any English text.

This script re-clusters the existing N1 outputs (no model calls, $0)
with the polluting keywords removed and surfaces the HONEST theme
convergence. Reads ``experiments/results/n1_ollama_outputs/<latest>/``
by default; writes ``data/k4_plaintext_themes_ollama_clean.yaml``.

Usage:
    uv run python scripts/cluster_n1_clean.py
    uv run python scripts/cluster_n1_clean.py --run-dir <path>
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path


# Clean keyword lists. Removed: EAST, NORTH (crib pollution),
# I, OUR, MY (too common in English to be informative). Added: more
# specific lexicon for each theme.
THEMES = {
    "navigation_clean": {
        # Removed EAST, NORTH; kept genuinely directional/measurement
        # vocabulary that doesn't overlap with the cribs.
        "DEGREES", "MINUTES", "COORDINATES", "LATITUDE", "LONGITUDE",
        "BEARING", "COMPASS", "MERIDIAN", "TOWARD", "TOWARDS",
        "FIFTYTWO", "THIRTEEN", "FORTYDEGREES",
    },
    "first_person_clean": {
        # Removed "I" (too short, matches anywhere); kept multi-letter
        # first-person pronouns/markers.
        "MYSELF", "OURSELVES", "OURS", "WE",
    },
    "berlin_wall": {
        "WALL", "FALL", "GATE", "ALEXANDERPLATZ", "WELTZEITUHR", "URANIA",
        "BORNHOLMER", "BRANDENBURG", "NOVEMBER", "CROSSING", "CHECKPOINT",
        "STRIKES", "FELL", "OBSERVE", "IRONCURTAIN", "FREEDOM", "REVOLUTION",
    },
    "k2_k3_echo": {
        "BURIED", "LAYER", "PLINTH", "DUST", "WEAVE", "BREACH", "MIST",
        "CHAMBER", "CARTER", "TOMB", "PASSAGE", "MAGNETIC", "DOORWAY",
        "TREMBLING",
    },
    "egypt": {
        "EGYPT", "CAIRO", "KARNAK", "DESERT", "PYRAMID", "SAND",
    },
    "k5_forward": {
        # Imperative-verb-led "go find / look / search / dig" content
        "DIG", "LOOK", "SEARCH", "FIND", "BENEATH", "BELOW", "UNDER",
        "BEHIND", "WITHIN", "MARK", "POINT", "PLACE", "LOCATE", "FOLLOW",
        "REVEAL", "ROTATE", "PRESS", "MOVE", "MEASURE", "EXAMINE",
    },
    "espionage": {
        "AGENT", "DROP", "RENDEZVOUS", "MIDNIGHT", "RAVEN", "ASSET",
        "CODENAME", "EXFILTRATE", "STATION", "HANDLER", "CONTACT",
        "OPERATIVE", "TRADECRAFT", "COVERT", "SURVEILLANCE",
    },
    "sculpture_action": {
        # New theme: explicit instructions to manipulate the physical
        # sculpture (matches Sanborn's "do something with the sculpture
        # itself" hint, related to but distinct from k5_forward).
        "ROTATE", "TURN", "DIAL", "GEAR", "BASE", "PEDESTAL",
        "RELIEF", "PLATE", "RIVET", "BOLT", "PANEL",
    },
}


def cluster(candidates: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {t: 0 for t in THEMES}
    for cand in candidates:
        for theme, kws in THEMES.items():
            if any(kw in cand for kw in kws):
                counts[theme] += 1
    return counts


def find_latest_run(base_dir: Path) -> Path | None:
    if not base_dir.exists():
        return None
    runs = sorted(p for p in base_dir.iterdir() if p.is_dir() and p.name.startswith("run_"))
    return runs[-1] if runs else None


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help="N1 run directory; default = latest under experiments/results/n1_ollama_outputs/",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=Path("data/k4_plaintext_themes_ollama_clean.yaml"),
    )
    args = p.parse_args()

    base = Path("experiments/results/n1_ollama_outputs")
    run_dir = args.run_dir or find_latest_run(base)
    if run_dir is None or not run_dir.exists():
        print(f"no N1 run found at {base}", file=sys.stderr)
        return 1

    all_cands: list[str] = []
    per_framing: dict[str, dict] = {}
    for parsed_file in sorted(run_dir.glob("*_parsed.txt")):
        fname = parsed_file.stem.replace("_parsed", "")
        cands = [line.strip() for line in parsed_file.read_text().splitlines() if line.strip()]
        all_cands.extend(cands)
        counts = cluster(cands)
        per_framing[fname] = {
            "n_candidates": len(cands),
            "theme_hits": counts,
            "theme_pct": {t: round(100 * c / max(len(cands), 1), 1) for t, c in counts.items()},
        }

    total_counts = cluster(all_cands)
    total = max(len(all_cands), 1)
    total_pct = {t: round(100 * c / total, 1) for t, c in total_counts.items()}

    lines = [
        f"run_dir: {run_dir}",
        f"total_candidates: {len(all_cands)}",
        "",
        "per_framing:",
    ]
    for fname, info in per_framing.items():
        lines.append(f"  {fname}:")
        lines.append(f"    n_candidates: {info['n_candidates']}")
        lines.append(f"    theme_pct:")
        for t, pct in sorted(info["theme_pct"].items(), key=lambda kv: -kv[1]):
            lines.append(f"      {t}: {pct}%")
    lines.append("")
    lines.append("overall_theme_pct:")
    for t, pct in sorted(total_pct.items(), key=lambda kv: -kv[1]):
        lines.append(f"  {t}: {pct}%")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines) + "\n")

    print(f"=== Clean re-cluster of {len(all_cands)} candidates from {run_dir.name} ===")
    print()
    print("Overall (across all framings):")
    for t, pct in sorted(total_pct.items(), key=lambda kv: -kv[1]):
        bar = "#" * int(pct / 3)
        print(f"  {t:24s} {pct:5.1f}%  {bar}")
    print()
    print("Per-framing top theme:")
    for fname, info in per_framing.items():
        top = max(info["theme_pct"].items(), key=lambda kv: kv[1])
        print(f"  {fname:14s}  top: {top[0]} ({top[1]}%)")
    print()
    print(f"Full output: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
