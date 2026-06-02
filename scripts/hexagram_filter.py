"""Post-filter an N1 prior by hexagram fitness — keep only the top
X% most English-like candidates.

Background: Sonnet/Opus N1 runs produce thousands of crib-compliant
97-char candidate plaintexts. Quality varies — some read fluently in
Sanborn's register, others are technically crib-compliant but
grammatically lumpy. The hexagram fitness ([data/ngrams/english_hexagrams.txt],
3.18M entries) cleanly separates: real English plaintexts score about
-13 nats/char; gibberish scores -23 to -24.

This script reads every *_parsed.txt under a run directory, scores each
candidate, and writes a filtered run directory containing only the top
fraction (default 70%). The filtered directory is a drop-in replacement
for the original for downstream attacks via run_all_attacks.py.

Usage:
  uv run python scripts/hexagram_filter.py \
      --in-dir experiments/results/n1_claude_outputs/run_xyz/
      [--out-dir <derived>]
      [--top-frac 0.70]
      [--min-score -20.0]      # alternative cutoff: absolute hex/char threshold

Output:
  <out-dir>/{framing}_parsed.txt   filtered candidates per framing
  <out-dir>/filter_summary.json    distribution stats
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from kryptos.scoring.ngram_fitness import load_ngrams


HEX_PATH = Path("data/ngrams/english_hexagrams.txt")


def load_candidates_by_framing(run_dir: Path) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for f in sorted(run_dir.glob("*_parsed.txt")):
        fname = f.stem.replace("_parsed", "")
        cands = []
        for line in f.read_text().splitlines():
            line = line.strip()
            if len(line) == 97 and line.isalpha() and line.isupper():
                cands.append(line)
        out[fname] = cands
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--in-dir", type=Path, required=True,
                   help="N1 run dir with per-framing *_parsed.txt files")
    p.add_argument("--out-dir", type=Path, default=None,
                   help="output dir; defaults to <in-dir>_hexfiltered/")
    p.add_argument("--top-frac", type=float, default=0.70,
                   help="keep top X fraction by hex score per framing (default 0.70)")
    p.add_argument("--min-score", type=float, default=None,
                   help="alternative cutoff: only keep candidates with hex/char >= threshold")
    args = p.parse_args()

    if not args.in_dir.exists():
        sys.stderr.write(f"in-dir not found: {args.in_dir}\n")
        return 1

    out_dir = args.out_dir or args.in_dir.with_name(args.in_dir.name + "_hexfiltered")
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading hexagrams from {HEX_PATH} ...")
    hex_fit = load_ngrams(HEX_PATH, 6)

    cand_by_framing = load_candidates_by_framing(args.in_dir)
    total_in = sum(len(v) for v in cand_by_framing.values())
    print(f"Input: {len(cand_by_framing)} framings, {total_in} candidates total\n")

    per_framing_stats: dict[str, dict] = {}
    total_kept = 0
    overall_distribution: list[float] = []
    for fname, cands in sorted(cand_by_framing.items()):
        scored = [(c, hex_fit(c)) for c in cands]
        scored.sort(key=lambda r: -r[1])

        if args.min_score is not None:
            kept = [(c, s) for c, s in scored if s >= args.min_score]
        else:
            k = max(1, int(len(scored) * args.top_frac))
            kept = scored[:k]

        kept_strs = [c for c, _ in kept]
        # Write filtered file
        out_file = out_dir / f"{fname}_parsed.txt"
        out_file.write_text("\n".join(kept_strs) + "\n")

        scores = [s for _, s in scored]
        kept_scores = [s for _, s in kept]
        stats = {
            "n_in": len(scored),
            "n_kept": len(kept),
            "frac_kept": round(len(kept) / max(1, len(scored)), 3),
            "score_max": round(scores[0], 3) if scores else None,
            "score_median": round(scores[len(scores)//2], 3) if scores else None,
            "score_min": round(scores[-1], 3) if scores else None,
            "kept_score_min": round(kept_scores[-1], 3) if kept_scores else None,
        }
        per_framing_stats[fname] = stats
        total_kept += len(kept)
        overall_distribution.extend(scores)
        print(f"  {fname:30s}  in={stats['n_in']:>5}  kept={stats['n_kept']:>5}  "
              f"score range: [{stats['score_min']:.2f}, {stats['score_max']:.2f}], "
              f"kept_min={stats['kept_score_min']:.2f}")

    overall_distribution.sort(reverse=True)
    summary = {
        "in_dir": str(args.in_dir),
        "out_dir": str(out_dir),
        "top_frac": args.top_frac if args.min_score is None else None,
        "min_score": args.min_score,
        "n_in_total": total_in,
        "n_kept_total": total_kept,
        "frac_kept_overall": round(total_kept / max(1, total_in), 3),
        "overall_score_max": round(overall_distribution[0], 3) if overall_distribution else None,
        "overall_score_p10": round(overall_distribution[len(overall_distribution)//10], 3)
            if len(overall_distribution) >= 10 else None,
        "overall_score_median": round(overall_distribution[len(overall_distribution)//2], 3)
            if overall_distribution else None,
        "overall_score_min": round(overall_distribution[-1], 3) if overall_distribution else None,
        "per_framing": per_framing_stats,
    }
    (out_dir / "filter_summary.json").write_text(json.dumps(summary, indent=2))

    print()
    print(f"=== Filter summary ===")
    print(f"  input:   {total_in} candidates")
    print(f"  kept:    {total_kept} ({summary['frac_kept_overall']:.1%})")
    if summary["overall_score_max"] is not None:
        print(f"  scores:  max={summary['overall_score_max']:.2f}, "
              f"p10={summary['overall_score_p10']:.2f}, "
              f"median={summary['overall_score_median']:.2f}, "
              f"min={summary['overall_score_min']:.2f}")
        print(f"           (real English ≈ -13, gibberish ≈ -24)")
    print(f"  output:  {out_dir}")
    print()
    print(f"Next: uv run python scripts/run_all_attacks.py --run-dir {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
