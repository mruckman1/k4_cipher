"""Run the full Tier-A + Tier-B attack suite against a given N1 prior.

Given a path to an N1 run directory (containing per-framing *_parsed.txt
files of crib-compliant 97-char candidate plaintexts), this script
invokes every implemented cipher-family attack experiment in sequence,
collecting summary outputs and reporting any solves.

Attack suite (in order; total ~10-30 min wall time on M3 Max 14 cores):

  Tier A (linear / matrix / autokey):
    024 — Vigenere/Beaufort/variant-Beaufort periodic, Hill 2x2/3x3, Autokey

  Tier B (composites, polygraphic, fractionation):
    023 — Sonnet-candidate shift sequence vs 20.5k-generator library
    025 — W-segmented heterogeneous
    026 — Q3 + arithmetic offset / reversed / even-odd interleaved
    028 — Hill 4x4 through 8x8
    029 — Compose pipelines (remap / col / Q3 in 3 shapes)
    030 — Playfair variants (5x5 with 26 merges, 2x13, 13x2)
    027 — Trifid 3x3x3 hill-climb (longest; Numba + multiprocessing)

  N2 cross-product (if N2 hypotheses dir provided):
    Test each of the N2-proposed cipher methods against all candidates
    in the prior, looking for any (hypothesis, candidate) -> K4 solve.

A WIN at any layer is the end of the search: K4 is solved. Otherwise,
the prior is added to the ruled-out list.

Usage:
  uv run python scripts/run_all_attacks.py \
      --run-dir experiments/results/n1_claude_outputs/<run_id>/
      [--n2-hypotheses-dir experiments/results/n2_claude_outputs/<run_id>/]
      [--skip 023,027]              # skip particular experiments by number
      [--quick]                     # use smaller hill-climb budgets

Output:
  Each experiment writes its own JSONL under experiments/results/. This
  script additionally writes a meta-summary at:
    experiments/results/run_all_attacks_<timestamp>_<prior_name>.json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


# (experiment_id, script_path, description, default_args, quick_args)
# quick_args overrides default when --quick passed; None means no quick mode.
EXPERIMENTS: list[tuple[str, str, str, list[str], list[str] | None]] = [
    ("024",
     "experiments/024_tierA_known_plaintext.py",
     "Tier A: Vigenere/Beaufort/variant, Hill 2-3, Autokey known-plaintext",
     [],
     None),
    ("023",
     "experiments/023_sonnet_candidate_shift_vs_generators.py",
     "Sonnet-candidate shift sequence vs 20.5k generator library",
     [],
     None),
    ("025",
     "experiments/025_w_segmented_heterogeneous.py",
     "W-segmented heterogeneous (6 segs × short-period Vigenere variants)",
     [],
     None),
    ("026",
     "experiments/026_composite_q3_transforms.py",
     "Q3 + arithmetic offset / reversed / even-odd interleaved",
     [],
     None),
    ("028",
     "experiments/028_hill_block_sizes_4_to_8.py",
     "Hill block sizes 4x4 through 8x8",
     [],
     None),
    ("029",
     "experiments/029_compose_pipelines.py",
     "Compose pipelines: remap + col + Q3 in 3 nesting shapes",
     ["--columnar-widths", "3", "5", "7", "--max-period", "15"],
     ["--columnar-widths", "3", "5", "--max-period", "10"]),
    ("030",
     "experiments/030_playfair_dedicated_search.py",
     "Playfair: 5x5 with 26 merges + 2x13 + 13x2 rectangular",
     ["--n-workers", "14", "--n-restarts", "6", "--n-iters", "5000"],
     ["--n-workers", "14", "--n-restarts", "3", "--n-iters", "1500"]),
    ("031",
     "experiments/031_two_pass_columnar_q3.py",
     "Two-pass K3-style columnar transposition + optional Q3 composite",
     ["--max-period", "15"],
     ["--max-period", "10"]),
    ("032",
     "experiments/032_single_letter_ciphertext_error.py",
     "Single-letter ciphertext-error + Q3 KP attack (K2-IDBYROWS analog)",
     ["--max-period", "30"],
     ["--max-period", "20"]),
    ("027",
     "experiments/027_trifid_hillclimb.py",
     "Trifid 3x3x3 hill-climb (Numba + multiprocessing)",
     ["--n-workers", "14", "--n-restarts", "8", "--n-iters", "5000"],
     ["--n-workers", "14", "--n-restarts", "4", "--n-iters", "2000"]),
]


def find_solves_in_jsonl(jsonl_path: Path) -> tuple[int, dict | None, dict]:
    """Scan a JSONL log for any solve indicator. Returns (n_solves,
    sample_solve_record, summary_dict)."""
    if not jsonl_path.exists():
        return 0, None, {}
    solves = 0
    sample = None
    summary = {}
    try:
        for line in jsonl_path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("summary"):
                summary = r
                continue
            # Various solve indicators across exps
            if (r.get("SOLVED") is True
                    or r.get("status") == "FULLY_SOLVED"
                    or r.get("ok") is True):
                solves += 1
                if sample is None:
                    sample = r
            # 028/024-style hill solves
            if "best_score" in r and r.get("best_score") == 97:
                solves += 1
                if sample is None:
                    sample = r
    except Exception:
        pass
    return solves, sample, summary


def run_one(exp_id: str, script: str, args: list[str], run_dir: Path,
            extra: list[str] | None = None) -> dict:
    """Invoke a single experiment script in a subprocess."""
    cmd = ["uv", "run", "python", script, "--run-dir", str(run_dir)] + (args or [])
    if extra:
        cmd += extra
    t0 = time.perf_counter()
    print(f"\n{'='*70}")
    print(f"[{exp_id}] launching: {script}")
    print(f"       args: {' '.join(cmd[4:])}")
    print('='*70, flush=True)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.perf_counter() - t0
    print(f"[{exp_id}] exit_code={proc.returncode}, elapsed={elapsed:.1f}s")
    if proc.returncode != 0:
        print(f"[{exp_id}] STDERR (last 30 lines):")
        for line in proc.stderr.splitlines()[-30:]:
            print(f"  {line}")
    else:
        # Print last 12 lines of stdout for quick eyeball
        out_lines = proc.stdout.splitlines()
        for line in out_lines[-12:]:
            print(f"  {line}")
    return {
        "exp_id": exp_id,
        "script": script,
        "exit_code": proc.returncode,
        "elapsed_s": round(elapsed, 1),
        "stdout_tail": "\n".join(proc.stdout.splitlines()[-30:]),
        "stderr_tail": "\n".join(proc.stderr.splitlines()[-30:]),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run-dir", type=Path, required=True,
                   help="N1 run dir containing per-framing *_parsed.txt files")
    p.add_argument("--n2-hypotheses-dir", type=Path, default=None,
                   help="optional: N2 hypotheses dir to cross-test")
    p.add_argument("--skip", type=str, default="",
                   help="comma-separated list of exp ids to skip (e.g. '023,027')")
    p.add_argument("--only", type=str, default="",
                   help="comma-separated list of exp ids to run (overrides default order)")
    p.add_argument("--quick", action="store_true",
                   help="use smaller hill-climb budgets where applicable")
    p.add_argument("--out-meta", type=Path, default=None)
    args = p.parse_args()

    if not args.run_dir.exists():
        sys.stderr.write(f"run-dir not found: {args.run_dir}\n")
        return 1
    n_cands = sum(1 for f in args.run_dir.glob("*_parsed.txt")
                  for line in f.read_text().splitlines()
                  if line.strip() and len(line.strip()) == 97)
    print(f"Prior: {args.run_dir}")
    print(f"Candidate count: {n_cands}")

    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    only = {s.strip() for s in args.only.split(",") if s.strip()}

    plan = []
    for exp_id, script, desc, def_args, quick_args in EXPERIMENTS:
        if only and exp_id not in only:
            continue
        if exp_id in skip:
            print(f"  skipping {exp_id}: {desc}")
            continue
        cmd_args = (quick_args if args.quick and quick_args else def_args)
        plan.append((exp_id, script, desc, cmd_args))

    print(f"\nPlanned experiments ({len(plan)}):")
    for exp_id, script, desc, _ in plan:
        print(f"  [{exp_id}] {desc}")

    results: list[dict] = []
    total_solves = 0
    t0 = time.perf_counter()
    for exp_id, script, desc, cmd_args in plan:
        r = run_one(exp_id, script, cmd_args, args.run_dir)
        # Try to find the expected JSONL output and scan for solves
        date_prefix = datetime.now().strftime("%Y-%m-%d")
        # Each exp writes to a date-prefixed jsonl; find the most recent one
        # matching the exp_id
        results_dir = Path("experiments/results")
        candidates = sorted(results_dir.glob(f"*_{exp_id}_*.jsonl"))
        if candidates:
            n_solves, sample, summary = find_solves_in_jsonl(candidates[-1])
            r["n_solves"] = n_solves
            r["jsonl_path"] = str(candidates[-1])
            r["summary"] = summary
            if sample:
                r["sample_solve"] = sample
            total_solves += n_solves
            print(f"  [{exp_id}] n_solves={n_solves}")
        results.append(r)
        if total_solves > 0:
            print(f"\n!!! SOLVE FOUND in {exp_id} !!! Stopping further runs.")
            break

    # Optional N2 cross-product
    if args.n2_hypotheses_dir is not None and total_solves == 0:
        print(f"\n{'='*70}")
        print(f"[N2-XP] N2 cross-product against the prior")
        print('='*70, flush=True)
        cmd = ["uv", "run", "python", "scripts/n2_verify_against_candidates.py",
               "--hypotheses-dir", str(args.n2_hypotheses_dir),
               "--candidates-dir", str(args.run_dir)]
        t1 = time.perf_counter()
        proc = subprocess.run(cmd, capture_output=True, text=True)
        elapsed = time.perf_counter() - t1
        out_lines = proc.stdout.splitlines()
        for line in out_lines[-15:]:
            print(f"  {line}")
        n_solve_match = re.search(r"SOLVES:\s*(\d+)", proc.stdout or "")
        n_sol = int(n_solve_match.group(1)) if n_solve_match else 0
        results.append({
            "exp_id": "N2_XP",
            "elapsed_s": round(elapsed, 1),
            "n_solves": n_sol,
            "stdout_tail": "\n".join(out_lines[-30:]),
        })
        total_solves += n_sol
        print(f"  [N2_XP] n_solves={n_sol}")

    elapsed = time.perf_counter() - t0
    meta = {
        "run_dir": str(args.run_dir),
        "n_candidates": n_cands,
        "n2_hypotheses_dir": str(args.n2_hypotheses_dir) if args.n2_hypotheses_dir else None,
        "quick": args.quick,
        "skip": list(skip),
        "only": list(only),
        "total_elapsed_s": round(elapsed, 1),
        "total_solves": total_solves,
        "results": results,
    }

    out_meta = args.out_meta or Path(
        f"experiments/results/run_all_attacks_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_"
        f"{args.run_dir.name}.json"
    )
    out_meta.parent.mkdir(parents=True, exist_ok=True)
    out_meta.write_text(json.dumps(meta, indent=2))

    print()
    print(f"{'='*70}")
    print(f"FULL ATTACK SUITE COMPLETE")
    print(f"{'='*70}")
    print(f"  prior:        {args.run_dir.name}")
    print(f"  candidates:   {n_cands}")
    print(f"  experiments:  {len(plan)} planned, "
          f"{sum(1 for r in results if r.get('exit_code') == 0)} ok, "
          f"{sum(1 for r in results if r.get('exit_code') not in (0, None))} failed")
    print(f"  TOTAL SOLVES: {total_solves}")
    print(f"  elapsed:      {elapsed:.1f}s ({elapsed/60:.1f} min)")
    print(f"  meta:         {out_meta}")
    if total_solves > 0:
        print(f"\n*** K4 SOLVED *** see meta for details")
    return 0 if total_solves == 0 else 0  # always succeed; solves are signal not error


if __name__ == "__main__":
    sys.exit(main())
