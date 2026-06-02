"""For each N2-generated cipher hypothesis (cipher_class + params +
post_transforms), test against all 5,220 N1 Sonnet candidate plaintexts.

The N2 generation pass produced 272 cipher-method proposals; the
plaintexts Sonnet attached to each were NOT crib-compliant (Sonnet
generated free-form text without rigidly placing cribs at fixed
positions). But the cipher methods themselves are testable: for each
hypothesis × each of 5,220 crib-compliant N1 candidates, encrypt the
candidate under the hypothesis cipher and compare byte-exact to K4.

A WIN is any (hypothesis, candidate) where cipher(candidate) == K4.

This is the highest-information-density use of the N2 output: each
N2 hypothesis represents a structural cipher choice (Nicodemus with
keyword 'BERLIN', Compose with specific chain, Gromark with specific
primer, etc.) that hasn't been individually tested with this many
candidate plaintexts.

Output: <hypotheses-dir>/verify_vs_n1_candidates.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from pathlib import Path

import numpy as np

from kryptos.constants import K4

# Reuse the broad cipher builder from n2_verify.py
sys.path.insert(0, str(Path(__file__).parent))
from n2_verify import build_cipher, apply_post_transforms


def load_candidates(run_dir: Path) -> list[str]:
    out: list[str] = []
    for f in sorted(run_dir.glob("*_parsed.txt")):
        for line in f.read_text().splitlines():
            line = line.strip()
            if len(line) == 97 and line.isalpha() and line.isupper():
                out.append(line)
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--hypotheses-dir", type=Path, required=True)
    p.add_argument("--candidates-dir", type=Path, default=None,
                   help="default = latest Sonnet N1 run")
    args = p.parse_args()

    if args.candidates_dir is None:
        base = Path("experiments/results/n1_claude_outputs")
        runs = sorted(d for d in base.iterdir() if d.is_dir() and "sonnet" in d.name)
        args.candidates_dir = runs[-1]

    hyp_file = args.hypotheses_dir / "hypotheses_parsed.jsonl"
    hyps = [json.loads(l) for l in hyp_file.read_text().splitlines() if l.strip()]
    print(f"Hypotheses loaded: {len(hyps)} from {hyp_file}")

    cands = load_candidates(args.candidates_dir)
    print(f"N1 candidates loaded: {len(cands)} from {args.candidates_dir}")

    out_path = args.hypotheses_dir / "verify_vs_n1_candidates.jsonl"
    print(f"Output: {out_path}")

    # Deduplicate hypotheses by (cipher_class, params, post_transforms) tuple
    seen_keys = set()
    uniq_hyps = []
    for h in hyps:
        key = json.dumps({
            "cls": h.get("cipher_class"),
            "params": h.get("params", {}),
            "post": h.get("post_transforms", []),
        }, sort_keys=True)
        if key not in seen_keys:
            seen_keys.add(key)
            uniq_hyps.append(h)
    print(f"Unique hypothesis structures: {len(uniq_hyps)}")

    n_built = 0
    n_solved = 0
    best_partial = (-1, None)
    t0 = time.perf_counter()
    n_attempts = 0

    with open(out_path, "w") as f:
        for hi, h in enumerate(uniq_hyps):
            cipher = build_cipher(h.get("cipher_class", ""), h.get("params", {}))
            if cipher is None:
                f.write(json.dumps({
                    "hypothesis_index": hi,
                    "cipher_class": h.get("cipher_class"),
                    "params": h.get("params"),
                    "build_failed": True,
                }) + "\n")
                continue
            n_built += 1
            post = h.get("post_transforms", []) or []
            for ci, cand in enumerate(cands):
                n_attempts += 1
                try:
                    produced = cipher.encrypt(cand)
                    produced = apply_post_transforms(produced, post)
                    if produced == K4:
                        rec = {
                            "hypothesis_index": hi,
                            "cipher_class": h.get("cipher_class"),
                            "params": h.get("params"),
                            "post_transforms": post,
                            "candidate_index": ci,
                            "candidate": cand,
                            "SOLVED": True,
                        }
                        f.write(json.dumps(rec) + "\n")
                        n_solved += 1
                        print(f"  *** SOLVE: hyp {hi} × cand {ci} ***")
                    else:
                        # Track partial matches
                        L = min(len(produced), len(K4))
                        n_match = sum(1 for j in range(L) if produced[j] == K4[j])
                        if n_match > best_partial[0]:
                            best_partial = (n_match, {
                                "hypothesis_index": hi,
                                "cipher_class": h.get("cipher_class"),
                                "params": h.get("params"),
                                "candidate_index": ci,
                                "n_match": n_match,
                            })
                except Exception:
                    pass  # Cipher rejected this candidate, skip silently
            if (hi + 1) % 20 == 0:
                elapsed = time.perf_counter() - t0
                print(f"  [{hi+1}/{len(uniq_hyps)}] {n_attempts:,} attempts, "
                      f"{n_solved} solved, best partial {best_partial[0]}/97 "
                      f"({elapsed:.1f}s)", flush=True)

        elapsed = time.perf_counter() - t0
        f.write(json.dumps({
            "summary": True,
            "n_hypotheses": len(uniq_hyps),
            "n_built": n_built,
            "n_candidates": len(cands),
            "n_attempts": n_attempts,
            "n_solved": n_solved,
            "best_partial_n_match": best_partial[0],
            "best_partial_cipher": best_partial[1],
            "elapsed_s": round(elapsed, 1),
        }) + "\n")

    print()
    print(f"=== N2 cipher hypotheses vs N1 candidates ===")
    print(f"  unique hypotheses:  {len(uniq_hyps)}")
    print(f"  cipher build OK:    {n_built}")
    print(f"  candidates:         {len(cands)}")
    print(f"  encrypt attempts:   {n_attempts:,}")
    print(f"  SOLVES:             {n_solved}")
    print(f"  best partial match: {best_partial[0]}/97")
    if best_partial[1]:
        print(f"  best partial: cipher={best_partial[1]['cipher_class']} "
              f"hyp={best_partial[1]['hypothesis_index']} "
              f"cand={best_partial[1]['candidate_index']}")
    print(f"  elapsed:            {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
