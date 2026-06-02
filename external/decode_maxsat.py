"""Parse EvalMaxSAT output, decode K=4 alphabets, score under composite fitness.

EvalMaxSAT output format (MaxSAT 2020+):
  s OPTIMUM FOUND      | s SATISFIABLE | s UNSATISFIABLE | s UNKNOWN
  o <cost>             (optimal MaxSAT cost = sum of falsified-soft-clause weights)
  v 010110...          (bitstring: var i (1-indexed) at position i-1; '1' = TRUE, '0' = FALSE)
  c <comments>         (ignored)

Old format (--old flag):
  v <lit1> <lit2> ... 0 (positive literals are TRUE, negative are FALSE)

Variable encoding: x[a][p][c] = 1 + a*676 + p*26 + c
  a ∈ {0,1,2,3} (alphabet/color index)
  p ∈ {0..25}  (plain letter index)
  c ∈ {0..25}  (cipher letter index)

x[a][p][c] = TRUE means "in alphabet a, plain letter p maps to cipher letter c."

Usage: python decode_maxsat.py <solver_output_log>
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Iterable

SHINKA_DIR = Path("/Users/mruckman1/Desktop/dev/k4_cipher/shinka")
sys.path.insert(0, str(SHINKA_DIR))

from kryptos.constants import K4
from problem.initial import _consonant_count_array
from problem._fitness import _fitness


K = 4
N_POS = 97
N_VARS = K * 26 * 26  # 2704


def color_of(i):
    cc = _consonant_count_array(K4)
    return (2 * (i % 3) + 1 * cc[i]) % K


COLOR = [color_of(i) for i in range(N_POS)]


def var(a: int, p: int, c: int) -> int:
    return 1 + a * 676 + p * 26 + c


def parse_solver_output(text: str):
    """Return (status, cost, true_vars_set) from EvalMaxSAT-style output.

    Handles BOTH the new (bitstring v line) and old (literal-list v line)
    formats. Picks the LAST v line in the file (the best model found).
    """
    status = None
    cost = None
    last_v_line = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("s "):
            status = line[2:].strip()
        elif line.startswith("o "):
            try:
                cost = int(line.split()[1])
            except (IndexError, ValueError):
                pass
        elif line.startswith("v "):
            last_v_line = line[2:].strip()

    if last_v_line is None:
        return status, cost, None

    # Determine format by inspecting first token
    parts = last_v_line.split()
    true_vars: set[int] = set()
    if len(parts) == 1 and all(ch in "01" for ch in parts[0]):
        # New format: contiguous bitstring
        bitstring = parts[0]
        for var_idx_zero_based, bit in enumerate(bitstring):
            if bit == "1":
                true_vars.add(var_idx_zero_based + 1)  # 1-indexed
    elif len(parts) > 0 and all(ch in "01" for ch in parts[0]) and len(parts[0]) > 1:
        # Some solvers emit bitstring with potential continuation lines
        bitstring = "".join(parts)
        for var_idx_zero_based, bit in enumerate(bitstring):
            if bit == "1":
                true_vars.add(var_idx_zero_based + 1)
    else:
        # Old format: list of signed literals
        for tok in parts:
            try:
                lit = int(tok)
            except ValueError:
                continue
            if lit == 0:
                break
            if lit > 0:
                true_vars.add(lit)
    return status, cost, true_vars


def decode_alphabets(true_vars: set[int]) -> list[str]:
    """Extract 4 alphabets. alphabet[a][p] = cipher letter for plain letter p."""
    alphabets = []
    for a in range(K):
        alpha = [""] * 26
        for p in range(26):
            for c in range(26):
                if var(a, p, c) in true_vars:
                    alpha[p] = chr(c + 65)
                    break
        alphabets.append("".join(alpha))
    return alphabets


def decrypt_from_alphabets(alphabets: list[str]) -> str:
    """For each K4 position i, find p such that alphabets[color(i)][p] = K4[i]."""
    out = []
    for i in range(N_POS):
        a = COLOR[i]
        try:
            p = alphabets[a].index(K4[i])
        except ValueError:
            return "A" * N_POS
        out.append(chr(p + 65))
    return "".join(out)


def main():
    if len(sys.argv) < 2:
        print("Usage: python decode_maxsat.py <solver_output_log>")
        sys.exit(1)
    log_path = Path(sys.argv[1])
    if not log_path.exists():
        print(f"File not found: {log_path}")
        sys.exit(1)

    text = log_path.read_text()
    print("=" * 78)
    print(f"Parsing solver output: {log_path}")
    print("=" * 78)
    status, cost, true_vars = parse_solver_output(text)
    print(f"  status: {status}")
    print(f"  optimal cost: {cost}")
    if true_vars is None:
        print(f"  no 'v' line found — solver may have timed out without a model")
        sys.exit(2)
    print(f"  variables assigned TRUE: {len(true_vars)}")
    expected_true = K * 26
    print(f"  expected TRUE count for valid model: {expected_true} (= K × 26 = one per (a,p) row)")
    if len(true_vars) != expected_true:
        print(f"  WARNING: count mismatch — model may be incomplete or non-optimal")

    alphabets = decode_alphabets(true_vars)
    print(f"\nDecoded alphabets:")
    for a, alpha in enumerate(alphabets):
        valid = set(alpha) == set("ABCDEFGHIJKLMNOPQRSTUVWXYZ") and len(alpha) == 26
        print(f"  A{a}: {alpha}  (valid permutation: {valid})")

    pt = decrypt_from_alphabets(alphabets)
    print(f"\nDecrypted plaintext (length {len(pt)}):")
    print(f"  {pt}")
    if pt == "A" * N_POS:
        print(f"  ERROR: decryption produced all-A fallback. Alphabet is malformed.")
        sys.exit(3)

    score, meta = _fitness(pt)
    print(f"\nScore under composite fitness (×5 per_partition):")
    print(f"  composite:       {score:.4f}")
    print(f"  cribs satisfied: {meta.get('cribs_satisfied')}/4")
    print(f"  hex/char:        {meta.get('hexagram_per_char'):.4f}")
    print(f"  per_partition_z: {meta.get('per_partition_bigram_z'):.4f}")
    print(f"  ioc:             {meta.get('ioc'):.4f}")
    print(f"  n1 matched:      {meta.get('n1_thematic_keywords_matched')}")

    print(f"\nComparison vs prior best:")
    print(f"  prior best (2-opt from gen 66 + perturbation): 71.98")
    delta = score - 71.98
    if delta > 0.5:
        print(f"  ** BREAK: {score:.2f} (Δ=+{delta:.2f})")
    elif delta > -0.5:
        print(f"  TIES:     {score:.2f} (Δ={delta:+.2f})")
    else:
        print(f"  BELOW:    {score:.2f} (Δ={delta:+.2f})")
        print(f"  (MaxSAT optimizes bigram likelihood, not composite — this is informative")
        print(f"   if bigram-optimal ≠ composite-optimal.)")

    # Save result
    out_path = Path("/tmp/k4_maxsat_overnight_result.json")
    result = {
        "status": status,
        "maxsat_cost": cost,
        "alphabets": alphabets,
        "plaintext": pt,
        "composite_score": float(score),
        "metadata": {k: v for k, v in meta.items() if k != "candidate_plaintext"},
        "vs_prior_best_71_98": float(delta),
    }
    out_path.write_text(json.dumps(result, indent=2, default=str))
    print(f"\nResult saved to {out_path}")


if __name__ == "__main__":
    main()
