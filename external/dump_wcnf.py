"""Generate the K4 MaxSAT WCNF and dump to DIMACS format for external solvers.

Identical encoding to /tmp/maxsat_k4.py — K=4 + Prior A default rule,
permutation constraints + 24 cribs + 64,800 bigram soft clauses.

Output: /tmp/k4_maxsat.wcnf (DIMACS WCNF format)
"""
from __future__ import annotations

import math
import sys
import time
from pathlib import Path

SHINKA_DIR = Path("/Users/mruckman1/Desktop/dev/k4_cipher/shinka")
sys.path.insert(0, str(SHINKA_DIR))

from pysat.formula import WCNF
from pysat.card import CardEnc, EncType

from kryptos.constants import K4
from kryptos.cribs import CRIBS
from problem.initial import _consonant_count_array


K = 4
N_POS = 97


def color_of(i):
    cc = _consonant_count_array(K4)
    return (2 * (i % 3) + 1 * cc[i]) % K


COLOR = [color_of(i) for i in range(N_POS)]


def var(a: int, p: int, c: int) -> int:
    """Map (alphabet, plain_idx, cipher_idx) → unique positive integer 1..2704."""
    return 1 + a * 676 + p * 26 + c


def build_bigram_loglik() -> dict[str, float]:
    """Mayzner top-50 with uniform floor for remaining 626 bigrams."""
    mayzner = {
        "TH": 35.36, "HE": 30.74, "IN": 24.30, "ER": 21.79, "AN": 21.41,
        "RE": 17.84, "ON": 17.62, "AT": 14.93, "EN": 14.55, "ND": 13.51,
        "TI": 13.36, "ES": 13.16, "OR": 12.81, "TE": 12.05, "OF": 11.79,
        "ED": 11.69, "IS": 11.28, "IT": 11.21, "AL": 10.92, "AR": 10.75,
        "ST": 10.55, "TO": 10.47, "NT": 10.41, "NG":  9.55, "SE":  9.32,
        "HA":  9.26, "AS":  8.71, "OU":  8.71, "IO":  8.30, "LE":  8.27,
        "VE":  8.25, "CO":  7.94, "ME":  7.93, "DE":  7.65, "HI":  7.63,
        "RI":  7.28, "RO":  7.27, "IC":  6.99, "NE":  6.92, "EA":  6.88,
        "RA":  6.86, "CE":  6.51, "LI":  6.23, "CH":  5.98, "LL":  5.79,
        "BE":  5.78, "MA":  5.65, "SI":  5.55, "OM":  5.54, "UR":  5.42,
    }
    top_total = sum(mayzner.values())
    floor_freq = (1000.0 - top_total) / 626.0
    standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    loglik = {}
    for p1 in standard:
        for p2 in standard:
            bg = p1 + p2
            freq = mayzner.get(bg, floor_freq)
            prob = freq / 1000.0
            loglik[bg] = math.log(prob)
    return loglik


def get_crib_constraints():
    out = []
    for crib in CRIBS:
        for offset, (p, c) in enumerate(zip(crib.plaintext, crib.ciphertext)):
            pos = crib.start - 1 + offset
            out.append((pos, ord(p) - 65, ord(c) - 65, COLOR[pos]))
    return out


def build_wcnf(weight_scale: int = 1000) -> WCNF:
    print("Building WCNF...")
    wcnf = WCNF()

    # (1) Permutation hard constraints
    n_perm = 0
    for a in range(K):
        for p in range(26):
            vars_for_p = [var(a, p, c) for c in range(26)]
            eq1 = CardEnc.equals(lits=vars_for_p, bound=1, encoding=EncType.pairwise)
            for clause in eq1.clauses:
                wcnf.append(clause)
                n_perm += 1
        for c in range(26):
            vars_for_c = [var(a, p, c) for p in range(26)]
            eq1 = CardEnc.equals(lits=vars_for_c, bound=1, encoding=EncType.pairwise)
            for clause in eq1.clauses:
                wcnf.append(clause)
                n_perm += 1
    print(f"  {n_perm} permutation hard clauses")

    # (2) Cribs as unit hard clauses
    cribs = get_crib_constraints()
    for (pos, p, c, a) in cribs:
        wcnf.append([var(a, p, c)])
    print(f"  {len(cribs)} crib unit clauses")

    # (3) Bigram soft constraints
    bigram_loglik = build_bigram_loglik()
    max_ll = max(bigram_loglik.values())
    standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    n_soft = 0
    for i in range(1, N_POS):
        a_prev = COLOR[i - 1]
        a_curr = COLOR[i]
        c_prev = ord(K4[i - 1]) - 65
        c_curr = ord(K4[i]) - 65
        for p_prev_idx in range(26):
            for p_curr_idx in range(26):
                bg = standard[p_prev_idx] + standard[p_curr_idx]
                ll = bigram_loglik[bg]
                deficit = max_ll - ll
                weight = int(round(deficit * weight_scale))
                if weight > 0:
                    wcnf.append(
                        [-var(a_prev, p_prev_idx, c_prev),
                         -var(a_curr, p_curr_idx, c_curr)],
                        weight=weight,
                    )
                    n_soft += 1
    print(f"  {n_soft} bigram soft clauses")
    print(f"  total: {len(wcnf.hard)} hard, {len(wcnf.soft)} soft")
    return wcnf


def main():
    t0 = time.monotonic()
    wcnf = build_wcnf()
    out_path = Path("/tmp/k4_maxsat.wcnf")
    print(f"\nDumping to {out_path}...")
    wcnf.to_file(str(out_path))
    elapsed = time.monotonic() - t0
    size_mb = out_path.stat().st_size / 1e6
    print(f"  size: {size_mb:.1f} MB")
    print(f"  total wall: {elapsed:.1f}s")
    print(f"\nReady. Launch with:")
    print(f"  bash /Users/mruckman1/Desktop/dev/k4_cipher/external/run_maxsat_overnight.sh")


if __name__ == "__main__":
    main()
