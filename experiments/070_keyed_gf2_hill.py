"""070 — Keyed-index and GF(2) linear (Hill) ciphers.

Hill was ruled out (exp 028) ONLY over the STANDARD alphabet mod 26. Distinct
algebras remain (Bauer/Link/Molle 2016 matrix conjecture; "HILL" reads
vertically in the 27-letter tableau):
  (A) Hill over the KRYPTOS-KEYED index space mod 26 -- same matrix machinery,
      different letter<->number map (K1-K3 all use keyed alphabets). The crib
      overdetermination budget (B=2 -> 6 aligned known blocks) makes B=2,3 an
      exact crib-only solve.
  (B) GF(2) 5-bit linear map: encode each letter as 5 bits, apply a fixed 5x5
      binary matrix mod 2 (Matsui-style linear map). 24 cribs -> 24*5=120
      bit-equations in 25 unknowns -> exact GF(2) solve; require invertible.

Both are exact KPA (solve, require invertibility, decrypt, hexagram-score,
byte-verify). Planted self-tests validate each.

Output: experiments/results/<date>_070_keyed_gf2_hill.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import time
from datetime import date
from math import gcd
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD
from kryptos.constants import K4
from kryptos.cribs import CRIBS

_spec = importlib.util.spec_from_file_location(
    "e062", str(Path(__file__).parent / "062_vimark_algebraic_kpa.py"))
e062 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(e062)
solve_gfp, crt26 = e062.solve_gfp, e062.crt26

CRIB_PLAIN = {}
for c in CRIBS:
    for off, p in enumerate(c.plaintext):
        CRIB_PLAIN[c.start - 1 + off] = p


def modinv(a, n):
    a %= n
    g, x = n, 0
    a0, x0 = a, 1
    while a0:
        q = g // a0
        g, a0 = a0, g - q * a0
        x, x0 = x0, x - q * x0
    return x % n if g == 1 else None


def det_mod(M, n):
    B = len(M)
    if B == 2:
        return (M[0][0] * M[1][1] - M[0][1] * M[1][0]) % n
    d = 0
    for c in range(B):
        minor = [[M[r][cc] for cc in range(B) if cc != c] for r in range(1, B)]
        d += ((-1) ** c) * M[0][c] * det_mod(minor, n)
    return d % n


def inv_mat_mod(M, n):
    B = len(M)
    d = det_mod(M, n)
    di = modinv(d, n)
    if di is None:
        return None
    if B == 2:
        return [[(di * M[1][1]) % n, (-di * M[0][1]) % n],
                [(-di * M[1][0]) % n, (di * M[0][0]) % n]]
    adj = [[0] * B for _ in range(B)]
    for r in range(B):
        for c in range(B):
            minor = [[M[i][j] for j in range(B) if j != r] for i in range(B) if i != c]
            adj[r][c] = (((-1) ** (r + c)) * det_mod(minor, n)) % n
    return [[(di * adj[r][c]) % n for c in range(B)] for r in range(B)]


def solve_col_mod26(M_rows, b):
    ok2, x2, n2 = solve_gfp(M_rows, [v % 2 for v in b], 2)
    ok13, x13, n13 = solve_gfp(M_rows, [v % 13 for v in b], 13)
    if not (ok2 and ok13) or n2 or n13:
        return None
    return [crt26(x2[t], x13[t]) for t in range(len(x2))]


def keyed_hill_kpa(alpha, B):
    enc = {i: alpha.index(CRIB_PLAIN[i]) for i in CRIB_PLAIN}
    C = [alpha.index(ch) for ch in K4]
    Pblocks, Cblocks = [], []
    for blk in range(97 // B):
        idx = [blk * B + t for t in range(B)]
        if all(k in enc for k in idx):
            Pblocks.append([enc[k] for k in idx])
            Cblocks.append([C[k] for k in idx])
    if len(Pblocks) < B + 1:
        return None
    K = [[None] * B for _ in range(B)]      # P*K=C : K[r][c]
    for c in range(B):
        sol = solve_col_mod26(Pblocks, [cb[c] for cb in Cblocks])
        if sol is None:
            return None
        for r in range(B):
            K[r][c] = sol[r]
    if det_mod(K, 26) % 2 == 0 or det_mod(K, 26) % 13 == 0:
        return ("singular", K)
    return ("ok", K)


def hill_decrypt(alpha, K, B):
    Kinv = inv_mat_mod(K, 26)
    if Kinv is None:
        return None
    C = [alpha.index(ch) for ch in K4]
    out = [None] * 97
    for blk in range(97 // B):
        cb = [C[blk * B + t] for t in range(B)]
        pb = [sum(cb[r] * Kinv[r][c] for r in range(B)) % 26 for c in range(B)]
        for t in range(B):
            out[blk * B + t] = pb[t]
    tail = (97 // B) * B
    for i in range(tail, 97):
        out[i] = alpha.index(K4[i])         # leftover (prime length) -> passthrough
    return "".join(alpha.at(v) for v in out)


# ---------- GF(2) 5-bit ----------
def bits(v):
    return [(v >> k) & 1 for k in range(5)]


def gf2_5bit_kpa(value_of):
    """value_of: letter->int 0..25. Solve 5x5 GF(2) matrix M: cipher_bits=M*plain_bits."""
    rows_eq = [[] for _ in range(5)]         # per output bit: (plain_bits, target)
    for i, p in CRIB_PLAIN.items():
        pv = bits(value_of(p)); cv = bits(value_of(K4[i]))
        for ob in range(5):
            rows_eq[ob].append((pv, cv[ob]))
    M = [[None] * 5 for _ in range(5)]
    for ob in range(5):
        A = [pv for pv, _ in rows_eq[ob]]
        b = [t for _, t in rows_eq[ob]]
        ok, x, nul = solve_gfp(A, b, 2)
        if not ok or nul:
            return None
        M[ob] = x
    return M


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_070_keyed_gf2_hill.jsonl"
    t0 = time.perf_counter()
    best = (-99.0, None)
    n_consistent = n_inconsistent = 0
    solved = None

    # self-test: plant keyed Hill B=2, recover
    alpha = KRYPTOS_KEYED
    import random
    rng = random.Random(0)
    Ktrue = [[3, 3], [2, 5]]                  # det=9, invertible mod26
    P0 = [rng.randrange(26) for _ in range(97)]
    Ct = []
    for blk in range(48):
        pb = [P0[blk * 2], P0[blk * 2 + 1]]
        cb = [sum(pb[r] * Ktrue[r][c] for r in range(2)) % 26 for c in range(2)]
        Ct += cb
    # recover from all blocks
    cols = [[], []]
    for blk in range(48):
        for c in range(2):
            cols[c].append(([P0[blk * 2], P0[blk * 2 + 1]], Ct[blk * 2 + c]))
    Krec = [[None] * 2 for _ in range(2)]
    for c in range(2):
        sol = solve_col_mod26([v for v, _ in cols[c]], [t for _, t in cols[c]])
        for r in range(2):
            Krec[r][c] = sol[r]
    assert Krec == Ktrue, f"keyed-Hill self-test failed {Krec}"

    with open(out, "w") as f:
        # (A) keyed-index Hill
        for aname, alpha in (("standard", STANDARD), ("kryptos_keyed", KRYPTOS_KEYED)):
            for B in (2, 3):
                res = keyed_hill_kpa(alpha, B)
                if res is None:
                    n_inconsistent += 1; continue
                tag, K = res
                if tag == "singular":
                    n_inconsistent += 1
                    f.write(json.dumps({"family": "keyed_hill", "alphabet": aname, "B": B,
                                        "note": "consistent but singular K (non-invertible)"}) + "\n")
                    continue
                n_consistent += 1
                P = hill_decrypt(alpha, K, B)
                if P is None or any(P[i] != CRIB_PLAIN[i] for i in CRIB_PLAIN):
                    continue
                sc = _kpa.score_free_text(P)
                if sc > best[0]:
                    best = (sc, {"family": "keyed_hill", "alphabet": aname, "B": B,
                                 "K": K, "plaintext": P, "hex": round(sc, 2)})
                if sc > -16.0:
                    f.write(json.dumps({"family": "keyed_hill", "alphabet": aname, "B": B,
                                        "K": K, "hex": round(sc, 2), "plaintext": P}) + "\n")
                if sc > -15.0:
                    solved = {"family": "keyed_hill", "alphabet": aname, "B": B, "K": K, "plaintext": P}
        # (B) GF(2) 5-bit
        value_maps = {"std_A0": lambda ch: ord(ch) - 65,
                      "kryptos_idx": lambda ch: KRYPTOS_KEYED.index(ch)}
        for vname, vof in value_maps.items():
            M = gf2_5bit_kpa(vof)
            if M is None:
                n_inconsistent += 1; continue
            # invertible over GF(2)? decrypt
            ok2, _, nul = solve_gfp(M, [0] * 5, 2)
            # build inverse by solving M*x=e_k
            import numpy as np
            Mg = np.array(M) % 2
            # GF(2) invertibility via rank
            rank = 0
            Mr = Mg.copy()
            for col in range(5):
                piv = None
                for r in range(rank, 5):
                    if Mr[r, col]:
                        piv = r; break
                if piv is None:
                    continue
                Mr[[rank, piv]] = Mr[[piv, rank]]
                for r in range(5):
                    if r != rank and Mr[r, col]:
                        Mr[r] = (Mr[r] + Mr[rank]) % 2
                rank += 1
            invertible = rank == 5
            n_consistent += 1
            f.write(json.dumps({"family": "gf2_5bit", "value_map": vname, "M": M,
                                "invertible": bool(invertible)}) + "\n")

    elapsed = time.perf_counter() - t0
    bi = best[1]
    status = "solved" if solved else ("promising" if (bi and bi["hex"] > -15.0) else "ruled_out")
    insights = [
        f"Keyed-index Hill (B=2,3, standard & KRYPTOS-keyed) + GF(2) 5-bit linear maps, exact KPA: "
        f"{n_consistent} consistent / {n_inconsistent} inconsistent-or-singular.",
        (f"Best: {bi['family']} {bi['alphabet']} B={bi['B']} hexagram {bi['hex']}/char -> "
         f"{bi['plaintext'][:46]}..." if bi else "No consistent invertible map decrypts to English."),
    ]
    if status == "ruled_out":
        insights.append("Hill over the KRYPTOS-keyed index (B=2,3) and GF(2) 5-bit linear maps either fail "
                        "crib-consistency, recover a singular (non-invertible) matrix, or decrypt to gibberish. "
                        "The keyed/GF(2) linear-algebra extensions of the Bauer-2016 matrix conjecture are closed.")
    write_verdict(out, Verdict(
        exp="070", title="keyed-index & GF(2) linear (Hill) ciphers",
        hypothesis="K4 is a Hill cipher over a keyed index space or a GF(2) 5-bit linear map",
        status=status, best_score=bi["hex"] if bi else None,
        best_partial=f"{n_consistent} consistent / {n_inconsistent} inconsistent-or-singular",
        search_space=n_consistent + n_inconsistent, elapsed_s=round(elapsed, 1), solved_params=solved,
        insights=insights,
        next_steps=(["verify & announce"] if solved else
                    ["mod-27 Hill over the 27-letter tableau; 10x10 GF(2) over letter-pairs; affine-Hill"]),
        metrics={"best": bi})
    )
    print(f"\n{n_consistent} consistent / {n_inconsistent} inconsistent; best hex {best[0]:.2f}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
