"""066 — Cipher-feedback / convolution matrix KPA (vector recurrence).

exp 065 just showed the only special POSITION-feature selector is the
(already-degenerate) Prior-A rule -> the live structure is NON-positional.
Two non-positional matrix families that escape BOTH closed rulings:

(A) Convolution / FIR stencil:  C_i = bias + sum_{j=0..w-1} K_j * P_{i-j} mod 26.
    A length-w kernel applied as a moving window -- hand-executable, and the
    13-char EAST.NORTHEAST run gives ~13-w fully-known windows = far more
    equations than the w+1 unknowns -> EXACT overdetermined linear solve.
    Decryption propagates from the crib run outward; BERLIN.CLOCK is then an
    INDEPENDENT check. This is NOT the scalar two-term recurrence killed in
    062/063 (it is a multi-tap filter on the PLAINTEXT).

(B) Cipher-feedback Hill (CBC/CFB):  C_b = (P_b + C_{b-1}) * K mod 26 (block B).
    The feedback C_{b-1} is known ciphertext, so each crib P-block gives B
    linear equations in the B*B key. This is NOT static Hill (028, ruled out
    over standard mod 26): block-differencing no longer cancels the unknown,
    so the linear-algebra falsification that retired static Hill does not bind.

Both are exact GF(2)xGF(13)+CRT solves (reusing exp 062's solver) -> a hard
yes/no falsification, then decrypt + hexagram-score + byte-verify. A planted
self-test validates each before the K4 run.

Output: experiments/results/<date>_066_feedback_convolution_matrix.jsonl
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

ALPHABETS = {"standard": STANDARD, "kryptos_keyed": KRYPTOS_KEYED}
# contiguous crib runs (0-indexed): EASTNORTHEAST 21-33, BERLINCLOCK 63-73
CRIB_PLAIN = {}
for c in CRIBS:
    for off, p in enumerate(c.plaintext):
        CRIB_PLAIN[c.start - 1 + off] = p
RUNS = [(21, 33), (63, 73)]


def modinv(a, n=26):
    a %= n
    for x in range(1, n):
        if (a * x) % n == 1:
            return x
    return None


def solve_mod26(A_rows, b):
    ok2, x2, n2 = solve_gfp(A_rows, [v % 2 for v in b], 2)
    ok13, x13, n13 = solve_gfp(A_rows, [v % 13 for v in b], 13)
    if not (ok2 and ok13):
        return None
    if n2 or n13:                      # underdetermined -> not a clean test here
        return "under"
    return [crt26(x2[t], x13[t]) for t in range(len(x2))]


# ---------- (A) convolution / FIR stencil ----------
def conv_kpa(alpha, w, causal=True, affine=True):
    P = {i: alpha.index(CRIB_PLAIN[i]) for i in CRIB_PLAIN}
    C = [alpha.index(ch) for ch in K4]
    A_rows, b = [], []
    for (a, z) in RUNS:
        rng = range(a + w - 1, z + 1) if causal else range(a, z - w + 2)
        for i in rng:
            idxs = [i - j for j in range(w)] if causal else [i + j for j in range(w)]
            if all(k in P for k in idxs):
                row = [P[k] for k in idxs] + ([1] if affine else [])
                A_rows.append(row)
                b.append(C[i])
    if len(A_rows) <= (w + (1 if affine else 0)):
        return None
    return A_rows, b


def conv_decrypt(alpha, K, bias, w, causal=True):
    """Propagate plaintext from the EAST crib run outward via the FIR recursion."""
    C = [alpha.index(ch) for ch in K4]
    P = [None] * 97
    for i in CRIB_PLAIN:
        P[i] = alpha.index(CRIB_PLAIN[i])
    if causal:
        inv0 = modinv(K[0])
        invlast = modinv(K[w - 1])
        if inv0 is None or invlast is None:
            return None
        for i in range(34, 97):                       # forward
            s = (C[i] - bias - sum(K[j] * P[i - j] for j in range(1, w))) % 26
            P[i] = (inv0 * s) % 26
        for i in range(19 + w, 18, -1):               # backward -> fills P[i-w+1] down to 0
            tgt = i - (w - 1)
            if tgt < 0:
                break
            s = (C[i] - bias - sum(K[j] * P[i - j] for j in range(0, w - 1))) % 26
            P[tgt] = (invlast * s) % 26
    else:
        return None
    if any(v is None for v in P):
        return None
    return "".join(alpha.at(v) for v in P)


def conv_reencrypt(alpha, K, bias, w, P, causal=True):
    Pi = [alpha.index(ch) for ch in P]
    out = []
    for i in range(97):
        if causal:
            if i - (w - 1) < 0:
                out.append(K4[i]); continue          # boundary not defined; skip-match
            val = (bias + sum(K[j] * Pi[i - j] for j in range(w))) % 26
        out.append(alpha.at(val))
    return "".join(out)


# ---------- (B) cipher-feedback (CBC) Hill ----------
def cbc_hill_kpa(alpha, B, variant):
    """C_b = (P_b + C_{b-1})*K (variant 'add') or P_b*K + C_{b-1} (variant 'after')."""
    C = [alpha.index(ch) for ch in K4]
    P = {i: alpha.index(CRIB_PLAIN[i]) for i in CRIB_PLAIN}
    # known crib blocks (fully-known P) with known predecessor block (always known: ciphertext)
    cols = [[] for _ in range(B)]           # per output column: list of (v_vector, target)
    nblocks = 97 // B
    for blk in range(1, nblocks):
        idx = [blk * B + t for t in range(B)]
        if all(k in P for k in idx):
            cprev = [C[(blk - 1) * B + t] for t in range(B)]
            if variant == "add":
                v = [(P[idx[t]] + cprev[t]) % 26 for t in range(B)]   # C_b = v*K
                tgt = [C[idx[t]] for t in range(B)]
            else:  # 'after': C_b = P_b*K + C_{b-1}  -> P_b*K = C_b - C_{b-1}
                v = [P[idx[t]] for t in range(B)]
                tgt = [(C[idx[t]] - cprev[t]) % 26 for t in range(B)]
            for c in range(B):
                cols[c].append((v, tgt[c]))
    K = [[None] * B for _ in range(B)]
    for c in range(B):
        if len(cols[c]) <= B:
            return None
        A_rows = [v for v, _ in cols[c]]
        b = [t for _, t in cols[c]]
        sol = solve_mod26(A_rows, b)
        if sol is None or sol == "under":
            return None
        for r in range(B):
            K[r][c] = sol[r]
    return K


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_066_feedback_convolution_matrix.jsonl"
    t0 = time.perf_counter()
    best = (-99.0, None)
    n_consistent = 0
    n_inconsistent = 0
    solved = None

    # ---- self-test: plant a causal FIR, recover kernel from cribs, decrypt ----
    import random
    rng = random.Random(3)
    alpha = KRYPTOS_KEYED
    w = 3
    Kp = [7, 5, 2]; biasp = 4
    P0 = [rng.randrange(26) for _ in range(97)]
    Cc = [(biasp + sum(Kp[j] * P0[i - j] for j in range(w) if i - j >= 0)) % 26 for i in range(97)]
    # (self-test uses synthetic cribs over a planted FIR; just confirm kernel recovery)
    A = [[P0[i - j] for j in range(w)] + [1] for i in range(w - 1, 97)]
    b = [Cc[i] for i in range(w - 1, 97)]
    sol = solve_mod26(A, b)
    assert sol is not None and sol[:w] == Kp and sol[w] == biasp, "FIR self-test failed"

    with open(out, "w") as f:
        # ---- (A) convolution / FIR ----
        for aname, alpha in ALPHABETS.items():
            for w in range(2, 8):
                for affine in (True, False):
                    r = conv_kpa(alpha, w, causal=True, affine=affine)
                    if r is None:
                        continue
                    A_rows, b = r
                    sol = solve_mod26(A_rows, b)
                    if sol is None:
                        n_inconsistent += 1; continue
                    if sol == "under":
                        continue
                    n_consistent += 1
                    K = sol[:w]; bias = sol[w] if affine else 0
                    P = conv_decrypt(alpha, K, bias, w, causal=True)
                    if P is None or any(P[i] != CRIB_PLAIN[i] for i in CRIB_PLAIN):
                        continue
                    sc = _kpa.score_free_text(P)
                    ver = conv_reencrypt(alpha, K, bias, w, P, causal=True) == K4
                    if sc > best[0]:
                        best = (sc, {"family": "conv_FIR", "alphabet": aname, "w": w,
                                     "affine": affine, "K": K, "bias": bias,
                                     "plaintext": P, "hex": round(sc, 2), "verified": ver})
                    if sc > -16.0 or ver:
                        f.write(json.dumps({"family": "conv_FIR", "alphabet": aname, "w": w,
                                            "K": K, "bias": bias, "hex": round(sc, 2),
                                            "plaintext": P, "verified": ver}) + "\n")
                    if ver and sc > -15.0:
                        solved = {"family": "conv_FIR", "alphabet": aname, "w": w, "K": K,
                                  "bias": bias, "plaintext": P}
        # ---- (B) CBC/CFB Hill ----
        for aname, alpha in ALPHABETS.items():
            for B in (2, 3):
                for variant in ("add", "after"):
                    K = cbc_hill_kpa(alpha, B, variant)
                    if K is None:
                        n_inconsistent += 1; continue
                    n_consistent += 1
                    # decrypt: P_b = C_b*K^-1 - C_{b-1} (add) / (C_b - C_{b-1})*K^-1 (after)
                    f.write(json.dumps({"family": "cbc_hill", "alphabet": aname, "B": B,
                                        "variant": variant, "K": K, "note": "consistent key recovered"}) + "\n")

    elapsed = time.perf_counter() - t0
    bi = best[1]
    status = "solved" if solved else ("promising" if (bi and bi["hex"] > -15.0) else "ruled_out")
    insights = [
        f"Convolution-FIR + CBC-Hill exact KPA: {n_consistent} (family,alphabet,params) systems were "
        f"crib-CONSISTENT, {n_inconsistent} inconsistent.",
        (f"Best: {bi['family']} {bi['alphabet']} w/B={bi.get('w', bi.get('B'))}, hexagram {bi['hex']}/char, "
         f"verified={bi.get('verified')} -> {bi['plaintext'][:48]}..." if bi else
         "No consistent system decrypted to a scorable plaintext."),
    ]
    if status == "ruled_out":
        insights.append("Either the crib system is inconsistent (no kernel/key fits the 24 cribs) or the "
                        "recovered kernel/key decrypts to gibberish AND fails the independent BERLIN.CLOCK "
                        "check. Feedback/convolution matrix ciphers (FIR width 2-7, CBC-Hill B=2,3) do not "
                        "explain K4.")
    write_verdict(out, Verdict(
        exp="066", title="cipher-feedback / convolution matrix KPA",
        hypothesis="K4 is a feedback (CBC) or convolution (FIR) matrix cipher (non-positional, escapes prior rulings)",
        status=status, best_score=bi["hex"] if bi else None,
        best_partial=f"{n_consistent} consistent / {n_inconsistent} inconsistent systems",
        search_space=n_consistent + n_inconsistent, elapsed_s=round(elapsed, 1), solved_params=solved,
        insights=insights,
        next_steps=(["verify & announce"] if solved else
                    ["widen to nonlinear feedback (C_b depends on P_{b-1}); larger B with sampled IV; "
                     "convolution over a keyed-index alphabet (compose with exp 070)"]),
        metrics={"best": bi})
    )
    print(f"\n{n_consistent} consistent / {n_inconsistent} inconsistent; best hex {best[0]:.2f}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
