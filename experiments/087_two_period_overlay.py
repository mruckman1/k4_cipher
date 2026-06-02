"""087 — Q3 + short-Vigenere additive overlay: exact "sum of two short periods" KPA.

exp 084's fingerprint says K4's modification of Quagmire-III is a FLATTENING one;
exp 086 ruled out the progressive-key reading by exact algebra. The next
flattening modification it pointed at is an ADDITIVE OVERLAY: run K1/K2's
period-K Quagmire, then add a second short Vigenere key of period L. The net
per-position key is then a SUM OF TWO SHORT PERIODS:

    k_i = a[i mod K] + b[i mod L]   (mod 26)

This is the one regime the repeating-key sweeps MISSED: a single periodic key
was searched only to period <=24 (043/015/031), but a sum of a K- and an
L-period key has effective period lcm(K,L), which exceeds 24 for most coprime-ish
(K,L) (e.g. 5x7=35, 7x8=56, 9x11=99) -- and exp 085 says flattening needs an
effective alphabet count >=4, which a long lcm supplies. It also satisfies both
hard facts (additive => one-to-one positional; long effective period => flattens).

KPA is EXACT, not search. The 24 crib shifts give 24 equations a[r]+b[s]=k over
Z26; the a-nodes and b-nodes form a bipartite constraint graph, solved by
potential propagation (BFS with a consistency check on every cycle). A fully-
determined consistent solution (the constraint graph connects all needed
residues) -> decrypt all 97 + hexagram-score. 24 equations vs K+L-1 free params
is strongly overdetermined, so any consistent fit is structurally meaningful, not
chance (quantified by a scrambled-crib control).

$0, local, pure decipherment. Output:
experiments/results/<date>_087_two_period_overlay.jsonl
"""

from __future__ import annotations

import json
import math
import random
import time
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, keyed_alphabet
from kryptos.constants import K4

N = 97
ALPHS = {"kryptos_keyed": KRYPTOS_KEYED, "standard": STANDARD,
         "keyed_PALIMPSEST": keyed_alphabet("PALIMPSEST"),
         "keyed_ABSCISSA": keyed_alphabet("ABSCISSA")}


def crib_keys(alpha, conv):
    out = []
    for pos, pi, ci in _kpa.crib_position_triples(alpha):
        if conv == "vigenere":
            k = (ci - pi) % 26
        elif conv == "beaufort":
            k = (ci + pi) % 26
        else:
            k = (pi - ci) % 26
        out.append((pos, k))
    return out


def solve_two_period(cribkeys, K, L):
    """Solve k_i = a[i%K] + b[i%L] (mod 26) from cribs by potential propagation.

    Nodes: a-nodes 0..K-1, b-nodes K..K+L-1. Edge (pos,k): x[a]-x[b]=k where
    x[a]=a[r], x[b]=-b[s], so k=a[r]+b[s]. Returns (x, comp) if consistent (x is
    the per-node potential, comp the component id), else None.
    """
    adj = {i: [] for i in range(K + L)}
    for pos, k in cribkeys:
        u = pos % K
        v = K + pos % L
        adj[u].append((v, k % 26))     # x[u] - x[v] = k
        adj[v].append((u, (-k) % 26))  # x[v] - x[u] = -k
    x = {}
    comp = {}
    cid = 0
    for start in range(K + L):
        if start in x:
            continue
        x[start] = 0
        comp[start] = cid
        stack = [start]
        while stack:
            n = stack.pop()
            for m, w in adj[n]:
                val = (x[n] - w) % 26
                if m in x:
                    if x[m] != val:
                        return None  # cycle inconsistency
                else:
                    x[m] = val
                    comp[m] = cid
                    stack.append(m)
        cid += 1
    return x, comp


def keystream_two_period(x, comp, K, L):
    """k_i for all 97 positions, or None if any position is under-determined
    (its a-node and b-node lie in different components -> relative offset free)."""
    ks = []
    for i in range(N):
        ua, vb = i % K, K + i % L
        if comp[ua] != comp[vb]:
            return None
        ks.append((x[ua] - x[vb]) % 26)
    return ks


def decrypt(alpha, conv, ks):
    out = []
    for i, ch in enumerate(K4):
        ci = alpha.index(ch)
        k = ks[i] % 26
        if conv == "vigenere":
            pi = (ci - k) % 26
        elif conv == "beaufort":
            pi = (k - ci) % 26
        else:
            pi = (ci + k) % 26
        out.append(alpha.at(pi))
    return "".join(out)


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_087_two_period_overlay.jsonl"
    t0 = time.perf_counter()

    # (K,L) pairs in the UNCOVERED regime: lcm>24 (new) and <=N, K<=L, both 2..12,
    # and solvable-to-connected (need K+L-1 <= 24 crib equations).
    pairs = []
    for K in range(2, 13):
        for L in range(K, 13):
            lcm = K * L // math.gcd(K, L)
            if 24 < lcm <= N and (K + L - 1) <= 24:
                pairs.append((K, L))

    fits = []
    determined_fits = []
    best = (-99.0, None)
    solved = None
    n_configs = 0

    with open(out, "w") as f:
        for an, alpha in ALPHS.items():
            for conv in _kpa.CONVENTIONS:
                ck = crib_keys(alpha, conv)
                for (K, L) in pairs:
                    n_configs += 1
                    sol = solve_two_period(ck, K, L)
                    if sol is None:
                        continue
                    x, comp = sol
                    fits.append({"alpha": an, "conv": conv, "K": K, "L": L})
                    ks = keystream_two_period(x, comp, K, L)
                    if ks is None:
                        continue  # consistent but under-determined
                    P = decrypt(alpha, conv, ks)
                    sc = _kpa.score_free_text(P)
                    rec = {"alpha": an, "conv": conv, "K": K, "L": L,
                           "lcm": K * L // math.gcd(K, L), "hex": round(sc, 2), "plaintext": P}
                    determined_fits.append(rec)
                    f.write(json.dumps(rec) + "\n")
                    if sc > best[0]:
                        best = (sc, rec)
                    if sc > -15.0:
                        solved = rec

    # ---- scrambled-crib control ----
    rng = random.Random(0)
    base_ck = crib_keys(KRYPTOS_KEYED, "vigenere")
    positions = [p for p, _ in base_ck]
    keyvals = [k for _, k in base_ck]
    TRIALS = 1000
    ctrl_determined = 0
    for _ in range(TRIALS):
        shuf = keyvals[:]
        rng.shuffle(shuf)
        sck = list(zip(positions, shuf))
        hit = False
        for (K, L) in pairs:
            sol = solve_two_period(sck, K, L)
            if sol and keystream_two_period(sol[0], sol[1], K, L) is not None:
                hit = True
                break
        ctrl_determined += 1 if hit else 0
    ctrl_p = ctrl_determined / TRIALS

    elapsed = time.perf_counter() - t0
    bi = best[1]

    if solved:
        status = "solved"
    elif bi and bi["hex"] > -15.0:
        status = "promising"
    elif determined_fits and ctrl_p < 0.05 and bi and bi["hex"] > -16.0:
        status = "promising"
    else:
        status = "ruled_out"

    insights = [
        f"Sum-of-two-short-periods overlay, EXACT crib KPA over {n_configs} configs "
        f"({len(ALPHS)} alphabets x 3 conventions x {len(pairs)} (K,L) pairs with 24<lcm<={N}). "
        f"{len(fits)} configs admitted a consistent solution; {len(determined_fits)} were fully determined "
        f"(constraint graph connected enough to fix all 97 positions).",
        (f"Best fully-determined fit: {bi['alpha']}/{bi['conv']} K={bi['K']} L={bi['L']} (lcm {bi['lcm']}) "
         f"free-hex {bi['hex']} -> {bi['plaintext'][:44]}..." if bi else
         "NO (K,L) overlay admitted a fully-determined consistent fit against the 24 cribs."),
        f"SCRAMBLED-CRIB CONTROL: a determined two-period fit arises for {ctrl_p*100:.2f}% of randomly permuted "
        f"crib-shift assignments ({TRIALS} trials) -- {'a real fit is structurally meaningful, not chance' if ctrl_p < 0.05 else 'fits are common enough to be chance at these (K,L)'}.",
    ]
    if status == "ruled_out":
        insights.append(
            "VERDICT: the 24 crib shifts are not a sum of two short periodic keys (lcm>24) in any tested keyed "
            "alphabet that decrypts to English -- the Q3 + short-Vigenere additive overlay is RULED OUT. "
            "Combined with 086, the flattening modifications the 084 fingerprint favoured (progressive, "
            "additive overlay) are now both closed; the live path is the memorable hand-crafted-alphabet "
            "triples decrypting under a simple selector (README #2 / exp 088).")

    write_verdict(out, Verdict(
        exp="087", title="Q3 + short-Vigenere additive overlay (sum of two short periods) exact KPA",
        hypothesis="K4's key is a sum of two short periodic keys (effective period lcm>24), the additive-"
                   "overlay flattening modification favoured by exp 084",
        status=status, best_score=(bi["hex"] if (bi and status in ("solved", "promising")) else None),
        best_partial=(f"{len(determined_fits)} determined fits; best free-hex {bi['hex']} "
                      f"({bi['alpha']}/{bi['conv']} K={bi['K']} L={bi['L']})" if bi else
                      "no determined two-period fit against 24 cribs"),
        search_space=n_configs, elapsed_s=round(elapsed, 1), solved_params=solved,
        insights=insights,
        next_steps=(["verify byte-exact & announce"] if solved else
                    ["additive-overlay flattening closed; build the memorable hand-crafted-alphabet triples "
                     "that 3-cover the cribs and decrypt under a simple period-3/W-aligned selector "
                     "(README direction #2 / exp 088) -- the one escape hatch the squeeze bound leaves open"]),
        metrics={"n_determined_fits": len(determined_fits), "best": bi, "control_p": round(ctrl_p, 4),
                 "n_pairs": len(pairs)}),
    )
    print(f"\n{len(determined_fits)} determined two-period fits over {n_configs} configs ({len(pairs)} (K,L) "
          f"pairs); best free-hex {best[0]:.2f}; control p={ctrl_p:.4f}; status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
