"""073 — 3-stage tiny composite: transposition o substitution o transposition.

The next rung of Sanborn's "I modified the systems": P -> T2 -> sub -> T1 -> K4,
with T1,T2 small hand-executable block permutations and sub a short-period
substitution. Reduction (exact KPA): let M' = T1^{-1}(K4) = sub(T2(P)). Then
M'[i] = sub(P[perm2[i]], key[i mod L]); for a crib position p, the K4-index is
i=inv2[p], giving key[(inv2[p]) mod L] = keyfrom(M'[inv2[p]], P[p]). Sweep
(T1,T2,L,alphabet,convention); fully-pinned -> decrypt + hexagram-score +
byte-verify. A planted self-test validates the 3-stage KPA first.

Output: experiments/results/<date>_073_three_stage_composite.jsonl
"""

from __future__ import annotations

import json
import time
from datetime import date
from itertools import permutations

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD
from kryptos.constants import K4
from kryptos.cribs import CRIBS

N = 97
CRIB_PLAIN = {}
for c in CRIBS:
    for off, p in enumerate(c.plaintext):
        CRIB_PLAIN[c.start - 1 + off] = p
CRIB_POS = sorted(CRIB_PLAIN)
ALPHABETS = {"standard": STANDARD, "kryptos_keyed": KRYPTOS_KEYED}


def block_perm(d, pi):
    perm = list(range(N))
    for b in range(N // d):
        for t in range(d):
            perm[b * d + t] = b * d + pi[t]
    return perm


def invert(perm):
    inv = [0] * N
    for k, p in enumerate(perm):
        inv[p] = k
    return inv


def keyfrom(c, p, conv):
    return (c - p) % 26 if conv == "vigenere" else (c + p) % 26 if conv == "beaufort" else (p - c) % 26


def dec(c, k, conv):
    return (c - k) % 26 if conv == "vigenere" else (k - c) % 26 if conv == "beaufort" else (c + k) % 26


def enc(p, k, conv):
    return (p + k) % 26 if conv == "vigenere" else (k - p) % 26 if conv == "beaufort" else (p - k) % 26


def all_block_perms(dmax=5):
    out = []
    for d in range(2, dmax + 1):
        for pi in permutations(range(d)):
            out.append((d, list(pi)))
    return out


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_073_three_stage_composite.jsonl"
    t0 = time.perf_counter()

    # ---- self-test ----
    import random
    rng = random.Random(5)
    a = KRYPTOS_KEYED
    p1 = block_perm(3, [2, 0, 1]); i1 = invert(p1)
    p2 = block_perm(2, [1, 0]); i2 = invert(p2)
    L = 4; key = [rng.randrange(26) for _ in range(L)]
    P0 = [rng.randrange(26) for _ in range(N)]
    # encrypt P0: T2 then sub then T1
    M = [P0[p2[i]] for i in range(N)]                       # T2(P0)
    Nn = [enc(M[i], key[i % L], "vigenere") for i in range(N)]   # sub
    Ct = [Nn[p1[i]] for i in range(N)]                      # T1
    # KPA recover key
    Mp = [Ct[i1[j]] for j in range(N)]                      # M' = T1^{-1}(Ct) = sub(T2(P0))
    slot = {}
    for p in range(N):
        idx = i2[p]; kv = keyfrom(Mp[idx], P0[p], "vigenere"); s = idx % L
        slot.setdefault(s, kv)
    rec = [slot[s] for s in range(L)]
    assert rec == key, f"3-stage self-test key mismatch {rec} vs {key}"

    BPERMS = all_block_perms(5)                              # 152 perms (d=2..5)
    best = (-99.0, None)
    n_perm_pairs = 0
    decryptable = 0
    solved = None

    with open(out, "w") as f:
        for an, alpha in ALPHABETS.items():
            k4 = [alpha.index(ch) for ch in K4]
            cp = {p: alpha.index(CRIB_PLAIN[p]) for p in CRIB_POS}
            for (d1, pi1) in BPERMS:
                perm1 = block_perm(d1, pi1); inv1 = invert(perm1)
                Mp = [k4[inv1[j]] for j in range(N)]        # M' depends on T1, alpha
                for (d2, pi2) in BPERMS:
                    perm2 = block_perm(d2, pi2); inv2 = invert(perm2)
                    n_perm_pairs += 1
                    for conv in _kpa.CONVENTIONS:
                        pairs = [(inv2[p], keyfrom(Mp[inv2[p]], cp[p], conv)) for p in CRIB_POS]
                        for L in range(1, 25):
                            slot = {}
                            ok = True
                            for idx, kv in pairs:
                                s = idx % L
                                if s in slot and slot[s] != kv:
                                    ok = False; break
                                slot[s] = kv
                            if not ok or len(slot) != L:
                                continue
                            decryptable += 1
                            key = [slot[s] for s in range(L)]
                            # decrypt: P[perm2[i]] = dec(Mp[i], key[i%L])
                            P = [None] * N
                            for i in range(N):
                                P[perm2[i]] = alpha.at(dec(Mp[i], key[i % L], conv))
                            P = "".join(P)
                            if any(P[p] != CRIB_PLAIN[p] for p in CRIB_POS):
                                continue
                            sc = _kpa.score_free_text(P)
                            if sc > best[0]:
                                best = (sc, {"alphabet": an, "T1": [d1, pi1], "T2": [d2, pi2],
                                             "L": L, "conv": conv, "plaintext": P, "hex": round(sc, 2)})
                            if sc > -16.0:
                                f.write(json.dumps({"alphabet": an, "T1": [d1, pi1], "T2": [d2, pi2],
                                                    "L": L, "conv": conv, "hex": round(sc, 2),
                                                    "plaintext": P}) + "\n")
                            if sc > -15.0:
                                solved = {"alphabet": an, "T1": [d1, pi1], "T2": [d2, pi2],
                                          "L": L, "conv": conv, "plaintext": P}

    elapsed = time.perf_counter() - t0
    bi = best[1]
    status = "solved" if solved else ("promising" if (bi and bi["hex"] > -16.0) else "ruled_out")
    insights = [
        f"3-stage T1.sub.T2 with block perms d=2-5 (152 each -> {n_perm_pairs:,} T-pairs/alphabet) x L=1-24 "
        f"x 3 conventions x 2 alphabets; {decryptable:,} fully crib-pinned decryptable combos. "
        f"Best free hexagram {best[0]:.2f}/char.",
        (f"Best: {bi['alphabet']} T1={bi['T1']} T2={bi['T2']} L={bi['L']} {bi['conv']}, hex {bi['hex']} -> "
         f"{bi['plaintext'][:46]}..." if bi else "No fully-pinned 3-stage composite."),
    ]
    if status == "ruled_out":
        insights.append("No 3-stage block-transposition / short-substitution composite decrypts K4 to English. "
                        "Adding a third tiny stage does not escape the 2-stage wall (043/064).")
    write_verdict(out, Verdict(
        exp="073", title="3-stage tiny composite (transposition o substitution o transposition)",
        hypothesis="K4 = T1(sub(T2(P))) with two small block transpositions and a short substitution",
        status=status, best_score=best[0], best_partial=f"{decryptable} decryptable combos",
        search_space=n_perm_pairs, elapsed_s=round(elapsed, 1), solved_params=solved, insights=insights,
        next_steps=(["verify & announce"] if solved else
                    ["this exhausts tiny multi-stage transposition+substitution; remaining = dynamic/mechanical"]),
        metrics={"best": bi})
    )
    print(f"\n{decryptable} decryptable; best hex {best[0]:.2f}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
