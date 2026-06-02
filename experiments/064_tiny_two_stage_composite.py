"""064 — Tiny 2-stage composite: short block transposition + short-period sub.

The remaining few-parameter structure. Individually, columnar transposition
(015/029/031/043/052) and periodic substitution (002/024/062/063) are swept.
What is untested is the COUPLING of two *tiny* stages constrained jointly by
the cribs: a short, hand-executable BLOCK transposition (a fixed permutation pi
of d positions applied to every d-letter block -- "shuffle each group of d the
same way", very Scheidt-compatible) composed with a short-period substitution.

Both stage orders:
  order b (P -> sub -> T -> K4):  M = Tinv(K4) = sub(P); standard periodic KPA
                                   on (M, cribs) recovers the key.
  order a (P -> T -> sub -> K4):  K4 = sub(T(P)); the cribs pin key slots via
                                   M[invperm[p]] = P[p] -> keyfrom(K4, M).

For every (block period d in 2..7, permutation pi in S_d, order, alphabet,
convention) we derive the per-slot key the cribs force, test period-L
consistency for L=1..24, and for fully-pinned cases decrypt all 97 and
hexagram-score + byte-verify. A planted self-test validates both orders first.

Output: experiments/results/<date>_064_tiny_two_stage_composite.jsonl
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
from kryptos.scoring.lm_fitness import backoff_scorer

N = 97
CRIB_PLAIN = {}
for c in CRIBS:
    for off, p in enumerate(c.plaintext):
        CRIB_PLAIN[c.start - 1 + off] = p
CRIB_POS = sorted(CRIB_PLAIN)
ALPHABETS = {"standard": STANDARD, "kryptos_keyed": KRYPTOS_KEYED}


def block_perm(d, pi):
    """perm[k] = source index for output k; pi applied per d-block, identity tail."""
    perm = list(range(N))
    for b in range(N // d):
        for t in range(d):
            perm[b * d + t] = b * d + pi[t]
    return perm


def invert(perm):
    inv = [0] * len(perm)
    for k, p in enumerate(perm):
        inv[p] = k
    return inv


def T(text, perm):
    return "".join(text[perm[k]] for k in range(len(perm)))


def Tinv(text, inv):
    return "".join(text[inv[k]] for k in range(len(inv)))


def keyfrom(c, p, conv):
    if conv == "vigenere":
        return (c - p) % 26
    if conv == "beaufort":
        return (c + p) % 26
    return (p - c) % 26                  # variant_beaufort


def dec(c, k, conv):
    if conv == "vigenere":
        return (c - k) % 26
    if conv == "beaufort":
        return (k - c) % 26
    return (c + k) % 26


def enc(p, k, conv):
    if conv == "vigenere":
        return (p + k) % 26
    if conv == "beaufort":
        return (k - p) % 26
    return (p - k) % 26


def kpa(perm, inv, alpha, conv, order, ct, crib_plain):
    """(slot_index, key_value) pairs the cribs force, plus M (order b only)."""
    cpos = sorted(crib_plain)
    if order == "b":                     # P->sub->T->K4 ; M = Tinv(K4) = sub(P)
        M = Tinv(ct, inv)
        pairs = [(p, keyfrom(alpha.index(M[p]), alpha.index(crib_plain[p]), conv)) for p in cpos]
        return pairs, M
    # order a: P->T->sub->K4 ; M[invperm[p]] = P[p]
    pairs = [(inv[p], keyfrom(alpha.index(ct[inv[p]]), alpha.index(crib_plain[p]), conv)) for p in cpos]
    return pairs, None


def decrypt(perm, inv, alpha, conv, order, key, L, M_b, ct):
    if order == "b":
        return "".join(alpha.at(dec(alpha.index(M_b[j]), key[j % L], conv)) for j in range(N))
    Mfull = [alpha.at(dec(alpha.index(ct[i]), key[i % L], conv)) for i in range(N)]
    P = [None] * N
    for i in range(N):
        P[perm[i]] = Mfull[i]
    return "".join(P)


def reencrypt(perm, alpha, conv, order, P, key, L):
    if order == "b":                     # M=sub(P); ct=T(M)
        M = "".join(alpha.at(enc(alpha.index(P[j]), key[j % L], conv)) for j in range(N))
        return T(M, perm)
    M = T(P, perm)                       # order a: M=T(P); ct=sub(M)
    return "".join(alpha.at(enc(alpha.index(M[i]), key[i % L], conv)) for i in range(N))


def pinned_key(pairs, L):
    slot = {}
    for idx, kv in pairs:
        s = idx % L
        if s in slot and slot[s] != kv:
            return None
        slot[s] = kv
    return [slot[s] for s in range(L)] if len(slot) == L else None


def self_test():
    import random
    rng = random.Random(7)
    for order in ("a", "b"):
        d = 4
        pi = list(range(d)); rng.shuffle(pi)
        perm = block_perm(d, pi); inv = invert(perm)
        L = 5
        key = [rng.randrange(26) for _ in range(L)]
        alpha, conv = KRYPTOS_KEYED, "vigenere"
        P0 = "".join(alpha.at(rng.randrange(26)) for _ in range(N))
        K = reencrypt(perm, alpha, conv, order, P0, key, L)
        cribs = {p: P0[p] for p in range(24)}            # synthetic cribs
        pairs, M_b = kpa(perm, inv, alpha, conv, order, K, cribs)
        rec_key = pinned_key(pairs, L)
        assert rec_key is not None, f"order {order}: key not pinned"
        P = decrypt(perm, inv, alpha, conv, order, rec_key, L, M_b, K)
        assert all(P[p] == P0[p] for p in cribs), f"order {order}: decrypt mismatch"
        assert reencrypt(perm, alpha, conv, order, P0, key, L) == K
    return True


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_064_tiny_two_stage_composite.jsonl"
    assert self_test(), "composite KPA self-test failed"
    print("self-test OK for both stage orders")
    _kpa.hexagram_scorer()  # warm
    t0 = time.perf_counter()
    best = (-99.0, None)
    n_perms = 0
    decryptable = 0
    solved = None

    with open(out, "w") as f:
        for d in range(2, 8):
            for pi in permutations(range(d)):
                perm = block_perm(d, list(pi)); inv = invert(perm)
                n_perms += 1
                for aname, alpha in ALPHABETS.items():
                    for conv in _kpa.CONVENTIONS:
                        for order in ("a", "b"):
                            pairs, M_b = kpa(perm, inv, alpha, conv, order, K4, CRIB_PLAIN)
                            for L in range(1, 25):
                                key = pinned_key(pairs, L)
                                if key is None:
                                    continue
                                decryptable += 1
                                P = decrypt(perm, inv, alpha, conv, order, key, L, M_b, K4)
                                if any(P[p] != CRIB_PLAIN[p] for p in CRIB_POS):
                                    continue
                                sc = _kpa.score_free_text(P)
                                if sc > best[0]:
                                    best = (sc, {"d": d, "pi": list(pi), "order": order, "L": L,
                                                 "alphabet": aname, "convention": conv,
                                                 "plaintext": P, "hex": round(sc, 2)})
                                if sc > -16.0:
                                    f.write(json.dumps({"d": d, "pi": list(pi), "order": order, "L": L,
                                                        "alphabet": aname, "convention": conv,
                                                        "hex": round(sc, 2), "plaintext": P}) + "\n")
                                if sc > -15.0 and reencrypt(perm, alpha, conv, order, P, key, L) == K4:
                                    solved = {"d": d, "pi": list(pi), "order": order, "L": L,
                                              "alphabet": aname, "convention": conv, "plaintext": P}

    elapsed = time.perf_counter() - t0
    bi = best[1]
    status = "solved" if solved else ("promising" if (bi and bi["hex"] > -16.0) else "ruled_out")
    insights = [
        f"Swept {n_perms} block permutations (period d=2-7, all d! perms) x 2 alphabets x 3 conventions x "
        f"2 stage-orders x L=1-24; {decryptable:,} combos were fully crib-pinned and decryptable. "
        f"Best free-position hexagram {best[0]:.2f}/char.",
        (f"Best: d={bi['d']} pi={bi['pi']} order={bi['order']} L={bi['L']} {bi['alphabet']}/{bi['convention']}, "
         f"hex {bi['hex']} -> {bi['plaintext'][:50]}..." if bi else "No fully-pinned decryptable composite."),
    ]
    if status == "ruled_out":
        insights.append("No tiny 2-stage composite (short block transposition + short-period substitution, "
                        "either order) decrypts K4 to English. The coupling of two short stages -- the last "
                        "few-parameter structure consistent with Scheidt's 'simple, memorable' -- is closed "
                        "for block periods 2-7 and substitution periods 1-24.")
    write_verdict(out, Verdict(
        exp="064", title="tiny 2-stage composite (short block transposition + short-period substitution)",
        hypothesis="K4 = a short block transposition coupled with a short-period substitution",
        status=status, best_score=best[0],
        best_partial=f"{decryptable} fully-pinned decryptable combos", search_space=n_perms,
        elapsed_s=round(elapsed, 1), solved_params=solved, insights=insights,
        next_steps=(["verify & announce"] if solved else
                    ["widen block period to 8-14; add a SECOND substitution stage; or couple a route "
                     "(non-block) short transposition with substitution"]),
        metrics={"best": bi})
    )
    print(f"\n{decryptable} decryptable combos; best hex {best[0]:.2f}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
