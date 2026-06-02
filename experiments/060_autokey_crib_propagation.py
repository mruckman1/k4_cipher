"""060 — Few-parameter autokey families via crib-chain propagation.

With the per-position-substitution model retired (exp 059: degenerate), the
remaining cryptanalytic lever is FEW-PARAMETER ciphers consistent with
Scheidt's "simple, can be remembered and executed years later". The
strongest untested candidate is AUTOKEY, where the keystream is derived
from the text itself -- a primer keyword then the plaintext (or ciphertext)
runs on as the key. This naturally produces an aperiodic shift and a
per-position one-to-one mapping (matching K4's diagnostics) with very few
parameters: (primer length L, alphabet, convention, plaintext-vs-ciphertext).

Plaintext autokey:  key_i = primer_i (i<L) then P_{i-L} (i>=L).
  A single KNOWN crib position determines its entire residue-class chain
  (forward P_i=dec(C_i,P_{i-L}); backward P_{i-L}=keyfrom(C_i,P_i)). Multiple
  cribs in a chain must agree -> strong consistency filter. We propagate the
  4 cribs along chains for each (L, alphabet, convention), reject on conflict,
  and score the DERIVED plaintext (smooth LM + hexagram).

Ciphertext autokey: key_i = C_{i-L} (i>=L) -> P_i = dec(C_i, C_{i-L}) is fully
  determined by ciphertext; we just check cribs and score.

Few parameters; keyed alphabets included (the documented gap -- prior autokey
tests used short primers over the standard alphabet only).

Output: experiments/results/<date>_060_autokey_crib_propagation.jsonl
"""

from __future__ import annotations

import json
import time
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, keyed_alphabet
from kryptos.constants import K4
from kryptos.cribs import CRIBS
from kryptos.scoring.lm_fitness import backoff_scorer

N = 26
CRIB_PLAIN = {}                      # 0-idx position -> plaintext letter
for c in CRIBS:
    for off, p in enumerate(c.plaintext):
        CRIB_PLAIN[c.start - 1 + off] = p
CRIB_POS = set(CRIB_PLAIN)
FREE_NONCRIB = [i for i in range(97) if i not in CRIB_POS]

ALPHABETS = {
    "standard": STANDARD, "kryptos_keyed": KRYPTOS_KEYED,
    "keyed_BERLIN": keyed_alphabet("BERLIN"),
    "keyed_WELTZEITUHR": keyed_alphabet("WELTZEITUHR"),
    "keyed_PALIMPSEST": keyed_alphabet("PALIMPSEST"),
    "keyed_ABSCISSA": keyed_alphabet("ABSCISSA"),
}


def dec(c, k, conv):
    if conv == "vigenere":
        return (c - k) % N
    if conv == "beaufort":
        return (k - c) % N
    return (c + k) % N                # variant_beaufort


def keyfrom(c, p, conv):
    if conv == "vigenere":
        return (c - p) % N
    if conv == "beaufort":
        return (c + p) % N
    return (p - c) % N                # variant_beaufort


def plaintext_autokey(L, alpha, conv):
    """Return (P_indices or None on conflict, coverage_noncrib)."""
    cidx = [alpha.index(ch) for ch in K4]
    P = [None] * 97
    for pos, ch in CRIB_PLAIN.items():
        P[pos] = alpha.index(ch)
    # propagate each residue chain that contains >=1 crib
    for r in range(L):
        chain = list(range(r, 97, L))
        knowns = [i for i in chain if P[i] is not None]
        if not knowns:
            continue
        # forward fill across the whole chain from the lowest known
        # first, ensure all known cribs in the chain are mutually consistent
        # by filling forward/backward from the lowest known and checking.
        base = knowns[0]
        # backward from base to chain start
        for idx in range(chain.index(base) - 1, -1, -1):
            i_hi = chain[idx + 1]
            i_lo = chain[idx]
            val = keyfrom(cidx[i_hi], P[i_hi], conv)   # key_{i_hi} = P_{i_hi-L} = P[i_lo]
            if P[i_lo] is not None and P[i_lo] != val:
                return None, 0
            P[i_lo] = val
        # forward from base to chain end
        for idx in range(chain.index(base) + 1, len(chain)):
            i = chain[idx]
            val = dec(cidx[i], P[chain[idx - 1]], conv)
            if P[i] is not None and P[i] != val:
                return None, 0
            P[i] = val
    cov = sum(1 for i in FREE_NONCRIB if P[i] is not None)
    return P, cov


def ciphertext_autokey(L, alpha, conv):
    cidx = [alpha.index(ch) for ch in K4]
    P = [None] * 97
    for i in range(L, 97):
        P[i] = dec(cidx[i], cidx[i - L], conv)
    # check cribs (those at i>=L)
    for pos, ch in CRIB_PLAIN.items():
        if pos >= L and P[pos] != alpha.index(ch):
            return None, 0
    cov = sum(1 for i in FREE_NONCRIB if P[i] is not None)
    return P, cov


def decode(P, alpha):
    return "".join(alpha.at(x) if x is not None else "?" for x in P)


def score_determined(P, alpha, lm):
    det = "".join(alpha.at(P[i]) for i in FREE_NONCRIB if P[i] is not None)
    if len(det) < 10:
        return -99.0, -99.0, len(det)
    return _kpa.hexagram_scorer()(det), lm(det), len(det)


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_060_autokey_crib_propagation.jsonl"
    lm = backoff_scorer()
    t0 = time.perf_counter()
    best = (-99.0, None)        # by smooth LM among full-coverage, crib-consistent
    rows = 0
    n_consistent = 0
    with open(out, "w") as f:
        for mode, fn in (("plaintext_autokey", plaintext_autokey),
                         ("ciphertext_autokey", ciphertext_autokey)):
            for L in range(1, 31):
                for aname, alpha in ALPHABETS.items():
                    for conv in ("vigenere", "beaufort", "variant_beaufort"):
                        P, cov = fn(L, alpha, conv)
                        if P is None:
                            continue
                        n_consistent += 1
                        hexs, lmsc, ndet = score_determined(P, alpha, lm)
                        rec = {"mode": mode, "L": L, "alphabet": aname, "convention": conv,
                               "coverage_noncrib": cov, "n_scored": ndet,
                               "hex": round(hexs, 2), "lm": round(lmsc, 3),
                               "plaintext": decode(P, alpha)}
                        if hexs > -16.0 or lmsc > -3.5:
                            f.write(json.dumps(rec) + "\n")
                        rows += 1
                        # rank by smooth LM among reasonably-covered solutions
                        if cov >= 40 and lmsc > best[0]:
                            best = (lmsc, rec)
    elapsed = time.perf_counter() - t0
    bi = best[1]
    status = "promising" if (bi and (bi["hex"] > -15.0 or bi["lm"] > -3.0)) else "ruled_out"
    insights = [
        f"Tested {rows} autokey configs ((plaintext|ciphertext) x L=1-30 x {len(ALPHABETS)} alphabets x 3 "
        f"conventions); {n_consistent} were crib-consistent.",
        (f"Best (>=40 non-crib positions derived): {bi['mode']} L={bi['L']} {bi['alphabet']}/{bi['convention']}, "
         f"coverage {bi['coverage_noncrib']}/73, hexagram {bi['hex']}/char, smooth-LM {bi['lm']}. "
         f"Derived plaintext: {bi['plaintext'][:60]}..." if bi else "No autokey config derived >=40 positions."),
    ]
    if status == "ruled_out":
        insights.append("No autokey family (plaintext- or ciphertext-keyed, any L<=30, standard or keyed "
                        "alphabet, any convention) propagates the cribs into English. The crib chains either "
                        "conflict (rejected) or derive gibberish. Few-parameter autokey is closed.")
    else:
        insights.append("An autokey config derives partially-English plaintext from the cribs alone -- "
                        "PURSUE: extend the derived chains, fill free residue-chains by smooth-LM search.")
    write_verdict(out, Verdict(
        exp="060", title="few-parameter autokey crib-chain propagation",
        hypothesis="K4 is a plaintext/ciphertext autokey (few params) over a keyed alphabet",
        status=status, best_score=bi["hex"] if bi else None,
        best_partial=(f"{bi['coverage_noncrib']}/73 derived, LM {bi['lm']}" if bi else "no coverage"),
        search_space=rows, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["extend the best autokey config: free-chain fill via smooth-LM, then byte-verify"]
                    if status == "promising" else
                    ["try Gromark/running-key with text-derived primers; combine a short transposition "
                     "with autokey (2-param composite)"]),
        metrics={"best": bi})
    )
    print(f"\nTested {rows} autokey configs in {elapsed:.1f}s; best LM {best[0]:.2f}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
