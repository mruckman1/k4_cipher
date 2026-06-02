"""044 — Null-deletion / deliberate-misspelling period restoration.

Sanborn provably salts text: IQLUSION (K1), UNDERGRUUND (K2), DESPARATLY
(K3). If K4 has a few inserted NULL ciphertext letters in the
unconstrained gaps, then the 97-char text is a shorter periodic cipher
with nulls salted in, and every L<=30 periodic sweep (exps 002/013/024)
would have missed the real period by a handful of displaced letters.

Method: choose a deletion set D of 1-3 (sampled 4) positions drawn ONLY
from the 73 non-crib positions. Deleting them shifts every later crib
LEFT by the count of deletions before it; the crib's ciphertext LETTER is
unchanged, only its POSITION (hence its period slot) moves. We then test
whether the re-indexed cribs become consistent with a short periodic
key, and for fully-pinned small periods we decrypt the shortened text and
hexagram-score it. byte-exact restoration would be a solve.

The no-deletion baseline is consistent only at L>=27; any small-L English
hit after deleting a few salted nulls is the signal.

$0, local. Output: experiments/results/<date>_044_null_deletion_restoration.jsonl
"""

from __future__ import annotations

import argparse
import itertools
import json
import time
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD
from kryptos.constants import K4
from kryptos.cribs import CRIBS, all_known_positions

MAX_L = 24
DECRYPT_MAX_L = 20
ALPHAS = {"standard": STANDARD, "kryptos_keyed": KRYPTOS_KEYED}
CRIB_POS = sorted(all_known_positions())                 # 24 0-indexed
NONCRIB = [i for i in range(97) if i not in set(CRIB_POS)]   # 73


def crib_letters(alphabet):
    """(orig_pos, plain_idx, cipher_idx) for the 24 cribs."""
    out = []
    for c in CRIBS:
        for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext)):
            pos = c.start - 1 + off
            out.append((pos, alphabet.index(p), alphabet.index(ch)))
    return out


def shifted_pos(pos, deleted_sorted):
    """New 0-index of `pos` after removing the positions in deleted_sorted."""
    return pos - sum(1 for d in deleted_sorted if d < pos)


def consistency(triples, L, conv):
    slot = {}
    for pos, pi, ci in triples:
        if conv == "vigenere":
            k = (ci - pi) % 26
        elif conv == "beaufort":
            k = (pi + ci) % 26
        else:
            k = (pi - ci) % 26
        s = pos % L
        if s in slot and slot[s] != k:
            return None
        slot[s] = k
    return slot


def decrypt_short(deleted_set, key_by_slot, L, alphabet, conv) -> str:
    cipher = "".join(K4[i] for i in range(97) if i not in deleted_set)
    out = []
    for j, ch in enumerate(cipher):
        ci = alphabet.index(ch)
        k = key_by_slot[j % L]
        if conv == "vigenere":
            pi = (ci - k) % 26
        elif conv == "beaufort":
            pi = (k - ci) % 26
        else:
            pi = (ci + k) % 26
        out.append(alphabet.at(pi))
    return "".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--max-deletions", type=int, default=3)
    ap.add_argument("--quad-sample", type=int, default=200_000)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    out = args.out or (_kpa.RESULTS / f"{date.today()}_044_null_deletion_restoration.jsonl")

    base_triples = {n: crib_letters(a) for n, a in ALPHAS.items()}
    import numpy as np
    rng = np.random.default_rng(0)

    def deletion_sets():
        for r in range(1, min(args.max_deletions, 3) + 1):
            yield from itertools.combinations(NONCRIB, r)
        if args.max_deletions >= 4:
            seen = set()
            for _ in range(args.quad_sample):
                s = tuple(sorted(rng.choice(NONCRIB, size=4, replace=False).tolist()))
                if s not in seen:
                    seen.add(s); yield s

    t0 = time.perf_counter()
    n = 0
    decryptable = 0
    small_hits = 0
    best_score = -99.0
    best_info = None
    solved = None
    minL_hist: dict[int, int] = {}

    with open(out, "w") as f:
        for D in deletion_sets():
            Dset = set(D)
            for an, alpha in ALPHAS.items():
                tri = [(shifted_pos(p, D), pi, ci) for (p, pi, ci) in base_triples[an]]
                for conv in _kpa.CONVENTIONS:
                    found_L = None
                    for L in range(1, MAX_L + 1):
                        slot = consistency(tri, L, conv)
                        if slot is not None:
                            found_L = (L, slot)
                            break
                    if found_L is None:
                        continue
                    L, slot = found_L
                    minL_hist[L] = minL_hist.get(L, 0) + 1
                    if L <= 16:
                        small_hits += 1
                    if len(slot) == L and L <= DECRYPT_MAX_L:
                        decryptable += 1
                        P = decrypt_short(Dset, slot, L, alpha, conv)
                        sc = _kpa.hexagram_scorer()(P)   # whole shortened text
                        if sc > best_score:
                            best_score = sc
                            best_info = {"deletions": list(D), "alphabet": an,
                                         "convention": conv, "L": L,
                                         "plaintext": P, "score": round(sc, 2)}
                        if sc > -16.0:
                            f.write(json.dumps({"deletions": list(D), "alphabet": an,
                                                "convention": conv, "L": L,
                                                "plaintext": P, "hex": round(sc, 2)}) + "\n")
            n += 1
    elapsed = time.perf_counter() - t0
    status = "promising" if best_score > -16.0 else "ruled_out"
    insights = [
        f"Tested {n:,} deletion sets (1-{args.max_deletions} nulls from the 73 non-crib positions); "
        f"{decryptable:,} decryptable at fully-pinned L<= {DECRYPT_MAX_L}. Best hexagram = {best_score:.2f}/char.",
        f"min-consistent-L histogram: {dict(sorted(minL_hist.items()))}",
    ]
    if status == "ruled_out":
        insights.append("Removing up to N salted nulls does not restore a short periodic substitution that "
                        "decrypts to English. The period-displacement-by-nulls hypothesis is closed at this depth.")
    write_verdict(out, Verdict(
        exp="044", title="null-deletion / misspelling period restoration",
        hypothesis="K4 is a short-period substitution with a few inserted null ciphertext letters",
        status=status, best_score=round(best_score, 2),
        best_partial=f"{decryptable} decryptable; {small_hits} minL<=16",
        search_space=n, elapsed_s=round(elapsed, 1), solved_params=solved,
        insights=insights,
        next_steps=(["push best decryptable with free-slot hill-climb"] if status == "promising"
                    else ["extend to quad deletions (--max-deletions 4); try deletions of crib-adjacent positions"]),
        metrics={"best": best_info},
    ))
    print(f"\nTested {n:,} deletion sets in {elapsed:.1f}s; best hex {best_score:.2f}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
