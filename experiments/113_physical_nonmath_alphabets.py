"""113 — Physical / non-mathematical alphabet sources vs the chi=3 crib cover.

Sanborn: "who says it's even a math solution?" / "fortunate not to understand
mathematics". Scheidt: ideas "that didn't necessarily depend on mathematics". The
088/110 cover tests used keyword/route/compass/typo/clock/construction-grammar
alphabets -- all 'mathematical' or linguistic. NEVER tested: PHYSICAL / MNEMONIC
letter orderings a non-mathematician would reach for:
  - keyboard layouts (QWERTY rows/cols, Dvorak) and keyboard-NEIGHBOUR shifts
  - Morse-code tree order, English-frequency order, Scrabble-value order
These are concrete, hand-usable "charts" that don't depend on math. Test (like
088): do any 3 of them chi=3-cover the 24 cribs (and decrypt under a simple
selector)? Plus the 110-style partial-cover SIGNAL vs random, per source family.

$0, local, deterministic, no LLM, no K5, no plaintext. Output:
experiments/results/<date>_113_physical_nonmath_alphabets.jsonl
"""

from __future__ import annotations

import json
import random
import time
from datetime import date

import _crib_sat as cs
import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K4
from kryptos.cribs import CRIBS

A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# physical / mnemonic base orderings (each a permutation of A-Z)
BASES = {
    "qwerty_rows": "QWERTYUIOPASDFGHJKLZXCVBNM",
    "qwerty_cols": "QAZWSXEDCRFVTGBYHNUJMIKOLP",
    "dvorak": "PYFGCRLAOEUIDHTNSQJKXBMWVZ",
    "azerty": "AZERTYUIOPQSDFGHJKLMWXCVBN",
    "morse_tree": "ETIANMSURWDKGOHVFLPJBXCYZQ",     # by Morse-code length/tree order
    "freq": "ETAOINSHRDLCUMWFGYPBVKJXQZ",            # English frequency order
    "scrabble": "AEILNORSTUDGBCMPFHVWYKJXQZ",         # by Scrabble value then alpha
    "phone_keypad": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",     # keypad groups = alphabetical (baseline)
}
# keyboard-neighbour substitution (each letter -> key to its right on the row, wrap)
QROWS = ["QWERTYUIOP", "ASDFGHJKL", "ZXCVBNM"]
neigh = {}
for row in QROWS:
    for i, ch in enumerate(row):
        neigh[ch] = row[(i + 1) % len(row)]
BASES["qwerty_right"] = "".join(neigh.get(c, c) for c in A)


def perms_from(base, label):
    """rotations + reverse + the base itself, as cover-pool entries (label, perm)."""
    out = []
    seen = set()
    for variant, s in [("", base), ("rev", base[::-1])]:
        for r in range(26):
            p = s[r:] + s[:r]
            if len(set(p)) == 26 and p not in seen:
                seen.add(p); out.append((f"{label}{variant}rot{r}", p))
    return out


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_113_physical_nonmath_alphabets.jsonl"
    t0 = time.perf_counter()

    pool, by_source = [], {}
    for label, base in BASES.items():
        if len(set(base)) != 26:
            continue
        ps = perms_from(base, label)
        by_source[label] = ps
        pool.extend(ps)

    cons = cs.crib_constraints()
    cover3 = cs.find_cover(pool, 3)
    gk, glabels, gcov, gtot = cs.greedy_cover(pool)
    bp_n, bp_tot, bp_labels = cs.best_partial_cover(pool, 3)

    # per-source best partial 3-cover (directional signal)
    per_source = {}
    for label, ps in by_source.items():
        if len(ps) >= 3:
            n, _, _ = cs.best_partial_cover(ps, 3)
            per_source[label] = n

    # random control (equal pool size)
    rng = random.Random(0)
    rand_partials = []
    for _ in range(5):
        rp = []
        for _ in range(len(pool)):
            s = list(A); rng.shuffle(s); rp.append(("r", "".join(s)))
        n, _, _ = cs.best_partial_cover(rp[:max(1, len(pool))], 3)
        rand_partials.append(n)
    rand_best = max(rand_partials)

    # decrypt if a 3-cover exists (simple selector, like 088)
    crib_triples = [(c.start - 1 + off, p, ch)
                    for c in CRIBS for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext))]
    decrypt_best = (-99.0, None)
    if cover3:
        lbl2s = dict(pool)
        alphas = [lbl2s[l] for l in cover3[0]]
        cfs = [lambda i: i % 3, lambda i: (i // 7) % 3, lambda i: (2 * i) % 3]
        for cf in cfs:
            for b in [(0, 1, 2), (0, 2, 1), (1, 0, 2), (1, 2, 0), (2, 0, 1), (2, 1, 0)]:
                if all(alphas[b[cf(pos)]][ord(p) - 65] == ch for pos, p, ch in crib_triples):
                    P = "".join(chr(alphas[b[cf(i)]].index(K4[i]) + 65) for i in range(97))
                    sc = _kpa.score_free_text(P)
                    if sc > decrypt_best[0]:
                        decrypt_best = (sc, P)

    elapsed = time.perf_counter() - t0
    signal = bp_n > rand_best + 1
    solved = decrypt_best[1] is not None and decrypt_best[0] > -15.0
    status = "promising" if (solved or cover3 or signal) else "ruled_out"

    with open(out, "w") as f:
        f.write(json.dumps({"pool_size": len(pool), "exact_3_cover": bool(cover3),
                            "cover_labels": cover3[0] if cover3 else None,
                            "best_partial_3cover": bp_n, "of": bp_tot, "greedy_k": gk,
                            "per_source_best_partial": per_source, "random_best_partial": rand_best,
                            "decrypt_best_hex": round(decrypt_best[0], 2) if decrypt_best[1] else None}) + "\n")

    insights = [
        f"Physical/non-mathematical alphabet sources ({len(BASES)} base orderings: keyboard QWERTY/Dvorak/"
        f"AZERTY rows&cols, keyboard-neighbour shift, Morse-tree, frequency, Scrabble) x rotations/reverse = "
        f"{len(pool)} alphabets. Exact chi=3 cover of the 24 cribs: {'FOUND ' + str(cover3[0]) if cover3 else 'NONE'}. "
        f"Greedy k={gk}; best 3 cover {bp_n}/{bp_tot}.",
        f"PER-SOURCE best 3-partial cover: {per_source}. Random control best 3-partial: {rand_best}. "
        f"Signal (physical sources beat random by >1): {signal}.",
        (f"DECRYPT: 3-cover exists; best simple-selector decrypt free-hex {decrypt_best[0]:.2f}." if cover3 else
         "No 3-cover -> no decrypt."),
    ]
    if status == "ruled_out":
        insights.append(
            "VERDICT: no 3 physical/non-mathematical alphabets (keyboard / Morse / frequency / Scrabble) "
            "chi=3-cover the cribs, and they cover no more than random. The 'non-math, physical chart' reading "
            "of Sanborn/Scheidt does NOT correspond to any of these concrete hand-orderings -- the chart's "
            "letter orderings are not keyboard/mnemonic either. Tightens 088/110 further.")

    write_verdict(out, Verdict(
        exp="113", title="physical / non-mathematical alphabet sources vs chi=3 crib cover",
        hypothesis="K4's >=3 alphabets are physical/mnemonic orderings (keyboard, Morse, frequency, Scrabble) "
                   "-- a non-mathematical hand chart",
        status=status, best_score=(decrypt_best[0] if solved else None),
        best_partial=f"3-cover={'yes' if cover3 else 'no'}; best partial {bp_n}/{bp_tot} (random {rand_best}); "
                     f"per-source {per_source}; signal={signal}",
        search_space=len(pool), elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["recover the selector & decrypt with the covering physical alphabets"] if (cover3 or signal)
                    else ["physical/mnemonic alphabet orderings closed; the chart is not keyboard/Morse/freq/"
                          "Scrabble-ordered either"]),
        metrics={"pool_size": len(pool), "exact_3_cover": bool(cover3), "best_partial": bp_n,
                 "per_source": per_source, "random_best_partial": rand_best, "signal": signal}),
    )
    print(f"\npool={len(pool)}; 3-cover={'yes' if cover3 else 'no'}; best partial {bp_n}/{bp_tot} "
          f"(random {rand_best}); per-source {per_source}; signal={signal}; status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
