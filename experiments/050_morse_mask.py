"""050 — Morse slabs as a binary mask / 2-alphabet selector.

Scheidt said the K4 technique "masks" the underlying cipher; the courtyard
morse slabs are the one intrinsically BINARY physical element (dots/dashes).
The repo has only ever treated morse as thematic plaintext, never as a
structural bitmask.

Two structural roles tested:
  (A) NULL-MASK: the morse bitstring (cycled to 97) flags positions to
      delete; run the periodic-substitution KPA on the surviving stream
      (re-using the exp 044 deletion machinery). Does removing the
      dash-flagged (or dot-flagged) positions restore a short period?
  (B) 2-ALPHABET SELECTOR: dot-positions use alphabet A, dash-positions
      alphabet B; over route-alphabet pairs, does any pair satisfy all 24
      cribs under this binary selection rule? (exp 035-style crib check,
      but with a morse-derived rule instead of position_mod_k.)

$0, local. Output: experiments/results/<date>_050_morse_mask.jsonl
"""

from __future__ import annotations

import itertools
import json
import time
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets_routes import route_alphabets
from kryptos.cribs import CRIBS

MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..",
}
MESSAGES = ["SOS", "LUCIDMEMORY", "TISYOURPOSITION", "SHADOWFORCES",
            "VIRTUALLYINVISIBLE", "DIGETALINTERPRETATIT", "RQ"]
CRIB_POS = set()
for c in CRIBS:
    CRIB_POS.update(range(c.start - 1, c.end))


def bitstring(letters: str) -> str:
    return "".join(MORSE[ch] for ch in letters)        # '.'=0 '-'=1


def cycled_mask(bits: str, n: int = 97) -> list[int]:
    return [0 if bits[i % len(bits)] == "." else 1 for i in range(n)]


def role_a_nullmask(name: str, mask: list[int], delete_bit: int):
    """Delete positions where mask==delete_bit (only non-crib positions),
    then test short-period substitution consistency + decrypt."""
    D = sorted(i for i in range(97) if mask[i] == delete_bit and i not in CRIB_POS)
    if not D or len(D) > 60:
        return None
    Dset = set(D)
    from kryptos.alphabets import KRYPTOS_KEYED, STANDARD
    best = (-99.0, None)
    for an, alpha in (("standard", STANDARD), ("kryptos_keyed", KRYPTOS_KEYED)):
        # re-index cribs after deletion
        tri = []
        for c in CRIBS:
            for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext)):
                pos = c.start - 1 + off
                newpos = pos - sum(1 for d in D if d < pos)
                tri.append((newpos, alpha.index(p), alpha.index(ch)))
        for conv in _kpa.CONVENTIONS:
            for L in range(1, 21):
                slot = {}
                ok = True
                for pos, pi, ci in tri:
                    k = ((ci - pi) % 26 if conv == "vigenere"
                         else (pi + ci) % 26 if conv == "beaufort" else (pi - ci) % 26)
                    s = pos % L
                    if s in slot and slot[s] != k:
                        ok = False; break
                    slot[s] = k
                if ok and len(slot) == L:
                    cipher = "".join(_kpa.K4_TEXT[i] for i in range(97) if i not in Dset)
                    P = []
                    for j, ch in enumerate(cipher):
                        ci = alpha.index(ch); k = slot[j % L]
                        pi = ((ci - k) % 26 if conv == "vigenere"
                              else (k - ci) % 26 if conv == "beaufort" else (ci + k) % 26)
                        P.append(alpha.at(pi))
                    sc = _kpa.hexagram_scorer()("".join(P))
                    if sc > best[0]:
                        best = (sc, {"mask": name, "delete_bit": delete_bit,
                                     "alphabet": an, "convention": conv, "L": L})
                    break
    return best


def role_b_selector(name: str, mask: list[int], pool):
    """dot->alphabet A, dash->alphabet B; does any (A,B) route pair satisfy
    all 24 cribs under this binary rule?"""
    # constraints split by mask bit
    cons0, cons1 = set(), set()
    for c in CRIBS:
        for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext)):
            pos = c.start - 1 + off
            (cons0 if mask[pos] == 0 else cons1).add((ord(p) - 65, ord(ch) - 65))
    cons0, cons1 = sorted(cons0), sorted(cons1)

    def covers(alpha, cons):
        return all(ord(alpha[pi]) - 65 == ci for (pi, ci) in cons)
    A_ok = [lb for lb, s in pool if covers(s, cons0)]
    B_ok = [lb for lb, s in pool if covers(s, cons1)]
    return bool(A_ok and B_ok), len(A_ok), len(B_ok), len(cons0), len(cons1)


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_050_morse_mask.jsonl"
    pool = route_alphabets()
    t0 = time.perf_counter()
    masks = {}
    for m in MESSAGES:
        masks[m] = cycled_mask(bitstring(m))
    masks["ALL"] = cycled_mask("".join(bitstring(m) for m in MESSAGES))

    best_score, best_info, solved = -99.0, None, None
    selector_hits = []
    with open(out, "w") as f:
        for name, mask in masks.items():
            for delete_bit in (0, 1):
                r = role_a_nullmask(name, mask, delete_bit)
                if r and r[0] > best_score:
                    best_score, best_info = r
            ok, na, nb, n0, n1 = role_b_selector(name, mask, pool)
            f.write(json.dumps({"mask": name, "selector_2alpha_solvable": ok,
                                "A_covers": na, "B_covers": nb,
                                "cons_dot": n0, "cons_dash": n1}) + "\n")
            if ok:
                selector_hits.append(name)

    elapsed = time.perf_counter() - t0
    status = "promising" if (best_score > -16.0 or selector_hits) else "ruled_out"
    insights = [
        f"Role A (morse null-mask -> delete -> short-period KPA): best free hexagram {best_score:.2f}/char.",
        f"Role B (morse dot/dash -> 2 route alphabets): {len(selector_hits)} masks admit a covering "
        f"route-alphabet pair {selector_hits or ''}.",
    ]
    if status == "ruled_out":
        insights.append("Morse slabs as either a null-mask or a binary 2-alphabet selector do not satisfy "
                        "the cribs / restore English. The morse content is thematic, not structural.")
    write_verdict(out, Verdict(
        exp="050", title="morse slabs as binary mask / 2-alphabet selector",
        hypothesis="Scheidt's 'masking' is implemented by the courtyard morse dot/dash pattern",
        status=status, best_score=round(best_score, 2),
        best_partial=f"selector hits: {selector_hits}", search_space=len(masks) * 2,
        elapsed_s=round(elapsed, 1), solved_params=solved, insights=insights,
        next_steps=(["pursue the covering morse-selector pair via exp 055"] if selector_hits else
                    ["morse not structural; deprioritise. Try morse as a transposition route instead."]),
        metrics={"best": best_info})
    )
    print(f"\nDone in {elapsed:.1f}s; role-A best {best_score:.2f}; selector hits {selector_hits}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
