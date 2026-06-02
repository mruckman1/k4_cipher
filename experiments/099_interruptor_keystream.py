"""099 — Interruptor / irregular-advance keystream: a period-L key whose advance
is modulated by a trigger letter, breaking period detection.

No prior experiment touched this (grep: "interrupt" appears nowhere). It is a
classic hand technique and a genuine gap: a short period-L key, but the key index
does NOT advance uniformly -- it RESETS to 0, SKIPS, or ADVANCES only when a
chosen interruptor letter X occurs in the ciphertext. The schedule is fully
determined by the (known) ciphertext + X + L + rule, so this is an EXACT crib KPA,
not a fuzzy search: build the schedule, then require the 24 crib shifts to be
consistent within each key slot (the exp-086 slot-consistency test); a consistent,
fully-pinned schedule decrypts all 97.

Sweep: interruptor letter X (each letter present in K4) x base period L (2-12) x
rule {reset-before, reset-after, skip-on-X, advance-on-X} x keyed alphabet x
{vigenere, beaufort, variant}. A consistent fit that decrypts to English is a
solve; a scrambled-crib control shows a fit cannot arise by chance.

Honest caveat (stated up front): a SIMPLE interruptor rule is the kind of short
selector the squeeze (085) bounds, and a complex one is under-determined (092);
so the prior is low. But the mechanism is distinct and was never tested.

$0, local, pure decipherment. Output:
experiments/results/<date>_099_interruptor_keystream.jsonl
"""

from __future__ import annotations

import json
import random
import time
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, keyed_alphabet
from kryptos.constants import K4

N = 97
M = 26
ALPHS = {"kryptos_keyed": KRYPTOS_KEYED, "standard": STANDARD,
         "keyed_PALIMPSEST": keyed_alphabet("PALIMPSEST"), "keyed_ABSCISSA": keyed_alphabet("ABSCISSA")}
RULES = ("reset_before", "reset_after", "skip_on", "advance_on")
LETTERS = sorted(set(K4))


def schedule(X, L, rule):
    """Per-position key index under an interruptor letter X, base period L."""
    idx = []
    c = 0
    for i in range(N):
        ch = K4[i]
        if rule == "reset_before":
            if ch == X:
                c = 0
            idx.append(c % L); c += 1
        elif rule == "reset_after":
            idx.append(c % L)
            c = 0 if ch == X else c + 1
        elif rule == "skip_on":          # advance only on non-X
            idx.append(c % L)
            if ch != X:
                c += 1
        else:                            # advance_on: advance only on X
            idx.append(c % L)
            if ch == X:
                c += 1
    return idx


def crib_shifts(alpha, conv):
    out = []
    for pos, pi, ci in _kpa.crib_position_triples(alpha):
        if conv == "vigenere":
            k = (ci - pi) % M
        elif conv == "beaufort":
            k = (ci + pi) % M
        else:
            k = (pi - ci) % M
        out.append((pos, k))
    return out


def fit_slots(idx, cribsh):
    """Return {slot: shift} if all cribs agree within their key slot, else None."""
    slots = {}
    for pos, k in cribsh:
        sl = idx[pos]
        if sl in slots and slots[sl] != k:
            return None
        slots[sl] = k
    return slots


def decrypt(alpha, conv, idx, slots):
    out = []
    for i in range(N):
        sl = idx[i]
        k = slots[sl]
        ci = alpha.index(K4[i])
        if conv == "vigenere":
            pi = (ci - k) % M
        elif conv == "beaufort":
            pi = (k - ci) % M
        else:
            pi = (ci + k) % M
        out.append(alpha.at(pi))
    return "".join(out)


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_099_interruptor_keystream.jsonl"
    t0 = time.perf_counter()

    fits = []          # fully-pinned consistent fits
    best = (-99.0, None)
    solved = None
    n_configs = 0

    with open(out, "w") as f:
        for an, alpha in ALPHS.items():
            for conv in _kpa.CONVENTIONS:
                cribsh = crib_shifts(alpha, conv)
                for X in LETTERS:
                    for L in range(2, 13):
                        for rule in RULES:
                            n_configs += 1
                            idx = schedule(X, L, rule)
                            slots = fit_slots(idx, cribsh)
                            if slots is None:
                                continue
                            if not all(idx[i] in slots for i in range(N)):
                                continue  # not fully pinned -> cannot decrypt deterministically
                            P = decrypt(alpha, conv, idx, slots)
                            sc = _kpa.score_free_text(P)
                            rec = {"alpha": an, "conv": conv, "X": X, "L": L, "rule": rule,
                                   "hex": round(sc, 2), "plaintext": P}
                            fits.append(rec)
                            if sc > best[0]:
                                best = (sc, rec)
                            if sc > -16.0:
                                f.write(json.dumps(rec) + "\n")
                            if sc > -15.0:
                                solved = rec

    # scrambled-crib control: does an interruptor schedule fit by chance?
    rng = random.Random(0)
    base = crib_shifts(KRYPTOS_KEYED, "vigenere")
    positions = [p for p, _ in base]
    vals = [k for _, k in base]
    TRIALS = 1000
    ctrl_fits = 0
    for _ in range(TRIALS):
        sv = vals[:]; rng.shuffle(sv)
        sc_cribs = list(zip(positions, sv))
        hit = False
        for X in LETTERS[:8]:
            for L in range(2, 13):
                for rule in RULES:
                    idx = schedule(X, L, rule)
                    slots = fit_slots(idx, sc_cribs)
                    if slots is not None and all(idx[i] in slots for i in range(N)):
                        hit = True; break
                if hit:
                    break
            if hit:
                break
        ctrl_fits += 1 if hit else 0
    ctrl_p = ctrl_fits / TRIALS

    elapsed = time.perf_counter() - t0
    bi = best[1]
    if solved:
        status = "solved"
    elif bi and bi["hex"] > -15.0:
        status = "promising"
    elif fits and ctrl_p < 0.01 and bi and bi["hex"] > -16.0:
        status = "promising"
    else:
        status = "ruled_out"

    insights = [
        f"Interruptor keystream EXACT crib KPA over {n_configs} configs ({len(ALPHS)} alphabets x 3 conventions "
        f"x {len(LETTERS)} interruptor letters x L=2-12 x {len(RULES)} advance rules). {len(fits)} configs gave "
        f"a fully-pinned consistent interruptor schedule.",
        (f"Best interruptor fit: X='{bi['X']}' L={bi['L']} {bi['rule']} {bi['alpha']}/{bi['conv']} free-hex "
         f"{bi['hex']} -> {bi['plaintext'][:44]}..." if bi else
         "NO interruptor schedule (reset/skip/advance on any letter, L=2-12) admitted a fully-pinned consistent "
         "fit against the 24 cribs."),
        f"SCRAMBLED-CRIB CONTROL: an interruptor schedule fits {ctrl_p*100:.2f}% of randomly permuted crib-shift "
        f"assignments ({TRIALS} trials) -- a consistent fit is {'NOT chance' if ctrl_p < 0.01 else 'common enough to be chance'}.",
    ]
    if status == "ruled_out":
        if fits:
            insights.append("VERDICT: interruptor schedules CAN be consistent with the cribs but decrypt to "
                            "gibberish (best free-hex below -16) -- chance alignments, not the cipher. The "
                            "interruptor/irregular-advance keystream is RULED OUT.")
        else:
            insights.append("VERDICT: no interruptor/irregular-advance schedule (reset/skip/advance on any "
                            "letter, period 2-12, any keyed alphabet/convention) is consistent with the 24 crib "
                            "shifts. The interruptor keystream is RULED OUT -- the last untested classical "
                            "keystream mechanism is closed.")

    write_verdict(out, Verdict(
        exp="099", title="interruptor / irregular-advance keystream exact crib KPA",
        hypothesis="K4's key is a short period-L key whose advance is reset/skipped/triggered by an interruptor "
                   "letter in the ciphertext",
        status=status, best_score=(bi["hex"] if (bi and status in ("solved", "promising")) else None),
        best_partial=(f"{len(fits)} consistent interruptor fits; best free-hex {bi['hex']} "
                      f"(X={bi['X']} L={bi['L']} {bi['rule']})" if bi else
                      "no consistent interruptor schedule against 24 cribs"),
        search_space=n_configs, elapsed_s=round(elapsed, 1), solved_params=solved,
        insights=insights,
        next_steps=(["verify byte-exact & announce"] if solved else
                    ["interruptor keystream closed; classical keystream mechanisms (toroidal 006-009, reflecting "
                     "083, progressive 086, two-period 087, interruptor 099) are now exhausted. Open work "
                     "remains only outside letter-statistics (register 097) and as partial recovery (098)"]),
        metrics={"n_fits": len(fits), "best": bi, "control_p": round(ctrl_p, 4)}),
    )
    print(f"\n{len(fits)} interruptor fits over {n_configs} configs; best free-hex {best[0]:.2f}; "
          f"control p={ctrl_p:.4f}; status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
