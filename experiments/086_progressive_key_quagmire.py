"""086 — Progressive-key Quagmire: exact crib-constrained KPA.

exp 084's modification fingerprint (calibrated: K1/K2 read as plain Q3) ranked a
PROGRESSIVE-key Quagmire as the modification whose statistics sit nearest K4 --
i.e. run Sanborn's own K1/K2 system (Vigenere in a KRYPTOS-keyed alphabet) but
let the key ADVANCE as it goes instead of repeating. That is a "memorable
modification" (Scheidt) that was never given a dedicated crib KPA: 016/026 did
plain/double Q3, the period sweeps (043/015/031) covered only REPEATING keys.

A progressive key makes the per-position key value k_i a short deterministic
progression. This experiment solves it EXACTLY from the 24 crib shifts -- not a
search but algebra: 24 crib equations against a 2-parameter progression are
wildly overdetermined (a random shift sequence fits with probability ~26^-22),
so ANY consistent fit is a near-certain structural hit, not chance.

Progression families (per keyed alphabet x vigenere/beaufort/variant):
  linear        k_i = base + step*i              (classic progressive key)
  block_g       k_i = base + step*(i//g)         (key advances every g letters)
  periodic_ramp k_i = key[i mod L] + step*(i//L) (a period-L Quagmire key that
                                                   advances one ramp per cycle)

For each, every candidate `step` in 0..25 is tried; `base`/`key` are then forced
by the cribs and the fit is checked against ALL 24. A full consistent fit ->
decrypt all 97 + hexagram-score. A scrambled-crib control confirms a real fit
cannot arise by chance.

$0, local, pure decipherment. Output:
experiments/results/<date>_086_progressive_key_quagmire.jsonl
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
ALPHS = {"kryptos_keyed": KRYPTOS_KEYED, "standard": STANDARD,
         "keyed_PALIMPSEST": keyed_alphabet("PALIMPSEST"),
         "keyed_ABSCISSA": keyed_alphabet("ABSCISSA")}
BLOCKS = list(range(2, 15))     # block-progressive advance every g letters
RAMP_L = list(range(2, 13))     # periodic key length for the ramp family


def crib_keys(alpha, conv):
    """[(pos, key_value)] for the 24 cribs under (alpha, conv). key conventions
    match _kpa/exp083: vig key=C-P, beaufort=C+P, variant=P-C."""
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


def decrypt(alpha, conv, keystream):
    out = []
    for i, ch in enumerate(K4):
        ci = alpha.index(ch)
        k = keystream[i] % 26
        if conv == "vigenere":
            pi = (ci - k) % 26
        elif conv == "beaufort":
            pi = (k - ci) % 26
        else:
            pi = (ci + k) % 26
        out.append(alpha.at(pi))
    return "".join(out)


def fit_linear(cribkeys, xfun):
    """Solve k = base + step*x (mod 26) against all cribs; xfun(pos)->x.
    Returns (base, step) if a single consistent solution exists, else None."""
    pts = [(xfun(p), k) for p, k in cribkeys]
    for step in range(26):
        base = (pts[0][1] - step * pts[0][0]) % 26
        if all((base + step * x) % 26 == k for x, k in pts):
            return base, step
    return None


def fit_periodic_ramp(cribkeys, L):
    """Solve k = key[i mod L] + step*(i//L) (mod 26). Returns
    (key_dict, step, pinned_slots) for the first consistent step, else None.
    key_dict maps slot->value for slots pinned by cribs."""
    for step in range(26):
        slots = {}
        ok = True
        for pos, k in cribkeys:
            resid = (k - step * (pos // L)) % 26
            sl = pos % L
            if sl in slots and slots[sl] != resid:
                ok = False
                break
            slots[sl] = resid
        if ok:
            return slots, step, len(slots)
    return None


def keystream_linear(base, step, xfun):
    return [(base + step * xfun(i)) % 26 for i in range(N)]


def keystream_ramp(slots, step, L):
    return [(slots[i % L] + step * (i // L)) % 26 for i in range(N)]


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_086_progressive_key_quagmire.jsonl"
    t0 = time.perf_counter()

    fits = []          # every consistent fit (param-level)
    best = (-99.0, None)
    solved = None
    n_configs = 0

    with open(out, "w") as f:
        for an, alpha in ALPHS.items():
            for conv in _kpa.CONVENTIONS:
                ck = crib_keys(alpha, conv)

                # linear
                n_configs += 1
                r = fit_linear(ck, lambda p: p)
                if r:
                    base, step = r
                    ks = keystream_linear(base, step, lambda p: p)
                    P = decrypt(alpha, conv, ks)
                    sc = _kpa.score_free_text(P)
                    rec = {"alpha": an, "conv": conv, "prog": "linear", "base": base,
                           "step": step, "hex": round(sc, 2), "plaintext": P}
                    fits.append(rec); f.write(json.dumps(rec) + "\n")
                    if sc > best[0]:
                        best = (sc, rec)
                    if sc > -15.0:
                        solved = rec

                # block-progressive
                for g in BLOCKS:
                    n_configs += 1
                    r = fit_linear(ck, lambda p, g=g: p // g)
                    if r:
                        base, step = r
                        ks = keystream_linear(base, step, lambda p, g=g: p // g)
                        P = decrypt(alpha, conv, ks)
                        sc = _kpa.score_free_text(P)
                        rec = {"alpha": an, "conv": conv, "prog": f"block{g}", "base": base,
                               "step": step, "hex": round(sc, 2), "plaintext": P}
                        fits.append(rec); f.write(json.dumps(rec) + "\n")
                        if sc > best[0]:
                            best = (sc, rec)
                        if sc > -15.0:
                            solved = rec

                # periodic-ramp (key advances one ramp per period-L cycle)
                for L in RAMP_L:
                    n_configs += 1
                    r = fit_periodic_ramp(ck, L)
                    if r:
                        slots, step, pinned = r
                        if pinned < L:
                            # under-determined: not all slots pinned by cribs -> cannot decrypt fully
                            fits.append({"alpha": an, "conv": conv, "prog": f"ramp{L}",
                                         "step": step, "pinned": pinned, "of": L, "under_determined": True})
                            continue
                        ks = keystream_ramp(slots, step, L)
                        P = decrypt(alpha, conv, ks)
                        sc = _kpa.score_free_text(P)
                        rec = {"alpha": an, "conv": conv, "prog": f"ramp{L}", "step": step,
                               "hex": round(sc, 2), "plaintext": P}
                        fits.append(rec); f.write(json.dumps(rec) + "\n")
                        if sc > best[0]:
                            best = (sc, rec)
                        if sc > -15.0:
                            solved = rec

    # ---- scrambled-crib control: does a 2-param progression fit by chance? ----
    rng = random.Random(0)
    base_ck = crib_keys(KRYPTOS_KEYED, "vigenere")
    positions = [p for p, _ in base_ck]
    keyvals = [k for _, k in base_ck]
    ctrl_fits = 0
    TRIALS = 2000
    for _ in range(TRIALS):
        shuf = keyvals[:]
        rng.shuffle(shuf)
        sck = list(zip(positions, shuf))
        if fit_linear(sck, lambda p: p) is not None:
            ctrl_fits += 1
        else:
            for g in BLOCKS:
                if fit_linear(sck, lambda p, g=g: p // g) is not None:
                    ctrl_fits += 1
                    break
    ctrl_p = ctrl_fits / TRIALS

    elapsed = time.perf_counter() - t0
    full_fits = [r for r in fits if "hex" in r]
    bi = best[1]

    # honest verdict: a consistent 2-param progression fit is itself the strong
    # signal (chance ~0); a fit that ALSO decrypts to English = solve. A fit that
    # decrypts to gibberish is logged but is not a lead (would be a rare chance
    # alignment quantified by the control).
    if solved:
        status = "solved"
    elif bi and bi.get("hex", -99) > -15.0:
        status = "promising"
    elif full_fits and ctrl_p < 0.01 and bi and bi.get("hex", -99) > -16.0:
        status = "promising"
    else:
        status = "ruled_out"

    insights = [
        f"Progressive-key Quagmire, EXACT crib KPA over {n_configs} configs "
        f"({len(ALPHS)} keyed alphabets x 3 conventions x [linear, block2-14, periodic-ramp2-12]). "
        f"{len(full_fits)} configs admitted a fully-pinned consistent progression fit.",
        (f"Best consistent fit: {bi['alpha']}/{bi['conv']}/{bi['prog']} (step={bi.get('step')}) "
         f"free-hex {bi['hex']} -> {bi['plaintext'][:44]}..." if bi else
         "NO progressive-key configuration admitted a fully-pinned consistent fit against the 24 cribs."),
        f"SCRAMBLED-CRIB CONTROL: a 2-parameter linear/block progression fits {ctrl_p*100:.2f}% of randomly "
        f"permuted crib-shift assignments ({TRIALS} trials) -- a consistent fit is {'NOT chance' if ctrl_p < 0.01 else 'common enough to be chance'}; "
        f"24 constraints vs 2 free parameters means a real fit is structurally meaningful.",
    ]
    if status == "ruled_out":
        if full_fits:
            insights.append("VERDICT: a consistent progression EXISTS but decrypts to gibberish -- a rare "
                            "chance alignment, not the cipher. The progressive-key Quagmire is RULED OUT.")
        else:
            insights.append("VERDICT: the 24 crib shifts are NOT a linear/block/periodic-ramp progression in "
                            "any tested keyed alphabet -- the progressive-key Quagmire is RULED OUT. The 084 "
                            "fingerprint's flattening signal is not THIS modification; pursue the Q3 + short-"
                            "Vigenere additive overlay (sum-of-two-short-periods, lcm>24) and the memorable "
                            "hand-crafted-alphabet triples (README #2).")

    write_verdict(out, Verdict(
        exp="086", title="progressive-key Quagmire exact crib KPA",
        hypothesis="K4 is a KRYPTOS-keyed Quagmire whose key advances as a short progression (linear / block / "
                   "periodic-ramp), per the exp-084 fingerprint",
        status=status, best_score=(bi["hex"] if (bi and status in ("solved", "promising")) else None),
        best_partial=(f"{len(full_fits)} consistent fits; best free-hex {bi['hex']} "
                      f"({bi['alpha']}/{bi['conv']}/{bi['prog']})" if bi else
                      "no consistent progression fit against 24 cribs"),
        search_space=n_configs, elapsed_s=round(elapsed, 1), solved_params=solved,
        insights=insights,
        next_steps=(["verify byte-exact & announce"] if solved else
                    ["progressive-key Quagmire closed; build the Q3 + short-Vigenere additive overlay KPA "
                     "(sum of two short periods, lcm>24 -- uncovered by the period<=24 sweeps) and the "
                     "memorable hand-crafted-alphabet triples (README direction #2 / exp 087)"]),
        metrics={"n_full_fits": len(full_fits), "best": bi, "control_p": round(ctrl_p, 4)}),
    )
    print(f"\n{len(full_fits)} consistent progression fits over {n_configs} configs; "
          f"best free-hex {best[0]:.2f}; control p={ctrl_p:.4f}; status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
