"""083 — Reflecting (non-toroidal) tableau-walk keystream.

THE GENUINELY-NEW MECHANISM. Every keystream generator ever tested against
K4 -- exp 006's constant/Fibonacci/lagged-Fibonacci/LCG/text families, and the
entire period-L Vigenere / Quagmire / Gromark line (043/015/031/060/062/063) --
is TOROIDAL: the per-position shift either is constant within a period-L slot
or advances mod 26 (a sawtooth that wraps 0..25,0..25). A REFLECTING walk is
the one "simple, memorable" (Scheidt) generator class nobody enumerated: a
point walks the 26x26 KRYPTOS Vigenere tableau and BOUNCES off the edges
instead of wrapping, so the shift it reads is a TRIANGLE wave
(0,1,..,25,24,..,1,0,1,..) -- period 2*(M-1)=50, NOT 26, and not expressible as
any period-L Vigenere or any of exp 006's modular recurrences. It is exactly
the kind of hand-executable rule the physical sculpture invites: "start on a
cell, step by a fixed vector, bounce off the border, read the cell."

Family (= README direction #1: start cell x step vector x bounce rule):
  (A) BILLIARD  -- a point (row,col) moves by (dr,dc), each axis reflecting
      independently in [0,25]; the per-position shift is read as the row, the
      col, or the cell value (row+col) mod 26. The 1-D triangle wave is the
      dr=0 / dc=0 slice, so it is covered.
  (B) BOUSTROPHEDON -- a serpentine head moves +-1 along a row, reverses at
      the row edge and steps the row by `vstep` (row reflects too); shift =
      cell value. The classic ox-plough reading order.

Match logic reuses _kpa's crib-shift convention (vigenere/beaufort/variant) in
both STANDARD and KRYPTOS-keyed index spaces, and exp 006's >=k-consecutive-run
scoring on the two crib windows. A walk that reproduces ALL 24 crib shifts (or a
long boundary-aligned run that decrypts to English) is a candidate solve. A
scrambled-keystream control (equal sample of uniform-random keystreams) gives
the chance ceiling on total crib matches, so a "good" walk can't be a fluke.

$0, local, pure decipherment. Output:
experiments/results/<date>_083_reflecting_tableau_walk.jsonl
"""

from __future__ import annotations

import json
import time
from datetime import date

import numpy as np

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD
from kryptos.constants import K4
from kryptos.cribs import BERLINCLOCK, EASTNORTHEAST

M = 26
N = 97
PERIOD = 2 * (M - 1)  # reflecting (triangle-wave) period on [0, M-1] = 50
STEP_RANGE = range(-4, 5)  # step-vector components (excluding (0,0))
ALPHAS = (("standard", STANDARD), ("kryptos_keyed", KRYPTOS_KEYED))
# Two crib windows (0-indexed), exp-006 style. They coincide exactly with the
# union of the four crib positions (EAST+NORTHEAST = 21..33, BERLIN+CLOCK = 63..73).
WINDOWS = [(EASTNORTHEAST.name, list(range(EASTNORTHEAST.start - 1, EASTNORTHEAST.end))),
           (BERLINCLOCK.name, list(range(BERLINCLOCK.start - 1, BERLINCLOCK.end)))]


def conv_targets(alpha):
    """{conv: {pos: required key}} for the 24 crib positions in `alpha`.
    Matches _kpa decryption conventions exactly:
      vigenere  key = C - P   beaufort key = C + P   variant key = P - C
    """
    tri = _kpa.crib_position_triples(alpha)  # (pos, plain_idx, cipher_idx)
    out = {"vigenere": {}, "beaufort": {}, "variant_beaufort": {}}
    for pos, pi, ci in tri:
        out["vigenere"][pos] = (ci - pi) % M
        out["beaufort"][pos] = (ci + pi) % M
        out["variant_beaufort"][pos] = (pi - ci) % M
    return out


# Ordered crib positions and, per (alpha,conv), the target key vector aligned to them.
POS = sorted({pos for pos, _, _ in _kpa.crib_position_triples(STANDARD)})
POS_ARR = np.array(POS, dtype=np.int64)
TARGETS = []  # list of (alpha_name, conv, np.array target over POS)
for an, alpha in ALPHAS:
    ct = conv_targets(alpha)
    for conv in _kpa.CONVENTIONS:
        TARGETS.append((an, conv, np.array([ct[conv][p] for p in POS], dtype=np.int64)))


def refl(x0, d, idx):
    """Reflecting (triangle-wave) position of a point started at x0 moving by d,
    bouncing in [0, M-1]. x0: (S,) array; d: int; idx: (P,) positions. -> (S,P)."""
    q = (x0[:, None] + d * idx[None, :]) % PERIOD
    return np.where(q < M, q, PERIOD - q)


def refl1(x0, d, idx):
    """Scalar-start version -> (len(idx),)."""
    q = (x0 + d * idx) % PERIOD
    return np.where(q < M, q, PERIOD - q)


def billiard_keystream(row0, col0, dr, dc, read, length=N):
    idx = np.arange(length)
    r = refl1(row0, dr, idx)
    c = refl1(col0, dc, idx)
    if read == "row":
        return r
    if read == "col":
        return c
    return (r + c) % M  # "sum" = cell value on the tableau


def boustrophedon_keystream(row0, col0, hdir, vstep, length=N):
    """Serpentine head: move +-1 along the row (hdir), reverse at the row edge
    and step the row by vstep; both axes reflect. Shift = (row+col) mod M."""
    r, c, h = row0, col0, hdir
    ks = []
    for _ in range(length):
        ks.append((r + c) % M)
        nc = c + h
        if nc < 0 or nc >= M:                 # bounce horizontally -> advance row
            h = -h
            nc = c + h
            nr = r + vstep
            if nr < 0 or nr >= M:             # row reflects too
                vstep = -vstep
                nr = r + vstep
            r = max(0, min(M - 1, nr))
        c = max(0, min(M - 1, nc))
    return np.array(ks, dtype=np.int64)


def runs_and_matches(ks_at_pos):
    """Given the keystream restricted to POS, return for the best (alpha,conv):
    (total matches /24, longest run anywhere in either window, boundary-aligned
    run, which alpha/conv/window). Mirrors exp 006's run scoring."""
    pos_index = {p: i for i, p in enumerate(POS)}
    best = {"matches": -1, "alpha": None, "conv": None, "run": 0,
            "boundary_run": 0, "window": None}
    for an, conv, tgt in TARGETS:
        eq = ks_at_pos == tgt
        matches = int(eq.sum())
        # longest run + boundary-aligned run within each contiguous window
        best_run, best_brun, best_win = 0, 0, None
        for win_name, win in WINDOWS:
            cur = 0
            for j, p in enumerate(win):
                if eq[pos_index[p]]:
                    cur += 1
                    if cur > best_run:
                        best_run, best_win = cur, win_name
                else:
                    cur = 0
            # boundary-aligned: run starting exactly at the window's first position
            b = 0
            for p in win:
                if eq[pos_index[p]]:
                    b += 1
                else:
                    break
            if b > best_brun:
                best_brun = b
        if (matches, best_run) > (best["matches"], best["run"]):
            best = {"matches": matches, "alpha": an, "conv": conv,
                    "run": best_run, "boundary_run": best_brun, "window": best_win}
    return best


def decrypt(ks, alpha, conv):
    out = []
    for i, ch in enumerate(K4):
        ci = alpha.index(ch)
        k = int(ks[i])
        if conv == "vigenere":
            pi = (ci - k) % M
        elif conv == "beaufort":
            pi = (k - ci) % M
        else:  # variant_beaufort
            pi = (ci + k) % M
        out.append(alpha.at(pi))
    return "".join(out)


def alpha_by_name(name):
    return dict(ALPHAS)[name]


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_083_reflecting_tableau_walk.jsonl"
    t0 = time.perf_counter()

    ROWS = np.repeat(np.arange(M), M)   # row0 for each of 676 start cells
    COLS = np.tile(np.arange(M), M)     # col0
    tgt_mat = np.stack([t for _, _, t in TARGETS])  # (6, 24)

    # ---- BILLIARD family (vectorised over the 676 start cells) ----------
    best_overall = {"matches": -1}
    n_walks = 0
    distinct_keystreams = 0
    for dr in STEP_RANGE:
        for dc in STEP_RANGE:
            if dr == 0 and dc == 0:
                continue
            rvals = refl(ROWS, dr, POS_ARR)  # (676, 24)
            cvals = refl(COLS, dc, POS_ARR)
            for read in ("row", "col", "sum"):
                if read == "row":
                    ks = rvals
                elif read == "col":
                    ks = cvals
                else:
                    ks = (rvals + cvals) % M
                n_walks += ks.shape[0]
                distinct_keystreams += ks.shape[0]
                # matches of every walk against every (alpha,conv) target
                # ks: (676,24); tgt_mat: (6,24) -> (676,6)
                mm = (ks[:, None, :] == tgt_mat[None, :, :]).sum(axis=2)
                s = int(mm.max())
                if s > best_overall["matches"]:
                    si, ti = np.unravel_index(int(mm.argmax()), mm.shape)
                    row0, col0 = int(ROWS[si]), int(COLS[si])
                    best_overall = {"matches": s, "family": "billiard", "read": read,
                                    "row0": row0, "col0": col0, "dr": dr, "dc": dc,
                                    "target_idx": int(ti)}

    # ---- BOUSTROPHEDON family ------------------------------------------
    for row0 in range(M):
        for col0 in range(M):
            for hdir in (1, -1):
                for vstep in (1, 2, 3, 5, 7):
                    ks_full = boustrophedon_keystream(row0, col0, hdir, vstep)
                    n_walks += 1
                    distinct_keystreams += 1
                    ksp = ks_full[POS_ARR]
                    mm = (ksp[None, :] == tgt_mat).sum(axis=1)  # (6,)
                    s = int(mm.max())
                    if s > best_overall["matches"]:
                        best_overall = {"matches": s, "family": "boustrophedon",
                                        "read": "sum", "row0": row0, "col0": col0,
                                        "hdir": hdir, "vstep": vstep,
                                        "target_idx": int(mm.argmax())}

    # ---- reconstruct best keystream, decrypt, score, runs ---------------
    if best_overall["family"] == "billiard":
        ks_best = billiard_keystream(best_overall["row0"], best_overall["col0"],
                                     best_overall["dr"], best_overall["dc"],
                                     best_overall["read"])
    else:
        ks_best = boustrophedon_keystream(best_overall["row0"], best_overall["col0"],
                                          best_overall["hdir"], best_overall["vstep"])
    an_best, conv_best, _ = TARGETS[best_overall["target_idx"]]
    detail = runs_and_matches(ks_best[POS_ARR])
    pt_best = decrypt(ks_best, alpha_by_name(an_best), conv_best)
    hex_best = _kpa.score_free_text(pt_best)

    # also fully decrypt+score the best by English-likeness over a top slice,
    # in case the right walk doesn't max crib-matches under our conv assumptions
    # (cheap: rescore the single best-match walk is already done; the family is
    # small enough that crib-match is the right primary filter).

    # ---- scrambled-keystream control (chance ceiling) -------------------
    rng = np.random.default_rng(0)
    R = min(distinct_keystreams, 200_000)
    rand = rng.integers(0, M, size=(R, len(POS)), dtype=np.int64)
    ctrl_best = np.zeros(R, dtype=np.int64)
    for t in tgt_mat:
        ctrl_best = np.maximum(ctrl_best, (rand == t[None, :]).sum(axis=1))
    ctrl_max = int(ctrl_best.max())
    ctrl_p999 = int(np.percentile(ctrl_best, 99.9))
    ctrl_mean = float(ctrl_best.mean())
    # p-value: fraction of random keystreams reaching the walk's best match count
    p_value = float((ctrl_best >= best_overall["matches"]).mean())

    elapsed = time.perf_counter() - t0

    # ---- verdict --------------------------------------------------------
    solved_full = best_overall["matches"] == 24 and hex_best > -15.0
    # "promising" only if the structured walk clearly beats the random ceiling
    # AND there is some English signal; otherwise the matches are chance. The
    # honest ceiling is the control's MAX over an equal-size sample (not the
    # 99.9th pct): a structured family must out-hit the best random keystream.
    beats_chance = (best_overall["matches"] > ctrl_max) and (p_value < 0.01)
    promising = solved_full or (beats_chance and hex_best > -16.0)
    status = "solved" if solved_full else ("promising" if promising else "ruled_out")

    rec = {"best": best_overall, "best_alpha": an_best, "best_conv": conv_best,
           "best_matches_of_24": best_overall["matches"], "best_detail": detail,
           "best_free_hex": round(hex_best, 2), "best_plaintext": pt_best,
           "control": {"sampled": R, "max_match": ctrl_max, "p999_match": ctrl_p999,
                       "mean_match": round(ctrl_mean, 3), "p_value_vs_walk": round(p_value, 4)},
           "n_walks": n_walks}
    with open(out, "w") as f:
        f.write(json.dumps(rec) + "\n")

    insights = [
        f"Reflecting (triangle-wave, period {PERIOD}) tableau walks are NOT expressible as any period-L "
        f"Vigenere or exp-006 modular recurrence -- the one 'simple, memorable' keystream class never "
        f"enumerated. Swept {n_walks:,} walks (billiard start-cell x step-vector x read-rule + "
        f"boustrophedon) x {len(TARGETS)} alpha/convention targets.",
        f"Best walk reproduces {best_overall['matches']}/24 crib shifts "
        f"({best_overall['family']}/{best_overall['read']}, {an_best}/{conv_best}); longest crib-window run "
        f"{detail['run']} (boundary-aligned {detail['boundary_run']}). Full decrypt free-hex {hex_best:.2f} "
        f"-> {pt_best[:40]}...",
        f"SCRAMBLED-KEYSTREAM CONTROL: {R:,} uniform-random keystreams reach a max of {ctrl_max}/24 crib "
        f"matches (99.9th pct {ctrl_p999}, mean {ctrl_mean:.2f}); the best walk's {best_overall['matches']}/24 "
        f"has chance p={p_value:.4f}. {'BEATS' if beats_chance else 'does NOT beat'} the random ceiling.",
    ]
    if not solved_full and not promising:
        insights.append(
            "VERDICT: reflecting-walk keystreams do not satisfy the 24 crib shifts beyond chance and do not "
            "decrypt to English. The reflecting (non-toroidal) generator family is RULED OUT as K4's "
            "keystream -- the bounce mechanism is closed; the surviving open directions are the K1/K2 "
            "modification-fingerprint forward search and the squeeze-as-lower-bound (README directions #2, #3).")

    write_verdict(out, Verdict(
        exp="083", title="reflecting (non-toroidal) tableau-walk keystream",
        hypothesis="K4's per-position shift is a reflecting (triangle-wave) walk that bounces off the "
                   "KRYPTOS-tableau edges, not a toroidal/period-L keystream",
        status=status,
        best_score=hex_best if solved_full else None,
        best_partial=(f"{best_overall['matches']}/24 crib shifts (chance ceiling {ctrl_p999}, p={p_value:.3f}); "
                      f"best run {detail['run']}; free-hex {round(hex_best, 2)}"),
        search_space=n_walks, elapsed_s=round(elapsed, 1),
        solved_params=(best_overall if solved_full else None),
        insights=insights,
        next_steps=(["verify byte-exact & announce"] if solved_full else
                    ["reflecting-walk keystream closed; build the K1/K2 modification-fingerprint forward "
                     "search (README #2, reuse exp 080 feats()) and the squeeze lower-bound sweep (README #3)"]),
        metrics={"best_matches": best_overall["matches"], "control_p999": ctrl_p999,
                 "p_value": round(p_value, 4), "best_free_hex": round(hex_best, 2),
                 "best_params": best_overall}),
    )
    print(f"\nbest {best_overall['matches']}/24 crib matches ({best_overall['family']}/"
          f"{best_overall['read']}, {an_best}/{conv_best}); control p999={ctrl_p999}, p={p_value:.4f}; "
          f"free-hex {hex_best:.2f}; status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
