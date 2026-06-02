"""105 — Two-stage MASK -> keyword-Vigenere CORE (Scheidt's "masking", exact KPA).

Primary source: Scheidt (WIRED 2005) — for the fourth part he "masked the English
language" and "you need to solve the technique [mask] first and then go for the
puzzle [core]". Modelled as: K4 = MASK(CORE(plaintext)), both length-preserving
(Fact 1). The CORE is a K1-K3-style keyword Vigenere/Quagmire (period L) — the
Cyrillic-Projector lesson is that, left to himself, Sanborn used keyword-Vigenere.
The MASK is a per-position rotation selected by a simple rule g (the "technique").

Because both stages are additive per-position in a keyed alphabet, the composite
crib shift FACTORS: s_i = a[g(i)] + b[i mod L] (mod 26), where a[] are the mask's
per-class rotations and b[] the core's period-L key. So the two-stage hypothesis
is an EXACT crib factorization test (the same bipartite potential solver as exp
087's two-period overlay), per (mask selector g, core period L, alphabet,
convention). A consistent, fully-determined factorization that decrypts to
English is a solve. NOTE: when g is itself periodic (g=i mod k) this reduces to
exp 087 (ruled out); the genuinely-new cases are NON-periodic mask selectors
(priorA, non-vowel clock, row-of-7), which are tested here for the first time as
the mask stage of a two-stage cipher.

$0, local, deterministic, pure decipherment (no LLM, no K5, no plaintext). Output:
experiments/results/<date>_105_twostage_mask_core.jsonl
"""

from __future__ import annotations

import json
import random
import time
from collections import defaultdict
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, keyed_alphabet
from kryptos.constants import K4

M = 26
ALPHS = {"kryptos_keyed": KRYPTOS_KEYED, "standard": STANDARD,
         "keyed_PALIMPSEST": keyed_alphabet("PALIMPSEST"), "keyed_ABSCISSA": keyed_alphabet("ABSCISSA")}
VOWELS = set("AEIOU")
CC = []
_c = 0
for ch in K4:
    if ch not in VOWELS:
        _c += 1
    CC.append(_c)

# mask selectors g(i)->class. Non-periodic ones are the genuinely-new mask stage.
MASK_SELECTORS = {
    "i%2": (lambda i: i % 2, True), "i%3": (lambda i: i % 3, True), "i%4": (lambda i: i % 4, True),
    "row7%3": (lambda i: (i // 7) % 3, False), "cc%3": (lambda i: CC[i] % 3, False),
    "cc%2": (lambda i: CC[i] % 2, False), "priorA3": (lambda i: (2 * (i % 3) + CC[i]) % 3, False),
    "(i+cc)%3": (lambda i: (i + CC[i]) % 3, False), "(i//7+i)%3": (lambda i: (i // 7 + i) % 3, False),
}
CORE_L = list(range(1, 13))


def crib_shifts(alpha, conv):
    out = []
    for pos, pi, ci in _kpa.crib_position_triples(alpha):
        out.append((pos, (ci - pi) % M if conv == "vigenere"
                    else (ci + pi) % M if conv == "beaufort" else (pi - ci) % M))
    return out


def factor_solve(cribsh, g, L, nclasses):
    """Solve s = a[g(i)] + b[i%L] (mod 26) by potential propagation over a
    bipartite graph (a-nodes = mask classes, b-nodes = core slots). Returns
    (x, comp) or None if inconsistent. x[a]-x[b]=s with x[a]=a-node, x[b]=-b-node."""
    A0, B0 = nclasses, nclasses + L
    adj = defaultdict(list)
    for pos, s in cribsh:
        u = g(pos)
        v = nclasses + (pos % L)
        adj[u].append((v, s % M)); adj[v].append((u, (-s) % M))
    x, comp, cid = {}, {}, 0
    for start in range(B0):
        if start in x or start not in adj and start >= nclasses:
            # b-nodes with no crib are isolated; skip unless referenced
            pass
        if start in x:
            continue
        if start not in adj:
            continue
        x[start] = 0; comp[start] = cid; stack = [start]
        while stack:
            n = stack.pop()
            for m_, w in adj[n]:
                val = (x[n] - w) % M
                if m_ in x:
                    if x[m_] != val:
                        return None
                else:
                    x[m_] = val; comp[m_] = cid; stack.append(m_)
        cid += 1
    return x, comp


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_105_twostage_mask_core.jsonl"
    t0 = time.perf_counter()
    fits, determined = [], []
    best = (-99.0, None)
    solved = None
    n_configs = 0

    with open(out, "w") as f:
        for an, alpha in ALPHS.items():
            for conv in _kpa.CONVENTIONS:
                cs = crib_shifts(alpha, conv)
                for gname, (g, periodic) in MASK_SELECTORS.items():
                    nclasses = len(set(g(p) for p, _ in cs)) if cs else 0
                    nclasses = max(g(i) for i in range(97)) + 1
                    for L in CORE_L:
                        n_configs += 1
                        sol = factor_solve(cs, g, L, nclasses)
                        if sol is None:
                            continue
                        x, comp = sol
                        fits.append((gname, L, an, conv, periodic))
                        # determined? every position's (mask class, core slot) pinned & same component
                        ks, full = [], True
                        for i in range(97):
                            ua, vb = g(i), nclasses + (i % L)
                            if ua not in comp or vb not in comp or comp[ua] != comp[vb]:
                                full = False; break
                            ks.append((x[ua] - x[vb]) % M)
                        if not full:
                            continue
                        determined.append((gname, L, an, conv, periodic))
                        # decrypt: composite shift ks[i]; P = C - shift (per conv)
                        P = []
                        for i in range(97):
                            ci = alpha.index(K4[i]); k = ks[i]
                            pi = ((ci - k) % M if conv == "vigenere"
                                  else (k - ci) % M if conv == "beaufort" else (ci + k) % M)
                            P.append(alpha.at(pi))
                        P = "".join(P); sc = _kpa.score_free_text(P)
                        rec = {"mask_selector": gname, "core_L": L, "alpha": an, "conv": conv,
                               "periodic_mask": periodic, "hex": round(sc, 2), "plaintext": P}
                        if sc > best[0]:
                            best = (sc, rec)
                        if sc > -16.0:
                            f.write(json.dumps(rec) + "\n")
                        if sc > -15.0:
                            solved = rec

    # scrambled-crib control
    rng = random.Random(0)
    base = crib_shifts(KRYPTOS_KEYED, "vigenere")
    positions = [p for p, _ in base]; vals = [s for _, s in base]
    TR = 1000; ctrl = 0
    for _ in range(TR):
        sv = vals[:]; rng.shuffle(sv); scr = list(zip(positions, sv))
        hit = False
        for gname, (g, _) in MASK_SELECTORS.items():
            nclasses = max(g(i) for i in range(97)) + 1
            for L in (3, 5, 7):
                sol = factor_solve(scr, g, L, nclasses)
                if sol and all((g(i) in sol[1] and nclasses + (i % L) in sol[1]
                                and sol[1][g(i)] == sol[1][nclasses + (i % L)]) for i in range(97)):
                    hit = True; break
            if hit:
                break
        ctrl += 1 if hit else 0
    ctrl_p = ctrl / TR

    elapsed = time.perf_counter() - t0
    bi = best[1]
    new_determined = [d for d in determined if not d[4]]  # non-periodic mask = genuinely new
    if solved:
        status = "solved"
    elif bi and bi["hex"] > -15.0:
        status = "promising"
    elif new_determined and ctrl_p < 0.05 and bi and bi["hex"] > -16.0:
        status = "promising"
    else:
        status = "ruled_out"

    insights = [
        f"Two-stage MASK(CORE) exact crib-factorization KPA over {n_configs} configs ({len(ALPHS)} alphabets x "
        f"3 conventions x {len(MASK_SELECTORS)} mask selectors x core period L=1-12). The crib shifts must "
        f"factor as s_i = a[mask_class(i)] + b[i mod L]. {len(fits)} configs are consistent; {len(determined)} "
        f"are fully determined ({len(new_determined)} with a NON-periodic mask = the genuinely-new cases).",
        (f"Best two-stage decrypt: mask {bi['mask_selector']} (periodic={bi['periodic_mask']}) + core L={bi['core_L']} "
         f"{bi['alpha']}/{bi['conv']} free-hex {bi['hex']} -> {bi['plaintext'][:40]}..." if bi else
         "NO mask-selector + core-period factorization is fully determined against the 24 cribs."),
        f"SCRAMBLED-CRIB CONTROL: a determined factorization arises for {ctrl_p*100:.1f}% of permuted crib "
        f"assignments -- {'meaningful' if ctrl_p < 0.05 else 'common (chance)'}.",
    ]
    if status == "ruled_out":
        insights.append(
            "VERDICT: Scheidt's 'mask + core' two-stage model, with a simple mask selector (periodic OR "
            "non-periodic) and a period<=12 keyword-Vigenere core, does NOT decrypt K4 to English under any "
            "tested alphabet/convention. The masking hypothesis, in its additive-mask + keyword-core form, is "
            "RULED OUT. (Periodic-mask cases coincide with exp 087's two-period overlay, already closed; the "
            "non-periodic mask cases are newly closed here.)")

    write_verdict(out, Verdict(
        exp="105", title="two-stage mask -> keyword-Vigenere core (Scheidt masking) exact KPA",
        hypothesis="K4 = a simple per-position rotation MASK composed with a short-period keyword-Vigenere CORE "
                   "(Scheidt 'masked the English language; solve the technique then the puzzle')",
        status=status, best_score=(bi["hex"] if (bi and status in ("solved", "promising")) else None),
        best_partial=(f"{len(determined)} determined factorizations ({len(new_determined)} non-periodic); best "
                      f"free-hex {bi['hex']}" if bi else "no determined mask+core factorization vs 24 cribs"),
        search_space=n_configs, elapsed_s=round(elapsed, 1), solved_params=solved,
        insights=insights,
        next_steps=(["verify byte-exact & announce"] if solved else
                    ["additive mask+core closed; if 'masking' means a NON-additive (chart/lookup) mask, that is "
                     "the idiosyncratic hand-crafted-alphabet residue (exp 088) -- not enumerable. Pursue the "
                     "constraint-solver falsification (A) and HMM/MCMC (C)"]),
        metrics={"n_determined": len(determined), "n_new_nonperiodic": len(new_determined),
                 "best": bi, "control_p": round(ctrl_p, 4)}),
    )
    print(f"\n{len(determined)} determined ({len(new_determined)} non-periodic); best free-hex {best[0]:.2f}; "
          f"control p={ctrl_p:.3f}; status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
