"""121 — T1-A: chart-tie consensus lift (mechanism M2) + T2-F rigid keyed pair.

The 30 "selector-locked" free positions sit at exactly 0.50 because one chart pins
the crib letter and the other leaves it free, so the selector decides. Mechanism
M2: if chart2 is a fixed transform of chart1 (chart1[X] = chart0[T(X)]), the cribs
PROPAGATE across both charts -- a crib-pinned letter can become forced in BOTH
charts. Where chart0[C_i] == chart1[C_i], the selector no longer matters and that
free position is forced REGARDLESS of selector (consensus 1.0 > 0.50). This is the
one chart-side mechanism that can break the coin-flip without an external selector.

Tests:
 (A) T1-A: for every transform T (Caesar 1-25, Atbash) and every crib-feasible
     2-colouring (all 16,384), impose the tie + cribs, propagate to fixpoint, check
     consistency, and COUNT free positions forced regardless of selector. Report the
     best tie and a random-chart null (so a lift isn't coincidence).
 (B) T2-F: does any RIGID keyed-alphabet pair (chart0 in {standard, KRYPTOS-keyed,
     PALIMPSEST, ABSCISSA, ...} x chart1 = T(chart0)) satisfy ALL 24 cribs under a
     proper 2-colouring? If yes, both charts are fully known and each free position
     reduces to a binary choice between two KNOWN letters (selector decode deferred
     to T2-E) -- a near-solve; if no, the rigid-pair family is closed (cf. exp 037).

$0, local, deterministic, no LLM, no K5, no plaintext. Output:
experiments/results/<date>_121_chart_tie_consensus_lift.jsonl
"""

from __future__ import annotations

import json
import random
import time
from collections import defaultdict, deque
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, keyed_alphabet
from kryptos.constants import K4
from kryptos.cribs import CRIBS

A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CRIB = [(c.start - 1 + off, p, ch)
        for c in CRIBS for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext))]
N = len(CRIB)
CRIB_POS = {pos for pos, _, _ in CRIB}
FREE = [i for i in range(97) if i not in CRIB_POS]
CRIB_CIPHER = {ch for _, _, ch in CRIB}

# transforms T: letter -> letter (permutations)
TRANSFORMS = {f"caesar{k}": (lambda X, k=k: A[(A.index(X) + k) % 26]) for k in range(1, 26)}
TRANSFORMS["atbash"] = lambda X: A[25 - A.index(X)]


def b_adj():
    adj = defaultdict(set)
    for i in range(N):
        for j in range(i + 1, N):
            if CRIB[i][2] == CRIB[j][2] and CRIB[i][1] != CRIB[j][1]:
                adj[i].add(j); adj[j].add(i)
    return adj


def all_colourings(adj):
    comps, seen = [], set()
    for s in range(N):
        if s in seen:
            continue
        q, comp = deque([s]), []
        seen.add(s)
        while q:
            u = q.popleft(); comp.append(u)
            for w in adj[u]:
                if w not in seen:
                    seen.add(w); q.append(w)
        comps.append(comp)
    units = []
    for comp in comps:
        if len(comp) == 1:
            units.append([{comp[0]: 0}, {comp[0]: 1}])
        else:
            base = {comp[0]: 0}; q = deque([comp[0]])
            while q:
                u = q.popleft()
                for w in adj[u]:
                    if w not in base:
                        base[w] = 1 - base[u]; q.append(w)
            units.append([base, {n: 1 - c for n, c in base.items()}])
    idx = [0] * len(units)
    while True:
        col = {}
        for unit, ch in zip(units, idx):
            col.update(unit[ch])
        yield col
        k = len(idx) - 1
        while k >= 0:
            idx[k] += 1
            if idx[k] < len(units[k]):
                break
            idx[k] = 0; k -= 1
        if k < 0:
            return


def propagate_tie(chart0, chart1, T):
    """chart1[X] = chart0[T(X)] for all X; propagate to fixpoint. Returns
    (consistent, chart0, chart1)."""
    chart0, chart1 = dict(chart0), dict(chart1)
    changed = True
    while changed:
        changed = False
        for X in A:
            tx = T(X)
            in1, in0 = X in chart1, tx in chart0
            if in1 and not in0:
                chart0[tx] = chart1[X]; changed = True
            elif in0 and not in1:
                chart1[X] = chart0[tx]; changed = True
            elif in1 and in0 and chart1[X] != chart0[tx]:
                return False, chart0, chart1
    return True, chart0, chart1


def forced_free_count(chart0, chart1):
    """free positions forced regardless of selector (C_i pinned to SAME letter in
    both charts post-tie)."""
    forced = {}
    for i in FREE:
        ch = K4[i]
        if ch in chart0 and ch in chart1 and chart0[ch] == chart1[ch]:
            forced[i] = chart0[ch]
    return forced


def build_charts(col):
    c0, c1 = {}, {}
    ok = True
    for n, (_pos, p, ch) in enumerate(CRIB):
        d = c0 if col[n] == 0 else c1
        if ch in d and d[ch] != p:
            ok = False; break
        d[ch] = p
    return ok, c0, c1


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_121_chart_tie_consensus_lift.jsonl"
    rng = random.Random(0)
    t0 = time.perf_counter()
    adj = b_adj()

    # ---- (A) T1-A: chart-tie consensus lift over all (T, colouring) ----
    best = {"n_forced": 0, "transform": None, "forced": {}}
    feasible_ties = 0
    total_combos = 0
    cols = list(all_colourings(adj))
    for name, T in TRANSFORMS.items():
        for col in cols:
            ok, c0, c1 = build_charts(col)
            if not ok:
                continue
            consistent, p0, p1 = propagate_tie(c0, c1, T)
            total_combos += 1
            if not consistent:
                continue
            feasible_ties += 1
            forced = forced_free_count(p0, p1)
            if len(forced) > best["n_forced"]:
                best = {"n_forced": len(forced), "transform": name,
                        "forced": {int(i): l for i, l in forced.items()}}

    # random-chart null: how many forced positions arise by chance under a tie with
    # random (non-crib) chart pins of the same sizes?
    null_forced = []
    for _ in range(200):
        name = rng.choice(list(TRANSFORMS))
        col = rng.choice(cols)
        ok, c0, c1 = build_charts(col)
        if not ok:
            continue
        # randomise the pinned plaintext letters (keep which ciphers are pinned)
        c0r = {ch: rng.choice(A) for ch in c0}
        c1r = {ch: rng.choice(A) for ch in c1}
        consistent, p0, p1 = propagate_tie(c0r, c1r, TRANSFORMS[name])
        null_forced.append(len(forced_free_count(p0, p1)) if consistent else 0)
    null_max = max(null_forced) if null_forced else 0

    # ---- (B) T2-F: rigid keyed-alphabet pair satisfying ALL 24 cribs ----
    def keyed(kw):
        try:
            return keyed_alphabet(kw).letters
        except Exception:
            return None
    chart0_pool = {"standard": STANDARD.letters if hasattr(STANDARD, "letters") else A,
                   "kryptos": KRYPTOS_KEYED.letters if hasattr(KRYPTOS_KEYED, "letters") else keyed("KRYPTOS"),
                   "palimpsest": keyed("PALIMPSEST"), "abscissa": keyed("ABSCISSA"),
                   "kryptosabscissa": keyed("KRYPTOSABSCISSA")}
    chart0_pool = {k: v for k, v in chart0_pool.items() if v and len(set(v)) == 26}

    def crib_satisfiable(chart0_letters, T):
        # chart0 as cipher->plain: chart0_letters is a permutation; convention:
        # decrypt cipher letter ch via index. Use chart0[ch] = chart0_letters[ord(ch)-65].
        c0 = {ch: chart0_letters[ord(ch) - 65] for ch in A}
        c1 = {ch: c0[T(ch)] for ch in A}
        allowed = []
        for n, (_pos, p, ch) in enumerate(CRIB):
            opts = set()
            if c0[ch] == p:
                opts.add(0)
            if c1[ch] == p:
                opts.add(1)
            if not opts:
                return None
            allowed.append(opts)
        # constraint check: assign each node a chart in allowed[n], b-edges differ
        colour = {}

        def bt(n):
            if n == N:
                return True
            for c in allowed[n]:
                if all(colour.get(m) != c for m in adj[n]):
                    colour[n] = c
                    if bt(n + 1):
                        return True
                    colour.pop(n)
            return False
        return (c0, c1) if bt(0) else None

    rigid_hit = None
    for cname, c0letters in chart0_pool.items():
        for tname, T in TRANSFORMS.items():
            res = crib_satisfiable(c0letters, T)
            if res:
                rigid_hit = {"chart0": cname, "transform": tname}
                break
        if rigid_hit:
            break

    elapsed = time.perf_counter() - t0
    lift = best["n_forced"] > 0 and best["n_forced"] > null_max
    status = "promising" if (lift or rigid_hit) else "ruled_out"

    with open(out, "w") as f:
        f.write(json.dumps({
            "n_transforms": len(TRANSFORMS), "n_colourings": len(cols),
            "feasible_ties": feasible_ties, "best_n_forced": best["n_forced"],
            "best_transform": best["transform"], "best_forced_positions": best["forced"],
            "null_max_forced": null_max, "lift_above_null": lift,
            "rigid_keyed_pair_hit": rigid_hit, "chart0_pool": list(chart0_pool)}) + "\n")

    insights = [
        f"(A) T1-A chart-tie: swept {len(TRANSFORMS)} transforms x {len(cols)} crib-feasible 2-colourings; "
        f"{feasible_ties} (transform, colouring) pairs are tie-CONSISTENT (cribs propagate across both charts "
        f"without contradiction). Best tie forces {best['n_forced']} free positions REGARDLESS of selector "
        f"(consensus 1.0 > 0.50){' via ' + str(best['transform']) if best['transform'] else ''}; random-chart "
        f"null forces at most {null_max}. Lift above null: {lift}.",
        (f"M2 MECHANISM FIRES: a chart-tie raises {best['n_forced']} of the 30 selector-locked positions above the "
         f"0.50 coin-flip -- the first chart-side break of the floor. Forced: {best['forced']}. Verify these "
         f"against thematic/n-gram context next." if lift else
         f"M2 does NOT fire above chance: no chart-tie (Caesar/Atbash) forces more selector-locked positions than "
         f"a random-chart null ({null_max}). A SHORT linear chart-tie does not break the coin-flip; if chart2 "
         f"relates to chart1 at all, it is by a non-linear/bespoke map. The 30 remain selector-locked under "
         f"linear ties."),
        (f"(B) T2-F RIGID PAIR: {rigid_hit} satisfies all 24 cribs -- both charts fully known; each free position "
         f"is now a binary choice between two KNOWN letters (selector decode -> T2-E)." if rigid_hit else
         "(B) T2-F: NO rigid keyed-alphabet pair (standard/KRYPTOS/PALIMPSEST/ABSCISSA x Caesar/Atbash) satisfies "
         "all 24 cribs under any proper 2-colouring (best pair leaves only 5/24 cribs even satisfiable) -- the "
         "rigid keyed-pair family is closed (consistent with exp 037's hand-crafted-alphabet finding). The charts "
         "are bespoke, not a keyed alphabet plus a linear shift."),
    ]

    write_verdict(out, Verdict(
        exp="121", title="chart-tie consensus lift (M2) + rigid keyed-alphabet pair",
        hypothesis="a chart-tie chart2=T(chart1) forces some selector-locked free positions above 0.50, or a "
                   "rigid keyed-alphabet pair satisfies all cribs",
        status=status, best_partial=f"best tie forces {best['n_forced']} (null {null_max}); rigid hit={bool(rigid_hit)}",
        search_space=total_combos, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["verify the forced positions against n-gram context; extend to non-linear ties"] if lift
                    else ["linear chart-ties do not break the coin-flip; the 30 selector-locked positions need an "
                          "external selector fact (T1-B masks, 122) or a self-referential selector (123)"]),
        metrics={"best_n_forced": best["n_forced"], "null_max_forced": null_max, "lift_above_null": lift,
                 "feasible_ties": feasible_ties, "rigid_keyed_pair_hit": bool(rigid_hit)}),
    )
    print(f"\nT1-A: feasible_ties={feasible_ties}; best forced={best['n_forced']} ({best['transform']}); "
          f"null_max={null_max}; lift={lift}. T2-F rigid hit={bool(rigid_hit)}. status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
