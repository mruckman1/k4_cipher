"""118 — Crib-extended homophonic KPA: forced-vs-free entry accounting under the
2-chart homophonic model (move 2 of the homophonic thread).

117 enumerated the 512 structural (16,384 incl. isolated-node freedom) proper
2-colourings of the b-graph -- each a crib-feasible split of the 24 crib
positions into 2 homophonic charts. This characterises, EXACTLY (by enumerating
every crib-feasible colouring, no sampling), how much the cribs pin:

  (1) per chart: how many of the 26 cipher->plain entries are FORCED by the
      cribs vs FREE (homophonic charts are non-injective, so free entries are
      genuinely open);
  (2) per free position (73 of them): is its plaintext FORCED regardless of the
      selector (cipher letter pinned to the SAME plaintext in BOTH charts),
      forced only under one selector branch (pinned in exactly one chart), or
      never forced (cipher letter pinned in neither chart);
  (3) the GUARANTEED determined set -- free positions forced to one consistent
      letter across ALL 16,384 crib-feasible colourings (selector- AND
      colouring-independent). Head-to-head with 098's bijective 3-chart
      consensus floor: with only 2 charts each covers more crib letters, so the
      homophonic model could pin MORE free positions than the bijective one did.

$0, local, deterministic, no LLM, no K5, no plaintext. Output:
experiments/results/<date>_118_homophonic_crib_kpa.jsonl
"""

from __future__ import annotations

import json
import statistics
import time
from collections import Counter, defaultdict, deque
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K4
from kryptos.cribs import CRIBS

A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CRIB = [(c.start - 1 + off, p, ch)
        for c in CRIBS for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext))]
N = len(CRIB)
CRIB_POS = {pos for pos, _, _ in CRIB}
FREE = [i for i in range(97) if i not in CRIB_POS]


def b_conf(x, y):
    return x[2] == y[2] and x[1] != y[1]


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_118_homophonic_crib_kpa.jsonl"
    t0 = time.perf_counter()

    # b-graph adjacency over crib nodes
    adj = defaultdict(set)
    edges = set()
    for i in range(N):
        for j in range(i + 1, N):
            if b_conf(CRIB[i], CRIB[j]):
                adj[i].add(j); adj[j].add(i); edges.add((i, j))

    # connected components
    seen, comps = set(), []
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
    edge_comps = [c for c in comps if len(c) > 1]
    isolated = [c[0] for c in comps if len(c) == 1]

    # ambiguous cipher letters (the ones that FORCE the splits) -- diagnostic
    cipher_to_plains = defaultdict(set)
    for _, p, ch in CRIB:
        cipher_to_plains[ch].add(p)
    ambiguous = {ch: sorted(ps) for ch, ps in cipher_to_plains.items() if len(ps) > 1}
    distinct_cipher_letters = len(cipher_to_plains)
    distinct_pairs = len({(ch, p) for _, p, ch in CRIB})

    # enumerate every crib-feasible 2-colouring: each edge-bearing comp has 2
    # bipartitions, each isolated node 2 free choices -> 2^9 * 2^5 = 16,384.
    comp_options = []  # for each independent unit, the list of {node:colour} dicts
    for comp in edge_comps:
        base = {comp[0]: 0}
        q = deque([comp[0]])
        while q:
            u = q.popleft()
            for w in adj[u]:
                if w not in base:
                    base[w] = 1 - base[u]; q.append(w)
        comp_options.append([base, {n: 1 - c for n, c in base.items()}])
    for iso in isolated:
        comp_options.append([{iso: 0}, {iso: 1}])

    # iterate the product without materialising all 16,384 dicts at once
    def colourings():
        idx = [0] * len(comp_options)
        while True:
            col = {}
            for unit, choice in zip(comp_options, idx):
                col.update(unit[choice])
            yield col
            k = len(idx) - 1
            while k >= 0:
                idx[k] += 1
                if idx[k] < len(comp_options[k]):
                    break
                idx[k] = 0; k -= 1
            if k < 0:
                return

    pinned_per_chart = []          # (n_pinned_chart0, n_pinned_chart1) per colouring
    forced_both_counts = []        # #free positions forced regardless of selector
    forced_one_counts = []
    # guaranteed-determined accumulator: pos -> set of forced letters seen across colourings
    guaranteed = {i: set() for i in FREE}
    free_ever_forced = set()
    n_col = 0
    for col in colourings():
        charts = {0: {}, 1: {}}
        for n, (pos, p, ch) in enumerate(CRIB):
            c = col[n]
            charts[c][ch] = p          # proper colouring => no contradiction
        pinned_per_chart.append((len(charts[0]), len(charts[1])))
        fb = fo = 0
        for i in FREE:
            ch = K4[i]
            in0, in1 = ch in charts[0], ch in charts[1]
            if in0 and in1:
                if charts[0][ch] == charts[1][ch]:
                    fb += 1
                    guaranteed[i].add(charts[0][ch]); free_ever_forced.add(i)
                else:
                    fo += 1                       # forced to different letters by branch
                    free_ever_forced.add(i)
                    guaranteed[i].add(None)        # inconsistent -> not guaranteed
            elif in0 or in1:
                fo += 1; free_ever_forced.add(i)
                guaranteed[i].add(None)            # free in the other chart -> selector-dependent
            else:
                guaranteed[i].add(None)            # never pinned under this colouring
        forced_both_counts.append(fb)
        forced_one_counts.append(fo)
        n_col += 1

    # guaranteed determined = forced to ONE consistent letter, never None, across ALL colourings
    guaranteed_positions = {i: next(iter(s)) for i, s in guaranteed.items()
                            if len(s) == 1 and None not in s}

    elapsed = time.perf_counter() - t0
    pin0 = [a for a, _ in pinned_per_chart]
    pin1 = [b for _, b in pinned_per_chart]

    with open(out, "w") as f:
        f.write(json.dumps({
            "n_colourings_enumerated": n_col, "n_b_edges": len(edges),
            "distinct_cipher_letters_in_cribs": distinct_cipher_letters,
            "distinct_cipher_plain_pairs": distinct_pairs,
            "ambiguous_cipher_letters": ambiguous,
            "pinned_entries_per_chart_min": [min(pin0), min(pin1)],
            "pinned_entries_per_chart_max": [max(pin0), max(pin1)],
            "pinned_entries_per_chart_median": [statistics.median(pin0), statistics.median(pin1)],
            "free_entries_per_chart_median": [26 - statistics.median(pin0),
                                              26 - statistics.median(pin1)],
            "forced_both_count_range": [min(forced_both_counts), max(forced_both_counts)],
            "forced_one_count_range": [min(forced_one_counts), max(forced_one_counts)],
            "n_free_ever_forced": len(free_ever_forced),
            "n_guaranteed_determined": len(guaranteed_positions),
            "guaranteed_positions": {str(i): L for i, L in sorted(guaranteed_positions.items())}}) + "\n")

    insights = [
        f"Cribs hold {distinct_pairs} distinct (cipher->plain) pairs over {distinct_cipher_letters} distinct "
        f"cipher letters; {len(ambiguous)} cipher letters are AMBIGUOUS (map to >1 plaintext: {ambiguous}) -- "
        f"these are exactly what force the {len(edge_comps)} b-graph splits. Enumerated all {n_col:,} "
        f"crib-feasible 2-colourings (exact, no sampling).",
        f"PER-CHART ENTRY ACCOUNTING: each homophonic chart has 26 cipher->plain entries; the cribs FORCE "
        f"{min(pin0)}-{max(pin0)} of them in chart 0 and {min(pin1)}-{max(pin1)} in chart 1 (median "
        f"{statistics.median(pin0):.1f}/{statistics.median(pin1):.1f}), leaving ~{26 - statistics.median(pin0):.1f}"
        f"/{26 - statistics.median(pin1):.1f} entries FREE per chart. Non-injective free entries are the residual "
        f"degrees of freedom (092/093).",
        f"FREE-POSITION DETERMINATION (of {len(FREE)} free positions): per colouring, "
        f"{min(forced_both_counts)}-{max(forced_both_counts)} are forced REGARDLESS of selector (cipher letter "
        f"pinned identically in both charts); {min(forced_one_counts)}-{max(forced_one_counts)} are forced only "
        f"on one selector branch. {len(free_ever_forced)} free positions are touched by a crib letter at all.",
        f"GUARANTEED DETERMINED FLOOR: {len(guaranteed_positions)} free positions are forced to ONE consistent "
        f"letter across ALL {n_col:,} crib-feasible colourings -- selector- AND colouring-independent. "
        + (f"Positions/letters: {guaranteed_positions}. " if guaranteed_positions else "")
        + "This is the exact homophonic determination floor; compare 098's bijective 3-chart consensus (sampled). "
        "The remaining free positions stay under-determined: the homophonic model escapes the bijective squeeze "
        "structurally (117) but the free chart entries leave decryption multiplicity (the honest gap).",
    ]

    status = "promising" if guaranteed_positions else "inconclusive"
    write_verdict(out, Verdict(
        exp="118", title="crib-extended homophonic KPA -- exact forced/free entry & position accounting",
        hypothesis="under the 2-chart homophonic model the cribs force a larger guaranteed-determined free-position "
                   "set than the bijective 3-chart model (098), because 2 charts each cover more crib letters",
        status=status,
        best_partial=f"forced-both {min(forced_both_counts)}-{max(forced_both_counts)}/73 per colouring; "
                     f"{len(guaranteed_positions)} guaranteed across all {n_col} colourings; "
                     f"~{26 - statistics.median(pin0):.1f} free entries/chart",
        search_space=n_col, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=["119: homophonic determinacy floor as a per-position probability over the full model space "
                    "(exact enumeration) head-to-head with 098, plus a decrypt-multiplicity census"],
        metrics={"n_colourings": n_col, "n_guaranteed_determined": len(guaranteed_positions),
                 "forced_both_max": max(forced_both_counts), "free_entries_per_chart_median":
                 [26 - statistics.median(pin0), 26 - statistics.median(pin1)],
                 "ambiguous_cipher_letters": list(ambiguous)}),
    )
    print(f"\ncolourings={n_col}; pinned/chart median {statistics.median(pin0):.1f}/{statistics.median(pin1):.1f}; "
          f"forced-both {min(forced_both_counts)}-{max(forced_both_counts)}; guaranteed={len(guaranteed_positions)}; "
          f"status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
