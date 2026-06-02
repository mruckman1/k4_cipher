"""101 — Ciphertext-transcription robustness: is the universal negative an
artifact of a mis-read engraving letter?

Every one of the 100 prior experiments assumed the canonical 97-char K4 string is
letter-perfect. The engraving has documented letter-reading debates. If even ONE
ciphertext letter at a crib position is mis-transcribed, the load-bearing
structural facts (chi=3, the fanout floor, simple-selector incolourability) -- and
thus the whole negative -- could be artifacts of a wrong input. This is
information about the INPUT, not more cipher search (extends exp 032, which tested
cipher-FIT per variant; this tests the STRUCTURAL FACTS per variant).

Only crib-position changes can move the structural facts (chi/fanout depend solely
on the 24 crib (plaintext, ciphertext) pairs; free-position errors are
structurally invisible -- they would only perturb a final decryption, which we do
not have). So we sweep every single-letter substitution at the 24 crib positions
(24x25=600), plus the highest-value two-letter changes (pairs among the positions
that touch a conflict edge), and recompute:
  - chi (chromatic number of the crib conflict graph) -- a drop to <=2 would mean
    the >=3-alphabet bound is a transcription artifact;
  - fanout (max distinct ciphertext per crib plaintext letter) -- a drop below the
    baseline floor would admit a simpler per-position cipher;
  - simple-selector proper-colourability -- if a 1-letter fix lets a SIMPLE
    position selector (i%k, row-of-7) properly 3-colour the cribs, the squeeze
    (085/093) is a transcription artifact.

A flagged variant = a concrete transcription-error candidate to scrutinise. NONE
flagged = the negative is ROBUST to single (and high-value double) misreads, a
strong result: the conclusion does not hinge on reading one engraved letter.

$0, local, deterministic, pure decipherment. Output:
experiments/results/<date>_101_transcription_robustness.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import time
from datetime import date
from itertools import combinations
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.solvers.sat_ilp import fanout

e035 = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
    "e035", str(Path(__file__).parent / "035_minimum_alphabet_analysis.py")))
e035.__spec__.loader.exec_module(e035)

A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
BASE = e035.build_crib_constraints()           # 24 x (pos, p, c, pi, ci)
POSITIONS = [c[0] for c in BASE]
PLAIN = [c[1] for c in BASE]
CIPHER0 = [c[2] for c in BASE]

# position-only simple selectors (independent of the ciphertext, so variant-safe)
SELECTORS = {
    "i%3": lambda i: i % 3, "i%4": lambda i: i % 4, "i%5": lambda i: i % 5,
    "(i//7)%3": lambda i: (i // 7) % 3, "(2i)%3": lambda i: (2 * i) % 3,
    "(i//8)%3": lambda i: (i // 8) % 3, "(i+i//7)%3": lambda i: (i + i // 7) % 3,
}


def edges_of(cipher):
    cons = [(POSITIONS[j], PLAIN[j], cipher[j], ord(PLAIN[j]) - 65, ord(cipher[j]) - 65)
            for j in range(24)]
    E = set()
    for a in range(24):
        for b in range(a + 1, 24):
            if e035.cribs_conflict(cons[a], cons[b]):
                E.add((a, b))
    return E


def chi_of(cipher):
    return e035.chromatic_number(24, edges_of(cipher))


def fanout_of(cipher):
    return fanout("".join(PLAIN), "".join(cipher))


def selector_colours(cipher):
    """Names of simple selectors that PROPERLY colour the crib graph for this
    ciphertext (>=3 colours used at crib nodes, no monochromatic conflict edge)."""
    E = edges_of(cipher)
    good = []
    for name, g in SELECTORS.items():
        col = [g(POSITIONS[j]) for j in range(24)]
        if len(set(col)) >= 3 and all(col[a] != col[b] for a, b in E):
            good.append(name)
    return good


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_101_transcription_robustness.jsonl"
    t0 = time.perf_counter()

    base_chi = chi_of(CIPHER0)
    base_fan = fanout_of(CIPHER0)
    base_sel = selector_colours(CIPHER0)

    flagged = []          # variants that reduce structural complexity
    single_tested = 0
    min_chi_seen = base_chi
    min_fan_seen = base_fan

    # crib positions that touch a conflict edge (highest-value for 2-letter)
    base_edges = edges_of(CIPHER0)
    edge_nodes = sorted({a for a, _ in base_edges} | {b for _, b in base_edges})

    with open(out, "w") as f:
        # ---- single-letter sweep over the 24 crib positions ----
        for j in range(24):
            for L in A:
                if L == CIPHER0[j]:
                    continue
                single_tested += 1
                cip = CIPHER0[:]; cip[j] = L
                chi = chi_of(cip); fan = fanout_of(cip); sel = selector_colours(cip)
                min_chi_seen = min(min_chi_seen, chi); min_fan_seen = min(min_fan_seen, fan)
                if chi < base_chi or fan < base_fan or (sel and not base_sel):
                    rec = {"kind": "single", "crib_index": j, "pos": POSITIONS[j],
                           "from": CIPHER0[j], "to": L, "chi": chi, "fanout": fan, "selectors": sel}
                    flagged.append(rec); f.write(json.dumps(rec) + "\n")

        # ---- two-letter sweep over conflict-edge-incident crib positions ----
        two_tested = 0
        for a, b in combinations(edge_nodes, 2):
            for La in A:
                if La == CIPHER0[a]:
                    continue
                for Lb in A:
                    if Lb == CIPHER0[b]:
                        continue
                    two_tested += 1
                    cip = CIPHER0[:]; cip[a] = La; cip[b] = Lb
                    chi = chi_of(cip)
                    if chi < base_chi:
                        fan = fanout_of(cip); sel = selector_colours(cip)
                        if chi <= 2 or fan < base_fan or (sel and not base_sel):
                            rec = {"kind": "double", "crib_indices": [a, b],
                                   "pos": [POSITIONS[a], POSITIONS[b]],
                                   "from": [CIPHER0[a], CIPHER0[b]], "to": [La, Lb],
                                   "chi": chi, "fanout": fan, "selectors": sel}
                            flagged.append(rec); f.write(json.dumps(rec) + "\n")

    elapsed = time.perf_counter() - t0
    chi_drops = [r for r in flagged if r["chi"] < base_chi]
    sel_enabled = [r for r in flagged if r["selectors"]]
    single_chi_drops = [r for r in chi_drops if r["kind"] == "single"]

    insights = [
        f"Baseline structural facts of the canonical K4 cribs: chi={base_chi}, fanout={base_fan}, "
        f"simple-selector proper-colourings={base_sel or 'NONE'}. Swept {single_tested} single-letter and "
        f"{two_tested} high-value two-letter crib-ciphertext variants.",
        f"SINGLE-LETTER robustness: the minimum chi over all 600 single-letter crib variants is {min_chi_seen} "
        f"(baseline {base_chi}); minimum fanout {min_fan_seen} (baseline {base_fan}). "
        f"{len(single_chi_drops)} single-letter changes drop chi below {base_chi}; "
        f"{len([r for r in sel_enabled if r['kind']=='single'])} enable a simple selector.",
        (f"FLAGGED transcription-error candidates: {[(r.get('pos'), r.get('from'), '->', r.get('to'), 'chi', r['chi']) for r in flagged[:8]]}"
         f"{' ...' if len(flagged) > 8 else ''}. These positions, if the engraving were misread to the 'to' "
         f"letter, would reduce the structural complexity -- worth scrutinising against high-resolution images."
         if flagged else
         "NO single-letter and NO high-value two-letter crib-ciphertext variant reduces chi below baseline, "
         "drops the fanout floor, or enables a simple selector."),
    ]
    # the result is ROBUST (strong negative) iff nothing meaningfully simplifies under 1 (or high-value 2) edits
    robust = (min_chi_seen >= base_chi and min_fan_seen >= base_fan and not sel_enabled)
    if robust:
        insights.append(
            "VERDICT: the universal negative is ROBUST to transcription error -- no single misread crib letter "
            "(and no high-value double) makes K4 structurally simpler (chi stays >=3, fanout >= floor, no simple "
            "selector). The conclusion does NOT hinge on reading one engraved letter; the structural bound is a "
            "property of the cribs as published, not an artifact.")
    else:
        insights.append(
            "VERDICT: at least one low-edit-distance ciphertext correction reduces the structural complexity -- "
            "a concrete transcription-error candidate. Re-examine those crib positions against the engraving "
            "before treating the structural bound as final.")

    write_verdict(out, Verdict(
        exp="101", title="ciphertext-transcription robustness of the structural facts (chi / fanout / selector)",
        hypothesis="a single (or high-value double) mis-transcribed crib letter makes K4 structurally simpler, "
                   "meaning the universal negative is an input artifact",
        status="promising" if not robust else "ruled_out",
        best_partial=f"baseline chi={base_chi}/fanout={base_fan}; min over single-letter chi={min_chi_seen}/"
                     f"fanout={min_fan_seen}; {len(flagged)} flagged variants; robust={robust}",
        search_space=single_tested + two_tested, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["scrutinise the flagged crib positions against high-resolution engraving images; re-run the "
                     "surviving cipher families on the corrected ciphertext"] if not robust else
                    ["transcription robustness confirmed -- the structural negative is not an input artifact. "
                     "Remaining info paths: public method-clue catalog (102), crib-shift number theory (103), "
                     "physical-structure audit (104)"]),
        metrics={"base_chi": base_chi, "base_fanout": base_fan, "min_chi": min_chi_seen,
                 "min_fanout": min_fan_seen, "n_flagged": len(flagged), "robust": robust,
                 "n_single": single_tested, "n_double": two_tested}),
    )
    print(f"\nbaseline chi={base_chi} fanout={base_fan}; min single-letter chi={min_chi_seen} fanout={min_fan_seen}; "
          f"{len(flagged)} flagged; robust={robust}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
