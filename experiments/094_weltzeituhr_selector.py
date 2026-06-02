"""094 — Weltzeituhr (the confirmed "Berlin Clock") as the per-position alphabet
SELECTOR, and as a hand-crafted-alphabet source.

Sanborn confirmed (Nov 2025) that K4's "Berlin Clock" is the Urania Weltzeituhr
at Alexanderplatz. Its salient structure is 24 city columns ordered by UTC
offset (data/physical/weltzeituhr_zones.csv). Prior clock work is already CLOSED:
  - exp 003: the clock as a time-advance KEYSTREAM -> ruled out.
  - exp 049: the 24-column order as a TRANSPOSITION key -> ruled out (and Fact 1
    forbids net transposition anyway).
  - exp 043: ALL period <= 24 keys (covers a static period-24 clock key) -> ruled out.

The one clock role neither 003 nor 049 tested -- and, per the exp 092/093
identifiability result, exactly the crux -- is the clock as the per-position
ALPHABET SELECTOR: position i -> a Weltzeituhr city (cycling the 24 columns at
some phase) -> a class (by UTC sign / offset residue / column / marker). Each
class uses one rotation of a keyed base alphabet (the non-degenerate model of
082/090). We sweep the phase (which city aligns to position 1 -- the "memorable"
parameter) and ask the 090 question: is any (phase, class-rule, alphabet,
convention) a proper colouring of the chi=3 crib graph AND crib-determined AND
decrypts to English? Part B adds Weltzeituhr-keyed alphabets (city names, the
24-marker string) to the exp-088 chi=3 cover test.

Honest expectation (from 085/090/093-A): simple selectors do not properly-colour
the cribs, so the clock selector likely has empty support -- but it is the
Sanborn-confirmed structure and must be checked. A hit would be a genuine lead;
no hit closes the last clock role.

$0, local, pure decipherment. Output:
experiments/results/<date>_094_weltzeituhr_selector.jsonl
"""

from __future__ import annotations

import csv
import importlib.util
import json
import time
from datetime import date
from pathlib import Path

import _crib_sat as cs
import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, keyed_alphabet
from kryptos.constants import K4

e035 = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
    "e035", str(Path(__file__).parent / "035_minimum_alphabet_analysis.py")))
e035.__spec__.loader.exec_module(e035)

N = 97
M = 26
ALPHS = {"kryptos_keyed": KRYPTOS_KEYED, "standard": STANDARD, "keyed_PALIMPSEST": keyed_alphabet("PALIMPSEST")}


def load_zones():
    lines = [ln for ln in Path("data/physical/weltzeituhr_zones.csv").read_text().splitlines()
             if ln and not ln.startswith("#")]
    rows = list(csv.DictReader(lines))
    rows.sort(key=lambda r: int(r["column"]))
    utc = [int(float(r["utc_offset"])) for r in rows]
    city = [r["city"] for r in rows]
    marker = [r["zone_marker"] for r in rows]
    return utc, city, marker  # length 24, physical-column order


def class_rules(utc, marker):
    """City -> class. Several Weltzeituhr-natural partitions."""
    R = {}
    R["utc_sign"] = lambda c: (0 if utc[c] < 0 else 1 if utc[c] == 0 else 2)      # West/GMT/East
    R["utc%3"] = lambda c: utc[c] % 3
    R["utc%4"] = lambda c: utc[c] % 4
    R["col%3"] = lambda c: c % 3
    R["col%4"] = lambda c: c % 4
    R["marker0%3"] = lambda c: (ord(marker[c][0]) - 65) % 3
    return R


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_094_weltzeituhr_selector.jsonl"
    t0 = time.perf_counter()
    utc, city, marker = load_zones()
    NC = len(city)  # 24

    cribs = e035.build_crib_constraints()
    positions = [c[0] for c in cribs]
    edges = set()
    for i in range(len(cribs)):
        for j in range(i + 1, len(cribs)):
            if e035.cribs_conflict(cribs[i], cribs[j]):
                edges.add((i, j))

    rules = class_rules(utc, marker)
    best = (-99.0, None)
    solved = None
    n_proper = 0
    n_determined_full = 0
    n_underdet = 0
    n_configs = 0

    with open(out, "w") as f:
        # ---- PART A: clock as per-position SELECTOR ----
        for phase in range(NC):                      # which city aligns to position 0
            citycol = lambda i, ph=phase: (i + ph) % NC
            for rname, rule in rules.items():
                g = lambda i, rule=rule, cc=citycol: rule(cc(i))
                n_configs += 1
                vals = {node: g(positions[node]) for node in range(len(cribs))}
                proper = all(vals[u] != vals[v] for u, v in edges)
                if proper:
                    n_proper += 1
                for an, alpha in ALPHS.items():
                    for conv in _kpa.CONVENTIONS:
                        cls, ok = {}, True
                        for (pos, p_, c_, _, _) in cribs:
                            pi, ci = alpha.index(p_), alpha.index(c_)
                            sh = ((ci - pi) % M if conv == "vigenere"
                                  else (ci + pi) % M if conv == "beaufort" else (pi - ci) % M)
                            cl = g(pos)
                            if cl in cls and cls[cl] != sh:
                                ok = False; break
                            cls[cl] = sh
                        if not ok:
                            continue
                        full = all(g(i) in cls for i in range(N))
                        if not full:
                            n_underdet += 1
                            continue
                        n_determined_full += 1
                        P = []
                        for i in range(N):
                            sh = cls[g(i)]; ci = alpha.index(K4[i])
                            pi = ((ci - sh) % M if conv == "vigenere"
                                  else (sh - ci) % M if conv == "beaufort" else (ci + sh) % M)
                            P.append(alpha.at(pi))
                        P = "".join(P)
                        sc = _kpa.score_free_text(P)
                        rec = {"phase": phase, "rule": rname, "alphabet": an, "conv": conv,
                               "n_classes": len(cls), "hex": round(sc, 2), "plaintext": P}
                        if sc > best[0]:
                            best = (sc, rec)
                        if sc > -16.0:
                            f.write(json.dumps(rec) + "\n")
                        if sc > -15.0:
                            solved = rec

        # ---- PART B: Weltzeituhr-keyed alphabets in the chi=3 cover test ----
        kw = ["WELTZEITUHR", "ALEXANDERPLATZ", "URANIA", "BERLIN", "CAIRO",
              "".join(m for m in marker),                       # 24 two-letter markers concatenated
              "".join(c[0] for c in city)]                      # city initials in column order
        clock_alphas, seen = [], set()
        for k in kw:
            s = keyed_alphabet("".join(ch for ch in k.upper() if ch.isalpha())).letters
            if s not in seen:
                seen.add(s); clock_alphas.append((f"kw[{k[:10]}]", s))
        cover3 = cs.find_cover(clock_alphas, 3)
        bp_n, bp_tot, _ = cs.best_partial_cover(clock_alphas, min(3, len(clock_alphas)))

    elapsed = time.perf_counter() - t0
    bi = best[1]
    if solved:
        status = "solved"
    elif bi and bi["hex"] > -16.0:
        status = "promising"
    else:
        status = "ruled_out"

    insights = [
        f"PART A (clock as SELECTOR -- the role 003/049 never tested): swept {NC} phase alignments x "
        f"{len(rules)} Weltzeituhr class-rules (UTC sign/residue, column, marker) x {len(ALPHS)} alphabets x 3 "
        f"conventions = {n_configs * len(ALPHS) * 3} configs. Proper 3-colourings of the crib graph: {n_proper}/"
        f"{n_configs}. Crib-determined & full (decryptable): {n_determined_full}; under-determined: {n_underdet}.",
        (f"Best clock-selector decrypt: phase {bi['phase']} rule {bi['rule']} {bi['alphabet']}/{bi['conv']} "
         f"free-hex {bi['hex']} -> {bi['plaintext'][:40]}..." if bi else
         "No Weltzeituhr selector admitted a crib-determined full fit at any phase."),
        f"PART B (clock as ALPHABET source): Weltzeituhr-keyed alphabets (city names, marker string, initials) "
        f"3-cover the 24 cribs: {'YES ' + str(cover3[0]) if cover3 else 'NO'}; best 3 cover {bp_n}/{bp_tot} "
        f"constraints (consistent with 088: memorable alphabets do not 3-cover).",
    ]
    if status == "ruled_out":
        insights.append(
            "VERDICT: the Weltzeituhr does not work as a per-position alphabet SELECTOR (no phase/rule properly "
            "colours the cribs and decrypts) nor as an alphabet source (no 3-cover) -- the last untested clock "
            "role is closed. Combined with 003 (keystream) and 049 (transposition), the Sanborn-confirmed "
            "Berlin Clock is exhausted as a cipher mechanism. Consistent with 092/093: the clock cannot rescue "
            "an under-determined per-position cipher unless it supplies a NON-letter-statistics constraint that "
            "we have not been able to operationalize (e.g. it points at a specific plaintext, not a mechanism).")

    write_verdict(out, Verdict(
        exp="094", title="Weltzeituhr (Berlin Clock) as per-position alphabet selector + alphabet source",
        hypothesis="K4's alphabet selector (or its hand-crafted alphabets) derive from the Weltzeituhr's "
                   "24-city UTC-ordered structure",
        status=status, best_score=(bi["hex"] if (bi and status in ("solved", "promising")) else None),
        best_partial=(f"best phase {bi['phase']} rule {bi['rule']} free-hex {bi['hex']}" if bi else
                      f"0 crib-determined clock selectors over {NC} phases; clock alphabets cover {bp_n}/{bp_tot}; "
                      f"{n_proper} proper colourings"),
        search_space=n_configs * len(ALPHS) * 3, elapsed_s=round(elapsed, 1), solved_params=solved,
        insights=insights,
        next_steps=(["verify byte-exact & announce; the matching phase pins the city/position alignment"]
                    if solved else
                    ["clock exhausted as a mechanism (003 keystream + 049 transposition + 094 selector/alphabet). "
                     "Per 092/093 the remaining levers are a SEMANTIC plaintext prior (local LLM re-rank) or the "
                     "bounded/under-determined writeup -- not another mechanism search"]),
        metrics={"n_proper": n_proper, "n_determined_full": n_determined_full, "n_underdet": n_underdet,
                 "clock_alpha_cover": bool(cover3), "best_partial_cover": bp_n, "best": bi}),
    )
    print(f"\nPart A: {n_proper} proper, {n_determined_full} determined-full clock selectors over {NC} phases; "
          f"best free-hex {best[0]:.2f}. Part B cover: {'yes' if cover3 else 'no'} ({bp_n}/{bp_tot}). "
          f"status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
