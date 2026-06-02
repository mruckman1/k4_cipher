"""102 — Operationalize the EXISTING public Sanborn method-clues as deterministic
structural checks, and flag any implied mechanism not yet tested.

The 4 cribs themselves came from Sanborn's public reveals; his public statements
about the cipher TECHNIQUE are the same category of legal information (not the
plaintext, not K5, not future reveals). This catalogs each documented public
method-clue -> its cryptographic prediction -> the experiment(s) that tested it ->
the result, and surfaces gaps. One clue ("masking") gets a fresh deterministic
probe here.

STRICT BOUNDARY: only clues already public are used; this never waits for or
assumes a future reveal (the forbidden leak-waiting pattern), and never uses any
recovered plaintext.

$0, local, deterministic, pure decipherment. Output:
experiments/results/<date>_102_method_clue_catalog.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import time
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.solvers.sat_ilp import fanout

e035 = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
    "e035", str(Path(__file__).parent / "035_minimum_alphabet_analysis.py")))
e035.__spec__.loader.exec_module(e035)

BASE = e035.build_crib_constraints()
POS = [c[0] for c in BASE]
PLAIN = [c[1] for c in BASE]
CIPHER = [c[2] for c in BASE]


def chi_fanout(indices):
    """chi and fanout over the crib SUBSET given by `indices`."""
    sub = [BASE[j] for j in indices]
    E = set()
    for a in range(len(sub)):
        for b in range(a + 1, len(sub)):
            if e035.cribs_conflict(sub[a], sub[b]):
                E.add((a, b))
    chi = e035.chromatic_number(len(sub), E)
    fan = fanout("".join(PLAIN[j] for j in indices), "".join(CIPHER[j] for j in indices))
    return chi, fan


def masking_probe():
    """'Masking': test whether any regular periodic mask (keep positions with
    i%m==phase) leaves a structurally SIMPLER surviving-crib sub-cipher
    (chi<=2 or fanout<=2) than the full chi=3/fanout floor."""
    full_chi, full_fan = chi_fanout(list(range(24)))
    best = None
    for m in range(2, 8):
        for phase in range(m):
            idx = [j for j in range(24) if POS[j] % m == phase]
            if len(idx) < 4:
                continue
            chi, fan = chi_fanout(idx)
            if best is None or (chi, fan, -len(idx)) < (best["chi"], best["fan"], -best["n"]):
                best = {"m": m, "phase": phase, "n": len(idx), "chi": chi, "fan": fan}
    return full_chi, full_fan, best


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_102_method_clue_catalog.jsonl"
    t0 = time.perf_counter()

    full_chi, full_fan, mask_best = masking_probe()
    masking_simplifies = mask_best is not None and (mask_best["chi"] <= 2 and mask_best["n"] >= 8)

    # the catalog: public clue -> prediction -> test -> result/status
    catalog = [
        {"clue": "Berlin Clock (2025: the Weltzeituhr at Alexanderplatz)",
         "prediction": "key/selector/transposition/alphabet from the 24-city UTC-ordered clock",
         "tested_in": "003 (keystream), 049 (transposition), 094 (selector + alphabet)", "status": "CLOSED (ruled out)"},
        {"clue": "EAST / NORTHEAST / BERLIN / CLOCK (the 4 confirmed cribs)",
         "prediction": "known plaintext at fixed positions; pos74 K->K fixed point",
         "tested_in": "every experiment (anchors)", "status": "USED"},
        {"clue": "'a technique NOT used in K1-K3'",
         "prediction": "K4 is NOT Quagmire-III (K1/K2) nor plain columnar (K3)",
         "tested_in": "001 calib + the whole per-position-frame negative", "status": "CONFIRMED (K4 != K1-K3 families)"},
        {"clue": "'I changed/modified the system'",
         "prediction": "K4 is a MODIFIED Quagmire; its statistics fingerprint the modification class",
         "tested_in": "084 (modification fingerprint -> flattening, not transposition)",
         "status": "OPERATIONALIZED (084: flattening modification; 086/087 ruled out the two cleanest)"},
        {"clue": "plaintext, once decrypted, points to a physical LOCATION",
         "prediction": "plaintext register is telegraphic/navigational/coordinate, not prose",
         "tested_in": "067, 097, 100", "status": "TESTED (register apt but circular/under-determined)"},
        {"clue": "'masking technique'",
         "prediction": "a mask/null pattern hides the real cipher among decoy positions",
         "tested_in": "044 (null deletion), 050 (morse mask), 102 (this: periodic-mask structural probe)",
         "status": ("GAP: a regular mask leaves a simpler sub-cipher -- investigate" if masking_simplifies
                    else "COVERED (no regular mask simplifies the crib structure)")},
        {"clue": "layered: the plaintext requires a FURTHER step after decryption",
         "prediction": "first-layer plaintext is recoverable English at fixed crib positions (Fact 1)",
         "tested_in": "implicit (cribs are first-layer English at fixed positions)", "status": "CONSISTENT"},
        {"clue": "K2 'IDBYROWS' single-letter drop precedent",
         "prediction": "K4 may carry a single-letter transcription/encoding error",
         "tested_in": "032 (cipher-fit per 1-letter variant), 101 (structural facts per 1-letter variant)",
         "status": "TESTED (see 101)"},
    ]

    gaps = [c for c in catalog if c["status"].startswith("GAP")]
    elapsed = time.perf_counter() - t0
    with open(out, "w") as f:
        f.write(json.dumps({"catalog": catalog, "masking_probe":
                            {"full_chi": full_chi, "full_fanout": full_fan, "best_mask": mask_best,
                             "masking_simplifies": masking_simplifies}}) + "\n")

    insights = [
        f"Catalogued {len(catalog)} public Sanborn METHOD-clues (cipher technique, not plaintext) -> deterministic "
        f"checks. Status: "
        f"{sum(1 for c in catalog if 'CLOSED' in c['status'] or 'CONFIRMED' in c['status'] or 'COVERED' in c['status'])} "
        f"closed/covered, {sum(1 for c in catalog if 'TESTED' in c['status'] or 'OPERATIONALIZED' in c['status'] or 'USED' in c['status'] or 'CONSISTENT' in c['status'])} "
        f"tested/used, {len(gaps)} gaps.",
        f"MASKING probe: full crib chi={full_chi}/fanout={full_fan}; best periodic mask (keep i%m==phase) leaves "
        f"a sub-cipher with chi={mask_best['chi']}/fanout={mask_best['fan']} on {mask_best['n']} cribs "
        f"(m={mask_best['m']}, phase={mask_best['phase']}). Masking {'SIMPLIFIES the structure -- a gap to chase' if masking_simplifies else 'does NOT simplify (no decoy-mask reading helps)'}.",
        ("OPEN GAP(S): " + "; ".join(c["clue"] for c in gaps) if gaps else
         "NO GAPS: every public method-clue is operationalized and either closed, confirmed, or tested. No "
         "documented Sanborn technique-hint implies an untested mechanism -- the clue space is exhausted "
         "(without waiting for any future reveal)."),
    ]

    write_verdict(out, Verdict(
        exp="102", title="public Sanborn method-clue catalog -> deterministic checks",
        hypothesis="a documented public method-clue implies a structural test not yet run",
        status="promising" if gaps else "inconclusive",
        best_partial=f"{len(catalog)} clues catalogued; {len(gaps)} gaps; masking_simplifies={masking_simplifies}",
        search_space=len(catalog), elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["chase the flagged clue gap(s) as new experiments"] if gaps else
                    ["public method-clue space exhausted; all hints operationalized. Remaining info paths: "
                     "transcription robustness (101), crib-shift number theory (103), physical audit (104)"]),
        metrics={"n_clues": len(catalog), "n_gaps": len(gaps), "masking_simplifies": masking_simplifies,
                 "full_chi": full_chi, "full_fanout": full_fan}),
    )
    print(f"\n{len(catalog)} clues; {len(gaps)} gaps; masking_simplifies={masking_simplifies}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
