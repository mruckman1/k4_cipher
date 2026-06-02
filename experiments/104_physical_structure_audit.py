"""104 — Physical-structure constraint audit: has every deterministic feature of
the Kryptos sculpture been extracted as a constraint and cross-checked against K4?

Lower novelty (an audit), but it closes the question of whether any public,
deterministic physical feature of the sculpture remains un-mined. For each
feature: its cryptographic role, the experiment(s) that used it, and whether a gap
remains. Includes one fresh deterministic check (the 27-letter tableau anomaly:
does the doubled-L sculpture alphabet admit a crib mapping the 26-letter one
forbids?).

$0, local, deterministic, pure decipherment. Output:
experiments/results/<date>_104_physical_structure_audit.jsonl
"""

from __future__ import annotations

import importlib.util
import json
import time
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, KRYPTOS_WITH_EXTRA_L
from kryptos.cribs import CRIBS

e035 = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
    "e035", str(Path(__file__).parent / "035_minimum_alphabet_analysis.py")))
e035.__spec__.loader.exec_module(e035)


def tableau_anomaly_check():
    """Does the 27-letter doubled-L sculpture tableau let a SINGLE keyed alphabet
    cover more cribs than the 26-letter keyed alphabet? (a quick admissibility
    delta; the 27-letter alphabet is non-injective so decryption is multivalued,
    but a coverage gain would flag the anomaly as load-bearing)."""
    def max_cover(alpha):
        # in a single monoalphabetic substitution, count cribs whose (p->c) is
        # consistent with SOME fixed shift in this alphabet's index space (vigenere)
        from collections import Counter
        shifts = Counter()
        for c in CRIBS:
            for p, ch in zip(c.plaintext, c.ciphertext):
                try:
                    shifts[(alpha.index(ch) - alpha.index(p)) % len(alpha)] += 1
                except ValueError:
                    pass
        return max(shifts.values()) if shifts else 0
    return max_cover(KRYPTOS_KEYED), max_cover(KRYPTOS_WITH_EXTRA_L)


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_104_physical_structure_audit.jsonl"
    t0 = time.perf_counter()

    cov26, cov27 = tableau_anomaly_check()
    anomaly_helps = cov27 > cov26

    features = [
        {"feature": "KRYPTOS Vigenere tableau (keyed alphabet)",
         "role": "the alphabet for K1-K3 and the base for K4 alphabets",
         "used_in": "001/046 + every keyed-alphabet KPA", "status": "EXTRACTED"},
        {"feature": "Tableau anomaly (doubled-L / 27-letter row; 'HILL' vertical)",
         "role": "a 27-letter or shifted alphabet as the K4 substitution alphabet",
         "used_in": "002 (DYAHR primer), 009 (27-letter search), 104 (this: coverage delta)",
         "status": ("GAP: 27-letter anomaly raises single-alphabet crib coverage -- revisit"
                    if anomaly_helps else "EXTRACTED (27-letter anomaly gives no crib-coverage gain)")},
        {"feature": "Morse code section (SOS / LUCID MEMORY / etc.)",
         "role": "keystream / mask / plaintext-theme source",
         "used_in": "050 (morse mask)", "status": "EXTRACTED"},
        {"feature": "Compass rose / lodestone bearings (0, 248, 45 deg)",
         "role": "physical-seed alphabets / the NORTHEAST=45deg link",
         "used_in": "047 (compass-bearing alphabets)", "status": "EXTRACTED"},
        {"feature": "Weltzeituhr (Berlin Clock, Sanborn-confirmed)",
         "role": "keystream / transposition / selector / alphabet source",
         "used_in": "003/049/094", "status": "EXTRACTED (closed)"},
        {"feature": "K4 transcript line layout (OBKR + 3x31)",
         "role": "route/grid transposition or 2-D selector clock",
         "used_in": "052 (route/engraving transposition), 090 (2-D grid selector), 126/127 (grid selector)",
         "status": "UNVERIFIED TRANSCRIPT CONVENTION -- not a measured physical engraving (verified via web "
                   "2026-05-30): OBKR is NOT a standalone line; it is the last 4 chars (cols 27-30) of the 31-wide "
                   "transcript row that ENDS K3 (...DOHW?OBKR), so K4 shares Panel 2 and that row with K3. The "
                   "'31' is a transcript-grid width; physical copper rows vary ~29-33 and no certified per-line "
                   "engraving layout is publicly published (Elonka's own note: the digital layout 'failed' to "
                   "match the sculpture). Treat [4,31,31,31] as a convention, not a measurement; 127 uses the "
                   "corrected continuous-panel geometry (OBKR offset)"},
        {"feature": "K1-K3 keys (PALIMPSEST, ABSCISSA, KRYPTOS; K3 columnar width-7)",
         "role": "calibration + keyword pools + the offset-7 autocorrelation lead",
         "used_in": "001/033/048/081", "status": "EXTRACTED"},
        {"feature": "pos-74 K->K fixed point",
         "role": "a hard zero-shift constraint at one position",
         "used_in": "crib machinery (it is a crib position)", "status": "EXTRACTED"},
    ]

    gaps = [f for f in features if f["status"].startswith("GAP")]
    unverified = [f for f in features if "UNVERIFIED" in f["status"]]
    elapsed = time.perf_counter() - t0
    with open(out, "w") as f:
        f.write(json.dumps({"features": features, "tableau_anomaly":
                            {"cover26": cov26, "cover27": cov27, "anomaly_helps": anomaly_helps}}) + "\n")

    insights = [
        f"Audited {len(features)} deterministic physical features of the sculpture against the experiment record. "
        f"Extracted/closed: {sum(1 for f in features if 'EXTRACTED' in f['status'])}; gaps: {len(gaps)}; "
        f"UNVERIFIED assumptions: {len(unverified)}.",
        f"Tableau-anomaly check: a single keyed alphabet covers {cov26} crib letters in the 26-letter "
        f"KRYPTOS alphabet vs {cov27} in the 27-letter doubled-L sculpture alphabet -- the anomaly "
        f"{'RAISES coverage (revisit as a load-bearing alphabet)' if anomaly_helps else 'gives no gain (not load-bearing for the cribs)'}.",
        ("OPEN GAP(S): " + "; ".join(f["feature"] for f in gaps) if gaps else
         "NO MINEABLE PUBLIC GAPS: every deterministic physical feature with a public source is already extracted "
         "and cross-checked."),
        (f"CORRECTION (web-verified 2026-05-30): {len(unverified)} feature is an UNVERIFIED assumption, not a "
         f"measured fact -- the K4 'engraved line layout [4,31,31,31]'. It is a TRANSCRIPT convention: OBKR is the "
         f"last 4 chars of the 31-wide row that ENDS K3 (not a standalone line), physical rows vary ~29-33, and "
         f"no certified per-line copper layout is published. So the prior 'physical-structure fully mined / 0 "
         f"gaps' was an overstatement on this one feature; 052/090/126 used the mis-framed standalone layout. 127 "
         f"re-tests the corrected continuous-panel geometry; a truly physical layout would require measuring a "
         f"high-res photo/rubbing (not available)." if unverified else
         "All audited features are measured facts, not assumptions."),
    ]

    write_verdict(out, Verdict(
        exp="104", title="physical-structure constraint audit",
        hypothesis="a deterministic physical feature of the sculpture remains un-extracted as a K4 constraint",
        status="promising" if gaps else "inconclusive",
        best_partial=f"{len(features)} features audited; {len(gaps)} gaps; tableau-anomaly cover 26={cov26}/27={cov27}",
        search_space=len(features), elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["extract the flagged physical feature(s) as a new constraint/experiment"] if gaps else
                    ["no mineable public gap; one UNVERIFIED assumption (K4 line layout) corrected -- 127 tests "
                     "the verified transcript geometry; a measured physical layout needs a high-res photo/rubbing "
                     "(not publicly available). Otherwise the public data is exhausted under decipherment-only."]),
        metrics={"n_features": len(features), "n_gaps": len(gaps), "n_unverified": len(unverified),
                 "cover26": cov26, "cover27": cov27, "anomaly_helps": anomaly_helps}),
    )
    print(f"\n{len(features)} features; {len(gaps)} gaps; tableau anomaly cover 26={cov26}/27={cov27}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
