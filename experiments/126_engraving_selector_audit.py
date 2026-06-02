"""126 — Lever 2 (the buildable part): engraving-grid selector masks + a
transcription/1-indexing audit. The 5th-positional-crib path is documented as
BLOCKED (decipherment-legal only if Sanborn releases one; never fabricated/awaited).

The 30 selector-locked positions can move ONLY under a genuinely external
per-position selector fact (121/122/123 closed chart-ties, the clock, and
message-internal autokey). The one external structure not yet swept is the PHYSICAL
ENGRAVING LAYOUT: K4 is carved on the copper in a grid, so the selector could be a
row/column parity of that grid. We do not have the exact line layout (and there is
a documented transcription dispute), so instead of guessing one layout we SWEEP the
grid-width family -- row-parity (i//W)%2 and column-parity (i%W)%2 for all plausible
widths W -- the systematic version of "the engraving layout selects the chart".
This extends 116's 9 simple selectors to the full grid family. Each mask is tested
in the homophonic 2-colouring model (does it 2-colour the b-graph? if so, decrypt
vs the random-selector null), honestly against the exp-120 budget N_max=52.

PART A also runs a TRANSCRIPTION / 1-INDEXING AUDIT (cheap insurance flagged by the
ideation): confirm the canonical 97-char K4 string, that each crib's ciphertext
matches K4 at its stated 1-indexed span, and that the b-graph / 30-43 split are what
the whole homophonic analysis assumes -- so a silent index error cannot invalidate
exps 117-125.

$0, local, deterministic, no LLM, no K5, no plaintext. Output:
experiments/results/<date>_126_engraving_selector_audit.jsonl
"""

from __future__ import annotations

import json
import math
import random
import time
from collections import defaultdict
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K4
from kryptos.cribs import CRIBS

A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CANON_K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
EXPECTED_CRIBS = {  # 1-indexed start, plaintext, ciphertext (public Sanborn clues)
    "EAST": (22, "EAST", "FLRV"),
    "NORTHEAST": (26, "NORTHEAST", "QQPRNGKSS"),
    "BERLIN": (64, "BERLIN", "NYPVTT"),
    "CLOCK": (70, "CLOCK", "MZFPK"),
}
ENGLISH_BAR = -15.0


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_126_engraving_selector_audit.jsonl"
    rng = random.Random(0)
    t0 = time.perf_counter()

    # ---------------- PART A: transcription / 1-indexing audit ----------------
    audit = {"length_ok": len(K4) == 97, "matches_canonical": K4 == CANON_K4,
             "crib_checks": {}, "all_cribs_consistent": True}
    for name, (start, pt, ct) in EXPECTED_CRIBS.items():
        seg = K4[start - 1:start - 1 + len(ct)]
        ok = seg == ct
        audit["crib_checks"][name] = {"start_1idx": start, "expect_ct": ct, "found": seg, "ok": ok}
        if not ok:
            audit["all_cribs_consistent"] = False
    # rebuild the crib triples from the library and cross-check positions/letters
    lib_crib = [(c.start - 1 + off, p, ch)
                for c in CRIBS for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext))]
    lib_ct_ok = all(K4[pos] == ch for pos, _p, ch in lib_crib)
    audit["library_cribs_match_K4"] = lib_ct_ok
    audit["n_crib_positions"] = len(lib_crib)

    # b-graph + 30/43 split, recomputed, as the audit baseline
    CRIB = lib_crib
    Nn = len(CRIB)
    adj = defaultdict(set)
    n_edges = 0
    for i in range(Nn):
        for j in range(i + 1, Nn):
            if CRIB[i][2] == CRIB[j][2] and CRIB[i][1] != CRIB[j][1]:
                adj[i].add(j); adj[j].add(i); n_edges += 1
    CRIB_POS = {pos for pos, _, _ in CRIB}
    FREE = [i for i in range(97) if i not in CRIB_POS]
    CRIB_CIPHER = {ch for _, _, ch in CRIB}
    n_locked = sum(1 for i in FREE if K4[i] in CRIB_CIPHER)
    n_prior = len(FREE) - n_locked
    audit.update({"n_b_edges": n_edges, "n_free": len(FREE),
                  "n_selector_locked": n_locked, "n_prior_governed": n_prior})
    B_EDGES = [(i, j) for i in range(Nn) for j in range(i + 1, Nn)
               if CRIB[i][2] == CRIB[j][2] and CRIB[i][1] != CRIB[j][1]]
    audit_ok = (audit["length_ok"] and audit["matches_canonical"] and audit["all_cribs_consistent"]
                and lib_ct_ok and n_edges == 10 and n_locked == 30 and n_prior == 43)

    # ---------------- PART B: engraving-grid selector masks ----------------
    def two_colours(mask):
        return all(mask[CRIB[i][0]] != mask[CRIB[j][0]] for i, j in B_EDGES)

    def decrypt_score(mask, restarts=10, steps=2000):
        pins = {0: {}, 1: {}}
        for pos, p, ch in CRIB:
            pins[mask[pos]][ch] = p
        free_ciphers = {c: [X for X in A if X not in pins[c]] for c in (0, 1)}
        best = -99.0
        for _ in range(restarts):
            chart = {c: dict(pins[c]) for c in (0, 1)}
            for c in (0, 1):
                for X in free_ciphers[c]:
                    chart[c][X] = rng.choice(A)
            dec = lambda: "".join(chart[mask[i]][K4[i]] for i in range(97))
            cur = _kpa.score_free_text(dec())
            for s in range(steps):
                T = 0.5 * (0.01 / 0.5) ** (s / steps)
                c = rng.randrange(2)
                if not free_ciphers[c]:
                    continue
                X = rng.choice(free_ciphers[c]); old = chart[c][X]; nw = rng.choice(A)
                if nw == old:
                    continue
                chart[c][X] = nw
                cand = _kpa.score_free_text(dec())
                if cand >= cur or rng.random() < math.exp((cand - cur) / max(T, 1e-6)):
                    cur = cand
                else:
                    chart[c][X] = old
            best = max(best, _kpa.score_free_text(dec()))
        return best

    # build the grid masks: row-parity (i//W)%2 and column-parity (i%W)%2
    masks = {}
    for W in range(2, 41):
        masks[f"row_parity_W{W}"] = [(i // W) % 2 for i in range(97)]
        masks[f"col_parity_W{W}"] = [(i % W) % 2 for i in range(97)]
        masks[f"col_half_W{W}"] = [1 if (i % W) >= (W // 2) else 0 for i in range(97)]
    n_masks = len(masks)
    passers = [name for name, m in masks.items() if two_colours(m)]

    best_pass = (-99.0, None)
    for name in passers:
        sc = decrypt_score(masks[name])
        if sc > best_pass[0]:
            best_pass = (sc, name)
    # random-selector null
    null_best = -99.0
    npass = tries = 0
    while npass < 8 and tries < 4000:
        tries += 1
        rm = [rng.randrange(2) for _ in range(97)]
        if two_colours(rm):
            npass += 1
            null_best = max(null_best, decrypt_score(rm, restarts=5, steps=1200))

    elapsed = time.perf_counter() - t0
    signal = best_pass[1] is not None and best_pass[0] >= ENGLISH_BAR and best_pass[0] > null_best + 1.0
    status = "promising" if signal else ("inconclusive" if not audit_ok else "ruled_out")

    with open(out, "w") as f:
        f.write(json.dumps({
            "transcription_audit": audit, "audit_ok": audit_ok,
            "n_grid_masks": n_masks, "mask_budget_N_max": 52, "n_passers": len(passers),
            "passers": passers, "best_pass_hex": round(best_pass[0], 2), "best_pass_mask": best_pass[1],
            "random_null_hex": round(null_best, 2), "english_bar": ENGLISH_BAR, "signal": signal,
            "fifth_crib_status": "BLOCKED: a 5th positional crib is decipherment-legal only if Sanborn "
                                 "publicly releases one; never fabricated, never waited on (exp 102 found 0 gaps "
                                 "in public clues)."}) + "\n")

    insights = [
        f"PART A TRANSCRIPTION/INDEX AUDIT: K4 length=97 {audit['length_ok']}, matches canonical string "
        f"{audit['matches_canonical']}, all 4 cribs match K4 at their 1-indexed spans "
        f"{audit['all_cribs_consistent']} (library cribs match K4: {lib_ct_ok}); recomputed b-edges={n_edges}, "
        f"free={len(FREE)}, split {n_locked} selector-locked / {n_prior} prior-governed. AUDIT {'PASSES' if audit_ok else 'FAILS'} "
        f"-- the entire 117-125 homophonic analysis rests on a byte-exact, correctly-indexed foundation"
        f"{'.' if audit_ok else ' -- WARNING: a discrepancy invalidates downstream counts!'}",
        f"PART B ENGRAVING-GRID SELECTORS: swept {n_masks} grid masks (row/column parity & half over widths "
        f"2-40). {len(passers)} properly 2-COLOUR the b-graph: {passers or 'NONE'}. "
        + (f"Best passer decrypt {best_pass[0]:.2f} ({best_pass[1]}) vs random-selector null {null_best:.2f}. "
           + ("SIGNAL: a grid-parity selector beats the null -- the engraving grid may select the chart; inspect."
              if signal else "no passer beats the null (hill-climbing free cells reaches the floor under any "
              "2-colouring selector, 116/122).") if passers else
           "NO grid-parity selector 2-colours the cribs -- the chart selector is not a row/column parity of any "
           "engraving grid width 2-40 (extends 116's 9-selector negative to the full grid family). Note: this "
           "tests the grid PARITY family, not a bespoke physical layout, which would need the exact carved "
           "line-structure data (not in repo; a documented transcription dispute exists)."),
        "5TH-CRIB PATH (the other external lever): BLOCKED by the decipherment-only rule -- a 5th positional crib "
        "is admissible only if Sanborn publicly releases one; it is never fabricated and never waited on (exp 102 "
        "already found 0 gaps in the public clue record). So of Lever 2's two routes, the engraving-grid family is "
        + ("an open lead." if signal else "now closed for grid parities; only the un-obtained exact carved layout "
           "or a future Sanborn release remains.") + " The 30 selector-locked positions stay blocked.",
    ]

    write_verdict(out, Verdict(
        exp="126", title="engraving-grid selector sweep + transcription/indexing audit (Lever 2 buildable part)",
        hypothesis="the per-position chart selector is a row/column parity of K4's physical engraving grid "
                   "(swept over widths), and the canonical transcription/indexing underpinning 117-125 is exact",
        status=status, best_score=(best_pass[0] if signal else None),
        best_partial=f"audit_ok={audit_ok}; {len(passers)}/{n_masks} grid masks 2-colour; best {best_pass[0]:.2f} "
                     f"vs null {null_best:.2f}; signal={signal}",
        search_space=n_masks, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["inspect/verify the grid-parity selector decrypt"] if signal else
                    ["engraving-grid PARITY selectors closed; the 30 selector-locked positions need the exact "
                     "carved line-layout (not in repo) or a Sanborn-released 5th crib. Transcription audit "
                     "confirms 117-125 rest on a byte-exact foundation"]),
        metrics={"audit_ok": audit_ok, "n_grid_masks": n_masks, "n_passers": len(passers),
                 "best_pass_hex": round(best_pass[0], 2), "random_null_hex": round(null_best, 2),
                 "signal": signal, "n_b_edges": n_edges, "split_locked_prior": [n_locked, n_prior]}),
    )
    print(f"\nAUDIT ok={audit_ok} (len97={audit['length_ok']}, canonical={audit['matches_canonical']}, "
          f"cribs={audit['all_cribs_consistent']}, edges={n_edges}, split={n_locked}/{n_prior}). "
          f"GRID: {len(passers)}/{n_masks} 2-colour; best {best_pass[0]:.2f} vs null {null_best:.2f}; "
          f"signal={signal}; status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
