"""128 — The Ventris move: hypothesized thematic cribs + cascade test.

Linear B fell when Ventris BET that certain words were Cretan place-names, slotted
them into Kober's structural grid, and the bet CASCADED (forced absolute sign values)
and SELF-CONFIRMED (other words came out as Greek; the tripod tablet matched its
pictures). The analogue here: the four real cribs do not cascade (proven
under-determination, exps 092/093/119). So we test the genuinely-Ventris move --
HYPOTHESIZE additional thematic crib words at free positions (from context only: the
cribs' direction/Berlin/clock theme + the public K1-K3 narrative; NEVER from any
purported solution), and ask, for each (word, position):
  (1) CONSISTENCY -- does the hypothesis stay homophonic-consistent (the extended
      b-conflict graph remains 2-colourable)? An inconsistent guess "breaks the grid"
      and is rejected, exactly as a wrong place-name would.
  (2) CASCADE -- how many previously-unanchored free positions does the word newly
      anchor through shared chart cells (cipher letters it introduces that the real
      cribs lacked)? This is the Ventris "reach".
  (3) SELF-CONFIRMATION -- fixing real+hypothesized cribs, hill-climb the rest and
      score the free positions OUTSIDE the hypothesized word. Does pinning HERE make
      the text read as English THERE?
All three are compared against a RANDOM-WORD null (diagnostic-gate discipline): a
thematic crib is only a lead if it beats random guesses, not merely if it is
consistent (the model is permissive, so most guesses are consistent).

HONEST SCOPE: by the proven under-determination this cannot UNIQUELY solve K4; it can
only (a) surface a structurally privileged thematic crib (a real lead, to be
externally confirmed) or (b) show none is privileged (re-confirming under-
determination against the classic hypothesized-crib attack). Outputs are best-fitting
HYPOTHESES, never verified solutions.

$0, local, deterministic, no LLM, no K5, no leaked/claimed plaintext. Output:
experiments/results/<date>_128_ventris_hypothesized_cribs.jsonl
"""

from __future__ import annotations

import json
import math
import random
import statistics
import time
from collections import defaultdict, deque
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K4
from kryptos.cribs import CRIBS

A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
REAL = [(c.start - 1 + off, p, ch)
        for c in CRIBS for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext))]
REAL_POS = {pos for pos, _, _ in REAL}
REAL_CIPHERS = {ch for _, _, ch in REAL}
FREE = [i for i in range(97) if i not in REAL_POS]
FREE_WINDOWS = [(0, 20), (34, 62), (74, 96)]   # 0-indexed inclusive contiguous free runs
ENGLISH_BAR = -15.0

# Thematic lexicon -- derived ONLY from public context (crib theme + public K1-K3
# narrative + generic direction/Berlin/clock/time vocabulary). NOT from any solution.
THEMATIC = [
    # directions / geodesy (the EAST/NORTHEAST crib theme)
    "NORTH", "SOUTH", "WEST", "NORTHWEST", "SOUTHWEST", "SOUTHEAST", "DEGREES", "DEGREE",
    "LATITUDE", "LONGITUDE", "COMPASS", "BEARING", "MERIDIAN", "POLE", "GRID", "NORTHERLY",
    # Berlin / Cold War (the BERLIN crib theme)
    "WALL", "GATE", "BRANDENBURG", "GERMANY", "IRON", "CURTAIN", "CHECKPOINT", "BORDER",
    # clock / time (the CLOCK crib theme)
    "TIME", "HOUR", "MINUTE", "SECOND", "OCLOCK", "NOON", "MIDNIGHT", "SHADOW", "SUNDIAL",
    "DAYLIGHT", "MORNING", "EVENING",
    # public K1-K3 narrative vocabulary (themes only)
    "BETWEEN", "SUBTLE", "SHADING", "ABSENCE", "LIGHT", "ILLUSION", "INVISIBLE", "BURIED",
    "LAYER", "UNDERGROUND", "DEBRIS", "CHAMBER", "PASSAGE", "CANDLE", "NUANCE",
    # generic English function / locative words
    "THE", "AND", "WITH", "FROM", "THAT", "HERE", "THERE", "BENEATH", "BELOW", "BEYOND",
    "HIDDEN", "SECRET", "LOCATION", "PLACE", "WITHIN", "ENTRANCE", "FOUND", "LOOK", "FIND",
]


def placements(word):
    """All free windows where `word` fits entirely inside one contiguous free run."""
    L = len(word)
    out = []
    for a, b in FREE_WINDOWS:
        for start in range(a, b - L + 2):
            out.append(start)
    return out


def extended_entries(word, start):
    return REAL + [(start + i, word[i], K4[start + i]) for i in range(len(word))]


def is_2colourable(entries):
    """b-conflict graph (same cipher, different plaintext) bipartite?"""
    n = len(entries)
    adj = defaultdict(set)
    for i in range(n):
        for j in range(i + 1, n):
            if entries[i][2] == entries[j][2] and entries[i][1] != entries[j][1]:
                adj[i].add(j); adj[j].add(i)
    colour = {}
    for s in range(n):
        if s in colour:
            continue
        colour[s] = 0; q = deque([s])
        while q:
            u = q.popleft()
            for w in adj[u]:
                if w not in colour:
                    colour[w] = 1 - colour[u]; q.append(w)
                elif colour[w] == colour[u]:
                    return False, None
    return True, colour


def cascade(word, start):
    """# free positions outside the word newly ANCHORED: cipher letter introduced by
    the word, absent from the real cribs, mapping unambiguously in the extended set."""
    ext = extended_entries(word, start)
    c2p = defaultdict(set)
    for _pos, p, ch in ext:
        c2p[ch].add(p)
    new_ciphers = {ext[k][2] for k in range(len(REAL), len(ext))} - REAL_CIPHERS
    wpos = set(range(start, start + len(word)))
    n = 0
    for j in FREE:
        if j in wpos:
            continue
        ch = K4[j]
        if ch in new_ciphers and len(c2p[ch]) == 1:   # unambiguous new anchor
            n += 1
    return n


def self_confirm(word, start, colour, rng, restarts=6, steps=1400):
    """Fix real+hypothesized cribs (under extended 2-colouring `colour`); hill-climb
    free-position selector bits + free chart cells; score free positions OUTSIDE the
    hypothesized word (the Ventris 'does it read elsewhere' test)."""
    ext = extended_entries(word, start)
    wpos = set(range(start, start + len(word)))
    outside = [i for i in FREE if i not in wpos]
    # pins from extended cribs under the chosen colouring
    pins = {0: {}, 1: {}}
    sel = {}
    for n, (pos, p, ch) in enumerate(ext):
        c = colour[n]; sel[pos] = c
        pins[c][ch] = p   # proper 2-colouring => consistent
    free_pos = [i for i in range(97) if i not in sel]
    free_ciphers = {c: [X for X in A if X not in pins[c]] for c in (0, 1)}

    def score(selector, chart):
        s = "".join(chart[selector[i]][K4[i]] for i in range(97))
        return _kpa.hexagram_scorer()("".join(s[i] for i in outside))

    best = -99.0
    for _ in range(restarts):
        selector = dict(sel)
        for i in free_pos:
            selector[i] = rng.randrange(2)
        chart = {c: dict(pins[c]) for c in (0, 1)}
        for c in (0, 1):
            for X in free_ciphers[c]:
                chart[c][X] = rng.choice(A)
        cur = score(selector, chart)
        for s in range(steps):
            T = 0.5 * (0.01 / 0.5) ** (s / steps)
            if rng.random() < 0.5 and free_pos:
                i = rng.choice(free_pos); selector[i] ^= 1
                cand = score(selector, chart)
                if cand >= cur or rng.random() < math.exp((cand - cur) / max(T, 1e-6)):
                    cur = cand
                else:
                    selector[i] ^= 1
            else:
                c = rng.randrange(2)
                if not free_ciphers[c]:
                    continue
                X = rng.choice(free_ciphers[c]); old = chart[c][X]; nw = rng.choice(A)
                if nw == old:
                    continue
                chart[c][X] = nw
                cand = score(selector, chart)
                if cand >= cur or rng.random() < math.exp((cand - cur) / max(T, 1e-6)):
                    cur = cand
                else:
                    chart[c][X] = old
        best = max(best, cur)
    return best


def scan(words, rng):
    rows = []
    for w in words:
        for start in placements(w):
            ok, colour = is_2colourable(extended_entries(w, start))
            if not ok:
                continue
            rows.append({"word": w, "start": start + 1, "cascade": cascade(w, start),
                         "_colour": colour, "_start0": start})
    return rows


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_128_ventris_hypothesized_cribs.jsonl"
    rng = random.Random(0)
    t0 = time.perf_counter()

    # random-word null: same length multiset as the thematic lexicon
    lengths = [len(w) for w in THEMATIC]
    rand_words = ["".join(rng.choice(A) for _ in range(L)) for L in lengths]

    them = scan(THEMATIC, rng)
    null = scan(rand_words, rng)

    n_them_total = sum(len(placements(w)) for w in THEMATIC)
    n_null_total = sum(len(placements(w)) for w in rand_words)
    them_consistent = len(them)
    null_consistent = len(null)
    them_casc = [r["cascade"] for r in them]
    null_casc = [r["cascade"] for r in null]

    # self-confirmation on the top-by-cascade of each pool
    them.sort(key=lambda r: -r["cascade"])
    null.sort(key=lambda r: -r["cascade"])
    TOPK = 18
    for r in them[:TOPK]:
        r["self_hex"] = round(self_confirm(r["word"], r["_start0"], r["_colour"], rng), 2)
    null_fits = []
    for r in null[:TOPK]:
        null_fits.append(self_confirm(r["word"], r["_start0"], r["_colour"], rng))
    them_fits = [r["self_hex"] for r in them[:TOPK]]
    best_them = max(them[:TOPK], key=lambda r: r.get("self_hex", -99)) if them else None
    null_fit_best = max(null_fits) if null_fits else -99.0
    them_fit_best = max(them_fits) if them_fits else -99.0

    # is any thematic crib structurally PRIVILEGED vs the random null?
    casc_privileged = (them_casc and null_casc
                       and max(them_casc) > max(null_casc)
                       and statistics.mean(them_casc) > statistics.mean(null_casc) + 0.5)
    fit_privileged = them_fit_best > null_fit_best + 1.0
    lead = fit_privileged and best_them and best_them.get("self_hex", -99) >= ENGLISH_BAR

    top_rows = [{"word": r["word"], "start_1idx": r["start"], "cascade": r["cascade"],
                 "self_hex": r.get("self_hex")} for r in them[:10]]

    elapsed = time.perf_counter() - t0
    with open(out, "w") as f:
        f.write(json.dumps({
            "n_thematic_words": len(THEMATIC), "n_placements_thematic": n_them_total,
            "n_placements_null": n_null_total,
            "consistent_thematic": them_consistent, "consistent_null": null_consistent,
            "consistency_rate_thematic": round(them_consistent / max(1, n_them_total), 3),
            "consistency_rate_null": round(null_consistent / max(1, n_null_total), 3),
            "cascade_thematic_max": max(them_casc) if them_casc else 0,
            "cascade_thematic_mean": round(statistics.mean(them_casc), 2) if them_casc else 0,
            "cascade_null_max": max(null_casc) if null_casc else 0,
            "cascade_null_mean": round(statistics.mean(null_casc), 2) if null_casc else 0,
            "self_confirm_thematic_best": round(them_fit_best, 2),
            "self_confirm_null_best": round(null_fit_best, 2),
            "cascade_privileged": casc_privileged, "fit_privileged": fit_privileged,
            "lead": lead, "english_bar": ENGLISH_BAR,
            "best_hypothesis": ({"word": best_them["word"], "start_1idx": best_them["start"],
                                 "cascade": best_them["cascade"], "self_hex": best_them.get("self_hex")}
                                if best_them else None),
            "top10_by_cascade": top_rows}) + "\n")

    insights = [
        f"Tested {len(THEMATIC)} context-derived thematic crib words (direction/Berlin/clock theme + public K1-K3 "
        f"narrative) across {n_them_total} free-window placements; a random-word null of matched lengths gives "
        f"{n_null_total} placements. CONSISTENCY (extended b-graph stays 2-colourable): thematic "
        f"{them_consistent}/{n_them_total} ({them_consistent/max(1,n_them_total):.0%}) vs null "
        f"{null_consistent}/{n_null_total} ({null_consistent/max(1,n_null_total):.0%}). As expected the "
        f"homophonic model is PERMISSIVE -- consistency alone does not privilege a thematic guess.",
        f"CASCADE (Ventris reach: free positions a word newly anchors): thematic max {max(them_casc) if them_casc else 0} "
        f"mean {statistics.mean(them_casc):.2f} vs null max {max(null_casc) if null_casc else 0} mean "
        f"{statistics.mean(null_casc):.2f}. Privileged over null: {casc_privileged}. "
        + ("A thematic crib reaches further than random -- inspect the top cascaders." if casc_privileged else
           "Thematic cribs do not cascade further than random length-matched strings: the reach is a function of "
           "WHICH cipher letters a word's positions carry, not of the word's meaning."),
        f"SELF-CONFIRMATION (hex at positions OUTSIDE the hypothesized word, best of top-{TOPK} by cascade): "
        f"thematic {them_fit_best:.2f} vs null {null_fit_best:.2f} (English bar {ENGLISH_BAR}). Fit privileged: "
        f"{fit_privileged}. "
        + (f"LEAD: thematic crib '{best_them['word']}'@{best_them['start']} self-confirms above the null and the "
           f"English bar -- inspect/verify (and seek external confirmation), the Ventris test fires." if lead else
           "No thematic crib makes the rest read as English better than a random word does: pinning a "
           "thematically-plausible word HERE does not make the text read THERE. The Ventris cascade does not "
           "close -- consistent with the proven under-determination (the cribs+guessing do not lock K4)."),
        "VERDICT: " + ("a hypothesized thematic crib is structurally privileged -- the first Ventris-style opening; "
        "it still requires external confirmation (it is a hypothesis, not a verified solve)." if lead else
        "the Ventris move does NOT break K4. Unlike Linear B -- where place-names cascaded through Kober's grid and "
        "self-confirmed on the tripod tablet -- K4's homophonic grid is too permissive and its redundancy too "
        "exhausted for a hypothesized crib to cascade or self-confirm above chance. This is the negative the Linear-B "
        "analogy predicts: the missing information is genuinely external (a measured selector or a Sanborn-released "
        "5th positional crib), not recoverable by thematic guessing."),
    ]

    status = "promising" if lead else "inconclusive"
    write_verdict(out, Verdict(
        exp="128", title="Ventris-style hypothesized thematic cribs -- cascade + self-confirmation test",
        hypothesis="a hypothesized thematic crib word, slotted into a free window, cascades through the homophonic "
                   "chart cells and self-confirms (makes other positions read as English) better than a random "
                   "word -- the Linear-B decipherment move applied to K4",
        status=status, best_score=(them_fit_best if them_fit_best > -90 else None),
        best_partial=f"consistency {them_consistent}/{n_them_total} (null {null_consistent}/{n_null_total}); "
                     f"cascade max {max(them_casc) if them_casc else 0} (null {max(null_casc) if null_casc else 0}); "
                     f"self-confirm {them_fit_best:.2f} vs null {null_fit_best:.2f}; lead={lead}",
        search_space=n_them_total + n_null_total, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["inspect/verify the privileged thematic hypothesis; it is a LEAD, not a verified solve -- seek "
                     "external (physical/5th-crib) confirmation before any claim"] if lead else
                    ["hypothesized thematic cribs do not cascade/self-confirm above a random-word null; the Ventris "
                     "move is exhausted. The missing information is external (measured selector or 5th positional "
                     "crib), exactly as the under-determination result predicts"]),
        metrics={"consistent_thematic": them_consistent, "consistency_rate_null":
                 round(null_consistent / max(1, n_null_total), 3), "cascade_thematic_max":
                 max(them_casc) if them_casc else 0, "cascade_null_max": max(null_casc) if null_casc else 0,
                 "self_confirm_thematic_best": round(them_fit_best, 2), "self_confirm_null_best":
                 round(null_fit_best, 2), "cascade_privileged": casc_privileged, "fit_privileged": fit_privileged,
                 "lead": lead}),
    )
    print(f"\nconsistency them {them_consistent}/{n_them_total} vs null {null_consistent}/{n_null_total}; "
          f"cascade max them {max(them_casc) if them_casc else 0} null {max(null_casc) if null_casc else 0}; "
          f"self-confirm them {them_fit_best:.2f} null {null_fit_best:.2f}; lead={lead}; status={status}.")
    print(f"top thematic hypotheses by cascade: {top_rows[:6]}")
    print(f"-> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
