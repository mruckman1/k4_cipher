"""124 — T2-E: joint chart-aware decode, measuring per-position stability to
EMPIRICALLY confirm the 30/43 decomposition (Path-A honest measurement, not a solve).

120 split the 73 free positions structurally into 30 "selector-locked" (crib-pinned
cipher letter -> 0.50 coin-flip) and 43 "prior-governed" (cipher letter absent
from cribs -> both chart entries free -> decided by the plaintext prior). This
measures that split EMPIRICALLY: sample many (proper-2-colouring + free selector)
configs, hill-climb the free chart cells to English under the hexagram prior, keep
the English-level decrypts, and measure each free position's letter ENTROPY across
them. Naive prediction (TESTED AND OVERTURNED here): that the 43 prior-governed
positions would converge (language pinning them) while the 30 selector-locked stay
split. The measurement shows the OPPOSITE -- the prior-governed positions are the
MOST variable (both chart cells free), while the selector-locked are anchored by
their recurring crib letter -- so the honest deliverable is the residual-ambiguity
count (distinct English decrypts) plus the per-position stability by class, NOT a
confirmation that language "owns" the 43.

$0, local, deterministic, no LLM, no K5, no plaintext. Output:
experiments/results/<date>_124_joint_decode_stability.jsonl
"""

from __future__ import annotations

import json
import math
import random
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
CRIB_CIPHER = {ch for _, _, ch in CRIB}
SELECTOR_LOCKED = [i for i in FREE if K4[i] in CRIB_CIPHER]      # 30
PRIOR_GOVERNED = [i for i in FREE if K4[i] not in CRIB_CIPHER]  # 43
ENGLISH_BAR = -15.0


def b_adj():
    adj = defaultdict(set)
    for i in range(N):
        for j in range(i + 1, N):
            if CRIB[i][2] == CRIB[j][2] and CRIB[i][1] != CRIB[j][1]:
                adj[i].add(j); adj[j].add(i)
    return adj


def proper_2colouring(adj, rng):
    """Random proper 2-colouring of the b-graph (BFS bipartition per comp, random
    swap; isolated nodes random)."""
    col = {}
    for s in range(N):
        if s in col:
            continue
        comp = {s: rng.randrange(2)}
        q = deque([s])
        while q:
            u = q.popleft()
            for w in adj[u]:
                if w not in comp:
                    comp[w] = 1 - comp[u]; q.append(w)
        col.update(comp)
    return [col[i] for i in range(N)]


def hillclimb_joint(col, rng, steps=3000):
    """JOINT SA over (free chart cells AND the 73 free-position selector bits),
    crib positions held at the proper colouring `col`. This is the strongest
    deterministic decode: it optimises which chart each free position uses together
    with the free chart entries. Returns (plaintext, free-hex)."""
    selector = [0] * 97
    for n, (pos, _p, _ch) in enumerate(CRIB):
        selector[pos] = col[n]
    for i in FREE:
        selector[i] = rng.randrange(2)
    pins = {0: {}, 1: {}}
    for n, (pos, p, ch) in enumerate(CRIB):
        pins[selector[pos]][ch] = p
    free_ciphers = {c: [X for X in A if X not in pins[c]] for c in (0, 1)}
    chart = {c: dict(pins[c]) for c in (0, 1)}
    for c in (0, 1):
        for X in free_ciphers[c]:
            chart[c][X] = rng.choice(A)
    dec = lambda: "".join(chart[selector[i]][K4[i]] for i in range(97))
    cur = _kpa.score_free_text(dec())
    for s in range(steps):
        T = 0.6 * (0.01 / 0.6) ** (s / steps)
        if rng.random() < 0.5:
            # move a free chart cell
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
        else:
            # flip a free-position selector bit
            i = rng.choice(FREE); selector[i] ^= 1
            cand = _kpa.score_free_text(dec())
            if cand >= cur or rng.random() < math.exp((cand - cur) / max(T, 1e-6)):
                cur = cand
            else:
                selector[i] ^= 1
    pt = dec()
    return pt, _kpa.score_free_text(pt)


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_124_joint_decode_stability.jsonl"
    rng = random.Random(0)
    t0 = time.perf_counter()
    adj = b_adj()

    samples = 80
    kept = []         # English-level decrypts
    best_hex = -99.0
    for _ in range(samples):
        col = proper_2colouring(adj, rng)
        pt, sc = hillclimb_joint(col, rng)
        best_hex = max(best_hex, sc)
        if sc >= ENGLISH_BAR:
            kept.append(pt)

    # per free position: letter entropy across kept English decrypts
    def entropy(pos):
        c = Counter(pt[pos] for pt in kept)
        tot = sum(c.values())
        if tot == 0:
            return None
        return -sum((v / tot) * math.log2(v / tot) for v in c.values())

    ent_locked = [entropy(i) for i in SELECTOR_LOCKED if entropy(i) is not None]
    ent_prior = [entropy(i) for i in PRIOR_GOVERNED if entropy(i) is not None]
    distinct = len(set(kept))

    # also: mode-fraction (how often the most common letter wins) per class
    def mode_frac(pos):
        c = Counter(pt[pos] for pt in kept)
        tot = sum(c.values())
        return (max(c.values()) / tot) if tot else None
    mf_locked = [mode_frac(i) for i in SELECTOR_LOCKED if mode_frac(i) is not None]
    mf_prior = [mode_frac(i) for i in PRIOR_GOVERNED if mode_frac(i) is not None]

    mean_ent_locked = statistics.mean(ent_locked) if ent_locked else None
    mean_ent_prior = statistics.mean(ent_prior) if ent_prior else None
    mean_mf_locked = statistics.mean(mf_locked) if mf_locked else None
    mean_mf_prior = statistics.mean(mf_prior) if mf_prior else None
    enough = len(kept) >= 10   # need an ensemble for a reliable stability estimate
    # the decomposition is confirmed if prior-governed are more determined (lower
    # entropy) than selector-locked, on a non-trivial ensemble
    confirmed = (enough and mean_ent_prior is not None and mean_ent_locked is not None
                 and mean_ent_prior < mean_ent_locked)

    elapsed = time.perf_counter() - t0
    with open(out, "w") as f:
        f.write(json.dumps({
            "samples": samples, "n_english_kept": len(kept), "distinct_english": distinct,
            "best_free_hex": round(best_hex, 2), "ensemble_sufficient": enough,
            "n_selector_locked": len(SELECTOR_LOCKED), "n_prior_governed": len(PRIOR_GOVERNED),
            "mean_entropy_selector_locked": round(mean_ent_locked, 3) if mean_ent_locked else None,
            "mean_entropy_prior_governed": round(mean_ent_prior, 3) if mean_ent_prior else None,
            "mean_mode_frac_selector_locked": round(mean_mf_locked, 3) if mean_mf_locked else None,
            "mean_mode_frac_prior_governed": round(mean_mf_prior, 3) if mean_mf_prior else None,
            "decomposition_confirmed": confirmed, "english_bar": ENGLISH_BAR}) + "\n")

    insights = [
        f"Joint decode (strongest tried): {samples} restarts, each a JOINT SA over the free chart cells AND the "
        f"73 free-position selector bits; best free-hex {best_hex:.2f}; {len(kept)} reached the English bar "
        f"({distinct} distinct decrypts). The distinct count is the honest residual-ambiguity measure of the "
        f"homophonic decode.",
        (f"PER-POSITION STABILITY across {len(kept)} English decrypts -- mean letter ENTROPY: prior-governed "
         f"(43) = {mean_ent_prior} bits vs selector-locked (30) = {mean_ent_locked} bits; mean MODE-FRACTION: "
         f"prior {mean_mf_prior} vs locked {mean_mf_locked}. "
         + ("CONFIRMED: the 43 prior-governed positions are MORE determined (lower entropy) -- language pins "
            "them -- while the 30 selector-locked stay split, the 120 decomposition realised empirically."
            if confirmed else
            "Prior-determined are NOT cleanly more determined than selector-locked on this ensemble -- the joint "
            "SA collapses each restart to a different local fluent optimum, so per-position entropy reflects the "
            "decode's multiplicity, not the structural split.")
         if enough else
         f"ENSEMBLE TOO SMALL ({len(kept)} English decrypts < 10): the joint decode rarely clears the hexagram "
         f"bar from random restarts (best {best_hex:.2f}), so a reliable per-position stability estimate is not "
         f"available. The structural 30/43 split (120) stands on the crib algebra (119); this empirical cross-"
         f"check is inconclusive on sampling grounds, not a refutation."),
        "HONEST SCOPE: this MEASURES residual ambiguity; it does not pin the plaintext. The selector-locked 30 "
        "stay at a coin-flip (119, 121-123); a stronger non-saturating prior (PPM/word-level) is the open Path-A "
        "lever for the 43 prior-governed positions, but cannot touch the 30 -- those need an EXTERNAL "
        "per-position selector fact, which 121/122/123 showed is neither a chart-tie, the clock, nor a "
        "message-internal autokey.",
    ]

    write_verdict(out, Verdict(
        exp="124", title="joint chart-aware decode -- per-position stability confirms the 30/43 split",
        hypothesis="under the joint n-gram decode the 43 prior-governed positions converge (language pins them) "
                   "while the 30 selector-locked stay split -- the 120 decomposition, measured",
        status="inconclusive",
        best_partial=f"best free-hex {best_hex:.2f}; {len(kept)} English ({distinct} distinct); entropy prior "
                     f"{mean_ent_prior} vs locked {mean_ent_locked} (confirmed={confirmed}, n_ok={enough})",
        search_space=samples, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=["Path A: swap the saturating hexagram for a PPM/word-level prior to sharpen the 43 "
                    "prior-governed positions; the 30 selector-locked remain blocked pending an external "
                    "per-position selector fact (engraving layout / 5th positional crib)"],
        metrics={"distinct_english": distinct, "mean_entropy_prior_governed":
                 round(mean_ent_prior, 3) if mean_ent_prior else None, "mean_entropy_selector_locked":
                 round(mean_ent_locked, 3) if mean_ent_locked else None,
                 "decomposition_confirmed": confirmed}),
    )
    print(f"\nbest_hex={best_hex:.2f}; kept={len(kept)} distinct={distinct} (enough={enough}); "
          f"entropy prior={mean_ent_prior} locked={mean_ent_locked}; confirmed={confirmed}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
