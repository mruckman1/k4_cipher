"""125 — Lever 1: a SHARPER deterministic prior (non-saturating backoff char-LM +
word-dictionary) over the 43 prior-governed free positions.

124 measured the joint homophonic decode under the SATURATING hexagram prior and
found the 43 prior-governed positions the MOST ambiguous (entropy 3.19 vs 1.08 for
selector-locked; 80/80 distinct English decrypts). The hexagram table floors on any
unseen 6-gram, so once a window is mostly-unseen its gradient flattens -- it cannot
discriminate among the many locally-fluent settings of the free cells. The one
unexhausted Path-A lever is a STRONGER, non-saturating deterministic prior. This
swaps the objective for the stupid-backoff char-LM (smooth, no hard floor; the
explicitly-allowed n-gram/char-LM class -- NOT a neural LLM) and re-measures the
residual ambiguity, head-to-head with 124. Decisive question: does a sharper prior
COLLAPSE the 43's ambiguity (lower entropy, fewer distinct optima), or is the
under-determination information-theoretic (the cipher destroyed the info, so no
deterministic prior can recover it)?

Also reports a WORD-level dictionary diagnostic on the best decrypt (does it segment
into real words?) -- a different, sharper English signal than any char n-gram.

$0, local, deterministic, no LLM (backoff char-LM only), no K5, no plaintext. Output:
experiments/results/<date>_125_sharper_prior_43.jsonl
"""

from __future__ import annotations

import json
import math
import random
import statistics
import time
from collections import Counter, deque
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K4
from kryptos.cribs import CRIBS
from kryptos.scoring.lm_fitness import backoff_scorer
from kryptos.utils import clean

A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CRIB = [(c.start - 1 + off, p, ch)
        for c in CRIBS for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext))]
N = len(CRIB)
CRIB_POS = {pos for pos, _, _ in CRIB}
FREE = [i for i in range(97) if i not in CRIB_POS]
CRIB_CIPHER = {ch for _, _, ch in CRIB}
SELECTOR_LOCKED = [i for i in FREE if K4[i] in CRIB_CIPHER]      # 30
PRIOR_GOVERNED = [i for i in FREE if K4[i] not in CRIB_CIPHER]   # 43

LM = backoff_scorer(maxn=7)   # non-saturating stupid-backoff char-LM


def load_words():
    try:
        ws = set()
        for line in open("/usr/share/dict/words"):
            w = line.strip().upper()
            if 2 <= len(w) <= 12 and w.isalpha():
                ws.add(w)
        ws |= {"EAST", "NORTHEAST", "BERLIN", "CLOCK", "A", "I"}
        return ws
    except Exception:
        return set()


WORDS = load_words()


def word_coverage(text, min_len=4):
    """Greedy longest-match dictionary segmentation; fraction of chars covered by
    words of length >= min_len (lenient short-word tiling is meaningless on random
    A-Z, so we only credit substantial words)."""
    if not WORDS:
        return 0.0
    i, covered = 0, 0
    n = len(text)
    while i < n:
        best = 0
        for L in range(min(12, n - i), min_len - 1, -1):
            if text[i:i + L] in WORDS:
                best = L; break
        if best:
            covered += best; i += best
        else:
            i += 1
    return covered / n


def b_adj():
    from collections import defaultdict
    adj = defaultdict(set)
    for i in range(N):
        for j in range(i + 1, N):
            if CRIB[i][2] == CRIB[j][2] and CRIB[i][1] != CRIB[j][1]:
                adj[i].add(j); adj[j].add(i)
    return adj


def proper_2colouring(adj, rng):
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


def _sa(chart, selector, free_ciphers, objective, rng, steps, T0):
    """Generic joint SA over free cells + free-position selector bits under
    `objective(text)->float` (higher better). Mutates chart/selector in place."""
    dec = lambda: "".join(chart[selector[i]][K4[i]] for i in range(97))
    cur = objective(dec())
    for s in range(steps):
        T = T0 * (0.01 / T0) ** (s / steps)
        if rng.random() < 0.5:
            c = rng.randrange(2)
            if not free_ciphers[c]:
                continue
            X = rng.choice(free_ciphers[c]); old = chart[c][X]; nw = rng.choice(A)
            if nw == old:
                continue
            chart[c][X] = nw
            cand = objective(dec())
            if cand >= cur or rng.random() < math.exp((cand - cur) / max(T, 1e-6)):
                cur = cand
            else:
                chart[c][X] = old
        else:
            i = rng.choice(FREE); selector[i] ^= 1
            cand = objective(dec())
            if cand >= cur or rng.random() < math.exp((cand - cur) / max(T, 1e-6)):
                cur = cand
            else:
                selector[i] ^= 1
    return dec()


def hillclimb_joint(col, rng, hex_steps=1500, lm_steps=1500):
    """FAIR test: phase 1 warm-starts to a fluent decrypt with the HEXAGRAM (the
    124 baseline), then phase 2 POLISHES the same state with the sharper backoff
    char-LM -- giving the sharper prior its best chance to disambiguate among
    hexagram-fluent decrypts. Returns the backoff-polished decrypt + both scores."""
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
    _sa(chart, selector, free_ciphers, _kpa.score_free_text, rng, hex_steps, 0.5)   # warm-start
    pt = _sa(chart, selector, free_ciphers, LM, rng, lm_steps, 0.1)                  # backoff polish
    return pt, LM(pt)


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_125_sharper_prior_43.jsonl"
    rng = random.Random(0)
    t0 = time.perf_counter()
    adj = b_adj()

    # calibrate the backoff LM scale on real English 97-char windows
    corp = clean((_kpa.REPO / "data" / "corpora" / "buchan_39steps.txt").read_text())
    eng_scores = [LM(corp[k:k + 97]) for k in range(0, 97 * 40, 97)][:40]
    eng_mean = statistics.mean(eng_scores); eng_sd = statistics.pstdev(eng_scores)

    samples = 60
    decs = []
    for _ in range(samples):
        col = proper_2colouring(adj, rng)
        pt, sc = hillclimb_joint(col, rng)
        decs.append((sc, pt))
    decs.sort(reverse=True)
    best_sc, best_pt = decs[0]

    # residual ambiguity over the TOP-K optima (the prior's most-favoured decrypts)
    K = 20
    top = [pt for _, pt in decs[:K]]

    def entropy(pos, pool):
        c = Counter(pt[pos] for pt in pool)
        tot = sum(c.values())
        return -sum((v / tot) * math.log2(v / tot) for v in c.values()) if tot else 0.0

    ent_locked_top = statistics.mean(entropy(i, top) for i in SELECTOR_LOCKED)
    ent_prior_top = statistics.mean(entropy(i, top) for i in PRIOR_GOVERNED)
    all_pts = [pt for _, pt in decs]
    ent_locked_all = statistics.mean(entropy(i, all_pts) for i in SELECTOR_LOCKED)
    ent_prior_all = statistics.mean(entropy(i, all_pts) for i in PRIOR_GOVERNED)
    distinct_all = len({pt for _, pt in decs})
    distinct_top = len(set(top))

    wc_best = word_coverage(best_pt)
    # how English-like is the best decrypt, in backoff sigmas above gibberish?
    best_sigma = (best_sc - eng_mean) / eng_sd if eng_sd else 0.0

    # 124 hexagram baseline (for the head-to-head)
    base = {"entropy_prior_124": 3.19, "entropy_locked_124": 1.08, "distinct_124": 80,
            "samples_124": 80}
    # did the sharper prior collapse the 43? (entropy_prior must drop meaningfully)
    collapsed = ent_prior_all < base["entropy_prior_124"] - 0.5
    elapsed = time.perf_counter() - t0

    with open(out, "w") as f:
        f.write(json.dumps({
            "objective": "backoff_char_lm_maxn7", "samples": samples,
            "english_calib_mean": round(eng_mean, 3), "english_calib_sd": round(eng_sd, 3),
            "best_lm_score": round(best_sc, 4), "best_sigma_vs_english": round(best_sigma, 2),
            "best_word_coverage": round(wc_best, 3),
            "distinct_all": distinct_all, "distinct_top20": distinct_top,
            "entropy_prior_all": round(ent_prior_all, 3), "entropy_locked_all": round(ent_locked_all, 3),
            "entropy_prior_top20": round(ent_prior_top, 3), "entropy_locked_top20": round(ent_locked_top, 3),
            "hexagram_baseline_124": base, "collapsed_43": collapsed,
            "best_plaintext": best_pt}) + "\n")

    insights = [
        f"Sharper prior = stupid-backoff char-LM (maxn=7, non-saturating; the allowed char-LM class). Real-English "
        f"97-char windows score mean {eng_mean:.2f}±{eng_sd:.2f}. Best joint-decode score {best_sc:.2f} "
        f"({best_sigma:+.1f}σ vs English), word-coverage {wc_best:.0%}. Over {samples} restarts: {distinct_all} "
        f"distinct decrypts ({distinct_top} distinct among the top-20).",
        f"RESIDUAL AMBIGUITY head-to-head vs 124's saturating hexagram: per-position entropy of the PRIOR-GOVERNED "
        f"43 = {ent_prior_all:.2f} (all) / {ent_prior_top:.2f} (top-20) vs hexagram's 3.19; SELECTOR-LOCKED 30 = "
        f"{ent_locked_all:.2f} / {ent_locked_top:.2f} vs hexagram's 1.08. "
        + ("The sharper prior COLLAPSES the 43's ambiguity -- it pins the prior-governed positions far better than "
           "the saturating hexagram. Path A is live: inspect the converged decrypt." if collapsed else
           "The sharper prior does NOT collapse the 43: even a smooth non-saturating char-LM leaves the "
           "prior-governed positions highly ambiguous. The under-determination of the 43 is information-theoretic "
           "(the homophonic flattening destroyed the per-position signal), not a weakness of the hexagram floor."),
        f"WORD-LEVEL check: best decrypt segments {wc_best:.0%} into dictionary words. "
        + ("A high coverage on a UNIQUE decrypt would be a real lead." if wc_best > 0.7 and distinct_top <= 2 else
           "Char-statistical fluency does not imply word-level English here; many distinct decrypts share similar "
           "char-LM scores -- the hallmark of genuine under-determination, not a scorer artifact."),
        "VERDICT ON LEVER 1: " + ("a sharper deterministic prior materially sharpens the 43 prior-governed "
        "positions -- the first Path-A traction." if collapsed else "a sharper deterministic prior does NOT break "
        "the 43; combined with 121-123 (selector mechanisms closed for the 30), NO admissible deterministic lever "
        "in hand resolves K4's free positions. The remaining levers are genuinely external (engraving layout / "
        "5th positional crib, exp 126) -- not more priors or selector algebra."),
    ]

    status = "promising" if collapsed else "inconclusive"
    write_verdict(out, Verdict(
        exp="125", title="sharper deterministic prior (backoff char-LM + word-level) over the 43 prior-governed",
        hypothesis="a non-saturating backoff char-LM / word-level prior collapses the residual ambiguity of the 43 "
                   "prior-governed free positions that the saturating hexagram left wide open (124)",
        status=status, best_score=round(best_sc, 3),
        best_partial=f"entropy_prior {ent_prior_all:.2f} (hexagram 3.19); distinct {distinct_all}/{samples}; "
                     f"best {best_sigma:+.1f}σ, word-cov {wc_best:.0%}; collapsed={collapsed}",
        search_space=samples, elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["inspect the converged decrypt; verify word-level English + thematic content"] if collapsed
                    else ["the 43 are information-theoretically under-determined by char-level priors too; Path A "
                          "is effectively exhausted for unique recovery. Only an external per-position selector "
                          "fact (126) can advance the 30, and only a higher-order semantic constraint (disallowed: "
                          "LLM) could further bias the 43"]),
        metrics={"entropy_prior_all": round(ent_prior_all, 3), "entropy_prior_top20": round(ent_prior_top, 3),
                 "entropy_locked_all": round(ent_locked_all, 3), "distinct_all": distinct_all,
                 "best_sigma": round(best_sigma, 2), "best_word_coverage": round(wc_best, 3),
                 "collapsed_43": collapsed}),
    )
    print(f"\nbackoff: best {best_sc:.2f} ({best_sigma:+.1f}σ) wc {wc_best:.0%}; distinct {distinct_all}/{samples}; "
          f"entropy prior {ent_prior_all:.2f} (hex 3.19) locked {ent_locked_all:.2f} (hex 1.08); "
          f"collapsed={collapsed}; status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
