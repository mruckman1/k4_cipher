"""Path A (augmented): n-gram beam search for the K4 plaintext.

The cribs constrain 24 of 97 positions. The other 73 positions are free.
This experiment searches plaintext-space (not cipher-space) for the
most-likely English continuations consistent with the cribs.

  - Build a character-level trigram language model from K1+K2+K3
    plaintexts plus an augmented corpus (Carter/Carnarvon's "Five Years'
    Explorations at Thebes", Smith's "Tutankhamen and the Discovery of
    His Tomb", and Buchan's "The Thirty-Nine Steps" -- all Project
    Gutenberg, public domain, total ~440k letters of period-appropriate
    high-register English with topical match to K4's Berlin/Egypt themes).
  - Bigram backoff + add-k smoothing.
  - Beam search of width W=5000 over 97 positions. At each non-crib
    position, expand each beam by 26 candidate letters and prune to
    top W by cumulative log-probability. At each crib position, force
    the crib letter.

This is a DIAGNOSTIC, not an open-ended search. We are testing whether
the plaintext-space approach has traction at K4's constraint level. The
decision rule is pre-committed (see DECISION_RULE below) and applied at
the end. The result drives the next move, regardless of which way it goes.

==============================================================================
PRE-COMMITTED DECISION RULE (do not modify after running)
==============================================================================

Three criteria, each pass/fail:

  1. READABILITY: Top-1 candidate is readable English (a human reading
     it should not laugh). Subjective; report verbatim and trust the
     reviewer.

  2. PROBABILITY MASS: Top-1 to top-100 logP gap exceeds 2 nats per
     character of K4 length (= 2 * 97 = 194 nats total). The earlier
     unaugmented run had a gap of 0.83 nats total; that is "no
     preference". A real signal requires the top candidate to be
     meaningfully distinguished from the bulk.

  3. THEMATIC CONTENT: Top-1 candidate contains at least one of
     {BERLIN, WALL, EGYPT, CAIRO, PYRAMID, NORTH, EAST, WEST, TOMB,
     PHARAOH} as a substring outside the crib positions, OR the top-100
     candidates collectively cluster on Berlin- or Egypt-related
     vocabulary (>= 30% contain at least one topical keyword).

Outcomes:
  - 3 pass: PROCEED TO PATH B (modern LM, multi-day investment).
  - 2 pass: BORDERLINE -- investigate the failed criterion before deciding.
  - <2 pass: PIVOT TO PATH C (cipher-space search constrained by partial
    plaintext signal + the unfinished items: Q3 hill-climb on doubled-L
    27-letter, transposition-after-substitution, double Q3, running-key
    over Carter/Buchan/Hofstadter).

This rule is the experiment's main output, independent of whether (A)
"wins." Committing to it before running is the discipline that
distinguishes a falsification test from an investment-extension trap.

Run:
    uv run python experiments/012_plaintext_beam_search.py
"""

from __future__ import annotations

import argparse
import math
import re
import sys
import time
from collections import Counter
from pathlib import Path

from kryptos import K1_PLAINTEXT, K2_PLAINTEXT, K3_PLAINTEXT, K4
from kryptos.cribs import CRIBS
from kryptos.experiment_logger import ExperimentLogger


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
K4_LENGTH = len(K4)

CORPORA_DIR = Path(__file__).resolve().parents[1] / "data" / "corpora"
AUGMENTATION_FILES = [
    "carnarvon_carter_thebes.txt",   # Carter/Carnarvon, 1912, Egypt theme
    "smith_tutankhamen.txt",         # Smith, 1923, Tut tomb context
    "buchan_39steps.txt",            # Buchan, 1915, period spy fiction
]
CORPUS_CAP_CHARS = 500_000

THEMATIC_KEYWORDS = [
    "BERLIN", "WALL", "EGYPT", "CAIRO", "PYRAMID", "NORTH", "EAST",
    "WEST", "TOMB", "PHARAOH",
]

# Decision-rule thresholds; committed before running, do not modify after.
DECISION_LOGP_GAP_PER_CHAR = 2.0   # criterion 2
DECISION_THEMATIC_CLUSTER_FRAC = 0.30   # criterion 3 fallback


# --------------------------- LM ---------------------------------------


class CharLM:
    """Trigram char LM with bigram backoff + add-k smoothing.

    log p(c | a, b) = log [(count(abc) + k) / (count(ab) + k * 26)]
    backoff to bigram: log [(count(bc) + k) / (count(b) + k * 26)]
    backoff to unigram for start positions.

    Mixing weights lambda_tri, lambda_bi are picked to give modest
    backoff to bigram when trigram counts are very sparse (which they
    are with a 768-char corpus -- only ~764 trigrams, vs 17576 possible).
    """

    def __init__(self, corpus: str, k: float = 0.5,
                 lambda_tri: float = 0.65, lambda_bi: float = 0.30):
        if abs(lambda_tri + lambda_bi - 1.0) > 0.01 and lambda_tri + lambda_bi > 1.0:
            raise ValueError("lambda_tri + lambda_bi should be <= 1")
        self.k = k
        self.lambda_tri = lambda_tri
        self.lambda_bi = lambda_bi
        self.lambda_uni = 1.0 - lambda_tri - lambda_bi
        self.unigram_total = len(corpus)
        self.unigram = Counter(corpus)
        self.bigram = Counter(corpus[i : i + 2] for i in range(len(corpus) - 1))
        self.bigram_ctx = Counter(corpus[i] for i in range(len(corpus) - 1))
        self.trigram = Counter(corpus[i : i + 3] for i in range(len(corpus) - 2))
        self.trigram_ctx = Counter(
            corpus[i : i + 2] for i in range(len(corpus) - 2)
        )
        # Precompute log_p table for (a, b) -> 26 log probs, much faster.
        self._cache: dict[str, list[float]] = {}

    def _row_for_context(self, ab: str) -> list[float]:
        if ab in self._cache:
            return self._cache[ab]
        k = self.k
        tri_ctx = self.trigram_ctx.get(ab, 0)
        bi_ctx = self.bigram_ctx.get(ab[-1], 0) if len(ab) >= 1 else self.unigram_total
        uni_total = self.unigram_total
        row: list[float] = []
        for c in ALPHABET:
            p_tri = (self.trigram.get(ab + c, 0) + k) / (tri_ctx + k * 26)
            p_bi = (self.bigram.get(ab[-1] + c, 0) + k) / (bi_ctx + k * 26) if ab else 1 / 26
            p_uni = (self.unigram.get(c, 0) + k) / (uni_total + k * 26)
            p = (self.lambda_tri * p_tri
                 + self.lambda_bi * p_bi
                 + self.lambda_uni * p_uni)
            row.append(math.log(p))
        self._cache[ab] = row
        return row

    def score_text(self, text: str) -> tuple[float, float]:
        """Return (total_logp, per_char_logp). Position 0 is scored
        from unigram, position 1 from bigram, position 2+ from trigram."""
        if not text:
            return 0.0, 0.0
        total = 0.0
        for i, c in enumerate(text):
            if i == 0:
                p = (self.unigram.get(c, 0) + self.k) / (self.unigram_total + self.k * 26)
                total += math.log(p)
            elif i == 1:
                row = self._row_for_context(text[0])
                total += row[ALPHABET.index(c)]
            else:
                row = self._row_for_context(text[i - 2 : i])
                total += row[ALPHABET.index(c)]
        return total, total / len(text)


# --------------------------- search -----------------------------------


def crib_table() -> dict[int, str]:
    """0-indexed position -> required plaintext letter."""
    out: dict[int, str] = {}
    for c in CRIBS:
        for i, ch in enumerate(c.plaintext):
            out[c.start - 1 + i] = ch
    return out


def beam_search(
    lm: CharLM,
    cribs: dict[int, str],
    length: int = K4_LENGTH,
    beam_width: int = 5000,
) -> list[tuple[float, str]]:
    """Standard beam search, cribs as hard constraints."""
    # beam: list of (log_prob, partial_text)
    beam: list[tuple[float, str]] = [(0.0, "")]
    alphabet_idx = list(range(26))
    for pos in range(length):
        new_beam: list[tuple[float, str]] = []
        if pos in cribs:
            forced = cribs[pos]
            forced_idx = ALPHABET.index(forced)
            for lp, partial in beam:
                if pos == 0:
                    inc_lp = math.log(
                        (lm.unigram.get(forced, 0) + lm.k) / (lm.unigram_total + lm.k * 26)
                    )
                elif pos == 1:
                    inc_lp = lm._row_for_context(partial[-1])[forced_idx]
                else:
                    inc_lp = lm._row_for_context(partial[-2:])[forced_idx]
                new_beam.append((lp + inc_lp, partial + forced))
        else:
            for lp, partial in beam:
                if pos == 0:
                    row = [
                        math.log((lm.unigram.get(c, 0) + lm.k)
                                 / (lm.unigram_total + lm.k * 26))
                        for c in ALPHABET
                    ]
                elif pos == 1:
                    row = lm._row_for_context(partial[-1])
                else:
                    row = lm._row_for_context(partial[-2:])
                for idx in alphabet_idx:
                    new_beam.append((lp + row[idx], partial + ALPHABET[idx]))
        # Prune to beam_width.
        new_beam.sort(key=lambda x: -x[0])
        beam = new_beam[:beam_width]
    return beam


# --------------------------- main -------------------------------------


_NON_LETTER = re.compile(r"[^A-Za-z]")


def strip_pg_and_clean(path: Path) -> str:
    text = path.read_text(errors="ignore")
    m_start = re.search(r"\*\*\*\s*START OF (?:THE|THIS) PROJECT GUTENBERG EBOOK[^*]*\*\*\*", text)
    m_end = re.search(r"\*\*\*\s*END OF (?:THE|THIS) PROJECT GUTENBERG EBOOK[^*]*\*\*\*", text)
    if m_start:
        text = text[m_start.end():]
    if m_end:
        text = text[:m_end.start()]
    return _NON_LETTER.sub("", text).upper()


def build_augmented_corpus() -> tuple[str, dict[str, int]]:
    """Concatenate K1+K2+K3 plaintexts with the augmentation files,
    capped at CORPUS_CAP_CHARS. Returns (full_corpus, sizes_dict)."""
    parts: list[str] = [K1_PLAINTEXT + K2_PLAINTEXT + K3_PLAINTEXT]
    sizes = {"K1+K2+K3": len(parts[0])}
    total = len(parts[0])
    for fname in AUGMENTATION_FILES:
        p = CORPORA_DIR / fname
        if not p.exists():
            print(f"  WARNING: {p} missing; run with original-corpus-only mode.")
            sizes[fname] = 0
            continue
        cleaned = strip_pg_and_clean(p)
        remaining = CORPUS_CAP_CHARS - total
        if remaining <= 0:
            sizes[fname] = 0
            continue
        chunk = cleaned[:remaining]
        parts.append(chunk)
        sizes[fname] = len(chunk)
        total += len(chunk)
    return "".join(parts), sizes


def main(beam_width: int = 5000, top_k: int = 25,
         use_augmented: bool = True) -> int:
    if use_augmented:
        corpus, sizes = build_augmented_corpus()
        print(f"AUGMENTED corpus:  {len(corpus):,} chars (cap = {CORPUS_CAP_CHARS:,})")
        for src, n in sizes.items():
            print(f"   {src:32s} {n:>10,} chars")
    else:
        corpus = K1_PLAINTEXT + K2_PLAINTEXT + K3_PLAINTEXT
        print(f"BASELINE corpus:  {len(corpus):,} chars (K1+K2+K3 plaintexts only)")
    lm = CharLM(corpus, k=0.5, lambda_tri=0.65, lambda_bi=0.30)
    print(f"unique unigrams:  {len(lm.unigram)} of 26")
    print(f"unique bigrams:   {len(lm.bigram)} of 676")
    print(f"unique trigrams:  {len(lm.trigram)} of 17576")
    print()

    # Baselines: how does the LM score known plaintexts vs noise?
    print("=== baselines (per-char log-prob under the K1+K2+K3 trigram LM) ===")
    for name, t in [("K1 plaintext", K1_PLAINTEXT),
                     ("K2 plaintext", K2_PLAINTEXT),
                     ("K3 plaintext", K3_PLAINTEXT)]:
        total, per_char = lm.score_text(t)
        print(f"  {name:18s} per_char_logp = {per_char:.4f}")
    # K1 etc are in the training corpus, so these are upper bounds.
    # Add a leave-one-out style score: K1 against an LM trained on K2+K3 only.
    lm_loo = CharLM(K2_PLAINTEXT + K3_PLAINTEXT, k=0.5, lambda_tri=0.65, lambda_bi=0.30)
    _, k1_loo = lm_loo.score_text(K1_PLAINTEXT)
    print(f"  K1 (LOO: trained on K2+K3 only)  per_char_logp = {k1_loo:.4f}")
    # Random A-Z baseline.
    import random
    rng = random.Random(0)
    rand_scores = []
    for _ in range(20):
        t = "".join(rng.choice(ALPHABET) for _ in range(K4_LENGTH))
        _, pc = lm.score_text(t)
        rand_scores.append(pc)
    print(f"  random A-Z (97 chars, n=20)      per_char_logp = "
          f"{sum(rand_scores) / len(rand_scores):.4f} +/- "
          f"{(sum((x - sum(rand_scores) / len(rand_scores)) ** 2 for x in rand_scores) / len(rand_scores)) ** 0.5:.4f}")
    print()

    cribs = crib_table()
    print(f"crib constraints: {sorted(cribs.keys())[:6]}... ({len(cribs)} positions)")
    print(f"beam width:       {beam_width}")
    print(f"search length:    {K4_LENGTH}")
    print()

    print("running beam search ...")
    t0 = time.perf_counter()
    beam = beam_search(lm, cribs, length=K4_LENGTH, beam_width=beam_width)
    dt = time.perf_counter() - t0
    print(f"  done in {dt:.1f}s. Final beam size: {len(beam)}")
    print()

    # Reporting.
    with ExperimentLogger("012_plaintext_beam_search") as log:
        log.write({"beam_width": beam_width, "corpus_size": len(corpus),
                   "k4_length": K4_LENGTH, "elapsed_s": dt})

        print(f"=== top {top_k} candidates by per-char log-prob ===")
        for rank, (lp, cand) in enumerate(beam[:top_k], 1):
            per_char = lp / K4_LENGTH
            print(f"  #{rank:>2}  logP={lp:>8.2f}  perChar={per_char:>7.4f}  {cand}")
            log.write({"rank": rank, "logP": lp, "perChar": per_char,
                       "candidate": cand})

        # Probability mass concentration.
        print()
        print("=== probability mass concentration ===")
        gap_1_100 = beam[0][0] - beam[99][0] if len(beam) >= 100 else 0.0
        gap_per_char = gap_1_100 / K4_LENGTH
        print(f"  top-1   log_p:                  {beam[0][0]:.2f}")
        print(f"  top-5   mean log_p:             {sum(x[0] for x in beam[:5]) / 5:.2f}")
        print(f"  top-100 mean log_p:             {sum(x[0] for x in beam[:100]) / 100:.2f}")
        print(f"  top-1 -- top-100 gap (total):   {gap_1_100:.2f}")
        print(f"  top-1 -- top-100 gap per char:  {gap_per_char:.4f}")
        top_per_char = beam[0][0] / K4_LENGTH
        print(f"  top-1 per_char_logp:            {top_per_char:.4f}")
        print(f"  K1 leave-one-out per_char_logp: {k1_loo:.4f}")
        print(f"  gap (top-1 -- K1-LOO):          {top_per_char - k1_loo:+.4f}")
        log.write({
            "section": "concentration",
            "top1_logp": beam[0][0],
            "top1_per_char": top_per_char,
            "top100_mean_logp": sum(x[0] for x in beam[:100]) / 100,
            "gap_1_100_total": gap_1_100,
            "gap_1_100_per_char": gap_per_char,
            "k1_loo_per_char": k1_loo,
        })

        # ----- PRE-COMMITTED DECISION RULE -----
        print()
        print("=" * 70)
        print("PRE-COMMITTED DECISION RULE")
        print("=" * 70)
        top1 = beam[0][1]

        # crib position mask so we ignore cribs when checking topical content
        crib_positions = set(cribs.keys())

        def strip_crib_positions(text: str) -> str:
            return "".join(c for i, c in enumerate(text) if i not in crib_positions)

        top1_outside_cribs = strip_crib_positions(top1)

        # Criterion 1: subjective; print verbatim and trust the reviewer.
        print()
        print("CRITERION 1 (readability) - subjective; verbatim top-1:")
        print(f"  {top1}")
        print(f"  (75-char tail: ...{top1[-75:]})")

        # Criterion 2: probability-mass gap.
        crit2_pass = gap_per_char > DECISION_LOGP_GAP_PER_CHAR
        print()
        print(f"CRITERION 2 (probability mass): gap_per_char = {gap_per_char:.4f}; "
              f"threshold = {DECISION_LOGP_GAP_PER_CHAR}")
        print(f"  --> {'PASS' if crit2_pass else 'FAIL'}")

        # Criterion 3: thematic content.
        top1_hits = [w for w in THEMATIC_KEYWORDS if w in top1_outside_cribs]
        top100_with_kw = 0
        for _, cand in beam[:100]:
            cand_no_cribs = strip_crib_positions(cand)
            if any(w in cand_no_cribs for w in THEMATIC_KEYWORDS):
                top100_with_kw += 1
        thematic_frac = top100_with_kw / 100
        crit3_pass = (len(top1_hits) > 0) or (thematic_frac >= DECISION_THEMATIC_CLUSTER_FRAC)
        print()
        print(f"CRITERION 3 (thematic content):")
        print(f"  top-1 keyword hits (outside cribs): {top1_hits or 'NONE'}")
        print(f"  fraction of top-100 with any thematic kw: {thematic_frac:.2f}  "
              f"(threshold {DECISION_THEMATIC_CLUSTER_FRAC})")
        print(f"  --> {'PASS' if crit3_pass else 'FAIL'}")

        # Outcome.
        print()
        print("CRITERION 1 (readability) is subjective. Quoting top-1 and top-5")
        print("verbatim above; reviewer assesses pass/fail.")
        c2 = "PASS" if crit2_pass else "FAIL"
        c3 = "PASS" if crit3_pass else "FAIL"
        print()
        print(f"OBJECTIVE OUTCOME: criterion 2 {c2}, criterion 3 {c3}")
        if crit2_pass and crit3_pass:
            print("  --> If reviewer judges criterion 1 PASS: PROCEED TO PATH B.")
            print("  --> If reviewer judges criterion 1 FAIL: BORDERLINE.")
        elif crit2_pass or crit3_pass:
            print("  --> BORDERLINE (one objective criterion passes).")
        else:
            print("  --> PIVOT TO PATH C. Plaintext-space search lacks traction.")

        log.write({
            "section": "decision_rule",
            "top1": top1,
            "top1_keyword_hits": top1_hits,
            "thematic_frac_top100": thematic_frac,
            "criterion_2_pass": crit2_pass,
            "criterion_3_pass": crit3_pass,
            "gap_per_char": gap_per_char,
        })

    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--beam-width", type=int, default=5000)
    ap.add_argument("--top-k", type=int, default=25)
    ap.add_argument("--baseline", action="store_true",
                    help="use K1+K2+K3 only (no Carter/Buchan augmentation)")
    args = ap.parse_args()
    sys.exit(main(args.beam_width, args.top_k, use_augmented=not args.baseline))
