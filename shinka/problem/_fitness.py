"""Frozen scoring infrastructure for the K4 evolution.

This module is intentionally separate from ``initial.py`` because
shinka_adapter's AST safety check is applied to the candidate file
(initial.py) and forbids ``import time``, ``pathlib``, and submodule
imports of kryptos. The scoring code legitimately needs those, so it
lives here. ``initial.py`` imports a single ``score_plaintext`` entry
function from this module; the AST gate sees only the safe import line.

The LLM mutates ``decrypt_k4`` in ``initial.py``. Nothing here is
mutated -- this is the immutable scorer.
"""

from __future__ import annotations

import ast
import inspect
import time
from pathlib import Path
from typing import Any, Callable

from kryptos.cribs import CRIBS
from kryptos.scoring.crib_check import surviving_positions
from kryptos.scoring.ngram_fitness import NgramFitness, build_from_corpus, load_ngrams


_NGRAM_CACHE: NgramFitness | None = None


def _get_ngrams() -> NgramFitness:
    """Load the n-gram fitness table. Uses a pickle cache at /tmp to avoid
    re-parsing the 31 MB hexagram file on every subprocess startup; shinka
    spawns one subprocess per eval, so parsing-on-load adds ~1.5 s/gen
    overhead without the cache. Pickle is invalidated by mtime check."""
    import os
    import pickle

    global _NGRAM_CACHE
    if _NGRAM_CACHE is not None:
        return _NGRAM_CACHE

    ngram_dir = Path(__file__).resolve().parents[2] / "data" / "ngrams"
    for n, fname in [(6, "english_hexagrams.txt"), (4, "english_quadgrams.txt")]:
        path = ngram_dir / fname
        if not path.exists():
            continue

        cache_path = Path(f"/tmp/k4_ngram_cache_{fname}.pkl")
        try:
            if cache_path.exists() and cache_path.stat().st_mtime >= path.stat().st_mtime:
                with open(cache_path, "rb") as fh:
                    _NGRAM_CACHE = pickle.load(fh)
                if isinstance(_NGRAM_CACHE, NgramFitness) and _NGRAM_CACHE.n == n:
                    return _NGRAM_CACHE
                _NGRAM_CACHE = None  # corrupt / wrong n -- fall through and rebuild
        except (pickle.UnpicklingError, EOFError, AttributeError):
            _NGRAM_CACHE = None  # stale pickle from old NgramFitness layout

        _NGRAM_CACHE = load_ngrams(path, n)
        try:
            with open(cache_path, "wb") as fh:
                pickle.dump(_NGRAM_CACHE, fh, protocol=pickle.HIGHEST_PROTOCOL)
            os.chmod(cache_path, 0o644)
        except OSError:
            pass  # /tmp not writable; degrade to re-parse each subprocess
        return _NGRAM_CACHE

    from kryptos.constants import K1_PLAINTEXT, K2_PLAINTEXT, K3_PLAINTEXT
    corpus = K1_PLAINTEXT + K2_PLAINTEXT + K3_PLAINTEXT
    _NGRAM_CACHE = build_from_corpus(corpus, n=4)
    return _NGRAM_CACHE


# N1 thematic prior: keywords that appeared in >= 5% of the 72 candidates
# produced by 12 independent LM subagents. See
# experiments/results/n1_subagent_outputs/cluster_n1.py and
# data/k4_plaintext_themes.yaml. Cross-subagent convergence:
#   navigation     12/12 (100%)
#   first_person   12/12 (100%)
#   berlin_wall    11/12 (92%)
#   k2_k3_echo      9/12 (75%)
#   egypt           8/12 (67%)
#   k5_forward      8/12 (67%)
_N1_THEMATIC_KEYWORDS = [
    "WALL", "GATE", "CROWD", "ALEXANDERPLATZ", "ALEXANDER", "PLATZ",
    "BORNHOLMER", "WELTZEITUHR", "URANIA", "WEST", "CROSSING",
    "BRANDENBURG", "NOVEMBER", "FELL", "STRIKES",
    "DEGREES", "MINUTES", "NORTH", "FIFTYTWO", "THIRTEEN", "THIRTYTHREE",
    "TOWARD",
    "LAYER", "BURIED", "PLINTH", "LASTMESSAGE", "BREACH", "MIST",
    "EGYPT", "CAIRO", "KARNAK", "DESERT", "STONE", "PYRAMID", "TOMB",
]
_N1_BONUS_CAP = 5.0


def _thematic_bonus(plaintext: str) -> tuple[float, list[str]]:
    matched = [kw for kw in _N1_THEMATIC_KEYWORDS if kw in plaintext]
    raw = 0.5 * len(matched)
    return min(raw, _N1_BONUS_CAP), matched


# --------------------------------------------------------------------------
# Richer fitness signals — IoC and bigram chi-squared.
#
# Hexagrams reward local 6-char patterns and are easily saturated. Adding
# IoC and bigram chi-squared captures GLOBAL letter-frequency profile and
# LETTER-PAIR distribution, which a candidate has to also get right to
# beat the plateau. Empirical observation (k4_full_v2 + resume): 5+
# distinct patches all topped out at -132.42, suggesting the hexagram
# signal alone is saturating before the cipher is actually right.

# Standard English bigram frequencies (per 1000 bigrams, from Norvig 2013
# Mayzner analysis). Used in chi-squared to penalize candidates whose
# letter-pair distribution diverges from English.
_ENGLISH_BIGRAM_FREQ = {
    "TH": 35.36, "HE": 30.74, "IN": 24.30, "ER": 21.79, "AN": 21.41,
    "RE": 17.84, "ON": 17.62, "AT": 14.93, "EN": 14.55, "ND": 13.51,
    "TI": 13.36, "ES": 13.16, "OR": 12.81, "TE": 12.05, "OF": 11.79,
    "ED": 11.69, "IS": 11.28, "IT": 11.21, "AL": 10.92, "AR": 10.75,
    "ST": 10.55, "TO": 10.47, "NT": 10.41, "NG":  9.55, "SE":  9.32,
    "HA":  9.26, "AS":  8.71, "OU":  8.71, "IO":  8.30, "LE":  8.27,
    "VE":  8.25, "CO":  7.94, "ME":  7.93, "DE":  7.65, "HI":  7.63,
    "RI":  7.28, "RO":  7.27, "IC":  6.99, "NE":  6.92, "EA":  6.88,
    "RA":  6.86, "CE":  6.51, "LI":  6.23, "CH":  5.98, "LL":  5.79,
    "BE":  5.78, "MA":  5.65, "SI":  5.55, "OM":  5.54, "UR":  5.42,
}
# Normalize to probabilities (sum the top-50 freqs above, divide each by total).
_TOTAL_BIGRAM_FREQ = sum(_ENGLISH_BIGRAM_FREQ.values())
_ENGLISH_BIGRAM_PROB = {b: f / _TOTAL_BIGRAM_FREQ for b, f in _ENGLISH_BIGRAM_FREQ.items()}


def index_of_coincidence(text: str) -> float:
    """IoC = sum_i n_i*(n_i-1) / (N*(N-1)), where n_i is count of letter i.
    English ~ 0.0667; uniform random over 26 letters ~ 0.0385.
    """
    if len(text) < 2:
        return 0.0
    n = len(text)
    counts: dict[str, int] = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    s = sum(f * (f - 1) for f in counts.values())
    return s / (n * (n - 1))


def bigram_chi_squared(text: str) -> float:
    """Chi-squared between observed top-50 bigram fraction and English ref.
    Returns 0 for perfect English-like distribution; large positive for
    divergence. Only counts bigrams that appear in the English reference
    so the metric isn't dominated by rare-bigram noise.
    """
    if len(text) < 2:
        return 0.0
    observed: dict[str, int] = {}
    n_bigrams_in_ref = 0
    for i in range(len(text) - 1):
        bg = text[i : i + 2]
        if bg in _ENGLISH_BIGRAM_PROB:
            observed[bg] = observed.get(bg, 0) + 1
            n_bigrams_in_ref += 1
    if n_bigrams_in_ref == 0:
        return 1000.0  # no reference-bigrams at all -> deeply non-English
    chi2 = 0.0
    for bg, p in _ENGLISH_BIGRAM_PROB.items():
        expected = p * n_bigrams_in_ref
        obs = observed.get(bg, 0)
        chi2 += (obs - expected) ** 2 / expected
    return chi2


def _global_english_signals(plaintext: str) -> tuple[float, float, float]:
    """Compute IoC bonus + bigram-chi-squared penalty terms for the
    composite fitness. Returns (ioc, ioc_bonus, bigram_chi2_penalty).

    IoC bonus is shaped so it peaks (+5 pts) inside the English IoC band
    [0.060, 0.072], degrades linearly outside. Bigram chi-squared
    penalty is -chi2/30 (typical English text: chi2 ~ 30-80; gibberish:
    chi2 ~ 500-2000). Both terms are small relative to cribs (100) but
    large enough to differentiate within the hexagram plateau.
    """
    ioc = index_of_coincidence(plaintext)
    if 0.060 <= ioc <= 0.072:
        ioc_bonus = 5.0
    else:
        ioc_bonus = max(-5.0, 5.0 - 100.0 * abs(ioc - 0.066))
    chi2 = bigram_chi_squared(plaintext)
    chi2_penalty = -min(chi2 / 30.0, 50.0)  # cap penalty at -50
    return ioc, ioc_bonus, chi2_penalty


# --------------------------------------------------------------------------
# Per-partition bigram fitness (Prior A: per-position-alphabet selection)
#
# Under Prior A's k=4 rule, the LLM mutates 4 alphabets. Hexagrams scored
# on the full 73-char free string are too coarse — at length 73 the
# hexagram signal is noisy and a swap on one alphabet only directly
# affects ~18 plaintext positions. We need a per-color signal so the
# search has gradient on each alphabet independently.
#
# For each color, compute the bigram chi-squared of the plaintext
# positions assigned to that color. A color whose alphabet is closer
# to "correct" will produce more English-like bigrams in its slice.
# Sum across colors with a small scale (~+15 swing).

def _prior_a_color_at_position(ciphertext: str, i: int) -> int:
    """Recompute Prior A's rule color at position i. Kept in sync with
    initial.py's rule. If decrypt_k4 changes the rule, this needs to
    change too. Cheap: just (2 × pos_mod_3 + cumulative_consonant_count) mod 4."""
    vowels = "AEIOU"
    cnt = 0
    for j in range(i + 1):
        if ciphertext[j] not in vowels:
            cnt += 1
    return (2 * (i % 3) + cnt) % 4


def per_partition_bigram_score(plaintext: str, ciphertext: str = None) -> float:
    """Per-partition bigram score under Prior A's rule.

    For each color c, extract plaintext positions where rule(i) == c.
    Compute bigram chi-squared of that partition. Convert to a small
    positive bonus for English-likeness vs random.

    Returns a sum of per-color z-scores (positive = better than random
    on average across partitions). Capped at ±15.
    """
    if ciphertext is None:
        from kryptos.constants import K4
        ciphertext = K4
    n = len(plaintext)
    # Group positions by color
    colors_at = [_prior_a_color_at_position(ciphertext, i) for i in range(n)]
    k = max(colors_at) + 1
    partitions: list[str] = []
    for c in range(k):
        partitions.append("".join(plaintext[i] for i in range(n) if colors_at[i] == c))

    # For each partition, score by bigram chi-squared. Lower chi-sq
    # = more English-like. Random baseline at length L ≈ L (each
    # bigram contributes O(1) under expected uniform distribution).
    # We compute a z-score against random: how many SD below random?
    total_z = 0.0
    for p in partitions:
        if len(p) < 3:
            continue
        chi = bigram_chi_squared(p)
        # Expected random chi for a uniform string of length L ≈ L (rough)
        # SD ≈ sqrt(2L) (chi-sq variance approximation)
        expected = max(len(p) - 1, 1)
        sd = max((2 * expected) ** 0.5, 1.0)
        z = (chi - expected) / sd
        total_z += -z  # negative chi = positive English signal
    # Cap at ±15 to keep this term in the same scale as ioc_bonus/n1_bonus
    return max(-15.0, min(15.0, total_z))


def _fitness(plaintext: str) -> tuple[float, dict[str, Any]]:
    # Structural filter: K4 position 74 (0-indexed 73) is the final K of
    # CLOCK and the ciphertext at that position is also K -- the documented
    # self-encryption constraint. Pure-Beaufort and certain
    # non-self-encrypting cipher configurations cannot produce K->K here
    # by construction. Hard-reject candidates that don't match: send them
    # to -300 (well below the gibberish floor of ~-150 with IoC+bigram
    # penalties), so the optimizer always prefers a K-at-74 candidate
    # over a non-K one regardless of other crib hits.
    if plaintext[73] != "K":
        crib_positions = 0
        for c in CRIBS:
            for offset, expected in enumerate(c.plaintext):
                if plaintext[c.start - 1 + offset] == expected:
                    crib_positions += 1
        return -300.0, {
            "cribs_satisfied": 0,
            "crib_positions_hit": crib_positions,
            "crib_positions_total": sum(len(c.plaintext) for c in CRIBS),
            "crib_frac": crib_positions / sum(len(c.plaintext) for c in CRIBS),
            "hexagram_per_char": 0.0,
            "ioc": 0.0,
            "ioc_bonus": 0.0,
            "bigram_chi2_penalty": 0.0,
            "n1_thematic_bonus": 0.0,
            "n1_thematic_keywords_matched": [],
            "candidate_plaintext": plaintext,
            "rejected_by_pos74_filter": True,
        }

    crib_positions = 0
    for c in CRIBS:
        for offset, expected in enumerate(c.plaintext):
            if plaintext[c.start - 1 + offset] == expected:
                crib_positions += 1
    crib_total = sum(len(c.plaintext) for c in CRIBS)
    crib_frac = crib_positions / crib_total

    free_idx = surviving_positions(plaintext_length=len(plaintext), cribs=CRIBS)
    free_text = "".join(plaintext[i] for i in free_idx)
    hex_per_char = _get_ngrams()(free_text)

    n1_bonus, n1_matched = _thematic_bonus(plaintext)
    ioc, ioc_bonus, bigram_penalty = _global_english_signals(plaintext)

    # Per-partition bigram score (Prior A specific). Provides early signal
    # at the per-alphabet level even when global hexagram is still weak.
    try:
        per_partition_z = per_partition_bigram_score(plaintext)
    except Exception:
        per_partition_z = 0.0

    # Composite scoring (Run C revision after Run B v2 revealed K=6
    # gaming the per_partition term — its 15× weight let smaller
    # partitions inflate score without real English gain):
    #   cribs            × 100  (always dominant, structurally anchored)
    #   hexagrams        ×  30  (the actual English-likeness signal)
    #   per-partition    ×   5  (downweighted from 15, since the metric
    #                            uses Prior A's K=4 rule for partitioning
    #                            regardless of candidate's K; can't be
    #                            trusted as a primary signal across K
    #                            values, but kept as a weak tie-breaker)
    #   n1 thematic      ×  10
    #   ioc + bigram     unchanged
    composite = (
        100.0 * crib_frac
        + 30.0 * (hex_per_char + 9.0) / 10.0
        + 5.0 * per_partition_z / 10.0        # downweighted ×15 → ×5
        + 10.0 * n1_bonus / 5.0
        + ioc_bonus
        + bigram_penalty
    )

    return composite, {
        "cribs_satisfied": sum(1 for c in CRIBS if plaintext[c.slice0] == c.plaintext),
        "crib_positions_hit": crib_positions,
        "crib_positions_total": crib_total,
        "crib_frac": crib_frac,
        "hexagram_per_char": hex_per_char,
        "per_partition_bigram_z": per_partition_z,
        "ioc": ioc,
        "ioc_bonus": ioc_bonus,
        "bigram_chi2_penalty": bigram_penalty,
        "n1_thematic_bonus": n1_bonus,
        "n1_thematic_keywords_matched": n1_matched,
        "candidate_plaintext": plaintext,
        "rejected_by_pos74_filter": False,
    }


def score_plaintext(plaintext: Any, *, t0: float | None = None) -> dict[str, Any]:
    """Validate the candidate plaintext and return the EvalResult dict.

    Used by ``initial.py``'s ``run_experiment``. Kept here (not in the
    AST-checked candidate file) so it can use ``time`` and ``pathlib``.
    """
    elapsed = (time.monotonic() - t0) if t0 is not None else 0.0

    if not isinstance(plaintext, str):
        return {
            "score": float("-inf"),
            "solved": True,
            "runtime_s": elapsed,
            "error_tail": f"decrypt_k4 returned {type(plaintext).__name__}, expected str",
        }
    if len(plaintext) != 97:
        return {
            "score": float("-inf"),
            "solved": True,
            "runtime_s": elapsed,
            "error_tail": f"decrypt_k4 returned len={len(plaintext)}, expected 97",
        }
    if not plaintext.isupper() or not plaintext.isalpha():
        return {
            "score": float("-inf"),
            "solved": True,
            "runtime_s": elapsed,
            "error_tail": "decrypt_k4 must return uppercase A-Z only",
        }

    score, meta = _fitness(plaintext)
    # NOTE on `solved`: this is NOT "I cracked K4." shinka_adapter's
    # aggregator (metrics.py::effective_score) discards the reported
    # `score` and substitutes a PAR-2 timeout penalty (-2 * timeout_s)
    # whenever solved=False, collapsing all unsolved candidates onto a
    # single floor and killing the ranking signal. For continuous-score
    # tasks like ours, `solved=True` means "the eval ran to completion
    # and produced a valid 97-char string"; the actual fitness comes
    # from `score`. The true "is K4 cracked?" check lives in
    # meta["full_solution"] for downstream inspection.
    return {
        "score": float(score),
        "solved": True,
        "runtime_s": elapsed,
        "metadata": {
            **meta,
            "full_solution": (
                meta["cribs_satisfied"] == 4
                and meta["hexagram_per_char"] >= -7.5
            ),
        },
    }


def now() -> float:
    """Wall-clock helper. Kept here so the AST-checked candidate file does
    not need ``import time``."""
    return time.monotonic()


# --------------------------------------------------------------------------
# Reward-hack guards.
#
# Failure mode 1: hardcoded plaintext that ignores `ciphertext`. Caught by
# the differential-input check in initial.run_experiment.
#
# Failure mode 2: hardcoded crib strings stitched into a real cipher's
# output. The cipher genuinely runs (differential passes) but the crib
# windows are overwritten with literal "EAST"/"NORTHEAST"/"BERLIN"/"CLOCK".
# Caught here by source scan: if the EVOLVE block source contains all four
# crib literals OR contains the suspicious adjacent pair "EAST"+"NORTHEAST"
# (the rare combo a stitcher needs), reject with -inf.
#
# Failure mode 3: branchy lookup table or position-mapper that produces
# cribs at the right positions for K4 input AND for the reversed sentinel.
# Caught here by `count_crib_letters_in_sentinel`: if a candidate's output
# on REVERSED-K4 also satisfies cribs at the K4 positions, the cribs are
# coming from code structure, not the cipher.

_CRIB_WORDS = ("EAST", "NORTHEAST", "BERLIN", "CLOCK")


def find_crib_literal_cheat(decrypt_fn: Callable[..., Any]) -> str | None:
    """Return an error message if the function source contains a tell-tale
    hardcoded-crib-stitching pattern, else None.

    Pattern A: all four crib literals appear in the source (legitimate
    cipher candidates almost never need all four crib words as constants).
    Pattern B: "EAST" and "NORTHEAST" appear together (only crib-stitchers
    need both adjacent crib words; a real cipher might use BERLIN as a
    key but won't also use NORTHEAST).

    Docstrings are stripped before scanning so the seed and LLM-generated
    candidates can mention the crib words in their docstrings (e.g. "do
    not stitch EAST / NORTHEAST / BERLIN / CLOCK") without triggering
    the heuristic. Comments are removed by ast.parse automatically.
    """
    try:
        source = inspect.getsource(decrypt_fn)
    except (OSError, TypeError):
        return None

    try:
        tree = ast.parse(source.lstrip())
    except SyntaxError:
        return None

    # Collect string constants from code positions, excluding docstrings.
    # ast.get_docstring returns the cleaned text; matching it back to the
    # raw source is fragile. Instead, identify docstring nodes by AST
    # position (first Expr->Constant(str) inside a body) and skip those.
    docstring_node_ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)
        ):
            body = getattr(node, "body", None) or []
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                docstring_node_ids.add(id(body[0].value))

    code_strings: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docstring_node_ids
        ):
            code_strings.append(node.value)

    haystack = " ".join(code_strings)
    found = [w for w in _CRIB_WORDS if w in haystack]
    if len(found) >= 4:
        return (
            "decrypt_k4 contains all four crib literals "
            f"({', '.join(found)}) as code string constants; rejecting as "
            "crib-stitching reward-hack. Cipher candidates should reach "
            "the cribs via decryption, not by embedding the answer in code."
        )
    if "EAST" in haystack and "NORTHEAST" in haystack:
        return (
            "decrypt_k4 uses both 'EAST' and 'NORTHEAST' as code string "
            "constants; rejecting as crib-stitching reward-hack."
        )
    return None


def count_crib_letter_hits(plaintext: str) -> int:
    """How many of the 24 crib positions does `plaintext` satisfy?

    Random expectation for random-uniform text is 24 / 26 ~ 0.92 hits.
    Used by run_experiment to compare K4-output vs. sentinel-output:
    if the sentinel hits more cribs than chance, the cribs are coming
    from code structure rather than from the cipher.
    """
    hits = 0
    for c in CRIBS:
        for offset, expected in enumerate(c.plaintext):
            i = c.start - 1 + offset
            if 0 <= i < len(plaintext) and plaintext[i] == expected:
                hits += 1
    return hits


# --------------------------------------------------------------------------
# Stronger reward-hack guards (added after the 2026-05-23_13-40-03 run, where
# the LLM operating blind converged on hardcoding plaintext via chr() and
# concat tricks to bypass find_crib_literal_cheat, plus explicit
# `if ciphertext.startswith("OBKR")` branching to bypass the single-sentinel
# test). Three layers, in order from cheapest to most decisive:
#
#   1. find_crib_construction_cheat — AST scan for chr(crib-ascii) and
#      single-char crib-letter Constants. Catches the obfuscated literals.
#
#   2. multi_sentinel_check — runs decrypt_k4 against 4 inputs that all
#      break K4's startswith/substring signature. Hardcoded-with-branching
#      candidates fail because their fallback path doesn't reproduce the
#      cribs.
#
#   3. differential_input_check — perturbs 5 non-crib ciphertext positions
#      and verifies the plaintext changes. A hardcoded decrypt_k4 (no
#      branching) produces identical plaintext under any input. This is
#      the decisive check: it cannot be bypassed without actually
#      implementing the cipher.

# 13 unique crib letters across EAST/NORTHEAST/BERLIN/CLOCK
_CRIB_LETTER_SET: frozenset[str] = frozenset("".join(c.plaintext for c in CRIBS))
_CRIB_LETTER_ASCII: frozenset[int] = frozenset(ord(c) for c in _CRIB_LETTER_SET)
# Threshold chosen so the seed (which has 6 crib letters appearing in
# CONSTRAINTS_BY_COLOR: T,R,N,L,S,K) does not trip, but any candidate that
# adds 4+ more crib letters via chr() or single-char string constants does.
_CRIB_CONSTRUCTION_THRESHOLD = 10


def find_crib_construction_cheat(decrypt_fn: Callable[..., Any]) -> str | None:
    """AST-level detector for obfuscated crib-letter construction.

    `find_crib_literal_cheat` catches the words EAST/NORTHEAST/BERLIN/CLOCK
    as `ast.Constant(str)` nodes. LLMs evade it by building the letters
    through `chr(69)+chr(65)+chr(83)+chr(84)` (Call nodes, not Constants)
    or `"E"+"A"+"S"+"T"` (each single letter is its own short Constant,
    never concatenated in the AST). This function counts how many of the
    13 distinct crib letters appear as either:

      (a) single-character `ast.Constant(str)` values in code positions
          (excluding docstrings), or
      (b) `chr(N)` calls where N is the ASCII code of a crib letter.

    If the union covers ≥ 10 of 13 crib letters, the candidate is almost
    certainly stitching cribs from primitives and is rejected.
    """
    try:
        source = inspect.getsource(decrypt_fn)
    except (OSError, TypeError):
        return None

    try:
        tree = ast.parse(source.lstrip())
    except SyntaxError:
        return None

    docstring_node_ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)
        ):
            body = getattr(node, "body", None) or []
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                docstring_node_ids.add(id(body[0].value))

    crib_letters_seen: set[str] = set()

    for node in ast.walk(tree):
        # (a) Single-character string Constants (not docstrings)
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docstring_node_ids
            and len(node.value) == 1
            and node.value in _CRIB_LETTER_SET
        ):
            crib_letters_seen.add(node.value)
            continue

        # (b) chr(N) calls with crib-ASCII arguments
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "chr"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, int)
            and node.args[0].value in _CRIB_LETTER_ASCII
        ):
            crib_letters_seen.add(chr(node.args[0].value))

    if len(crib_letters_seen) >= _CRIB_CONSTRUCTION_THRESHOLD:
        letters = "".join(sorted(crib_letters_seen))
        return (
            f"decrypt_k4 references {len(crib_letters_seen)}/{len(_CRIB_LETTER_SET)} "
            f"crib letters ({letters}) via single-char string constants or "
            "chr() calls. This pattern is characteristic of crib-stitching "
            "reward-hacks that bypass the literal-string detector by "
            "constructing crib words from primitives. Rejecting."
        )
    return None


# Deterministic seed for sentinel/perturbation choice. Fixed so the same
# decrypt_k4 sees the same tests across re-evaluations, but unrelated to
# anything the LLM can predict the consequences of (since passing the
# tests requires actually implementing the cipher, not predicting indices).
_ROBUSTNESS_RNG_SEED = 0xC4FACE
_DIFFERENTIAL_N_PERTURB = 5
_DIFFERENTIAL_MIN_CHANGES = 2
_NON_K4_SENTINEL_CRIB_HITS_THRESHOLD = 6


def _crib_positions_set() -> set[int]:
    out: set[int] = set()
    for c in CRIBS:
        for offset in range(len(c.plaintext)):
            out.add(c.start - 1 + offset)
    return out


def build_non_k4_sentinels(ciphertext: str) -> list[tuple[str, str]]:
    """Build inputs that all break K4's signature (startswith / substring),
    so candidates branching on `ciphertext.startswith("OBKR")` are exposed.

    Returns list of (label, modified_ciphertext) pairs.
    """
    import random as _random

    rng = _random.Random(_ROBUSTNESS_RNG_SEED)
    n = len(ciphertext)
    if n < 4:
        return []

    # 1. First and last chars swapped — breaks startswith("OBKR")
    first_last_swap = ciphertext[-1] + ciphertext[1:-1] + ciphertext[0]

    # 2. Left-rotate by 5 — moves OBKR out of the prefix
    rot5 = ciphertext[5:] + ciphertext[:5]

    # 3. Replace the first 4 chars with random letters — breaks startswith
    #    and removes the OBKRUOXOGH substring from its expected location
    rand_prefix = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(4))
    new_prefix = rand_prefix + ciphertext[4:]

    # 4. Fully random 97-char string — no signature whatsoever
    random_text = "".join(
        rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(n)
    )

    return [
        ("first_last_swap", first_last_swap),
        ("rotated_by_5", rot5),
        ("random_prefix", new_prefix),
        ("fully_random", random_text),
    ]


def multi_sentinel_check(decrypt_fn: Callable[..., Any], ciphertext: str) -> str | None:
    """Run decrypt_k4 against 4 non-K4 inputs. A hardcoded cipher produces
    cribs on EVERY sentinel (since it ignores input). A real cipher
    produces noise on at least one — and probably all — sentinels.

    Subtlety: per-position substitution with cumulative-state features
    (e.g. consonant_count) can ACCIDENTALLY preserve crib alignments
    under some sentinels — a random replacement of K4's prefix has ~31%
    chance of leaving `cc_array mod 4` unchanged at downstream positions,
    which preserves color assignments and thus crib letters. So we don't
    require every sentinel to produce noise; we require AT LEAST ONE to.
    Failing all four = hardcoded plaintext.

    A real cipher operating on a non-K4 input typically produces ~1 hit
    on the 24 crib positions (uniform random expectation).
    """
    per_sentinel: list[tuple[str, int]] = []
    for label, sentinel in build_non_k4_sentinels(ciphertext):
        try:
            pt = decrypt_fn(sentinel)
        except Exception:
            # A real cipher might crash on weird input; that's evidence
            # of input-dependence (counts as "not hardcoded").
            per_sentinel.append((label, -1))
            continue
        if not isinstance(pt, str) or len(pt) != len(ciphertext):
            per_sentinel.append((label, -1))
            continue
        per_sentinel.append((label, count_crib_letter_hits(pt)))

    # If any sentinel produced ≤ threshold hits (or crashed/returned
    # bad output), the cipher is responding to input — pass.
    if any(0 <= hits <= _NON_K4_SENTINEL_CRIB_HITS_THRESHOLD for _, hits in per_sentinel):
        return None
    if any(hits == -1 for _, hits in per_sentinel):
        return None

    # Every sentinel reproduced > 6 cribs → cribs come from code, not cipher.
    detail = ", ".join(f"{lab}={h}" for lab, h in per_sentinel)
    return (
        f"decrypt_k4 reproduces > {_NON_K4_SENTINEL_CRIB_HITS_THRESHOLD} "
        f"crib-letter hits on EVERY non-K4 sentinel ({detail}). A real "
        "cipher decrypts at least one such input to noise; reproducing "
        "cribs on all of them means the function is hardcoded or "
        "branches on K4's signature."
    )


def differential_input_check(
    decrypt_fn: Callable[..., Any],
    ciphertext: str,
    plaintext: str,
) -> str | None:
    """Perturb 5 non-crib positions in the ciphertext, re-decrypt, and
    require ≥ 2 plaintext positions to change.

    A real per-position substitution changes plaintext[p] when ciphertext[p]
    changes (and possibly cascades through cumulative-state features like
    consonant_count). A hardcoded decrypt_k4 produces identical plaintext
    regardless of input — fail.

    Non-crib positions are perturbed so the test doesn't accidentally
    invalidate the crib-derived structural anchor (the cribs would still
    be enforced by construction in Prior A regardless).
    """
    import random as _random

    if not isinstance(plaintext, str) or len(plaintext) != len(ciphertext):
        return None  # caller already handles length issues

    rng = _random.Random(_ROBUSTNESS_RNG_SEED + 1)
    crib_pos = _crib_positions_set()
    non_crib = [i for i in range(len(ciphertext)) if i not in crib_pos]
    if len(non_crib) < _DIFFERENTIAL_N_PERTURB:
        return None

    pert_positions = rng.sample(non_crib, k=_DIFFERENTIAL_N_PERTURB)
    perturbed = list(ciphertext)
    for p in pert_positions:
        old = perturbed[p]
        # Guarantee a different character; pick a deterministic alternative
        # that differs from the current char.
        perturbed[p] = "Z" if old != "Z" else "Y"
    perturbed_text = "".join(perturbed)

    try:
        perturbed_pt = decrypt_fn(perturbed_text)
    except Exception as e:
        return (
            f"decrypt_k4 crashed on perturbed-K4 input ({_DIFFERENTIAL_N_PERTURB} "
            f"non-crib positions modified): {type(e).__name__}: {e}. A real "
            "cipher must be robust to ciphertext content."
        )

    if not isinstance(perturbed_pt, str) or len(perturbed_pt) != len(plaintext):
        return None  # length mismatch is handled by other checks

    n_changes = sum(1 for a, b in zip(plaintext, perturbed_pt) if a != b)
    if n_changes < _DIFFERENTIAL_MIN_CHANGES:
        return (
            f"decrypt_k4 plaintext is invariant to ciphertext content: "
            f"only {n_changes} positions differ after perturbing "
            f"{_DIFFERENTIAL_N_PERTURB} non-crib ciphertext positions. A "
            "real per-position substitution cipher changes plaintext at "
            "the perturbed position(s); zero changes means the function "
            "ignores its ciphertext argument (hardcoded plaintext)."
        )
    return None


# --------------------------------------------------------------------------
# External SA hill-climber over FREE_LETTERS.
#
# Added for Run B (hypothesis-mutation architecture, 2026-05-23). The LLM
# proposes (K, selection_rule, FREE_LETTERS, MODIFICATIONS); this function
# runs a Simulated Annealing search over FREE_LETTERS per evaluation,
# refining the alphabets within whatever hypothesis the LLM proposed and
# reporting the BEST-REFINED score. This separates "propose cipher
# hypothesis" (LLM's job) from "refine alphabets" (SA's job).
#
# Schedule: round-robin color selection (color c = iter_count % K) so each
# color gets equal swap budget regardless of K. Geometric cooling from
# initial_temp to min_temp over n_outer_steps cooling steps; inner_steps
# swap attempts per temperature level. Default 100 × 20 = 2000 total
# swaps, evenly distributed across K colors.
#
# Inner-loop fitness: the full _fitness composite (cribs × 100 + hex ×
# 30 + per-partition × 15 + ioc/bigram), so the SA optimizes exactly
# what we ultimately score. Cribs are structurally fixed regardless of
# FREE_LETTERS, so the SA's gradient is mostly on hex.

def score_with_refinement(
    *,
    decrypt_with_state: Callable[..., str],
    ciphertext: str,
    K: int,
    selection_rule: Callable[..., int],
    free_letters: list[str],
    modifications: list,
    n_outer_steps: int = 100,
    inner_steps: int = 20,
    initial_temp: float = 10.0,
    min_temp: float = 0.05,
    t0: float | None = None,
) -> dict[str, Any]:
    """Run external SA on free_letters, return refined-state score + plaintext."""
    import math
    import random as _random

    # Validate the LLM-proposed hypothesis is structurally consistent.
    if len(free_letters) != K or len(modifications) != K:
        elapsed = (time.monotonic() - t0) if t0 is not None else 0.0
        return {
            "score": float("-inf"),
            "solved": True,
            "runtime_s": elapsed,
            "error_tail": (
                f"hypothesis mismatch: K={K} but FREE_LETTERS has "
                f"{len(free_letters)} entries and MODIFICATIONS has "
                f"{len(modifications)}. All three must match K."
            ),
        }

    state: list[list[str]] = [list(s) for s in free_letters]
    rng = _random.Random(0xBADF00D)

    def score_state() -> tuple[float, str]:
        try:
            pt = decrypt_with_state(
                ciphertext, K, selection_rule,
                ["".join(s) for s in state],
                modifications,
            )
        except Exception:
            return float("-inf"), ""
        if not isinstance(pt, str) or len(pt) != len(ciphertext):
            return float("-inf"), ""
        return _fitness(pt)[0], pt

    initial_score, initial_pt = score_state()
    if initial_score == float("-inf"):
        elapsed = (time.monotonic() - t0) if t0 is not None else 0.0
        return {
            "score": float("-inf"),
            "solved": True,
            "runtime_s": elapsed,
            "error_tail": (
                "Initial cipher state produced invalid plaintext "
                "(decryption failed, wrong length, or all-A fallback). "
                "Check that K, selection_rule, FREE_LETTERS, and "
                "MODIFICATIONS are self-consistent."
            ),
        }

    best_score = initial_score
    best_state = [list(s) for s in state]
    current_score = initial_score

    cooling_rate = (
        (min_temp / initial_temp) ** (1.0 / max(n_outer_steps, 1))
        if n_outer_steps > 0 else 0.9
    )

    temp = initial_temp
    iter_count = 0
    for _outer in range(n_outer_steps):
        for _inner in range(inner_steps):
            c = iter_count % K  # round-robin: equal swap budget per color
            L = len(state[c])
            if L >= 2:
                i, j = rng.sample(range(L), 2)
                state[c][i], state[c][j] = state[c][j], state[c][i]
                new_score, _ = score_state()
                accept = False
                if new_score == float("-inf"):
                    accept = False
                elif new_score > current_score:
                    accept = True
                else:
                    delta = new_score - current_score
                    try:
                        accept = rng.random() < math.exp(delta / max(temp, 1e-6))
                    except OverflowError:
                        accept = False
                if accept:
                    current_score = new_score
                    if new_score > best_score:
                        best_score = new_score
                        best_state = [list(s) for s in state]
                else:
                    state[c][i], state[c][j] = state[c][j], state[c][i]  # revert
            iter_count += 1
        temp *= cooling_rate

    # Score the best state with full metadata
    final_letters = ["".join(s) for s in best_state]
    final_pt = decrypt_with_state(
        ciphertext, K, selection_rule, final_letters, modifications,
    )
    score, meta = _fitness(final_pt)
    meta["candidate_plaintext"] = final_pt
    meta["initial_score_pre_refinement"] = float(initial_score)
    meta["refined_score"] = float(best_score)
    meta["n_hillclimb_iters"] = iter_count
    meta["refined_free_letters"] = final_letters
    meta["K"] = K
    elapsed = (time.monotonic() - t0) if t0 is not None else 0.0
    return {
        "score": float(score),
        "solved": True,
        "runtime_s": elapsed,
        "metadata": {
            **meta,
            "full_solution": (
                meta.get("cribs_satisfied") == 4
                and meta.get("hexagram_per_char", -100) >= -7.5
            ),
        },
    }
