"""English n-gram log-likelihood fitness.

Standard practical-cryptography quadgram fitness; supports any n (load
hexagrams the same way once you have the table). For K4 (~73
unconstrained positions) quadgram scoring is noisy enough that gibberish
can score competitively with marginal English; hexagrams calibrated on a
deduped Gutenberg corpus are the recommended K4 fitness function.

File format expected (Practical Cryptography convention):

    NGRAM COUNT
    NGRAM COUNT
    ...

Higher score = more English-like. Returned as natural log-likelihood per
character, so scores from different-length plaintexts are comparable.
"""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path


class NgramFitness:
    """Log-likelihood scorer for a fixed n-gram length."""

    def __init__(self, counts: dict[str, int], n: int) -> None:
        if not counts:
            raise ValueError("empty n-gram table")
        self.n = n
        total = sum(counts.values())
        self.log_total = math.log(total)
        self.log_probs: dict[str, float] = {
            g: math.log(c) - self.log_total for g, c in counts.items()
        }
        # Floor for unseen n-grams: 0.01 / total. Standard practice.
        self.floor = math.log(0.01) - self.log_total

    def __call__(self, text: str) -> float:
        if len(text) < self.n:
            return self.floor
        get = self.log_probs.get
        score = 0.0
        n = self.n
        floor = self.floor
        for i in range(len(text) - n + 1):
            score += get(text[i : i + n], floor)
        return score / (len(text) - n + 1)


def load_quadgrams(path: str | Path) -> NgramFitness:
    """Load Practical Cryptography's `english_quadgrams.txt`."""
    return _load(path, 4)


def load_ngrams(path: str | Path, n: int) -> NgramFitness:
    return _load(path, n)


def _load(path: str | Path, n: int) -> NgramFitness:
    counts: dict[str, int] = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ngram, count = line.split()
            except ValueError:
                continue
            if len(ngram) != n:
                continue
            counts[ngram.upper()] = int(count)
    return NgramFitness(counts, n)


def build_from_corpus(corpus_text: str, n: int) -> NgramFitness:
    """Build a fitness table directly from `corpus_text`. Useful for
    quick experiments; for serious K4 work, build hexagrams from a
    deduped Gutenberg dump and save them to disk so scoring is fast."""
    from kryptos.utils import clean
    cleaned = clean(corpus_text)
    counts: Counter[str] = Counter()
    for i in range(len(cleaned) - n + 1):
        counts[cleaned[i : i + n]] += 1
    return NgramFitness(dict(counts), n)
