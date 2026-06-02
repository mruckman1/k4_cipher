"""N-gram counting and ranking. Purely descriptive; for scoring see
`kryptos.scoring.ngram_fitness`.
"""

from __future__ import annotations

from collections import Counter

from kryptos.utils import iter_window


def ngram_counts(text: str, n: int) -> Counter[str]:
    """Counter of every length-n substring of `text`."""
    return Counter(iter_window(text, n))


def top_ngrams(text: str, n: int, k: int = 20) -> list[tuple[str, int]]:
    """`k` most common length-n substrings."""
    return ngram_counts(text, n).most_common(k)


def doubled_letters(text: str) -> list[tuple[int, str]]:
    """0-indexed positions of every doubled letter (text[i] == text[i+1]).
    K4 has anomalously many: BB(17), QQ(25), SS(31), SS(41), ZZ(45),
    TT(66), UU(91) in 0-indexed coordinates.
    """
    return [(i, text[i]) for i in range(len(text) - 1) if text[i] == text[i + 1]]
