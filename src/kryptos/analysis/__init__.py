"""Statistical analysis primitives."""

from kryptos.analysis.friedman import friedman_key_length
from kryptos.analysis.ioc import index_of_coincidence, periodic_ioc
from kryptos.analysis.kasiski import kasiski_periods, kasiski_repeats
from kryptos.analysis.ngrams import ngram_counts, top_ngrams
from kryptos.analysis.partitions import partition_at, w_partition
from kryptos.analysis.permutation_test import (
    PermutationResult,
    english_at_cribs_test,
    english_score,
    permutation_test,
    positional_shift_uniformity,
)

__all__ = [
    "index_of_coincidence",
    "periodic_ioc",
    "kasiski_repeats",
    "kasiski_periods",
    "ngram_counts",
    "top_ngrams",
    "friedman_key_length",
    "w_partition",
    "partition_at",
    "PermutationResult",
    "permutation_test",
    "english_at_cribs_test",
    "english_score",
    "positional_shift_uniformity",
]
