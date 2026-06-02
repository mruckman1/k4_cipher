"""Instance catalog — K4 is a single instance, repeated.

Shinka's cascade machinery wants per-stage instance counts > 0, but K4 has
exactly one ciphertext. The single instance is the K4 ciphertext itself;
the runner just calls decrypt_k4(K4) and scores the result. The instance
dict is passed straight to run_experiment().
"""

from __future__ import annotations

import random
from typing import Any

from kryptos.constants import K4

_K4_INSTANCE: dict[str, Any] = {
    "id": "k4",
    "family": "k4",
    "ciphertext": K4,
}


def sample(benchmark_set: str, n: int, rng: random.Random) -> list[dict[str, Any]]:
    """Return ``n`` copies of the K4 instance. There is only one instance for
    this problem; cascade stages with n>1 just re-score the same input.

    Determinism: trivially deterministic — the same input is returned.
    """
    del benchmark_set, rng  # single-instance catalog
    return [_K4_INSTANCE for _ in range(max(n, 1))]
