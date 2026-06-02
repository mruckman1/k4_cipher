"""Simulated annealing search over keys.

Like HillClimber but accepts down-moves with probability exp(dE / T),
with T cooling from `t_start` to `t_end` over `max_iters`. Reliable
escape from local optima at the cost of more iterations.
"""

from __future__ import annotations

import math
import random
from collections.abc import Callable
from dataclasses import dataclass, field

from kryptos.alphabets import Alphabet


@dataclass
class SimulatedAnnealing:
    alphabet: Alphabet
    key_length: int
    score: Callable[[str], float]
    constraint: Callable[[str], bool] | None = None
    max_iters: int = 200_000
    t_start: float = 10.0
    t_end: float = 0.01
    seed: int = 0
    history: list[tuple[float, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)

    def _random_key(self) -> str:
        return "".join(self._rng.choices(self.alphabet.letters, k=self.key_length))

    def _mutate(self, key: str) -> str:
        i = self._rng.randrange(self.key_length)
        new = self._rng.choice(self.alphabet.letters)
        if new == key[i]:
            new = self.alphabet.letters[(self.alphabet.index(key[i]) + 1) % len(self.alphabet)]
        return key[:i] + new + key[i + 1 :]

    def _safe_score(self, key: str) -> float:
        if self.constraint is not None and not self.constraint(key):
            return float("-inf")
        return self.score(key)

    def run(self) -> tuple[float, str]:
        key = self._random_key()
        s = self._safe_score(key)
        best_key, best_score = key, s
        for it in range(self.max_iters):
            T = self.t_start * (self.t_end / self.t_start) ** (it / max(1, self.max_iters - 1))
            new_key = self._mutate(key)
            new_s = self._safe_score(new_key)
            dE = new_s - s
            if dE > 0 or (dE != float("-inf") and self._rng.random() < math.exp(dE / T)):
                key, s = new_key, new_s
                if s > best_score:
                    best_key, best_score = key, s
                    self.history.append((s, key))
        return best_score, best_key
