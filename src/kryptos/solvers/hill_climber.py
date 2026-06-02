"""Hill-climbing search over keys.

Single-letter substitutions on a current key, accept if score improves.
With random restarts this solves K1 quickly given a quadgram fitness.

For K4 you almost certainly want crib_check as a hard filter on top of
the fitness; see HillClimber(..., constraint=...).
"""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass, field

from kryptos.alphabets import STANDARD, Alphabet


@dataclass
class HillClimber:
    """Single-letter mutation hill-climber over a fixed-length key.

    Args:
        alphabet:    keyspace alphabet
        key_length:  length of the key being searched
        score:       (key, ciphertext) -> float to maximise. Bring your
                     own decrypt+fitness here; the climber stays cipher-agnostic.
        constraint:  optional (key, ciphertext) -> bool; if False, key is
                     discarded before scoring (use this to enforce cribs).
        max_iters:   stop after this many mutations
        restart_every: random restart after this many non-improving moves
        seed:        RNG seed
    """

    alphabet: Alphabet
    key_length: int
    score: Callable[[str], float]
    constraint: Callable[[str], bool] | None = None
    max_iters: int = 100_000
    restart_every: int = 5_000
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

    def run(self) -> tuple[float, str]:
        best_key = self._random_key()
        best_score = self._safe_score(best_key)
        stagnant = 0
        for _ in range(self.max_iters):
            candidate = self._mutate(best_key)
            cs = self._safe_score(candidate)
            if cs > best_score:
                best_key, best_score = candidate, cs
                self.history.append((cs, candidate))
                stagnant = 0
            else:
                stagnant += 1
                if stagnant >= self.restart_every:
                    best_key = self._random_key()
                    best_score = self._safe_score(best_key)
                    stagnant = 0
        return best_score, best_key

    def _safe_score(self, key: str) -> float:
        if self.constraint is not None and not self.constraint(key):
            return float("-inf")
        return self.score(key)
