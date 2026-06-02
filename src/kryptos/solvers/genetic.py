"""Genetic algorithm over keys.

Stub. Hill-climbing with restarts is usually competitive enough on
classical ciphers that GAs are not worth their tuning overhead, but the
class is here for completeness if you want population-based diversity.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from kryptos.alphabets import Alphabet


@dataclass
class GeneticAlgorithm:
    alphabet: Alphabet
    key_length: int
    score: Callable[[str], float]
    constraint: Callable[[str], bool] | None = None
    population_size: int = 200
    generations: int = 500
    mutation_rate: float = 0.05
    crossover_rate: float = 0.7
    elitism: int = 5
    seed: int = 0

    def run(self) -> tuple[float, str]:
        raise NotImplementedError(
            "GA not implemented. Fill in if hill_climber + simulated_annealing "
            "are inadequate for a particular cipher family."
        )
