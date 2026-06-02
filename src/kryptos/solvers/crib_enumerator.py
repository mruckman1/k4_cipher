"""Crib-constrained key search.

For each cipher family, enumerate keys/primers, decrypt, hard-check
against the four cribs, score the survivors by English log-likelihood,
log every candidate to JSONL. This is the workhorse for Phase 1 of the
staged attack: most cipher classes will return zero crib-satisfying
candidates and be eliminated cheaply.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field

from kryptos.cribs import CRIBS, Crib
from kryptos.scoring.crib_check import crib_check


@dataclass
class Candidate:
    """One key/primer that survived the crib filter."""

    key: str
    plaintext: str
    score: float
    params: dict = field(default_factory=dict)


class CribEnumerator:
    """Generic crib-constrained enumerator.

    Plug in:
        - keys:        iterable of (key_label, decrypt_fn(ciphertext) -> plaintext)
        - score:       plaintext -> float
        - cribs:       which cribs to enforce
        - top_k:       how many survivors to keep
    """

    def __init__(
        self,
        ciphertext: str,
        keys: Iterable[tuple[str, Callable[[str], str]]],
        score: Callable[[str], float],
        cribs: Iterable[Crib] = CRIBS,
        top_k: int = 50,
    ) -> None:
        self.ciphertext = ciphertext
        self.keys = keys
        self.score = score
        self.cribs = tuple(cribs)
        self.top_k = top_k

    def run(self, on_candidate: Callable[[Candidate], None] | None = None) -> list[Candidate]:
        survivors: list[Candidate] = []
        for key_label, decrypt in self.keys:
            plain = decrypt(self.ciphertext)
            if not crib_check(plain, self.cribs):
                continue
            cand = Candidate(key=key_label, plaintext=plain, score=self.score(plain))
            if on_candidate is not None:
                on_candidate(cand)
            survivors.append(cand)
        survivors.sort(key=lambda c: c.score, reverse=True)
        return survivors[: self.top_k]
