"""Standardised experiment verdict records + the project findings ledger.

Every new experiment ends by calling `write_verdict(...)`, which appends a
single `{"_verdict": True, ...}` record to that experiment's JSONL. The
report generator (`scripts/report.py`) scans every results file for these
records and regenerates a human ledger (FINDINGS.md) plus a machine
aggregate (findings.json).

The point: never lose a result, and make the search space provably narrow
over time. Each verdict carries not just a pass/fail but the *insight* and
the *next step*, so the cumulative ledger reads as "here is everything we
now know, and here is what is still open".
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# Status vocabulary, ordered from "closed" to "open lead".
STATUSES = ("solved", "promising", "partial", "ruled_out", "inconclusive", "error")


@dataclass
class Verdict:
    exp: str                      # "043"
    title: str                    # short human title
    hypothesis: str               # what we were testing
    status: str                   # one of STATUSES
    best_score: float | None = None        # hexagram/char of best decrypt (higher=better)
    best_partial: int | None = None         # e.g. crib letters matched, or /97
    search_space: int | None = None         # how many configs tested
    elapsed_s: float | None = None
    solved_params: dict | None = None        # if status=="solved", the verifying params
    insights: list[str] = field(default_factory=list)   # what we learned
    next_steps: list[str] = field(default_factory=list)  # how to push further
    metrics: dict[str, Any] = field(default_factory=dict)  # free-form numbers

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"status {self.status!r} not in {STATUSES}")

    def to_record(self) -> dict:
        d = asdict(self)
        d["_verdict"] = True
        d["ts"] = time.time()
        return d


def write_verdict(out_path: str | Path, verdict: Verdict) -> None:
    """Append the verdict record to a JSONL file and echo a banner."""
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a") as f:
        f.write(json.dumps(verdict.to_record(), default=str) + "\n")
    print("\n" + "=" * 64)
    print(f"VERDICT  exp {verdict.exp}  [{verdict.status.upper()}]  {verdict.title}")
    if verdict.best_score is not None:
        print(f"  best hexagram/char: {verdict.best_score:.2f}  (English ~-13, gibberish ~-24)")
    if verdict.best_partial is not None:
        print(f"  best partial:       {verdict.best_partial}")
    if verdict.search_space is not None:
        print(f"  search space:       {verdict.search_space:,}")
    for ins in verdict.insights:
        print(f"  insight: {ins}")
    for nxt in verdict.next_steps:
        print(f"  next:    {nxt}")
    print("=" * 64)
