"""Tiny JSONL experiment logger.

Don't reach for MLflow or W&B; for this project a 50-line writer is
enough and keeps every result greppable on disk. The Kryptos community
has lost work for 30 years because people reported "I tried X" without
preserving exactly what X was -- don't repeat that.

Every experiment script ends with a JSONL dump of
    (seed, cipher_class, params, score, candidate_plaintext)
into experiments/results/{date}_{name}.jsonl.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import date
from pathlib import Path
from typing import Any

DEFAULT_RESULTS_DIR = Path(__file__).resolve().parents[2] / "experiments" / "results"


class ExperimentLogger:
    """Append-only JSONL logger with a header record describing the run."""

    def __init__(
        self,
        name: str,
        results_dir: Path | str = DEFAULT_RESULTS_DIR,
        date_str: str | None = None,
    ) -> None:
        results_dir = Path(results_dir)
        results_dir.mkdir(parents=True, exist_ok=True)
        date_str = date_str or date.today().isoformat()
        self.path = results_dir / f"{date_str}_{name}.jsonl"
        self.name = name
        self._fh = open(self.path, "a", buffering=1)  # line-buffered
        self.write({
            "_header": True,
            "name": name,
            "ts": time.time(),
            "argv": list(sys.argv),
            "cwd": os.getcwd(),
        })

    def write(self, record: dict[str, Any]) -> None:
        self._fh.write(json.dumps(record, default=str) + "\n")

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "ExperimentLogger":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
