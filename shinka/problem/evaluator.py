"""InProcessEvaluator factory. The candidate module is imported in a
subprocess-isolated worker; `run_experiment` from problem/initial.py is the
entrypoint that gets called per instance.
"""

from __future__ import annotations

from pathlib import Path

from shinka_adapter.evaluators import Evaluator, InProcessEvaluator


def build() -> Evaluator:
    return InProcessEvaluator(
        entrypoint="run_experiment",
        extra_sys_path=[Path(__file__).resolve().parent.parent],
    )
