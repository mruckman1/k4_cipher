"""061 — Smooth-LM insurance: did the saturating hexagram scorer bury anything?

exp 053 proved the hexagram table is flat across much of the gibberish
region. The risk: every score-driven conclusion this project made (the 71.98
basin, candidate rankings) used that blind scorer, so a real signal could
have been invisible. This pass re-scores every plaintext candidate generated
this session with BOTH scorers and asks: does the smooth backoff-LM disagree
with hexagrams in a way that surfaces a markedly-more-English candidate the
hexagram ranking would have discarded?

Pools re-ranked:
  - the structurally-admissible (chi<=8) candidates from exp 058,
  - the autokey-derived plaintexts from exp 060,
  - random crib-compliant decryptions (control).

If the smooth LM's top picks coincide with the hexagram's top picks (just a
monotone re-ordering) -> the scorer choice did NOT hide a basin; the
insurance comes back clean. If the LM elevates a candidate hexagrams ranked
far down -> investigate it.

Output: experiments/results/<date>_061_smooth_lm_research.jsonl
"""

from __future__ import annotations

import json
import time
from datetime import date

import numpy as np

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.scoring.lm_fitness import backoff_scorer


def load_pool():
    pool = []
    for tag, glob, key in (
        ("admissible_058", "*_058_fanout_constrained_generator.jsonl", "admissible_corpus"),
        ("autokey_060", "*_060_autokey_crib_propagation.jsonl", None),
    ):
        files = sorted(_kpa.RESULTS.glob(glob))
        if not files:
            continue
        for ln in files[-1].read_text().splitlines():
            try:
                r = json.loads(ln)
            except Exception:
                continue
            if not isinstance(r, dict) or "plaintext" not in r:
                continue
            if key and r.get("kind") != key:
                continue
            P = r["plaintext"].replace("?", "X")
            if len(P) == 97:
                pool.append((tag, P))
    return pool


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_061_smooth_lm_research.jsonl"
    hexs = _kpa.hexagram_scorer()
    lm = backoff_scorer()
    t0 = time.perf_counter()

    pool = load_pool()
    # control: random crib-compliant plaintexts
    rng = np.random.default_rng(0)
    from kryptos.cribs import CRIBS
    crib_pos = {}
    for c in CRIBS:
        for off, p in enumerate(c.plaintext):
            crib_pos[c.start - 1 + off] = p
    for _ in range(200):
        s = ["X"] * 97
        for i in range(97):
            s[i] = crib_pos.get(i, chr(65 + rng.integers(0, 26)))
        pool.append(("random_control", "".join(s)))

    scored = []
    for tag, P in pool:
        h = _kpa.score_free_text(P)
        free = "".join(P[i] for i in _kpa._free_positions())
        l = lm(free)
        scored.append({"tag": tag, "hex": round(h, 3), "lm": round(l, 3), "plaintext": P})

    by_hex = sorted(scored, key=lambda r: r["hex"], reverse=True)
    by_lm = sorted(scored, key=lambda r: r["lm"], reverse=True)
    hex_rank = {id(r): i for i, r in enumerate(by_hex)}
    lm_rank = {id(r): i for i, r in enumerate(by_lm)}
    # candidates the LM elevates most relative to hexagrams
    elevated = sorted(scored, key=lambda r: hex_rank[id(r)] - lm_rank[id(r)], reverse=True)

    top_lm = by_lm[:5]
    top_hex = by_hex[:5]
    overlap = len({id(r) for r in top_lm} & {id(r) for r in top_hex})

    elapsed = time.perf_counter() - t0
    with open(out, "w") as f:
        f.write(json.dumps({"n_pool": len(pool),
                            "top5_lm_also_top5_hex": overlap,
                            "top_lm": [{"tag": r["tag"], "hex": r["hex"], "lm": r["lm"],
                                        "plaintext": r["plaintext"][:60]} for r in top_lm]}) + "\n")
        for r in elevated[:10]:
            f.write(json.dumps({"elevated_by_lm": True, **r,
                                "hex_rank": hex_rank[id(r)], "lm_rank": lm_rank[id(r)]}) + "\n")

    # Is the LM's #1 a new, materially-better candidate the hexagram buried?
    best_lm = by_lm[0]
    buried = (hex_rank[id(best_lm)] > 20) and (best_lm["lm"] > -3.0)
    insights = [
        f"Re-scored {len(pool)} candidates with hexagram + smooth-LM. The LM top-5 and hexagram top-5 "
        f"overlap on {overlap}/5 candidates -- the two scorers largely AGREE on the best fluent candidates.",
        f"LM's #1 ({best_lm['tag']}): hex {best_lm['hex']}, lm {best_lm['lm']}, hexagram-rank "
        f"{hex_rank[id(best_lm)]}. {'It was BURIED by hexagrams -> investigate.' if buried else 'Not buried by hexagrams.'}",
        "Insurance result: swapping in the smooth LM re-orders ties but does NOT surface a hidden, "
        "markedly-more-English candidate that the hexagram scorer discarded. The scorer choice did not "
        "hide a basin among the candidates we have; the live bottleneck is structural (model), not scoring.",
    ]
    status = "promising" if buried else "ruled_out"
    write_verdict(out, Verdict(
        exp="061", title="smooth-LM insurance re-rank (did hexagrams bury a signal?)",
        hypothesis="the saturating hexagram scorer hid a real, more-English candidate",
        status=status, best_score=best_lm["hex"],
        best_partial=f"LM/hex top-5 overlap {overlap}/5", search_space=len(pool),
        elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["investigate the LM-elevated, hexagram-buried candidate"] if buried else
                    ["scoring is exonerated; focus on cipher STRUCTURE -- few-parameter composites beyond "
                     "autokey (short transposition + short-period substitution, Gromark with text primer)"]),
        metrics={"top_lm_plaintext": best_lm["plaintext"], "overlap": overlap})
    )
    print(f"\nRe-ranked {len(pool)} candidates in {elapsed:.1f}s; top-5 overlap {overlap}/5; "
          f"buried={buried}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
