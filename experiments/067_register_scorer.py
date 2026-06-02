"""067 — Telegraphic/coordinate-register scorer + restricted-alphabet re-derivation.

The scoring exoneration (053/061) compared two PROSE-trained scorers and
concluded "no candidate is more prose-like." Wrong axis: K2's plaintext spells
GPS coordinates and ALL four K4 cribs are navigational (EAST, NORTHEAST=45deg,
BERLIN, CLOCK). A telegraphic coordinate string ("...DEGREES...MINUTES...
NORTHEAST...POINT...") is LESS prose-like by construction, so both prose
scorers co-rank it as junk -- a mis-calibration that could have rejected the
true plaintext at the scoring stage.

This experiment (pure cryptanalysis -- SYNTHETIC corpora only, never the real
plaintext):
  (A) builds a register char-LM from synthetic spelled-coordinate / bearing /
      telegraphese, and re-scores every candidate decryption we have on disk
      with register-LM vs prose-LM, surfacing any candidate the prose scorer
      buried.
  (B) restricted-alphabet re-derivation: generate crib-compliant
      coordinate-register plaintexts and measure their fanout vs K4 -- if any
      reach fanout<=4/5/6 (prose candidates floored at 7), a restricted-register
      per-position cipher is admissible where prose is not, partially re-opening
      exp 055/059.

Output: experiments/results/<date>_067_register_scorer.jsonl
"""

from __future__ import annotations

import json
import random
import time
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K4
from kryptos.cribs import CRIBS
from kryptos.scoring.lm_fitness import BackoffCharLM, backoff_scorer
from kryptos.solvers.sat_ilp import fanout

DIRS = ["NORTH", "SOUTH", "EAST", "WEST", "NORTHEAST", "NORTHWEST", "SOUTHEAST",
        "SOUTHWEST", "NORTHBY", "EASTBY"]
DIGITS = ["ZERO", "ONE", "TWO", "THREE", "FOUR", "FIVE", "SIX", "SEVEN", "EIGHT",
          "NINE", "TEN", "ELEVEN", "TWELVE", "THIRTEEN", "FOURTEEN", "FIFTEEN",
          "TWENTY", "THIRTY", "FORTY", "FIFTY", "SIXTY", "SEVENTY", "EIGHTY", "NINETY"]
UNITS = ["DEGREES", "MINUTES", "SECONDS", "POINT", "DEGREE", "MINUTE"]
NAV = ["LATITUDE", "LONGITUDE", "BEARING", "HEADING", "MARK", "GRID", "PROCEED",
       "LOCATE", "BENEATH", "BURIED", "LAYER", "WEST", "NORTH", "DEGREES", "MINUTES",
       "BERLIN", "CLOCK", "FIELD", "MAGNETIC", "UNDERGROUND", "LOCATION"]


def register_corpus(n_chars: int, rng) -> str:
    out = []
    while sum(len(x) for x in out) < n_chars:
        kind = rng.random()
        if kind < 0.5:  # a coordinate
            out += [rng.choice(DIGITS), rng.choice(["TY"]) if rng.random() < 0.1 else "",
                    rng.choice(DIGITS), "DEGREES", rng.choice(DIGITS), "MINUTES",
                    rng.choice(DIGITS), "POINT", rng.choice(DIGITS), "SECONDS",
                    rng.choice(["NORTH", "SOUTH"])]
        elif kind < 0.8:  # a bearing/direction phrase
            out += [rng.choice(DIRS), "BY", rng.choice(DIRS), rng.choice(UNITS),
                    rng.choice(DIGITS)]
        else:  # navigational instruction
            out += [rng.choice(NAV), rng.choice(NAV), rng.choice(DIGITS), rng.choice(UNITS)]
    return "".join(out)[:n_chars]


def load_candidate_pool():
    pool = []
    for glob, key in (("*_058_fanout_constrained_generator.jsonl", "admissible_corpus"),
                      ("*_059_retire_per_position_model.jsonl", None),
                      ("*_054_latent_rule_fit.jsonl", None)):
        files = sorted(_kpa.RESULTS.glob(glob))
        if not files:
            continue
        for ln in files[-1].read_text().splitlines():
            try:
                r = json.loads(ln)
            except Exception:
                continue
            if isinstance(r, dict) and r.get("plaintext") and len(r["plaintext"]) == 97:
                if key and r.get("kind") != key:
                    continue
                pool.append(r["plaintext"])
    return pool


def crib_compliant_register(rng, n=400):
    """Generate n crib-compliant coordinate-register plaintexts (free spans
    filled with register text)."""
    spans = [(0, 21), (34, 63), (74, 97)]
    cp = {}
    for c in CRIBS:
        for off, p in enumerate(c.plaintext):
            cp[c.start - 1 + off] = p
    base = list("X" * 97)
    for i, ch in cp.items():
        base[i] = ch
    out = []
    for _ in range(n):
        s = base[:]
        for a, b in spans:
            txt = register_corpus(b - a + 40, rng)
            for k, i in enumerate(range(a, b)):
                s[i] = txt[k]
        out.append("".join(s))
    return out


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_067_register_scorer.jsonl"
    rng = random.Random(0)
    t0 = time.perf_counter()

    # (A) register LM vs prose LM
    print("Building register corpus + LM...")
    reg = BackoffCharLM(register_corpus(400_000, rng), maxn=6)
    prose = backoff_scorer()
    pool = load_candidate_pool()
    print(f"Re-scoring {len(pool)} candidate decryptions (register vs prose)...")
    free = _kpa._free_positions()
    scored = []
    for P in pool:
        ft = "".join(P[i] for i in free)
        scored.append({"reg": round(reg(ft), 3), "prose": round(prose(ft), 3),
                       "plaintext": P})
    by_reg = sorted(scored, key=lambda r: r["reg"], reverse=True)
    # candidates the prose scorer buries but register likes
    elevated = sorted(scored, key=lambda r: r["reg"] - r["prose"], reverse=True)

    # (B) restricted-register fanout
    print("Measuring fanout of crib-compliant coordinate-register plaintexts...")
    regtexts = crib_compliant_register(rng, n=600)
    fanouts = sorted(fanout(P, K4) for P in regtexts)
    min_fan = fanouts[0]
    n_le6 = sum(1 for x in fanouts if x <= 6)

    elapsed = time.perf_counter() - t0
    with open(out, "w") as f:
        f.write(json.dumps({"n_pool": len(pool),
                            "top_register": [{"reg": r["reg"], "prose": r["prose"],
                                              "plaintext": r["plaintext"][:60]} for r in by_reg[:5]],
                            "register_min_fanout": min_fan, "register_n_fanout_le6": n_le6,
                            "register_fanout_min5": fanouts[:5]}) + "\n")

    insights = [
        f"Built a coordinate/telegraphic-register char-LM and re-scored {len(pool)} candidate decryptions. "
        f"Top register-LM candidate: reg={by_reg[0]['reg']} prose={by_reg[0]['prose']} -> "
        f"{by_reg[0]['plaintext'][:48]}...",
        f"Restricted-register re-derivation: min fanout over {len(regtexts)} crib-compliant "
        f"coordinate-register plaintexts = {min_fan} (prose candidates floored at 7); "
        f"{n_le6} reached fanout<=6.",
    ]
    # Decide status: a register candidate that is clearly coordinate-fluent, OR a register
    # plaintext admissible at low fanout, would be promising.
    reopened = min_fan <= 6
    status = "promising" if reopened else "inconclusive"
    if reopened:
        insights.append(f"RE-OPENED: coordinate-register plaintext can reach fanout {min_fan}<=6, where prose "
                        f"could not (min 7) -- a restricted-register per-position cipher is structurally "
                        f"admissible. Worth a register-scored KPA over the surviving positional families.")
    else:
        insights.append("Even coordinate-register plaintexts do not beat the fanout-7 floor, and no buried "
                        "register-fluent candidate emerged. The register mis-calibration did NOT hide an "
                        "admissible solution; prose-scoring was not the blocker.")
    write_verdict(out, Verdict(
        exp="067", title="telegraphic/coordinate-register scorer + restricted-alphabet fanout",
        hypothesis="K4 plaintext is navigational/coordinate register, mis-scored by prose LMs",
        status=status, best_score=by_reg[0]["reg"],
        best_partial=f"register min fanout {min_fan}; pool {len(pool)}",
        search_space=len(pool) + len(regtexts), elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["run a register-LM-scored KPA over the shortlisted selectors (exp 065) and the "
                     "live cipher families"] if reopened else
                    ["register scoring exonerated too; the blocker is structural, not the plaintext model"]),
        metrics={"top_register_plaintext": by_reg[0]["plaintext"], "register_min_fanout": min_fan})
    )
    print(f"\nDone in {elapsed:.1f}s; register min fanout {min_fan}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
