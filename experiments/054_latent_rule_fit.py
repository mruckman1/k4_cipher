"""054 — Latent selection-rule fit: which (candidate, rule, k) best explains
K4 as a per-position substitution?

exps 035-037 tested selection RULES against the 24 cribs only. 055 showed
the FREE-coloring chromatic number of every N1 candidate is >=7. This
experiment closes the loop: for each candidate plaintext and a library of
closed-form selection rules R(i)->{0..k-1} (position mod k; consonant-count
mod k; the ShinkaEvolve Prior-A rule (2*(i%3)+cc) mod k), how many positions
must be VIOLATED for the per-position substitution to be consistent (within
each colour group a plaintext letter must map to one cipher letter and vice
versa)? Zero violations + cribs satisfied = that candidate IS decryptable
under that rule -> recover alphabets, hexagram-verify.

This is the EM 'discover the rule' step done exhaustively over a rule
library instead of iteratively. The minimum-violation (candidate, rule, k)
is the sharpest structural fit and tells us whether ANY simple rule + the
LLM prior is even close.

Output: experiments/results/<date>_054_latent_rule_fit.jsonl
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import date
from pathlib import Path

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.constants import K4

VOWELS = set("AEIOU")


def consonant_prefix(ciphertext: str) -> list[int]:
    cc, out = 0, []
    for ch in ciphertext:
        if ch not in VOWELS:
            cc += 1
        out.append(cc)
    return out


CC = consonant_prefix(K4)


def rule_library():
    rules = {}
    for k in range(4, 9):
        rules[f"pos_mod_{k}"] = (k, lambda i, k=k: i % k)
        rules[f"cc_mod_{k}"] = (k, lambda i, k=k: CC[i] % k)
        rules[f"priorA_mod_{k}"] = (k, lambda i, k=k: (2 * (i % 3) + CC[i]) % k)
    return rules


def violations(P: str, rule, k: int) -> int:
    groups_pc = [dict() for _ in range(k)]   # plain->cipher per color
    groups_cp = [dict() for _ in range(k)]
    v = 0
    for i, (p, c) in enumerate(zip(P, K4)):
        col = rule(i)
        pc, cp = groups_pc[col], groups_cp[col]
        bad = (p in pc and pc[p] != c) or (c in cp and cp[c] != p)
        if bad:
            v += 1
        else:
            pc[p] = c
            cp[c] = p
    return v


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--limit", type=int, default=2000)
    ap.add_argument("--run-dir", type=Path, default=None)
    args = ap.parse_args()
    out = _kpa.RESULTS / f"{date.today()}_054_latent_rule_fit.jsonl"

    run_dir = args.run_dir or _kpa.latest_run_dir("sonnet")
    cands = _kpa.load_candidates(run_dir)
    cands = sorted(cands, key=_kpa.score_free_text, reverse=True)[:args.limit]
    rules = rule_library()
    print(f"{len(cands)} candidates x {len(rules)} rules")

    t0 = time.perf_counter()
    best = (10 ** 9, None)   # (violations, info)
    zero_hits = []
    per_rule_min = {name: 10 ** 9 for name in rules}
    for P in cands:
        for name, (k, rule) in rules.items():
            v = violations(P, rule, k)
            per_rule_min[name] = min(per_rule_min[name], v)
            if v < best[0]:
                best = (v, {"rule": name, "k": k, "violations": v,
                            "free_hex": round(_kpa.score_free_text(P), 2), "plaintext": P})
            if v == 0:
                zero_hits.append({"rule": name, "k": k, "plaintext": P,
                                  "free_hex": round(_kpa.score_free_text(P), 2)})

    elapsed = time.perf_counter() - t0
    with open(out, "w") as f:
        f.write(json.dumps({"per_rule_min_violations": per_rule_min,
                            "best": best[1], "n_zero": len(zero_hits)}) + "\n")
        for z in zero_hits[:30]:
            f.write(json.dumps(z) + "\n")

    status = "solved" if zero_hits else "ruled_out"
    insights = [
        f"Best structural fit over {len(cands)} candidates x {len(rules)} rules: {best[0]} positions must "
        f"be violated (min over all (candidate,rule,k)). Rule {best[1]['rule']} on the best candidate.",
        f"Per-rule minimum violations: {dict(sorted(per_rule_min.items(), key=lambda x: x[1])[:6])} ...",
        f"{len(zero_hits)} candidate+rule combos reach ZERO violations (= a clean per-position decryption).",
    ]
    if not zero_hits:
        insights.append("No N1 candidate is consistent with ANY tested closed-form selection rule at k<=8 "
                        "(min violations far from 0). Consistent with exp 055: the LLM prior plaintexts are "
                        "structurally incompatible with a simple-rule per-position cipher; the true plaintext "
                        "and/or rule lies outside the current prior + closed-form-rule families.")
    write_verdict(out, Verdict(
        exp="054", title="latent selection-rule fit over candidate plaintexts",
        hypothesis="some N1 candidate is a clean per-position substitution under a simple closed-form rule",
        status=status, best_partial=f"min violations {best[0]}",
        search_space=len(cands) * len(rules), elapsed_s=round(elapsed, 1),
        solved_params=(zero_hits[0] if zero_hits else None),
        insights=insights,
        next_steps=(["verify the zero-violation decryptions byte-exact"] if zero_hits else
                    ["the rule must be non-closed-form (hand-crafted lookup) OR plaintext outside prior; "
                     "generate fanout<=k plaintexts (exp 055 filter) and re-fit; try W-segment rules"]),
        metrics={"per_rule_min": per_rule_min, "best": best[1]})
    )
    print(f"\nDone in {elapsed:.1f}s; min violations {best[0]}; zero-hits {len(zero_hits)}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
