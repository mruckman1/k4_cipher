"""N1: local-LLM plaintext-content inference for Kryptos K4 (ollama edition).

The earlier N1 used 12 cloud-LLM subagents and clustered to themes like
navigation, first_person, berlin_wall. This script reproduces that
approach using a local ollama model (default qwen3.6:35b-a3b-mlx-bf16),
so it can run cheaply and iteratively.

Approach:
  1. For each of N "framings" (cold-war espionage, navigation, K2/K3 echo,
     Berlin Wall, surveyor's hint, K5 forward-reference), prompt the model
     for K candidate K4 plaintexts that satisfy the four known cribs at
     positions 22-25, 26-34, 64-69, 70-74.
  2. Parse responses into 97-char A-Z strings (strict).
  3. Cluster by keyword overlap (the same N1 cluster_n1.py logic).
  4. Surface convergent themes the model proposes across framings.

Output:
  - data/k4_plaintext_themes_ollama.yaml  (clustered themes + frequencies)
  - experiments/results/n1_ollama_outputs/  (raw per-framing outputs)

Usage:
  uv run python scripts/n1_ollama.py
  uv run python scripts/n1_ollama.py --model qwen3.5:27b-q8_0 --n-per 10
  uv run python scripts/n1_ollama.py --dry-run    # just print prompts
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

try:
    import requests
except ImportError:
    print("requests not installed; pip install requests", file=sys.stderr)
    sys.exit(1)


OLLAMA_URL = "http://localhost:11434/api/generate"
# gemma4:26b-a4b-it-q8_0 is a non-thinking instruction-tuned MoE (~4B active
# params); faster wall-clock than qwen3.6 thinking mode on Apple silicon
# even with "think: false", and follows the strict CANDIDATE_N: format
# reliably enough for parse_candidates.
DEFAULT_MODEL = "gemma4:26b-a4b-it-q8_0"

CRIBS_DESC = """
The K4 ciphertext is 97 letters A-Z (no spaces). Four plaintext spans are
confirmed (Sanborn's hints, 2010-2020):
  - positions 22-25:  EAST
  - positions 26-34:  NORTHEAST
  - positions 64-69:  BERLIN
  - positions 70-74:  CLOCK
Position 74's plaintext is K and the ciphertext is also K (self-encryption,
known constraint). Everything else (positions 1-21, 35-63, 75-97) is unknown.

Sculpture context: K1-K3 ciphers were Vigenere/Vigenere/Columnar by
Jim Sanborn (1990), themed around CIA history, geography, and a buried-
device "magnetic field" passage. K4 has resisted cryptanalysis for 36 years.
"""

FRAMINGS = {
    "espionage": (
        "You are reasoning about Cold-War-era CIA / Berlin-station tradecraft. "
        "If the K4 plaintext mentions agents, dead drops, exfiltration, codenames, "
        "Wall crossings, or surveillance logs, what plausible English text could it be?"
    ),
    "navigation": (
        "You are reasoning about Sanborn's known love of coordinates and geography "
        "(K2 ends with WIDTHANDFTSCONCEDTOTHESECRETLOCATIONIDBYROWS — Langley HQ "
        "coordinates). If K4's plaintext is navigational, what coordinates or "
        "directional language could it be? EAST + NORTHEAST + BERLIN are heavily "
        "directional."
    ),
    "k2_k3_echo": (
        "You are reasoning about stylistic continuity with K2 and K3's prose. K2 is "
        "an excavation/burial narrative; K3 quotes Howard Carter's Tut diary. K4 "
        "may continue the buried-device or Carter motifs. What text could echo that?"
    ),
    "berlin_wall": (
        "You are reasoning about the November 1989 fall of the Berlin Wall, six "
        "months after K4 was set in the sculpture. The 1989 timing + BERLIN + CLOCK "
        "(possibly Weltzeituhr at Alexanderplatz or the Tower of the Cosmos clock?) "
        "suggests Wall-fall imagery. What text could it be?"
    ),
    "surveyor": (
        "You are reasoning about Sanborn's day job as a sculptor and his stated "
        "hint that K4 'tells you to do something with the sculpture itself'. K4 "
        "might be a tactile/spatial instruction. What text could it be?"
    ),
    "k5_forward": (
        "You are reasoning about Sanborn's hint that K4 may forward-reference a K5 "
        "(an external puzzle requiring physical search). K4 might be an INSTRUCTION "
        "to look at a specific location. What text could it be?"
    ),
}


def build_schema(n: int) -> dict:
    """JSON schema enforcing exactly {n} candidates, each with three free
    text spans of FIXED lengths (21, 29, 23). We assemble final 97-char
    plaintexts in code: free_a + EAST + NORTHEAST + free_b + BERLIN +
    CLOCK + free_c. Cribs are hard-coded, so the model literally cannot
    misspell them or misposition them."""
    span = lambda min_l, max_l: {
        "type": "string", "minLength": min_l, "maxLength": max_l,
    }
    return {
        "type": "object",
        "properties": {
            "candidates": {
                "type": "array",
                "minItems": n,
                "maxItems": n,
                "items": {
                    "type": "object",
                    "properties": {
                        # Slightly relaxed bounds (-/+1) so the model has
                        # wiggle room; we pad/truncate in code.
                        "free_a_21_chars": span(20, 22),
                        "free_b_29_chars": span(28, 30),
                        "free_c_23_chars": span(22, 24),
                    },
                    "required": [
                        "free_a_21_chars", "free_b_29_chars", "free_c_23_chars",
                    ],
                },
            },
        },
        "required": ["candidates"],
    }


def build_prompt(framing_name: str, framing_desc: str, n: int) -> str:
    """Free-form prompt; JSON schema enforces structure."""
    return f"""{CRIBS_DESC}

Framing: {framing_desc}

Generate {n} distinct candidate K4 plaintexts in this framing.

Each candidate has three FREE text spans that you fill with plausible
English letters (A-Z only, no spaces or punctuation):
  - free_a_21_chars: 21 letters opening the plaintext (positions 1-21)
  - free_b_29_chars: 29 letters between NORTHEAST and BERLIN (positions 35-63)
  - free_c_23_chars: 23 letters closing the plaintext (positions 75-97)

The four cribs (EAST, NORTHEAST, BERLIN, CLOCK) will be inserted at the
correct positions automatically; you only fill the free spans.

Make the three spans, when joined with the cribs, read as plausible
English text in the framing above. Words may run together (no spaces);
that's normal for K4 plaintexts. Return ALL {n} candidates as JSON
matching the schema. Return JSON only."""


MAX_PER_CALL = 25  # Empirical safe batch (gemma4 truncates ~25-30 / call)


def call_ollama(
    model: str,
    prompt: str,
    schema: dict,
    timeout_s: int = 3600,
    num_predict: int = 16384,
) -> str:
    """Call ollama's /api/generate with a JSON schema (structured outputs).

    ``think: false`` disables the Qwen3 thinking-mode reasoning trace.
    ``format`` is the JSON schema the response must conform to (added in
    Ollama Dec 2024). With structured outputs the model can't drift on
    field names or types -- it has to emit valid JSON matching the
    schema, which means no more "the model miscounted to 86 chars" or
    "the model invented its own prefix label" failure modes.
    """
    resp = requests.post(
        OLLAMA_URL,
        json={
            "model": model,
            "prompt": prompt,
            "stream": False,
            "think": False,
            "format": schema,
            "options": {"temperature": 0.9, "num_predict": num_predict},
        },
        timeout=timeout_s,
    )
    resp.raise_for_status()
    return resp.json().get("response", "")


def _pad_or_truncate(s: str, target: int) -> str:
    """Force a string to exactly `target` length, padding with X or
    truncating. Strips non-A-Z first."""
    cleaned = "".join(c for c in s.upper() if "A" <= c <= "Z")
    if len(cleaned) < target:
        cleaned = cleaned + "X" * (target - len(cleaned))
    return cleaned[:target]


def _try_recover_partial_json(raw_text: str) -> dict:
    """Recover whatever complete candidates we can from a truncated JSON.
    Common failure: model hit num_predict mid-array; we close the array
    and object so json.loads succeeds, dropping any partial final entry."""
    if not raw_text or "candidates" not in raw_text:
        return {}
    # Strip whitespace then try progressively-shorter prefixes ending at
    # the last complete `}` before truncation.
    last_complete_obj = raw_text.rfind("}")
    if last_complete_obj < 0:
        return {}
    fixed = raw_text[: last_complete_obj + 1] + "]}"
    # That assumes structure: {"candidates": [{}, {}, ...]}
    try:
        return json.loads(fixed)
    except json.JSONDecodeError:
        return {}


def parse_candidates(raw_text: str) -> list[str]:
    """Parse the model's JSON response and assemble 97-char plaintexts.

    Each candidate's three free spans are forced to exactly 21 / 29 / 23
    chars (pad with X if short, truncate if long); the four crib spans
    are hard-coded and inserted at the correct positions. Result is
    GUARANTEED to be a 97-char A-Z string with cribs at positions 22-25,
    26-34, 64-69, 70-74. The model just provides the free-text content.

    If the response is truncated (num_predict hit), recover whatever
    complete entries are at the start of the array.
    """
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError:
        data = _try_recover_partial_json(raw_text)
    cands_in = data.get("candidates", []) if isinstance(data, dict) else []
    out: list[str] = []
    for c in cands_in:
        if not isinstance(c, dict):
            continue
        a = _pad_or_truncate(c.get("free_a_21_chars", ""), 21)
        b = _pad_or_truncate(c.get("free_b_29_chars", ""), 29)
        c_ = _pad_or_truncate(c.get("free_c_23_chars", ""), 23)
        assembled = a + "EAST" + "NORTHEAST" + b + "BERLIN" + "CLOCK" + c_
        if len(assembled) == 97 and assembled.isalpha() and assembled.isupper():
            out.append(assembled)
    return out


def crib_compliant(cand: str) -> bool:
    """With JSON-mode assembly, every parsed candidate is crib-compliant
    by construction. Kept for back-compat with the reporting code."""
    return (
        len(cand) == 97
        and cand[21:25] == "EAST"
        and cand[25:34] == "NORTHEAST"
        and cand[63:69] == "BERLIN"
        and cand[69:74] == "CLOCK"
    )


# Theme keywords (mirrors the prior N1 clustering vocabulary).
THEMES = {
    "navigation": {
        "DEGREES", "MINUTES", "NORTH", "SOUTH", "WEST", "EAST", "DIRECTION",
        "BEARING", "COORDINATES", "LATITUDE", "LONGITUDE", "TOWARD",
        "FIFTYTWO", "THIRTEEN", "FORTYDEGREES",
    },
    "first_person": {
        "I", "WE", "MY", "MINE", "OUR", "MYSELF", "OURSELVES",
    },
    "berlin_wall": {
        "WALL", "FALL", "GATE", "ALEXANDERPLATZ", "WELTZEITUHR", "URANIA",
        "BORNHOLMER", "BRANDENBURG", "NOVEMBER", "CROSSING", "CHECKPOINT",
        "STRIKES", "FELL", "OBSERVE",
    },
    "k2_k3_echo": {
        "BURIED", "LAYER", "PLINTH", "DUST", "WEAVE", "BREACH", "MIST",
        "CHAMBER", "CARTER", "TOMB", "PASSAGE",
    },
    "egypt": {
        "EGYPT", "CAIRO", "KARNAK", "DESERT", "PYRAMID", "STONE", "SAND",
    },
    "k5_forward": {
        "DIG", "LOOK", "SEARCH", "FIND", "BENEATH", "BELOW", "UNDER", "BEHIND",
        "WITHIN", "MARK", "POINT", "PLACE",
    },
    "espionage": {
        "AGENT", "DROP", "RENDEZVOUS", "MIDNIGHT", "RAVEN", "ASSET", "CODENAME",
        "EXFILTRATE", "STATION", "HANDLER",
    },
}


def cluster_themes(candidates: list[str]) -> dict[str, int]:
    """Count how many candidates contain ANY keyword from each theme."""
    counts: dict[str, int] = {t: 0 for t in THEMES}
    for cand in candidates:
        for theme, kws in THEMES.items():
            if any(kw in cand for kw in kws):
                counts[theme] += 1
    return counts


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--n-per", type=int, default=6, help="candidates per framing")
    p.add_argument("--framings", nargs="*", default=None,
                   help="subset of framings to run; default = all")
    p.add_argument("--dry-run", action="store_true",
                   help="print prompts only, no model calls")
    p.add_argument("--out-dir", type=Path,
                   default=Path("experiments/results/n1_ollama_outputs"))
    p.add_argument("--themes-out", type=Path,
                   default=Path("data/k4_plaintext_themes_ollama.yaml"))
    args = p.parse_args()

    framings = args.framings or list(FRAMINGS)
    bad = [f for f in framings if f not in FRAMINGS]
    if bad:
        print(f"unknown framings: {bad}; available: {list(FRAMINGS)}", file=sys.stderr)
        return 1

    args.out_dir.mkdir(parents=True, exist_ok=True)
    args.themes_out.parent.mkdir(parents=True, exist_ok=True)

    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = args.out_dir / f"run_{stamp}_{args.model.replace(':', '_').replace('/', '_')}"
    run_dir.mkdir(parents=True, exist_ok=True)

    all_candidates: list[str] = []
    compliant_candidates: list[str] = []
    per_framing: dict[str, dict] = {}

    for fname in framings:
        fdesc = FRAMINGS[fname]
        # Split n_per into batches of MAX_PER_CALL (gemma4 truncates above
        # ~25 candidates per call); concatenate results across batches.
        n_batches = (args.n_per + MAX_PER_CALL - 1) // MAX_PER_CALL
        per_batch = (args.n_per + n_batches - 1) // n_batches if n_batches else args.n_per

        if args.dry_run:
            prompt = build_prompt(fname, fdesc, per_batch)
            print(f"\n===== FRAMING: {fname} (batch {per_batch} x {n_batches}) =====\n{prompt}\n")
            continue

        print(f"[{fname}] {n_batches} batch(es) of {per_batch} via {args.model}...", flush=True)
        t0 = time.perf_counter()
        framing_cands: list[str] = []
        framing_raws: list[str] = []
        framing_errors: list[str] = []
        for bi in range(n_batches):
            prompt = build_prompt(fname, fdesc, per_batch)
            schema = build_schema(per_batch)
            try:
                raw = call_ollama(args.model, prompt, schema)
            except Exception as e:
                framing_errors.append(f"batch {bi}: {type(e).__name__}: {e}")
                continue
            framing_raws.append(raw)
            batch_cands = parse_candidates(raw)
            framing_cands.extend(batch_cands)
            print(f"  [batch {bi+1}/{n_batches}] -> {len(batch_cands)} parsed "
                  f"({time.perf_counter()-t0:.1f}s elapsed)", flush=True)

        elapsed = time.perf_counter() - t0
        compliant = [c for c in framing_cands if crib_compliant(c)]
        all_candidates.extend(framing_cands)
        compliant_candidates.extend(compliant)

        # Save raw responses (one per batch) + parsed assembled candidates
        for bi, raw in enumerate(framing_raws):
            (run_dir / f"{fname}_batch{bi:02d}_raw.txt").write_text(raw)
        (run_dir / f"{fname}_parsed.txt").write_text(
            "\n".join(framing_cands) + "\n"
        )
        per_framing[fname] = {
            "elapsed_s": round(elapsed, 1),
            "n_batches": n_batches,
            "n_parsed": len(framing_cands),
            "n_compliant": len(compliant),
            "errors": framing_errors,
        }
        print(f"[{fname}] DONE: {len(framing_cands)} parsed, "
              f"{len(compliant)} crib-compliant, {elapsed:.1f}s total")

    if args.dry_run:
        return 0

    # Cluster on ALL parsed candidates (themes) -- not just exact-97
    # crib-compliant ones, since the model often miscounts but its
    # semantic content is still informative.
    theme_counts = cluster_themes(all_candidates)
    total = max(len(all_candidates), 1)
    theme_freq = {t: c / total for t, c in theme_counts.items()}

    summary = {
        "model": args.model,
        "timestamp": stamp,
        "framings_run": framings,
        "n_per_framing": args.n_per,
        "total_parsed": len(all_candidates),
        "total_crib_compliant": len(compliant_candidates),
        "per_framing": per_framing,
        "theme_counts": theme_counts,
        "theme_frequency": {t: round(f, 2) for t, f in theme_freq.items()},
    }

    # Write YAML manually (avoid yaml dep)
    yaml_lines = []
    for k, v in summary.items():
        if isinstance(v, dict):
            yaml_lines.append(f"{k}:")
            for kk, vv in v.items():
                if isinstance(vv, dict):
                    yaml_lines.append(f"  {kk}:")
                    for kkk, vvv in vv.items():
                        yaml_lines.append(f"    {kkk}: {vvv}")
                else:
                    yaml_lines.append(f"  {kk}: {vv}")
        elif isinstance(v, list):
            yaml_lines.append(f"{k}:")
            for it in v:
                yaml_lines.append(f"  - {it}")
        else:
            yaml_lines.append(f"{k}: {v}")
    args.themes_out.write_text("\n".join(yaml_lines) + "\n")

    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    print()
    print(f"=== SUMMARY ({args.model}) ===")
    print(f"  total parsed:         {len(all_candidates)}")
    print(f"  total crib-compliant: {len(compliant_candidates)}")
    print(f"  per-theme frequency (among compliant candidates):")
    for t, f in sorted(theme_freq.items(), key=lambda kv: -kv[1]):
        bar = "#" * int(f * 30)
        print(f"    {t:14s}  {f*100:5.1f}%  {bar}")
    print(f"\nFull outputs: {run_dir}")
    print(f"Themes YAML : {args.themes_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
