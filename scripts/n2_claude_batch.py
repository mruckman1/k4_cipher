"""N2: hand-curated cipher-method hypothesis generation via Claude batch.

N1 produces plaintext candidates; N2 produces *cipher hypotheses*. Each
hypothesis must be a complete (cipher_family, params, expected_plaintext)
triple suitable for mechanical verification via src/kryptos/verify.py.

The strength of N2 over N1 is information density: rather than scaling
plaintext candidate counts, N2 generates a small number of high-quality
*structural* hypotheses informed by the full evidence stack (29 prior
negatives, four cribs, Scheidt/Sanborn quotes, K1-K3 reference texts).

Cost discipline (per [[feedback_paid_runs]])
-------------------------------------------
Defaults to DRY RUN. Sonnet 4-6 batch, ~10 requests at ~30 hypotheses each:

  Per request: ~7K input (mostly cached), ~10K output tokens
  Per request cost (Sonnet, with 90% cache hits): ~$0.08
  Total for 10 requests: ~$0.77

  Haiku 4-5 alternative: ~$0.26 total
  Opus 4-7 alternative:  ~$1.30 total

  All well under the $5 threshold; still gated behind --confirm.

Usage
-----
  # Dry-run (default; prints prompt + cost; no API call):
  uv run python scripts/n2_claude_batch.py --model sonnet --n-requests 10

  # Launch (Sonnet, $0.77 estimated):
  uv run python scripts/n2_claude_batch.py --model sonnet --n-requests 10 --confirm

Output
------
  experiments/results/n2_claude_outputs/run_<timestamp>_<model>/
    summary.json
    batch_id.txt
    hypotheses_parsed.jsonl
    raw_batch_<NN>.txt
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
import time
from pathlib import Path

try:
    from anthropic import Anthropic
    from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
    from anthropic.types.messages.batch_create_params import Request
except ImportError:
    sys.stderr.write("anthropic SDK not installed. uv sync --extra claude\n")
    sys.exit(1)


MODELS = {
    "haiku":  {"id": "claude-haiku-4-5",  "in": 0.50, "out": 2.50,  "cache_read": 0.05},
    "sonnet": {"id": "claude-sonnet-4-6", "in": 1.50, "out": 7.50,  "cache_read": 0.15},
    "opus":   {"id": "claude-opus-4-7",   "in": 2.50, "out": 12.50, "cache_read": 0.25},
}


SYSTEM_CONTEXT = """You are a cryptanalyst hypothesis generator. Your job is
to propose CONCRETE TESTABLE cipher hypotheses for Kryptos K4.

================================================================
K4 ciphertext (97 letters, positions 1-97)
================================================================

    OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR

K4 contains ALL 26 letters A-Z (verified). Position 74 has K→K self-encryption.

================================================================
Confirmed cribs (Sanborn, 2010-2020)
================================================================

  pos 22-25 (1-indexed):  EAST     -> FLRV
  pos 26-34:              NORTHEAST-> QQPRNGKSS
  pos 64-69:              BERLIN   -> NYPVTT
  pos 70-74:              CLOCK    -> MZFPK

Letter-by-letter (ACA 2013): N=B, Y=E, P=R, V=L, T=I, T=N — "Emphatically."

================================================================
Reference: K1-K3 plaintexts (Sanborn's literary register)
================================================================

K1 (Quagmire III, key PALIMPSEST, KRYPTOS-keyed; deliberate IQLUSION):
> BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT LIES THE NUANCE OF IQLUSION

K2 (Q3, key ABSCISSA, KRYPTOS-keyed; deliberate UNDERGRUUND; sculpture ends IDBYROWS due to one dropped letter at encryption time, intended end was XLAYERTWO):
> IT WAS TOTALLY INVISIBLE HOWS THAT POSSIBLE THEY USED THE EARTHS MAGNETIC FIELD X THE INFORMATION WAS GATHERED AND TRANSMITTED UNDERGRUUND TO AN UNKNOWN LOCATION X DOES LANGLEY KNOW ABOUT THIS THEY SHOULD ITS BURIED OUT THERE SOMEWHERE X WHO KNOWS THE EXACT LOCATION ONLY WW THIS WAS HIS LAST MESSAGE X THIRTY EIGHT DEGREES FIFTY SEVEN MINUTES SIX POINT FIVE SECONDS NORTH SEVENTY SEVEN DEGREES EIGHT MINUTES FORTY FOUR SECONDS WEST X LAYER TWO

K3 (two-pass columnar transposition with KRYPTOS column order, 7-wide; deliberate DESPARATLY; terminating Q):
> SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT PRESENTLY DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST X CAN YOU SEE ANYTHING Q

================================================================
Sanborn and Scheidt statements about K4
================================================================

Scheidt 2011 Kryptos Dinner: "K4 cryptography is not mathematical (although
this does not preclude it being modeled mathematically), it is simple, can
be remembered, and executed years later when used with the correct key
word/s." — argues for hand-executable cipher, not SAT/ILP design.

Sanborn 2005 Wired: "I was modifying systems and developing my own which
would make it virtually impossible for [Scheidt] to decipher all of it." —
the cipher is Scheidt's classical scheme + Sanborn's modification.

Sanborn 12 Nov 2025 Spy Museum: "Berlin Clock" = Weltzeituhr at
Alexanderplatz (NOT Mengenlehreuhr); 1989 Berlin Wall fall + 1986 Egypt
trip are the two stated K4 plaintext themes.

================================================================
HYPOTHESES ALREADY RULED OUT (do NOT propose these)
================================================================

Across 29 experiments + Tier A/B sweeps against 5,220 Sonnet candidates:

  Cipher family                        | Tested range                              | Result
  -------------------------------------|-------------------------------------------|--------
  Vigenere/Beaufort periodic           | L ∈ {1..30}, both alphabets, 3 conventions| 0 hits
  Quagmire III/IV periodic             | L ∈ {1..30}, both alphabets               | 0 hits
  Hill cipher                          | block sizes 2..8, both alphabets          | 0 hits
  Autokey (plaintext / ciphertext)     | primer L ∈ {1..10}                        | 0 hits
  Caesar (L=1 Vigenere)                | all 26 shifts                             | 0 hits
  Running-key Vigenere/Beaufort        | Carter, Smith, Buchan, K1-K3 texts        | 0 hits
  Gromark / Vimark                     | base-5/10 primers, exhaustive             | 0 hits
  Trifid 3x3x3 hill-climb              | periods {5,7,9}, all 5,220 candidates     | best 37/97
  W-segmented heterogeneous            | 6 segs × L ∈ {2..6} × 3 convs             | 0 hits
  Q3 + arithmetic offset (a×i+b)       | a ∈ {1..25}, b ∈ {0..25}, L ∈ {1..15}     | 0 hits
  Q3 + single positional perturbation  | ±5 shifts, 600 letter subs, L ∈ {2..26}   | 0 hits (best hex -21)
  Q3 ∘ positional_remap (10 remaps)    | rev/swap/rotate/bit_rev/K3-cols           | 0 hits
  Q3 ∘ columnar W=3,5,7 (all perms)    | W=10 already tested in exp 015            | 0 hits at hexagram
  Double-Q3 (Q3 ∘ Q3)                  | L_A ∈ {1..15} × L_B ∈ {1..15}             | 0 hits
  Weltzeituhr keystream                | 85,680 configurations                     | 0 hits
  Mengenlehreuhr keystream             | 180 configurations                        | 0 hits
  Generator library (20.5k generators) | mathematical constants, LCG, Fibonacci,…  | 0 hits at >= 8 consec
  ShinkaEvolve LLM-mutation search     | 223 generations Opus+Flash bandit         | best score -40 (cribs not satisfied)

Structurally ruled out by K4's letter completeness (all 26 letters present):
  Bifid, Playfair, Two-square, Four-square (5x5 grid, one letter merged)
  ADFGVX / ADFGX (length-doubling)

================================================================
Primitives available in src/kryptos/ciphers/ that you may invoke
================================================================

Use these cipher class names verbatim in your hypotheses:

  Vigenere(key, alphabet)
  Beaufort(key, alphabet)
  QuagmireI(key, alphabet_keyword)
  QuagmireII(key, alphabet_keyword)
  QuagmireIII(key, alphabet_keyword)         # K1/K2 cipher
  QuagmireIV(key, alphabet_keyword)
  Autokey(primer, alphabet, mode={plaintext, ciphertext})
  Gromark(primer, alphabet_keyword)
  Vimark(primer, alphabet_keyword)
  RunningKey(key_text, alphabet, offset)
  ColumnarTransposition(keyword)             # K3 cipher
  Hill(key_matrix, alphabet)
  Playfair(keyword, merge=("I","J"))
  Bifid(keyword, period, merge=("I","J"))
  Trifid(keyword, period)
  TwoSquare(top_keyword, bottom_keyword)
  FourSquare(tr_keyword, bl_keyword)
  ADFGVX(grid_keyword, transposition_keyword)
  Nicodemus(keyword)                          # transposition + per-col Vigenere
  WSegmented([cipher_per_seg])                # exp 020 / Lethuillier
  Compose([cipher_A, cipher_B, …])           # arbitrary chain

Sanborn-modification helpers:
  FinalCaesar(shift)                          # post-encryption Caesar
  PrependCaesar(shift)                        # pre-encryption Caesar
  PositionalRemap(perm)                       # permutation of positions

Alphabets: STANDARD (A-Z), KRYPTOS_KEYED (K1/K2 alphabet), KRYPTOS_WITH_EXTRA_L (27-letter sculpture variant).

================================================================
What makes a HIGH-QUALITY N2 hypothesis
================================================================

1. STRUCTURAL: not already in the ruled-out list. Look for cipher
   constructions that exploit K4's specific features (97 chars,
   K→K at 74, W positions at 20/36/48/58/74, all 26 letters present).

2. HAND-EXECUTABLE: Scheidt's "simple, memorable" constraint. A
   sculptor with a pencil and a printed key should be able to encrypt
   97 characters in an afternoon. Rules out anything requiring tables
   of more than ~30 entries or per-position lookups.

3. SANBORN-MODIFIED: assume Scheidt's classical backbone + one
   non-trivial modification Sanborn added. Most-likely modifications
   per [data/plaintext_priors.yaml]: FinalCaesar shift, positional
   remap (reverse / swap / K3-style columnar), W-segment swap,
   one-letter encoding error (cf. K2's IDBYROWS).

4. PLAINTEXT FIT: the proposed plaintext should sit in Sanborn's
   register (K1-K3 style; X separators; deliberate Sanborn-style
   misspellings; 1989 Berlin Wall and/or 1986 Egypt thematic anchors;
   possible K5-forward instruction).

5. CONCRETE & VERIFIABLE: every parameter must be specified. The
   verifier needs cipher_class(**params).encrypt(plaintext) == K4.
"""


def build_user_prompt(n_per_request: int, request_seed: int) -> str:
    return f"""Propose {n_per_request} distinct, SPECIFIC, MECHANICALLY-TESTABLE cipher
hypotheses for K4.

For each hypothesis, return ONE JSON object with this exact structure:

  {{
    "cipher_class": "<one of the listed cipher classes>",
    "params": {{ ...all parameters needed to instantiate the class... }},
    "post_transforms": [<optional list of FinalCaesar / PositionalRemap entries>],
    "expected_plaintext": "<exactly 97 uppercase A-Z letters, no spaces, with cribs at correct positions>",
    "rationale": "<1-2 sentences explaining WHY this hypothesis is novel & worth testing>"
  }}

The expected_plaintext must:
  - Be exactly 97 uppercase A-Z letters (no spaces, no punctuation)
  - Have EAST at positions 22-25, NORTHEAST at 26-34, BERLIN at 64-69, CLOCK at 70-74
  - Read as plausible English in Sanborn's K1-K3 register

The cipher_class + params + (optional post_transforms) must produce K4
when applied to expected_plaintext under standard semantics.

Diversify across hypotheses: use different cipher_class options, different
key/keyword choices, different post_transforms. Avoid the ruled-out list.

This is generation pass #{request_seed}. Generate {n_per_request} UNIQUE hypotheses.

Return JSON: {{"hypotheses": [...{n_per_request} entries...]}}.
Return JSON only. No prose, no markdown, no code fences."""


def load_api_key() -> str:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return key
    env_file = Path("shinka/.env")
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("ANTHROPIC_API_KEY="):
                return line.split("=", 1)[1].strip()
    sys.stderr.write("ANTHROPIC_API_KEY not found.\n")
    sys.exit(1)


def estimate_cost(model_key: str, n_requests: int,
                  cached_input_tok: int, output_tok: int,
                  cache_hit: float = 0.85) -> dict:
    m = MODELS[model_key]
    total_input = n_requests * cached_input_tok
    cached = total_input * cache_hit
    uncached = total_input - cached
    cost_in = uncached / 1e6 * m["in"] + cached / 1e6 * m["cache_read"]
    cost_out = (n_requests * output_tok) / 1e6 * m["out"]
    return {
        "model": m["id"],
        "n_requests": n_requests,
        "cached_input_tokens": int(cached),
        "uncached_input_tokens": int(uncached),
        "output_tokens": n_requests * output_tok,
        "cost_input_usd": round(cost_in, 4),
        "cost_output_usd": round(cost_out, 4),
        "cost_total_usd": round(cost_in + cost_out, 2),
    }


def _strip_code_fences(s: str) -> str:
    m = re.search(r"```(?:json)?\s*(.+?)```", s, re.DOTALL)
    return m.group(1) if m else s


def parse_hypotheses(raw: str) -> list[dict]:
    text = _strip_code_fences(raw).strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Try to truncate to last complete `}` and close array
        last = text.rfind("}")
        if last < 0:
            return []
        fixed = text[: last + 1] + "]}"
        try:
            data = json.loads(fixed)
        except json.JSONDecodeError:
            return []
    return data.get("hypotheses", []) if isinstance(data, dict) else []


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--model", choices=list(MODELS), default="sonnet")
    p.add_argument("--n-requests", type=int, default=10)
    p.add_argument("--n-per-request", type=int, default=30)
    p.add_argument("--confirm", action="store_true",
                   help="required to actually launch (paid run protection)")
    p.add_argument("--out-dir", type=Path,
                   default=Path("experiments/results/n2_claude_outputs"))
    p.add_argument("--poll-interval", type=int, default=30)
    p.add_argument("--resume", type=str, default=None)
    args = p.parse_args()

    # Estimate
    input_tok = 7_000   # system context (cached) + user prompt
    output_tok = 12_000  # ~30 hypotheses × ~400 tokens each
    estimate = estimate_cost(args.model, args.n_requests, input_tok, output_tok)

    print("=" * 60)
    print("N2 Claude Batch — cipher-method hypothesis generation")
    print("=" * 60)
    print(f"  model:                  {estimate['model']}")
    print(f"  n_requests:             {estimate['n_requests']}")
    print(f"  n_per_request:          {args.n_per_request}")
    print(f"  total hypotheses:       ~{estimate['n_requests'] * args.n_per_request}")
    print(f"  cached input tokens:    ~{estimate['cached_input_tokens']:,}")
    print(f"  uncached input tokens:  ~{estimate['uncached_input_tokens']:,}")
    print(f"  output tokens:          ~{estimate['output_tokens']:,}")
    print(f"  est cost (input):       ${estimate['cost_input_usd']:.4f}")
    print(f"  est cost (output):      ${estimate['cost_output_usd']:.4f}")
    print(f"  est cost TOTAL:         ${estimate['cost_total_usd']:.2f}")
    print("=" * 60)

    if not (args.confirm or args.resume):
        print("\nDry run — no API call. Re-run with --confirm to launch.")
        return 0

    api_key = load_api_key()
    client = Anthropic(api_key=api_key)

    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_model = MODELS[args.model]["id"].replace("/", "_")
    run_dir = args.out_dir / f"run_{stamp}_{safe_model}"
    run_dir.mkdir(parents=True, exist_ok=True)

    if args.resume:
        batch_id = args.resume
        print(f"\nResuming batch {batch_id} ...")
    else:
        requests = []
        for i in range(args.n_requests):
            requests.append(Request(
                custom_id=f"n2_hyp_{i:03d}",
                params=MessageCreateParamsNonStreaming(
                    model=MODELS[args.model]["id"],
                    max_tokens=output_tok + 1024,
                    system=[
                        {
                            "type": "text",
                            "text": SYSTEM_CONTEXT,
                            "cache_control": {"type": "ephemeral"},
                        },
                    ],
                    messages=[{
                        "role": "user",
                        "content": build_user_prompt(args.n_per_request, i),
                    }],
                    temperature=0.95,
                ),
            ))
        print(f"\nSubmitting batch with {len(requests)} requests ...")
        batch_id = client.messages.batches.create(requests=requests).id
        (run_dir / "batch_id.txt").write_text(batch_id + "\n")
        print(f"Batch id: {batch_id}")

    # Poll
    print("\nPolling batch ...")
    t0 = time.time()
    while True:
        batch = client.messages.batches.retrieve(batch_id)
        if batch.processing_status == "ended":
            print(f"Batch ended: {batch.request_counts}")
            break
        counts = batch.request_counts
        print(f"  [{int(time.time()-t0):5d}s] {batch.processing_status}: "
              f"ok={counts.succeeded} err={counts.errored} proc={counts.processing}",
              flush=True)
        time.sleep(args.poll_interval)

    # Retrieve
    print("Retrieving results ...")
    hyp_records: list[dict] = []
    for result in client.messages.batches.results(batch_id):
        cid = result.custom_id
        if result.result.type != "succeeded":
            (run_dir / f"{cid}_error.json").write_text(
                json.dumps(result.result.model_dump(), default=str)
            )
            continue
        text = "".join(b.text for b in result.result.message.content
                       if getattr(b, "type", None) == "text")
        (run_dir / f"{cid}_raw.txt").write_text(text)
        for h in parse_hypotheses(text):
            h["_source_custom_id"] = cid
            hyp_records.append(h)

    (run_dir / "hypotheses_parsed.jsonl").write_text(
        "\n".join(json.dumps(h) for h in hyp_records) + "\n"
    )
    (run_dir / "summary.json").write_text(json.dumps({
        "batch_id": batch_id,
        "model": MODELS[args.model]["id"],
        "n_requests": args.n_requests,
        "n_per_request": args.n_per_request,
        "n_hypotheses_parsed": len(hyp_records),
        "cost_estimate": estimate,
    }, indent=2))

    print()
    print(f"=== Hypotheses parsed: {len(hyp_records)} ===")
    print(f"Output: {run_dir}")
    print(f"\nNext step: verify each hypothesis with:")
    print(f"  uv run python scripts/n2_verify.py --hypotheses-dir {run_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
