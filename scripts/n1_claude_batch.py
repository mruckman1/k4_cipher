"""N1 Claude batch: plaintext-content inference for Kryptos K4 via the
Anthropic Message Batches API.

Mirrors scripts/n1_ollama.py's output layout so the existing
scripts/cluster_n1_clean.py downstream works without modification:
each framing writes ``<framing>_parsed.txt`` (one assembled 97-char
candidate per line) into a timestamped run directory under
``experiments/results/n1_claude_outputs/``.

Purpose
-------
Cross-model validation of the gemma4 5,100-candidate N1 themes. If
Claude (Sonnet/Opus) converges on the same theme distribution
(k5_forward dominant, navigation / first_person / berlin_wall in the
middle band, egypt weak), the gemma4 prior is real. If it collapses,
the prior was gemma4-bias.

Cost discipline (per [[feedback_paid_runs]])
-------------------------------------------
Defaults to DRY RUN. No API calls happen without explicit flags:

  --smoke              ~180 candidates, single batch.   <$1 on any model.
  --full --confirm     ~5,100 candidates, six framings. Gated.

Batch pricing (50% off standard) with prompt caching of the heavy
inference context (~2,500 tokens cached at 90% off after first call):

                       Smoke (180)    Full (5,100)
  haiku   (4-5)        ~$0.07         ~$2.20
  sonnet  (4-6)        ~$0.22         ~$5.70
  opus    (4-7)        ~$0.36         ~$9.10

Numbers above are upper bounds (assume 30% cache hit; actual usage
typically 50-90% gives lower cost).

Usage
-----
  # Dry-run (default; prints prompts + cost estimate; no API call):
  uv run python scripts/n1_claude_batch.py --model sonnet --n-per 850

  # Smoke (<$1, launches without --confirm gate):
  uv run python scripts/n1_claude_batch.py --model sonnet --smoke

  # Full 5,100-candidate run (requires explicit --confirm):
  uv run python scripts/n1_claude_batch.py --model sonnet --full --confirm

Output
------
  experiments/results/n1_claude_outputs/run_<timestamp>_<model>/
    {framing}_parsed.txt         one 97-char candidate per line
    {framing}_batch{NN}_raw.txt  raw JSON response per request
    summary.json                 batch_id, costs, per-framing stats
    batch_id.txt                 the Anthropic batch ID (for resume)
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
import time
from collections import Counter
from pathlib import Path

try:
    from anthropic import Anthropic
    from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
    from anthropic.types.messages.batch_create_params import Request
except ImportError:
    sys.stderr.write(
        "anthropic SDK not installed. Run: uv sync --extra claude\n"
    )
    sys.exit(1)


# ---------------------------------------------------------------- pricing

# Per-MTok batch rates from docs.claude.com (Nov 2025). Cache reads are
# ~10% of input rate (the docs publish per-model cache_read pricing;
# these are conservative defaults).
MODELS = {
    "haiku":  {"id": "claude-haiku-4-5",  "in": 0.50, "out": 2.50,  "cache_read": 0.05},
    "sonnet": {"id": "claude-sonnet-4-6", "in": 1.50, "out": 7.50,  "cache_read": 0.15},
    "opus":   {"id": "claude-opus-4-7",   "in": 2.50, "out": 12.50, "cache_read": 0.25},
}


# ---------------------------------------------------------------- prompts

DEFAULT_FRAMINGS: dict[str, str] = {
    "espionage": (
        "You are reasoning about Cold-War-era CIA / Berlin-station tradecraft. "
        "If the K4 plaintext mentions agents, dead drops, exfiltration, codenames, "
        "Wall crossings, or surveillance logs, what plausible English text could it be?"
    ),
    "navigation": (
        "You are reasoning about Sanborn's known love of coordinates and geography. "
        "K2 spelled out the sculpture's own GPS in plain English ('THIRTYEIGHTDEGREES "
        "FIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTH...'). If K4's plaintext is "
        "navigational, what coordinates or directional language could it be? "
        "EAST + NORTHEAST + BERLIN are heavily directional."
    ),
    "k2_k3_echo": (
        "You are reasoning about stylistic continuity with K2 and K3's prose. K2 "
        "is an excavation/burial narrative; K3 quotes Howard Carter's Tutankhamen "
        "diary. K4 may continue the buried-device or Carter motifs. What text "
        "could echo that?"
    ),
    "berlin_wall": (
        "You are reasoning about the November 1989 fall of the Berlin Wall. Sanborn "
        "confirmed in Nov 2025 that K4's CLOCK refers to the Weltzeituhr at "
        "Alexanderplatz -- the gathering place for the crowds that brought down the "
        "Wall. The 1989 timing + BERLIN + CLOCK + EAST/NORTHEAST direction "
        "(Bornholmer Strasse is northeast of Alexanderplatz) suggests Wall-fall "
        "imagery. What text could it be?"
    ),
    "surveyor": (
        "You are reasoning about Sanborn's day job as a sculptor and his stated "
        "hint that K4 'tells you to do something with the sculpture itself'. K4 "
        "might be a tactile/spatial instruction. What text could it be?"
    ),
    "k5_forward": (
        "You are reasoning about Sanborn's Nov 2025 confirmation that K5 exists, "
        "is 97 characters, will appear in a public space after K4 is "
        "cryptographically solved, and shares words at the same positions as K4. "
        "K4 might be an INSTRUCTION pointing forward to K5. What text could it be?"
    ),
}

# Expanded framings — built after analyzing what the default 6 framings
# produced and what they missed. Each one targets a specific gap in
# Sonnet 4-6's first 5,220-candidate prior. Use --framing-set=expanded or
# --framing-set=both to include these. Best paired with Opus 4.7 budget run.
EXPANDED_FRAMINGS: dict[str, str] = {
    "bornholmer_specific": (
        "You are reasoning about the SPECIFIC moment the Berlin Wall fell. "
        "On 9 November 1989, at approximately 23:30 CET, Stasi guard "
        "Harald Jaeger opened the Bornholmer Strasse checkpoint, the FIRST "
        "crossing to fall, after the Schabowski press conference. Sanborn "
        "was in Berlin during this week. K4 plaintext may name Bornholmer "
        "Strasse, Schabowski, Jaeger, or the time 23:30. What text could it be?"
    ),
    "egypt_1986_specific": (
        "You are reasoning about Sanborn's stated 1986 Egypt trip (one of "
        "two confirmed K4 plaintext influences). The trip was Sanborn's "
        "SECOND visit. Specific sites Sanborn cited in interviews: Karnak, "
        "the Valley of the Kings, the Cairo Museum, the Sphinx, Luxor. "
        "K4 plaintext may name a specific Egyptian site, an artifact, or "
        "describe a sensory observation at one of these places. K3 already "
        "quoted Carter's tomb diary; K4 may extend that. What text could it be?"
    ),
    "k2_coords_explicit": (
        "You are reasoning about explicit geographic coordinates. K2 spelled "
        "out 38°57'06.5\" N, 77°08'44\" W in plain English. K4 may contain "
        "a different set of coordinates: Bornholmer Strasse is approximately "
        "52°33'18\" N, 13°23'47\" E (FIFTYTWODEGREES THIRTYTHREE etc); "
        "Alexanderplatz is 52°31'17\" N, 13°24'45\" E. Render coordinates "
        "spelled out as K2-style English digits. What text could it be?"
    ),
    "weltzeituhr_visual": (
        "You are reasoning about Erich John's Weltzeituhr (1969) at "
        "Alexanderplatz: a cylindrical drum with 24 trapezoidal columns "
        "(one per UTC offset, city names labeled), a zodiac ring rotating "
        "once per year, and a planetary armillary on top. Crowds gathered "
        "around it on 9 November 1989. K4 plaintext may describe the clock "
        "concretely: ROTATING DRUM, TWENTY FOUR ZONES, ZODIAC, PLANETARY, "
        "BRONZE, COLUMNS. What text could it be?"
    ),
    "layer_three_forward": (
        "You are reasoning about K2's ending. K2 ended with 'X LAYER TWO' "
        "(Sanborn-intended; sculpture has the dropped-X 'IDBYROWS' typo). "
        "K3 quoted Carter's tomb opening, fitting 'LAYER TWO' = digging "
        "deeper. K4 may end with 'X LAYER THREE' or similar layer-pointer "
        "to K5. K4 has 97 chars; positions 75-97 are unconstrained 23 letters "
        "at the end. What text could fit a LAYER THREE final phrase pattern?"
    ),
    "carter_continuation": (
        "You are reasoning about K3 as the source pattern. K3 quotes Howard "
        "Carter's 26 November 1922 diary near-verbatim: 'WITH TREMBLING "
        "HANDS I MADE A TINY BREACH...CAN YOU SEE ANYTHING'. K4 may continue "
        "Carter — the entry continues with 'AT FIRST I COULD SEE NOTHING' "
        "or pivot to the answer 'YES WONDERFUL THINGS'. What text could "
        "extend Carter's tomb-opening narrative into K4?"
    ),
    "k1_poetic_echo": (
        "You are reasoning about K1's literary register specifically. K1 "
        "is poetic, abstract, about PERCEPTION: 'BETWEEN SUBTLE SHADING AND "
        "THE ABSENCE OF LIGHT LIES THE NUANCE OF IQLUSION'. K4 may share "
        "K1's metaphysical-about-seeing register, but applied to the Berlin "
        "Wall or Egypt theme. Avoid imperatives; favor descriptive, "
        "observational, sensory abstract prose. What text could it be?"
    ),
    "first_person_witness": (
        "You are reasoning about Sanborn as first-person witness in 1989 "
        "Berlin. Sanborn was in Berlin during the Wall's fall. K4 may be "
        "an I-witnessed scene: I STOOD, I WATCHED, I SAW, I FELT, I HEARD. "
        "Use first-person observational past tense. What did Sanborn see, "
        "hear, smell, feel at Alexanderplatz on the night the Wall fell?"
    ),
    "descriptive_no_imperative": (
        "You are reasoning ADVERSARIALLY: Sanborn's K4 plaintext is "
        "purely descriptive, NOT an instruction. No DIG, LOOK, FIND, SEEK, "
        "GO, SEARCH, LOCATE, BENEATH, BEYOND. K1-K3 are all descriptive; "
        "K4 is the same. K5 forward-reference is structural (shared words "
        "at same positions), not imperative. Write descriptive observational "
        "prose in Sanborn's K1-K3 register. What text could it be?"
    ),
    "k4_self_referential": (
        "You are reasoning about K4 as self-referential to the sculpture itself. "
        "Sanborn has hinted K4 'tells you to do something with the sculpture' "
        "but also has explicitly NOT confirmed K4 is imperative. K4 may "
        "describe the sculpture: the four panels, the bronze, the courtyard, "
        "the engraved letters, the petrified wood, the CIA Langley setting, "
        "the lodestone, the compass rose, the Morse plates. What text could "
        "describe the sculpture itself in Sanborn's voice?"
    ),
}

# Additional framings added for breadth — purely to widen the prior, not
# to bias toward any specific content. Each is a distinct angle on what
# K4's plaintext could be.
BREADTH_FRAMINGS: dict[str, str] = {
    "schliemann_memoirs": (
        "You are reasoning about Heinrich Schliemann's memoirs as a possible "
        "source text. Schliemann was a Sanborn-favorite per the 2009 Berman "
        "oral history. Schliemann's archeological narrative voice mixes "
        "first-person observation with classical / Trojan references. K3 "
        "quoted Carter's tomb diary near-verbatim; K4 may similarly be a "
        "near-direct quote or paraphrase from Schliemann's writings about "
        "Troy, Mycenae, or his 1880s German-language correspondence. What "
        "Schliemann-register English text could it be?"
    ),
    "near_verbatim_quote": (
        "You are reasoning about K4 as a NEAR-VERBATIM quote from a known "
        "historical text (the way K3 quoted Carter's diary). Candidate source "
        "texts Sanborn has cited or alluded to: Hofstadter's GODEL ESCHER "
        "BACH, Buchan's THIRTY NINE STEPS, Smith's TUTANKHAMEN, classical "
        "Greek tragedy, German Romantic poetry (Heine, Goethe). K4 may be a "
        "fragment of one of these with a deliberate misspelling. What text "
        "could it be?"
    ),
    "morse_thematic_echo": (
        "You are reasoning about the seven Morse plates engraved on granite "
        "in the Kryptos courtyard: SOS / LUCID MEMORY / T IS YOUR POSITION / "
        "SHADOW FORCES / VIRTUALLY INVISIBLE / DIGETAL INTERPRETATIT / RQ. "
        "Their letter-distribution doesn't match K4 (so they're not the key "
        "or source) but they're thematic gloss. K4 plaintext may pick up "
        "those motifs: surveillance, memory, position, shadow, virtuality, "
        "digital interpretation. What text could echo the Morse-plate themes?"
    ),
    "non_english_loanword": (
        "You are reasoning about K4 potentially including non-English "
        "loanwords. K4 is uppercase A-Z (per K1-K3 convention), but words "
        "like BERLINER, WELTZEITUHR, ALEXANDERPLATZ, BORNHOLMER are German "
        "transliterations. Egypt-1986 theme could give KAIROBYNILE, "
        "KARNAKDOORS, LUXORSANDS. What German/Egyptian-loanword K4 text "
        "in uppercase ASCII could it be?"
    ),
    "dedication_day_1990": (
        "You are reasoning about Sanborn's 3 November 1990 sculpture "
        "dedication at CIA Langley. K2 references the sculpture's own GPS "
        "and ends with LAYER TWO; K4 may similarly self-reference its "
        "dedication date (THIRD NOVEMBER, NINETEEN NINETY) or context "
        "(LANGLEY, VIRGINIA, NEW HEADQUARTERS BUILDING). What text could "
        "anchor K4 in its dedication moment?"
    ),
    "sensory_specific": (
        "You are reasoning about K4 as sensory observation — but NOT visual. "
        "K3 was visual (peering through a breach). K4 may foreground a "
        "different sense: sound (footsteps echoing, train whistle, bells, "
        "crowd noise), smell (cigarette smoke, pine, sand, salt), touch "
        "(cold bronze, rough granite, warm hand on wall), taste. What "
        "non-visual sensory K4 text could it be in Sanborn's register?"
    ),
    "kobek_byrne_archival": (
        "You are reasoning about K4 self-referencing the archival recovery "
        "process. Sanborn donated the K4 coding charts to the Smithsonian "
        "Archives of American Art in ~2023; Jarett Kobek and Richard Byrne "
        "assembled the plaintext from these in Sept 2025. K4 may have been "
        "written with awareness it'd eventually be archive-recovered. What "
        "text could allude to discovery, archive, paper, ink, time, recovery?"
    ),
    "k1_perception_paradox": (
        "You are reasoning specifically about K1's paradox structure: "
        "'BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT LIES THE NUANCE "
        "OF IQLUSION' — a paradox about perception under partial occlusion. "
        "K4 may share this structure: a paradox or partial-revelation "
        "statement about seeing, knowing, hiding, or revealing. Not Berlin, "
        "not Egypt — abstract philosophical perception. What text could it be?"
    ),
    # Egypt-1986 re-weighting framings — Sanborn explicitly named the 1986
    # Egypt trip as one of TWO stated K4 plaintext influences (Spy Museum
    # talk, Nov 2025). Sonnet's first pass weighted Egypt at only 5.3% —
    # a clear model-coverage bias since Sanborn's confirmation gives Egypt
    # ~50% prior weight. These framings widen Egypt coverage without
    # constraining toward any specific Egypt sub-narrative.
    "karnak_temple_observation": (
        "You are reasoning about Sanborn's 1986 visit to Karnak Temple "
        "(Luxor, Egypt). Karnak is the largest religious building ever "
        "constructed: the hypostyle hall has 134 sandstone columns each "
        "10m tall, hieroglyphs deeply carved, dappled light filtering "
        "between columns. Sanborn — a sculptor — would have studied "
        "stone surfaces and carvings. K4 may be a Karnak observation: "
        "the columns, the carved hieroglyphs, the sandstone, the light. "
        "What Karnak-grounded K4 text in Sanborn's register could it be?"
    ),
    "valley_of_kings_tomb": (
        "You are reasoning about Sanborn's 1986 visit to the Valley of "
        "the Kings (Luxor, Egypt) — where Tutankhamen's tomb is. K3 "
        "quotes Howard Carter's 1922 diary about opening Tutankhamen's "
        "tomb (KV62). K4 may be Sanborn's own present-tense observation "
        "of standing in a Valley tomb sixty years after Carter: rock-cut "
        "burial chamber, hieroglyphs, descent into stone, dust, sealed "
        "doorways, antechambers. What Valley-of-the-Kings K4 text could "
        "extend the K3 Carter motif into the first-person 1986 present?"
    ),
    "cairo_museum_artifact": (
        "You are reasoning about Sanborn's 1986 visit to the Cairo Museum "
        "(Egyptian Museum on Tahrir Square). Specific objects Sanborn "
        "would have seen: Tutankhamen's gold mask, alabaster canopic "
        "jars, the Narmer Palette, Akhenaten colossi, royal mummies. "
        "K4 may center on one specific artifact, its case, its lighting, "
        "Sanborn's reaction. What Cairo-Museum-grounded K4 text could it be?"
    ),
}

ALL_FRAMINGS = {**DEFAULT_FRAMINGS, **EXPANDED_FRAMINGS, **BREADTH_FRAMINGS}


def select_framings(framing_set: str) -> dict[str, str]:
    if framing_set == "default":
        return DEFAULT_FRAMINGS
    if framing_set == "expanded":
        return EXPANDED_FRAMINGS
    if framing_set == "breadth":
        return BREADTH_FRAMINGS
    if framing_set == "both":   # default + expanded (back-compat)
        return {**DEFAULT_FRAMINGS, **EXPANDED_FRAMINGS}
    if framing_set == "all":
        return ALL_FRAMINGS
    raise ValueError(f"unknown framing_set: {framing_set!r}; "
                     f"use 'default', 'expanded', 'breadth', 'both', or 'all'")


# Back-compat alias for code that previously used FRAMINGS
FRAMINGS = DEFAULT_FRAMINGS

SYSTEM_PROMPT_TAIL = """

STRUCTURAL CONSTRAINTS ON K4 PLAINTEXT
======================================

- K4 ciphertext contains every letter A-Z (verified). Plaintexts that
  use only a subset of letters are not invalidated by this — the cipher
  determines output letter coverage.
- Position 74 (last K of CLOCK) is a self-encryption (plaintext K
  encrypts to ciphertext K). This is a constraint on the cipher, not
  the plaintext.

ANTI-PATHOLOGY GUARDRAILS (avoid these failure modes)
====================================================

1. DO NOT copy substrings from K4 CIPHERTEXT into your free spans.
   The K4 ciphertext is:
     OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAW
     INFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR
   Free spans must be ORIGINAL plaintext English, not ciphertext
   fragments. If your free_b begins with letters that resemble the
   ciphertext at positions 35-63 (OTWTQSJQSSEKZZWATJKLUDIAWINFB), you
   have copied the ciphertext — this is a known LM failure mode.

2. Make grammatical fit at crib boundaries. The full 97-char plaintext
   should read smoothly. Avoid lumpy seams like
   "AND BEY X EASTNORTHEAST THE SECRET IS BURIED" where letters before
   and after a crib don't grammatically chain. Examples of good fit:
       "...HEADING NEAR THE EASTNORTHEAST CORNER OF THE PLAZA..."
       "...A WIND CAME FROM EASTNORTHEAST OVER THE COBBLES..."
       "...WE LEFT THE BERLINCLOCK CHIMING IN THE BACKGROUND..."

3. Use exactly the requested span lengths: free_a = 21, free_b = 29,
   free_c = 23. Letters only, uppercase A-Z. No spaces, no digits, no
   punctuation, no padding letters unless they fit semantically.

4. Do NOT pad with strings of X letters or repeated letters to make
   the count work. Each character should carry meaning.

OUTPUT FORMAT
=============

Return ONLY a JSON object with this exact structure:

  {"candidates": [
    {
      "free_a_21_chars": "<exactly 21 uppercase A-Z letters>",
      "free_b_29_chars": "<exactly 29 uppercase A-Z letters>",
      "free_c_23_chars": "<exactly 23 uppercase A-Z letters>"
    },
    ... <N total candidates>
  ]}

The four cribs (EAST at 22-25, NORTHEAST at 26-34, BERLIN at 64-69,
CLOCK at 70-74) will be inserted at the correct positions automatically;
you only provide the three free spans:

  free_a_21_chars: opens the plaintext (positions 1-21)
  free_b_29_chars: between NORTHEAST and BERLIN (positions 35-63)
  free_c_23_chars: closes the plaintext (positions 75-97)

When the four cribs are inserted between your three spans, the full
97-character text should read as plausible English in the requested
framing. Words may run together with no spaces (standard for Kryptos
plaintexts).

Return ONLY the JSON. No prose, no markdown, no code fences.
"""


def load_k4_inference_context() -> str:
    """The heavy system context that gets prompt-cached across requests."""
    p = Path("data/k4_inference_context.md")
    if not p.exists():
        sys.stderr.write(f"missing: {p}\n")
        sys.exit(1)
    return p.read_text()


def build_user_prompt(framing_name: str, framing_desc: str, n: int) -> str:
    return f"""FRAMING ({framing_name}): {framing_desc}

Generate {n} DISTINCT candidate K4 plaintexts under this framing.

Vary them substantially in vocabulary, sentence structure, and specific
imagery. The N candidates should not be near-duplicates of each other.

Output the JSON object described in the system prompt. {n} candidates total."""


# ---------------------------------------------------------------- parsing
# Mirrors scripts/n1_ollama.py::parse_candidates / _pad_or_truncate so
# the assembled candidates have the same shape and feed cluster_n1_clean.py
# unchanged.

def _pad_or_truncate(s: str, target: int) -> str:
    cleaned = "".join(c for c in str(s).upper() if "A" <= c <= "Z")
    if len(cleaned) < target:
        cleaned = cleaned + "X" * (target - len(cleaned))
    return cleaned[:target]


def _strip_code_fences(text: str) -> str:
    """Claude sometimes wraps JSON in ```json ... ``` fences despite the
    instruction. Strip them."""
    m = re.search(r"```(?:json)?\s*(.+?)```", text, re.DOTALL)
    return m.group(1) if m else text


def _try_recover_partial_json(raw: str) -> dict:
    raw = _strip_code_fences(raw).strip()
    if "candidates" not in raw:
        return {}
    last = raw.rfind("}")
    if last < 0:
        return {}
    fixed = raw[: last + 1] + "]}"
    try:
        return json.loads(fixed)
    except json.JSONDecodeError:
        return {}


def parse_candidates(raw_text: str) -> list[str]:
    text = _strip_code_fences(raw_text).strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = _try_recover_partial_json(text)
    cands_in = data.get("candidates", []) if isinstance(data, dict) else []
    out: list[str] = []
    for c in cands_in:
        if not isinstance(c, dict):
            continue
        a = _pad_or_truncate(c.get("free_a_21_chars", ""), 21)
        b = _pad_or_truncate(c.get("free_b_29_chars", ""), 29)
        cc = _pad_or_truncate(c.get("free_c_23_chars", ""), 23)
        assembled = a + "EAST" + "NORTHEAST" + b + "BERLIN" + "CLOCK" + cc
        if len(assembled) == 97 and assembled.isalpha() and assembled.isupper():
            out.append(assembled)
    return out


# ---------------------------------------------------------------- cost

# Empirical sizings (validate on smoke run, adjust if needed).
INPUT_TOKENS_PER_REQUEST = 3_000   # ~2500 cached context + framing + schema reminder
OUTPUT_TOKENS_PER_REQUEST = 4_000  # 30 candidates x ~120 tokens each
CACHE_HIT_RATE = 0.30              # conservative; docs cite 30-98%
CANDIDATES_PER_REQUEST = 30


def estimate_cost(model_key: str, total_candidates: int) -> dict:
    m = MODELS[model_key]
    n_req = max(1, (total_candidates + CANDIDATES_PER_REQUEST - 1) // CANDIDATES_PER_REQUEST)

    input_tok = n_req * INPUT_TOKENS_PER_REQUEST
    output_tok = n_req * OUTPUT_TOKENS_PER_REQUEST

    cached_tok = input_tok * CACHE_HIT_RATE
    uncached_tok = input_tok - cached_tok

    cost_in = uncached_tok / 1e6 * m["in"] + cached_tok / 1e6 * m["cache_read"]
    cost_out = output_tok / 1e6 * m["out"]
    return {
        "model": m["id"],
        "n_requests": n_req,
        "input_tokens_est": input_tok,
        "output_tokens_est": output_tok,
        "cache_hit_assumed": CACHE_HIT_RATE,
        "cost_input_usd": round(cost_in, 4),
        "cost_output_usd": round(cost_out, 4),
        "cost_total_usd": round(cost_in + cost_out, 2),
    }


# ---------------------------------------------------------------- api key

def load_api_key() -> str:
    """Look in env first, fall back to shinka/.env where the existing
    OPENROUTER_API_KEY / ANTHROPIC_API_KEY values already live."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return key

    env_file = Path("shinka/.env")
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("ANTHROPIC_API_KEY="):
                return line.split("=", 1)[1].strip()

    sys.stderr.write(
        "ANTHROPIC_API_KEY not found. Set it in env or shinka/.env\n"
    )
    sys.exit(1)


# ---------------------------------------------------------------- batch

def build_request(
    custom_id: str,
    model_id: str,
    system_context: str,
    framing_name: str,
    framing_desc: str,
    n: int,
    max_tokens: int,
    temperature: float | None = 0.9,
) -> Request:
    """One batch request. The heavy K4 inference context is marked
    cache_control=ephemeral so the second-and-later requests in the
    batch read it from cache at ~10% of the input rate.

    Some newer models (Claude Opus 4.7+) deprecate the ``temperature``
    parameter — pass temperature=None to omit it from the request."""
    params_dict = {
        "model": model_id,
        "max_tokens": max_tokens,
        "system": [
            {
                "type": "text",
                "text": system_context + SYSTEM_PROMPT_TAIL,
                "cache_control": {"type": "ephemeral"},
            },
        ],
        "messages": [
            {
                "role": "user",
                "content": build_user_prompt(framing_name, framing_desc, n),
            },
        ],
    }
    if temperature is not None:
        params_dict["temperature"] = temperature
    return Request(
        custom_id=custom_id,
        params=MessageCreateParamsNonStreaming(**params_dict),
    )


def submit_batch(
    client: Anthropic,
    requests: list[Request],
) -> str:
    """Submit batch, return the batch id."""
    batch = client.messages.batches.create(requests=requests)
    return batch.id


def poll_batch(
    client: Anthropic,
    batch_id: str,
    poll_interval_s: int = 60,
    max_wait_s: int = 24 * 3600,
) -> dict:
    t0 = time.time()
    while True:
        batch = client.messages.batches.retrieve(batch_id)
        if batch.processing_status == "ended":
            return batch
        elapsed = time.time() - t0
        if elapsed > max_wait_s:
            raise TimeoutError(f"batch {batch_id} did not end within {max_wait_s}s")
        counts = batch.request_counts
        print(
            f"  [{int(elapsed):5d}s] {batch.processing_status}: "
            f"proc={counts.processing} ok={counts.succeeded} "
            f"err={counts.errored} cxl={counts.canceled} exp={counts.expired}",
            flush=True,
        )
        time.sleep(poll_interval_s)


def retrieve_results(
    client: Anthropic,
    batch_id: str,
) -> dict[str, dict]:
    """Stream results back keyed by custom_id."""
    out: dict[str, dict] = {}
    for result in client.messages.batches.results(batch_id):
        out[result.custom_id] = result
    return out


# ---------------------------------------------------------------- main

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--model", choices=list(MODELS), default="sonnet",
                   help="haiku / sonnet / opus (default sonnet)")
    p.add_argument("--n-per", type=int, default=None,
                   help="candidates per framing (default 850, matching gemma4 5k run)")
    p.add_argument("--framing-set",
                   choices=["default", "expanded", "breadth", "both", "all"],
                   default="default",
                   help="which framing set to use. default=6 original, "
                        "expanded=10 first-expansion, breadth=8 additional, "
                        "both=default+expanded (16), all=default+expanded+breadth (24)")
    p.add_argument("--framings", nargs="*", default=None,
                   help="explicit subset of framings to run; overrides --framing-set")
    p.add_argument("--temperatures", type=float, nargs="+", default=[0.9],
                   help="list of temperatures to sweep. Each framing × each temperature "
                        "generates n_per/len(temperatures) candidates per batch. "
                        "Example: --temperatures 0.7 0.9 1.1")
    p.add_argument("--smoke", action="store_true",
                   help="smoke test: single framing, 30 candidates, <$1")
    p.add_argument("--full", action="store_true",
                   help="full 5,100-candidate cross-model run (gated by --confirm)")
    p.add_argument("--confirm", action="store_true",
                   help="required to actually launch --full (paid run protection)")
    p.add_argument("--out-dir", type=Path,
                   default=Path("experiments/results/n1_claude_outputs"))
    p.add_argument("--poll-interval", type=int, default=60,
                   help="seconds between batch status polls")
    p.add_argument("--resume", type=str, default=None,
                   help="resume an existing batch_id (skip submit, just poll/retrieve)")
    args = p.parse_args()

    # ----- mode resolution
    framing_map = select_framings(args.framing_set)
    all_framings = list(framing_map)
    if args.smoke:
        framings = ["k5_forward"] if "k5_forward" in framing_map else [all_framings[0]]
        n_per = 30
    elif args.full:
        if not args.confirm:
            sys.stderr.write(
                "--full requires --confirm (paid run protection). Re-run with both.\n"
            )
            return 2
        framings = args.framings or all_framings
        n_per = args.n_per or 850
    else:
        # Dry-run default: estimate cost only; no API call.
        framings = args.framings or all_framings
        n_per = args.n_per or 850

    bad = [f for f in framings if f not in ALL_FRAMINGS]
    if bad:
        sys.stderr.write(f"unknown framings: {bad}; available (all): {list(ALL_FRAMINGS)}\n")
        return 1

    total_candidates = len(framings) * n_per
    estimate = estimate_cost(args.model, total_candidates)

    # ----- always print estimate
    print("=" * 60)
    print(f"N1 Claude Batch — cost estimate")
    print("=" * 60)
    print(f"  model:            {estimate['model']}")
    print(f"  framings:         {framings}")
    print(f"  candidates each:  {n_per}")
    print(f"  total candidates: {total_candidates}")
    print(f"  batch requests:   {estimate['n_requests']}")
    print(f"  input tokens:     ~{estimate['input_tokens_est']:,}")
    print(f"  output tokens:    ~{estimate['output_tokens_est']:,}")
    print(f"  cache assumed:    {int(estimate['cache_hit_assumed']*100)}% hit rate")
    print(f"  est cost (in):    ${estimate['cost_input_usd']:.4f}")
    print(f"  est cost (out):   ${estimate['cost_output_usd']:.4f}")
    print(f"  est cost TOTAL:   ${estimate['cost_total_usd']:.2f}")
    print("=" * 60)

    if not (args.smoke or args.full or args.resume):
        print("\nDry run only — no API calls.")
        print("Re-run with --smoke (~$1) or --full --confirm to launch.")
        return 0

    # ----- prepare run directory
    api_key = load_api_key()
    client = Anthropic(api_key=api_key)

    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_model = MODELS[args.model]["id"].replace("/", "_")
    run_dir = args.out_dir / f"run_{stamp}_{safe_model}"
    run_dir.mkdir(parents=True, exist_ok=True)

    # ----- build / submit / resume
    if args.resume:
        batch_id = args.resume
        print(f"\nResuming batch {batch_id} ...")
    else:
        system_context = load_k4_inference_context()
        max_tokens = OUTPUT_TOKENS_PER_REQUEST + 1024  # headroom for JSON overhead

        requests: list[Request] = []
        per_batch = CANDIDATES_PER_REQUEST
        # Opus 4.7+ deprecates temperature; pass None to skip it.
        model_id = MODELS[args.model]["id"]
        temperature_supported = not model_id.startswith("claude-opus-4-7")
        if not temperature_supported:
            print(f"NOTE: model {model_id} deprecates explicit temperature; "
                  f"omitting --temperatures and collapsing to a single pass.")
            # Collapse the temperature dimension into a single pass at model default.
            temps: list[float | None] = [None]
        else:
            temps = list(args.temperatures or [0.9])
        for fname in framings:
            # Split n_per across temperatures (rounded so total ≈ n_per)
            n_per_temp = max(1, n_per // len(temps))
            for temp_idx, temperature in enumerate(temps):
                n_batches = (n_per_temp + per_batch - 1) // per_batch
                per_actual = (n_per_temp + n_batches - 1) // n_batches if n_batches else n_per_temp
                for bi in range(n_batches):
                    # custom_id encodes framing, temperature index, batch index
                    custom_id = f"{fname}_t{temp_idx}_b{bi:03d}"
                    requests.append(build_request(
                        custom_id=custom_id,
                        model_id=model_id,
                        system_context=system_context,
                        framing_name=fname,
                        framing_desc=ALL_FRAMINGS[fname],
                        n=per_actual,
                        max_tokens=max_tokens,
                        temperature=temperature,
                    ))

        print(f"\nSubmitting batch with {len(requests)} requests ...")
        batch_id = submit_batch(client, requests)
        (run_dir / "batch_id.txt").write_text(batch_id + "\n")
        print(f"Batch id: {batch_id}")
        print(f"(Saved to {run_dir}/batch_id.txt — resume with --resume {batch_id})")

    # ----- poll
    print("\nPolling batch ...")
    final_batch = poll_batch(client, batch_id, poll_interval_s=args.poll_interval)
    print(f"\nBatch ended: {final_batch.request_counts}")

    # ----- retrieve
    print("Retrieving results ...")
    results = retrieve_results(client, batch_id)

    # ----- parse, write per-framing parsed.txt files
    per_framing_stats: dict[str, dict] = {fname: {
        "n_requests": 0, "n_succeeded": 0, "n_errored": 0,
        "n_parsed": 0, "n_compliant": 0,
    } for fname in framings}

    framing_to_parsed: dict[str, list[str]] = {fname: [] for fname in framings}

    for custom_id, result in results.items():
        # custom_id format: "<framing>_t<temp_idx>_b<batch_idx>"
        # OR back-compat: "<framing>_b<batch_idx>"
        if "_t" in custom_id and "_b" in custom_id.split("_t", 1)[1]:
            fname = custom_id.rsplit("_t", 1)[0]
        else:
            fname = custom_id.rsplit("_b", 1)[0]
        if fname not in per_framing_stats:
            continue
        per_framing_stats[fname]["n_requests"] += 1

        if result.result.type == "succeeded":
            per_framing_stats[fname]["n_succeeded"] += 1
            text_blocks = result.result.message.content
            raw = "".join(b.text for b in text_blocks if getattr(b, "type", None) == "text")
            (run_dir / f"{custom_id}_raw.txt").write_text(raw)

            cands = parse_candidates(raw)
            framing_to_parsed[fname].extend(cands)
            per_framing_stats[fname]["n_parsed"] += len(cands)
            per_framing_stats[fname]["n_compliant"] += sum(
                1 for c in cands
                if c[21:25] == "EAST" and c[25:34] == "NORTHEAST"
                and c[63:69] == "BERLIN" and c[69:74] == "CLOCK"
            )
        else:
            per_framing_stats[fname]["n_errored"] += 1
            err_text = json.dumps(result.result.model_dump(), default=str)
            (run_dir / f"{custom_id}_error.json").write_text(err_text)

    for fname, cands in framing_to_parsed.items():
        (run_dir / f"{fname}_parsed.txt").write_text("\n".join(cands) + "\n")

    summary = {
        "batch_id": batch_id,
        "model": MODELS[args.model]["id"],
        "timestamp": stamp,
        "framings_run": framings,
        "n_per_framing": n_per,
        "total_parsed": sum(s["n_parsed"] for s in per_framing_stats.values()),
        "total_compliant": sum(s["n_compliant"] for s in per_framing_stats.values()),
        "per_framing": per_framing_stats,
        "cost_estimate": estimate,
        "request_counts": {
            "succeeded": final_batch.request_counts.succeeded,
            "errored": final_batch.request_counts.errored,
            "canceled": final_batch.request_counts.canceled,
            "expired": final_batch.request_counts.expired,
        },
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    print()
    print(f"=== SUMMARY ({MODELS[args.model]['id']}) ===")
    print(f"  batch id:             {batch_id}")
    print(f"  total parsed:         {summary['total_parsed']}")
    print(f"  total crib-compliant: {summary['total_compliant']}")
    for fname, st in per_framing_stats.items():
        print(f"  [{fname:14s}] req={st['n_requests']} ok={st['n_succeeded']} "
              f"err={st['n_errored']} parsed={st['n_parsed']} compliant={st['n_compliant']}")
    print()
    print(f"Outputs: {run_dir}")
    print(f"Cluster: uv run python scripts/cluster_n1_clean.py --run-dir {run_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
