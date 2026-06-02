# kryptos

A cipher library and experiment harness for attacking Kryptos K4.

> **There's a paper.** The findings are written up in
> **[the K4 paper](https://mattruckman.com/papers/k4/)** (local copy:
> [PDF](paper/k4_underdetermination.pdf), [source](paper/k4_underdetermination.tex)),
> with a companion essay,
> **[The Answer in the Box](https://mattruckman.com/blog/the-answer-in-the-box/)**.
> Every numerical claim traces to a logged `Verdict` in
> [experiments/results/FINDINGS.md](experiments/results/FINDINGS.md) (regenerate via
> `python scripts/report.py`), and the load-bearing structural results are re-derived
> from scratch by
> [scripts/rederive_load_bearing.py](scripts/rederive_load_bearing.py).

> **New here / picking this up cold?** Jump to **[Open directions — PICK UP
> HERE](#open-directions--pick-up-here-untested-0-local-pure-decipherment)** for
> a self-contained handoff: what K4 is, the constraints (decipherment only — no
> recovered plaintext, no K5), the two surviving structural facts and "the
> squeeze", the live ledger (`python scripts/report.py` → FINDINGS.md), and the
> three untested directions with concrete build steps.

The product is the infrastructure; "solving K4" is one experiment that
runs on top of it. A tightly-coupled K4 solver gets thrown out in three
weeks; a clean cipher library plus an experiment harness lets you pivot
cheaply when (not if) the first hypothesis fails.

## Status

K4 is **not solved**. The plaintext is privately held by Sanborn,
Scheidt, Kobek, Byrne, and the anonymous bidder who paid $962,500 on
20 November 2025 (per Sanborn's 12 Nov 2025 International Spy Museum
talk and the RR Auction "Decoding History" sale); this repo targets
the cryptographic method, not the plaintext.

42 experiments have run to date (000-042), plus four N1 plaintext-
inference layers (12-subagent cloud LLM, gemma4:26b local 5,100
candidates, Claude Sonnet 4-6 batch 5,220 candidates, Claude Opus 4.7
batch 26,265 candidates at 27 framings × ~$45-49), plus one N2
cipher-hypothesis-generation pass (Sonnet 4-6 batch, 272 cipher
proposals at $0.92), plus two early ShinkaEvolve mutation-search runs
(`k4_full_v1` at -40.0 best, `v2` at -132.0), **plus a hypothesis-
mutation architecture rewrite (Run A/B/C + deep-SA, $25.12 + $0)
followed by an extensive batch of free local-compute experiments (RC2
MaxSAT, EvalMaxSAT 8h, rule library expansion, beam search, trial-crib
sweeps, per-color modifications) that ultimately reached score 71.98 /
hex/char -16.98 under K=4 + Prior A default rule with 2-opt + perturbed
multi-start alphabet refinement** (full details below in "ShinkaEvolve
hypothesis-mutation architecture" and "Post-71.98 search exhaustion").
Zero positive cipher hits across the entire test corpus. **The
structural shape of K4's cipher is now narrowly constrained by the
cribs alone** — see "Structural ruling from the cribs" below.

The full 10-experiment attack suite + N2 cross-product has now been
run against both the original Sonnet 5,220-candidate prior AND the
expanded Opus 18,372-filtered-candidate prior, totaling **23,592
distinct high-quality crib-compliant Sanborn-register candidate
plaintexts × ~10 cipher families × multiple modifications** — every
combination round-tripped to **zero solves**.

**The strongest result of the session is from the cribs themselves,
not from the search**: the 24 crib positions force structural
properties on any valid K4 cipher. Specifically, the chromatic
number of the crib conflict graph is **χ = 3** (the cipher MUST use
at least 3 distinct alphabet permutations), no natural rule produces
a valid 3-coloring (the rotation rule is either non-natural or uses
k ≥ 8), and all 88 Sanborn-context keyed alphabets collectively fail
to cover 7 of the 24 cribs — at least some alphabets MUST be
hand-crafted.

### Library state

- Fully functional: `Vigenere`, `Quagmire I-IV`, `Beaufort`, `Autokey`,
  `Gromark`, `Vimark`, `RunningKey`, `ColumnarTransposition`, `Hill`,
  `Playfair`, `Bifid`, `Trifid`, `TwoSquare`, `FourSquare`, `ADFGVX`,
  `Nicodemus`, `WSegmented`, `Compose` + `FinalCaesar` +
  `PrependCaesar` + `PositionalRemap`, plus IoC / Kasiski / Friedman /
  n-gram / crib-check / hill-climber / simulated-annealing /
  brute-force / crib-enumerator / consistency propagator / Bean's
  permutation test framework.
- Stubbed (raise NotImplementedError): `GeneticAlgorithm`, `sat_ilp.*`.
  Fill in only when a real experiment needs them.
- N-gram tables shipped: `english_quadgrams.txt` (389k entries, ~3 MB,
  Practical Cryptography 2013), `english_hexagrams.txt` (3.18M entries,
  31 MB, built locally from Project Gutenberg corpus).
- Pathology guards in scoring code (e.g. drop candidates that
  literally copy K4 ciphertext into a free span — Sonnet did this once
  in 5,220).
- Reward-hack guards in ShinkaEvolve's evaluator (added 2026-05-23
  after observing the LLM converge on hardcoded-plaintext patterns when
  operating without scoring signal):
  `find_crib_construction_cheat` (AST detection of `chr(int)` and
  single-char crib-letter Constants used to construct cribs while
  evading literal-string scan), `multi_sentinel_check` (runs decrypt
  against 4 non-K4-signature inputs; rejects if all reproduce cribs),
  `differential_input_check` (perturbs non-crib ciphertext positions;
  requires plaintext to change in response). See
  [`shinka/problem/_fitness.py`](shinka/problem/_fitness.py).

The Phase-0 regression that the library can decrypt K1 and K2 with the
Gillogly-1999 keys is in
[`experiments/001_baseline_quagmire_iii_K1_K2.py`](experiments/001_baseline_quagmire_iii_K1_K2.py)
and should be the first thing you run.

## Install

Uses [uv](https://docs.astral.sh/uv/) for environment + dependency management.

```bash
uv sync                                       # core + dev group
uv sync --extra fast                          # + numba JIT for hot loops
uv sync --extra fast --extra claude           # + anthropic SDK for N1 batch
uv sync --extra fast --extra sat --extra ilp  # + Z3 and PuLP
```

`uv sync` creates `.venv/`, installs everything from `pyproject.toml`,
and writes/refreshes `uv.lock`. The CLI is installed as `kryptos`.

## Quick start

```bash
# Sanity: dump the four ciphertexts.
uv run kryptos constants

# Decrypt K1 with the Gillogly-1999 key (Quagmire III, KRYPTOS-keyed alphabet).
uv run kryptos decrypt --cipher quagmire3 --key PALIMPSEST \
  --alphabet-keyword KRYPTOS --text "$(cat data/ciphertexts/k1.txt)"

# Run the Phase-0 regression script.
uv run python experiments/001_baseline_quagmire_iii_K1_K2.py
```

`uv run` runs in the project's `.venv` without needing `source .venv/bin/activate`.

## Repository layout

```
kryptos/
├── pyproject.toml
├── README.md
├── data/
│   ├── ciphertexts/                # K1-K4, Cyrillic Projector, Antipodes
│   ├── plaintexts/                 # K1-K3 + K2 intended (370-char XLAYERTWO)
│   ├── alphabets/                  # standard, KRYPTOS-keyed, extra-L variant
│   ├── cribs.yaml                  # four confirmed K4 cribs, 1-indexed
│   ├── clues.yaml                  # every Sanborn/Scheidt utterance archive
│   ├── rejected_solutions.yaml     # 8 public claims, annotated with failure points
│   ├── plaintext_priors.yaml       # 276-line catalog of Sanborn/Scheidt-stated constraints
│   ├── k4_inference_context.md     # brief used as system prompt for N1 LM queries
│   ├── k4_plaintext_themes.yaml    # 12-subagent cloud LLM run themes
│   ├── k4_plaintext_themes_ollama_clean.yaml         # gemma4 5,100 themes
│   ├── k4_plaintext_themes_claude_sonnet_clean.yaml  # Sonnet 5,220 themes
│   ├── ngrams/                     # quadgrams (3 MB), hexagrams (31 MB), wikitext-103 source
│   ├── corpora/                    # Carter/Carnarvon, Smith Tutankhamen, Buchan 39 Steps
│   └── physical/                   # Weltzeituhr zones, Morse plates, compass bearings
├── src/kryptos/
│   ├── alphabets.py                # Alphabet objects (standard, KRYPTOS-keyed, 27-letter)
│   ├── constants.py                # K1-K4 ciphertexts, K1-K3 plaintexts, K1/K2 keys
│   ├── cribs.py                    # K4 crib constants in both alphabets
│   ├── generators.py               # 20.5k keystream generator library
│   ├── utils.py
│   ├── cli.py                      # `kryptos` entry point
│   ├── experiment_logger.py
│   ├── verify.py                   # canonical "solved" test: re-encrypt and byte-compare
│   ├── ciphers/                    # all cipher classes
│   ├── analysis/                   # IoC, Kasiski, n-grams, Friedman, partitions, Bean's permutation test
│   ├── scoring/                    # n-gram fitness, crib check, English classifier
│   ├── solvers/                    # brute, hill_climber, SA, crib_enumerator, consistency propagator
│   └── physical/                   # Weltzeituhr + Mengenlehreuhr keystream generators
├── experiments/                    # 29 numbered hypothesis tests
│   ├── 000_reproduce_bean_2021.py
│   ├── 001_baseline_quagmire_iii_K1_K2.py           # Phase 0 regression
│   ├── 002_gromark_k4_dyahr_primer.py
│   ├── 003_weltzeituhr_keystream.py                 # 85k-config sweep
│   ├── 004_w_partition_dual_key.py
│   ├── 006_shift_sequence_analysis.py               # 20.5k generators vs crib shifts
│   ├── 007_ciphertext_edit_search.py
│   ├── 008_crib_perturbation_search.py
│   ├── 009_27letter_search.py
│   ├── 010_quagmire_iv_slope1_berlinclock.py
│   ├── 011_bigram_analysis.py
│   ├── 012_plaintext_beam_search.py
│   ├── 013_running_key_search.py
│   ├── 014_q3_doubled_l_27letter.py
│   ├── 015_transposition_then_q3.py
│   ├── 016_double_q3_crib_constrained.py
│   ├── 020_horenberg_lethuillier.py
│   ├── 021_q3_perturbation_consistency.py           # Q3 + single positional or letter perturbation
│   ├── 022_regate_exp015_with_hexagrams.py          # hexagram-rescore exp 015's chi-sq survivors
│   ├── 023_sonnet_candidate_shift_vs_generators.py  # 5,220 candidates vs 20.5k generators
│   ├── 024_tierA_known_plaintext.py                 # Vigenere/Beaufort/Hill/Autokey KP attacks
│   ├── 025_w_segmented_heterogeneous.py             # 6-segment heterogeneous Lethuillier
│   ├── 026_composite_q3_transforms.py               # Q3 + arithmetic offset / reversed / interleaved
│   ├── 027_trifid_hillclimb.py                      # Trifid 3x3x3 hill-climb (Numba + multiprocess)
│   ├── 028_hill_block_sizes_4_to_8.py               # extended Hill known-plaintext
│   ├── 029_compose_pipelines.py                     # Q3 ∘ remap, remap ∘ Q3, col ∘ Q3 ∘ remap
│   ├── 030_playfair_dedicated_search.py             # 5×5 (26 merges) + 2×13 + 13×2 rectangular
│   ├── 031_two_pass_columnar_q3.py                  # K3-style two-pass columnar + Q3 composite
│   ├── 032_single_letter_ciphertext_error.py        # K2-IDBYROWS-style single-letter error model
│   ├── 033_per_position_alphabet_selection.py       # keyword-driven per-position alpha select (33 lines = pool insufficient)
│   ├── 033b_per_position_state_dependent.py         # state-dependent (vowels/W-distance) — best 8/24 at dist_to_w
│   ├── 034_candidate_shift_statistics.py            # shift entropy of 23,592 candidates (~uniform; can't distinguish (a) vs (b))
│   ├── 035_minimum_alphabet_analysis.py             # ★ proves χ=3: minimum alphabets required
│   ├── 036_rule_compatibility_with_chromatic_3.py   # ★ no natural rule at k=3; k=8 floor for natural rules
│   ├── 037_position_mod_8_alphabet_search.py        # ★ no natural keyword covers any slot under k=8 rules
│   └── results/                                     # JSONL logs (gitignored by default)
├── scripts/
│   ├── build_hexagrams.py                           # Project Gutenberg -> hexagram table
│   ├── calibrate_fitness.py                         # n-gram fitness threshold calibration
│   ├── download_quadgrams.py
│   ├── plot_shifts.py
│   ├── n1_ollama.py                                 # local LM plaintext inference (gemma4)
│   ├── cluster_n1_clean.py                          # re-cluster N1 outputs without crib pollution
│   ├── n1_claude_batch.py                           # N1 via Anthropic batch API (Sonnet/Opus/Haiku)
│   ├── n2_claude_batch.py                           # N2 cipher-hypothesis generation via batch API
│   ├── n2_verify.py                                 # mechanically verify N2 hypotheses
│   ├── n2_verify_against_candidates.py              # cross-product N2 hypotheses × N1 candidates
│   ├── hexagram_filter.py                           # post-filter an N1 prior by hexagram fitness
│   └── run_all_attacks.py                           # meta-runner: full attack suite against any N1 prior
├── docs/
│   ├── weltzeituhr_negative_result.md               # 85k-config writeup
│   └── shift_sequence_hypotheses.md                 # priority queue for generator families
├── shinka/                                          # ShinkaEvolve-driven N2 sub-project
│   ├── README.md                                    # setup, costs, fitness function
│   ├── pyproject.toml
│   ├── configs/                                     # Hydra config tree
│   ├── problem/                                     # initial.py, evaluator.py, catalog.py
│   └── results/                                     # 13 probes + k4_full_v1 ($51) + v2 ($26)
└── notebooks/
```

## What's been tried

29 numbered experiments + Tier A/B known-plaintext sweeps against
5,220 Sonnet candidates. Every result is reproducible from its
corresponding `experiments/results/*.jsonl` log. Every "solved" claim
is gated by `src/kryptos/verify.py` — byte-exact re-encryption test.

### Bean / Gillogly diagnostics (000, 011)

| Exp | Hypothesis | Result |
|---|---|---|
| 000 | Cryptodiagnosis: shift-uniformity and English-at-cribs tests under random null | K4 is consistent with single-letter polyalphabetic, inconsistent with pure transposition (Bean's original finding holds) |
| 011 | K4 bigram statistics at offsets 1..30 vs a Q3-on-English null distribution (500 samples) | K4 sits inside the Q3-on-English null envelope at all offsets — no significant z-score outliers |

### Periodic-shift cipher families (002, 013, 014, 016, 024, 026, 028)

**Hypothesis class:** K4 = some periodic-key shift cipher (Vigenere /
Beaufort / Quagmire) with crib-derivable key, possibly with
single-perturbation or arithmetic modification.

| Exp | Test | Search space | Result |
|---|---|---|---|
| 002 | Gromark / Vimark / Autokey base sweep, both alphabets, periods 4-5 | 27.2M ciphertexts | 0 crib survivors |
| 013 | Running-key Vigenere/Beaufort/variant from Carter, Smith, Buchan, K1-K3 plaintexts/ciphertexts, both directions, both alphabets | 5.3M decryptions | 0 hits |
| 014 | Q3 doubled-L 27-letter brute force at L ∈ {27, 28, 29} | 14.9M keys | 0 below chi-squared T99 |
| 016 | Double-Q3 crib-constrained (Q3 ∘ Q3 with different periods) | 12.4M pairs | 0 hits |
| 024 (Tier A) | Vigenere/Beaufort/variant-Beaufort periodic L ∈ {1..30} × Hill 2×2/3×3 × Autokey {plain, cipher} primer L ∈ {1..10} known-plaintext attack against 5,220 Sonnet candidates | ~140k (cand, family, params) tuples | 0 solves |
| 026 (Tier B) | Q3 + arithmetic offset (a×i+b), reversed-direction Q3, even/odd interleaved dual-key Q3 against 5,220 Sonnet candidates | a ∈ {1..25}, b ∈ {0..25}, L ∈ {1..15}, reversal variants, L_A,L_B ∈ {1..10} | 0 solves across all 3 families |
| 028 (Tier B) | Hill block sizes 4×4, 5×5, 6×6, 7×7, 8×8 known-plaintext against 5,220 Sonnet candidates × both alphabets | 5,220 × 10 (B, α) combinations | 0 solves |

**Ruling:** the cipher is not a periodic shift cipher at any L ≤ 30,
nor a Hill cipher at any block size 2-8, nor a single-positional-offset
modification of either, against any of 5,220 candidate plaintexts.

### Physical-clock keystream attacks (003, [docs/weltzeituhr_negative_result.md](docs/weltzeituhr_negative_result.md))

| Exp | Test | Search space | Result |
|---|---|---|---|
| 003 | Weltzeituhr keystream sweep: 5 generators × {7 anchors × 5 intervals × 24 zodiac angles × params} × both alphabets | 85,680 configurations | 0 crib survivors |

Sanborn confirmed in Nov 2025 that K4's "Berlin Clock" is the
Weltzeituhr at Alexanderplatz, NOT the Mengenlehreuhr that the
community attacked for 15 years. This is the first systematic
crib-constrained sweep against the correct clock.

**Ruling:** clock-state-as-keystream attacks under any documented
generator/anchor/interval do not satisfy K4's cribs. Strong evidence
the clock is *thematic* (a noun in the plaintext) rather than
*cryptographic* (a keystream source).

### Generator-library shift-sequence attacks (006, 007, 008, 009, 023)

**Hypothesis class:** K4's per-position shift pattern is the output of
some closed-form generator (text-keystream, math constant, LCG,
Fibonacci, Mengenlehreuhr, etc.).

| Exp | Test | Search space | Threshold | Result |
|---|---|---|---|---|
| 006 | 20.5k-generator library × 2 alphabets vs K4's 24 crib shifts | ~41k (gen, alpha) tuples | ≥ 5 consecutive | 0 hits |
| 007 | Single-character ciphertext edit (insert/delete/swap) at each of 97 positions × generator library | 112M comparisons | ≥ 8 consecutive | 0 hits; 5 noise-floor 5-runs |
| 008 | Single-crib perturbation (shift ±1, letter sub) × generator library | 25M comparisons | ≥ 8 consecutive | 0 hits; 1 noise-floor 5-run |
| 009 | 27-letter doubled-L + locally-arithmetic generators (~125k gens at mod-27, +100k locally-arithmetic) × 4 alphabets | ~225k generators per family | ≥ 5 consecutive | 0 hits |
| 023 | 20.5k-generator library × 5,220 Sonnet candidate plaintexts × 2 alphabets (FULL 97-position shift sequence at non-crib positions, not just cribs) | 214M (cand, gen, alpha) comparisons | ≥ 10 consecutive (win), ≥ 8 (interesting) | 0 hits; best 5 consecutive (noise floor) |

**Ruling:** the K4 shift sequence is not the output of any text /
mathematical-constant / LCG / Fibonacci / lagged-Fibonacci /
Mengenlehreuhr generator in the 20.5k library, against the cribs OR
against any of 5,220 high-quality Sanborn-register candidate
plaintexts.

### Quagmire IV slope-1 BERLINCLOCK (010)

| Exp | Test | Search space | Result |
|---|---|---|---|
| 010 | Q4 with slope-1 keystream applied to BERLINCLOCK at positions 64-74, sweeping (plain_alphabet, cipher_alphabet, start_value) | 42k triples | 0 exact 11/11 matches |

**Ruling:** Q4 with slope-1 keystream does not produce the BERLINCLOCK
window in K4 under any documented alphabet pair.

### Compositional / multi-stage attacks (004, 015, 020, 025, 027)

| Exp | Test | Search space | Result |
|---|---|---|---|
| 004 | W-partition dual-key Q3 (two interleaved keys on W-segmented partition) | 463k pairs at L_max=2 | 0 hits (search incomplete; needs hill-climb to L=3-4) |
| 015 | Transposition-then-Q3 (W ∈ {7,8,9,10} columnar permutations × Q3 periods × free slots) | 3.6M permutations at W=10 | 98,218 below chi-squared T99 at W=10 |
| 020 | Hörenberg XOR-mask reanalysis + Lethuillier per-segment Q3 | 12.5k Hörenberg variants + W-seg | Hörenberg's claimed IoC=0.061 doesn't reproduce (max 0.0479); Lethuillier's per-segment Q3 inconsistent at periods 1-8 |
| 022 | Hexagram-rescore exp 015's 215 best-per-(W,perm,L) chi-squared survivors | 215 plaintexts | Best hex/char = **-23.23** (real English ≈ -13); 0 above -18 threshold. The "98k chi-sq survivors" are all gibberish at hexagram granularity |
| 025 (Tier B) | W-segmented heterogeneous: 6 independent segments, per-segment short-period Vigenere/Beaufort/Q3 (L ∈ {2..6}, 2 alphas × 3 convs) | All 5,220 candidates × 6 segs × 6 (L,α,conv) tuples | 0 candidates with all 6/6 segs simultaneously consistent; max 2/6 segs |
| 029 | Compose pipelines: 10 positional remaps (identity / reverse / swap_halves / rotate_{1,5,10,24,48} / bit_reverse_7 / K3_columnar_w7) × 5,163 columnar perms (W ∈ {3,5,7}) × 2 alphabets × 3 conventions × L ∈ {1..15}. Shape A (Q3 ∘ remap), Shape B (remap ∘ Q3), Shape C (col ∘ Q3 ∘ remap) | 103,300 pipelines × 5,220 candidates per pipeline | **0 solves** in 9.5 min wall time |

**Ruling:** Two-stage transposition-then-Q3 at W=10 produces chi-squared
filter survivors, but ALL fail the hexagram-fitness gate (deep
gibberish at -23.23). W-segmented heterogeneous with up to 6 independent
keys produces 0 fully-solved candidates against 5,220 Sonnet plaintexts.
Hörenberg's published XOR-mask recipe does not reproduce his claimed
IoC; Lethuillier's per-segment Q3 hypothesis is not short-period.

### Q3 + positional perturbation (021)

**Hypothesis class** (highest-priority per [docs/shift_sequence_hypotheses.md](docs/shift_sequence_hypotheses.md)):
Quagmire III + a single Sanborn-style positional perturbation (one
inserted letter, one deleted letter, one transposed pair, or one
single-letter crib substitution).

| Exp | Test | Search space | Result |
|---|---|---|---|
| 021 | 77 positional shifts (all cribs by ±5, BERLIN+CLOCK by ±3) + 600 single-crib-letter substitutions × periods {2..26} × 2 alphabets × 3 conventions, consistency propagator + free-slot brute-force fill + hexagram score | 67,700 consistency checks; 184 consistents with up to 4 free slots brute-forced | 0 hits at "English plaintext"; **best hexagram score -21.34** (gibberish) |

**Ruling:** the single-positional-perturbation hypothesis flagged in
the docs as "build next" is now **closed**. No positional shift (±5
all, ±3 BC) and no single-letter crib substitution makes K4 a periodic
Q3 producing English at any L ≤ 26 in either alphabet.

### Polygraphic / fractionation families (Tier B redirect, 027)

**Structural rulings (no exp needed):**

K4 contains every letter A-Z (verified: 26/26 present; J appears 3×).
This rules out the standard 25-cell-grid polygraphic family a priori,
because each of these ciphers' output ciphertext cannot contain the
merged-away letter:

- **Bifid** (5×5 = 25 cells, one merge) — output set is 25 letters → cannot match K4
- **Playfair** (5×5, one merge) — same ruling
- **Two-square, Four-square** (5×5 grids, one merge) — same ruling
- **ADFGVX / ADFGX** — length-doubling: 97-char K4 would require 48.5-char plaintext

**Hill-climbed:**

| Exp | Test | Search space | Result |
|---|---|---|---|
| 027 (Tier B) | Trifid 3×3×3 = 27 cells (no merge needed), periods {5, 7, 9}, 8 random restarts × 5,000 iters per candidate, Numba-compiled inner loop, multiprocessing 14 workers | 5,220 cands × 24 hill-climbs each, ~626M total iters | **Best score 37/97**, 0 candidates ≥ 50/97, 0 full solves |
| 030 | Dedicated Playfair search: Phase 1 — 5×5 grid with each of 26 possible merge "drop letters" (KRYPTOS-keyed grid), direct encrypt against all 5,220 cands. Phase 2 — 2×13 rectangular Playfair (no merge needed), Numba hill-climb 6 restarts × 5,000 iters × 14 workers. Phase 3 — 13×2 rectangular Playfair (same setup). | Phase 1: 26 merges × 5,220 cands; Phase 2/3: ~313M Playfair encrypts | **Phase 1 best 14/97** (every merge had ~70-position gap vs max possible, mechanically confirms structural ruling); **Phase 2/3 best 33/97**; 0 full solves across all three variants in 12.4s wall |
| 031 | Two-pass K3-style columnar transposition: **Shape B1** (`col2(col1(plain, kw1), kw2)`) and **Shape B4** (`Q3(col2(col1(plain, kw1), kw2), q3_key)`). Keyword pool: KRYPTOS, ABSCISSA, PALIMPSEST, BERLIN, CLOCK, BERLINCLOCK, WELTZEITUHR, DYAHR, SANBORN, LANGLEY, IQLUSION, UNDERGRUUND. | B1: 144 (kw1, kw2) pairs × 5,220 cands. B4: same + 2 alphas × 3 convs × 15 periods | **B1 0 solves** (best partial 16/97 at DYAHR × BERLIN); **B4 0 solves**; ~67M Q3 KP consistency checks in 1.6s |
| 032 | K2-IDBYROWS-style single-letter ciphertext-error model: for each (cand, alter_pos, new_letter, alpha, convention, L): substitute one K4 letter and run Q3/Vigenere/Beaufort KP attack. Tests the hypothesis that K4 has a Sanborn-style encoding error mirroring K2's missing-X-separator. | 5,220 cands × 97 positions × 25 letter substitutions × 30 periods × 2 alphabets × 3 conventions ≈ **760M consistency checks** | **0 solves** in 189.7s |

**Ruling:** Trifid hill-climb best match is 37/97 = 38% — well above
random expectation (~3.6/97) but far from a solve. No grid + period
combination produces K4 from any Sonnet candidate.

### LM-based plaintext inference (N1)

Three N1 layers built. Each produces a *probability distribution over
themes*, not a single plaintext.

| Run | Model | Candidates | Compute | Cost |
|---|---|---|---|---|
| N1-subagent (early) | 12 cloud LLM subagents | 12 × 6 = 72 candidates | hand-orchestrated | ~$3 |
| N1-ollama (gemma4:26b) | gemma4:26b-a4b-it-q8_0 local | 5,100 (6 framings × 850) | ~2h35m local wall | $0 |
| N1-Claude (Sonnet 4-6) | claude-sonnet-4-6 via Anthropic batch API | 5,220 (174 batched requests, 30 candidates each) | ~3 min wall, batch | ~$5.70 |

**Cross-model theme comparison** ([data/k4_plaintext_themes_claude_opus_clean.yaml](data/k4_plaintext_themes_claude_opus_clean.yaml)
vs [data/k4_plaintext_themes_claude_sonnet_clean.yaml](data/k4_plaintext_themes_claude_sonnet_clean.yaml)
vs [data/k4_plaintext_themes_ollama_clean.yaml](data/k4_plaintext_themes_ollama_clean.yaml)):

| Theme | gemma4 (n=5,100) | Sonnet 4-6 (n=5,220) | **Opus 4.7 (n=26,265)** | Subagent (n=72) |
|---|---|---|---|---|
| berlin_wall | 24.0% | **54.3%** | 30.6% | 58% |
| k5_forward | **54.9%** | 43.9% | 33.0% | 26% |
| first_person (clean) | 29.7% | 22.5% | **39.5%** | 100% (polluted) |
| navigation (clean) | 27.1% | 16.3% | 14.2% | 100% (polluted) |
| espionage | 20.6% | 15.6% | 2.8% | — |
| k2_k3_echo | 12.7% | 18.3% | 16.4% | 33% |
| **egypt** | 5.3% | 11.3% | **14.7%** ↑ | 26% |
| sculpture_action | 8.3% | 8.1% | 9.7% | — |

**Findings across models:**
- gemma4's k5_forward-dominant prior was substantially model bias.
- Sonnet 4-6 over-weighted Berlin Wall (54.3%) and under-sampled
  Egypt (5.3%), even though Sanborn confirmed Egypt-1986 as one of
  TWO stated K4 themes.
- **Opus 4.7 distributes attention more evenly across stated K4
  themes**: Berlin Wall drops to 30.6% (corrected over-weighting),
  Egypt climbs to 14.7% (Egypt re-weighting working — 4 explicit
  Egypt framings added: `karnak_temple_observation`,
  `valley_of_kings_tomb`, `cairo_museum_artifact`,
  `egypt_1986_specific`). Espionage drops sharply (2.8% vs Sonnet's
  15.6%) — Opus less prone to Cold-War-thriller framing.
- Opus also produces dramatically higher-quality candidates: median
  hexagram fitness -14.89/char vs Sonnet's ~-15.6, and a much
  healthier per-framing response pattern (22 of 27 framings respond
  to their own prompt, vs Sonnet's 4 of 6 collapsing to k5_forward).

The combined **23,592 Sonnet+Opus filtered candidates** are now a
reusable Sanborn-register plaintext prior consumed by exps 023-032
as known-plaintext-attack input.

### Running all attacks against a new prior

The full Tier A + Tier B attack suite is wired up as a single meta-runner.
Given any directory of crib-compliant 97-char candidate plaintexts (one
per line in `<framing>_parsed.txt` files), the runner invokes every
implemented experiment in sequence and reports any solves.

```bash
# Run the entire suite against a new N1 prior:
uv run python scripts/run_all_attacks.py \
    --run-dir experiments/results/n1_claude_outputs/<run_id>/

# Add the N2 hypothesis cross-product if you have N2 hypotheses:
uv run python scripts/run_all_attacks.py \
    --run-dir experiments/results/n1_claude_outputs/<run_id>/ \
    --n2-hypotheses-dir experiments/results/n2_claude_outputs/<n2_run_id>/

# Faster (smaller hill-climb budgets, ~10 min total):
uv run python scripts/run_all_attacks.py \
    --run-dir <run_id>/ --quick

# Skip specific experiments:
uv run python scripts/run_all_attacks.py \
    --run-dir <run_id>/ --skip 023,027

# Only run specific experiments:
uv run python scripts/run_all_attacks.py \
    --run-dir <run_id>/ --only 024,025,028
```

The runner sequences attacks by both depth (linear/matrix first, then
composites, then hill-climbed polygraphic last) AND wall-time budget
(cheapest first). If any experiment reports a solve, the runner stops
and exits early. Otherwise it writes a meta-summary at
`experiments/results/run_all_attacks_<ts>_<prior_name>.json`.

Total wall time for a fresh 5,000-candidate prior on M3 Max 14 cores:
~30 minutes (default budgets) or ~10 minutes (--quick).

### N1 expansion — Opus 4.7 run completed

**Hypothesis (b) from the cumulative ruling above** ("cipher is in our
prior but the real plaintext isn't in Sonnet's 5,220 candidates") was
pressure-tested by [scripts/n1_claude_batch.py](scripts/n1_claude_batch.py),
extended with 21 new framings on top of the original 6 (total 27),
plus anti-pathology guardrails in the system prompt, plus a hexagram-
fitness post-filter. Total framings:

| Framing | Targets gap |
|---|---|
| `bornholmer_specific` | Specific 9 Nov 1989 23:30 details (Bornholmer Strasse, Jaeger, Schabowski) |
| `egypt_1986_specific` | Sanborn's stated 1986 Egypt trip — Karnak, Cairo Museum, Sphinx |
| `k2_coords_explicit` | Bornholmer / Alexanderplatz coordinates spelled out in K2-style English digits |
| `weltzeituhr_visual` | Erich John's 1969 clock physically: 24 zones, zodiac ring, bronze drum |
| `layer_three_forward` | K2's "LAYER TWO" pattern continued into K4-end "LAYER THREE" |
| `carter_continuation` | K3 quotes Carter's diary; K4 may extend ("WONDERFUL THINGS") |
| `k1_poetic_echo` | K1's metaphysical-about-seeing register applied to Berlin/Egypt |
| `first_person_witness` | Sanborn's I-witness at Alexanderplatz, Nov 1989 |
| `descriptive_no_imperative` | Adversarial — strips "look/find/dig" verbs Sonnet over-weighted |
| `k4_self_referential` | K4 describes the Kryptos sculpture itself |

**Improvements made before the Opus launch** (no-bias breadth maximizers
+ structural quality controls + Egypt model-bias correction):

- 27 framings now wired up (default 6 + expanded 10 + breadth 8 +
  Egypt 3). New framings cast a wider thematic net: `schliemann_memoirs`,
  `near_verbatim_quote`, `morse_thematic_echo`, `non_english_loanword`,
  `dedication_day_1990`, `sensory_specific`, `kobek_byrne_archival`,
  `k1_perception_paradox`, plus 3 Egypt-specific framings
  (`karnak_temple_observation`, `valley_of_kings_tomb`,
  `cairo_museum_artifact`) added to correct Sonnet's first-pass Egypt
  under-weighting (5.3% vs Sanborn's confirmed ~50% prior since Egypt
  is one of two stated K4 themes). This is *model-bias correction*, not
  content bias — Sanborn's confirmation gives Egypt structural prior
  weight, but Sonnet under-sampled it.

**Opus 4.7 run executed 2026-05-23**:
- Total candidates: **26,265** (100% crib-compliant)
- Framings: 27 (all responded; 22 of 27 had top theme matching their
  own framing, vs Sonnet's 4 of 6)
- Wall time: 8 min batch + 30s hex filter + 44 min attack suite
- Temperature: single (Opus 4.7 deprecates explicit `temperature`,
  see below); diversity from framings + sampling
- Cost: ~$45-49 (estimate was $49.93; actual depends on cache hit rate)
- **Hexagram-filtered top-70% = 18,372 candidates** with median
  hex/char = -14.89 (real English ≈ -13). Best Opus candidate
  hex/char = **-12.30** vs Sonnet's best -12.87.

**Opus 4.7 temperature note**: the `temperature` parameter is
deprecated on this model and now raises `invalid_request_error`. The
[scripts/n1_claude_batch.py](scripts/n1_claude_batch.py) script
auto-detects this and omits the parameter for Opus 4.7. Effect:
modest (~20-30%) reduction in exploration diversity compared to a
3-temperature sweep, compensated for by 27× framing diversity and
Opus's higher per-candidate quality.
- Multi-temperature sweep wired in: `--temperatures 0.7 0.9 1.1`
  triples the diversity at fixed candidate count.
- Anti-pathology guardrails added to the system prompt: explicit
  instruction not to copy K4 ciphertext substrings into free spans
  (Sonnet did this once in 5,220), instruction to make smooth
  grammatical fit at crib boundaries (avoid Sonnet's lumpy seams), no
  X-padding allowed.
- Hexagram post-filter ([scripts/hexagram_filter.py](scripts/hexagram_filter.py))
  lets you drop the worst 30% of any prior by hexagram fitness *after*
  generation — improves downstream attack signal-to-noise without
  requiring re-generation.
- Two new cipher attacks (exps 031 + 032) wired into the attack suite,
  closing previously-open gaps (two-pass K3-style transposition; K2-style
  single-letter ciphertext error model).

**Recommended Opus 4.7 run** (do NOT launch without explicit go, per
[[feedback_paid_runs]]):

```bash
uv run python scripts/n1_claude_batch.py \
    --model opus \
    --framing-set all \
    --n-per 1000 \
    --temperatures 0.7 0.9 1.1 \
    --full --confirm
```

Estimated cost (verified via dry-run): **~$49.93** for 27 framings ×
1000 candidates × 3 temperatures = 27,000 total candidates. Hits the
$50 budget cleanly; actual cost likely $45-48 in practice (the
estimator assumes a conservative 30% cache hit rate; Anthropic batch
typically achieves 50-90%).

What this buys vs the Sonnet baseline:
- **2× model capability** (Opus 4.7 SWE-Bench 87.6%, much stronger
  prior on Sanborn's literary register and Berlin-1989 / Egypt-1986
  historical detail)
- **4.5× more framings** (27 vs 6) covering thematic angles Sonnet's
  first pass missed, with explicit Egypt re-weighting (4 framings vs 0)
- **3× more temperature diversity** (3 temps vs 1)
- **Anti-pathology + structural guardrails** in the system prompt

**Post-launch workflow executed (all 0 solves)**:

```bash
# 1. Hexagram filter (top 70%): 26,265 -> 18,372 candidates
uv run python scripts/hexagram_filter.py \
    --in-dir experiments/results/n1_claude_outputs/run_20260523_083115_claude-opus-4-7/ \
    --top-frac 0.70

# 2. Theme clustering:
uv run python scripts/cluster_n1_clean.py \
    --run-dir experiments/results/n1_claude_outputs/run_20260523_083115_claude-opus-4-7_hexfiltered/

# 3. Full 10-experiment attack suite + N2 cross-product:
uv run python scripts/run_all_attacks.py \
    --run-dir experiments/results/n1_claude_outputs/run_20260523_083115_claude-opus-4-7_hexfiltered/ \
    --n2-hypotheses-dir experiments/results/n2_claude_outputs/run_20260522_233722_claude-sonnet-4-6/
```

**Result: 0 solves in 43.8 min wall.** Per-experiment results below.

| Exp | Family | Time | Solves | Best partial |
|---|---|---|---|---|
| 024 | Tier A (Vigenere / Beaufort / Hill 2-3 / Autokey) | 41s | 0 | — |
| 023 | Shift sequence vs 20.5k generators | 26s | 0 | 5/97 (noise) |
| 025 | W-segmented heterogeneous | 0.5s | 0 | 2/6 segs |
| 026 | Q3 + arith / reversed / interleaved | 84s | 0 | — |
| 028 | Hill 4×4 through 8×8 | 110s | 0 | — |
| 029 | Compose pipelines (103k combos) | **25.4 min** | 0 | — |
| 030 | Playfair variants (5×5 + 2×13 + 13×2) | 47s | 0 | 33/97 |
| 031 | Two-pass K3-style columnar (+ Q3) | 5s | 0 | 16/97 |
| 032 | K2-IDBYROWS single-letter ciphertext error | 10 min | 0 | — |
| 027 | Trifid hill-climb | 2 min | 0 | **38/97** |
| N2-XP | 209 N2 cipher hypotheses × 18,372 cands = 2.08M attempts | 46s | 0 | 15/97 |

The Trifid hill-climb's best partial improved from 37/97 (Sonnet) to
38/97 (Opus) — marginal but consistent with the higher candidate
quality. None of the partials reached the WIN threshold (97/97).

**What this conclusively shows**: across **23,592 high-quality
crib-compliant Sanborn-register candidate plaintexts** (5,220 Sonnet
+ 18,372 Opus-filtered) tested against **every classical cipher family
in the suite**, hundreds of millions of (plaintext, cipher, key) tuples
evaluated produced **zero K4-matching combinations**.

Combined with the original 27,000-candidate Opus run before hex-filter
(of which 18,372 survived), the negative across all classical families
is now extremely robust. Hypothesis (b) "the real plaintext isn't in
our prior" is substantially weakened — if the cipher were in the
tested space, an Opus prior 5× larger than Sonnet's at 27 framings vs
6 should have surfaced *some* candidate that round-trips.

**The remaining most-likely explanation is hypothesis (a)**: Sanborn's
modification of Scheidt's classical scheme produces a cipher
structurally outside the tested family space.

### N2 hypothesis-generation pass ($0.92 Sonnet batch)

Goal: rather than scale plaintext candidate counts, ask Sonnet 4-6 to
*propose specific testable cipher constructions* given the full
evidence stack (29 prior negatives, four cribs, Scheidt/Sanborn quotes,
K1-K3 reference texts, structural rulings).

| Step | Detail | Output |
|---|---|---|
| Generation | Anthropic batch API, 10 requests × 30 hypotheses, Sonnet 4-6, ~2 min wall | 272 parsed hypotheses, $0.92 |
| Cipher class distribution | Compose 87, Nicodemus 86, FourSquare 19, Gromark 14, TwoSquare 14, Vimark 9, Autokey 9, RunningKey 9, QuagmireI 5, QuagmireII 4, WSegmented 4, Trifid 4, QuagmireIV 3, Playfair 3, Beaufort 2 | [data/k4_plaintext_themes_claude_sonnet_clean.yaml](data/k4_plaintext_themes_claude_sonnet_clean.yaml) |
| Sonnet-attached plaintexts | Not crib-compliant (Sonnet generated free-form text without rigid crib placement). Lengths varied 75-121 chars (target 97) | rejected at verify step |
| Cross-product test | 209 unique cipher-method structures × 5,220 N1 candidates as proposed plaintexts | 113 cipher builds OK, 589,860 encrypt attempts, **0 solves**, best partial match 15/97 (TwoSquare) |

**Ruling:** none of Sonnet's 272 N2-proposed cipher constructions
× any of 5,220 high-quality Sanborn-register candidate plaintexts
produces K4 under encryption. The best partial match (15/97) is at the
noise floor.

Scripts:
- [scripts/n2_claude_batch.py](scripts/n2_claude_batch.py) — generation
- [scripts/n2_verify.py](scripts/n2_verify.py) — verify Sonnet's own (cipher, plaintext) pairs
- [scripts/n2_verify_against_candidates.py](scripts/n2_verify_against_candidates.py) — cross-product against N1 candidates

### ShinkaEvolve mutation search

Sub-project at [`shinka/`](shinka/) — LLM-driven evolutionary search
where Gemini 3.5 Flash + Claude Opus 4.7 (via OpenRouter, UCB bandit
between arms) propose mutations to a `decrypt_k4` Python pipeline
composed of `kryptos.ciphers` primitives.

| Run | Cost | Generations | Best score | Cribs satisfied? |
|---|---|---|---|---|
| `k4_probe` + `k4_probe2..13` | small | feasibility checks | various | mostly no |
| `k4_full_v1` (2026-05-21) | $51.25 | 223 | **-40.0** | No (cribs threshold = 100) |
| `k4_full_v2` (2026-05-21) | $26.44 | fewer | **-132.0** | No |

Best v1 patches: `autokey_tail_reconstruction`, `q4_remap_cross_sweep`,
`crib_aware_remap_q3_dispatcher`. **No shinka run has crossed the
score-100 threshold** (cribs satisfied + gibberish at the 73
unconstrained positions), let alone score-110 (cribs + English-ish).
The mutation search is structurally stuck below the crib-pass floor —
indicating the right primitive composition isn't reachable from the
current seed `decrypt_k4` via the mutation distributions tested.

### ShinkaEvolve hypothesis-mutation architecture (Run A/B/C + deep-SA, 2026-05-23/24)

Following the v1/v2 plateau, the architecture was rewritten to separate
cipher hypothesis (LLM mutates) from alphabet refinement (external SA in
the fitness function). The cipher form was fixed to **K=4 per-position
alphabet substitution with crib-derived constraints baked into the
fitness function**, with the LLM exposed to four mutable parameters
inside an EVOLVE-BLOCK: `K` (number of alphabets), `selection_rule(i,
ciphertext)`, `FREE_LETTERS` (starting alphabet ordering per color),
`MODIFICATIONS` (per-color Caesar/reverse). Decryption and helpers live
outside the EVOLVE-BLOCK and are not LLM-mutable.

| Run | Architecture | Cost | Best | Notes |
|---|---|---|---|---|
| A | Continued original (gen 66 seed, K=4 internal SA) | $9.08 | 48.10 | LLM optimized the internal hill-climber, never alphabets; 0 candidates above seed |
| B v1 | Hypothesis-mutation, killed early for bug | $5.85 | — | `_decrypt_with_state` returned `"A"*97` on malformed cipher state → sentinel guard fired with misleading "ignores ciphertext" message → every K=5/K=6 LLM proposal got -inf for the wrong reason |
| B v2 | Hypothesis-mutation, bug fixed | $4.83 | 58.15 | K=6 candidates won, but the gain was per_partition gaming (see below) |
| C | K=5 W-segment locked, only alphabets+modifications mutable | $5.36 | 62.51 | Below K=4 default's 63.10 — K=5 W-segment is structurally weaker |
| Deep-SA | Local 2-opt × 51 multi-start (NO LLM, NO API) | $0 | **70.79** | Run B's 2000-iter SA was inadequate; 2-opt from gen 66's "converged" state added +7.68 in 17 sweeps |

**Five load-bearing findings**:

(a) **The `per_partition_z` fitness term was K-gameable.** The metric
uses Prior A's hardcoded K=4 partitioning regardless of candidate K, so
smaller partitions (K=6) inflate the z-score artifactually. Downweighted
×15 → ×5 in `_fitness.py`. Under honest fitness, the Run B v2 "K=6 wins"
result reversed — K=4 default scores 63.10 vs K=6's ~62.

(b) **K=4 + Prior A default rule outperforms all tested alternatives
under honest fitness and proper alphabet search.** Empirical ranking:

| Hypothesis | Score (honest fitness, deep-SA refined) |
|---|---|
| K=4 + Prior A default rule | **70.79** (2-opt from gen 66; max of 51 deep-SA runs) |
| K=5 W-segment (top-ranked K=5 rule, exp 038) | 62.51 (Run C best) |
| K=6 + various consonant-count rules | ~58-62 under honest fitness |

The "W-structure is load-bearing" finding from exp 040 doesn't translate
to a better cipher hypothesis at K=5 or K=8. The Predicted-cipher-
structure section's recommendation to try `pos_in_w_seg_mod_8` is
**superseded by this empirical result**.

(c) **Cross-color English fragments quantified at the new best (70.79).**
Plaintext:
```
KUKMURALINGISTHAVESUCEASTNORTHEASTHIPIDUSITSWALLHUMMAYGODTHEHOFBERLINCLOCKPYONGANDPREINGBUTWCKKKT
```
Non-crib English words present: THE×2 (positions 28-30 crib, 57-59
non-crib spanning 3 colors), AND (79-81, 2 colors), HAVE (14-17, **4
colors**), MAY (51-53, 3 colors), GOD (54-56, 3 colors), BUT (88-90, 2
colors), HOF (60-62, 3 colors), WALL (44-47, 3 colors), SITS (40-43, 2
colors). **Every non-crib English fragment spans 2-4 colors** — exactly
the signature of a correct per-position substitution where the alphabets
are partially-correct (each alphabet at each color produces enough right
letters that natural words emerge cross-color, while extracting any
single color's substring still looks like gibberish).

Most striking: **"...SITS WALL HUMMAY GOD THE HOF BERLIN CLOCK..."** at
positions 40-74 forms a 35-character sequence of thematically-loaded
fragments around the confirmed BERLIN CLOCK crib. WALL + BERLIN +
religious vocabulary is consistent with the Nov 2025 Spy Museum
confirmation of Berlin Wall as one of K4's two thematic anchors.

(d) **Run B's 2000-iter SA was inadequate by ~13,000 swap evaluations.**
Exhaustive 2-opt best-improvement local search from gen 66's
"converged" state added +7.68 score in 17 sweeps (~13k evaluations).
The 48.10 ceiling (Run A) and 63.10 ceiling (Run B v2 under honest
fitness) were both **SA-truncation artifacts, not hypothesis ceilings**.
51 multi-start 2-opt runs produced a distribution: max 70.79, median
65.26, p10 62.51, p90 68.32. 45/51 random-init runs beat the previous
63.10 ceiling; 1 broke 70. Per-color partitions remain uniformly
gibberish (~-24 hex/char); all score improvement is in cross-color
English emergence.

(e) **Reward-hack guards added to scoring**, after Run B v1's analysis
showed the LLM operating blind on Run A's failed-eval scores converged
on hardcoding the plaintext via `chr()`/concatenation tricks that
bypassed the original literal-string detector:
  - `find_crib_construction_cheat` — AST scan for `chr(int)` calls with
    crib-letter ASCII codes (65,66,67,69,72,73,75,76,78,79,82,83,84) and
    single-char `Constant(str)` crib letters. Rejects if ≥10 of the 13
    unique crib letters appear via these primitives.
  - `multi_sentinel_check` — runs `decrypt_k4` against 4 non-K4-signature
    inputs (first/last swap, rotate-by-5, random-prefix, fully-random);
    rejects if ALL produce > 6 crib-letter hits at the K4 crib positions.
  - `differential_input_check` — perturbs 5 random non-crib ciphertext
    positions, requires ≥ 2 plaintext positions to change. The decisive
    test: hardcoded plaintext fails mechanically.

  Run A's 250 candidates re-scored locally: 98 (39%) caught as reward
  hacks. 6 had score >50 under the original scoring path because the
  harness never invoked the evaluator (a separate
  `SHINKA_ADAPTER_EVAL_MODULE` env-var bug — fixed via `shinka/.env`).

**Total spend across the new architecture: $25.12** (Run A $9.08 + Run B
v1 killed $5.85 + Run B v2 $4.83 + Run C $5.36) + deep-SA $0.

### Operational lessons from the multi-run session

These are setup / harness / fitness issues that bit during the session
and would bite again on a fresh run if not preserved:

**(1) `SHINKA_ADAPTER_EVAL_MODULE` env var.** The shinka subprocess
scheduler in `cluster/local.yaml` defaults to passing the literal
string `shinka_adapter.evaluate` as a Python file path. The actual
file is `.venv/lib/python3.11/site-packages/shinka_adapter/evaluate.py`.
Without the env var set, **every candidate's evaluator subprocess
fails to start and the harness reports score 0.00 for the whole run**.
This burned Run A's first $17.97 before diagnosis. Fix is now in
[`shinka/.env`](shinka/.env) — `SHINKA_ADAPTER_EVAL_MODULE=` set to
the absolute path of the installed evaluate.py.

Diagnostic signature: every `gen_N/results/job_log.err` contains
`python: can't open file '<cwd>/shinka_adapter.evaluate': [Errno 2]`
and the harness's database shows "0/N correct programs."

**(2) Recovering the wasted run.** When the env-var bug surfaced,
the 250 LLM-mutated `gen_N/main.py` candidates were still on disk —
just never evaluated. Scoring all 250 locally with the actual fitness
function revealed:
  - 123 valid candidates (all clustering at seed-level ~33)
  - **98 candidates (39%) were reward hacks** caught by the new
    guards: 36 by `find_crib_construction_cheat` (chr()/single-char
    crib-letter patterns), 58 by the literal-cheat detector, 3 by
    `differential_input_check`, 1 by `multi_sentinel_check`
  - 29 runtime errors in the LLM's code

Key behavioral finding: the LLM operating *blind* (seeing 0.00 for
every prior candidate) converged on hardcoded-plaintext patterns. The
top 6 candidates by raw composite score (the "fake" scores 50-75) all
used `chr(int)` calls or single-char concatenation to construct crib
letters while evading the AST string-scan. Multiple generations
independently rediscovered the same obfuscation pattern. **Without
the new guards, the harness would have rewarded reward-hacking
behavior.**

**(3) The `"A" * 97` fallback in `_decrypt_with_state` caused a
misleading sentinel rejection.** When the LLM proposed a K=5 or K=6
hypothesis with FREE_LETTERS arrays sized for K=4 (a common mistake),
`_decrypt_with_state` returned `"A" * 97` as a panic fallback. The
reversed-K4 sentinel test then saw `decrypt_k4(K4) == "A"*97 ==
decrypt_k4(reversed_K4)`, triggering the "100% identical positions
between K4 and reversed-K4 outputs → decrypt_k4 appears to ignore its
ciphertext argument" rejection — a *misleading* error message for what
was actually a structural inconsistency in the LLM's hypothesis. Run
B v1 wasted $5.85 with every K=5/K=6 candidate getting this
misleading -inf.

Fix: added `_diagnose_cipher_state` to `problem/initial.py` which
checks for specific causes (`len(FREE_LETTERS) != K`, constraint
plain-conflicts, constraint cipher-conflicts) and returns a clear
error message *before* the sentinel check runs. The LLM now sees
"hypothesis mismatch: K=5 but FREE_LETTERS has 4 entries" instead of
"appears to ignore its ciphertext argument."

**(4) The `per_partition_z` fitness term was K-gameable.** The metric
uses Prior A's hardcoded K=4 rule for partitioning the plaintext
regardless of which K the candidate uses. When the LLM proposed K=6
hypotheses, the smaller per-color partitions (~16 chars each, instead
of 24) had lower bigram chi-squared variance, inflating the z-score.
Run B v2's apparent "K=6 wins" finding (gen 9 score 58.15) was almost
entirely this artifact:

  - Gen 66 (K=4): per_partition_z = -15 (floor), contribution = -22.5
    at original ×15 weight
  - Gen 9 (K=6): per_partition_z = -3.66, contribution = -5.49 at ×15
  - Differential: +17 score from gaming, while global hex actually
    got *worse* (−21.99 vs gen 66's −19.91)

Fix: downweighted ×15 → ×5 in `_fitness.py::_fitness`. Under honest
weighting, K=4 default scores 63.10 and K=6 ~62 — the apparent K=6
advantage was scoring artifact only.

**Current composite fitness formula** (in
[`shinka/problem/_fitness.py`](shinka/problem/_fitness.py)):
```
composite = (
    100 * crib_frac
  + 30 * (hex_per_char + 9) / 10        # was 30, unchanged
  + 5 * per_partition_z / 10            # was ×15, downweighted to ×5
  + 10 * n1_thematic_bonus / 5          # N1 thematic keyword bonus
  + ioc_bonus                           # IoC English-band reward
  + bigram_penalty                      # bigram chi-squared penalty
)
```
With `crib_frac = 1.0` (cribs satisfied by structural construction
in Prior A), the baseline is +100 and remaining terms drive the
discrimination.

**(5) MaxSAT encoding's hidden mismatch.** Encoding bigram
likelihoods as MaxSAT soft constraints optimizes *bigram-optimal*,
but our composite fitness weights hexagrams ×30. They're not the same
target. EvalMaxSAT's 8h "optimal" (`s SATISFIABLE` at cost 264454)
scored 49.92 under composite — much worse than our 71.98 — because
hexagram patterns aren't captured. Encoding hexagrams as MaxSAT soft
constraints is infeasible at 26^6 = 308M possibilities × ~91 position
hexa-windows.

This is the fundamental reason MaxSAT can't break our ceiling: the
encoding language can't express the optimization target. The fact
that EvalMaxSAT *was* making progress (cost decreased monotonically
7.9M → 264k = ~30× improvement) shows the search was working — just
on the wrong objective.

**(6) Gen 66's converged FREE_LETTERS** (the 70.79 / 71.98 basin)
are stored at lines 596-601 of an earlier `shinka/problem/initial.py`
revision and are the empirical "best starting point" for any future
alphabet search on K=4 + Prior A default rule:

```
color 0: "XDJFUWYAZIKCNBSOEVLH"   (20 free letters)
color 1: "KHEIBZOGFSWCTNAUJDLMX"  (21 free letters)
color 2: "WOIREDQZCMHTPJAUXBGY"   (20 free letters)
color 3: "RQACBXWOHVGDULEJYIM"    (19 free letters)
```

These are the FREE_LETTERS strings after gen 66's internal SA convergence.
2-opt from this state reaches 70.79; one specific 4-swap perturbation
(captured in `/tmp/free_experiments_results.json`) reaches 71.98 after
further 2-opt.

**(7) Where HOF specifically persisted** (positions 60-62), across
independent search methods:
  - Gen 66 (Run A internal SA, score 48.10 under old fitness): `...THEHOF...`
  - 2-opt from gen 66 (70.79): `...THEHOF...`
  - Phase 1 perturbations in the 70.96-71.14 ridge: `...THEHOF...` (multiple)
  - 71.98 specifically: `...THEHOC...` (the F→C regression at pos 62
    in trial 92's specific perturbation; HOF returns in all other
    ridge candidates)
  - EvalMaxSAT 8h result (49.92 composite): `...MALIHOF...` (position 58-60)
  - Trial-crib v3 best `BURIED` at pos 5 plaintext: `...TBDHOF...`
  - Trial-crib v3 hits for `BAHNHOF` cluster at position 56-62

7+ independent search methods converging on `HOF` at positions 60-62
(or immediately adjacent 58-60). Strong evidence for German "Hof"
content in the actual plaintext. Most plausible word: `BAHNHOF`
(Bahnhof Alexanderplatz, the S-Bahn station directly adjacent to the
Weltzeituhr crib at positions 64-74).

**What this changes about the cipher hypothesis:**

The cipher is per-position substitution with K=4 alphabets selected by
`(2 × pos_mod_3 + consonant_count) mod 4`. The cribs are structurally
anchored by construction. Under exhaustive 2-opt alphabet search the
best plaintext reaches hex/char -16.98 — still 4 nats above readable
English (-13), but with cross-color English fragments emerging at
thematically-correct positions. The remaining gap is plausibly closable
with deeper alphabet search (more 2-opt multi-starts from gen 66's
basin), per-color cipher modifications not yet tested, or — if those
fail — a refinement of the rule itself that the exp 038 sweep missed.

## Post-71.98 search exhaustion (free local compute, 2026-05-25/27)

Following the 70.79 deep-SA result, an extensive series of free local
compute experiments tested whether any search strategy or hypothesis
variant could break the K=4 + Prior A default rule ceiling. **All
strategies converged to the same finding: 71.98 is the empirical
ceiling under the current cipher hypothesis, robust across rule
families, search algorithms, alphabet starting points, and
modification variants.**

### Push from 70.79 → 71.98 via perturbation around the basin

Phase 1 of `free_experiments_v2.py`: 200 perturbed starts (1-5 random
swaps from the 70.79 state, then 2-opt). Result:
  - **192/200 returned exactly to 70.79** (strong basin attractor)
  - **8/200 escaped to 70.96-71.98** (narrow ridge of slightly-better optima)
  - **New best: 71.98** (trial 92, 4-swap perturbation)

Best plaintext at 71.98:
```
KUKKURAWINGISTHAVESUCEASTNORTHEASTHIKIDUSITSWALLHUMMAYGODTHEHOCBERLINCLOCKKLONGANDPREINGBUTWWKBGT
```
9 letter changes from gen 66's converged state. HOF→HOC at position 62
is a regression on the German "Hof" thematic reading, but global hex
improved by 1.21 nats. Non-crib English fragments present at 71.98:
HAVE (4 colors), MAY (3 colors), GOD (3 colors), BUT (2 colors), HOC
(3 colors), AND (2 colors), SITS (2 colors), WALL (3 colors), THE
(twice). All emergent English remains cross-color — per-color
partitions stay uniformly gibberish at hex ~-24.

### Alt-rule deep-SA at 100 multi-starts each — alt1 ties default

Tested the 3 alternative K=4 rules from `k4_priors_by_k.json` with
matched 100-restart budgets:

| Rule | Max | Median | N > 70 |
|---|---|---|---|
| **alt1** `(2·(i%3) + 3·cc) % 4` | **71.64** | 65.46 | **1/100** |
| alt2 `(2·(i%5) + 1·cc) % 4` | 66.47 | 61.70 | 0/100 |
| alt3 `(2·(i%5) + 3·cc) % 4` | 66.34 | 61.87 | 0/100 |

**alt1's outlier at 71.64 effectively ties the default rule's 71.98.**
Default's lead is within noise (Δ=0.34). The "default rule wins"
conclusion from the prior 30-start sweep was sample-size confounded.
**Default and alt1 are co-equal candidates for Sanborn's rule** under
the natural-compound-rule family at K=4.

The HUNGARY fragment found in alt2's prior 31-start run did **not
recur** in 100 multi-starts (0/100 plaintexts contained HUNGARY) —
confirms it was a coincidence, not signal.

### Per-color partition reveals per-alphabet English signal at alt rules

**Methodology note:** the per-color partition is computed by extracting
plaintext letters at positions where `rule(i) == c`, concatenating
them (non-contiguous in the original K4 plaintext), and computing hex
on the substring. Random expectation for a uniform 16-25 letter
substring is hex ≈ -24.41 (the floor below which the hexagram tables
contain no entries). Real English at this partition length is around
hex -12 to -19 (calibrated from K1 plaintext segments of matching
length).

| Plaintext (rule, score) | C0 hex_free | C1 hex_free | C2 hex_free | C3 hex_free |
|---|---|---|---|---|
| Default 71.98 | -24.41 | -24.41 | -24.41 | -23.86 |
| **alt1 71.64** | -24.41 | **-21.12** ★ | -24.41 | -24.41 |
| **alt2 66.47** | -24.41 | -24.41 | **-17.38** ★ | -24.41 |
| K1 reference (real English) | -12.67 | -12.23 | -19.39 | — |

Two alphabets per alternative rule broke the -24.41 floor:
  - **alt1 color 1** (hex -21.12) free-only substring contains "SUBTL"
    at positions 6-10 — K1's first sentence is "BETWEEN SUBTLE SHADING"
  - **alt2 color 2** (hex -17.38, lowest per-color hex of any run) free-
    only substring contains "ANUMBER"/"IS A NUMBER" at positions 8-14

Caveat: per-color substrings are non-contiguous in the K4 plaintext, so
"SUBTL" and "ANUMBER" don't imply those words appear at specific K4
positions. They imply the alphabets for those colors are producing
English-like *letter sequences* at their assigned positions — partial
alphabet correctness.

### MaxSAT attempts — both failed to break ceiling

**RC2 + Glucose3 (PySAT, 34h crash):** Encoded the K=4 + Prior A
hypothesis as weighted MaxSAT (2,704 boolean variables, 67,832 hard
clauses for permutations + cribs, 64,800 bigram soft clauses,
max weight 3915). After 34h elapsed wall time the underlying Glucose3
SAT solver crashed with `libc++abi: terminating due to uncaught
exception of type Glucose30::OutOfMemoryException`. Memory grew from
21 GB → 77 GB (peak at 10h) then decayed to 47 GB before the crash.
**No partial model recovered** (called `RC2.compute()` not the
generator variant). Total lost: 34h, $0 (local compute).

**EvalMaxSAT (8h overnight, 2026-05-27):** Same WCNF encoding, switched
to EvalMaxSAT solver (algorithmically different — hybrid linear-vs-
core). EvalMaxSAT actually emitted incumbent cost updates (RC2 was
silent): cost decreased monotonically `7929449 → 1203485 → 464065 →
264454` (~30× improvement). After 8h hit the gtimeout SIGTERM, returned
`s SATISFIABLE` (optimality not proved). Decoded model:
  - **Composite fitness: 49.92** (under our actual scoring, including
    hexagrams)
  - Hex/char -23.59, cribs 4/4, plaintext less coherent than 71.98's
  - **HOF appears AGAIN at positions 60-62** (3rd run in a row across
    radically different optimization methods)

**Why MaxSAT didn't break the ceiling:** the encoding optimizes
**bigram likelihood**, but our composite fitness weights hexagrams ×30.
Bigrams alone don't capture hexagram patterns. The "bigram-optimal"
EvalMaxSAT solution scores far below the "composite-optimal" 2-opt
result. Encoding hexagrams as MaxSAT soft constraints is infeasible
(26^6 = 308M possibilities; combinatorial explosion).

**Sanborn-style alphabet inspection on 71.98's alphabets:** scanned
each of the 4 alphabets for partial-keyword structure (KRYPTOS-like,
BAHNHOF-like, ALEXANDERPLATZ-like substrings of length 4-10). **Clean
negative** — no Sanborn-context word fragments appear in any alphabet,
consistent with exp 037's finding that all alphabets must be
hand-crafted (not keyword-derived).

### Rule library expansion — 134 new compound rules, none beat ceiling

`rule_library_expansion.py` tested compound rules using NEW feature
families not in exp 038:
  - cumulative XOR of ciphertext bytes
  - position-of-nearest-doubled-letter
  - pos_mod 7 / 11 / 13
  - cumulative_consonant XOR cumulative_vowel
  - count of doubled-letter pairs before position
  - K4-letter-frequency rank
  - segment_id-with-doubled-letter combinations

For each new compound rule at K ∈ {3, 4, 5, 6} that is crib-consistent
and uses k_used = K colors, ran 2-opt from English-frequency-ordered
init.

  - 134 valid new rules surfaced (split: K=4 4 rules, K=5 48 rules,
    K=6 82 rules)
  - **Best new rule: `(cc_xor_vc + n_doubled_before) mod 5` → 65.01**
  - Other top rules: K=6 variants involving cumxor_ct, letter_freq_rank,
    pos_mod_11 — all in the 64-65 range
  - **0/134 rules exceeded the 71.98 ceiling**

Strongly negative: feature-space expansion using cumulative-XOR,
doubled-letter, mod-prime, and letter-frequency-rank features does not
produce a rule with higher alphabet ceiling than the default Prior A
rule.

### Beam search alphabet recovery — found a *different* basin

`beam_search_alphabets.py` (width 2000, English-freq branch order,
hex-prefix-scored pruning): position-by-position alphabet extension.
17.4 seconds wall.
  - **Best score: 66.78**
  - Plaintext: `ARKBUILDINGOFTHAVEFREEASTNORTHEASTHITISSUITSHOULDHAMONGMYDDWHOMBERLINCLOCKTYPMCLNWDRWIMGWUDGWKGKT`
  - Visible English: "ARK BUILDING OF", "HIT IS", "SHOULD" — *different*
    thematic surface than gen 66's "WALL MAY GOD HOF" basin

Confirms the K=4 hypothesis space has **multiple distinct
"near-English" alphabet basins**. Beam at width 2000 was likely too
narrow (all initial branches had identical hex scores → greedy lock-in
to one direction). The 66.78 basin and the 71.98 basin are distinct
local optima of the same hypothesis with different English content.

### Trial-crib substring sweep — no thematic word at any position breaks ceiling

Three versions tested:

**v1/v2** (English-frequency-ordered init): tested 23 thematic
substrings (BAHNHOF, ALEXANDERPLATZ, BORNHOLMER, MAUERFALL, WELTZEITUHR,
HUNGARY, MAYGOD, WOUNDS, WALL, etc.) at all feasible K4 positions, with
single-letter variants (top-9 English letters) for substrings ≤ 8
chars. For each consistent (substring, position) candidate, ran 2-opt
with combined real + trial constraints from English-freq init.

  - 681 trial-crib (substring, position) combinations beat the
    English-freq-init baseline by Δ > 1
  - **Top hits:** HUNGARY as HUNGANY at pos 75 (64.17), WOUNDS as WOHNDS
    at pos 7 (63.61), MAYGOD as MAYAOD at pos 51 (62.79), WALL as HALL
    at pos 44 (62.76), BAHNHOF as BASNHOF at pos 56 (62.30)
  - **All hits below 71.98** — but compared to weak English-freq
    baseline, not gen-66 basin

**v3** (gen 66 seeded — the proper test): 2-opt seeded from gen 66's
converged FREE_LETTERS with trial constraints added on top. The lenient
`_build_alphabet` accepts gen 66's letter preferences while honoring
new constraints. This properly tests whether any thematic substring at
any position EXTENDS gen 66's 71.98 basin.

  - **0/897 trial cribs exceed the 71.98 ceiling by Δ > 0.5**
  - Best v3 results all cluster *just below* 71.98:
    - MAYGOD as MAYGRD at pos 51: 70.84 (Δ=−1.14)
    - WALL at pos 44 (exact): 70.77 (Δ=−1.21) — *reproduces 71.98's plaintext exactly, scores slightly lower*
    - MAYGOD at pos 51 (exact): 70.54
    - WALL at pos 56: 70.33
    - BURIED at pos 5: 69.53
  - **Cribs consistent with 71.98's plaintext** (WALL@44, MAYGOD@51)
    reproduce that plaintext but score slightly lower because the
    constraint removes the perturbation slack that got us from 70.79
    → 71.98. **Cribs inconsistent with 71.98's plaintext** all score
    even lower (in the 67-69 range).
  - **Strongest possible negative for plaintext-side anchoring on the
    K=4 + default rule + gen 66 alphabets hypothesis.** No single
    substring anchor at any position can break the 71.98 ceiling.

### Per-color modification sweep — Caesar/reverse don't help

`per_color_modifications_v2.py`: for each of 4 colors × 26 modifications
(25 Caesar shifts + 1 reverse), rebuilds the crib constraints so the
modification is structurally consistent (cribs still satisfied under
the shift), then runs 2-opt from gen 66's FREE_LETTERS seed.

  - **Baseline (no mods, 2-opt from gen 66): 70.77** (close to the
    71.98 ceiling; small difference because the gen-66-seeded 2-opt
    differs slightly from the 70.79 → 71.98 perturbation path)
  - **Best single-color modification: color 1 with Caesar shift 7 →
    49.67**
  - **0 of 104 modifications exceeded the 71.98 ceiling**

Top 15 modifications are all color-1 Caesar shifts in the 47-50 range.
Modifications to colors 0, 2, 3 generally score worse (some hit the
K-at-74 -300 filter).

**Why:** under Caesar shift n at color c, non-crib positions in that
color produce plaintext shifted by n from what gen 66's alphabets
produce. Gen 66's alphabets are tuned for the no-modification hypothesis
— their English-emergent cross-color fragments depend on the unshifted
output. Shifting one color's output destroys those fragments.

To properly test "Caesar modifications are part of the cipher" we'd need
broad multi-start search under each (color, shift) hypothesis. Single-
start from gen 66 is decisively negative.

### Persistent signal across all post-71.98 work

**HOF at positions 60-62 appears in EVERY high-scoring plaintext we
have produced**, across radically different optimization methods:
  - gen 66 / Run A (LLM evolutionary search, 48.10 score)
  - 70.79 (2-opt from gen 66)
  - 71.98 (perturbation from 70.79; technically HOC here, but HOF in
    the surrounding 70.96-71.14 trials)
  - EvalMaxSAT (49.92 score, much lower fit)
  - Many trial-crib results

That's 4+ independent search methods converging on HOF at the same
position. Strong evidence for German "Hof" content (possibly the start
of "Bahnhof" / "Hofgarten" / "Lichthof" — train station or courtyard
in German Berlin context).

### Synthesis: 71.98 is robust

Five independent search strategies tested whether *any* path breaks the
71.98 ceiling:

| Strategy | Best | Δ vs 71.98 |
|---|---|---|
| Multi-swap from 71.98 (5000 samples 2/3/4-swap, then 2-opt) | 71.98 | 0 (genuine local max) |
| Alt-rule deep-SA (alt1, 100 multi-starts) | 71.64 | -0.34 (effective tie) |
| **Trial-crib v3 (gen 66 seeded, 897 trials)** | **70.84** | **-1.14** (closest, but doesn't break) |
| EvalMaxSAT 8h (bigram-optimal) | 49.92 | -22.06 |
| Rule library expansion (134 new rules) | 65.01 | -6.97 |
| Beam search (width 2000) | 66.78 | -5.20 |
| Trial-crib v1/v2 (English-freq baseline) | 64.17 | -7.81 |
| Per-color modifications v2 (104 trials) | 49.67 | -22.31 |

**71.98 stands as the empirical ceiling.** Multiple cross-method,
cross-hypothesis verifications. The K=4 + Prior A default rule + 2-opt
on alphabets + cribs structurally anchored is the strongest cipher
hypothesis we have, and additional search effort within this hypothesis
plateaus around 71-72 score / -17 hex/char.

To break the ceiling further would require either:
  - A fundamentally different cipher structure (not per-position
    substitution; possibly multi-stage Compose pipelines depth ≥ 3 or
    hand-crafted non-natural rules)
  - Plaintext-side anchoring: use the visible cross-color English
    fragments (HAVE, MAY GOD, HOF, WALL, AND, BUT, SITS) as known-
    plaintext constraints to extend the 24-crib set to 30-40 positions
    and re-search
  - Direct LM-based completion of the 71.98 plaintext to identify the
    most-likely full plaintext, then verify by re-encryption

Total spend across all post-Shinka work: **$0** (all free local
compute). Total session spend remains $25.12 (Run A + B v1 + B v2 + C).

## Structural ruling from the 24 cribs alone

This section captures findings derived from the cribs themselves
(without any plaintext priors or candidate search), which constrain
K4's cipher structure to a narrow shape. Source: exps 035, 036, 037.

### χ = 3: the minimum number of alphabets

Build the **crib conflict graph**: 24 nodes (one per crib position),
edge (u, v) iff cribs u and v cannot be satisfied by the same
alphabet permutation. Two cribs conflict iff:

  - same plain letter → different cipher letters (a permutation can't
    map one input to two outputs), OR
  - same cipher letter → different plain letters (a permutation has
    each letter at exactly one index)

The conflict graph has **24 nodes and 22 edges**. Its **chromatic
number is χ = 3** (computed in exp 035). This is a proven lower
bound: **K4's cipher must use at least 3 distinct alphabet
permutations**.

The reason χ ≥ 3 (a clean argument): plaintext T appears at 4 crib
positions (25, 29, 34, 68) with 3 distinct ciphertexts (V, R, S, T).
Three of those positions form a triangle in the conflict graph
(pairwise conflicting), forcing χ ≥ 3. Plaintext E similarly has 3
distinct mappings (F at 22, G at 31, Y at 65), confirming χ ≥ 3.

### No natural rule produces a valid 3-coloring; k=8 is the floor

What if the cipher's per-position alphabet selection rule is some
natural function R(i) → {0..k-1}? For R to be a valid cipher rule,
no two conflicting cribs can share R's value (color). Exp 036 tested
six natural rule families × k ∈ {2..13}:

| Rule family | k=2 | k=3 | k=4 | k=5 | k=6 | k=7 | k=8 | k=9 | k=10 |
|---|---|---|---|---|---|---|---|---|---|
| `position_mod_k` | 7 | 9 | 2 | 5 | 2 | 3 | **0** ✓ | 6 | 1 |
| `consonant_count_mod_k` | 6 | 9 | 4 | 4 | 2 | 3 | **0** ✓ | 8 | **0** ✓ |
| `vowel_count_mod_k` | 13 | 13 | 13 | 13 | 13 | 22 | 13 | 13 | 13 |
| `pos_in_w_seg_mod_k` | 7 | 6 | 7 | 4 | 1 | 3 | **0** ✓ | 4 | **0** ✓ |
| `w_segment_index_mod_k` | 13 | 22 | 13 | 13 | 13 | 13 | 13 | 13 | 13 |
| `dist_to_w_mod_k` | 7 | 4 | 5 | 7 | **1** | **1** | **1** | **1** | **1** |

Numbers = violations (0 = the rule produces a valid coloring).

**Two findings**:

(a) **No natural rule at k=3 is valid.** χ=3 is achievable only by a
selection rule outside our natural family (Sanborn-designed
position-to-alphabet table).

(b) **The minimum natural-rule k is 8**, achieved by three independent
rule families: `position_mod_8`, `consonant_count_mod_8`, and
`pos_in_w_seg_mod_8`. The W-related rule (`pos_in_w_seg_mod`, the
position offset within the current W-bounded segment) is one of the
three, consistent with Lethuillier's W-segmentation finding being
load-bearing.

### The dist_to_w near-miss

`dist_to_w_mod_k` has **exactly 1 violation across all k ∈ {6, 7, 8,
9, 10}**. The persistent obstruction is a single conflict edge:

> **pos 31** (E→G, W-distance 6, within NORTHEAST) ←→ **pos 65**
> (E→Y, W-distance 6, within BERLIN)

Both positions have W-distance exactly 6 (pos 30 → W@36; pos 64 →
W@58, both gap = 6), and both have plaintext E. Under any pure
`dist_to_w_mod_k`, they receive the same alphabet — but the cipher
needs different alphabets to encode E→G vs E→Y.

This single pair is consistent with either (a) the rule being a
refinement of W-distance that distinguishes "W ahead" from "W
behind" (signed dist), or (b) a different rule that's correlated with
W-structure (e.g., `pos_in_w_seg_mod_8`, which correctly distinguishes
these positions and has 0 violations), or (c) one of these crib
mappings is a Sanborn deliberate-misspelling exception analogous to
IQLUSION / UNDERGRUUND / DESPARATLY in K1-K3.

### No natural keyword satisfies any slot under k=8 rules

Exp 037 tested every natural keyed alphabet in an 88-keyword Sanborn-
context pool against each of the 8 slots under the three valid k=8
rules. **No slot in any rule has a fully-compatible natural alphabet.**
Best per-slot partial matches are 1-2 of 2-4 cribs — noise floor.

Combined with χ = 3 from exp 035 and 7 cribs uncoverable by any
natural alphabet from exp 033, this gives the **strongest structural
finding**: **at least some (likely all) of K4's alphabets are
hand-crafted permutations**, not derivable from any Sanborn-context
keyword.

### The W-segmented-one-alphabet-per-segment hypothesis is ruled out

The χ=3 coloring (from exp 035) puts crib positions from BOTH segment
1 (EASTNORTHEAST) and segment 4 (BERLINCLOCK) into EVERY color class.
No valid 3-coloring respects W-segment boundaries. Furthermore,
within segment 1 alone, plaintext T at positions 25/29/34 has 3
distinct ciphers (V/R/S) → segment 1 by itself requires ≥3 alphabets.

So a "Quagmire III with one keyword per W-segment" cipher (the
Lethuillier hypothesis taken literally) is **mathematically
impossible**. But the FINER W-structure (W-segment offset rather than
W-segment identity) IS load-bearing — `pos_in_w_seg_mod_8` is one of
only three valid k=8 natural rules.

### Predicted cipher structure

Combining the structural findings:

- **k ≥ 3 alphabets are required**, with **k = 3 reachable only via a
  hand-crafted (non-natural) selection rule**, OR **k = 8 reachable
  via specific natural rules** (`position_mod_8`,
  `consonant_count_mod_8`, `pos_in_w_seg_mod_8`)
- **All alphabets must be hand-crafted** — none derivable from natural
  Sanborn-context keywords
- **W-structure is load-bearing** at the per-position-offset level
  (not per-segment), with three independent lines of evidence:
  Lethuillier's null-distribution finding, exp 033b's `dist_to_w` best
  partial, and exp 036's `pos_in_w_seg_mod_8` zero-violation result

This is now a specific, narrow, mathematically-derived structural
prior. The natural next step is **a ShinkaEvolve sub-problem with a
fixed selection rule** (most likely `pos_in_w_seg_mod_8` since it's
the W-aligned variant that achieves zero violations) where the LLM
mutates the 8 hand-crafted alphabets directly. Cribs constrain ~3
positions per alphabet on average; the remaining ~22 positions per
alphabet are free for hexagram-fitness optimization on the 73
non-crib K4 positions. Estimated cost: $25-50 — same envelope as
existing Shinka runs but with a structural prior derived from the
cribs rather than guessed.

**UPDATE (2026-05-24, after Run A/B/C + deep-SA — see "ShinkaEvolve
hypothesis-mutation architecture" subsection above):** The
recommendation above was operationalized via two related tests. Run C
locked K=5 W-segment (the top-Scheidt K=5 W-feature compound rule from
exp 038, structurally related to K=8 `pos_in_w_seg_mod_8`) and reached
score 62.51 — **below** K=4 + Prior A default rule's 63.10 baseline and
far below K=4's 70.79 ceiling under exhaustive 2-opt alphabet search.
The "W-structure is load-bearing" intuition from exp 040 doesn't
translate to a better empirical cipher hypothesis at K=5 or
(by extension, given how close K=5 W-seg and K=8 W-seg are
structurally) at K=8.

**The strongest current cipher hypothesis is K=4 with the Prior A
default rule `(2 × pos_mod_3 + consonant_count) mod 4`**, where
exhaustive 2-opt alphabet refinement reaches score 70.79 (hex/char
-16.98). Cross-color English fragments WALL, MAY GOD, THE HOF, AND,
HAVE, BUT, SITS appear at thematically-correct positions in the best
plaintext. The remaining gap to readable English (hex -13) is 4
nats/char; whether it closes with deeper alphabet search, untested
per-color modifications, or a finer rule refinement remains the open
question.

## Cumulative ruling — what 33 experiments + Tier A/B/N2 + Opus expansion have closed

Across **23,592 high-quality Sanborn-register candidate plaintexts**
(Sonnet 5,220 + Opus hex-filtered 18,372) × 27 thematic framings × both
standard and KRYPTOS-keyed alphabets, the following cipher families
yield **zero solves** under known-plaintext attack — for every prior
tested, including the expanded Opus prior at 5× Sonnet's scale:

- **Single-letter polyalphabetic at any period 1-30**: Vigenere, Beaufort,
  variant-Beaufort, Quagmire I-IV, Caesar
- **Hill cipher at block sizes 2-8** (matrix encryption fully ruled out
  across the natural range)
- **Autokey (plaintext + ciphertext primer modes)** at primer L 1-10
- **Polygraphic 5×5-grid family** (Bifid, Playfair, TwoSquare,
  FourSquare): structurally ruled out by K4 letter completeness (26/26);
  mechanically confirmed in exp 030 Phase 1 across all 26 possible merge
  drop-letters (best 14/97 vs theoretical max ~90+)
- **Rectangular Playfair** (2×13 and 13×2, no merge): hill-climbed, best
  33/97 (exp 030 Phase 2/3)
- **Trifid 3×3×3** with periods 5/7/9, hill-climbed: best 37/97 (Sonnet),
  best 38/97 (Opus) — both far from solve threshold
- **ADFGVX-family**: structurally ruled out by length doubling
- **Q3 + modifications**: arithmetic position offset (a×i+b), reversed
  direction (plain/cipher/both), even/odd interleaved dual-key, single
  positional perturbation, single crib-letter substitution, ColumnarTransposition
  at W ∈ {3,5,7,10}, 10 sanborn-natural positional remaps (reverse,
  swap_halves, rotates, bit_reverse_7, K3_columnar_w7), double-Q3,
  W-segmented heterogeneous (6 segments × per-seg short-period Vigenere)
- **Two-pass K3-style columnar transposition** (B1) and **K3-style + Q3
  composite** (B4) across 12 keyword pool × 12 keyword pool (exp 031):
  144 (kw1, kw2) pairs × both passes both alphabets all conventions, 0
  solves; best B1 partial 16/97
- **K2-IDBYROWS-style single-letter ciphertext error model** (B2): each
  candidate × every (alter_pos, new_letter, alpha, conv, L) — 760M
  consistency checks against Sonnet, 2.7B against Opus, 0 solves total
  (exp 032)
- **Compose 2-3-deep pipelines**: 103,300 combinations of
  (positional_remap, columnar, Q3) at all 3 nesting shapes (exp 029)
- **Running-key Vigenere/Beaufort** from Carter, Smith, Buchan, K1-K3
  texts, both directions
- **20.5k-generator keystream library** against the cribs *and* against
  full 97-position shift sequences of all 23,592 combined candidate
  plaintexts (across both Sonnet and Opus priors)
- **Weltzeituhr + Mengenlehreuhr keystreams** in 85,000+ configurations
- **272 N2-proposed cipher constructions** (Sonnet hypothesis-generation
  output) cross-tested against candidates: 113 cipher builds OK,
  589,860 attempts (Sonnet prior) + 2,076,036 attempts (Opus prior),
  best partial 15/97 (Nicodemus on Opus, TwoSquare on Sonnet — both
  at noise floor)
- **ShinkaEvolve mutation search** (~$78 invested across two full runs):
  bandit-driven LLM mutations of `decrypt_k4` never crossed the
  cribs-satisfied threshold of score 100

**Total session API cost**: $5.70 (N1 Sonnet) + $0.92 (N2 Sonnet) +
~$45-49 (N1 Opus 4.7 expanded run) + $77.69 (Shinka v1+v2 OpenRouter)
= **~$130** (the failed Opus attempt with `temperature` deprecation
cost $0 — Anthropic doesn't bill errored requests).

Everything else (29 numbered experiments, Tier A/B sweeps, exp 029-030,
N2 cross-product verification) ran free on local compute. The Numba-
compiled + multiprocessing-parallelized inner loops (exps 027, 030)
delivered ~313M Playfair encrypts in 11 seconds on the M3 Max's 14 cores.

## Session 2026-05-28/30: experiments 043-128 + the findings ledger

Forty new attacks (14 from an expert ideation panel + 26 follow-ons),
each vetted against the rulings above. All ran at **$0** (local; `ortools` is
the only added dep). The two LLM passes (057 calibration, 058 generation) used
local **ollama/gemma** ($0). Plan + per-experiment detail in
[docs/attack_plan_043_057.md](docs/attack_plan_043_057.md); the auto-generated
cross-experiment ledger is
[experiments/results/FINDINGS.md](experiments/results/FINDINGS.md) — regenerate
with `python scripts/report.py` (every experiment emits a standardised
`Verdict` via [experiments/_verdict.py](experiments/_verdict.py)). **The full
narrative synthesis is [docs/K4_synthesis.md](docs/K4_synthesis.md); the
arXiv-style manuscript is [paper/k4_underdetermination.tex](paper/k4_underdetermination.tex)
(compiles to a 9-page PDF; see [paper/README.md](paper/README.md)).**
Net tally
across 86 experiments (categorised by `scripts/report.py`): **0 solved,
2 promising, 15 knowledge, 1 tooling, 2 inconclusive, 3 retired-LLM, 63 ruled out**
— the **2 promising** items (114/115) are the **homophonic reframe**: a 2-chart
*homophonic* model satisfies both hard facts (cribs via χ_b=2; flattening via the
homophonic floor=2) with fewer charts than the bijective ≥4 the squeeze assumed —
so the squeeze is a *bijective* bound, and the live model is now a **2-chart
homophonic bespoke chart**. The homophonic thread's three next-moves were then
*executed* (117–119) and all landed as **knowledge**: the homophonic crib-split
space (16,384 proper 2-colourings) is ~1,458× smaller than the bijective
3-colouring space (23,887,872) (117), each chart pins ~half its entries (118), yet
the free-position determinacy floor is **unchanged from the bijective model** —
nothing is determined above a coin-flip (119). So the
open gap is **decryption multiplicity** (under-determination is now proven
*model-robust*, bijective *and* homophonic), not chart count. The
earlier "live leads" count was a bucketing artifact (inconclusive/knowledge/retired
lumped together).
The 15 "knowledge" findings (058, 065, 071, 092, 093, 098, 106, 107, 117, 118, 119,
120, 124, 125, 128) *establish* the identifiability result — they are not partial solves; 7 once-inconclusive
items (067/084/091/097/102/104/108) were reclassified to ruled_out (a later
experiment superseded them), and 3 LLM runs (057/095/096) are tagged retired.
Twenty-eight follow-on directions were built in **exps 083–110** (verdicts
adversarially verified by a 12-agent
audit/re-derive/refute workflow that caught and forced a fix on real gaps in
089/090/091): reflecting-walk keystream (083) ruled out; modification fingerprint
(084) = flattening-not-transposition, calibrated; the squeeze formalized into a
closed bound (085); its two flattening candidates killed by exact crib algebra —
progressive-key Quagmire (086) and Q3 + additive overlay (087); the memorable
hand-crafted-alphabet escape hatch (088); the running-key inverse test (089) and
the 2-D physical-clock selector (090) both ruled out; a K1–K3 forward-invariant
hunt (091) that came up empty; and the **keystone identifiability result**
(092 analytic + 093 empirical): K4 sits at its **unicity distance** — at the
flatten floor k\*=4 it is barely (~14 bits) uniquely determined, and the
degeneracy turns on at exactly k=4 ({3:1, 4:10, 5:21, 6:25} distinct English
decryptions), so **K4 is information-theoretically under-determined for n-gram
cryptanalysis at the complexity it requires.** Finally 094 exhausted the
Sanborn-confirmed **Berlin Clock** (Weltzeituhr) as a *mechanism* — as a
per-position selector and alphabet source, joining 003 (keystream) and 049
(transposition) in the ruled-out column. Finally the two SOTA "outside
letter-statistics" levers were run: **095** put a calibrated 31B local LLM
(gemma4:31b-it) on the crib-consistent hexagram-English decryptions — it rates
them all meaningless (max 10/100 vs English 80), confirming under-determination at
the *semantic* level; **096** (Z3 MaxSAT) confirmed solutions exist in
multiplicity but the global optimisation is solver-intractable in budget (no clean
global bound added). Finally the three "outside-the-prose-prior" approaches ran:
**097** (register-driven — telegraphic/coordinate prior, search + 31B
register-judge) found crib-consistent decryptions wear a coordinate costume far
better than prose (judge 75 vs 10) — *plausible that K4's register is telegraphic*
— but it is partly circular and still under-determined; **098** (consensus
determination) showed the cribs determine **0** free positions beyond themselves
at ≥50% confidence (an information-isolation floor); **099** (interruptor
keystream) ruled out the last untested classical keystream mechanism; and **100**
showed 097's register signal was **circular** — an independent model (qwen3.5:27b)
on candidates *not* generated by register-search finds no telegraphic affinity
beyond the fixed cribs (register-driven 61 vs cribs-only baseline 45, prose-driven
24), so the one positive-looking texture was a search artifact. Every
letter-statistics axis and mechanism is closed, the strongest domain prior with
it, and no prose/telegraphic/LLM prior singles out the plaintext — see
**[Open directions — PICK UP HERE](#open-directions--pick-up-here-untested-0-local-pure-decipherment)**
for the full results.

**The squeeze (exp 082).** Facts 1+2 (positional one-to-one *and* flattened
beyond one alphabet) force K4 to be a per-position polyalphabetic with many
alphabets selected by a deterministic rule — but exp 082 (combined
position×ciphertext-context selectors, the untested product of 065 and 079)
shows the bind directly: combined selectors are proper colorings of the χ=3
graph only at high alphabet-count k (12–14), and *none* admits a consistent
crib-determined rotation — so a selector simple enough to be non-degenerate
cannot flatten, and one rich enough to flatten needs hand-crafted per-class
alphabets (degenerate, exp 059). The non-degenerate/flatten requirement is
unsatisfiable across all position/context/product selectors tested.

### Frontier round (exps 079-081): attacking the shared assumption

A 6-lens + adversarial-director ideation (which debunked several of its own
ideas in-repo) identified the load-bearing assumption behind all prior work:
**the cipher's "clock" is the string position `i`, key-phase-aligned from
position 1.** The three endorsed, non-degenerate (forward / few-parameter)
follow-ups:
- **079 — ciphertext-context selector** (the untested *self-synchronizing*
  frame: alphabet at `i` chosen by `g(C_{i-1},C_{i-2})`): **closed.** Of 42
  context selectors, **none even properly-colours the χ=3 graph** — so the
  "selector = preceding ciphertext" door (left ajar by 060/065/066) is shut for
  1–2-letter context.
- **080 — forward stage-structure classifier** calibrated on K1–K3: the fine
  family classifier **failed calibration** (K2→bifid; substitution/fractionation
  clouds overlap at N=97, so single-family verdicts are unsupportable) — but its
  *exact, plaintext-invariant* axes hold and corroborate 071: K4's IoC is
  flattened ⇒ **the outermost stage is a flattener, not a transposition**, and
  K4 is **flatter than a single substitution alphabet** ⇒ the flattening exceeds
  one alphabet (multi-alphabet / fractionation / composite).
- **081 — offset-7 anomaly**: K4's offset-7 autocorrelation (9 hits, a-priori
  p=0.005) is **not significant after multiple-comparison correction**
  (max-over-30 p=0.088) → **retired as small-N noise**; the geometries that peak
  at 7 are period-7 artifacts of already-closed families.

### Headline: the per-position-substitution model is RETIRED (exp 059)

The dominant hypothesis — K4 = per-position substitution with K alphabets
selected by a rule R(i) — is now closed by a *proof*, not just failed
searches. Both horns fail:

- **Closed-form rule → cannot fit.** No simple rule R(i)
  (position / consonant-count / Prior-A mod k, k ≤ 8) reproduces *any* N1
  candidate plaintext; the least-bad (`cc_mod_8`) still needs 20/97 position
  violations (exp 054).
- **Hand-crafted (free) rule → degenerate.** With K=8 alphabets and a free
  per-position assignment, **15 of 15 completely different fluent plaintexts
  byte-exactly encrypt to K4**, each with its own valid 8 alphabets (exp 059).
  A model that "verifies" an unbounded family of mutually-exclusive plaintexts
  cannot identify K4's — it is unfalsifiable as posed.

This recasts the ShinkaEvolve **71.98 basin as a free-assignment artifact**,
not a near-solution: exp 056 (K=4 tempered search with a smooth scorer + a
per-colour-coherence reward) leaves all four colour partitions at ~-24/char
gibberish — the cross-colour "words" are a mirage. It also contradicts
Scheidt's stated constraint ("simple, can be remembered and executed years
later"): eight bespoke alphabets + an arbitrary 97-position rule is neither.

### The structural bound behind it (exp 055)

For a K-alphabet per-position cipher, each plaintext letter maps to ≤ K
distinct ciphertext letters, so the 97-position conflict-graph chromatic
number lower-bounds K. The **minimum fanout is 7** across exp 055's 5,220
Sonnet candidates (exact χ = 7-8 by CP-SAT on the low-fanout subset), and it
holds across all **38,100** candidates in exp 058 (only 66 reach fanout 7);
none is admissible at K ≤ 6, and the repo's independent natural-rule floor
(k = 8) agrees. exp 058 turned this into a filter (96.2% of the 38,100 pruned →
1,436 admissible at K ≤ 8), but exp 059 shows admissibility is *necessary, not
sufficient* — once the model itself is retired, the filter points nowhere useful.

### Scoring is exonerated (exps 053, 061)

exp 053: the hexagram table is flat across much of the gibberish region (it
ties 41% of random-gibberish pairs; a smooth backoff char-LM, no torch,
separates 80% of those), so every *score-driven* conclusion warranted a
re-check. exp 061 ran it: re-ranking every candidate with the smooth LM vs
hexagrams gives 3/5 top-5 overlap and surfaces **no** hidden, more-English
candidate the hexagram scorer had buried. The bottleneck is **structural (the
cipher model), not the scorer.**

### Other families closed this session (all `verify`-grade negatives)

substitution→columnar transposition (043, 340k configs); null-deletion /
misspelling restoration (044); sub-uniform-IoC-as-fractionation-signature
(045 — IoC is *uninformative* at N=97: 23% of random strings match K4's
0.0361); tableau-route / compass-bearing / single-typo alphabets vs χ=3
(046/047/048 — need k = 9/11/9, never the 3-set); Weltzeituhr-as-transposition
(049); morse mask / 2-alphabet selector (050); sister-sculpture (Cyrillic
Projector) running key (051 — provisional, transliteration unverified);
rail-fence / route **+ the verified physical engraving layout `[4,31,31,31]`**
(052); few-parameter **autokey** (060 — of 1080 configs tested, only 55
survive crib-consistency, and those derive gibberish); and **Vimark/Gromark**
(062 — an algebraic KPA exploiting the linear lagged-Fibonacci recurrence
solves for the primer at *every* length L=2-24 over 5 alphabets × 2
conventions: all 230 systems are crib-INCONSISTENT, so no primer exists at any
length — closing the Bean-2021 leading academic hypothesis beyond exp 002's
L=4-5 brute force); the **whole two-term linear-recurrence keystream family**
(063 — the same algebraic KPA over all non-adjacent lag pairs `s_i=s_{i-j}+
s_{i-k}`, 2,514/2,530 systems inconsistent, the 16 determined ones all
gibberish); and **tiny 2-stage composites** (064 — every short block
transposition, period d=2-7, coupled with a short-period substitution, both
orders: 0 of 5,912 perms × alphabets × conventions × L become a fully-pinned
short-period substitution, like 043's columnar result). N1 LLM inference calibrated on K1 (057)
recovers theme/vocabulary but ~8% char-accuracy — a thematic prior, not
plaintext recovery.

### New reusable machinery

`experiments/_kpa.py` (KPA helpers + cached scorer + `best_over_transposition`),
`src/kryptos/alphabets_routes.py` (tableau-route alphabets),
`experiments/_crib_sat.py` (crib set-cover),
`src/kryptos/ciphers/keyed_fractionation.py` (length-preserving 2×13
fractionation), `src/kryptos/scoring/lm_fitness.py` (smooth backoff char-LM +
optional distilgpt2), and the filled `src/kryptos/solvers/sat_ilp.py`
(CP-SAT `fanout` / `min_alphabets_for` / `recover_coloring`).

### Wide-ideation round (exps 065-071): two new constraints, five more families closed

A 6-lens + adversarial-critic ideation produced genuinely-new directions; the
results sharpen the box K4 lives in:

- **exp 065 — selector characterization (the prune, ★).** Of 32 candidate
  position-features, **only the Prior-A rule `(2·(i%3)+cc)%k` is *non-trivially*
  graph-compatible** with the χ=3 cribs (p=0.003 vs a scrambled-edge control).
  Every `pos_mod_m` (m≤7) is invalid; all W-distance features are valid only by
  chance; **Phillips' block-mod-8 is invalid**. Since the one special positional
  selector (Prior-A) is exactly the one exp 059 retired as degenerate, the K4
  selector — if positional at all — is **non-positional / dynamic**.
- **exp 071 — entropy flatness bound (★).** The 73 free positions have unigram
  entropy **4.33 bits**, exceeding *every* monoalphabetic-English sample at that
  length (p99 = 3.88; 0/5000 reach K4's). This *proves* (like χ=3) that a
  **polyalphabetic or fractionating stage is required** — a model-agnostic lower
  bound. (It also debunks the per-plaintext-letter shift-clustering and
  restricted-shift-alphabet conjectures: E/T shifts spread by 19–23, and 14/26
  distinct shift values is unremarkable, p=0.19.)

**Five more families closed** (all exact KPA / admissibility, all `verify`-grade):
cipher-feedback & convolution matrix (066 — all 32 systems crib-inconsistent by
exact linear algebra); Chaocipher / dynamic wheels (068 — round-trip validated,
keyword-seeded + bounded SA reach only 15/24 cribs; the 2×26! keyspace is not
refuted in general but the Scheidt-memorable instances are); Phillips (069 — 6
monochromatic crib conflicts under block-mod-8); keyed-index & GF(2) 5-bit Hill
(070 — 0 consistent/invertible). Register scoring (067) was exonerated too: a
coordinate-register LM surfaced no buried candidate and coordinate plaintexts
floor at fanout 8 (≥ the prose 7), so the plaintext *model* was never the blocker.

### Speculative remainders run down (exps 072-076)

The last named candidates, attempted for completeness (all `verify`-grade,
self-tested where a cipher was implemented): **Chaocipher at scale** (072 — 28
restarts × 24k SA, ceiling 16/24 cribs, no trend → dynamic-alphabet exhausted
at hand-search scale); **3-stage tiny composite** T1∘sub∘T2 (073 — 46k
T-pairs/alphabet, 0 decryptable); **mod-27 / affine / 10×10-GF(2)-bigram Hill**
(074 — 0 consistent/invertible; closes the matrix conjecture across
mod-26/27, keyed/standard, linear/affine, GF(2)); **route (non-block)
transposition + substitution in both orders** (075 — rail/boustrophedon/
columnar/spiral/diagonal × both orders, 0 decryptable); and a **Hagelin M-209**
bounded hill-climb (076 — 19/24 crib displacements, no trend; deprioritised but,
given the enormous key space, *not* a formal refutation). Net: transposition +
substitution is now exhausted across block/route/columnar at depths 1–3 and
both orders, and the matrix and dynamic-alphabet families are closed at
hand-search scale.

### Net direction

The per-position-substitution family is **retired**; transposition /
composite-transposition (depth 1–3, block/route/columnar, both orders), autokey,
the **two-term linear-recurrence keystream family** (062/063), **all matrix
ciphers** (Hill standard/keyed/mod-27/affine/GF(2), feedback & convolution;
028/066/070/074), **Phillips** (069), and **Chaocipher / M-209 at hand-search
scale** (068/072/076) are all **closed**; scoring is **exonerated** in both
prose and coordinate registers.
The structural box is now very tight: K4 is consistent with single-letter
polyalphabetic, one-to-one positional, aperiodic shift, **requires an
entropy-flattening (polyalphabetic/fractionating) stage** (071), and — if its
alphabet selection is positional — uses a **non-`pos_mod_m`, non-block,
non-W-distance** rule (065); the only special positional selector (Prior-A) is
degenerate. **No named hand cipher remains that fits this box** — every
candidate in the classical taxonomy that is consistent with Scheidt's "simple,
memorable" description has now been tested and closed (043-078) — **including a
Lasry-scale parallel attempt on the dynamic/mechanical families** (077:
Chaocipher, 108.9M evaluations across 12 cores → 18/24 cribs, +2 over the
bounded run despite 160× compute, **no trend**; 078: M-209, 62.6M evaluations →
22/24 crib *displacements* but a gibberish decrypt, because matching mod-26
displacements is degenerately cheap against the M-209's enormous key, the same
underdetermination that retired the per-position model). Neither showed a basin
pulling toward a solution. The only non-refuted avenues are now (a) those
dynamic/mechanical families at **cluster scale** (orders of magnitude beyond
this, and a weak fit to the "keyword" framing — a long shot); and (b) a
**construction outside the named taxonomy** that no current hypothesis
anticipates. Both require a *new structural insight*, not another sweep: the
combinatorics now grow faster than the marginal information. The durable deliverable of this work is
the **tight structural box itself** — a stack of `verify`-grade closures plus
the χ=3, fanout-7, selector (065), and entropy-flatness (071) constraints — all
reproducible via `python scripts/report.py`.

## Open directions — PICK UP HERE (untested, $0 local, pure decipherment)

*Self-contained handoff for a new reader / new session. You need nothing prior
to this section to start.*

**Where things stand in one paragraph.** K4 (97 chars, public) is unsolved by
*method*. Four confirmed cribs only: EAST(22-25), NORTHEAST(26-34),
BERLIN(64-69), CLOCK(70-74); pos74 is K→K (a fixed point). The fully-known
K1=Quagmire-III(KRYPTOS,PALIMPSEST), K2=Q3(ABSCISSA), K3=double-columnar(width
7) are the calibration/Rosetta set. **Constraint: decipherment ONLY** — never
use the recovered plaintext, extra cribs from any solution, or **K5** (the
unreleased companion is off-limits, same as obtaining the plaintext). Only the
public K4 ciphertext + 4 cribs + known K1-K3 are admissible. Every experiment
(043-128) logs a standardised `Verdict`; the live ledger is
[experiments/results/FINDINGS.md](experiments/results/FINDINGS.md), regenerated
by `python scripts/report.py`. Reusable machinery in `experiments/_kpa.py`,
`experiments/_crib_sat.py`, `experiments/_verdict.py`, and `src/kryptos/`.

**Two facts that survived all 128 experiments, in tension** ("the squeeze"):
(1) K4 is **positional / one-to-one** (cribs map to fixed positions; Bean) —
this rules out length-changing/realigning ciphers (fractionated-Morse, Pollux,
Morbit, grille-with-realignment) a priori; (2) the free-position entropy (4.33
bits) is **flatter than any single substitution alphabet** — so the cipher uses
many alphabets. Together they force a per-position polyalphabetic with a
deterministic selector. **exp 085 formalized this into a closed bound:** the
flatten *floor* is k\*=4 alphabets (the min that, even in the best-case maximally-
mixing arrangement, reaches K4's 4.33-bit free-position entropy); the
determinacy *ceiling* is m≤24 (a non-degenerate selector must instantiate every
class it uses at ≥1 crib, else that class's rotation is free — the exp-059
degeneracy); and across the short position×ciphertext-context selector family,
**zero** selectors are both proper-3-colourings *and* crib-determined under the
rotation model (the proper ones all sit at high k=8–14, i.e. inside the flatten
band but crib-*under*-determined). So the region {flatten ∧ crib-determined ∧
short ∧ English} is **empty** — a simple-rule per-position polyalphabetic
cannot be K4. That bounds out an entire frame and redirects the search (below).

**Twenty-eight directions in play this session were built (exps 083–110).** The chain:
083 closed the last untested keystream *mechanism*; 084 gave a forward prior
(flattening, not transposition); 085 bounded out the simple-*selector* limb;
086/087 cashed out 084 and killed its two cleanest candidates by exact algebra;
088 closed the hand-crafted-*alphabet* limb; 089 closed the long-*meaningful*-key
(running-key) limb; 090 closed the alternate-*clock* axis; 091 found no new
forward invariant; and **092/093 are the keystone** — an analytic + empirical
identifiability result showing K4 sits at its unicity distance (under-determined
for n-gram cryptanalysis at the k\*=4 complexity it requires); 094 exhausted the
Berlin Clock (Weltzeituhr) as a *mechanism* (selector + alphabet source); and the
two SOTA "outside letter-statistics" levers ran — **095** (a calibrated 31B local
LLM rates every crib-consistent decryption meaningless, max 10/100: under-
determination is *semantic*, not just statistical) and **096** (Z3 MaxSAT: many
solutions exist but the global optimisation is solver-intractable in budget — no
clean bound added); and the three non-prose-prior approaches ran — **097**
(register-driven: crib-consistent decryptions wear a coordinate costume far better
than prose, judge 75 vs 10 — *plausibly K4 is telegraphic* — but circular and still
under-determined), **098** (consensus: the cribs determine **0** free positions
beyond themselves at ≥50% — information-isolation floor), **099** (interruptor
keystream ruled out — last classical keystream mechanism); and **100** broke the
circularity of 097's register signal with an independent model (qwen3.5:27b) on
non-register-generated candidates — register-driven 61 vs cribs-only baseline 45,
prose-driven 24 — confirming the texture was a **search artifact**, not intrinsic.
**Every letter-statistics axis, every keystream mechanism, the top domain prior,
and the register reframing are closed, and no prose/telegraphic/LLM plaintext
prior singles out the answer.** Finally an **information-source audit** (101–104,
deterministic) confirmed the input is correct and fully mined: **101** showed the
universal negative is robust to any single mis-transcribed crib letter (χ/fanout
unmoved across all 600 variants); **102/104** found 0 gaps in the public
method-clues and physical-sculpture features; **103** found the crib shifts
number-theoretically structureless. The public data is right and exhausted.

*Resolved this session (083–088 below; 089–104 in the next subsections, each
adversarially verified where it mattered):*

- **083 — reflecting (non-toroidal) tableau-walk keystream → RULED OUT.** 169k
  reflecting walks (billiard start-cell × step-vector × read-rule, + boustrophedon)
  over the KRYPTOS tableau × 2 alphabets × 3 conventions. Best walk = 7/24 crib
  shifts — *below* the 8/24 an equal sample of random keystreams reaches — and
  gibberish (free-hex −24.41). Keystream/generator attacks (toroidal **and**
  reflecting) are now exhausted.
- **084 — modification fingerprint from K1/K2 → INCONCLUSIVE, trustworthy forward
  prior.** Calibration holds (K1, K2 both read as plain Q3). K4 is pulled toward
  *flattening* modifications — `progressive` (nearest), `double_q3`, `overlay`,
  `fractionation` — not transposition (`stencil` last; unmodified Q3 rank 6/8).
  A prior, not a solve (separation within K4's noise radius).
- **085 — the squeeze, formalized → RULED OUT the simple-selector limb.** k\*=4
  flatten floor, m≤24 determinacy ceiling, **0** proper-and-crib-determined short
  selectors → feasible region empty (see squeeze paragraph above).
- **086 — progressive-key Quagmire, exact crib KPA → RULED OUT.** The #1 084
  candidate. 0/300 (alphabet × convention × linear/block/periodic-ramp) configs
  admit a consistent progression fit; scrambled-crib control = 0% chance fits, so
  a fit would have been meaningful. The fingerprint's statistical pull does **not**
  survive backward crib algebra.
- **087 — Q3 + short-Vigenère additive overlay (sum of two short periods, lcm>24),
  exact KPA → RULED OUT.** The period regime the ≤24 sweeps missed. 0/300 configs
  admit even a *consistent* two-period decomposition (control 0%). The other clean
  flattening modification, closed.
- **088 — memorable hand-crafted alphabet triples + simple selector → RULED OUT.**
  The 085 escape hatch. Combined the never-unioned pools (route + compass + typo +
  Kryptos-keyword = **6,689** alphabets); **no 3-cover of the 24 cribs exists**
  (best 3 cover 13/23; greedy needs 9; control 0%), so no simple-selector decrypt
  is even reachable. K4's mandatory ≥3 alphabets are not from these memorable
  families.

### The three ranked next-moves were built, verified, and closed (exps 089–091)

The negatives have a shape. The cribs *force* a per-position substitution
(Fact 1: C_i→P_i, same position, one-to-one — a final transposition would move
EAST off 22–25, so it's excluded). Within that forced frame the
**short-description** rules were already bounded; the two remaining axes were a
**long meaningful key** (a running key) and a different **clock** (we always
indexed by 1-D string position). Both are now closed, and a forward-invariant
hunt came up empty. Each was **adversarially verified** (a 12-agent workflow:
code audit + independent verdict re-derivation + refutation per experiment), and
each verdict below is the *post-correction* one — the review caught a real gap in
all three, which were then fixed and re-run.

- **089 — running-key INVERSE coherence test → RULED OUT.** 085/088 bound short
  selectors and memorable alphabets but not a *long meaningful* key. 013/051
  tested running keys only forward (guess the text → check cribs). The decisive
  inverse test — *recover the implied key letters from the cribs and ask if they
  read as English* — was never run. The EAST+NORTHEAST crib is a contiguous
  13-letter key fragment, BERLIN+CLOCK an 11-letter fragment. Across 4 message
  alphabets × 3 conventions × **4 independent key alphabets** (the Quagmire-IV
  degree of freedom — added after review flagged it) × 2 orientations, the best
  recovered key fragment scores −21.82, **4.6 below** the random-string max. No
  coherent-English key anywhere → the meaningful-running-key hypothesis is closed,
  strictly stronger than 013/051 (which only ruled out specific texts).
- **090 — 2-D grid-coordinate (physical-layout) selector → RULED OUT.** The
  "clock" axis: reshape the 97 chars into a width-W grid and key the alphabet on
  (row, col)/boustrophedon. K4's true engraving layout is *unsourced*, so widths
  7–31 are swept. Operative bar = crib-determined **and** full **and** English.
  Reduced (mod-2/3/4) selectors: 0/450 even properly 3-colour the crib graph (a
  real structural obstruction). Raw per-row/column selectors (added after review
  noted they're the literal "key on the column" reading): 63/125 *are* proper but
  every one is crib-**under**-determined (most of the 97 positions fall in
  crib-free classes → free rotation, the exp-059 degeneracy). **0** are
  full-crib-determined; none decrypts. The 2-D physical-clock axis is closed.
- **091 — K1–K3 invariant mining (family-matched nulls) → INCONCLUSIVE.** Hunt a
  higher-order statistic the known K1–K3 share *beyond their cipher family* that
  K4 must too. Review caught that a substitution-only null is wrong for K3 (a
  transposition) and that a rigid "all-of-K1–K3" gate hid a candidate doublet-rate
  trend; both were fixed (family-matched nulls — Quagmire for K1/K2, columnar for
  K3, both for K4 — plus a Monte-Carlo chance bar and a softer membership view).
  Result: **0** strict shared invariants (MC chance 0.048), and the doublet trend
  *dissolves* under the correct null (K3's doublet z: +1.32 → −0.62), so K2/K3/K4
  do not align. No new forward filter. (This is specific to these statistics and
  the all-of-K1–K3 rule — not a proof K4's higher-order structure is featureless.)

### The identifiability result (092–093): K4 is at its unicity distance

Two independent methods now locate the same boundary, which **explains** the
universal negative rather than just adding to it:

- **092 (Shannon, analytic).** Measured English redundancy D = 3.62 bits/char
  (entropy rate r = 1.085). For the HAND-CRAFTED multi-alphabet model 033/088
  force, the under-determination gap by alphabet count k is
  {1:−263, 2:−185, 3:−100, **4:−13.6**, 5:+69, 6:+162} bits — i.e. 97 letters +
  24 cribs *just barely* determine the plaintext at k=4 (~14 bits of margin) and
  fail at k=5. (Cheap rotation-alphabets have unicity ≈26–34 ≪ 97 and would be
  trivially solvable — but 085/088 ruled those out.)
- **093 (max-likelihood search, empirical).** Hill-climbing full hand-crafted
  alphabets under proper colourings, the count of *distinct* crib-consistent
  decryptions reaching real-English hexagram by k is **{3:1, 4:10, 5:21, 6:25}** —
  degeneracy turns on at **k=4**, exactly 092's analytic crossover. (And no simple
  selector even properly-colours the cribs, re-confirming 085/090, so the
  max-likelihood model's only support is arbitrary colourings.)

**The conclusion both reach:** the flatten floor (k\*=4, exp 085) sits right at
the unicity edge, so at the complexity K4 *requires*, 97 letters + 24 cribs admit
**many** English-statistic plaintexts and single out none. K4 is
**information-theoretically under-determined for n-gram cryptanalysis** — which is
why 35 years of letter-statistics attacks fail, and why the exp-059 degeneracy
appears. This is not defeat; it's a **reframing**: the intended plaintext is the
maximum-likelihood candidate under a prior that letter-statistics don't capture.

### What's left — the honest residue, and the SOTA levers

Within the crib-forced per-position frame, every *letter-statistics* axis is
closed (short selectors 085, memorable alphabets 088, long meaningful keys 089,
alternate clocks 083/090, flattening modifications 086/087, forward invariant
091, max-likelihood 092/093) — and now the **Berlin Clock** is exhausted as a
*mechanism* too (094: clock as selector + alphabet source ruled out, joining 003
keystream + 049 transposition). Progress now requires a constraint **outside
letter-statistics**. Ranked, all $0/local unless noted, none a paid API without
explicit approval:

1. **Sanborn DOMAIN priors → CLOSED as a mechanism (exp 094).** The cribs say
   BERLIN CLOCK; Sanborn confirmed (Nov 2025) the referent is the Weltzeituhr.
   003 (keystream), 049 (transposition) and 094 (the per-position alphabet
   *selector* across all 24 phase alignments + UTC/column/marker class-rules, and
   Weltzeituhr-keyed alphabets in the χ=3 cover) all fail: 0 proper colourings, 0
   crib-determined fits, no 3-cover. The clock cannot supply a *mechanism*; it
   could only ever supply a *plaintext* pointer (a semantic constraint), which is
   lever 2.
2. **Semantic language prior → DONE (exp 095): confirms under-determination at
   the SEMANTIC level.** A calibrated local 31B model (`gemma4:31b-it`, $0;
   English 80 / gibberish 0) scored 16 distinct crib-consistent *hexagram-English*
   decryptions (from the 093 hillclimb, k=4/5): **max semantic score 10, mean
   3.1** — all meaningless (the best is `…PAIREDPROGRATION…EASTNORTHEAST…
   BERLINCLOCK…`, cribs embedded in salad). So cipher + language prior (n-gram
   *or* a 31B LLM) cannot single out the plaintext. This is the strongest possible
   confirmation of 092/093: K4 is under-determined semantically, not just
   statistically. (A semantic-as-search-fitness variant is possible but far
   costlier and bounded by the same 092 result.)
3. **MaxSAT / SMT (Z3) → DONE (exp 096): solver-limited, conclusion unchanged.**
   The SAT pre-check confirms crib-consistent decryptions exist in multiplicity;
   but Z3 Optimize (Distinct + soft bigram rewards) **times out (`unknown`) with no
   proven optimum** — the MaxSAT is intractable for Z3 at this scale. That is a
   statement about solver scaling, *not* about the optimum, so 096 adds no clean
   global bound. The under-determination already stands three independent ways
   (092 analytic, 093 annealing, 095 LLM); a CNF/RC2 MaxSAT re-encoding could push
   further but is not worth it against an already-triply-established result.
**The three "open" approaches were built (exps 097–099).** None assumed a unique
solution; each tested a load-bearing assumption, extracted partial info, or closed
the last mechanism:

4. **Register-correct prior, *driven* (exp 097) → PLAUSIBLE but insufficient.**
   The deepest untested assumption: every search maximised *fluent-prose* English,
   but the cribs are navigational and K2 spelled coordinates. 097 re-derived
   unicity under telegraphic redundancy (D_tele=4.0 — slightly *more* formulaic
   than prose, but the crossover is still k=5, so register doesn't rescue
   uniqueness), ran a register-LM-driven search, and applied a calibrated 31B
   **register-matched judge** (reg-ctrl 97.5 / gibberish 0 / prose 3.3). Result:
   crib-consistent decryptions wear a **coordinate costume far better than prose**
   — judge max **75** vs the prose-judge's **10** (exp 095) — *weak support that
   K4's register is telegraphic*. BUT it's partly **circular** (optimise register →
   judge by register) and still **under-determined**: the best is coordinate-
   *flavoured salad* (`…FIVE…TEN DEGREE…EASTNORTHEAST…` amid gibberish), below the
   control bar and non-unique. The register prior is apt but does **not** single
   out the plaintext.
5. **Partial / consensus determination (exp 098) → a quantified floor.** Across
   4,000 crib-valid models (proper 3-colourings × uniform free-class assignment),
   **0 of 73** free positions are consensus-determined at ≥50% confidence — the
   skeleton is *just the cribs*. 30 free positions even contain a crib cipher-letter
   (9 unambiguously), yet under selector uncertainty none is pinned more than ~⅓ of
   the time. The cribs are nearly **information-isolated**: they determine
   essentially nothing beyond themselves — a partial-recovery floor confirming
   092/093 from another angle.
6. **Interruptor / irregular-advance keystream (exp 099) → RULED OUT.** 13,728
   configs (26 interruptor letters × L=2-12 × reset-before/reset-after/skip/advance
   × 4 alphabets × 3 conventions): **0** admit a consistent fully-pinned schedule
   (scrambled-crib control 0% — a fit would have been meaningful). The last untested
   classical keystream mechanism is closed; with 006–009/083/086/087, *every*
   keystream family — toroidal, reflecting, progressive, two-period, interruptor —
   is now exhausted.

7. **Register signal, non-circular re-test (exp 100) → CIRCULAR, thread closed.**
   097's "75 vs 10" looked like positive texture, so 100 stress-tested it with an
   *independent* model (qwen3.5:27b, not gemma) on candidates that were *not*
   register-driven, plus a cribs-only-filler baseline. Means: register-driven
   **61**, cribs-only baseline **45**, random crib-consistent **45**, prose-driven
   **24**. Only the register-*optimised* pool beats the baseline; the fixed
   navigational cribs alone account for the rest. So 097's signal was a **search
   artifact** — no intrinsic telegraphic affinity. The register reframing is closed.

**Net:** every letter-statistics axis, keystream mechanism, domain prior, and the
register reframing are closed. The one positive-looking texture (097) was shown
circular (100). No letter-statistics, mechanism, or prior approach remains
untested under decipherment-only.

### Information-source audit (exps 101–104): is the public data correct & fully mined?

After the cipher search closed, four deterministic (no-LLM) experiments asked not
"which cipher" but "is there *more information* to extract" — by checking the
input and mining the public artifacts:

- **101 — ciphertext-transcription robustness → ROBUST (the key result).** The one
  assumption nobody had stress-tested: that the canonical 97-char string is
  letter-perfect. Recomputed χ / fanout / simple-selector-colourability for all
  **600 single-letter** crib-position variants (+172.5k high-value two-letter):
  minimum χ stays **3**, fanout stays **3**, **0** enable a simple selector. So no
  single misread engraving letter makes K4 structurally simpler — **the universal
  negative is not a transcription artifact.** (Only 36 *two-letter* simultaneous
  swaps drop χ to 2 — implausible as accidental, flagged honestly.)
- **102 — public method-clue catalog → 0 gaps.** All 8 documented public Sanborn
  *technique* hints (Berlin Clock, "not a K1–K3 technique", "I modified the
  system", "masking", "leads to a location", IDBYROWS precedent, …) map to
  experiments and are closed/tested; a fresh periodic-mask probe finds no decoy
  mask that simplifies the cribs. No public hint implies an untested mechanism
  (without waiting for a future reveal — forbidden).
- **103 — crib-shift number theory → structureless.** The 24 crib shifts are not a
  ≤degree-2 polynomial, short linear recurrence, common indexed sequence, or
  run-to-run transform in any alphabet/convention. No hidden key-schedule rule.
- **104 — physical-structure audit → 0 gaps.** All 8 deterministic sculpture
  features (tableau + its 27-letter anomaly, Morse, compass, Weltzeituhr, line
  layout, K1–K3 keys, pos-74 fixed point) are extracted; the doubled-L anomaly
  gives no crib-coverage gain (26→4, 27→4).

**Conclusion of the audit:** the input is **correct** (101) and the public data is
**fully mined** (102/103/104) — which *strengthens* rather than weakens the
measured result: the public ciphertext + 4 cribs + sculpture genuinely do not
contain enough information to uniquely determine K4's plaintext (092/098), and we
have now verified there is no un-extracted deterministic information and no
transcription escape hatch.

### Literature-review batch (exps 105–109): SOTA methods + the K5-free subset of an external review

An external research pass proposed SAT/ILP decipherment (Ravi–Knight), neural and
HMM/MCMC methods, a two-stage "masking" model (Scheidt), and unicity attacks. Its
top recommendations rely on **K5** and the **recovered plaintext** — both forbidden
here — and on **LLM/neural** methods (retired). We built the **deterministic,
K5-free, no-LLM subset**:

- **106 — joint CP-SAT selector falsification (the standout) → the squeeze, now
  SOLVER-PROVEN.** The literature gap: no published SAT/ILP formulation of a
  *crib-constrained multi-alphabet-selector* cipher. OR-Tools CP-SAT, per
  closed-form selector, *proves* one of two verdicts: **11/12 selectors are
  crib-INFEASIBLE** (no k-alphabet decryption satisfies the cribs — provably not
  proper 3-colourings: i%2–i%7, row-7, non-vowel-clock, prior-A), and the lone
  feasible one (i%8) reaches **67** common bigrams vs English's ~34 → **degenerate**.
  No closed-form selector is *both* crib-feasible *and* English-determined — the
  empirical squeeze (082/085/093) is now a deterministic per-family proof.
- **105 — two-stage mask→keyword-Vigenère core (Scheidt "masking") → RULED OUT.**
  An additive mask (per-class rotations) + period-L keyword core forces the crib
  shifts to factor `s_i = a[g(i)] + b[i mod L]`; **0/1296** configs even factor
  (control 0%). So the additive reading of "masking" is closed; a *non-additive*
  chart/lookup mask = the idiosyncratic hand-crafted-alphabet residue (088), not
  enumerable.
- **107 — MCMC joint posterior (Stamp/Chen–Rosenthal, no-LLM) → under-determination,
  third method.** Metropolis sampling of the joint (selector × k=4 alphabets)
  posterior gives a **diffuse** result: mean per-free-position marginal entropy
  **4.09 / 4.70 bits**, 0/73 positions determined — a Bayesian confirmation of
  092/093/106.
- **108 — Sanborn-conditioned n-gram prior → prior-robust (data-limited).** A char
  LM from Sanborn's actual K1–K3 plaintexts is only ~768 chars — too starved to be
  a reliable discriminator (an apparent re-rank "signal" is overfitting over 4
  candidates). The under-determination is robust to the best realisable
  author-specific prior.
- **109 — unicity D-sweep → conclusion robust; the review's D-attack is wrong.**
  Across D ∈ [3.4, 4.3], the under-determination crossover is **k=5 for D ≥ 3.5**
  (including both measured values: prose 3.62, telegraphic 4.0) and k=4 only at the
  extreme D=3.4. Higher D moves the crossover *up*, so the review's "may not survive
  D ≥ 4.0" is incorrect (at D=4.0 it's k=5). (Antipodes byte-diff skipped —
  `antipodes.txt` is an un-populated placeholder.)

**Net:** the review's K5-free, deterministic, no-LLM subset *confirms and tightens*
the existing result — 106 turns the squeeze into a solver proof, 105 closes the
additive masking reading, and 107/108/109 confirm under-determination from a
Bayesian, an author-prior, and a redundancy-sensitivity angle. The one
genuinely-useful new fact (the auction catalog's "chart-based coding system" for
K4) is decipherment-legal and *corroborates* the residue: a hand-built chart with
bespoke alphabets, exactly what 088 proved is required and couldn't enumerate.

**exp 110 tested the chart-based hypothesis for signal → none.** If "chart" meant a
*systematic* hand-construction grammar (Friedman/Callimahos canon: keyword-keyed
columnar-mixed alphabets, decimation/multiplicative mixed alphabets, route reads)
rather than arbitrary bespoke alphabets, some 3 of them should χ=3-cover the cribs.
Over 10,020 such alphabets (30 keyword bases × 5 methods): **no 3-cover** (greedy
needs 6), and the best 3-partial cover is **15/23 — vs 14/23 for random alphabets**
(per method: decimation 15, boustrophedon 13, columnar 11, diagonal 10). Construction
grammars cover **no better than chance**, so the chart is **not grammar-constructible**
either — it is genuinely bespoke (≈26!³, recoverable only with the sealed chart).
This *tightens* 088 (the alphabets are not memorable AND not grammar-built) and
makes the "chart-based" fact an **explanatory keystone, not a lever**: it confirms
*why* every algorithmic attack across 110 experiments failed — there is no
algorithm or construction rule to find.

**exp 111 — the cross-disciplinary signal capstone (power-validated).** A final
"is there ANY signal, through any science?" battery: 8 lenses spanning information
theory (lzma/bz2 compressibility), statistics (runs, bigram-χ²), signal processing
(DFT periodogram), combinatorics (repeated bigrams), and classical crypto
(Friedman IoC-by-period, autocorrelation), each with a permutation p-value vs each
section's *own* shuffled multiset (the null that destroys only order). **Power
check (the crux):** the same battery *detects* the known ciphers' structure — it
reads **K2's polyalphabetic period at exactly m=8 (= ABSCISSA's keyword length)**
and K1's period (m=20, a multiple of PALIMPSEST=10). **K4 result: 0/8 tests survive
Bonferroni** (best p=0.048; IoC-by-period p=0.91). So the instrument that reads
K1/K2's keyword periods off the ciphertext finds **no structure whatsoever in K4**
— its letter order is statistically indistinguishable from a random shuffle of its
own letters. The bespoke chart fully randomised the order; **the public ciphertext
carries no exploitable signal beyond the cribs**, now confirmed across five
sciences with validated power.

### The HOMOPHONIC reframe (exps 114–128) — the model was over-constrained

Re-examining a foundational assumption (that K4's alphabets are **bijective**, held
since exp 035) opened the session's first *promising* results:

- **114 — χ_b = 2.** The published χ=3 used *both* crib-conflict types. But a
  **homophonic** chart (one plaintext letter → several cipher homophones; decryption
  many-to-one) legitimately allows the "same-plaintext→different-cipher" conflicts —
  only "same-cipher→different-plaintext" binds it. That homophonic chromatic number
  is **χ_b = 2 < 3**: the cribs need only **two** decryption charts.
- **115 — homophonic flatten floor = 2.** A 2-chart homophonic cipher flattens
  English to **4.63 bits**, past K4's 4.33 (homophony spreads frequent letters
  across homophones — the classic flattening mechanism). The bijective floor was
  k\*=4 (085).
- **So a 2-chart HOMOPHONIC model satisfies BOTH hard facts** (cribs χ_b=2 +
  flattening) with far fewer charts than the bijective ≥4. **The squeeze (082/085/
  106) is a *bijective-model* bound; it does not bind a homophonic chart.** This
  reframes "what K4 is": the most economical structure fitting both proven facts is
  a **2-chart homophonic bespoke chart**, exactly matching the auction catalog's
  "chart-based coding system" (homophonic charts are literally that).
- **116 — but the selector is still bespoke.** 0/9 simple 2-class selectors
  properly 2-colour the b-graph, and the non-injective free entries leave the 73
  free positions under-determined. So the homophonic model is *simpler and matches
  both facts*, but does **not** yield a unique decryption — it sharpens the
  description of the residue without breaking the under-determination (092/093).

This is genuine new understanding: K4's residue is now best characterised as a
**2-chart homophonic hand-chart with an idiosyncratic selector**, not a ≥3-alphabet
bijective polyalphabetic. The open gap is decryption multiplicity, not chart count.
(Along the way 112 closed the period/width range 25–48 and 113 closed the physical/
mnemonic alphabet family.)

**The three next-moves on the homophonic thread — EXECUTED (exps 117–119).** All
three landed as **knowledge**: the reframe is the most viable *structure* found, but
the under-determination is model-robust.

- **117 — enumerate the proper 2-colourings.** The b-graph is 10 edges over 24 crib
  nodes: **9 edge-bearing components** (eight 2-cliques + one triangle-free 3-node
  path) + **5 isolated nodes**. So there are exactly **512 structural 2-colourings**
  (256 distinct pinned chart-pairs), and **16,384 proper 2-colourings** of the 24
  crib positions counting isolated-node freedom — vs **23,887,872 proper
  3-colourings** of the same 24 positions in the bijective graph. Apples-to-apples
  (total vs total), the homophonic crib-feasible selector space is **~1,458× smaller**
  (23,887,872 ÷ 16,384 = 1458). The "far fewer valid 2-colourings" hypothesis is confirmed,
  and 16,384 is small enough to enumerate *exhaustively* (118/119 need no sampling).
- **118 — crib-extended homophonic KPA (exact entry accounting).** Of the 14
  distinct crib cipher letters, **9 are ambiguous** (map to two plaintexts each:
  F→E/O, R→S/T, V→L/T, Q→N/O, P→C/R, N→B/H, K→A/K, S→S/T, T→I/N) — these *are* the
  9 forced splits. Each chart pins **9–14 of its 26** entries (median **11.5**),
  leaving **~14.5 free, non-injective entries per chart**. But the
  **guaranteed-determined free-position
  floor = 0**: no free position is pinned independent of the selector, because every
  ambiguous letter is split across the two charts by construction, so a free
  position carrying one decrypts to *one of two* letters by selector branch.
- **119 — homophonic consensus (098 redone, exact).** Over the full model space
  (16,384 colourings × 2 chart-choices), the consensus floor at any meaningful
  confidence is **0** — identical to 098's bijective result. The "30 positions at
  ≥50%" are *all exactly 0.5* (max consensus = 0.500): a single-instance crib letter
  is pinned in 1-of-2 charts → forced in exactly ½ of instances, vs 1-of-3 = 0.33 for
  a single-instance letter in the bijective 3-chart model (a multi-instance letter
  can reach 0.5 even bijectively — e.g. cipher P — but those happen to sit only at
  crib positions, so 098's exact bijective free-position floor is still 0 at ≥50%).
  The 2-vs-3 chart count merely lands single-instance letters *on* the coin-flip
  boundary; **nothing is
  determined above a coin-flip in either model.**

**Net of 117–119:** the homophonic reframe narrows the crib-feasible colouring
space ~1,458× (16,384 vs 23.9M) and pins ~half of each chart, but the
**free-position determinacy floor is unchanged** — under-determination of the 73
free positions (092/093/098) is now
proven **model-robust** (it holds exactly for the 2-chart homophonic model too).
The homophonic model is structurally the most viable class found (both hard facts,
far fewer colourings), yet decryption requires information **beyond the cribs**.

**The frontier, sharpened — the 73 free positions are TWO disjoint problems.** The
decryption is `P_i = chart[S_i][C_i]`, where the cribs pin chart *entries* globally,
not positions. So whether crib/selector algebra can ever fix a free position turns
entirely on whether its ciphertext letter is crib-pinned, which splits the 73
exactly (verified against 118/119 data):
- **30 "selector-locked" positions** — the ciphertext letter *is* crib-pinned, so
  the chart entry is known and only the selector bit `S_i` is free → consensus is
  **exactly 0.50** (a coin-flip). A plaintext prior is pure re-weighting here; it
  *cannot* manufacture the missing selector bit. Only a **selector-coupled** fact
  can move these: **(M1)** an external per-position pattern that pins `S_i` directly
  (clock geometry, engraving layout, Morse, bearings), or **(M2)** a chart-tie
  `chart2 = transform(chart1)` that forces a crib-pinned letter in *both* charts.
- **43 "prior-governed" positions** — the ciphertext letter *never* appears in the
  cribs, so *both* chart entries are free → no coin-flip, but also no crib anchor:
  these are constrained *only* by the plaintext prior. Crucially, "prior-governed"
  is **not** "determined" — exp 124 measured the joint decode and found the
  (saturating hexagram) prior leaves them the *most* ambiguous positions of all
  (per-position entropy 3.19 bits vs 1.08 for the selector-locked, which are
  anchored by their recurring crib letter). A *sharper* prior (PPM/word-level) is
  the open lever, but it is unproven that any deterministic prior pins them.

So Path A (a stronger plaintext prior) and Path B (a new chart/selector fact)
target disjoint halves. Both were built (125/126) and both are now closed for
admissible deterministic methods: a sharper char-LM prior does not resolve the 43
(125), and no chart-tie / clock / autokey / engraving-grid selector resolves the 30
(121–123, 126). **Anything selector-decoupled (MDL-over-charts, register priors,
chart-count metadata) is mathematically capped at 0.50 on the 30**; and the 43 are
information-theoretically under-determined by char-level priors. What remains is
strictly external (the exact carved layout, or a Sanborn-released 5th crib) — see
the 120–127 record below.

### Attacking the two halves (exps 120–124) — both selector-coupling mechanisms fail

A wide-net ideation pass (6 independent lenses + an information-theoretic synthesis)
produced the selector-coupling filter above and a ranked menu; the build-now items
were executed:

- **120 — diagnostic gate (knowledge).** Exact structural numbers that re-price the
  menu: a random selector mask 2-colours the cribs with probability **2⁻¹⁰** → a
  mask budget **N_max = 52** before colouring-passes are expected by chance; the
  joint chart-aware decode has only **≤43 free cells** (chart × cipher-letter), not
  73 letters; the **30 / 43 split** confirmed exact, with the 43 falling in **12
  tied groups, 0 singletons** (heavy cross-position tying).
- **121 — chart-tie / M2 (ruled out).** Across 26 transforms × 16,384 colourings,
  **zero** Caesar/Atbash chart-ties (`chart2 = T(chart1)`) are even crib-consistent
  (a full linear tie over-constrains; the random null is also 0), and **no** rigid
  keyed-alphabet pair (KRYPTOS/PALIMPSEST/ABSCISSA × shift) satisfies all 24 cribs.
  The two charts are bespoke and **not** linearly related.
- **122 — Weltzeituhr selector / M1 (ruled out).** **0 / 48** UTC-sign and
  UTC-parity masks (the Sanborn-confirmed clock, all 24 phases) 2-colour the b-graph
  — the confirmed clock is not the homophonic binary selector either (complements
  094's bijective negative). (The random-selector null reaches ≈−14.6, reconfirming
  that hill-climbing free cells hits the English floor under *any* passing selector,
  so a decrypt only counts if it beats that null.)
- **123 — autokey / self-referential selector (ruled out).** The one family where a
  language prior could couple *into* the selector. Ciphertext-coupled selectors
  (`S_i = g(C)`): **0 / 8** 2-colour. Plaintext-autokey (`S_i = f(P_{i−1})`): the
  search found **no** crib-consistent rollout (best 4/24 mismatches) — tying the
  selector to the prior decoded letter makes it a forced consequence that *cannot*
  be chosen to satisfy the cribs. Message-internal selectors do not break the floor.
- **124 — joint decode, residual ambiguity (knowledge).** The strongest decode tried
  (joint SA over selector bits + free cells): **80 / 80 restarts reached distinct
  English-level decrypts** (best −12.94 free-hex). A different fluent decrypt every
  time — overwhelming residual ambiguity, confirming under-determination under the
  best available deterministic decode. It also overturned a naive guess: the 43
  prior-governed positions are the *most* variable, not the least (the prior governs
  but does not pin them).

**Net (120–124):** of the two mechanisms that *could* move the 30 selector-locked
positions, M2 (chart-tie) and M1 (external clock / message-internal autokey) are
both ruled out. The 30 now demonstrably require a **genuinely external per-position
selector fact** that is *not* a linear chart relation, the confirmed clock, or any
ciphertext/plaintext-internal rule.

### Both open levers, built and closed (exps 125–127)

The two levers that survived 120–124 were then built:

- **125 — Lever 1: a sharper deterministic prior for the 43 prior-governed
  positions (knowledge).** Swapped the saturating hexagram for the non-saturating
  stupid-backoff char-LM (the allowed n-gram/char-LM class, not a neural net), in a
  *fair* test: each restart warm-starts to a hexagram-fluent decrypt, then polishes
  with the backoff prior to give it its best chance to disambiguate. Result: it does
  **not** collapse the 43 — per-position entropy stays **3.38** (vs hexagram's 3.19),
  60/60 distinct decrypts. Sharper finding: the discriminating backoff prior scores
  even the best decrypts at **≈−25σ** vs real English, exposing that 124's
  hexagram-"fluent" decrypts are **not genuinely English** — *no* deterministic
  char-level prior endorses a unique English free-fill. The 43 are
  **information-theoretically under-determined** (homophonic flattening destroyed the
  per-position signal), not merely floored by the hexagram. Path A is exhausted for
  unique recovery.
- **126 — Lever 2: engraving-grid selector sweep + transcription audit (ruled
  out).** The transcription/1-indexing **audit PASSES** — K4 is byte-exact, all 4
  cribs match their 1-indexed spans, b-edges=10, split 30/43 — so the whole 117–125
  analysis rests on a verified foundation. The engraving-grid selector family
  (row/column parity over widths 2–40, **117 masks**) gives **0** that 2-colour the
  b-graph: the chart selector is not a row/column parity of any engraving grid
  (extends 116's negative). The **5th-positional-crib path is BLOCKED** by the
  decipherment-only rule (admissible only on a public Sanborn release; never
  fabricated, never waited on; exp 102 found 0 gaps in the public clue record).
- **127 — engraving selector under the *verified* geometry (ruled out).** Web
  verification (2026-05-30) of the canonical Elonka/Gwyn transcript corrected a
  long-standing repo assumption: the K4 layout `[4,31,31,31]` is a *transcript
  convention, not a measured physical fact*, and it was **mis-framed** — `OBKR` is
  not a standalone line; it is the **last 4 columns (27–30) of the 31-wide row that
  ends K3** (`…DOHW?OBKR`), so K4 shares that row with K3. (exp 104's status
  corrected from "EXTRACTED" to "UNVERIFIED transcript convention".) 052/090/126 all
  used the wrong standalone framing. 127 re-tests with the corrected continuous-panel
  geometry (OBKR offset, widths 29–33): **0/30** masks 2-colour the b-graph. The
  engraving-grid selector is closed under **both** geometries.

**Net (125–127) — the boundary is mapped.** Both buildable levers are closed: a
sharper deterministic prior does not resolve the 43 (125), and no chart-tie / clock
/ autokey / engraving-grid selector — standalone *or* the verified continuous-panel
geometry — resolves the 30 (121–123, 126, 127). **No admissible deterministic lever
currently in hand decrypts K4's free positions.**

**The Ventris move, tested (exp 128).** The Linear-B decipherment cascaded a
*hypothesized* contextual crib (Cretan place-names) through Kober's structural grid
and self-confirmed. We applied the analogue here: ~70 context-derived thematic crib
words (the cribs' direction/Berlin/clock theme + the public K1–K3 narrative)
slotted at every free-window placement, tested for homophonic consistency, cascade
reach, and self-confirmation (does pinning a word *here* make positions *there* read
as English?), all against a matched random-word null. Result: thematic cribs are
**not** privileged over random — consistency 17% vs 16%, cascade max 19 vs 19,
self-confirmation −13.44 vs −13.53 (best hypotheses LATITUDE@52, DAYLIGHT@52, but at
chance level). The cascade does not close and does not self-confirm: K4's homophonic
grid is too permissive and its redundancy too exhausted for the Ventris move to bite
(exactly the negative the Linear-B parallel predicts). What strictly remains is genuinely
external and not in our possession: a **measured** physical line-layout (no certified
per-line copper layout is publicly published — even the canonical transcript's
maintainer notes the digital layout "failed" to match the sculpture; only a
high-res photo/rubbing measurement would settle it), or a Sanborn-released 5th
positional crib. The honest standing result is a rigorous, model-robust
under-determination of the 73 free positions under all admissible
decipherment-legal inputs (cribs + colouring + selector algebra + deterministic
char-level priors), pending exactly one of those two external facts.

*Methods that DON'T fit (documented so they aren't re-proposed):* supervised
neural cipher-breakers (no parallel data; 97 chars too short); AZdecrypt-style
homophonic hillclimbing (K4 is one-to-one, not homophonic); pure-transposition
SOTA solvers (Fact 1 forbids net transposition). Their *max-likelihood framing*
(Knight lineage) is what we adopted in 092/093.

*(All $0/local, pure decipherment. Every verdict adversarially verified where it
mattered. Regenerate the ledger after any new experiment: `python scripts/report.py`.)*

## What probably explains the universal negative

After exps 035-037, the "what explains the negative" question has a
much sharper answer than after the Opus run alone. The cribs themselves
*directly prove* the cipher's structural form, not just empirically
rule out classical families.

**(a) The cipher uses ≥3 hand-crafted alphabet permutations selected
by a W-structure-aligned rule.** Proven by:

- χ = 3 (exp 035) — at least 3 alphabets required, by graph coloring
- No natural keyword in any 88-keyword pool can encrypt 7 of the 24
  cribs — those alphabets must be hand-crafted (exp 033)
- No slot under any valid k=8 natural rule has a compatible natural
  alphabet (exp 037) — ALL alphabets are likely hand-crafted
- `pos_in_w_seg_mod_8` and `dist_to_w_mod` are the only W-related
  rules near-compatible with the cribs (exps 036, 033b) — selection
  rule is W-structure-aligned

This is no longer hypothesis (a) — it's a **structurally-derived
prediction** with falsifiability built in. The Shinka-with-fixed-rule
experiment described above will either find a (selection rule, 8
alphabets, plaintext) triple that round-trips to K4, or rule out the
W-aligned-rule families completely.

**(b) The actual K4 plaintext isn't in either Sonnet's 5,220 or Opus's
18,372 filtered candidates.** Substantially weakened: 23,592
high-quality crib-compliant candidates were tested against the entire
classical cipher family with zero solves. If the cipher were classical
and just needed the right plaintext, an Opus prior at 5× Sonnet's
scale × 27 framings should have surfaced something.

**Note**: hypotheses (a) and (b) are no longer the same question. The
cribs ALONE force ≥3 hand-crafted alphabets — that's true whether or
not the real plaintext is in our prior. (b) is now relevant for the
NEXT step (finding the alphabets via a known-plaintext attack), but
the structural shape of the cipher is fixed by (a).

The remaining open question is now narrow: **what is the selection
rule, and what are the 3+ hand-crafted alphabet permutations?**

See "Structural ruling from the 24 cribs" above for the constrained
search space.

## Sanity oracles (per [data/clues.yaml](data/clues.yaml))

- **Position 74 (K → K) is a letter encrypting to itself.** Any
  reciprocal cipher (Beaufort variants) is dead on arrival without a
  workaround.
- **Sanborn confirmed in Nov 2025 that "Berlin Clock" is the Weltzeituhr
  at Alexanderplatz**, not the Mengenlehreuhr that was assumed for
  15+ years. Mengenlehreuhr-keystream attacks aim at the wrong device.
- **K4 contains every letter A-Z.** This structurally rules out
  Bifid/Playfair/Four-square (25-cell-grid polygraphic with one
  merge) and ADFGVX (length-doubling) before any computation.
- **Scheidt 2011 Kryptos Dinner**: "K4 cryptography is not mathematical,
  it is simple, can be remembered, and executed years later when used
  with the correct key word/s." Argues against SAT/ILP design and
  toward Gromark / autokey / Quagmire families with a hand-executable
  modification.
- **Sanborn 2005 Wired**: "I was modifying systems and developing my
  own which would make it virtually impossible for [Scheidt] to
  decipher all of it." The composable pipeline (`Compose` +
  `FinalCaesar` + `PositionalRemap`) exists for this hypothesis class.

## Sharp recommendations (updated)

- **Use the `verify()` gate.** Every claimed K4 solution must produce
  a byte-exact `cipher(plaintext, params) == K4`. No round-trip → not
  solved. Eight public claims to date have failed this gate
  ([data/rejected_solutions.yaml](data/rejected_solutions.yaml)).
- **Use the hexagram fitness, not chi-squared, for K4 candidate
  scoring.** At length 73 (unconstrained K4 positions), the
  chi-squared filter passes random-letter-distribution gibberish.
  Hexagram fitness ([data/ngrams/english_hexagrams.txt](data/ngrams/english_hexagrams.txt))
  cleanly separates real English (~-13 nats/char) from gibberish (~-24).
  See exp 022 for a worked example: 215 chi-sq survivors → 0 hexagram
  survivors above -18.
- **Filter Sonnet candidates for K4-ciphertext-copy pathology.** In
  5,220 Sonnet candidates, one candidate copied K4's ciphertext into
  its free-span filler, producing 30 consecutive shift-zero positions
  and 1,369 trivial "hits" against any generator with leading zeros.
  See [`experiments/023_sonnet_candidate_shift_vs_generators.py`](experiments/023_sonnet_candidate_shift_vs_generators.py)
  `is_pathological()`.
- **Cross-model N1 is more informative than scaling within one model.**
  gemma4's themes were model-specific bias; Sonnet shifted them
  meaningfully. If running another LM pass, use a different model
  family, not more samples from the same one.
- **JSONL logger before any solver.** Every experiment dumps
  `(seed, cipher_class, params, score, candidate_plaintext)`.
  Reproducibility is non-negotiable. See [src/kryptos/experiment_logger.py](src/kryptos/experiment_logger.py).
- **Structural derivations from the cribs trump enumeration sweeps.**
  Exps 035-037 produced more constraint on K4's cipher in 30 minutes of
  graph-theoretic analysis than the previous 30 enumeration experiments
  combined. Before launching a new search experiment, ask: what does
  the crib structure imply must be true? χ=3 means k≥3 alphabets; the
  k=8 natural-rule floor means non-natural rule for k=3; per-slot
  natural-keyword failure means hand-crafted alphabets. Each is a hard
  constraint that future experiments must respect.

## What is NOT here

- A working solution for K4. There isn't one publicly.
- The plaintext itself. Privately held; will leak when it leaks.
- Tests as a top-level pytest suite. Deliberately deferred for this
  scaffold; the Phase-0 regression script in `experiments/001*.py`
  plays the role of the K1/K2 smoke test for now.
- A K1-K3 calibration N1 (asking the LM to recover K1's plaintext from
  artificial cribs as a sanity check on whether N1 can do this task at
  all). Worth building.
- Tested cipher families: per-position alphabet selection, stream
  ciphers from non-letter physical observables, multi-stage `Compose`
  pipelines of depth ≥ 3, hand-curated Sanborn modifications proposed
  by an LM N2.

## Performance discipline

Pure-Python is fine for the API; inner loops want numpy at minimum and
Numba (`uv sync --extra fast`) for the hot path. The Trifid hill-climb
in exp 027 runs 626M inner iterations across 5,220 candidates in 34
seconds on a 14-worker M3 Max pool — Numba JIT was the enabling
optimization. Pure Python would have been 10-50× slower.

Experiments 023-028 (the Sonnet-candidate-driven Tier A/B sweeps)
process all 5,220 candidates × 10s of thousands of hyperparameter
tuples in under a minute each via vectorized numpy. Profile before
optimizing; but do not pretend pure Python is fast enough either.

## Further reading

- Dunin & Schmeh, *Codebreaking: A Practical Guide* (2020/2023).
- Bauer, *Unsolved!* (Princeton 2017).
- Bauer / Link / Molle, "James Sanborn's Kryptos and the matrix
  encryption conjecture", *Cryptologia* 40:6 (2016) 541-552.
- Bean, "Cryptodiagnosis of 'Kryptos K4'", *HistoCrypt* 2021.
- elonka.com/kryptos (canonical clues; FOIA documents; rubbings).
- scienceblogs.de/klausis-krypto-kolumne (Schmeh's Cipherbrain).

## Caveats

Per Sanborn's Spy Museum talk (12 Nov 2025) and Elonka Dunin: the
*words* of K4's plaintext were recovered by archival sleuthing in
September 2025 (Jarett Kobek and Richard Byrne assembled the plaintext
from taped-together coding charts Sanborn donated to the Smithsonian
Archives of American Art ~2023 during cancer treatment), but the
*cryptographic method* remains unsolved and that is what this
repository targets. The plaintext is privately held by Sanborn,
Scheidt, Kobek, Byrne, and the anonymous bidder who paid $962,500 on
20 November 2025; it could be leaked or published at any time, which
would convert this project from cryptanalysis to known-plaintext
method recovery.

The Smithsonian papers are sealed until 2075. K5 exists (per Sanborn's
2025 talk), is 97 characters, will appear in a public space after K4
is cryptographically solved, and shares words at the same positions
as K4 — a strong forward constraint on any candidate K4 plaintext.
