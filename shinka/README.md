# k4_cipher/shinka — ShinkaEvolve-driven K4 cipher-class exploration

This sub-project replaces the "synthetic-shift-signature classifier" version
of N2 with a ShinkaEvolve run: the LLM proposes mutations to a Python
`decrypt_k4` pipeline composed of `kryptos.ciphers` primitives, and the
fitness function combines crib satisfaction with hexagram log-likelihood at
the 73 unconstrained K4 positions.

It runs **separately from the main `kryptos` venv**: `shinka-adapter`
requires Python 3.11, and `k4_cipher` uses 3.12. This sub-project has its
own `.venv/` and `pyproject.toml`. Both reach the `kryptos` package via an
editable install of the parent directory.

## Prerequisites

- [uv](https://docs.astral.sh/uv/) installed.
- An `OPENROUTER_API_KEY` — both Gemini 3.5 Flash and Claude Opus 4.7
  are routed through OpenRouter (the `openrouter/anthropic/claude-opus-4.7`
  slug). No separate Anthropic key needed.
- Patience:
  - `make gemini` (Flash-only): 250 gens, ~2-4 hours, ~$15-25.
  - `make ensemble` (Flash + Opus 4.7, RECOMMENDED): 250 gens, ~2-4 hours,
    ~$30-50. Different model families produce genuinely different mutation
    distributions; Opus 4.7 has measurable coding edge (87.6% SWE-Bench
    Verified) which is precisely the task ShinkaEvolve is doing here
    ("modify cipher code to improve fitness"). UCB bandit selects between
    arms based on which produces higher-scoring proposals; Flash provides
    cheap volume, Opus provides quality on the harder mutations.

## One-time install

```bash
cd /Users/mruckman1/Desktop/dev/k4_cipher/shinka
make install            # creates .venv (Python 3.11), installs shinka-adapter + kryptos editable
cp .env.example .env    # then edit .env, fill OPENROUTER_API_KEY
```

## Validate the wiring before spending API budget

```bash
make smoke              # ~5s, $0. Confirms fitness function works on known inputs.
make preflight          # ~10s, $0. Confirms OPENROUTER_API_KEY is valid + Gemini 3.5 Flash reachable.
```

If `make smoke` fails because of missing n-gram tables, the fitness function
will fall back to building a (noisy) quadgram table from K1+K2+K3 plaintexts.
For serious runs, drop a real `english_quadgrams.txt` or `english_hexagrams.txt`
into `../data/ngrams/`.

## Real run

Two variants — pick one. The ensemble is the recommended default.

```bash
make ensemble           # variant=flash_plus_opus, 250 gens, $50 ceiling
                        # Flash + Opus 4.7 with cost-aware UCB bandit.
                        # Both via OpenRouter; OPENROUTER_API_KEY only.

make gemini             # variant=openrouter_only, 250 gens, $25 ceiling
                        # Flash only. Cheaper; less mutation diversity.
                        # Requires OPENROUTER_API_KEY only.
```

Equivalently:
```bash
. .venv/bin/activate
uv run shinka variant=flash_plus_opus     # or variant=openrouter_only
```

Override knobs from the CLI:
```bash
uv run shinka variant=flash_plus_opus \
  ++num_generations=500 \
  ++max_api_costs=100.0 \
  ++llm_kwargs.temperatures='[0.5, 0.9]'
```

## Why the ensemble (Flash + Opus 4.7)

The mutation task ShinkaEvolve performs ("modify Python cipher code to
improve a fitness score") is a SWE-Bench-Verified-domain task. Claude
Opus 4.7 scores 87.6% on SWE-Bench Verified; Gemini 3.5 Flash scores
substantially lower. Single-model runs use one model's mutation
distribution; ensemble runs use both, with the UCB bandit pulling each
arm in proportion to the per-cost-dollar fitness improvement it
produces.

Operationally:
- Flash provides volume. Cheap, fast, lands generations frequently.
- Opus 4.7 provides quality. ~6x cost per token, but a per-generation
  proposal from Opus is more likely to be a productive mutation than a
  Flash proposal at the same temperature.
- The bandit (`llm_dynamic_selection: ucb`,
  `cost_aware_coef=0.5`) computes a UCB1 score per arm: if Opus's
  empirical mean fitness gain is much higher than Flash's, the bandit
  pulls Opus more even though it's more expensive. If they're
  comparable, it favors Flash. Tweak `cost_aware_coef` upward to favor
  cost-economy, downward to favor pure quality.

This is the recommended config for a serious attack run.

## What you'll see during a run

- Every ~30-90 seconds a new `gen_N/` directory lands in
  `results/k4_gemini35flash/<timestamp>/` containing `main.py` (the mutated
  decrypt_k4) and the score metadata. Flash is faster per call than Pro, so
  generations land more frequently.
- `logs/run.log` updates with progress: `completed_gens=N/250,
  running_eval_jobs=K, api_costs=$X/$25`.
- Optional dashboard: `uv run shinka_visualize --port 8888` then open
  http://localhost:8888.

## What the fitness function measures

Composite score (higher is better):

| Component | Range | Meaning |
|---|---|---|
| `100 * crib_frac` | 0-100 | One point per matching crib position (24 total) |
| `10 * (hex_per_char + 9)` | ~5-30 | Hexagram log-likelihood at the 73 unconstrained positions |

- Score `< 100`: cribs not all satisfied. The LM should pursue cribs first.
- Score `100-110`: all cribs satisfied but unconstrained text is gibberish.
- Score `> 110`: all cribs satisfied with English-like unconstrained text.
  **This is the signal worth chasing**.

Score `100.0` exactly = all cribs hit + hexagrams at -9 (gibberish floor).
Score `~115` = all cribs + English-ish (-7.5 hexagrams).
Score `~120+` = the solution, or something very close.

## Cost discipline

- Default ceiling: 250 generations, $25 max API spend (variant config). The
  run aborts when either limit is hit.
- Start with one seed (`++seeds=[17]`) and `++num_runs=1` for the first run.
  Bump after you see scores moving above the seed baseline.
- Watch `logs/run.log` for the first ~50 generations (Flash lands gens
  quickly). If best score isn't climbing, two diagnoses to try in order:
  (a) patch parser failing — add `++patch_types=[full] ++patch_type_probs=[1.0]`;
  (b) model not capable enough at structured cipher reasoning — switch back
  to Pro by changing the variant config's `llm_models` slug to
  `openrouter/google/gemini-3.1-pro-preview` (and cap to ~200 gens / $30).

## What this is NOT

- **Not a solver for K4 by itself.** It's a structured search over compositions
  of `kryptos.ciphers` primitives. If the actual cipher uses primitives or
  modifications outside that library, ShinkaEvolve cannot find them by
  construction — garbage primitives in, garbage evolved.
- **Not an LM-plaintext-inference run (N1).** N1 lives separately:
  batch-query Claude/GPT/Gemini with the assembled K4 evidence context,
  cluster outputs, extract thematic priors. Build N1 as a one-shot
  experiment in `experiments/`, not here.
- **Not a quick check.** A meaningful run costs real money and takes hours.
  Don't launch `make gemini` casually.

## Resuming a killed run

```bash
DST=results/k4_gemini35flash/2026-05-21_10-30-00   # the existing run's dir

uv run shinka variant=openrouter_only \
  "++results_dir=$DST" \
  "++database.db_path=$DST/programs.sqlite" \
  "++evolution.results_dir=$DST"
```

Shinka picks up the bandit state, island populations, and prompt-evolution
archive from `programs.sqlite`.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| All proposals score -inf with `decrypt_k4 returned len=...` | Mutation broke the 97-char contract | Look at a failing `gen_N/main.py`; the LM is producing a malformed return |
| All proposals score exactly `0.0` (no crib hits, gibberish hexagrams) | Patch parser failing on reasoning-model prose | Add `++patch_types=[full] ++patch_type_probs=[1.0]` |
| `HTTP 400 "Reasoning is mandatory"` | Adapter patch didn't apply | `grep 'shinka_adapter: patches applied' logs/run.log` — must hit |
| `forbidden from-import: kryptos.ciphers` | AST gate's allowlist missing `kryptos` | Confirm `configs/evolution/default.yaml` → `ast_check.allowed_imports` includes `kryptos` |
| `ModuleNotFoundError: No module named 'kryptos'` | Editable install didn't take | `uv pip install -e ..` from inside `.venv` |

More gotchas: see `/Users/mruckman1/Desktop/dev/shinka_hybrid/scaffold/docs/learnings.md`.

## Files

- `pyproject.toml` — Python 3.11 sub-project, depends on shinka-adapter + kryptos.
- `Makefile` — convenience targets (venv, install, preflight, smoke, gemini).
- `.env.example` — copy to `.env`, fill `OPENROUTER_API_KEY`.
- `configs/` — Hydra config tree. `variant=openrouter_only` is the Gemini 3.1 Pro entry.
- `problem/initial.py` — fitness function (outside EVOLVE block) + seed `decrypt_k4` (inside).
- `problem/evaluator.py` — InProcessEvaluator factory.
- `problem/catalog.py` — K4 ciphertext as a single instance.
- `tests/test_smoke.py` — validates fitness wiring before spending API budget.
