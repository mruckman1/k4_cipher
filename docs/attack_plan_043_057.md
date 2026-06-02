# K4 attack plan & results — experiments 043–057 (2026-05-28)

Fifteen new attacks derived from an expert ideation panel, each vetted against
the repo's prior rulings. All ran at **$0** (local compute; `ortools` is the
only added dependency, free). The one LLM run (057) used local **ollama/gemma**
(`gemma4:26b-a4b-it-q8_0`), also $0.

Every experiment ends with a standardised `Verdict` (see `experiments/_verdict.py`)
appended to its JSONL. Regenerate the cross-experiment ledger any time with:

```
python scripts/report.py        # -> experiments/results/FINDINGS.md  + findings.json
```

## Shared scaffolding (Wave 0)

| Module | Purpose |
|---|---|
| `experiments/_kpa.py` | candidate loader, vectorised periodic-KPA helpers, generalised per-position consistency, cached hexagram scorer, `best_over_transposition()` |
| `src/kryptos/alphabets_routes.py` | geometric route alphabets from the KRYPTOS tableau (rows/cols/diagonals/columnar/boustrophedon) |
| `experiments/_crib_sat.py` | exact + greedy set-cover of the 23 crib constraints by an alphabet pool |
| `src/kryptos/ciphers/keyed_fractionation.py` | length-preserving 2×13/13×2 keyed-coordinate fractionation cipher |
| `src/kryptos/scoring/lm_fitness.py` | smooth stupid-backoff char LM (and optional distilgpt2) — non-saturating scorer |
| `src/kryptos/solvers/sat_ilp.py` | filled the stub: CP-SAT `min_alphabets_for` / `is_k_colorable` / `fanout` |
| `experiments/_verdict.py`, `scripts/report.py` | the findings ledger / tracking system |

## Experiments and outcomes

| exp | idea | result |
|---|---|---|
| 043 | substitution → keyed columnar transposition | **ruled out** (340,200 configs; no width re-pairs cribs to a short decryptable period) |
| 044 | null-deletion / misspelling period restoration | **ruled out** (64,897 deletion sets) |
| 045 | sub-uniform IoC discriminator + keyed fractionation | **ruled out** — IoC is uninformative at N=97 (23% of *random* strings ≤ 0.0361) |
| 046 | tableau-route alphabets vs χ=3 | **ruled out** — routes need k=9 to cover; best 3 cover 12/23 |
| 047 | compass/lodestone bearing alphabets | **ruled out** — k=11 |
| 048 | Sanborn deliberate-typo alphabets | **ruled out** — k=9 |
| 049 | Weltzeituhr 24-column transposition | **ruled out** |
| 050 | morse dot/dash mask / 2-alphabet selector | **ruled out** — morse is thematic, not structural |
| 051 | sister-sculpture (Cyrillic Projector) running key | **inconclusive** — blocked on a verified full transcript |
| 052 | rail-fence / route transposition | **ruled out** (engraved-line layout still unsourced) |
| 053 | smooth-LM scorer vs hexagram saturation | **🔎 lead** — hexagrams tie 41% of gibberish pairs; smooth LM separates 80% |
| 054 | latent selection-rule fit over candidates | **ruled out** — min 20/97 violations; `cc_mod_8` least-bad |
| 055 | CP-SAT chromatic / fanout structural filter | **★ key result** — every N1 candidate needs ≥7 alphabets (min fanout 7) |
| 056 | parallel tempering + contrastive coherence (smooth LM) | **ruled out** — K=4 per-colour partitions stay at −24/char (gibberish) |
| 057 | K1 calibration of N1 (ollama/gemma) | **inconclusive** — N1 recovers theme/vocabulary, ~8% char-accuracy (a *thematic prior*, not plaintext recovery) |

## The two findings that change the picture

1. **exp 055 — the fanout bound.** For a K-alphabet per-position substitution,
   each plaintext letter can map to at most K distinct ciphertext letters. The
   minimum fanout across all 5,220 N1 candidates is **7**; none is admissible at
   K≤6. So the combination *(ShinkaEvolve's K=4 model) AND (any LLM candidate
   plaintext)* is structurally impossible. Either the prior misses the true
   plaintext, or K4 is not a low-K per-position cipher.

2. **exp 056 confirms it.** A K=4 tempered search with a *better* (smooth, non-
   saturating) scorer **plus** an explicit per-colour-coherence reward still
   leaves all four colour partitions at −24/char gibberish. The cross-colour
   "words" the 71.98 basin shows are an artifact of forcing K=4 on a structure
   that cannot support it — not a decryption.

Together with **exp 053** (the hexagram landscape is provably flat across much
of the gibberish region) these say: the dominant per-position-substitution
hypothesis should be **downweighted**, and the search should pivot to
(a) generating plaintext candidates filtered by the **fanout ≤ K** constraint,
(b) transposition+substitution composites, and (c) using the smooth LM (or
distilgpt2) as the inner-loop objective rather than the saturating hexagram table.

## Reusable, still-open next steps

- Re-run 051 with a *verified* Cyrillic Projector / Antipodes transcript.
- Source K4's true engraved per-line layout; add it as a route in 052.
- Generate N1 candidates constrained to **fanout ≤ 4–8 vs K4** (a hard new filter), then re-fit rules (054) and re-search.
- Calibrate N1 on K2/K3 (057) and add cross-model ensembling (qwen, gemma-31b).
