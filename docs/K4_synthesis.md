# Kryptos K4: A Structural Cryptanalysis and a Model-Robust Under-Determination Result

*Synthesis of experiments 001–128 (this repository). Every quantitative claim below
is backed by a logged `Verdict` in `experiments/results/` and aggregated in
`experiments/results/FINDINGS.md` (regenerate with `python scripts/report.py`).
All work was $0 / local / deterministic; constraint throughout: **decipherment
only** — no recovered plaintext, no extra cribs, no K5, no LLM in the analytic
pipeline.*

---

## 0. Abstract

K4 is the 97-character unsolved final section of Jim Sanborn's *Kryptos* (1990, CIA
Langley). Working only from the public ciphertext, the four released cribs
(EAST / NORTHEAST / BERLIN / CLOCK), and the solved sister sections K1–K3, we ran 128
numbered deterministic experiments (125 distinct; indices 005/017/018/019 unused;
86 carry standardized logged verdicts; the verdict ledger began at exp 043). The result is not a decryption but a **sharp
structural characterization**:

1. **Two facts hold simultaneously and were thought to conflict ("the squeeze"):**
   K4 is positional / one-to-one / length-preserving (Fact 1), yet its non-crib
   positions are frequency-**flattened** to 4.33 bits/char (Fact 2).
2. **The bijective model is over-constrained.** Under the standard assumption that
   K4's alphabets are bijections, the cribs force ≥3 alphabets (χ=3) and flattening
   forces ≥4 (k\*=4) — and no short selector can be simultaneously crib-feasible,
   flattening, and English (the squeeze, solver-proven).
3. **A homophonic reframe resolves the squeeze.** A **2-chart homophonic** chart
   (non-injective, many cipher symbols → one plaintext letter) satisfies *both* hard
   facts with only two charts (χ_b = 2; homophonic flatten floor = 2). The squeeze is
   a bijective-only bound; it does not bind a homophonic chart. This is the most
   economical structure consistent with everything proven, and matches Sanborn's
   description of a "chart-based coding system."
4. **But the decryption is model-robustly under-determined.** The 73 free positions
   split exactly into **30 "selector-locked"** (a crib-pinned cipher letter → only
   the per-position chart-selector bit is free → exactly a 0.50 coin-flip) and
   **43 "prior-governed"** (no crib anchor → both chart entries free → constrained
   only by a language prior). No admissible deterministic lever decrypts either half:
   no chart-tie, clock, autokey, or engraving-grid selector breaks the 30; no
   deterministic char-level prior collapses the 43.

The standing result is a **rigorous, model-robust under-determination of K4's free
positions** under all public decipherment-legal inputs (cribs + selector colouring
algebra + deterministic char-level priors), pending exactly one external fact: a
*measured* per-position selector (e.g. the physical engraving layout) or a
Sanborn-released 5th positional crib.

---

## 1. Setup

- **Ciphertext (97 chars, 1-indexed):**
  `OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR`
- **Cribs (the only known K4 plaintext):** EAST (22–25), NORTHEAST (26–34),
  BERLIN (64–69), CLOCK (70–74); position 74 is a K→K fixed point. 24 crib letters,
  73 free positions.
- **Calibration (solved, Sanborn's hand):** K1 = Quagmire-III (keyword KRYPTOS,
  primer PALIMPSEST); K2 = Q3 (ABSCISSA); K3 = double-columnar transposition width 7.
- **Method discipline:** deterministic cryptanalysis + n-gram / backoff char-LM
  scorers only (no neural/LLM judge or generator); every experiment emits a
  standardized verdict; load-bearing findings were re-derived by independent
  adversarial verification passes.

---

## 2. What was attempted (the attack catalog)

**86 logged verdicts** (experiments are numbered to 128; the verdict ledger began at
exp 043, with earlier exploratory runs uncatalogued), of which **63 ruled out,
15 knowledge/structural, 2 promising (the homophonic reframe), 3 retired (early LLM
methods, since dropped), 1 tooling, 2 inconclusive, 0 solved.** By family:

| Family | Representative exps | Outcome |
|---|---|---|
| Classical polyalphabetic / Quagmire / Vigenère / Beaufort | 001, 010, 086, 087 | ruled out |
| Transposition (columnar / route / engraving) | 049, 052, 112 | ruled out (and Fact 1 forbids net transposition) |
| Periodic substitution, all periods ≤48 | 043, 112 | ruled out |
| Keystream / clock (Weltzeituhr) — keystream, transposition, selector | 003, 049, 094, 122 | ruled out |
| Alphabet sources: keyword pools, construction grammars, physical/mnemonic (keyboard/Morse/freq/Scrabble) | 033, 035, 088, 110, 113 | ruled out (alphabets are bespoke) |
| Selectors: modular, grid/2-D, register, interruptor, autokey, engraving-grid | 085, 090, 097, 099, 100, 123, 126, 127 | ruled out |
| Joint inference: CP-SAT / MaxSAT / MCMC | 055, 096, 106, 107 | knowledge (squeeze proof) / solver-limited |
| Plaintext priors: n-gram beam, smooth backoff char-LM, word-level | 012, 053, 108, 125 | knowledge (priors don't pin the free positions) |
| Identifiability / unicity | 092, 093, 109 | knowledge (the keystone) |
| Multi-lens signal detection (power-calibrated) | 111 | ruled out (no per-lens signal) |
| **Homophonic reframe** | **114–119, 124** | **promising / knowledge** |

The breadth matters: the negative is not "we didn't try X" — it is that every
classical family, every alphabet source, every short selector, and every
deterministic prior has been tested and excluded or shown non-determining.

---

## 3. What was learned (the established facts)

**3.1 The two hard facts ("the squeeze").**
- **Fact 1 — positional / one-to-one / length-preserving.** The cribs map to fixed
  positions; there is no net transposition. (Established across the early KPA work;
  Bean's positional analysis.)
- **Fact 2 — deliberate flattening.** The 73 free positions carry **4.33 bits/char**
  of entropy (exp 071: 4.332, vs the 99th-percentile monoalphabetic value 3.88) — the
  frequency profile is flattened well past any single alphabet.
- **The squeeze (exp 085, solver-proven 106).** Under bijective alphabets, the cribs
  cap the number of *crib-determined* alphabets at the chromatic number χ=3 (m≤24
  determined entries), while flattening to 4.33 bits needs a **flatten floor k\*=4**
  rotation alphabets. The crib-feasible-**and**-flattening-**and**-English region is
  **empty** (085: max proper-and-determined m = 0). CP-SAT confirms it directly: of
  12 simple selectors, **11/12 are crib-infeasible**; the only feasible one (i%8) is
  degenerate (106).

**3.2 Identifiability / unicity (the keystone, exps 092–093).**
- Measured redundancy r = 1.085, unicity distance **D = 3.62 bits/char** (092).
- For hand-crafted alphabets, the under-determination gap stays negative (uniquely
  solvable) only up to **k = 4**, crossing to positive (under-determined) at **k = 5**
  — i.e. K4 sits essentially *at* its unicity distance (092).
- Empirically (093), the number of distinct English-scoring decryptions by alphabet
  count is **{k=3: 1, k=4: 10, k=5: 21, k=6: 25}** — the degeneracy turns on at
  **k=4**. Best free-position hexagram −14.11 (English bar −16.21): fluent but not
  unique.
- **Interpretation:** K4 lives exactly on the boundary between "uniquely
  recoverable" and "degenerate." This is why every attack produces *plausible* but
  *non-unique* output.

**3.3 The HOMOPHONIC reframe (exps 114–119, 124) — the model was over-constrained.**
The squeeze and the ≥3-alphabet bound both assume **bijective** alphabets. A
**homophonic** chart (one plaintext letter → several cipher homophones; decryption
many-to-one) is the classic frequency-flattening device and is *not* bijective.
- **χ_b = 2 (114).** Of the two crib-conflict types, only "same-cipher → different
  plaintext" (type b) binds a homophonic decryption chart. The type-b chromatic
  number is **2** — the cribs need only **two** charts, not three.
- **Homophonic flatten floor = 2 (115).** A 2-chart homophonic cipher flattens
  English to 4.63 bits (curve {1: 4.01, 2: 4.63, 3: 4.68, …}), past K4's 4.33 — with
  far fewer charts than the bijective k\*=4. **A 2-chart homophonic model satisfies
  BOTH hard facts.** The squeeze does not bind it.
- **The crib-feasible selector space is ~1,458× smaller (117).** The b-conflict
  graph (24 crib nodes, 10 edges) is 9 edge-bearing components (eight 2-cliques + one
  3-node path) + 5 isolated nodes → **512 structural / 16,384 total** proper
  2-colourings, vs **23,887,872** proper 3-colourings of the bijective graph. Small
  enough to enumerate exhaustively.

**3.4 The decryption decomposition and model-robust under-determination
(exps 118–127).** Decryption is `P_i = chart[S_i][C_i]`; the cribs pin chart
*entries* globally, so whether crib/selector algebra can fix a free position turns
on whether its ciphertext letter is crib-pinned. This splits the 73 free positions
**exactly**:
- **30 "selector-locked"** (ciphertext letter is crib-pinned): the chart entry is
  known, only the selector bit `S_i` is free → consensus is **exactly 0.50** (119:
  max consensus over any free position = 0.500; 30 positions at exactly 0.5; **0**
  above ≥70%). The guaranteed-determined floor across all 16,384 colourings is **0**
  (118). 9 of the 14 distinct crib cipher letters are *ambiguous* (map to two
  plaintexts), which is exactly what forces the splits and the coin-flip.
- **43 "prior-governed"** (ciphertext letter never in cribs): both chart entries
  free → no crib anchor; constrained only by a plaintext prior. The joint decode
  (124) yields **80/80 distinct English-level decrypts** (a different one every
  restart); a *sharper* non-saturating backoff char-LM (125, fair warm-started test)
  does **not** collapse them (entropy 3.38 ≥ hexagram's 3.19; 60/60 distinct), and
  scores even its best decrypts ≈ **−25σ** below real English — i.e. no deterministic
  char-level prior endorses a unique English fill.

**3.5 Every selector mechanism that could move the 30 is closed.**
- **Chart-tie (M2, exp 121):** of 26 transforms × 16,384 colourings, **0** Caesar/
  Atbash ties `chart2 = T(chart1)` are even crib-consistent (a full linear tie
  over-constrains); no rigid keyed-alphabet pair satisfies all 24 cribs.
- **Confirmed Weltzeituhr clock (M1, exp 122):** **0/48** UTC-sign / UTC-parity masks
  2-colour the b-graph.
- **Message-internal / autokey (exp 123):** **0/8** ciphertext-coupled selectors
  2-colour; the plaintext-autokey `S_i = f(P_{i-1})` cannot be made crib-consistent
  (the selector at a crib position is a forced consequence of the prior decoded
  letter).
- **Engraving-grid selector (exps 126, 127):** **0/117** standalone-geometry masks
  and **0/30** corrected continuous-panel masks 2-colour. (See §6.2 for the layout
  correction this entailed.)

**3.6 Diagnostic gate (exp 120).** A random selector mask 2-colours the cribs with
probability **2⁻¹⁰** → a Bonferroni mask budget **N_max = 52**; the joint decode has
only **≤43 free cells** (chart × cipher-letter), not 73 independent letters, with the
43 prior-governed positions in **12 tied groups, 0 singletons**. This prices every
selector-mask search and bounds the decode dimension.

---

## 4. What is genuinely novel

To our knowledge the following are new contributions (relative to the public Kryptos
literature and standard cryptanalysis of this artifact):

1. **The homophonic chromatic reframe (χ_b = 2).** Prior analyses treat the
   ≥3-alphabet result as a hard floor. Separating the two crib-conflict types and
   recognizing that only type-b binds a *homophonic* (non-injective) chart reduces
   the required chart count to 2 and dissolves the long-standing squeeze. This
   reframes "what K4 is" from a ≥3-alphabet bijective polyalphabetic to a 2-chart
   homophonic chart.

2. **The selector-coupling decomposition (30 / 43).** A precise, exact account of
   *where* the under-determination lives: the model `P_i = chart[S_i][C_i]` localizes
   all per-position freedom to the selector bit, and the cribs partition the free
   positions into a coin-flip-locked set (30) movable only by a selector-coupled fact
   and a prior-governed set (43) movable only by a sharper prior. This turns "K4 is
   hard" into two crisply different, separately-attackable sub-problems with a proof
   of which levers can touch which.

3. **A constructive, model-robust under-determination result.** We show by exact
   enumeration (not sampling) that under the homophonic model class, cribs + selector
   colouring algebra determine **no** free position above a coin-flip (max consensus
   0.500), and that this is *model-robust* — it holds for the bijective ≥3-alphabet
   model and the 2-chart homophonic model alike. Combined with the prior results
   (§3.4–3.5), no admissible deterministic lever decrypts the free positions.

4. **The squeeze, formalized and solver-proven.** The flatten-floor-vs-crib-
   determinacy tension is stated as a closed bound (085) and independently confirmed
   by a CP-SAT falsification (106) — a reusable, machine-checkable statement rather
   than an empirical impression.

5. **The diagnostic gate.** The 2⁻¹⁰ colouring-pass false-positive rate / N_max = 52
   mask budget and the ≤43-cell decode dimension give a principled stopping/gating
   rule for selector-mask searches — preventing the "a mask 2-coloured!" coincidence
   that ~0.1%-per-mask rates would otherwise manufacture.

6. **Methodological: adversarial multi-agent verification and a corrected community
   assumption.** Every load-bearing finding was independently re-derived by a
   separate verification pass; this caught and corrected a propagated error — the
   widely-repeated "K4 is engraved as [4, 31, 31, 31]" is a *transcript convention,
   mis-framed*: `OBKR` is the last 4 columns of the 31-wide row that **ends K3**, not
   a standalone line, and no certified per-line *physical* layout is publicly
   published (see §6.2).

---

## 5. What we think K4 is

Our best-supported model, consistent with **every** proven fact and with Sanborn's
own framing:

> **A 2-chart homophonic bespoke hand-chart with an idiosyncratic, externally-keyed
> per-position selector.**

- **Homophonic, 2 charts:** the only structure that satisfies both hard facts
  economically (χ_b = 2, flatten floor 2). Matches the auction-catalog phrase
  "chart-based coding system" (a homophonic nomenclator chart is literally that) and
  Sanborn's "not a mathematician" / "not necessarily a math solution" statements.
- **Bespoke charts:** no natural keyword, physical/mnemonic ordering, construction
  grammar, or keyed-alphabet pair reproduces the crib entries (033/088/110/113/121) —
  the chart entries are hand-chosen.
- **Idiosyncratic, externally-keyed selector:** the per-position chart choice is not
  any simple modular rule, parity, register feature, clock reading, message-internal
  autokey, or engraving-grid parity (085/090/097/100/116/121/122/123/126/127). What
  remains is an *external* per-position key the analyst does not possess — most
  plausibly something physical/visual on the sculpture, consistent with Sanborn's
  emphasis on the physical object.

This is a **hypothesis about structure**, strongly constrained but not a proof of the
mechanism; it is the residue after eliminating everything else.

---

## 6. Paper-worthy framing

### 6.1 The publishable result

The contribution is a **rigorous negative / structural result**, in the lineage of
unicity-distance and identifiability analyses (Shannon; the Knight et al.
max-likelihood decipherment tradition):

> *Under the homophonic chart model that uniquely satisfies both of K4's proven
> structural constraints, the 73 free positions are information-theoretically
> under-determined by all public decipherment-legal inputs (the four cribs, the
> selector colouring algebra, and deterministic character-level language priors).
> The under-determination is model-robust (holds for the bijective and homophonic
> model classes alike) and decomposes exactly into 30 selector-locked positions
> (resolvable only by an external per-position selector fact) and 43 prior-governed
> positions (resolvable only by a prior sharper than any tested). Decryption from
> public information alone is therefore impossible without exactly one additional
> external fact: a measured per-position selector or a fifth positional crib.*

**Why it is worth publishing:**
- It **redirects the field.** Decades of public effort retry classical ciphers,
  clock keystreams, and selector rules — all of which this work shows are exhausted.
  The paper tells researchers precisely which approaches are closed and why.
- It **quantifies exactly what is missing**: the selector bits for the 30, and a
  super-char-level prior for the 43 — and proves the cribs cannot supply either.
- It introduces **reusable machinery**: the homophonic-chromatic reframe, the
  selector-coupling decomposition, the CP-SAT squeeze, the diagnostic gate, and an
  adversarial-verification workflow — applicable to other homophonic / chart ciphers.
- It **corrects the record** on the engraving layout (a community-propagated
  mis-framing) and on the clock identification.

### 6.2 Honest limits (state these prominently)

- **Model-class-conditional.** Results are proven within the homophonic chart model
  (which is itself the best-supported model, but not the only conceivable one). A
  fundamentally different structure (e.g. a non-positional layer) is not excluded,
  though Fact 1 strongly constrains it.
- **The "external fact" escape is real.** A 5th positional crib or a measured
  physical selector would change the picture; we do not claim K4 is *unsolvable*,
  only that it is undecryptable **from current public information** under this model.
- **Engraving layout is unverified.** The `[4, 31, 31, 31]` layout used by several
  experiments is a *transcript convention*, not a measured physical fact; `OBKR`
  shares K3's final row, physical rows vary ~29–33, and no certified per-line copper
  layout is published. Engraving-selector negatives (126/127) are therefore against
  the best-available convention, not a measured layout.
- **Heuristic search components.** Degeneracy counts (093/124/125) and autokey
  feasibility (123) rest on simulated annealing; exact enumerations (117–122, 126,
  127) do not. We label which is which.

### 6.3 Suggested structure for the paper

1. Background: Kryptos, K1–K3, the K4 cribs.
2. The two hard facts and the squeeze (085, solver-proven 106).
3. Identifiability: K4 at its unicity distance (092/093).
4. The homophonic reframe (114–119): χ_b = 2, flatten floor 2, the 1,458× narrowing.
5. The selector-coupling decomposition and model-robust under-determination
   (118–127).
6. Negative results catalog (the 63 ruled-out families) as an appendix.
7. Discussion: what K4 is; what external fact would suffice; methodology.

---

## 7. Open directions (honest)

Within deterministic, decipherment-legal cryptanalysis, the search is **exhausted**.
Two genuinely-external directions remain, neither in our possession:

1. **A measured physical line-layout.** Count letters-per-engraved-row off a
   high-resolution photograph or rubbing of the lower-left copper panel (e.g.
   jimsanborn.net, press photos, an Elonka rubbing scan), then re-test the engraving
   selector against the *measured* (not transcript) layout. This is the one untested
   variant of the engraving route.
2. **A Sanborn-released 5th positional crib.** Decipherment-legal only if published;
   never fabricated, never waited on. A single (position, plaintext) pair would add
   real ground truth and could break a selector-locked sub-region.

Everything else — more priors, chart-ties, modular/grid/clock/autokey selectors,
MDL-over-charts, classical families — is closed.

---

## 8. Experiment index (substantive findings)

| exp | bucket | finding |
|---|---|---|
| 035 | (foundational) | χ = 3 bijective crib-conflict chromatic number |
| 071 | knowledge | model-agnostic measurements; free entropy 4.332 (p99 3.88) |
| 085 | (foundational) | the squeeze formalized: flatten floor k\*=4 vs determinacy ceiling; region empty |
| 092 | knowledge | unicity D = 3.62 b/char; hand-crafted crossover k=5 |
| 093 | knowledge | degeneracy census {3:1, 4:10, 5:21, 6:25}; empirical crossover k=4 |
| 106 | knowledge | CP-SAT squeeze proof (11/12 selectors crib-infeasible) |
| 107 | knowledge | MCMC joint posterior (diffuse) |
| 114 | promising | χ_b = 2 (homophonic chromatic number) |
| 115 | promising | homophonic flatten floor = 2 (curve to 4.63 bits) |
| 117 | knowledge | 512/16,384 proper 2-colourings vs 23,887,872 bijective (~1,458×) |
| 118 | knowledge | forced/free entry accounting; guaranteed-determined floor = 0 |
| 119 | knowledge | homophonic consensus: max 0.500 (coin-flip); nothing above ≥70% |
| 120 | knowledge | diagnostic gate: FP 2⁻¹⁰, N_max 52, ≤43 cells, 30/43 split |
| 121 | ruled out | chart-tie (M2): 0 crib-consistent linear ties; no rigid keyed pair |
| 122 | ruled out | Weltzeituhr selector (M1): 0/48 masks 2-colour |
| 123 | ruled out | autokey selector: 0/8 ciphertext-coupled; plaintext-autokey crib-inconsistent |
| 124 | knowledge | joint decode: 80/80 distinct English; entropy prior 3.19 / locked 1.08 |
| 125 | knowledge | sharper backoff prior does not collapse the 43 (entropy 3.38; −25σ) |
| 126 | ruled out | engraving-grid (standalone) 0/117; transcription audit PASSES; 5th crib blocked |
| 127 | ruled out | engraving-grid (verified continuous-panel geometry) 0/30 |
| 128 | knowledge | Ventris hypothesized-crib cascade: thematic cribs not privileged vs random null |

Full record: `experiments/results/FINDINGS.md` (86 logged verdicts: 0 solved,
2 promising, 15 knowledge, 1 tooling, 2 inconclusive, 3 retired, 63 ruled out).

---

*This is an internal synthesis / paper-draft, not a claim of decryption. It reports
outcomes faithfully: K4 is not solved here; it is rigorously characterized.*
