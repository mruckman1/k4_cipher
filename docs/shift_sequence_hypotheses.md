# K4 shift-sequence as data: priority-ordered generator hypotheses

## What this document is

The four published cribs give us **24 known plaintext-to-ciphertext shifts**:

  - **EASTNORTHEAST** (positions 22-34, standard A-Z):
    `[25, 15, 1, 24, 23, 24, 2, 2, 20, 24, 16, 0, 1]`
  - **EASTNORTHEAST** (KRYPTOS-keyed):
    `[25, 16, 5, 8, 25, 11, 24, 3, 21, 24, 7, 0, 24]`
  - **BERLINCLOCK** (positions 64-74, standard A-Z):
    `[14, 6, 2, 16, 15, 20, 16, 12, 9, 13, 0]`
  - **BERLINCLOCK** (KRYPTOS-keyed):
    `[15, 9, 24, 21, 11, 15, 17, 18, 19, 6, 0]`

That is **data about the keystream**, not a constraint to filter against.
The cryptanalytic question reframes from "decrypt with X and check
cribs" to "find a generator function whose output reproduces these
24 specific values at positions {22-34, 64-74}."

**Win condition.** Any generator producing ≥ 5 consecutive correct
shifts in either window is a HIT. Probability under uniform random per
generator ≈ `24 × (1/26)^5 ≈ 2×10⁻⁶`; across the experiment's ~20k
generator library, expected false-positive 5-runs ≈ 0.04.

## Tested in this repo (experiments 006, 007, 008)

**Experiment 006** -- 20,524 generators against the unmodified K4 crib
shift sequence. **Zero 5+ consecutive matches in either window.**

**Experiment 007** -- 2,741 single-character ciphertext edits (insert,
delete, swap) of K4 × 20,524 generators × 2 alphabets (112M
comparisons). Win threshold: 8+ consecutive matches.
**Zero 8+ hits. Five 5-runs**, all LCG-based and at the noise floor
(LCG accounts for 80% of the library, hits proportional to family
size). Tests the "Sanborn made a single editing error" hypothesis;
result: no detectable signature.

**Experiment 008** -- 1,226 single-crib perturbations (position shift
+/-1, single-letter substitution) × 20,524 generators × 2 alphabets
(25M comparisons). Win threshold: 8+ consecutive matches.
**Zero 8+ hits. One 5-run** at NORTHEAST with R->U substitution +
Fibonacci(16, 21) seed pair + KRYPTOS-keyed alphabet -- at the noise
floor. Tests the "Sanborn's released cribs are slightly wrong"
hypothesis; result: no detectable signature.

All three experiments together = ~137M comparisons; expected count of
5-run hits under random would be in the few hundreds, observed is 6.
The deficit relative to random is itself a signal: K4's crib shift
sequences appear to be *less* matchable by these generator families
than truly random sequences would be -- possibly because the cribs
constrain the shifts into a structured but not-generator-shaped form.

In the original (unedited) sweep:
Eight generators produced 3 consecutive matches *starting exactly at
the crib boundary* (positions 22 or 64), modestly above random
expectation but below any discrimination threshold.

| Priority | Family | Generators tried | Reasoning |
|----------|--------|------------------|-----------|
| **1** | Text-as-keystream (K1/K2/K3 plaintext, K4 ciphertext, KRYPTOS-keyword variants, Sanborn-name strings) at varied offsets, both A-Z and KRYPTOS-keyed alphabets | ~1,800 | Sanborn/Scheidt prior: "simple, memorable, executable from a keyword years later." Most Scheidt-compatible class. |
| **2** | Sanborn-specific numeric sequences (K2 GPS coordinates, dates of historical events, K3 grid dimensions) at strides 1-2 | ~80 | Sanborn embeds specific numbers in K2 (the GPS); a numeric sequence as keystream is the most Sanborn-natural numeric-only construction. |
| **3** | Famous-constant digit sequences (π, e, φ, √2, √3, √5, ln 2, ln 10, Catalan, Apéry, γ) in base 10 and base 26, offsets 0-29, strides 1-3 | ~1,980 | A pencil-and-paper artist could write these from a table. |
| **4** | Lagged-Fibonacci with primer seeds drawn from interesting sets (KRYPTOS letters, DYAHR letters, natural Fibonacci) | 16 | Gromark family generalisation. |
| **5** | Fibonacci mod 26 with all 676 (seed_a, seed_b) pairs | 676 | Simplest two-parameter recurrence. |
| **6** | Mengenlehreuhr lamp-count keystreams at six Sanborn-significant dates × five hours × three intervals × two flavors | 180 | The clock the community attacked from 2014-2025; could still be the *generator* even though Sanborn confirmed the *referent* is Weltzeituhr. |
| **7** | LCG `x_{n+1} = (a·x + c) mod 26` over all `(a, c, seed)` triples | 16,250 | Classical, exhaustive at this mod; largest family. Lowest prior because LCGs are mathematical, against Scheidt's "not mathematical" hint. |

## What this rules out

After 137M comparisons across 006/007/008 with zero 8+ consecutive
matches and only 6 5-runs total (well under the random expectation),
the K4 crib shift sequences are **not** the output of any of the
following, in any of the configurations tested:

- A position-indexed generator from the 20k-generator library against
  the unmodified ciphertext (experiment 006).
- The same library against any single-character ciphertext edit
  (insert, delete, swap; experiment 007). This rules out the "Sanborn
  made one editing error" hypothesis at this generator-library
  breadth.
- The same library against any single-position-shift or
  single-letter-substitution perturbation of one crib at a time
  (experiment 008). This rules out the "one crib is slightly wrong"
  hypothesis at this breadth.

Three independent attacks; three null results. The K4 crib shift
sequence is not a clean position-indexed function of position, even
allowing for off-by-one errors or wrong-crib corrections.

The cribs' shift sequences are also **not** the output of any:

- Vigenère-style keystream from K1/K2/K3 plaintext (any offset)
- Keystream from K4 ciphertext as self-key (any offset)
- Vigenère-style keystream from any of {KRYPTOS, DYAHR, PALIMPSEST,
  ABSCISSA, BERLINCLOCK, BERLINUHR, WELTZEITUHR, JAMESSANBORN,
  EDWARDSCHEIDT, SANBORN, LANGLEY, IQLUSION, UNDERGRUUND} repeated
- Numeric-string keystream from K2 GPS coordinates, the obvious dates,
  or K3 grid dimensions
- Digit-sequence keystream from any of 11 famous constants in base 10
  or 26, at offsets 0-29 and strides 1-3
- Linear congruential mod 26
- Fibonacci mod 26 with any seed pair
- Lagged-Fibonacci with the tested primer sets
- Mengenlehreuhr lamp count at any of 6 significant dates × 5 hours ×
  3 intervals, in two flavors

## What to test next, in priority order

### High prior (Scheidt-compatible: hand-executable, memorable)

1. **Composed cipher hypothesis: classical-keystream + Sanborn perturbation.**
   The leading hypothesis from this session's reframe is *not* that the
   keystream itself is exotic, but that the cipher is a Quagmire III
   (which Sanborn knows works because K1 and K2 use it) with a
   *positional perturbation* — a single inserted letter, a single
   deleted letter, a single transposition, a single character-offset
   shift in some window. This is direction (1) in the parent analyst's
   suggested attack order. **Highest priority for next experiment.**

2. **Two-keystream interleaving on the K4nundrum W-partition.** glthr
   2024's observation that the two W-split groups have matching letter-
   frequency shapes (`p < 0.0004`) suggests dual-key interleaving. The
   shift-sequence search has not been run on the two partitions
   separately. Run it: extract the shift sequence at the cribs *within
   each partition*, and search for two generators (one per partition).

3. **Variant of (1) above:** stride-k reading. If K4's keystream is the
   output of generator G sampled at every k-th position, the same crib
   positions become different generator positions. Sweep stride k from
   1 to 24 on each generator family.

4. **Cipher-modified keystreams.** Apply a Caesar shift after the
   generator output (`(G(i) + s) mod 26` for s in 0-25). Cheap; trivially
   adds a factor of 26 to the search space.

5. **Compositions: constant + LCG, K-text + Caesar, etc.** Two
   independent generator outputs combined arithmetically. Most natural
   composition for a hand-executable cipher: `(G1(i) + G2(i)) mod 26`.

### Medium prior (mathematical but not absurd)

6. **Higher-order recurrences mod 26.** Pell-like recurrences
   `x_n = a x_{n-1} + b x_{n-2} mod m` with `(a, b, m)` swept over
   small values.

7. **Cellular-automata-derived keystreams.** Rule 30, Rule 110, etc.
   over a 32- or 64-bit state, read out as mod-26.

8. **Page-numbered text streams.** Take a specific book (e.g. Carter's
   *Tomb of Tut-ankh-Amen*) and use Vigenère with the running text as
   key. This is just the long-running-key cipher already in
   `kryptos.ciphers.running_key`, but the *book selection* is the
   parameter we haven't really swept. Top candidates per
   `data/clues.yaml`: Carter (confirmed K3 source), Schliemann
   memoirs (Sanborn favorite), Hofstadter's *Gödel, Escher, Bach*
   (Sanborn cited in interviews).

### Low prior (worth eliminating, low payoff)

9. **Larger constants library.** Liouville's number, Champernowne in
   base 26, Copeland-Erdős, Hardy-Ramanujan numbers.

10. **Larger LCG sweep.** `m` other than 26 (24, 25, 27, 28); larger
    `a` or `c`.

11. **Weltzeituhr state at the ~85k parameter combinations already
    tested in 003** but extracted as a *shift sequence* rather than
    a Vigenère key. The 003 experiment used the clock state to derive
    decryption shifts on the full 97-letter ciphertext; reading the
    same generators against the 24-position crib signature is a
    different (much smaller) check and may surface something the
    full-decrypt filter missed.

## Recommendation

Stop expanding generator-family breadth. Pivot to direction (1) above:
the Quagmire-III-plus-perturbation hypothesis. That is one experiment
of similar scale to 002, and unlike the keystream-from-generator
search, has a clear plausible win path:

  - Sweep all Quagmire-III keys of length L in {6, 7, 8} over both
    alphabets.
  - For each, compute the candidate plaintext.
  - For each plaintext, check whether *one positional perturbation*
    (insert, delete, transpose, or shift) makes the crib check pass.
  - Score survivors with the chi-squared fitness gate.

That experiment number will be **007**. Build it next.

## How to extend this document

Each future generator family that gets tested should append a row to
the "Tested" table with the count and the negative-result note. The
"What to test next" list is the working priority queue; cross items
off as the corresponding experiment lands. The hypothesis priority
reflects design-constraint reasoning (Sanborn's likely choices given
his artistic background and Scheidt's stated constraints), not just
mathematical convenience.

## Citation

Reproducible via:

```bash
uv run python experiments/006_shift_sequence_analysis.py
```

All 165 generators with ≥ 3 consecutive matches (and all 8 generators
with ≥ 2 boundary-aligned matches) are in
`experiments/results/{date}_006_shift_sequence_analysis.jsonl`. The
generator library is `src/kryptos/generators.py`.
