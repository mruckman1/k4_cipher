# Paper: K4 model-robust under-determination

arXiv-style manuscript synthesizing the repository's findings.

- **Source:** [`k4_underdetermination.tex`](k4_underdetermination.tex) — self-contained
  (standard `article` class; inline bibliography; one TikZ figure; no external assets,
  no `bibtex`/`biber` run required).
- **Output:** `k4_underdetermination.pdf` (9 pages).

## Build

```sh
pdflatex k4_underdetermination.tex   # run twice to resolve cross-refs
pdflatex k4_underdetermination.tex
# or, if available:
latexmk -pdf k4_underdetermination.tex
```

## Scope

The paper reports a **structural / negative result**, not a decryption: under the
best-fit two-chart homophonic model, K4's 73 free positions are model-robustly
under-determined by all public decipherment-legal inputs, decomposing into 30
selector-locked and 43 prior-governed positions. Every numerical claim traces to a
logged `Verdict` in `../experiments/results/` (aggregated in
`../experiments/results/FINDINGS.md`); a prose version is in
[`../docs/K4_synthesis.md`](../docs/K4_synthesis.md).

The author line and bibliography are editable before any submission. Title/abstract
are framed for a venue such as *Cryptologia* or arXiv `cs.CR`.
