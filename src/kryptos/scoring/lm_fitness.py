"""Neural / byte-level language-model fitness oracle.

The hexagram table saturates: any 6-gram never seen in the Gutenberg
corpus gets the same floor, so once a candidate is mostly-unseen windows
the gradient flattens (the documented "71.98 ceiling" artifact). A neural
char/byte LM gives a SMOOTH, non-saturating per-character surprisal that
still discriminates among gibberish strings, restoring a usable gradient.

Interface mirrors `NgramFitness.__call__`: `scorer(text) -> float`, higher
= more English-like (we return the negative mean NLL/char). Drop it in
anywhere the hexagram scorer is used.

Requires `transformers` + `torch` (free, local; runs on Apple MPS). Import
is lazy so the rest of the library works without them installed.
"""

from __future__ import annotations

from functools import lru_cache


class LMFitness:
    """Mean log-likelihood per character under a small causal LM.

    Uses a char-level GPT-2 (`distilgpt2` by default) scored token-by-token.
    K4 plaintext is uppercase A-Z; we lower-case for the LM's tokenizer.
    """

    def __init__(self, model_name: str = "distilgpt2", device: str | None = None) -> None:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        if device is None:
            if torch.backends.mps.is_available():
                device = "mps"
            elif torch.cuda.is_available():
                device = "cuda"
            else:
                device = "cpu"
        self.device = device
        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForCausalLM.from_pretrained(model_name).to(device).eval()

    def __call__(self, text: str) -> float:
        torch = self.torch
        s = text.lower()
        ids = self.tok(s, return_tensors="pt").input_ids.to(self.device)
        if ids.shape[1] < 2:
            return -100.0
        with torch.no_grad():
            out = self.model(ids, labels=ids)
        # out.loss is mean NLL per token (nats). Negate -> higher is better.
        return float(-out.loss.item())


@lru_cache(maxsize=2)
def lm_scorer(model_name: str = "distilgpt2") -> "LMFitness":
    return LMFitness(model_name)


class BackoffCharLM:
    """Stupid-backoff character n-gram model -- a SMOOTH scorer with NO hard
    floor, the key property the saturating hexagram table lacks.

    For each position it scores P(c | longest matching context up to order
    maxn-1), backing off by a constant factor alpha each time the context is
    unseen, all the way down to a +1-smoothed unigram. Because it never hits
    a single constant floor, it keeps a usable gradient among gibberish
    strings where fixed-order hexagram log-prob is flat. Pure-Python, no
    torch; trains in a second or two on the existing corpus.
    """

    def __init__(self, corpus: str, maxn: int = 7, alpha: float = 0.4) -> None:
        import math
        from collections import Counter
        self.maxn = maxn
        self.alpha = alpha
        self.log = math.log
        self.counts: list[Counter] = [Counter() for _ in range(maxn + 1)]
        self.ctx: list[Counter] = [Counter() for _ in range(maxn + 1)]
        for n in range(1, maxn + 1):
            for i in range(len(corpus) - n + 1):
                g = corpus[i:i + n]
                self.counts[n][g] += 1
                self.ctx[n][g[:-1]] += 1
        self.V = 26
        self.uni_total = sum(self.counts[1].values())

    def _p(self, ctx: str, ch: str) -> float:
        for n in range(min(self.maxn, len(ctx) + 1), 0, -1):
            context = ctx[-(n - 1):] if n > 1 else ""
            g = context + ch
            cg = self.counts[n].get(g, 0)
            if cg:
                back = self.alpha ** (min(self.maxn, len(ctx) + 1) - n)
                return back * cg / self.ctx[n][context]
        # +1 smoothed unigram
        return (self.counts[1].get(ch, 0) + 1) / (self.uni_total + self.V)

    def __call__(self, text: str) -> float:
        if not text:
            return -100.0
        s = 0.0
        for i, ch in enumerate(text):
            s += self.log(self._p(text[max(0, i - self.maxn + 1):i], ch))
        return s / len(text)


@lru_cache(maxsize=1)
def backoff_scorer(maxn: int = 7) -> "BackoffCharLM":
    from pathlib import Path
    from kryptos.utils import clean
    repo = Path(__file__).resolve().parents[3]
    corpus = clean(Path(repo / "data" / "corpora" / "buchan_39steps.txt").read_text())
    corpus += clean(Path(repo / "data" / "corpora" / "smith_tutankhamen.txt").read_text())
    return BackoffCharLM(corpus, maxn=maxn)
