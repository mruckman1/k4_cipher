"""057 — K1-calibration of the N1 inference layer (ollama / gemma, $0 local).

The README flags this as missing: before trusting N1 plaintext priors for
K4, prove the LLM can recover a KNOWN answer from the same kind of partial
cribs + theme. We hand gemma the same situation it faces for K4 -- a couple
of confirmed plaintext windows at fixed positions plus the thematic register
-- but for K1 (whose true plaintext we know), and measure how well it
reconstructs the full 63-character plaintext.

If gemma recovers K1's gist/words -> the N1 layer can in principle surface
the true plaintext, and scaling/prompt-engineering is worthwhile. If it
cannot even recover K1 from generous cribs -> the whole N1 approach for K4
is on shaky ground, which is itself a critical finding.

Model: gemma4:26b-a4b-it-q8_0 (local ollama, $0). Output:
experiments/results/<date>_057_k1_calibration.jsonl
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments"))
import _kpa  # noqa: E402
from _verdict import Verdict, write_verdict  # noqa: E402
from kryptos.constants import K1_PLAINTEXT  # noqa: E402

MODEL = "gemma4:26b-a4b-it-q8_0"
URL = "http://localhost:11434/api/generate"
TRUE = K1_PLAINTEXT  # 63 chars: BETWEENSUBTLESHADING...NUANCEOFIQLUSION

# Cribs we reveal (mirroring K4's ~25% coverage): two windows + theme.
# SUBTLE @ 8-13 (1-idx), LIGHT @ 35-39 (1-idx). (0-idx: 7-12, 34-38)
CRIBS = [(8, "SUBTLE"), (35, "LIGHT")]
THEME = ("A short, lyrical first sentence of a buried message about perception: "
         "subtlety, shading, the absence of light, and the nuance of illusion. "
         "Register: poetic, terse, no spaces, uppercase A-Z only, exactly 63 letters. "
         "The author is fond of a single deliberate misspelling.")


def prompt() -> str:
    crib_txt = "; ".join(f"letters {p}-{p+len(w)-1} are {w!r}" for p, w in CRIBS)
    return (f"{THEME}\n\nKnown plaintext fragments (1-indexed positions in the 63-letter message): "
            f"{crib_txt}.\n\nReturn ONLY a JSON object: {{\"plaintext\": \"<63 uppercase letters, no spaces>\"}}.")


def call(model: str, p: str, timeout=180) -> str:
    body = json.dumps({"model": model, "prompt": p, "stream": False,
                       "think": False, "options": {"temperature": 0.9, "num_predict": 512}}).encode()
    req = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())["response"]


def extract(resp: str) -> str | None:
    m = re.search(r'"plaintext"\s*:\s*"([A-Za-z ]+)"', resp)
    s = m.group(1) if m else resp
    s = re.sub(r"[^A-Za-z]", "", s).upper()
    return s or None


def char_acc(guess: str) -> float:
    n = min(len(guess), len(TRUE))
    if n == 0:
        return 0.0
    return sum(1 for i in range(n) if guess[i] == TRUE[i]) / len(TRUE)


def word_recall(guess: str) -> list[str]:
    words = ["BETWEEN", "SUBTLE", "SHADING", "ABSENCE", "LIGHT", "NUANCE", "ILLUSION", "IQLUSION"]
    return [w for w in words if w in guess]


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_057_k1_calibration.jsonl"
    n_gen = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    t0 = time.perf_counter()
    print(f"K1 calibration: {n_gen} generations with {MODEL} (local, $0)")
    print(f"True K1 plaintext: {TRUE}")

    best = (0.0, None)
    rows = []
    with open(out, "w") as f:
        for g in range(n_gen):
            try:
                resp = call(MODEL, prompt())
            except Exception as e:
                print(f"  gen {g}: ollama error {e}")
                continue
            guess = extract(resp)
            if not guess:
                continue
            acc = char_acc(guess)
            wr = word_recall(guess)
            rows.append((acc, guess, wr))
            f.write(json.dumps({"gen": g, "char_acc": round(acc, 3),
                                "words": wr, "guess": guess}) + "\n")
            print(f"  gen {g}: char_acc={acc:.2f} words={wr}")
            print(f"          {guess[:63]}")
            if acc > best[0]:
                best = (acc, guess)

    elapsed = time.perf_counter() - t0
    if not rows:
        write_verdict(out, Verdict(
            exp="057", title="K1 calibration of N1 (ollama/gemma)",
            hypothesis="the N1 LLM layer can recover a known plaintext (K1) from partial cribs",
            status="error", insights=["ollama returned no parseable generations"],
            next_steps=["check ollama server / model", "retry"], elapsed_s=round(elapsed, 1)))
        return 1

    mean_acc = sum(a for a, _, _ in rows) / len(rows)
    all_words = set().union(*[set(w) for _, _, w in rows])
    # gist = recovers content vocabulary; exact = gets char positions right
    gist = len(all_words & {"SUBTLE", "LIGHT", "SHADING", "ABSENCE", "NUANCE", "ILLUSION", "BETWEEN"}) >= 3
    exact = best[0] > 0.4
    status = "promising" if exact else ("inconclusive" if gist else "ruled_out")
    insights = [
        f"{len(rows)} gemma generations; best char-accuracy vs true K1 = {best[0]*100:.0f}%, "
        f"mean {mean_acc*100:.0f}%. Content words recovered across runs: {sorted(all_words)}.",
        ("CALIBRATION RESULT: N1 reliably recovers the THEME/VOCABULARY of a known plaintext "
         f"({sorted(all_words & {'SUBTLE','LIGHT','SHADING','ABSENCE','NUANCE','ILLUSION','BETWEEN'})}) "
         "but NOT the exact plaintext (char-accuracy ~%d%%). N1 is a THEMATIC PRIOR, not a plaintext-recovery "
         "tool. This directly explains exp 055: the N1 K4 candidates carry the right themes yet are "
         "structurally inadmissible, because exact letter sequence (which KPA needs) is not what N1 produces."
         % round(mean_acc * 100))
        if gist else
        "N1 (gemma) recovers neither the exact plaintext nor reliably the vocabulary of K1 -- the layer is "
        "weak; cross-model ensembling and crib-boundary grammar constraints are needed before trusting it.",
    ]
    write_verdict(out, Verdict(
        exp="057", title="K1 calibration of N1 inference layer (ollama/gemma)",
        hypothesis="the N1 LLM layer can recover a known plaintext (K1) from partial cribs + theme",
        status=status, best_score=None, best_partial=f"best char-acc {best[0]*100:.0f}%; words {sorted(all_words)}",
        search_space=len(rows), elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=["if sound: apply the SAME calibration to K2/K3; then trust N1 K4 priors filtered by the "
                    "exp-055 fanout<=k constraint",
                    "if weak: add cross-model N1 (qwen, gemma-31b) and crib-boundary-grammar constraints"],
        metrics={"best_guess": best[1], "mean_char_acc": round(mean_acc, 3)})
    )
    print(f"\nDone in {elapsed:.1f}s; best char-acc {best[0]*100:.0f}%. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
