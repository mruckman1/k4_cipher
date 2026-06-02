"""089 — Running-key INVERSE coherence test (the decisive, model-free move).

085 bounds short SELECTORS; 088 bounds memorable ALPHABET-sets. Neither bounds a
key that is LONG but MEANINGFUL -- a running-key Vigenere/Quagmire, whose key is
an English text. It satisfies both surviving facts (additive => one-to-one
positional, Fact 1; a varied long key => flattens, Fact 2) and is the most
"memorable" key of all. exps 013/051 tested this only FORWARD (guess a source
text -> decrypt -> check cribs) over a few corpora and failed.

The decisive test was never run: do NOT guess the text -- RECOVER the implied key
letters straight from the cribs and ask whether THEY read as English. If K4 is a
running key whose key advances one letter per position, then the key letters at
CONTIGUOUS crib positions are a contiguous slice of the key text. Two such slices
exist and are long enough to hexagram-score:
    EAST+NORTHEAST  = positions 22-34 -> a 13-letter key fragment
    BERLIN+CLOCK    = positions 64-74 -> an 11-letter key fragment

For every alphabet x {vigenere, beaufort, variant} x {render key in standard A-Z
or in the keyed alphabet} x {forward, reversed}, recover the two key fragments
and hexagram-score them against a random-string control. If any fragment is
coherent English (clears the control ceiling) -> K4 is a running key and 24 key
letters are recovered (hand off to a seeded source search). If EVERY rendering is
gibberish -> the meaningful-running-key hypothesis is CLOSED, strictly stronger
than 013/051 (which only ruled out specific texts).

$0, local, pure decipherment. Output:
experiments/results/<date>_089_running_key_inverse.jsonl
"""

from __future__ import annotations

import json
import random
import time
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, keyed_alphabet

M = 26
ALPHS = {"standard": STANDARD, "kryptos_keyed": KRYPTOS_KEYED,
         "keyed_PALIMPSEST": keyed_alphabet("PALIMPSEST"), "keyed_ABSCISSA": keyed_alphabet("ABSCISSA")}
# The KEY alphabet is INDEPENDENT of the message alphabet (Quagmire-IV: the key
# text need not be written in the same alphabet used on the plaintext/ciphertext).
# We recover the shift index in the MESSAGE alphabet's space, then render the key
# letter through every candidate KEY alphabet -- the on-hypothesis degree of
# freedom an earlier version collapsed (caught in adversarial review).
KEY_ALPHAS = {"standard": STANDARD, "kryptos_keyed": KRYPTOS_KEYED,
              "keyed_PALIMPSEST": keyed_alphabet("PALIMPSEST"), "keyed_ABSCISSA": keyed_alphabet("ABSCISSA")}
# Contiguous crib windows (0-indexed): the key fragments under a 1-letter/position advance.
WINDOWS = {"EASTNORTHEAST": list(range(21, 34)), "BERLINCLOCK": list(range(63, 74))}


def recovered_keys(alpha, conv):
    """{pos: key_index} at the 24 crib positions, key conventions per _kpa/exp083:
    vigenere key=C-P, beaufort key=C+P, variant key=P-C."""
    out = {}
    for pos, pi, ci in _kpa.crib_position_triples(alpha):
        if conv == "vigenere":
            out[pos] = (ci - pi) % M
        elif conv == "beaufort":
            out[pos] = (ci + pi) % M
        else:
            out[pos] = (pi - ci) % M
    return out


def render(keyidx, key_alpha):
    """Render the recovered shift indices as key letters in a given KEY alphabet."""
    return "".join(key_alpha.at(k) for k in keyidx)


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_089_running_key_inverse.jsonl"
    t0 = time.perf_counter()
    score = _kpa.hexagram_scorer()

    # ---- control: random A-Z strings of each window length ----
    rng = random.Random(0)
    ctrl = {}
    for wn, w in WINDOWS.items():
        L = len(w)
        samples = sorted(score("".join(chr(65 + rng.randrange(26)) for _ in range(L)))
                         for _ in range(8000))
        ctrl[wn] = {"mean": round(sum(samples) / len(samples), 2),
                    "p99": round(samples[int(0.99 * len(samples))], 2),
                    "max": round(samples[-1], 2)}

    results = []
    best = (-99.0, None)
    with open(out, "w") as f:
        for an, alpha in ALPHS.items():
            for conv in _kpa.CONVENTIONS:
                keys = recovered_keys(alpha, conv)
                for wn, w in WINDOWS.items():
                    keyidx = [keys[p] for p in w]
                    for kan, kalpha in KEY_ALPHAS.items():
                        frag = render(keyidx, kalpha)
                        for orient in ("fwd", "rev"):
                            s = frag if orient == "fwd" else frag[::-1]
                            sc = score(s)
                            rec = {"msg_alpha": an, "conv": conv, "window": wn, "key_alpha": kan,
                                   "orient": orient, "fragment": s, "hex": round(sc, 2),
                                   "ctrl_p99": ctrl[wn]["p99"], "ctrl_max": ctrl[wn]["max"]}
                            results.append(rec)
                            f.write(json.dumps(rec) + "\n")
                            if sc > best[0]:
                                best = (sc, rec)

    elapsed = time.perf_counter() - t0
    bi = best[1]
    # a fragment is an English signal only if it clears the control MAX for its
    # window length by a margin (the honest ceiling -- a 13/11-char fragment from a
    # large sweep must beat the best random string of equal length, not the mean).
    win = bi["window"]
    margin = bi["hex"] - ctrl[win]["max"]
    english_signal = margin > 1.0
    # promising requires a clearly-English fragment; else the running-key-with-
    # meaningful-contiguous-key hypothesis is ruled out (stronger than 013/051).
    status = "promising" if english_signal else "ruled_out"

    insights = [
        f"Recovered the implied key letters at the 24 crib positions for {len(ALPHS)} message-alphabets x 3 "
        f"conventions x {len(KEY_ALPHAS)} INDEPENDENT key-alphabets x 2 orientations, scoring the two CONTIGUOUS "
        f"key fragments (EASTNORTHEAST=13 letters, BERLINCLOCK=11 letters) as English -- the inverse test "
        f"013/051 never ran. The independent key-alphabet sweep (Quagmire-IV) closes the coverage gap an "
        f"earlier version had.",
        f"Best key fragment: '{bi['fragment']}' (hex {bi['hex']}) from msg={bi['msg_alpha']}/{bi['conv']}/"
        f"{bi['window']}/key={bi['key_alpha']}/{bi['orient']}. Control for length-{len(WINDOWS[win])} random "
        f"strings: mean {ctrl[win]['mean']}, p99 {ctrl[win]['p99']}, MAX {ctrl[win]['max']}. Margin over random "
        f"max = {margin:.2f}.",
        (f"ENGLISH SIGNAL: the best key fragment clears the random ceiling by {margin:.2f} -- K4 may be a "
         f"running key; 24 key letters are now recovered. NEXT: seed a forward source search (Egypt/Berlin/"
         f"Kryptos corpora, exp 013 machinery) with this fragment." if english_signal else
         f"NO ENGLISH SIGNAL: every recovered key fragment scores within random noise (best margin "
         f"{margin:.2f} over the random max). The implied running key is not coherent English in any tested "
         f"alphabet/convention/rendering -- the meaningful-running-key hypothesis is RULED OUT (strictly "
         f"stronger than 013/051, which only ruled out specific source texts)."),
    ]

    write_verdict(out, Verdict(
        exp="089", title="running-key inverse coherence test (is the recovered key English?)",
        hypothesis="K4 is a running-key Vigenere/Quagmire whose key is a meaningful English text; the key "
                   "letters recovered at contiguous crib positions should read as English",
        status=status, best_score=(bi["hex"] if english_signal else None),
        best_partial=f"best key fragment hex {bi['hex']} (msg={bi['msg_alpha']}/{bi['conv']}/{bi['window']}/"
                     f"key={bi['key_alpha']}), margin {margin:.2f} over random max "
                     f"(= {'English signal' if english_signal else 'noise'})",
        search_space=len(results), elapsed_s=round(elapsed, 1),
        insights=insights,
        next_steps=(["seed exp-013 forward source search with the recovered key fragment; verify + decrypt"]
                    if english_signal else
                    ["meaningful-running-key closed; the open per-position limb now narrows to the 2-D physical "
                     "clock (exp 090) and a NEW K1-K3 ciphertext invariant (exp 091)"]),
        metrics={"best": bi, "control": ctrl, "english_signal": english_signal,
                 "margin_over_random_max": round(margin, 2)}),
    )
    print(f"\nbest key fragment '{bi['fragment']}' hex {bi['hex']} (msg={bi['msg_alpha']}/{bi['conv']}/"
          f"{bi['window']}/key={bi['key_alpha']}); random max {ctrl[win]['max']}; margin {margin:.2f}; "
          f"english_signal={english_signal}; status={status}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
