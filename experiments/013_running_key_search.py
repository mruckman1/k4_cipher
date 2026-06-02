"""Running-key Vigenere/Beaufort search over period-appropriate corpora.

The most under-explored Path C item per the parent analyst. Sanborn used
Carter's *Tomb of Tut-ankh-Amen* as the K3 plaintext source; he was in
Egypt in 1986 (Tutankhamen context) and in Berlin in 1989 (Cold War spy
fiction context). If K4 is encrypted with a running key drawn from one
of these texts, this experiment finds it.

For each source text, sweep every starting offset. For each (source,
offset, alphabet, cipher_variant) tuple, decrypt K4 and check the four
cribs. Fully vectorized with numpy strided views; the full sweep over
~700k offsets x 2 alphabets x 2 directions x 2 variants is ~5M-10M
decryptions and runs in seconds.

Sources tested:
  - Carter/Carnarvon, "Five Years' Explorations at Thebes" (1912)
  - Smith, "Tutankhamen and the Discovery of His Tomb" (1923)
  - Buchan, "The Thirty-Nine Steps" (1915, period spy fiction)
  - K1, K2, K3 plaintexts
  - K1, K2, K3 ciphertexts

For each: forward and reversed.

Alphabets: standard A-Z (mod 26), KRYPTOS-keyed (mod 26).

Cipher variants:
  - Vigenere:   plain_i = (cipher_i - key_i) mod M
  - Beaufort:   plain_i = (key_i - cipher_i) mod M  (reciprocal)
  - Variant Beaufort: plain_i = (cipher_i + key_i) mod M  (rare; included
    so we sweep the full 3-way space of additive/subtractive combos)

Total: roughly 700k offsets x 2 alphabets x 2 directions x 3 variants
= ~8M decryptions, each O(97) and a 24-position crib check. With numpy
vectorisation this is a few seconds.

Win condition: any (source, offset, alphabet, variant) where all 24
crib positions decrypt correctly. Under uniform random, the probability
per offset is (1/26)^24 ~= 10^-34, so any hit is essentially certain
signal.

Run:
    uv run python experiments/013_running_key_search.py
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path

import numpy as np
from numpy.lib.stride_tricks import sliding_window_view

from kryptos import (
    K1,
    K1_PLAINTEXT,
    K2,
    K2_PLAINTEXT,
    K3,
    K3_PLAINTEXT,
    K4,
)
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, Alphabet
from kryptos.cribs import CRIBS
from kryptos.experiment_logger import ExperimentLogger


CORPORA_DIR = Path(__file__).resolve().parents[1] / "data" / "corpora"
NON_LETTER = re.compile(r"[^A-Za-z]")
K4_LEN = len(K4)


def strip_pg_clean(path: Path) -> str:
    text = path.read_text(errors="ignore")
    m_start = re.search(r"\*\*\*\s*START OF (?:THE|THIS) PROJECT GUTENBERG EBOOK[^*]*\*\*\*", text)
    m_end = re.search(r"\*\*\*\s*END OF (?:THE|THIS) PROJECT GUTENBERG EBOOK[^*]*\*\*\*", text)
    if m_start:
        text = text[m_start.end():]
    if m_end:
        text = text[:m_end.start()]
    return NON_LETTER.sub("", text).upper()


def assemble_sources() -> dict[str, str]:
    sources: dict[str, str] = {
        "K1pt":  K1_PLAINTEXT,
        "K2pt":  K2_PLAINTEXT,
        "K3pt":  K3_PLAINTEXT,
        "K1ct":  K1,
        "K2ct":  K2,
        "K3ct":  K3,
    }
    for fname in ("carnarvon_carter_thebes.txt", "smith_tutankhamen.txt",
                  "buchan_39steps.txt"):
        p = CORPORA_DIR / fname
        if p.exists():
            sources[fname.replace(".txt", "")] = strip_pg_clean(p)
    return sources


def sweep_alphabet(
    name: str, source_text: str, alphabet: Alphabet,
    reverse: bool, log,
) -> tuple[int, int]:
    """Vectorised sweep over all offsets of source_text under one
    alphabet, both directions (Vigenere + Beaufort + variant-Beaufort).

    Returns (n_decrypted, n_hits)."""
    if reverse:
        source_text = source_text[::-1]
    if len(source_text) < K4_LEN:
        return 0, 0

    # Encode source and K4 into alphabet-index arrays.
    try:
        source_idx = np.array(alphabet.encode(source_text), dtype=np.int8)
        k4_idx = np.array(alphabet.encode(K4), dtype=np.int8)
    except ValueError:
        # Source contains letters not in this alphabet (shouldn't with A-Z,
        # but defensive).
        return 0, 0

    m = alphabet.modulus
    n_offsets = len(source_idx) - K4_LEN + 1

    # Rolling-window view: shape (n_offsets, K4_LEN)
    keystreams = sliding_window_view(source_idx, K4_LEN)
    # Each operation produces a (n_offsets, K4_LEN) candidate-plaintext array.

    # Crib positions and expected plaintext indices in this alphabet.
    crib_positions = []
    crib_plain_idx = []
    for c in CRIBS:
        for i, p in enumerate(c.plaintext):
            crib_positions.append(c.start - 1 + i)
            crib_plain_idx.append(alphabet.index(p))
    crib_positions_arr = np.array(crib_positions, dtype=np.int32)
    crib_plain_arr = np.array(crib_plain_idx, dtype=np.int8)

    n_decrypted = 0
    n_hits = 0
    for variant in ("vigenere", "beaufort", "var_beaufort"):
        if variant == "vigenere":
            # plain = (cipher - key) mod M
            plain = (k4_idx[None, :].astype(np.int16) - keystreams.astype(np.int16)) % m
        elif variant == "beaufort":
            # plain = (key - cipher) mod M
            plain = (keystreams.astype(np.int16) - k4_idx[None, :].astype(np.int16)) % m
        else:
            # variant Beaufort: plain = (cipher + key) mod M
            plain = (k4_idx[None, :].astype(np.int16) + keystreams.astype(np.int16)) % m

        # Crib-check vectorised: (n_offsets, 24) == broadcast.
        crib_slice = plain[:, crib_positions_arr]
        ok_mask = (crib_slice == crib_plain_arr[None, :]).all(axis=1)
        n_decrypted += n_offsets

        hit_offsets = np.where(ok_mask)[0]
        for off in hit_offsets:
            n_hits += 1
            pt = "".join(alphabet.at(int(plain[off, i])) for i in range(K4_LEN))
            rec = {
                "source":       name,
                "alphabet":     alphabet.name,
                "reverse":      reverse,
                "variant":      variant,
                "offset":       int(off),
                "plaintext":    pt,
            }
            log.write(rec)
            print(f"  HIT  source={name:<28s}  alpha={alphabet.name:<14s}  "
                  f"rev={reverse:<5}  var={variant:<13s}  off={off}")
            print(f"       plain: {pt}")
    return n_decrypted, n_hits


def main() -> int:
    sources = assemble_sources()
    print(f"Sources loaded:")
    for n, s in sources.items():
        print(f"  {n:<32s} {len(s):>10,} chars")
    print()

    n_decrypted = 0
    n_hits = 0
    t0 = time.perf_counter()
    with ExperimentLogger("013_running_key_search") as log:
        log.write({"n_sources": len(sources), "k4_len": K4_LEN})
        for name, text in sources.items():
            for alpha in (STANDARD, KRYPTOS_KEYED):
                for rev in (False, True):
                    n_dec, n_hit = sweep_alphabet(name, text, alpha, rev, log)
                    n_decrypted += n_dec
                    n_hits += n_hit
        log.write({"summary": True, "n_decrypted": n_decrypted, "n_hits": n_hits,
                   "elapsed_s": time.perf_counter() - t0})

    dt = time.perf_counter() - t0
    print()
    print(f"=== summary ===")
    print(f"  decryptions tried: {n_decrypted:>14,}")
    print(f"  crib-passing hits: {n_hits:>14,}")
    print(f"  elapsed:           {dt:.2f}s")
    if n_hits == 0:
        print()
        print("No running-key + crib match across any (source, alphabet, direction, variant).")
        print("Excludes K4 being a Vigenere/Beaufort running-key encryption of K4-length")
        print("from any of: Carter/Carnarvon Thebes, Smith Tutankhamen, Buchan 39 Steps,")
        print("K1/K2/K3 plaintexts and ciphertexts (in either direction).")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    args = ap.parse_args()
    sys.exit(main())
