"""Shared known-plaintext-attack (KPA) helpers for experiments 043+.

Consolidates the numpy/period machinery that exps 015/024/031 each
re-implemented, plus a *generalised* per-position consistency check
(the consistency propagator works on contiguous Crib windows; several
new experiments need to test cribs that land at SCATTERED positions
after a transposition/deletion). Also exposes the cached hexagram
scorer and the candidate-corpus loader so every experiment scores the
same way.

Nothing here is K4-specific beyond importing the four cribs; the
functions are alphabet- and convention-parameterised.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import numpy as np

from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, Alphabet
from kryptos.constants import K4
from kryptos.cribs import CRIBS
from kryptos.scoring.crib_check import surviving_positions
from kryptos.scoring.ngram_fitness import load_ngrams

REPO = Path(__file__).resolve().parents[1]
RESULTS = REPO / "experiments" / "results"
HEXGRAMS = REPO / "data" / "ngrams" / "english_hexagrams.txt"
QUADGRAMS = REPO / "data" / "ngrams" / "english_quadgrams.txt"

K4_LEN = 97
CONVENTIONS = ("vigenere", "beaufort", "variant_beaufort")


# --------------------------------------------------------------------------
# Candidate corpus
# --------------------------------------------------------------------------
def latest_run_dir(model_substr: str = "sonnet", base: Path | None = None) -> Path:
    """Newest N1 output dir whose name contains `model_substr`."""
    base = base or (RESULTS / "n1_claude_outputs")
    runs = sorted(d for d in base.iterdir() if d.is_dir() and model_substr in d.name)
    if not runs:
        raise FileNotFoundError(f"no run dir matching {model_substr!r} in {base}")
    return runs[-1]


def load_candidates(run_dir: Path) -> list[str]:
    out: list[str] = []
    for f in sorted(Path(run_dir).glob("*_parsed.txt")):
        for line in f.read_text().splitlines():
            line = line.strip()
            if len(line) == K4_LEN and line.isalpha() and line.isupper():
                out.append(line)
    return out


# --------------------------------------------------------------------------
# Encoding / periodic KPA (vectorised, from exp 031)
# --------------------------------------------------------------------------
def encode_string(text: str, alphabet: Alphabet) -> np.ndarray:
    return np.fromiter((alphabet.index(c) for c in text), dtype=np.int16, count=len(text))


def encode_array(texts: list[str], alphabet: Alphabet) -> np.ndarray:
    arr = np.empty((len(texts), K4_LEN), dtype=np.int16)
    for r, t in enumerate(texts):
        for c, ch in enumerate(t):
            arr[r, c] = alphabet.index(ch)
    return arr


def required_key(cand_idx, cipher_idx, convention, n_letters=26):
    cands = cand_idx.astype(np.int16)
    cipher = cipher_idx.astype(np.int16)
    if cipher.ndim == 1:
        cipher = cipher[None, :]
    if convention == "vigenere":
        return ((cipher - cands) % n_letters).astype(np.int8)
    if convention == "beaufort":
        return ((cipher + cands) % n_letters).astype(np.int8)
    if convention == "variant_beaufort":
        return ((cands - cipher) % n_letters).astype(np.int8)
    raise ValueError(convention)


def check_slot_consistency(req_key, L):
    """Boolean (per-row) array: True iff the per-position required key is
    constant within each period-L slot."""
    n_cands, M = req_key.shape
    ok = np.ones(n_cands, dtype=bool)
    for s in range(L):
        positions = list(range(s, M, L))
        if len(positions) <= 1:
            continue
        vals = req_key[:, positions]
        ok &= np.all(vals == vals[:, 0:1], axis=1)
    return ok


def keyword_column_order(keyword: str) -> tuple[int, ...]:
    """Standard columnar column-read order from a keyword (K3 convention)."""
    indexed = list(enumerate(keyword))
    sorted_letters = sorted(indexed, key=lambda kv: (kv[1], kv[0]))
    return tuple(idx for idx, _ in sorted_letters)


def col_permutation_full(width: int, col_order: tuple[int, ...], n: int = K4_LEN) -> np.ndarray:
    """Length-n permutation for an *irregular* (length-preserving, no-pad)
    columnar transposition: output position k reads from input position
    perm[k]. Columns are read in `col_order`; the short last row is handled
    by skipping out-of-range cells."""
    rows = (n + width - 1) // width
    perm: list[int] = []
    for col in col_order:
        for row in range(rows):
            src = row * width + col
            if src < n:
                perm.append(src)
    return np.array(perm, dtype=np.int32)


# --------------------------------------------------------------------------
# Generalised per-position consistency (cribs at arbitrary positions)
# --------------------------------------------------------------------------
def crib_position_triples(alphabet: Alphabet = STANDARD) -> list[tuple[int, int, int]]:
    """(0-indexed position, plain_index, cipher_index) for all 24 cribs."""
    out: list[tuple[int, int, int]] = []
    for c in CRIBS:
        for off, (p, ch) in enumerate(zip(c.plaintext, c.ciphertext)):
            pos = c.start - 1 + off
            out.append((pos, alphabet.index(p), alphabet.index(ch)))
    return out


def per_position_consistency(
    triples: list[tuple[int, int, int]],
    period: int,
    convention: str = "vigenere",
    n: int = 26,
) -> tuple[bool, dict[int, int]]:
    """Given (position, plain_idx, cipher_idx) triples (positions may be
    arbitrary / non-contiguous), is there a single period-`period` key
    consistent with all of them? Returns (consistent, {slot: shift})."""
    pinned: dict[int, int] = {}
    for pos, pi, ci in triples:
        if convention == "vigenere":
            k = (ci - pi) % n
        elif convention == "beaufort":
            k = (pi + ci) % n
        elif convention == "variant_beaufort":
            k = (pi - ci) % n
        else:
            raise ValueError(convention)
        slot = pos % period
        if slot in pinned and pinned[slot] != k:
            return False, pinned
        pinned[slot] = k
    return True, pinned


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------
@lru_cache(maxsize=2)
def hexagram_scorer():
    """Cached hexagram fitness (log-prob/char; English ~-13, gibberish ~-24)."""
    return load_ngrams(HEXGRAMS, 6)


@lru_cache(maxsize=1)
def _free_positions() -> tuple[int, ...]:
    return tuple(surviving_positions(K4_LEN, CRIBS))


def score_free_text(plaintext: str) -> float:
    """Hexagram score over the 73 non-crib positions only (the signal-
    bearing positions). Higher = more English-like."""
    free = "".join(plaintext[i] for i in _free_positions())
    return hexagram_scorer()(free)


def score_full(plaintext: str) -> float:
    return hexagram_scorer()(plaintext)


# Re-export the canonical K4 ciphertext for convenience.
K4_TEXT = K4


# --------------------------------------------------------------------------
# Transposition + periodic-substitution KPA (shared by exps 043/049/052)
# --------------------------------------------------------------------------
_CRIB_POS = np.array([p for (p, _, _) in crib_position_triples(STANDARD)], dtype=np.int32)


def best_over_transposition(perm: np.ndarray, max_L: int = 24, decrypt_max_L: int = 20) -> dict:
    """Given a length-97 transposition `perm` (output k reads input perm[k]),
    re-pair the cribs through its inverse and, for each alphabet/convention,
    find the smallest period L with a slot-consistent key. For fully-pinned
    small L, decrypt all 97 and hexagram-score; byte-exact verify.

    Returns {best_score, best_plaintext, verified, decryptable, min_L, params}.
    """
    inv = np.empty_like(perm)
    inv[perm] = np.arange(perm.size)
    paired = inv[_CRIB_POS]
    best_score, best_pt, best_params, verified_flag = -99.0, None, None, False
    decryptable = 0
    min_L = 99
    for an, alpha in (("standard", STANDARD), ("kryptos_keyed", KRYPTOS_KEYED)):
        k4idx = np.array(alpha.encode(K4), dtype=np.int16)
        cipher_idx = k4idx[paired]
        p_idx = np.array([pi for (_, pi, _) in crib_position_triples(alpha)], dtype=np.int16)
        for conv in CONVENTIONS:
            if conv == "vigenere":
                shifts = (cipher_idx - p_idx) % 26
            elif conv == "beaufort":
                shifts = (cipher_idx + p_idx) % 26
            else:
                shifts = (p_idx - cipher_idx) % 26
            for L in range(1, max_L + 1):
                slot = {}
                ok = True
                for pos, s in zip(_CRIB_POS.tolist(), shifts.tolist()):
                    sl = pos % L
                    if sl in slot and slot[sl] != s:
                        ok = False
                        break
                    slot[sl] = s
                if not ok:
                    continue
                min_L = min(min_L, L)
                if len(slot) == L and L <= decrypt_max_L:
                    decryptable += 1
                    m_idx = k4idx[inv]
                    out = []
                    for j in range(97):
                        k = slot[j % L]
                        if conv == "vigenere":
                            pi = (int(m_idx[j]) - k) % 26
                        elif conv == "beaufort":
                            pi = (k - int(m_idx[j])) % 26
                        else:
                            pi = (int(m_idx[j]) + k) % 26
                        out.append(alpha.at(pi))
                    P = "".join(out)
                    sc = score_free_text(P)
                    if sc > best_score:
                        best_score = sc
                        best_pt = P
                        best_params = {"alphabet": an, "convention": conv, "L": L}
                break  # smallest L for this (alpha,conv) is enough
    return {"best_score": best_score, "best_plaintext": best_pt,
            "verified": verified_flag, "decryptable": decryptable,
            "min_L": (min_L if min_L < 99 else None), "params": best_params}
