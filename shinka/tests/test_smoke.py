"""Smoke tests — validate the fitness wiring before spending API budget.

What these check:
  1. _fitness scores K1's plaintext (used as a synthetic "K4-like" 97-char
     English target) much higher than random gibberish.
  2. _fitness gives partial credit when crib positions match — i.e. a
     gibberish string with EAST stitched in at positions 22-25 scores
     strictly higher than pure gibberish.
  3. run_experiment returns a finite score for the seed decrypt_k4, doesn't
     crash, and rejects malformed return values with -inf.

Run: `pytest tests/test_smoke.py -v`.
"""

from __future__ import annotations

import random

from problem._fitness import _fitness
from problem.initial import run_experiment

from kryptos.constants import K1_PLAINTEXT, K4


def _synthetic_97(text: str) -> str:
    """Pad/truncate `text` to exactly 97 uppercase A-Z characters."""
    s = "".join(c for c in text.upper() if "A" <= c <= "Z")
    if len(s) >= 97:
        return s[:97]
    rng = random.Random(0)
    return s + "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(97 - len(s)))


def _stitch_pos74_k(text: str) -> str:
    """The pos-74 filter rejects any plaintext where position 74 (0-indexed
    73) isn't K. These tests are about the fitness function, not the
    filter, so we ensure K is stitched in to bypass that gate."""
    return text[:73] + "K" + text[74:97]


def test_english_scores_higher_than_gibberish() -> None:
    english = _stitch_pos74_k(_synthetic_97(K1_PLAINTEXT * 2))  # 126 chars -> first 97
    rng = random.Random(42)
    gibberish = _stitch_pos74_k(
        "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(97))
    )

    eng_score, eng_meta = _fitness(english)
    gib_score, gib_meta = _fitness(gibberish)

    assert eng_meta["hexagram_per_char"] > gib_meta["hexagram_per_char"], (
        f"English hexagrams ({eng_meta['hexagram_per_char']:.3f}) should beat "
        f"gibberish ({gib_meta['hexagram_per_char']:.3f})"
    )
    # Both fail the cribs (neither has EAST/NORTHEAST/BERLIN/CLOCK at the
    # right positions, almost surely), so the difference is driven by the
    # hexagram component. English just needs to score strictly higher.
    assert eng_score > gib_score


def test_crib_positions_get_partial_credit() -> None:
    rng = random.Random(123)
    base = _stitch_pos74_k(
        "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(97))
    )
    # Stitch EAST into positions 22-25 (0-indexed 21-24).
    with_east = list(base)
    with_east[21:25] = list("EAST")
    with_east_str = "".join(with_east)

    base_score, _ = _fitness(base)
    east_score, east_meta = _fitness(with_east_str)

    # Stitched-in EAST guarantees at least 4 crib hits at positions 22-25.
    assert east_meta["crib_positions_hit"] >= 4
    # Crib component alone contributes 4/24 * 100 ≈ 16.7 points; the
    # hexagram component on neighbouring positions can drift by ±a few, so
    # require a margin of 5 to confirm cribs are pulling the score up.
    assert east_score > base_score + 5


def test_pos74_filter_rejects_missing_k() -> None:
    """A candidate with anything other than K at position 74 must be hard-
    rejected at -300, regardless of other crib matches."""
    rng = random.Random(7)
    base = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(97))
    base = base[:73] + "A" + base[74:]  # explicitly NOT K
    score, meta = _fitness(base)
    assert score == -300.0
    assert meta["rejected_by_pos74_filter"] is True


def test_run_experiment_completes_on_seed() -> None:
    res = run_experiment(instance={"id": "k4", "ciphertext": K4}, seed=0)
    assert "score" in res
    assert "solved" in res
    assert "runtime_s" in res
    # Seed pipeline doesn't solve K4 but must return a finite score, not -inf
    # (it returns a valid 97-char plaintext, just one that fails cribs).
    assert res["score"] > float("-inf"), (
        f"Seed decrypt failed: {res.get('error_tail', '(no error_tail)')}"
    )
    # `solved=True` here means "eval ran cleanly," not "K4 is cracked."
    # The true K4 check lives in metadata.full_solution; the seed is
    # known not to crack it.
    assert res["solved"] is True
    assert res["metadata"]["full_solution"] is False


def _patch_decrypt(fn):
    """Context-manager helper: monkey-patch initial.decrypt_k4 to ``fn``
    for the duration of a `with` block.
    """
    import contextlib
    import problem.initial as initial_module

    @contextlib.contextmanager
    def _cm():
        original = initial_module.decrypt_k4
        initial_module.decrypt_k4 = fn
        try:
            yield
        finally:
            initial_module.decrypt_k4 = original
    return _cm()


def test_hardcoded_plaintext_cheater_scores_minus_inf() -> None:
    """Cheater 1: decrypt_k4 ignores its argument and returns a hand-
    written English plaintext with cribs stitched at the right positions
    (like probe6/gen_17). The cheater function's *source* does NOT
    contain the crib literals (they're in an outer string), so the
    differential-input check is what must catch this.
    """
    fixed_plaintext = (
        "ITWASTOTALLYINVISIBLE"          # 21 free
        + "EAST" + "NORTHEAST"            # cribs
        + "WECANDIRECTLYSEETHEENDOFITALL"
        + "BERLIN" + "CLOCK"
        + "ISTHEKEYTOEVERYTHINGNOW"
    )
    assert len(fixed_plaintext) == 97

    def cheater_decrypt(_ciphertext: str) -> str:  # noqa: ARG001
        return fixed_plaintext

    with _patch_decrypt(cheater_decrypt):
        res = run_experiment(instance={"id": "k4", "ciphertext": K4}, seed=0)

    assert res["score"] == float("-inf")
    err = res["error_tail"].lower()
    assert "ignore" in err or "hardcoded" in err or "identical" in err


def test_crib_literals_in_source_cheater_scores_minus_inf() -> None:
    """Cheater 2: decrypt_k4 runs a real cipher (so differential passes)
    but then *stitches* the cribs into the output as literal strings.
    Caught by find_crib_literal_cheat scanning the function source.
    """
    from kryptos.alphabets import KRYPTOS_KEYED  # noqa: F401  (imported for realism)
    from kryptos.ciphers import QuagmireIII

    def stitch_after_cipher(ciphertext: str) -> str:
        out = list(QuagmireIII(key="KRYPTOS", alphabet_keyword="KRYPTOS").decrypt(ciphertext))
        out[21:25] = list("EAST")
        out[25:34] = list("NORTHEAST")
        out[63:69] = list("BERLIN")
        out[69:74] = list("CLOCK")
        return "".join(out)

    with _patch_decrypt(stitch_after_cipher):
        res = run_experiment(instance={"id": "k4", "ciphertext": K4}, seed=0)

    assert res["score"] == float("-inf")
    err = res["error_tail"].lower()
    assert "crib literal" in err or "crib-stitching" in err


def test_sentinel_cribs_cheater_scores_minus_inf() -> None:
    """Cheater 3: decrypt_k4 produces ct-dependent output (passes
    differential) and avoids literal crib strings in source (passes the
    source scan) but always stitches the cribs at the right positions
    using chr() arithmetic. Only the sentinel-also-scores check catches
    this: decrypt_k4(reversed_K4) also has the cribs at K4 positions.
    """
    # crib positions (0-indexed) and target letters, encoded as offsets
    # from 'A' so the function source has no literal "EAST"/"NORTHEAST"/
    # "BERLIN"/"CLOCK" strings.
    _STITCH_TARGETS = (
        # EAST at 21-24
        (21, 4), (22, 0), (23, 18), (24, 19),
        # NORTHEAST at 25-33
        (25, 13), (26, 14), (27, 17), (28, 19), (29, 7),
        (30, 4), (31, 0), (32, 18), (33, 19),
        # BERLIN at 63-68
        (63, 1), (64, 4), (65, 17), (66, 11), (67, 8), (68, 13),
        # CLOCK at 69-73
        (69, 2), (70, 11), (71, 14), (72, 2), (73, 10),
    )

    def smart_cheater(ciphertext: str) -> str:
        # ct-dependent base so differential passes
        out = [chr(((ord(c) - 65) * 3 + 5) % 26 + 65) for c in ciphertext]
        # Stitch cribs WITHOUT any literal crib string
        for i, off in _STITCH_TARGETS:
            out[i] = chr(65 + off)
        return "".join(out)

    with _patch_decrypt(smart_cheater):
        res = run_experiment(instance={"id": "k4", "ciphertext": K4}, seed=0)

    assert res["score"] == float("-inf")
    err = res["error_tail"].lower()
    assert "sentinel" in err or "code structure" in err or "reversed" in err


def test_malformed_return_scores_minus_inf() -> None:
    # Monkey-patch decrypt_k4 via a local synthetic call: instead, call _fitness
    # by hand isn't equivalent. Easier: feed a too-short instance to verify
    # run_experiment's length check fires correctly via the wrapper boundary.
    # Use a candidate where decrypt_k4 will produce a string of the wrong
    # length — we test the wrapper's length check by reaching past it.
    # In practice, the length/case checks are exercised by mutations during
    # evolution, not synthetic inputs, so this just confirms the guard exists.
    res = run_experiment(instance={"id": "k4", "ciphertext": K4[:50]}, seed=0)
    assert res["score"] == float("-inf")
    assert "error_tail" in res
