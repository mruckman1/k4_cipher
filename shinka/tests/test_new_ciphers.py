"""Round-trip + smoke tests for new cipher primitives added to
``kryptos.ciphers`` for the K4 evolution runs:

Round 1 additions (probe13):
  - Bifid    (Polybius fractionation + period reorder)
  - Trifid   (3D Polybius, 27 cells -> 26 letters via sentinel)
  - Playfair (5x5 keyed-square digram substitution)
  - WSegmented (Lethuillier-style W-position segmented cipher)

Round 2 additions (after k4_full_v2 plateau):
  - Nicodemus  (columnar transposition + per-column Vigenere)
  - TwoSquare  (digram substitution with 2 keyed grids)
  - FourSquare (digram substitution with 4 grids, 2 keyed)
  - ADFGVX     (Polybius substitution + columnar transposition;
                length-doubling, NOT a K4 direct-decrypt candidate)

Run with: ``pytest tests/test_new_ciphers.py -v``.
"""

from __future__ import annotations

import pytest

from kryptos.ciphers import (
    ADFGVX,
    Bifid,
    FourSquare,
    Nicodemus,
    Playfair,
    QuagmireIII,
    Trifid,
    TwoSquare,
    Vigenere,
    WSegmented,
)
from kryptos.constants import K4


# K4-specific structural constants.
K4_W_POSITIONS = (20, 36, 48, 58, 74)  # 0-indexed W positions in K4 ct


# --------------------------------------------------------------------------
# Bifid

@pytest.mark.parametrize("keyword,period", [
    ("KRYPTOS", 5), ("KRYPTOS", 7), ("PALIMPSEST", 5),
    ("ABSCISSA", 11), ("BERLIN", 3),
])
def test_bifid_roundtrip_on_text_without_j(keyword: str, period: int) -> None:
    """Bifid is length-preserving and a strict inverse for plaintext with
    no J (the canonical I/J merge maps J->I, so any J round-trips to I)."""
    b = Bifid(keyword=keyword, period=period)
    pt = "THEQUICKBROWNFOXUMPSOVERTHELAYDOG"  # 33 chars, no J
    ct = b.encrypt(pt)
    rt = b.decrypt(ct)
    assert len(ct) == len(pt)
    assert rt == pt


def test_bifid_k4_decrypt_produces_97_chars() -> None:
    """On K4 ciphertext, Bifid must produce a 97-char A-Z plaintext (the
    scoring contract). K4 has 3 Js (positions 40, 51, 81) which merge
    with I; we don't check round-trip exactness, just shape."""
    b = Bifid(keyword="KRYPTOS", period=5)
    pt = b.decrypt(K4)
    assert len(pt) == 97
    assert pt.isupper() and pt.isalpha()


def test_bifid_period_invalid() -> None:
    with pytest.raises(ValueError, match="period must be >= 1"):
        Bifid(keyword="KRYPTOS", period=0)


def test_bifid_merge_same_letter_rejected() -> None:
    with pytest.raises(ValueError, match="merge letters must differ"):
        Bifid(keyword="KRYPTOS", merge=("I", "I"))


# --------------------------------------------------------------------------
# Trifid

@pytest.mark.parametrize("keyword,period", [
    ("KRYPTOS", 5), ("PALIMPSEST", 5), ("ABSCISSA", 5),
])
def test_trifid_k4_decrypt_length(keyword: str, period: int) -> None:
    """Trifid on K4 must produce a 97-char A-Z plaintext (the scoring
    contract). Round-trip is intentionally non-injective (a 27-cell
    cipher can't be exactly inverted into a 26-letter alphabet), so we
    don't test round-trip here -- only that decrypt returns a valid
    97-char A-Z string for the fitness scorer."""
    t = Trifid(keyword=keyword, period=period)
    pt = t.decrypt(K4)
    assert len(pt) == 97
    assert pt.isupper() and pt.isalpha()


def test_trifid_period_invalid() -> None:
    with pytest.raises(ValueError, match="period must be >= 1"):
        Trifid(keyword="KRYPTOS", period=0)


def test_trifid_invalid_filler() -> None:
    with pytest.raises(ValueError, match="filler must be a single A-Z letter"):
        Trifid(keyword="KRYPTOS", filler="+")


def test_trifid_cube_has_27_unique_cells() -> None:
    """The cube must have 27 distinct symbols (26 letters + 1 sentinel)
    so that decryption is unambiguous per-cell."""
    from kryptos.ciphers.trifid import _build_cube
    cube, coord, rev = _build_cube("KRYPTOS")
    assert len(cube) == 27
    assert len(set(cube)) == 27
    assert len(rev) == 27


# --------------------------------------------------------------------------
# Playfair

def test_playfair_classic_test_vector() -> None:
    """Wheatstone's textbook example: keyword 'PLAYFAIR EXAMPLE',
    plaintext 'HIDE THE GOLD IN THE TREE STUMP'."""
    p = Playfair(keyword="PLAYFAIREXAMPLE", merge=("I", "J"))
    ct = p.encrypt("HIDETHEGOLDINTHETREESTUMP")
    assert ct == "BMODZBXDNABEKUDMUIXMMOUVIF"


def test_playfair_k4_decrypt_length() -> None:
    """K4 is 97 chars (odd) -- Playfair pads internally and truncates the
    output back to 97 so the fitness scorer accepts it."""
    p = Playfair(keyword="KRYPTOS")
    pt = p.decrypt(K4)
    assert len(pt) == 97
    assert pt.isupper() and pt.isalpha()


def test_playfair_invalid_filler() -> None:
    with pytest.raises(ValueError, match="filler must be a single letter"):
        Playfair(keyword="KRYPTOS", filler="XY")


# --------------------------------------------------------------------------
# WSegmented

def test_wsegmented_k4_uniform_roundtrip() -> None:
    """Uniform-cipher WSegmented with explicit K4 W positions round-trips
    the K4 ciphertext through any length-preserving cipher."""
    ws = WSegmented(
        segment_ciphers=Vigenere("KRYPTOS"),
        delimiter_positions=K4_W_POSITIONS,
    )
    pt = ws.decrypt(K4)
    assert len(pt) == 97
    # W's preserved at their K4 positions in the output:
    for p in K4_W_POSITIONS:
        assert pt[p] == "W"
    # Round-trip:
    assert ws.encrypt(pt) == K4


def test_wsegmented_k4_per_segment_roundtrip() -> None:
    """Per-segment ciphers: 6 segments, 6 distinct Quagmire III keys."""
    ws = WSegmented(
        segment_ciphers=[
            QuagmireIII(key="KRYPTOS"),
            QuagmireIII(key="PALIMPSEST"),
            QuagmireIII(key="ABSCISSA"),
            QuagmireIII(key="BERLIN"),
            QuagmireIII(key="DYAHR"),
            QuagmireIII(key="LANGLEY"),
        ],
        delimiter_positions=K4_W_POSITIONS,
    )
    pt = ws.decrypt(K4)
    assert len(pt) == 97
    assert ws.encrypt(pt) == K4


def test_wsegmented_segment_count_mismatch_raises() -> None:
    ws = WSegmented(
        segment_ciphers=[Vigenere("KRYPTOS")],  # only 1, K4 needs 6
        delimiter_positions=K4_W_POSITIONS,
    )
    with pytest.raises(ValueError, match="configured for 1 segments"):
        ws.decrypt(K4)


def test_wsegmented_positions_must_be_increasing() -> None:
    with pytest.raises(ValueError, match="must be strictly increasing"):
        WSegmented(
            segment_ciphers=Vigenere("A"),
            delimiter_positions=(5, 3, 7),  # not sorted
        )


def test_wsegmented_auto_detect_decrypt() -> None:
    """If delimiter_positions is None, positions are auto-detected from
    the input's delimiter occurrences. For DECRYPT on K4, this finds
    the 5 actual W positions."""
    ws = WSegmented(segment_ciphers=Vigenere("KRYPTOS"))
    pt = ws.decrypt(K4)
    assert len(pt) == 97
    # K4's actual W positions should be preserved as W in output
    for p in K4_W_POSITIONS:
        assert pt[p] == "W"


# --------------------------------------------------------------------------
# Nicodemus

@pytest.mark.parametrize("keyword,pt_len", [
    ("KRYPTOS", 44), ("BERLIN", 50), ("ABSCISSA", 97), ("DYAHR", 97),
])
def test_nicodemus_roundtrip_length_preserving(keyword: str, pt_len: int) -> None:
    """Nicodemus is length-preserving and a strict inverse for any text/length."""
    n = Nicodemus(keyword=keyword)
    pt = ("BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIES" * 5)[:pt_len]
    ct = n.encrypt(pt)
    rt = n.decrypt(ct)
    assert len(ct) == pt_len
    assert rt == pt


def test_nicodemus_k4_decrypt() -> None:
    n = Nicodemus(keyword="KRYPTOS")
    pt = n.decrypt(K4)
    assert len(pt) == 97
    assert pt.isupper() and pt.isalpha()


def test_nicodemus_short_keyword_rejected() -> None:
    with pytest.raises(ValueError, match="keyword must be >= 2"):
        Nicodemus(keyword="A")


# --------------------------------------------------------------------------
# TwoSquare

def test_twosquare_roundtrip_even_length() -> None:
    ts = TwoSquare(top_keyword="KRYPTOS", bottom_keyword="ABSCISSA")
    pt = "BETWEENSUBTLESHADING"  # 20 chars, no J
    ct = ts.encrypt(pt)
    rt = ts.decrypt(ct)
    assert rt == pt


def test_twosquare_k4_decrypt() -> None:
    ts = TwoSquare(top_keyword="KRYPTOS", bottom_keyword="BERLIN")
    pt = ts.decrypt(K4)
    assert len(pt) == 97
    assert pt.isupper() and pt.isalpha()


# --------------------------------------------------------------------------
# FourSquare

def test_foursquare_roundtrip_even_length() -> None:
    fs = FourSquare(top_right_keyword="EXAMPLE", bottom_left_keyword="KEYWORD")
    pt = "BETWEENSUBTLESHADING"  # 20 chars, no J
    ct = fs.encrypt(pt)
    rt = fs.decrypt(ct)
    assert rt == pt


def test_foursquare_k4_decrypt() -> None:
    fs = FourSquare(top_right_keyword="KRYPTOS", bottom_left_keyword="BERLIN")
    pt = fs.decrypt(K4)
    assert len(pt) == 97
    assert pt.isupper() and pt.isalpha()


# --------------------------------------------------------------------------
# ADFGVX

def test_adfgvx_roundtrip_doubles_length() -> None:
    """ADFGVX is length-doubling (each plain char -> 2 cipher chars).
    Round-trip on even-length input is exact."""
    for size in (5, 6):
        a = ADFGVX(grid_keyword="KRYPTOS", transposition_keyword="BERLIN", size=size)
        pt = "BETWEENSUBTLESHADING"  # 20 chars, no J
        ct = a.encrypt(pt)
        assert len(ct) == 2 * len(pt), f"size={size}: expected {2*len(pt)} got {len(ct)}"
        rt = a.decrypt(ct)
        assert rt == pt


def test_adfgvx_rejects_odd_length_decrypt() -> None:
    """K4's 97-char ciphertext cannot be decrypted by ADFGVX (odd length;
    each cipher pair collapses to one plain char). Cipher must raise."""
    a = ADFGVX(grid_keyword="KRYPTOS", transposition_keyword="BERLIN", size=5)
    with pytest.raises(ValueError, match="even-length"):
        a.decrypt(K4)


def test_adfgvx_invalid_size_rejected() -> None:
    with pytest.raises(ValueError, match="size must be 5"):
        ADFGVX(grid_keyword="KRYPTOS", transposition_keyword="BERLIN", size=7)
