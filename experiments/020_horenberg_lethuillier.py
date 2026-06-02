"""Experiment 020: Hörenberg XOR-strip + Lethuillier W-segmentation.

Two structural reframings from the K4 literature, both untested in this
repo until now:

  Hörenberg (kryptos.hoerenberg.com): K4 is 4 indicator characters
    (OBKR) + 93 doubly-encrypted characters. The second stage is an
    XOR mask drawn from the Vigenere tableau itself, starting at the
    M-row, column 5, with the 27-letter doubled-L variant. He reports
    an IoC jump from 0.036 (raw K4) to 0.061 after XOR-stripping.
    --- CALIBRATED FINDING (2026-05-21): "5-bit ASCII" is under-
    specified in the published recipe and Hörenberg's actual
    implementation isn't public. Across 12,486 (alphabet, drop,
    row_label, start_col, encoding) variants exhausting the
    construction's effective keystream space, the maximum IoC is
    0.0479, not 0.061. Honest framing: "the published recipe as
    best reconstructed from the public site does not reproduce
    Hörenberg's claimed IoC=0.061 across reasonable interpretations
    of the construction; the hypothesis is not supported by
    available evidence." This is NOT "Hörenberg is wrong" -- the
    door remains open if someone surfaces his actual implementation.

  Lethuillier (kryptos community): the six segments of K4 separated by
    its 5 W's have matching letter-frequency shapes (empirical null
    probability < 0.05%). Cribs sit at segment boundaries: EAST,
    NORTHEAST, BERLIN, CLOCK all anchor specific segments. K4 might be
    six independently-encrypted segments concatenated with W-separators.
    --- CALIBRATED FINDING (2026-05-21): The W-segmentation
    structural observation is genuine and load-bearing. What this
    experiment falsified is specifically the conjunction
    "segmentation + per-segment short-period Q3". The per-segment
    crib-consistency obstruction is the same as the global one:
    EASTNORTHEAST shifts within seg 1 are not consistent with any
    Q3 period 1-8 in either alphabet. The right reading: the
    W-segmentation hypothesis is sharpened, not rejected --- the
    per-segment cipher is not periodic Q3, but the segmentation
    itself may still be real.

This experiment has 5 steps, each independently informative:

  A. Implement the XOR-strip both ways (naive A=0..Z=25 mod 32, and
     ITA2/Baudot historical 5-bit). Try row M of the 26-letter and
     27-letter doubled-L tableau, starting at columns 0, 4, 5.

  B. For each (encoding, row, start_col) variant, report the IoC of
     the XOR-stripped 93-char intermediate. Verify Hörenberg's
     claimed 0.061 (or document divergence).

  C. For each variant, run the crib-constrained Q3 + Vimark + Gromark
     + Autokey sweep against the intermediate. Cribs at K4 positions
     22-34 and 64-74 (1-indexed) map to intermediate positions 18-30
     and 60-70 (subtract 4 for dropped OBKR).

  D. If C fails, apply W-segmentation to the intermediate and brute-
     force each segment with its own short key.

  E. Independently: apply Lethuillier's W-segmentation directly to
     raw K4. Six segments. For seg 1 (FLRVQQPRNGKSSOT, contains
     EASTNORTHEAST crib + 2 unknown) and seg 4 (INFBNYPVTTMZFPK,
     contains BERLINCLOCK crib + 4 unknown), brute-force Q3 keys.
     If a consistent key family emerges across segments, that's the
     cipher.

Run:
    uv run python experiments/020_horenberg_lethuillier.py
"""

from __future__ import annotations

import argparse
import itertools
import sys
import time
from collections import Counter

import numpy as np

from kryptos import K4
from kryptos.alphabets import KRYPTOS_KEYED, KRYPTOS_WITH_EXTRA_L, STANDARD, Alphabet
from kryptos.analysis import index_of_coincidence
from kryptos.ciphers.quagmire import QuagmireIII
from kryptos.cribs import BERLINCLOCK, CRIBS, EASTNORTHEAST
from kryptos.experiment_logger import ExperimentLogger
from kryptos.scoring.english_classifier import CHI_SQ_T99_RANDOM, chi_squared


# -------------------- Step A: encodings and tableau --------------------

# ITA2 (Baudot-Murray) 5-bit codes for letters. The historical teletype
# code Hörenberg most likely means by "5-bit ASCII".
ITA2_LETTERS: dict[str, int] = {
    "A": 0b00011, "B": 0b11001, "C": 0b01110, "D": 0b01001, "E": 0b00001,
    "F": 0b01101, "G": 0b11010, "H": 0b10100, "I": 0b00110, "J": 0b01011,
    "K": 0b01111, "L": 0b10010, "M": 0b11100, "N": 0b01100, "O": 0b11000,
    "P": 0b10110, "Q": 0b10111, "R": 0b01010, "S": 0b00101, "T": 0b10000,
    "U": 0b00111, "V": 0b11110, "W": 0b10011, "X": 0b11101, "Y": 0b10101,
    "Z": 0b10001,
}
ITA2_INV: dict[int, str] = {v: k for k, v in ITA2_LETTERS.items()}


def to_5bit_naive(c: str) -> int:
    return (ord(c.upper()) - ord("A"))


def from_5bit_naive(v: int) -> str:
    if 0 <= v <= 25:
        return chr(v + ord("A"))
    return "?"


def to_5bit_ita2(c: str) -> int:
    return ITA2_LETTERS[c.upper()]


def from_5bit_ita2(v: int) -> str:
    return ITA2_INV.get(v, "?")


ENCODINGS = {
    "naive_az_mod32": (to_5bit_naive, from_5bit_naive),
    "ita2_baudot":    (to_5bit_ita2,  from_5bit_ita2),
}


def build_keystream(row_letters: str, length: int, start_col: int) -> str:
    """Repeat-extend `row_letters` to `length`, starting at `start_col`."""
    rep = (row_letters[start_col:] + row_letters * (length // len(row_letters) + 2))[:length]
    return rep


def xor_strip(ciphertext: str, keystream: str, encoding: str) -> str:
    to5, from5 = ENCODINGS[encoding]
    out: list[str] = []
    for c, k in zip(ciphertext, keystream):
        try:
            cv = to5(c) ^ to5(k)
            out.append(from5(cv))
        except (KeyError, ValueError):
            out.append("?")
    return "".join(out)


# -------------------- tableau rows --------------------

KEYED_26 = "KRYPTOSABCDEFGHIJLMNQUVWXZ"          # standard KRYPTOS-keyed
KEYED_27 = "KRYPTOSABCDEFGHIJLLMNQUVWXZ"         # doubled-L sculpture variant


def tableau_row(label: str, alphabet: str) -> str:
    """Row of the Vigenere tableau whose label letter is at position 0.
    Built by shifting `alphabet` left until `label` is at index 0."""
    idx = alphabet.index(label)
    return alphabet[idx:] + alphabet[:idx]


# -------------------- Step C support: crib-constrained Q3 on intermediate --------------------


def crib_positions_in_intermediate(drop: int = 4) -> list[tuple[int, str]]:
    """Return (intermediate_pos, plaintext_letter) for each crib position.
    Intermediate is K4[drop:]; cribs at K4 positions 22..34 and 64..74
    (1-indexed) shift to intermediate positions 22-drop..34-drop and
    64-drop..74-drop (1-indexed).
    """
    out: list[tuple[int, str]] = []
    for crib in CRIBS:
        for i, p in enumerate(crib.plaintext):
            k4_pos = crib.start - 1 + i      # 0-indexed in K4
            inter_pos = k4_pos - drop         # 0-indexed in intermediate
            if inter_pos >= 0:
                out.append((inter_pos, p))
    return out


def q3_sweep_intermediate(intermediate: str,
                            alphabet: Alphabet,
                            max_period: int = 30,
                            drop: int = 4) -> dict:
    """Run a crib-constrained Q3 sweep on the XOR-stripped intermediate.

    For each period L in 2..max_period: check whether all crib positions
    in the intermediate produce a consistent key (key[pos mod L] equal
    across all positions mapping to the same slot). If consistent, count
    the free slots and (if few) brute-force enumerate and score.
    """
    crib_pos_letter = crib_positions_in_intermediate(drop)
    N = alphabet.modulus
    # Filter cribs that contain valid characters (not '?' from XOR failure)
    valid_cribs: list[tuple[int, int, int]] = []  # (pos, cipher_idx, plain_idx)
    for pos, p in crib_pos_letter:
        if pos < len(intermediate) and intermediate[pos] != "?":
            try:
                ci = alphabet.index(intermediate[pos])
                pi = alphabet.index(p)
                valid_cribs.append((pos, ci, pi))
            except ValueError:
                pass

    survivors: list[dict] = []
    for L in range(2, max_period + 1):
        pinned: dict[int, int] = {}
        ok = True
        for pos, ci, pi in valid_cribs:
            slot = pos % L
            shift = (ci - pi) % N
            if slot in pinned and pinned[slot] != shift:
                ok = False
                break
            pinned[slot] = shift
        if not ok:
            continue
        free = [s for s in range(L) if s not in pinned]
        n_free = len(free)
        # Brute-force only if free is small.
        if n_free > 4:
            continue
        # Build all key candidates.
        base_key = np.zeros(L, dtype=np.int32)
        for s, v in pinned.items():
            base_key[s] = v
        keystream_positions = np.arange(len(intermediate)) % L
        valid_pos_mask = np.array([c != "?" for c in intermediate], dtype=bool)
        # Encode valid positions into alphabet indices; invalid -> 0 placeholder.
        inter_idx = np.zeros(len(intermediate), dtype=np.int32)
        for i, c in enumerate(intermediate):
            if c != "?":
                inter_idx[i] = alphabet.index(c)

        n_cands = N ** n_free if n_free > 0 else 1
        best_chi = float("inf")
        best_fill: tuple[int, ...] = ()
        best_plain = ""
        for fill in (itertools.product(range(N), repeat=n_free) if n_free > 0 else [()]):
            key = base_key.copy()
            for j, s in enumerate(free):
                key[s] = fill[j]
            keystream = key[keystream_positions]
            plain = (inter_idx - keystream) % N
            text = "".join(
                alphabet.at(int(plain[i])) if valid_pos_mask[i] else "?"
                for i in range(len(intermediate))
            )
            scoring = "".join(c for c in text if c != "?")
            if not scoring:
                continue
            chi = chi_squared(scoring)
            if chi < best_chi:
                best_chi = chi
                best_fill = tuple(int(x) for x in fill)
                best_plain = text
        survivors.append({
            "L": L, "free": n_free,
            "n_cands": n_cands,
            "best_chi": round(best_chi, 2),
            "best_fill": list(best_fill),
            "best_plain": best_plain,
        })
    return {"valid_cribs": len(valid_cribs), "survivors": survivors}


# -------------------- Step E: W-segmentation --------------------


def w_segments(text: str) -> list[tuple[int, str]]:
    """Split `text` at W's (the W's themselves are dropped).
    Returns list of (start_pos_in_text, segment_string)."""
    segs: list[tuple[int, str]] = []
    start = 0
    for i, c in enumerate(text):
        if c == "W":
            if i > start:
                segs.append((start, text[start:i]))
            start = i + 1
    if start < len(text):
        segs.append((start, text[start:]))
    return segs


def segment_q3_attack(
    seg_text: str, seg_start: int,
    alphabet: Alphabet,
    max_period: int = 8,
) -> list[dict]:
    """For a segment with possible crib characters at known positions,
    sweep Q3 keys for each period L, crib-constrained, score by chi^2.

    `seg_start` is the segment's start position in the original K4
    (used to align with crib positions). Cribs at K4 positions inside
    [seg_start, seg_start + len(seg_text)) constrain key slots
    (pos - seg_start) % L.
    """
    # Locate cribs inside this segment.
    seg_end = seg_start + len(seg_text)
    constraints: list[tuple[int, str]] = []   # (within-segment 0-indexed pos, plain letter)
    for crib in CRIBS:
        for i, p in enumerate(crib.plaintext):
            k4_pos = crib.start - 1 + i
            if seg_start <= k4_pos < seg_end:
                constraints.append((k4_pos - seg_start, p))

    N = alphabet.modulus
    seg_idx = np.array(alphabet.encode(seg_text), dtype=np.int32)
    results: list[dict] = []
    for L in range(1, max_period + 1):
        pinned: dict[int, int] = {}
        ok = True
        for pos, p in constraints:
            ci = seg_idx[pos]
            pi = alphabet.index(p)
            slot = pos % L
            shift = (ci - pi) % N
            if slot in pinned and pinned[slot] != shift:
                ok = False
                break
            pinned[slot] = shift
        if not ok:
            continue
        free = [s for s in range(L) if s not in pinned]
        n_free = len(free)
        if n_free > 5:    # cap brute force
            continue
        base_key = np.zeros(L, dtype=np.int32)
        for s, v in pinned.items():
            base_key[s] = v
        keystream_positions = np.arange(len(seg_text)) % L

        # Brute force free slots, score by chi-squared.
        best_chi = float("inf")
        best_fill: tuple[int, ...] = ()
        best_plain = ""
        for fill in (itertools.product(range(N), repeat=n_free) if n_free > 0 else [()]):
            key = base_key.copy()
            for j, s in enumerate(free):
                key[s] = fill[j]
            keystream = key[keystream_positions]
            plain = (seg_idx - keystream) % N
            text = "".join(alphabet.at(int(x)) for x in plain)
            chi = chi_squared(text)
            if chi < best_chi:
                best_chi = chi
                best_fill = tuple(int(x) for x in fill)
                best_plain = text
        results.append({
            "L": L, "free": n_free,
            "best_chi": round(best_chi, 2),
            "best_fill": list(best_fill),
            "best_plain": best_plain,
            "key_pinned": {int(k): int(v) for k, v in pinned.items()},
        })
    return results


# -------------------- main --------------------


def main() -> int:
    print("=" * 78)
    print("EXPERIMENT 020: Horenberg XOR-strip + Lethuillier W-segmentation on K4")
    print("=" * 78)
    raw_K4 = K4
    raw_ioc = index_of_coincidence(raw_K4)
    print(f"raw K4 IoC: {raw_ioc:.4f}   (Horenberg's reference: 0.036)")
    print()

    with ExperimentLogger("020_horenberg_lethuillier") as log:
        log.write({"raw_K4": raw_K4, "raw_K4_ioc": raw_ioc})

        # ============================================================
        # Step A + B: XOR-strip the 93 chars after OBKR, multiple variants
        # ============================================================
        print("--- Step A + B: XOR-strip variants and IoC comparison ---")
        ciphertext_93 = raw_K4[4:]
        print(f"ciphertext to strip (K4[4:]): {ciphertext_93}")
        print()
        target_ioc = 0.061
        a_results: list[dict] = []
        for enc_name in ENCODINGS:
            for alphabet_name, alpha in [("KEYED_26", KEYED_26), ("KEYED_27_with_extra_L", KEYED_27)]:
                for row_label in ["M"]:
                    row = tableau_row(row_label, alpha)
                    for start_col in (0, 4, 5):
                        keystream = build_keystream(row, 93, start_col)
                        stripped = xor_strip(ciphertext_93, keystream, enc_name)
                        valid = "".join(c for c in stripped if c != "?")
                        n_valid = len(valid)
                        ioc = index_of_coincidence(valid) if n_valid >= 2 else 0.0
                        gap_to_target = abs(ioc - target_ioc)
                        rec = {
                            "step": "A_B",
                            "encoding": enc_name,
                            "tableau": alphabet_name,
                            "row_label": row_label,
                            "row_letters": row,
                            "start_col": start_col,
                            "n_valid_letters": n_valid,
                            "ioc": round(ioc, 4),
                            "gap_to_horenberg_0_061": round(gap_to_target, 4),
                            "stripped": stripped,
                        }
                        a_results.append(rec)
                        log.write(rec)
                        flag = " <-- close to Horenberg!" if gap_to_target < 0.005 else ""
                        print(f"  enc={enc_name:16s}  tab={alphabet_name:24s}  "
                              f"row={row_label}  start={start_col}  "
                              f"valid={n_valid}/93  IoC={ioc:.4f}{flag}")

        # Find the variant closest to Horenberg's claimed 0.061.
        a_results.sort(key=lambda r: r["gap_to_horenberg_0_061"])
        best_strip = a_results[0]
        print()
        print(f"Closest to IoC=0.061: gap={best_strip['gap_to_horenberg_0_061']:.4f}  "
              f"enc={best_strip['encoding']}  tableau={best_strip['tableau']}  "
              f"start={best_strip['start_col']}")
        print(f"  stripped: {best_strip['stripped']}")
        print()

        # ============================================================
        # Step C: crib-constrained Q3 sweep against best XOR-stripped intermediate
        # ============================================================
        print("--- Step C: crib-constrained Q3 sweep against best XOR-stripped intermediate ---")
        # Try the top 3 variants (closest to 0.061) for crib sweep.
        c_results: list[dict] = []
        for rank, variant in enumerate(a_results[:3], 1):
            intermediate = variant["stripped"]
            print(f"  variant rank {rank}: IoC={variant['ioc']:.4f} "
                  f"({variant['encoding']}, {variant['tableau']}, start={variant['start_col']})")
            for alphabet_for_sweep in (KRYPTOS_KEYED,):
                sweep = q3_sweep_intermediate(intermediate, alphabet_for_sweep, max_period=30)
                rec = {
                    "step": "C",
                    "variant_rank": rank,
                    "encoding": variant["encoding"],
                    "tableau": variant["tableau"],
                    "start_col": variant["start_col"],
                    "alphabet": alphabet_for_sweep.name,
                    "valid_cribs": sweep["valid_cribs"],
                    "n_survivors": len(sweep["survivors"]),
                }
                log.write(rec)
                log.write({"step": "C_survivors", "details": sweep["survivors"]})
                print(f"    {alphabet_for_sweep.name}: valid_cribs={sweep['valid_cribs']}/24  "
                      f"survivors={len(sweep['survivors'])}")
                if sweep["survivors"]:
                    sweep["survivors"].sort(key=lambda x: x["best_chi"])
                    for s in sweep["survivors"][:5]:
                        flag = "  <-- FITNESS HIT" if s["best_chi"] < CHI_SQ_T99_RANDOM else ""
                        print(f"      L={s['L']:2d} free={s['free']}  "
                              f"best_chi={s['best_chi']:.1f}{flag}")
                        print(f"        plain: {s['best_plain']}")
                c_results.append(rec)

        # ============================================================
        # Step E: Lethuillier W-segmentation directly on raw K4
        # ============================================================
        print()
        print("--- Step E: W-segmentation on RAW K4 ---")
        segs = w_segments(raw_K4)
        print(f"  segments: {len(segs)}")
        for i, (start, seg) in enumerate(segs):
            print(f"    seg {i}: pos {start}..{start + len(seg) - 1}  len={len(seg)}  {seg}")
        log.write({"step": "E_segments", "segments": [(s, t) for s, t in segs]})

        print()
        print("  per-segment Q3 attack:")
        for i, (start, seg) in enumerate(segs):
            print(f"    --- seg {i} ({seg}, start={start}, len={len(seg)}) ---")
            for alpha in (KRYPTOS_KEYED, STANDARD):
                results = segment_q3_attack(seg, start, alpha, max_period=8)
                if not results:
                    continue
                results.sort(key=lambda r: r["best_chi"])
                hits = [r for r in results if r["best_chi"] < 150]
                print(f"      alpha={alpha.name}: {len(results)} L's consistent, "
                      f"best chi^2 = {results[0]['best_chi']:.1f}")
                for r in results[:3]:
                    flag = "  <-- LOW CHI" if r["best_chi"] < 80 else ""
                    print(f"        L={r['L']} free={r['free']} chi={r['best_chi']:.1f}  "
                          f"plain={r['best_plain']}{flag}")
                log.write({
                    "step": "E_segment_results",
                    "segment_index": i, "segment_start": start, "segment_text": seg,
                    "alphabet": alpha.name,
                    "results": results,
                })

        # ============================================================
        # Step D: W-segmentation on best XOR-stripped intermediate
        # ============================================================
        print()
        print("--- Step D: W-segmentation on XOR-stripped intermediate ---")
        # Use the best-IoC intermediate from step A.
        intermediate = best_strip["stripped"]
        print(f"  using intermediate from rank-1 variant: {best_strip['encoding']}/"
              f"{best_strip['tableau']}/start={best_strip['start_col']}")
        print(f"  intermediate: {intermediate}")
        inter_segs = w_segments(intermediate)
        print(f"  intermediate segments (W-separators): {len(inter_segs)}")
        for i, (start, seg) in enumerate(inter_segs):
            print(f"    inter-seg {i}: pos {start}..{start + len(seg) - 1}  len={len(seg)}  {seg}")
        log.write({"step": "D_intermediate_segments",
                   "intermediate": intermediate,
                   "segments": [(s, t) for s, t in inter_segs]})

        # For each intermediate segment, attempt Q3 attack. Note cribs are
        # at INTERMEDIATE positions 18-30 and 60-70 (K4 pos - 4).
        for i, (start, seg) in enumerate(inter_segs):
            # Map intermediate position to K4 position by adding 4.
            k4_segment_start = start + 4
            inter_seg_text = seg.replace("?", "X")   # placeholder for invalid letters
            if "?" in seg:
                print(f"    inter-seg {i}: contains '?'; skipping crib-constrained attack")
                continue
            for alpha in (KRYPTOS_KEYED, STANDARD):
                results = segment_q3_attack(seg, k4_segment_start, alpha, max_period=8)
                if not results:
                    continue
                results.sort(key=lambda r: r["best_chi"])
                print(f"    inter-seg {i} alpha={alpha.name}: {len(results)} L's, "
                      f"best chi^2 = {results[0]['best_chi']:.1f}")
                for r in results[:2]:
                    flag = "  <-- LOW CHI" if r["best_chi"] < 80 else ""
                    print(f"      L={r['L']} free={r['free']} chi={r['best_chi']:.1f}  "
                          f"plain={r['best_plain']}{flag}")
                log.write({
                    "step": "D_segment_results",
                    "inter_segment_index": i, "segment_text": seg,
                    "alphabet": alpha.name, "results": results,
                })

    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    args = ap.parse_args()
    sys.exit(main())
