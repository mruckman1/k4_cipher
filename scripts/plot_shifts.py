"""Shift-pattern visualiser for the K4 cribs.

The aperiodicity of the EAST -> NORTHEAST shift sequence
[25,15,1,24,23,24,2,2,20,24,16,0,1] is the single strongest piece of
cryptanalytic evidence about K4. This script:

  1. Prints the shift sequence at each crib window in both standard A-Z
     and KRYPTOS-keyed index spaces.
  2. Correlates the K4 crib shifts against candidate keystreams:
        - Vigenere with key="KRYPTOS"
        - Vimark with primer="DYAHR" (KRYPTOS-keyed)
        - Various Gromark numeric primers
        - Carter running-key starting at offset O for many O (if corpus present)
  3. Optionally plots all of the above as a strip chart with matplotlib.

Usage:
    uv run python scripts/plot_shifts.py
    uv run python scripts/plot_shifts.py --plot out.png
    uv run python scripts/plot_shifts.py --running-key data/corpora/carter_tutankhamen.txt
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from kryptos import K4
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, Alphabet
from kryptos.ciphers.gromark import Gromark, Vimark
from kryptos.ciphers.vigenere import Vigenere
from kryptos.cribs import BERLINCLOCK, EASTNORTHEAST
from kryptos.utils import clean, repeat_to_length


def crib_shifts(alphabet: Alphabet, crib) -> list[int]:
    return [
        (alphabet.index(p) - alphabet.index(c)) % len(alphabet)
        for p, c in zip(crib.plaintext, crib.ciphertext)
    ]


def keystream_for(cipher_callable, length: int) -> list[int]:
    """Decrypt a known plaintext through `cipher_callable` to recover its
    shift sequence -- we feed the all-A plaintext and read the differences."""
    # Actually easier: encrypt all-A, the result reveals shifts directly.
    text = "A" * length
    ct = cipher_callable.encrypt(text)
    return [(STANDARD.index(c) - STANDARD.index("A")) % 26 for c in ct]


def vigenere_shifts(key: str, length: int) -> list[int]:
    key = repeat_to_length(key.upper(), length)
    return [STANDARD.index(k) for k in key]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--plot", type=Path, default=None,
                    help="optional output PNG path; requires matplotlib")
    ap.add_argument("--running-key", type=Path, default=None,
                    help="optional running-key corpus to scan as a keystream")
    ap.add_argument("--running-key-offsets", type=int, default=20,
                    help="how many leading offsets of the running key to consider")
    args = ap.parse_args()

    series: dict[str, list[int]] = {}

    # K4 shifts at the cribs.
    for alphabet in (STANDARD, KRYPTOS_KEYED):
        s_en = crib_shifts(alphabet, EASTNORTHEAST)
        s_bc = crib_shifts(alphabet, BERLINCLOCK)
        label_en = f"K4 EASTNORTHEAST ({alphabet.name})"
        label_bc = f"K4 BERLINCLOCK   ({alphabet.name})"
        series[label_en] = s_en
        series[label_bc] = s_bc
        print(f"\n{label_en} -> {s_en}")
        print(f"{label_bc} -> {s_bc}")

    # Candidate keystreams (length-len(K4), trimmed to crib windows).
    candidates: dict[str, list[int]] = {}
    candidates["Vigenere(KRYPTOS)"] = vigenere_shifts("KRYPTOS", len(K4))
    candidates["Vimark(DYAHR, KRYPTOS)"] = Vimark("DYAHR", "KRYPTOS").keystream(len(K4))
    candidates["Gromark(00001, KRYPTOS)"] = Gromark("00001", "KRYPTOS").keystream(len(K4))
    candidates["Gromark(12345, KRYPTOS)"] = Gromark("12345", "KRYPTOS").keystream(len(K4))

    if args.running_key:
        text = clean(args.running_key.read_text())
        for off in range(args.running_key_offsets):
            if off + len(K4) > len(text):
                break
            sl = text[off : off + len(K4)]
            candidates[f"running-key offset {off}"] = [STANDARD.index(c) for c in sl]

    print("\n=== candidate keystream shifts at EASTNORTHEAST (pos 22-34) ===")
    en_start = EASTNORTHEAST.start - 1
    en_end = EASTNORTHEAST.end
    for name, ks in candidates.items():
        seg = ks[en_start:en_end]
        # residual = (K4-shifts) - (candidate-shifts) mod 26
        residual = [(s - k) % 26 for s, k in zip(series[f"K4 EASTNORTHEAST ({STANDARD.name})"], seg)]
        print(f"  {name:35s} {seg}  residual={residual}")

    if args.plot:
        try:
            import matplotlib.pyplot as plt
        except ImportError:
            print("matplotlib not available; install with: uv add matplotlib", file=sys.stderr)
            return 1
        fig, axes = plt.subplots(2, 1, figsize=(10, 6), sharey=True)
        for ax, crib, key in zip(
            axes,
            (EASTNORTHEAST, BERLINCLOCK),
            (f"K4 EASTNORTHEAST ({STANDARD.name})", f"K4 BERLINCLOCK   ({STANDARD.name})"),
        ):
            xs = list(range(crib.start, crib.end + 1))
            ax.plot(xs, series[key], "o-", label="K4 (A-Z)")
            for name, ks in list(candidates.items())[:6]:
                seg = ks[crib.start - 1 : crib.end]
                ax.plot(xs, seg, ".--", alpha=0.6, label=name)
            ax.set_title(f"{crib.name} window")
            ax.set_xlabel("K4 position (1-indexed)")
            ax.set_ylabel("shift mod 26")
            ax.set_ylim(-1, 26)
            ax.legend(fontsize=7, loc="upper right")
        fig.tight_layout()
        fig.savefig(args.plot, dpi=120)
        print(f"wrote {args.plot}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
