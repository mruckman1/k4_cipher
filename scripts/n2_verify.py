"""Mechanically verify N2-generated cipher hypotheses against K4.

For each hypothesis in hypotheses_parsed.jsonl, instantiate the cipher,
encrypt the proposed plaintext, and compare byte-exact against K4.
Any pass is reported as a potential solve (must still pass downstream
hexagram fitness sanity checks before celebrating).

The verify path here is BROADER than src/kryptos/verify.py — it
supports Compose pipelines, FinalCaesar, PositionalRemap,
ColumnarTransposition, Playfair, Bifid, Trifid, Hill, ADFGVX,
WSegmented, and the post_transforms structure the N2 prompt allows.

Usage:
  uv run python scripts/n2_verify.py \
      --hypotheses-dir experiments/results/n2_claude_outputs/run_<ts>_<model>/

Output:
  <hypotheses-dir>/verify_results.jsonl  (one record per hypothesis)
  <hypotheses-dir>/verify_summary.json
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

import numpy as np

from kryptos.alphabets import KRYPTOS_KEYED, KRYPTOS_WITH_EXTRA_L, STANDARD, Alphabet, keyed_alphabet
from kryptos.constants import K4


# Map LM-friendly cipher-class names to actual import paths + factories.
# Sonnet may emit varied capitalisation; we lowercase for matching.

def make_alphabet(name: str | None) -> Alphabet:
    if name is None or name in ("STANDARD", "standard", "A-Z", "az"):
        return STANDARD
    n = name.lower()
    if n in ("kryptos_keyed", "kryptos-keyed", "kryptoskeyed", "kryptos"):
        return KRYPTOS_KEYED
    if "extra" in n or "27" in n:
        return KRYPTOS_WITH_EXTRA_L
    # Treat as keyword
    try:
        return keyed_alphabet(name)
    except Exception:
        return STANDARD


def build_cipher(cls: str, params: dict):
    """Best-effort construction of a Cipher instance from LM-emitted
    name + params dict. Returns None if cls is not supported here."""
    name = cls.lower().strip()
    p = dict(params or {})
    alphabet = make_alphabet(p.pop("alphabet", None) if "alphabet" in p else None)

    from kryptos.ciphers import (
        ADFGVX, Autokey, Beaufort, Bifid, ColumnarTransposition,
        Compose, FinalCaesar, FourSquare, Gromark, Hill, Nicodemus,
        Playfair, PositionalRemap, PrependCaesar, QuagmireI,
        QuagmireII, QuagmireIII, QuagmireIV, RunningKey,
        Trifid, TwoSquare, Vigenere, Vimark, WSegmented,
    )

    try:
        if name in ("vigenere", "vig"):
            return Vigenere(p.pop("key"), alphabet)
        if name in ("beaufort",):
            return Beaufort(p.pop("key"), alphabet)
        if name in ("quagmire1", "quagmirei", "q1"):
            return QuagmireI(p.pop("key"), p.pop("cipher_keyword", "KRYPTOS"),
                             indicator=p.pop("indicator", None))
        if name in ("quagmire2", "quagmireii", "q2"):
            return QuagmireII(p.pop("key"), p.pop("plain_keyword", "KRYPTOS"),
                              indicator=p.pop("indicator", None))
        if name in ("quagmire3", "quagmireiii", "q3"):
            return QuagmireIII(p.pop("key"), p.pop("alphabet_keyword", "KRYPTOS"))
        if name in ("quagmire4", "quagmireiv", "q4"):
            return QuagmireIV(p.pop("key"),
                              p.pop("plain_keyword", "KRYPTOS"),
                              p.pop("cipher_keyword", "ABSCISSA"),
                              indicator=p.pop("indicator", None))
        if name in ("autokey",):
            return Autokey(p.pop("primer"), alphabet,
                           mode=p.pop("mode", "plaintext"))
        if name in ("gromark",):
            return Gromark(p.pop("primer"), p.pop("alphabet_keyword", "KRYPTOS"))
        if name in ("vimark",):
            return Vimark(p.pop("primer"), p.pop("alphabet_keyword", "KRYPTOS"))
        if name in ("runningkey", "running_key", "running"):
            return RunningKey(p.pop("key_text"), alphabet,
                              offset=int(p.pop("offset", 0)))
        if name in ("columnartransposition", "columnar_transposition", "columnar"):
            return ColumnarTransposition(p.pop("keyword"))
        if name in ("playfair",):
            merge = tuple(p.pop("merge", ("I", "J")))
            return Playfair(p.pop("keyword", "KRYPTOS"), merge=merge,
                            filler=p.pop("filler", "X"), alphabet=alphabet)
        if name in ("bifid",):
            merge = tuple(p.pop("merge", ("I", "J")))
            return Bifid(p.pop("keyword", "KRYPTOS"),
                         period=int(p.pop("period", 5)),
                         merge=merge, alphabet=alphabet)
        if name in ("trifid",):
            return Trifid(p.pop("keyword", "KRYPTOS"),
                          period=int(p.pop("period", 5)))
        if name in ("twosquare", "two_square"):
            return TwoSquare(p.pop("top_keyword", "KRYPTOS"),
                             p.pop("bottom_keyword", "ABSCISSA"))
        if name in ("foursquare", "four_square"):
            return FourSquare(p.pop("tr_keyword", "KRYPTOS"),
                              p.pop("bl_keyword", "ABSCISSA"))
        if name in ("adfgvx",):
            return ADFGVX(p.pop("grid_keyword", "KRYPTOS"),
                          p.pop("transposition_keyword", "ABSCISSA"))
        if name in ("hill",):
            mat = p.pop("key_matrix") or p.pop("matrix")
            return Hill(np.array(mat, dtype=int), alphabet)
        if name in ("nicodemus",):
            return Nicodemus(p.pop("keyword"))
        if name in ("compose",):
            inner = []
            for spec in p.pop("stages", []):
                c = build_cipher(spec["cipher_class"], spec.get("params", {}))
                if c is None:
                    return None
                inner.append(c)
            return Compose(inner)
        if name in ("wsegmented", "w_segmented", "w-segmented"):
            inner = []
            for spec in p.pop("ciphers", []):
                c = build_cipher(spec["cipher_class"], spec.get("params", {}))
                if c is None:
                    return None
                inner.append(c)
            return WSegmented(inner, segment_positions=p.pop("segment_positions", None))
        return None
    except Exception:
        return None


def apply_post_transforms(ciphertext: str, transforms: list[dict]) -> str:
    """Apply a list of post-transformation specs (FinalCaesar shift,
    PositionalRemap with perm list, etc.) to a ciphertext string."""
    from kryptos.ciphers import FinalCaesar, PositionalRemap
    out = ciphertext
    for t in transforms or []:
        cls = t.get("cipher_class", "").lower()
        prm = t.get("params", {})
        try:
            if cls in ("finalcaesar", "final_caesar", "caesar"):
                shift = int(prm.get("shift", 0))
                alpha = make_alphabet(prm.get("alphabet"))
                out = "".join(alpha.at((alpha.index(c) + shift) % len(alpha))
                              for c in out)
            elif cls in ("positionalremap", "positional_remap", "remap"):
                perm = prm.get("perm")
                if perm is None or len(perm) != len(out):
                    return out  # bail; bad spec
                out = "".join(out[i] for i in perm)
            elif cls in ("prependcaesar", "prepend_caesar"):
                # Pre-encryption: noop here (applied to plaintext)
                pass
            else:
                # Unknown post-transform
                pass
        except Exception:
            return out
    return out


def is_crib_compliant(plaintext: str) -> bool:
    if len(plaintext) != 97 or not plaintext.isalpha() or not plaintext.isupper():
        return False
    return (plaintext[21:25] == "EAST"
            and plaintext[25:34] == "NORTHEAST"
            and plaintext[63:69] == "BERLIN"
            and plaintext[69:74] == "CLOCK")


def verify_hypothesis(hyp: dict, target: str = K4) -> dict:
    """Returns a result dict with ok=True iff the hypothesis re-encrypts
    its proposed plaintext to K4."""
    cls = hyp.get("cipher_class", "")
    params = hyp.get("params", {}) or {}
    pt = hyp.get("expected_plaintext", "") or ""
    post = hyp.get("post_transforms", [])

    rec = {
        "source_custom_id": hyp.get("_source_custom_id"),
        "cipher_class": cls,
        "crib_compliant": is_crib_compliant(pt),
        "ok": False,
        "error": None,
    }
    if not is_crib_compliant(pt):
        rec["error"] = "plaintext_not_crib_compliant"
        return rec

    cipher = build_cipher(cls, params)
    if cipher is None:
        rec["error"] = "unknown_cipher_class_or_bad_params"
        return rec
    try:
        produced = cipher.encrypt(pt)
        produced = apply_post_transforms(produced, post)
        rec["produced_ciphertext"] = produced
        rec["target_ciphertext"] = target
        # Length-tolerant compare: count matching positions
        L = min(len(produced), len(target))
        n_match = sum(1 for i in range(L) if produced[i] == target[i])
        rec["len_produced"] = len(produced)
        rec["len_target"] = len(target)
        rec["n_match"] = n_match
        rec["ok"] = (produced == target)
    except Exception as e:
        rec["error"] = f"encrypt_failed: {type(e).__name__}: {e}"
    return rec


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--hypotheses-dir", type=Path, required=True,
                   help="N2 run dir containing hypotheses_parsed.jsonl")
    args = p.parse_args()

    hyp_file = args.hypotheses_dir / "hypotheses_parsed.jsonl"
    if not hyp_file.exists():
        sys.stderr.write(f"missing {hyp_file}\n")
        return 1

    hyps = []
    for line in hyp_file.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                hyps.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    print(f"Verifying {len(hyps)} hypotheses against K4 ...")

    results = []
    n_ok = 0
    n_crib_ok = 0
    n_unknown_cls = 0
    n_errored = 0
    best_partial = (-1, None)   # (n_match, rec)
    for h in hyps:
        r = verify_hypothesis(h)
        results.append(r)
        if r.get("crib_compliant"):
            n_crib_ok += 1
        if r.get("ok"):
            n_ok += 1
        if r.get("error") == "unknown_cipher_class_or_bad_params":
            n_unknown_cls += 1
        elif r.get("error"):
            n_errored += 1
        if "n_match" in r and r["n_match"] > best_partial[0]:
            best_partial = (r["n_match"], r)

    out_path = args.hypotheses_dir / "verify_results.jsonl"
    with open(out_path, "w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")

    summary = {
        "n_hypotheses": len(hyps),
        "n_crib_compliant": n_crib_ok,
        "n_solved": n_ok,
        "n_unknown_cls": n_unknown_cls,
        "n_errored": n_errored,
        "best_partial_n_match": best_partial[0],
    }
    (args.hypotheses_dir / "verify_summary.json").write_text(json.dumps(summary, indent=2))

    print()
    print("=== N2 verification summary ===")
    print(f"  hypotheses:           {summary['n_hypotheses']}")
    print(f"  crib-compliant pts:   {summary['n_crib_compliant']}")
    print(f"  SOLVED (byte-exact):  {summary['n_solved']}")
    print(f"  unknown cipher_class: {summary['n_unknown_cls']}")
    print(f"  errors:               {summary['n_errored']}")
    print(f"  best partial match:   {best_partial[0]}/97")
    if best_partial[1]:
        print(f"  best candidate: cipher_class={best_partial[1].get('cipher_class')}, "
              f"produced[0:20]={best_partial[1].get('produced_ciphertext', '')[:20]}...")
    print(f"  output: {out_path}")

    if n_ok:
        print()
        print("=== SOLVED HYPOTHESES ===")
        for r in results:
            if r.get("ok"):
                print(json.dumps(r, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
