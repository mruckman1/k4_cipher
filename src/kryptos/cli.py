"""kryptos: small CLI for one-off cipher operations.

Examples:

    kryptos decrypt --cipher quagmire3 --key PALIMPSEST --alphabet-keyword KRYPTOS \\
        --text "$(cat data/ciphertexts/k1.txt)"

    kryptos solve --cipher gromark --primer 23917 --alphabet-keyword KRYPTOS \\
        --text "$(cat data/ciphertexts/k4.txt)"

    kryptos analyse --text "$(cat data/ciphertexts/k4.txt)"

Subcommands intentionally mirror the library surface: every cipher class
exposed in `kryptos.ciphers` is reachable as `--cipher <name>`. Keep this
file thin -- when a workflow grows beyond one or two flags, give it its
own experiments/ script instead.
"""

from __future__ import annotations

import argparse
import sys

from kryptos import constants
from kryptos.alphabets import STANDARD, keyed_alphabet
from kryptos.analysis import friedman_key_length, index_of_coincidence
from kryptos.ciphers import (
    Autokey,
    Beaufort,
    Gromark,
    QuagmireIII,
    RunningKey,
    Vigenere,
    Vimark,
)
from kryptos.utils import clean
from kryptos.verify import parse_params, verify


def _build_cipher(args: argparse.Namespace):
    name = args.cipher
    if name == "vigenere":
        alpha = (
            keyed_alphabet(args.alphabet_keyword) if args.alphabet_keyword else STANDARD
        )
        return Vigenere(args.key, alpha)
    if name == "quagmire3":
        return QuagmireIII(args.key, args.alphabet_keyword or "KRYPTOS")
    if name == "beaufort":
        alpha = (
            keyed_alphabet(args.alphabet_keyword) if args.alphabet_keyword else STANDARD
        )
        return Beaufort(args.key, alpha)
    if name == "autokey":
        alpha = (
            keyed_alphabet(args.alphabet_keyword) if args.alphabet_keyword else STANDARD
        )
        return Autokey(args.primer, alpha, mode=args.autokey_mode)
    if name == "gromark":
        return Gromark(args.primer, args.alphabet_keyword or "KRYPTOS")
    if name == "vimark":
        return Vimark(args.primer, args.alphabet_keyword or "KRYPTOS")
    if name == "running":
        return RunningKey(args.key_text, STANDARD, offset=args.offset)
    raise SystemExit(f"unknown cipher: {name}")


def _cmd_encrypt(args: argparse.Namespace) -> None:
    cipher = _build_cipher(args)
    print(cipher.encrypt(clean(args.text)))


def _cmd_decrypt(args: argparse.Namespace) -> None:
    cipher = _build_cipher(args)
    print(cipher.decrypt(clean(args.text)))


def _cmd_analyse(args: argparse.Namespace) -> None:
    text = clean(args.text)
    print(f"length: {len(text)}")
    print(f"ioc:    {index_of_coincidence(text):.4f}")
    print(f"friedman key length estimate: {friedman_key_length(text):.2f}")


def _cmd_constants(_: argparse.Namespace) -> None:
    constants.assert_lengths()
    for name in ("K1", "K2", "K3", "K4"):
        print(f"{name} ({len(getattr(constants, name))}): {getattr(constants, name)}")


def _cmd_verify(args: argparse.Namespace) -> int:
    params = parse_params(args.params or "")
    result = verify(
        cipher=args.cipher,
        params=params,
        plaintext=clean(args.plaintext),
        target_ciphertext=clean(args.target),
    )
    print(result.diff_report(max_show=args.show_diffs))
    return 0 if result.ok else 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kryptos")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_cipher_flags(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--cipher", required=True,
                        choices=["vigenere", "quagmire3", "beaufort", "autokey",
                                 "gromark", "vimark", "running"])
        sp.add_argument("--key")
        sp.add_argument("--primer")
        sp.add_argument("--alphabet-keyword", default=None)
        sp.add_argument("--autokey-mode", default="plaintext",
                        choices=["plaintext", "ciphertext"])
        sp.add_argument("--key-text", help="full running-key text")
        sp.add_argument("--offset", type=int, default=0)
        sp.add_argument("--text", required=True)

    se = sub.add_parser("encrypt"); add_cipher_flags(se); se.set_defaults(fn=_cmd_encrypt)
    sd = sub.add_parser("decrypt"); add_cipher_flags(sd); sd.set_defaults(fn=_cmd_decrypt)

    sa = sub.add_parser("analyse")
    sa.add_argument("--text", required=True)
    sa.set_defaults(fn=_cmd_analyse)

    sc = sub.add_parser("constants")
    sc.set_defaults(fn=_cmd_constants)

    sv = sub.add_parser("verify",
                        help="Re-encrypt a claimed plaintext and byte-compare against target.")
    sv.add_argument("--cipher", required=True,
                    help="cipher class name (lowercase): vigenere, quagmire3, gromark, ...")
    sv.add_argument("--params", default="",
                    help="comma-separated key=value (e.g. 'key=PALIMPSEST,alphabet_keyword=KRYPTOS')")
    sv.add_argument("--plaintext", required=True, help="claimed plaintext")
    sv.add_argument("--target", required=True, help="target ciphertext (e.g. K4)")
    sv.add_argument("--show-diffs", type=int, default=10,
                    help="number of differing positions to print")
    sv.set_defaults(fn=_cmd_verify)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    rc = args.fn(args)
    return rc if isinstance(rc, int) else 0


if __name__ == "__main__":
    sys.exit(main())
