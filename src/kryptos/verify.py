"""kryptos.verify -- the single canonical definition of "solved".

Every public K4 "solution" to date has failed independent reverse-
encryption (Thompson 2010, Coomer, Naughton/Grok, Klepp, Lacy, Avelar
ZETA, Bonifacino). This module is the test that turns a *claim* into
an *artifact*:

    Given (cipher_class, params, claimed_plaintext, target_ciphertext),
    re-instantiate the cipher with those params, encrypt the claimed
    plaintext, and assert byte-for-byte equality with target_ciphertext.

If `verify(...)` returns True, the plaintext + params *necessarily*
produce the ciphertext under the stated cipher. That is the only
acceptable definition of "K4 solved" in this codebase -- the absence of
a passing verify() means the claim is not solved, regardless of how
English-like the candidate text looks.

Use from a script:

    from kryptos.verify import verify, VerifyResult
    result = verify(
        cipher="quagmire3",
        params={"key": "PALIMPSEST", "alphabet_keyword": "KRYPTOS"},
        plaintext="BETWEEN...",
        target_ciphertext=K1,
    )
    assert result.ok

Or from the CLI:

    kryptos verify --cipher quagmire3 \\
      --params 'key=PALIMPSEST,alphabet_keyword=KRYPTOS' \\
      --plaintext "$(cat data/plaintexts/k1.txt)" \\
      --target "$(cat data/ciphertexts/k1.txt)"
"""

from __future__ import annotations

from dataclasses import dataclass

from kryptos.alphabets import STANDARD, keyed_alphabet
from kryptos.ciphers import (
    Autokey,
    Beaufort,
    Cipher,
    Gromark,
    QuagmireI,
    QuagmireII,
    QuagmireIII,
    QuagmireIV,
    RunningKey,
    Vigenere,
    Vimark,
)


@dataclass
class VerifyResult:
    """Result of a verify() call.

    `ok` is the only thing a downstream check should branch on; the other
    fields are for diagnostics (showing the user *where* a claim diverged
    from the target ciphertext).
    """

    ok: bool
    cipher: str
    params: dict
    produced_ciphertext: str
    target_ciphertext: str
    first_diff_position: int | None  # 0-indexed; None iff ok
    num_diff_positions: int

    def diff_report(self, max_show: int = 5) -> str:
        if self.ok:
            return f"VERIFIED: produced ciphertext matches target ({len(self.target_ciphertext)} chars)."
        lines = [
            f"NOT VERIFIED: {self.num_diff_positions} positions differ "
            f"(first at {self.first_diff_position})."
        ]
        diffs = [
            (i, p, t)
            for i, (p, t) in enumerate(zip(self.produced_ciphertext, self.target_ciphertext))
            if p != t
        ]
        for i, p, t in diffs[:max_show]:
            lines.append(f"  pos {i}: produced={p!r}, target={t!r}")
        if len(diffs) > max_show:
            lines.append(f"  ... and {len(diffs) - max_show} more")
        return "\n".join(lines)


def build_cipher(cipher: str, params: dict) -> Cipher:
    """Instantiate one of the cipher classes by name + params dict.

    Recognised cipher names match `kryptos.ciphers.__all__` (lowercase):
    vigenere, quagmire1, quagmire2, quagmire3, quagmire4, beaufort,
    autokey, gromark, vimark, running.

    `params` keys are the kwarg names of the matching class. Unknown
    cipher names raise ValueError so a typo in a claim never silently
    matches the wrong cipher.
    """
    name = cipher.lower()
    p = dict(params)  # copy; we mutate

    def _alpha(default_keyword: str | None = None):
        kw = p.pop("alphabet_keyword", default_keyword)
        return keyed_alphabet(kw) if kw else STANDARD

    if name == "vigenere":
        return Vigenere(p.pop("key"), _alpha())
    if name == "quagmire1":
        return QuagmireI(p.pop("key"), p.pop("cipher_keyword"),
                         indicator=p.pop("indicator", "A"))
    if name == "quagmire2":
        return QuagmireII(p.pop("key"), p.pop("plain_keyword"),
                          indicator=p.pop("indicator", "A"))
    if name == "quagmire3":
        return QuagmireIII(p.pop("key"), p.pop("alphabet_keyword", "KRYPTOS"))
    if name == "quagmire4":
        return QuagmireIV(p.pop("key"), p.pop("plain_keyword"),
                          p.pop("cipher_keyword"),
                          indicator=p.pop("indicator", "A"))
    if name == "beaufort":
        return Beaufort(p.pop("key"), _alpha())
    if name == "autokey":
        return Autokey(p.pop("primer"), _alpha(),
                       mode=p.pop("mode", "plaintext"))
    if name == "gromark":
        return Gromark(p.pop("primer"), p.pop("alphabet_keyword", "KRYPTOS"))
    if name == "vimark":
        return Vimark(p.pop("primer"), p.pop("alphabet_keyword", "KRYPTOS"))
    if name == "running":
        return RunningKey(p.pop("key_text"), STANDARD,
                          offset=int(p.pop("offset", 0)))
    raise ValueError(f"unknown cipher: {cipher!r}")


def verify(
    cipher: str,
    params: dict,
    plaintext: str,
    target_ciphertext: str,
) -> VerifyResult:
    """Re-encrypt `plaintext` with the named cipher + params and compare
    byte-for-byte against `target_ciphertext`."""
    c = build_cipher(cipher, params)
    produced = c.encrypt(plaintext)
    diffs = [i for i, (p, t) in enumerate(zip(produced, target_ciphertext)) if p != t]
    # Length mismatch is a divergence too -- count the tail.
    if len(produced) != len(target_ciphertext):
        tail = abs(len(produced) - len(target_ciphertext))
        first = len(produced) if len(produced) < len(target_ciphertext) else len(target_ciphertext)
        diffs.extend(range(first, first + tail))
    return VerifyResult(
        ok=(len(diffs) == 0),
        cipher=cipher,
        params=params,
        produced_ciphertext=produced,
        target_ciphertext=target_ciphertext,
        first_diff_position=diffs[0] if diffs else None,
        num_diff_positions=len(diffs),
    )


def parse_params(spec: str) -> dict:
    """Parse a CLI param spec like 'key=PALIMPSEST,alphabet_keyword=KRYPTOS'
    into a dict. Values are kept as strings; build_cipher() casts."""
    if not spec:
        return {}
    out: dict[str, str] = {}
    for kv in spec.split(","):
        if "=" not in kv:
            raise ValueError(f"bad params spec entry: {kv!r} (expected key=value)")
        k, v = kv.split("=", 1)
        out[k.strip()] = v.strip()
    return out
