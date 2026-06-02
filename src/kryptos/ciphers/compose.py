"""Composable cipher pipelines + Sanborn-modification primitives.

Sanborn explicitly told Wired (2005) that he modified Scheidt's classical
system. To attack those modifications, we need to chain a classical
cipher with one or more small perturbation layers (a final Caesar, a
positional remap, a column transposition) without rewriting each
combination as a new monolithic class.

The `Compose` class chains any sequence of objects that implement the
`Cipher` interface. Encryption applies each layer in order; decryption
applies inverses in reverse order.

The modifier primitives are intentionally tiny -- each one is the kind
of "one perturbation at a time" you would add per Sanborn's hint. Add
exactly one at a time; the combinatorics explode if you stack two
unknown perturbations simultaneously.

Examples:

    # Quagmire III, then a final Caesar shift of 3 over A-Z.
    pipeline = Compose([
        QuagmireIII(key="ABSCISSA", alphabet_keyword="KRYPTOS"),
        FinalCaesar(shift=3, alphabet=STANDARD),
    ])
    ct = pipeline.encrypt(plaintext)

    # Positional remap (e.g. swap every other pair) then Vigenere.
    pipeline = Compose([
        PositionalRemap(perm=[1, 0, 3, 2, 5, 4, ...]),
        Vigenere(key="DYAHR", alphabet=KRYPTOS_KEYED),
    ])
"""

from __future__ import annotations

from collections.abc import Sequence

from kryptos.alphabets import STANDARD, Alphabet
from kryptos.ciphers.base import Cipher


class Compose(Cipher):
    """Apply a sequence of ciphers in order. encrypt = layer_1 . layer_2 . ...,
    decrypt = layer_N^{-1} . layer_{N-1}^{-1} . ... . layer_1^{-1}.

    All layers must operate over the same alphabet; the first layer's
    alphabet defines the pipeline's alphabet.
    """

    def __init__(self, layers: Sequence[Cipher]) -> None:
        if not layers:
            raise ValueError("Compose needs at least one layer")
        super().__init__(layers[0].alphabet)
        for i, layer in enumerate(layers[1:], start=1):
            if len(layer.alphabet) != len(self.alphabet):
                raise ValueError(
                    f"layer {i} alphabet size {len(layer.alphabet)} "
                    f"!= layer 0 alphabet size {len(self.alphabet)}"
                )
        self.layers = list(layers)

    def encrypt(self, plaintext: str) -> str:
        text = plaintext
        for layer in self.layers:
            text = layer.encrypt(text)
        return text

    def decrypt(self, ciphertext: str) -> str:
        text = ciphertext
        for layer in reversed(self.layers):
            text = layer.decrypt(text)
        return text

    def __repr__(self) -> str:
        return f"Compose([{', '.join(repr(l) for l in self.layers)}])"


class FinalCaesar(Cipher):
    """Caesar shift by `shift` positions in `alphabet`.

    Standalone usage is a Caesar cipher; the intended use is as the LAST
    layer of a Compose pipeline -- a tiny additional shift Sanborn might
    have applied after the main substitution. K4's anomalously aperiodic
    shift pattern across the cribs is consistent with a per-position
    keystream, but a global +k after a periodic Quagmire III is one of
    the simplest "Sanborn modifications" worth ruling out cheaply.
    """

    def __init__(self, shift: int, alphabet: Alphabet = STANDARD) -> None:
        super().__init__(alphabet)
        self.shift = shift % len(alphabet)

    def encrypt(self, plaintext: str) -> str:
        self._validate(plaintext, "plaintext")
        at = self.alphabet.at
        ai = self.alphabet.index
        s = self.shift
        return "".join(at(ai(c) + s) for c in plaintext)

    def decrypt(self, ciphertext: str) -> str:
        self._validate(ciphertext, "ciphertext")
        at = self.alphabet.at
        ai = self.alphabet.index
        s = self.shift
        return "".join(at(ai(c) - s) for c in ciphertext)


class PrependCaesar(FinalCaesar):
    """Caesar shift intended as the FIRST layer of a Compose pipeline.

    Functionally identical to FinalCaesar but kept as a separate class
    so experiment scripts and JSONL logs record *intent* -- "this was a
    pre-substitution shift" vs. "this was a post-substitution shift" --
    and so future-you knows which kind of modification you were testing.
    """


class PositionalRemap(Cipher):
    """Permute positions according to `perm`.

    `perm` is a length-N permutation of [0..N-1]; encrypted text at
    position `i` comes from plaintext at position `perm[i]` (the standard
    "where each output letter comes from" form). Decryption inverts the
    permutation.

    Use cases:
      - Swap-every-other-pair: perm=[1,0,3,2,5,4,...].
      - K3-style transposition layered before/after a polyalphabetic.
      - Arbitrary stencil/grille rearrangements.

    PositionalRemap operates on inputs of length len(perm); shorter or
    longer inputs raise. For inputs longer than perm (e.g. apply a
    period-N remap across a longer text) use `Tiled(PositionalRemap(...))`
    -- not yet built; add when needed.
    """

    def __init__(self, perm: Sequence[int], alphabet: Alphabet = STANDARD) -> None:
        super().__init__(alphabet)
        perm = list(perm)
        n = len(perm)
        if sorted(perm) != list(range(n)):
            raise ValueError(
                f"perm must be a permutation of 0..{n-1}, got {perm}"
            )
        self.perm = perm
        # Inverse permutation for decryption.
        self.inv = [0] * n
        for i, p in enumerate(perm):
            self.inv[p] = i

    def encrypt(self, plaintext: str) -> str:
        self._validate(plaintext, "plaintext")
        if len(plaintext) != len(self.perm):
            raise ValueError(
                f"PositionalRemap expects length {len(self.perm)}, "
                f"got {len(plaintext)}"
            )
        return "".join(plaintext[self.perm[i]] for i in range(len(self.perm)))

    def decrypt(self, ciphertext: str) -> str:
        self._validate(ciphertext, "ciphertext")
        if len(ciphertext) != len(self.inv):
            raise ValueError(
                f"PositionalRemap expects length {len(self.inv)}, "
                f"got {len(ciphertext)}"
            )
        return "".join(ciphertext[self.inv[i]] for i in range(len(self.inv)))
