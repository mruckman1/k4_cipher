"""Quagmire I-IV.

Variants differ in which alphabets are keyed:

    Quagmire I:   standard plaintext, keyed ciphertext, period-N key
    Quagmire II:  keyed plaintext,    standard cipher,  period-N key
    Quagmire III: keyed plaintext,    same keyed cipher, period-N key
    Quagmire IV:  keyed plaintext,    different keyed cipher, period-N key

In all four, the indicator-letter convention picks where on the cipher row
the period-key letter lines up under the plaintext-row indicator.

For K1 and K2 (Quagmire III, both alphabets keyed by KRYPTOS), the tableau
reduces to Vigenere performed in the keyed-alphabet index space. We
implement Quagmire III in that explicit form because it is correct and
because the alternative (constructing 26 rows of the tableau) is slower
and obscures the shift math we actually need for solvers.

The general Quagmire (I, II, IV) implementation here uses the row-shift
formulation explicitly so it stays correct when the plaintext and cipher
alphabets differ.
"""

from __future__ import annotations

from kryptos.alphabets import KRYPTOS_KEYED, STANDARD, Alphabet, keyed_alphabet
from kryptos.ciphers.base import Cipher
from kryptos.utils import repeat_to_length


def _row_for_quagmire(
    plain_alpha: Alphabet,
    cipher_alpha: Alphabet,
    key_letter: str,
    indicator: str,
) -> str:
    """Build the cipher-row of length N for a Quagmire tableau.

    The row is the cipher alphabet cyclically shifted so that the key
    letter falls under the indicator letter of the plaintext alphabet.
    """
    n = len(plain_alpha)
    if n != len(cipher_alpha):
        raise ValueError("plain and cipher alphabets must be the same length")
    ind_pos = plain_alpha.index(indicator)
    key_pos_in_cipher = cipher_alpha.index(key_letter)
    shift = (key_pos_in_cipher - ind_pos) % n
    return cipher_alpha.letters[shift:] + cipher_alpha.letters[:shift]


class _QuagmireBase(Cipher):
    def __init__(
        self,
        key: str,
        plain_alphabet: Alphabet,
        cipher_alphabet: Alphabet,
        indicator: str | None = None,
    ) -> None:
        super().__init__(plain_alphabet)
        self.plain_alphabet = plain_alphabet
        self.cipher_alphabet = cipher_alphabet
        # Default indicator: first letter of the cipher alphabet.
        # This matches Sanborn's K1/K2 convention (the cipher alphabet
        # row for key letter K is the alphabet shifted left by idx_K,
        # giving the Vigenere-in-keyed-space formula). The ACA-standard
        # default of 'A' produces DIFFERENT ciphertext on K1/K2 -- see
        # the QuagmireIV-vs-QuagmireIII regression check in tests.
        if indicator is None:
            indicator = cipher_alphabet.letters[0]
        self.indicator = indicator
        key = key.upper()
        bad = [c for c in key if not plain_alphabet.contains(c)]
        if bad:
            raise ValueError(f"key letters {sorted(set(bad))} not in plain alphabet")
        self.key = key
        # Precompute the cipher row for every key letter.
        self._rows = [
            _row_for_quagmire(plain_alphabet, cipher_alphabet, k, indicator)
            for k in key
        ]

    def encrypt(self, plaintext: str) -> str:
        self._validate_plain(plaintext)
        out = []
        for i, p in enumerate(plaintext):
            row = self._rows[i % len(self._rows)]
            out.append(row[self.plain_alphabet.index(p)])
        return "".join(out)

    def decrypt(self, ciphertext: str) -> str:
        self._validate_cipher(ciphertext)
        out = []
        for i, c in enumerate(ciphertext):
            row = self._rows[i % len(self._rows)]
            out.append(self.plain_alphabet.letters[row.index(c)])
        return "".join(out)

    def _validate_plain(self, text: str) -> None:
        bad = [c for c in text if not self.plain_alphabet.contains(c)]
        if bad:
            raise ValueError(f"plaintext contains non-alphabet letters: {sorted(set(bad))}")

    def _validate_cipher(self, text: str) -> None:
        bad = [c for c in text if not self.cipher_alphabet.contains(c)]
        if bad:
            raise ValueError(f"ciphertext contains non-alphabet letters: {sorted(set(bad))}")


class QuagmireI(_QuagmireBase):
    """Standard plaintext alphabet, keyed cipher alphabet."""

    def __init__(self, key: str, cipher_keyword: str, indicator: str | None = None) -> None:
        super().__init__(
            key=key,
            plain_alphabet=STANDARD,
            cipher_alphabet=keyed_alphabet(cipher_keyword, STANDARD),
            indicator=indicator,
        )


class QuagmireII(_QuagmireBase):
    """Keyed plaintext alphabet, standard cipher alphabet."""

    def __init__(self, key: str, plain_keyword: str, indicator: str | None = None) -> None:
        super().__init__(
            key=key,
            plain_alphabet=keyed_alphabet(plain_keyword, STANDARD),
            cipher_alphabet=STANDARD,
            indicator=indicator,
        )


class QuagmireIII(Cipher):
    """Keyed plaintext alphabet == keyed cipher alphabet.

    Fast-path implementation: Quagmire III with matching alphabets is
    equivalent to Vigenere performed in keyed-alphabet index space. This
    is the cipher behind K1 and K2.
    """

    def __init__(
        self,
        key: str,
        alphabet_keyword: str = "KRYPTOS",
        base_alphabet: Alphabet = STANDARD,
    ) -> None:
        alphabet = keyed_alphabet(alphabet_keyword, base_alphabet)
        super().__init__(alphabet)
        key = key.upper()
        bad = [c for c in key if not alphabet.contains(c)]
        if bad:
            raise ValueError(f"key letters {sorted(set(bad))} not in keyed alphabet")
        self.key = key
        self.alphabet_keyword = alphabet_keyword
        self._key_idx = alphabet.encode(key)

    def encrypt(self, plaintext: str) -> str:
        self._validate(plaintext, "plaintext")
        n = len(self.alphabet)
        key = repeat_to_length(self.key, len(plaintext))
        ai = self.alphabet.index
        at = self.alphabet.at
        return "".join(at(ai(p) + ai(k)) for p, k in zip(plaintext, key))

    def decrypt(self, ciphertext: str) -> str:
        self._validate(ciphertext, "ciphertext")
        n = len(self.alphabet)
        key = repeat_to_length(self.key, len(ciphertext))
        ai = self.alphabet.index
        at = self.alphabet.at
        return "".join(at(ai(c) - ai(k)) for c, k in zip(ciphertext, key))


class QuagmireIV(_QuagmireBase):
    """Keyed plaintext alphabet, *different* keyed cipher alphabet.

    Supports direct alphabet objects (for 27-letter sculpture variants)
    via the from_alphabets() classmethod.
    """

    def __init__(
        self,
        key: str,
        plain_keyword: str,
        cipher_keyword: str,
        indicator: str | None = None,
    ) -> None:
        super().__init__(
            key=key,
            plain_alphabet=keyed_alphabet(plain_keyword, STANDARD),
            cipher_alphabet=keyed_alphabet(cipher_keyword, STANDARD),
            indicator=indicator,
        )

    @classmethod
    def from_alphabets(
        cls,
        key: str,
        plain_alphabet: Alphabet,
        cipher_alphabet: Alphabet,
        indicator: str | None = None,
    ) -> "_QuagmireBase":
        """Construct a Quagmire IV from explicit alphabet objects.

        Use this for experiments that need non-standard alphabets
        (e.g. the 27-letter doubled-L sculpture variant, or a reversed
        alphabet)."""
        instance = cls.__new__(cls)
        _QuagmireBase.__init__(
            instance, key=key,
            plain_alphabet=plain_alphabet, cipher_alphabet=cipher_alphabet,
            indicator=indicator,
        )
        return instance
