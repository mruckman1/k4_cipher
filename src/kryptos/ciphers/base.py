"""Abstract base class for every cipher in this library.

Each concrete cipher stores its parameters in the constructor (alphabet,
key, primer, ...) and exposes pure `encrypt` and `decrypt` methods. Inputs
and outputs are uppercase-letter-only strings drawn from `self.alphabet`.

Keeping the interface this narrow means:
  - the same `crib_check` works against any cipher
  - solvers can swap cipher classes without touching their fitness functions
  - inner hot loops can reach into the underlying numpy arrays directly
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from kryptos.alphabets import STANDARD, Alphabet
from kryptos.utils import assert_clean


class Cipher(ABC):
    """Subclasses must implement `encrypt` and `decrypt`."""

    def __init__(self, alphabet: Alphabet = STANDARD) -> None:
        self.alphabet = alphabet

    @abstractmethod
    def encrypt(self, plaintext: str) -> str:
        """Encrypt `plaintext` (must contain only letters from `self.alphabet`)."""

    @abstractmethod
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt `ciphertext` (must contain only letters from `self.alphabet`)."""

    def _validate(self, text: str, label: str) -> None:
        assert_clean(text, label)
        bad = [c for c in text if not self.alphabet.contains(c)]
        if bad:
            raise ValueError(
                f"{label} contains letters not in alphabet {self.alphabet.name}: "
                f"{sorted(set(bad))}"
            )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(alphabet={self.alphabet.name!r})"
