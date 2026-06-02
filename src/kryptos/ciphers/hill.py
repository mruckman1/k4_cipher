"""Hill cipher (matrix encryption over Z_N).

K4 length 97 is prime, so straight 2x2 or 3x3 Hill cannot be applied
without padding -- and the matrix-encryption conjecture (Bauer, Link,
Molle, *Cryptologia* 2016) was exhaustively brute-forced over 2x2 and 3x3
matrices in both standard and KRYPTOS-keyed index spaces with negative
result. Implementation here is for completeness and for cross-checking
those negative results.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from kryptos.alphabets import STANDARD, Alphabet
from kryptos.ciphers.base import Cipher

if TYPE_CHECKING:
    import numpy as np


def _np():
    """Lazy numpy import. Hill is the only cipher that needs numpy; keep
    the rest of the library importable on environments without it."""
    import numpy as np
    return np


def _modinv(a: int, m: int) -> int:
    """Modular inverse of `a` mod `m`, via extended Euclidean."""
    a %= m
    if a == 0:
        raise ValueError("0 has no modular inverse")
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError(f"{a} has no inverse mod {m} (gcd={g})")
    return x % m


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def matrix_inverse_mod(M, m: int):
    """Inverse of integer matrix `M` modulo `m`. Raises if not invertible."""
    np = _np()
    n = M.shape[0]
    det = int(round(np.linalg.det(M))) % m
    det_inv = _modinv(det, m)
    # Cofactor / adjugate.
    cof = np.zeros_like(M)
    for i in range(n):
        for j in range(n):
            minor = np.delete(np.delete(M, i, axis=0), j, axis=1)
            cof[i, j] = ((-1) ** (i + j)) * int(round(np.linalg.det(minor)))
    adj = cof.T % m
    return (det_inv * adj) % m


class Hill(Cipher):
    def __init__(self, key_matrix, alphabet: Alphabet = STANDARD) -> None:
        super().__init__(alphabet)
        np = _np()
        if key_matrix.ndim != 2 or key_matrix.shape[0] != key_matrix.shape[1]:
            raise ValueError("Hill key must be a square matrix")
        self.K = (key_matrix.astype(int) % len(alphabet))
        self.block = self.K.shape[0]
        # Validate invertibility for decryption.
        self.K_inv = matrix_inverse_mod(self.K, len(alphabet))

    def _blocks(self, text: str):
        np = _np()
        if len(text) % self.block != 0:
            raise ValueError(
                f"text length {len(text)} is not a multiple of block size {self.block}"
            )
        idx = np.array(self.alphabet.encode(text), dtype=int)
        return idx.reshape(-1, self.block)

    def encrypt(self, plaintext: str) -> str:
        self._validate(plaintext, "plaintext")
        b = self._blocks(plaintext)
        out = (b @ self.K) % len(self.alphabet)
        return self.alphabet.decode(out.flatten().tolist())

    def decrypt(self, ciphertext: str) -> str:
        self._validate(ciphertext, "ciphertext")
        b = self._blocks(ciphertext)
        out = (b @ self.K_inv) % len(self.alphabet)
        return self.alphabet.decode(out.flatten().tolist())
