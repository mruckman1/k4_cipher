"""Phase-0 regression: prove the library can solve K1 and K2 with the
Gillogly-1999 keys before doing anything else.

If this script ever stops printing the K1 / K2 plaintexts, the library
is broken and no K4 result derived from it should be trusted.

    python experiments/001_baseline_quagmire_iii_K1_K2.py
"""

from __future__ import annotations

from kryptos import (
    K1, K2, K3, K1_PLAINTEXT, K2_PLAINTEXT, K3_PLAINTEXT,
)
from kryptos import constants
from kryptos.ciphers import QuagmireIII, ColumnarTransposition
from kryptos.experiment_logger import ExperimentLogger


def main() -> None:
    constants.assert_lengths()

    with ExperimentLogger("001_baseline_quagmire_iii_K1_K2") as log:
        # --- K1 ---
        q1 = QuagmireIII(key=constants.K1_KEY,
                         alphabet_keyword=constants.K1_ALPHABET_KEYWORD)
        k1_plain = q1.decrypt(K1)
        ok1 = k1_plain == K1_PLAINTEXT
        log.write({"section": "K1", "key": constants.K1_KEY, "ok": ok1,
                   "plaintext": k1_plain})
        print(f"K1 ({'OK ' if ok1 else 'FAIL'}): {k1_plain}")
        assert ok1, "K1 decrypt does not match expected plaintext"

        # --- K2 ---
        q2 = QuagmireIII(key=constants.K2_KEY,
                         alphabet_keyword=constants.K2_ALPHABET_KEYWORD)
        k2_plain = q2.decrypt(K2)
        ok2 = k2_plain == K2_PLAINTEXT
        log.write({"section": "K2", "key": constants.K2_KEY, "ok": ok2,
                   "plaintext": k2_plain})
        print(f"K2 ({'OK ' if ok2 else 'FAIL'}): {k2_plain[:64]}...")
        assert ok2, "K2 decrypt does not match expected plaintext"

        # --- K3 (single columnar pass with KRYPTOS column ordering) ---
        # NOTE: K3 is a two-pass transposition in the canonical solution;
        # this single-pass illustration is wrong by design and is logged
        # as a regression placeholder. Implement the second pass before
        # claiming K3 is "solved" by the library.
        t3 = ColumnarTransposition(constants.K3_COLUMN_ORDER)
        k3_plain_partial = t3.decrypt(K3[: 7 * (len(K3) // 7)])
        log.write({"section": "K3", "note": "single-pass; partial",
                   "first_64": k3_plain_partial[:64]})
        print(f"K3 (single-pass partial): {k3_plain_partial[:64]}...")

        # Cross-check encrypt(decrypt(x)) == x for K1 and K2 (sanity).
        assert q1.encrypt(K1_PLAINTEXT) == K1
        assert q2.encrypt(K2_PLAINTEXT) == K2
        log.write({"event": "encrypt_decrypt_roundtrip", "ok": True})


if __name__ == "__main__":
    main()
