"""K4nundrum W-partition + alternating-key Quagmire III.

The glthr 2024 observation: splitting K4 at the six W's yields two
alternating groups with identical letter-frequency *shapes* (p<0.0004 on
random permutations). One natural cipher hypothesis is that the two
groups were encrypted with *different* keys under the same Quagmire III
construction, interleaved at the W boundaries.

This script enumerates small key pairs (length up to L_MAX) and tests
each pair against the four cribs. The cribs map cleanly onto positions
within each partition because the W-split is purely positional.

Caveat: with L_MAX=4 and the KRYPTOS-keyed alphabet this is ~26^8 ~ 2e11
key pairs -- too many for brute. The script is set up for a quick
demonstration with L_MAX=2 (~26^4 ~ 460k) so the harness runs in
seconds; tune L_MAX upward once you replace the brute body with a
hill-climber from `kryptos.solvers.hill_climber`.
"""

from __future__ import annotations

from itertools import product

from kryptos import K4
from kryptos.alphabets import keyed_alphabet
from kryptos.analysis.partitions import w_partition
from kryptos.ciphers.quagmire import QuagmireIII
from kryptos.cribs import CRIBS
from kryptos.experiment_logger import ExperimentLogger
from kryptos.scoring.crib_check import crib_check

L_MAX = 2


def _interleave_back(orig: str, a_plain: str, b_plain: str) -> str:
    """Reverse of w_partition: rebuild a length-len(orig) plaintext from
    the two partition plaintexts, walking the original to choose which
    plaintext stream to draw from at each step."""
    out: list[str] = []
    ai = bi = 0
    target = "a"
    for c in orig:
        if target == "a":
            out.append(a_plain[ai]); ai += 1
        else:
            out.append(b_plain[bi]); bi += 1
        if c == "W":
            target = "b" if target == "a" else "a"
    return "".join(out)


def main() -> None:
    a_cipher, b_cipher = w_partition(K4)
    alpha = keyed_alphabet("KRYPTOS")
    with ExperimentLogger("004_w_partition_dual_key") as log:
        log.write({"event": "partition", "a_len": len(a_cipher), "b_len": len(b_cipher)})
        print(f"W-partition: |A|={len(a_cipher)}, |B|={len(b_cipher)}")

        tried = 0
        for la in range(1, L_MAX + 1):
            for lb in range(1, L_MAX + 1):
                for ka in product(alpha.letters, repeat=la):
                    for kb in product(alpha.letters, repeat=lb):
                        tried += 1
                        ka_s, kb_s = "".join(ka), "".join(kb)
                        a_plain = QuagmireIII(ka_s, "KRYPTOS").decrypt(a_cipher)
                        b_plain = QuagmireIII(kb_s, "KRYPTOS").decrypt(b_cipher)
                        plain = _interleave_back(K4, a_plain, b_plain)
                        if crib_check(plain, CRIBS):
                            log.write({
                                "kind": "survivor",
                                "key_a": ka_s, "key_b": kb_s,
                                "plaintext": plain,
                            })
                            print(f"survivor: A={ka_s}, B={kb_s}\n  {plain}")
        log.write({"kind": "summary", "tried": tried})
        print(f"tried {tried} key pairs at L_MAX={L_MAX}")


if __name__ == "__main__":
    main()
