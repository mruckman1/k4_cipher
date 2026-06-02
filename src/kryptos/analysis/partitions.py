"""K4nundrum-style partition analysis.

The K4nundrum observation (glthr, 2024): splitting K4 at the six W's yields
two alternating groups with identical letter-frequency *shapes*. <0.04% of
random permutations of K4 exhibit this -- statistically significant,
suggests structured dual-key encryption interleaved on the two groups.

`w_partition` performs the W-split; `partition_at` is the general
single-letter split for trying other letters as boundary markers.
"""

from __future__ import annotations


def partition_at(text: str, boundary: str) -> tuple[str, str]:
    """Split `text` into two alternating groups, switching group every
    time the boundary letter is encountered. The boundary letter itself
    is kept in the *current* group before the switch.

    Example with boundary='W':
        text   = "AAWBBWCC"
        groups = ("AAW", "BBWCC")  # groups alternate at every W
    """
    if len(boundary) != 1:
        raise ValueError("boundary must be a single letter")
    a: list[str] = []
    b: list[str] = []
    target = a
    for c in text:
        target.append(c)
        if c == boundary:
            target = b if target is a else a
    return "".join(a), "".join(b)


def w_partition(text: str) -> tuple[str, str]:
    """The K4nundrum W-partition."""
    return partition_at(text, "W")
