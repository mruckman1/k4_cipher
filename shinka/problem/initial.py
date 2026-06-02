"""Per-position alphabet selection cipher for K4 — Run C focused test
of the K=5 W-segment hypothesis.

K and selection_rule are LOCKED outside the EVOLVE-BLOCK. The LLM
mutates only:
  - FREE_LETTERS: alphabet ordering per color (5 colors at K=5)
  - MODIFICATIONS: optional per-color cipher modification

The fitness function runs external SA on FREE_LETTERS per evaluation.

Background:
  - Run A (gen 66, $20): K=4 + Prior A default rule plateaued at 48.10
    (with old fitness using per_partition × 15)
  - Run B v2 (gen 1, $5): K=5 W-segment rule reached 57.29 (gen 1) and
    58.15 (gen 9 at K=6) — but the gain was artifactual, from the
    per_partition × 15 term being inflated at smaller partitions
  - Fitness fix applied (per_partition × 15 → × 5): under honest
    fitness, the K=4 seed scores 63.10 and the K=5 W-segment scores
    58.75. K=4 is genuinely better.
  - Run C tests whether K=5 W-segment has unexplored alphabet headroom
    under HONEST fitness. If K=5 with focused SA + LLM-proposed
    alphabet hypotheses can break 65, the hypothesis is competitive
    with K=4. If it stays in the 58-60 range, K=4 + default rule is
    confirmed as the cipher-hypothesis ceiling and the bottleneck is
    structurally different (rule is wrong, or the cipher uses
    modifications we haven't tested).
"""

from __future__ import annotations

from typing import Any

from problem._fitness import (
    count_crib_letter_hits,
    differential_input_check,
    find_crib_construction_cheat,
    find_crib_literal_cheat,
    multi_sentinel_check,
    now,
    score_with_refinement,
)


_SENTINEL_CRIB_HITS_THRESHOLD = 6


def run_experiment(*, instance: dict[str, Any], seed: int, **kwargs: Any) -> dict[str, Any]:
    """Score the EVOLVE-BLOCK hypothesis via external SA refinement."""
    t0 = now()
    ciphertext = instance["ciphertext"]

    literal_err = find_crib_literal_cheat(decrypt_k4)
    if literal_err is not None:
        return {
            "score": float("-inf"),
            "solved": True,
            "runtime_s": now() - t0,
            "error_tail": literal_err,
        }

    construction_err = find_crib_construction_cheat(decrypt_k4)
    if construction_err is not None:
        return {
            "score": float("-inf"),
            "solved": True,
            "runtime_s": now() - t0,
            "error_tail": construction_err,
        }

    try:
        plaintext = decrypt_k4(ciphertext)
    except Exception as e:
        return {
            "score": float("-inf"),
            "solved": True,
            "runtime_s": now() - t0,
            "error_tail": f"{type(e).__name__}: {e}",
        }

    # If decrypt_k4 returned the all-A fallback, the cipher state itself
    # is malformed (K/rule/FREE_LETTERS inconsistent or constraints
    # conflict). Diagnose specifically rather than letting the sentinel
    # test give the misleading "ignores ciphertext" message — gen 6 of
    # the first Run B attempt failed for this reason and the LLM got
    # confusing feedback for all K=5/K=6 mutations.
    if isinstance(plaintext, str) and plaintext == "A" * len(ciphertext):
        diagnosis = _diagnose_cipher_state(
            K, selection_rule, ciphertext, FREE_LETTERS, MODIFICATIONS,
        )
        return {
            "score": float("-inf"),
            "solved": True,
            "runtime_s": now() - t0,
            "error_tail": f"malformed cipher state: {diagnosis}",
        }

    sentinel = ciphertext[::-1]
    try:
        plaintext_sentinel = decrypt_k4(sentinel)
    except Exception as e:
        return {
            "score": float("-inf"),
            "solved": True,
            "runtime_s": now() - t0,
            "error_tail": (
                "decrypt_k4 crashes on reversed-ciphertext sentinel "
                "(non-robust to input): " + f"{type(e).__name__}: {e}"
            ),
        }

    if (
        isinstance(plaintext, str)
        and isinstance(plaintext_sentinel, str)
        and len(plaintext) == len(plaintext_sentinel)
        and len(plaintext) > 0
    ):
        same = sum(1 for a, b in zip(plaintext, plaintext_sentinel) if a == b)
        identity_ratio = same / len(plaintext)
        if identity_ratio > 0.5:
            return {
                "score": float("-inf"),
                "solved": True,
                "runtime_s": now() - t0,
                "error_tail": (
                    f"decrypt_k4 appears to ignore its ciphertext argument: "
                    f"{identity_ratio:.0%} identical positions between K4 "
                    f"and reversed-K4 outputs."
                ),
            }

        sentinel_hits = count_crib_letter_hits(plaintext_sentinel)
        if sentinel_hits > _SENTINEL_CRIB_HITS_THRESHOLD:
            return {
                "score": float("-inf"),
                "solved": True,
                "runtime_s": now() - t0,
                "error_tail": (
                    f"decrypt_k4 produces crib letters at the K4 crib "
                    f"positions even on reversed-ciphertext input "
                    f"({sentinel_hits} of 24 hits)."
                ),
            }

    multi_err = multi_sentinel_check(decrypt_k4, ciphertext)
    if multi_err is not None:
        return {
            "score": float("-inf"),
            "solved": True,
            "runtime_s": now() - t0,
            "error_tail": multi_err,
        }

    diff_err = differential_input_check(decrypt_k4, ciphertext, plaintext)
    if diff_err is not None:
        return {
            "score": float("-inf"),
            "solved": True,
            "runtime_s": now() - t0,
            "error_tail": diff_err,
        }

    return score_with_refinement(
        decrypt_with_state=_decrypt_with_state,
        ciphertext=ciphertext,
        K=K,
        selection_rule=selection_rule,
        free_letters=FREE_LETTERS,
        modifications=MODIFICATIONS,
        n_outer_steps=100,
        inner_steps=20,
        t0=t0,
    )


# ============================================================
# FIXED HELPERS — outside EVOLVE-BLOCK, the LLM cannot mutate these.
# ============================================================

def _consonant_count_array(ciphertext: str) -> list[int]:
    """Cumulative consonant count at each position 0..len(ciphertext)-1."""
    vowels = "AEIOU"
    out: list[int] = []
    cnt = 0
    for c in ciphertext:
        if c not in vowels:
            cnt += 1
        out.append(cnt)
    return out


def _vowel_count_array(ciphertext: str) -> list[int]:
    """Cumulative vowel count at each position."""
    vowels = "AEIOU"
    out: list[int] = []
    cnt = 0
    for c in ciphertext:
        if c in vowels:
            cnt += 1
        out.append(cnt)
    return out


def _w_seg_offset_array(ciphertext: str) -> list[int]:
    """Offset of each position within its W-bounded segment.

    K4 contains 5 'W' letters at positions {20, 36, 48, 58, 73}. They
    partition K4 into 6 segments. For position i, w_seg_offset[i] is the
    distance from the nearest preceding W (or start). This is the
    'pos_in_w_seg_mod_k' feature from exp 036 — the only natural feature
    that achieves the chromatic floor at K=8, and the basis for all
    K=5 compound rules in k4_priors_by_k.json.
    """
    n = len(ciphertext)
    w_positions = [i for i, c in enumerate(ciphertext) if c == "W"]
    out = [0] * n
    boundaries = [-1] + w_positions + [n]
    for s in range(len(boundaries) - 1):
        lo, hi = boundaries[s], boundaries[s + 1]
        for i in range(lo + 1, hi):
            if 0 <= i < n:
                out[i] = i - lo - 1
    return out


def _w_dist_array(ciphertext: str) -> list[int]:
    """Distance from each position to the nearest 'W' in the ciphertext.

    The dist_to_w rule has 1 violation across k ∈ {6..10} — the
    pos-31/pos-65 obstruction. See README section 'The dist_to_w
    near-miss'. Used in some k=6 rules in k4_priors_by_k.json.
    """
    n = len(ciphertext)
    w_positions = [i for i, c in enumerate(ciphertext) if c == "W"]
    if not w_positions:
        return [0] * n
    return [min(abs(i - w) for w in w_positions) for i in range(n)]


def _build_constraints(K_val: int, rule_fn, ciphertext: str) -> dict:
    """Derive {color: {plain_idx: cipher_letter}} from rule + cribs.

    Returns a dict mapping each color to a dict of {plain_letter_index:
    cipher_letter} constraints induced by the crib positions. If the rule
    sends multiple cribs with conflicting mappings to the same color, the
    later one overwrites the earlier (which will produce a malformed
    alphabet downstream and fail).
    """
    from kryptos.cribs import CRIBS
    out: dict[int, dict[int, str]] = {c: {} for c in range(K_val)}
    for crib in CRIBS:
        for offset, (p, ct) in enumerate(zip(crib.plaintext, crib.ciphertext)):
            pos = crib.start - 1 + offset
            color = rule_fn(pos, ciphertext)
            if not isinstance(color, int) or not (0 <= color < K_val):
                continue
            out[color][ord(p) - 65] = ct
    return out


def _build_alphabet(constraints: dict, free_letters: str):
    """Lenient alphabet construction. The LLM often mutates K or the rule
    without updating FREE_LETTERS to the correct per-color size — this
    function treats free_letters as a PREFERENCE ORDER and pads with
    remaining available letters alphabetically, rather than failing.

    Steps:
      1. Place constraint letters at their fixed plain-letter indices.
      2. Compute `available` = A-Z minus constraint values.
      3. Extract LLM preference: letters from free_letters that are in
         `available`, in order, deduplicated.
      4. Pad with any remaining `available` letters in alphabetical order.
      5. Fill free alphabet positions from this ordered list.

    Returns None only if the result is not a valid A-Z permutation (which
    would indicate a deeper constraints conflict).
    """
    standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    constrained_letters = set(constraints.values())
    if not constrained_letters.issubset(set(standard)):
        return None  # non-A-Z constraint letter

    available = [c for c in standard if c not in constrained_letters]
    available_set = set(available)

    # LLM preference order: dedup, filter to available
    seen: set[str] = set()
    ordered: list[str] = []
    for c in free_letters:
        if c in available_set and c not in seen:
            ordered.append(c)
            seen.add(c)
    # Pad with any remaining available letters in alphabetical order
    for c in available:
        if c not in seen:
            ordered.append(c)
            seen.add(c)

    alpha: list[str] = [""] * 26
    for idx, letter in constraints.items():
        if 0 <= idx < 26:
            alpha[idx] = letter

    free_iter = iter(ordered)
    for j in range(26):
        if alpha[j] == "":
            try:
                alpha[j] = next(free_iter)
            except StopIteration:
                return None

    if set(alpha) != set(standard):
        return None  # duplicate letters → conflicting constraints
    return "".join(alpha)


def _decrypt_with_state(
    ciphertext: str,
    K_val: int,
    rule_fn,
    free_letters: list,
    modifications: list,
) -> str:
    """Pure per-position alphabet selection cipher (no optimization).

    For each position i:
      color = rule_fn(i, ciphertext)
      alphabet = built from cribs constraints[color] + free_letters[color]
      j = alphabet.index(ciphertext[i])
      apply modifications[color] to j (caesar shift / reverse)
      plaintext[i] = STANDARD[j]
    """
    constraints_by_color = _build_constraints(K_val, rule_fn, ciphertext)
    alphabets: list = []
    standard_set = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    for c in range(K_val):
        a = _build_alphabet(constraints_by_color.get(c, {}), free_letters[c])
        if a is None or set(a) != standard_set:
            return "A" * len(ciphertext)  # malformed → all-A fallback
        alphabets.append(a)

    out: list[str] = []
    for i, ch in enumerate(ciphertext):
        color = rule_fn(i, ciphertext)
        if not isinstance(color, int) or not (0 <= color < K_val):
            return "A" * len(ciphertext)
        alpha = alphabets[color]
        mod = modifications[color] if color < len(modifications) else None
        try:
            j = alpha.index(ch)
        except ValueError:
            return "A" * len(ciphertext)
        if mod is not None and isinstance(mod, tuple) and len(mod) >= 1:
            if mod[0] == "caesar" and len(mod) >= 2 and isinstance(mod[1], int):
                j = (j + mod[1]) % 26
            elif mod[0] == "reverse":
                j = (25 - j) % 26
        out.append(chr(ord("A") + j))
    return "".join(out)


def _diagnose_cipher_state(
    K_val: int, rule_fn, ciphertext: str, free_letters: list, modifications: list,
) -> str:
    """When decrypt_k4(K4) returns all-A, this builds an actionable error
    message explaining what went wrong (so the LLM sees a useful diagnostic
    instead of the misleading 'ignores ciphertext' sentinel message)."""
    if len(free_letters) != K_val:
        return (
            f"hypothesis mismatch: K={K_val} but FREE_LETTERS has "
            f"{len(free_letters)} entries. Must have exactly K entries."
        )
    if len(modifications) != K_val:
        return (
            f"hypothesis mismatch: K={K_val} but MODIFICATIONS has "
            f"{len(modifications)} entries. Must have exactly K entries."
        )

    try:
        constraints_by_color = _build_constraints(K_val, rule_fn, ciphertext)
    except Exception as e:
        return f"selection_rule raised {type(e).__name__}: {e}"

    standard_set = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    for c in range(K_val):
        cs = constraints_by_color.get(c, {})
        values = list(cs.values())
        # Conflict: same plain_idx mapped to multiple cipher letters (silently
        # overwritten in _build_constraints; check by re-running)
        seen_by_plain: dict[int, str] = {}
        from kryptos.cribs import CRIBS
        conflict_msg: str | None = None
        for crib in CRIBS:
            for offset, (p, ct) in enumerate(zip(crib.plaintext, crib.ciphertext)):
                pos = crib.start - 1 + offset
                try:
                    color = rule_fn(pos, ciphertext)
                except Exception:
                    continue
                if color != c:
                    continue
                pi = ord(p) - 65
                if pi in seen_by_plain and seen_by_plain[pi] != ct:
                    conflict_msg = (
                        f"color {c}: rule maps two cribs with conflicting "
                        f"mappings to plain_letter {chr(pi+65)}: "
                        f"{seen_by_plain[pi]!r} vs {ct!r} (this would require "
                        f"alphabet[{c}][{pi}] to be both letters simultaneously). "
                        f"Try a different selection rule at this K."
                    )
                    break
                seen_by_plain[pi] = ct
            if conflict_msg:
                break
        if conflict_msg:
            return conflict_msg

        # Cipher-letter conflict: two cribs with different plain letters
        # mapped to the same color have the same cipher letter
        cipher_letter_to_plain: dict[str, int] = {}
        cipher_conflict: str | None = None
        for plain_idx, cipher_letter in cs.items():
            if cipher_letter in cipher_letter_to_plain and cipher_letter_to_plain[cipher_letter] != plain_idx:
                cipher_conflict = (
                    f"color {c}: two different plain letters "
                    f"({chr(cipher_letter_to_plain[cipher_letter]+65)} and "
                    f"{chr(plain_idx+65)}) map to the same cipher letter "
                    f"{cipher_letter!r}, but alphabet is a permutation — "
                    f"each cipher letter can only appear ONCE. Try a "
                    f"different rule."
                )
                break
            cipher_letter_to_plain[cipher_letter] = plain_idx
        if cipher_conflict:
            return cipher_conflict

        # Otherwise: try to build and see why
        a = _build_alphabet(cs, free_letters[c])
        if a is None or set(a) != standard_set:
            return (
                f"alphabet for color {c} cannot form a valid A-Z permutation. "
                f"constraints values: {sorted(set(cs.values()))}; "
                f"FREE_LETTERS[{c}] = '{free_letters[c]}' ({len(free_letters[c])} chars). "
                f"FREE_LETTERS is lenient (padded alphabetically), so this "
                f"suggests deeper structural issue."
            )

    return "decrypt_k4 returned all-A but no specific cause detected"


def decrypt_k4(ciphertext: str) -> str:
    """Pure-substitution decryption using LOCKED K + selection_rule and
    EVOLVE-BLOCK FREE_LETTERS + MODIFICATIONS."""
    return _decrypt_with_state(
        ciphertext, K, selection_rule, FREE_LETTERS, MODIFICATIONS,
    )


# ============================================================
# LOCKED CIPHER HYPOTHESIS — Run C tests K=5 W-segment specifically.
# K and selection_rule are outside the EVOLVE-BLOCK; the LLM cannot
# modify them. To test other hypotheses (K=4, K=6, different rules),
# launch a separate run with these constants changed manually.
# ============================================================

K = 5

def selection_rule(i: int, ciphertext: str) -> int:
    """LOCKED in Run C. Top-ranked K=5 rule from exp 038:
    (3 * pos_mod_3 + 4 * w_seg_offset) mod 5.
    Scheidt-score 29; the only natural compound rule space at K=5 uses
    the W-segment offset feature (exp 040's load-bearing W-structure)."""
    ws = _w_seg_offset_array(ciphertext)
    return (3 * (i % 3) + 4 * ws[i]) % K


# ============================================================
# EVOLVE-BLOCK-START
# ============================================================
# Run C: K=5 W-segment cipher hypothesis LOCKED. K and selection_rule
# are defined ABOVE this block (outside the mutable region). The LLM can
# only mutate FREE_LETTERS and MODIFICATIONS here.
#
# MUTATION RULES:
#
# 1. Decryption (_decrypt_with_state) and helpers above are FIXED.
#    DO NOT introduce hill-climbing, simulated annealing, or any
#    iterative refinement inside this block. The fitness function runs
#    an external 2000-iter SA over FREE_LETTERS for you.
#
# 2. PROHIBITED:
#    - Do NOT redefine K or selection_rule here. They are locked
#      outside this block; assignments here will be ignored (Python
#      executes top-to-bottom, but the locked values are already set).
#    - Do NOT define FREE_LETTERS or MODIFICATIONS as values produced
#      by running optimization/search. They are STATIC starting points.
#    - If you find yourself writing more than ~20 lines here, you are
#      likely re-introducing optimization. Stop.
#
# 3. Mutation surface (only):
#    FREE_LETTERS — list of 5 strings, one per color. Each is the
#      starting ordering of the free (non-crib-constrained) letters for
#      that color's alphabet. The SA refines via pair swaps. Good
#      starting points (KRYPTOS-keyed orderings, English-frequency-
#      ordered, reversed alphabets) can help find better local optima.
#      The alphabet builder is LENIENT — extra/missing/duplicated
#      letters are handled by padding alphabetically. So you can
#      propose any reasonable ordering and the SA will refine.
#
#    MODIFICATIONS — list of 5 entries.
#      None | ("caesar", shift) | ("reverse", None)
#      Sanborn-style per-color modification. Test specific Caesar
#      shifts or reversal per color. The locked rule has K=5 colors so
#      there are 5 modifications.
#
# 4. Context for Run C:
#    - Run B v2 best at K=5 W-segment was 58.75 (under new fitness)
#    - Under same fitness, K=4 default rule scores 63.10 (higher!)
#    - K=5 W-segment had no real advantage; Run B v2's "K=5 wins" was
#      per_partition-metric artifact (now fixed: weight 15 → 5)
#    - Run C tests whether K=5 W-segment has additional alphabet
#      headroom under HONEST fitness. Target: > 65 with hex > -18.
#    - If Run C plateaus near 60, K=5 W-segment is structurally weaker
#      than K=4 + Prior A default rule and we should pivot back.

# FREE_LETTERS — Run B v2 gen 1's SA-converged alphabets at K=5 W-segment.
# Starting at this state lets the LLM build on the best K=5 result we
# already have. Under the new (downweighted) fitness, this seed scores
# 58.75. Crib constraints are derived automatically from the locked
# rule.
FREE_LETTERS = [
    "LVXJOKZEUHWYSDNAIBCF",        # color 0 (20 chars, length matches free positions)
    "ZSOAILTEDHJNWMKFCGXUB",       # color 1 (21 chars)
    "DOBJUZIATHXYEMPGRQCW",        # color 2 (20 chars)
    "MCRAYXBLGVHWQUEDJOI",         # color 3 (19 chars)
    "SMAWCPVZEBDXONFTJIHYLKQRUG",  # color 4 (26 chars)
]

# Per-color cipher modifications. None = pure alphabet substitution.
# Try ("caesar", n) at one color, ("reverse", None) at another, etc.
MODIFICATIONS = [None, None, None, None, None]

# EVOLVE-BLOCK-END


# ============================================================
# POST-BLOCK LOCK RE-ASSERTION — overrides any LLM mutation that
# tries to redefine K or selection_rule inside the EVOLVE-BLOCK.
# This ensures the cipher hypothesis stays locked at K=5 W-segment
# regardless of what the LLM does in the mutable region.
# ============================================================

K = 5

def selection_rule(i: int, ciphertext: str) -> int:
    """Locked K=5 W-segment rule (post-block re-assertion)."""
    ws = _w_seg_offset_array(ciphertext)
    return (3 * (i % 3) + 4 * ws[i]) % K
