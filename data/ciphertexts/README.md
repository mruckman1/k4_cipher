# Kryptos ciphertexts -- provenance

Every byte in `k1.txt`, `k2.txt`, `k3.txt`, `k4.txt` is the result of a
cross-source check. Discrepancies and the choices made are documented
below so future-you (or a reviewer) does not have to redo this audit.

## Sources consulted

1. **Wikipedia "Kryptos"** -- en.wikipedia.org/wiki/Kryptos. Reproduces all
   four ciphertexts and K1/K2/K3 plaintexts inline.
2. **Elonka Dunin's Kryptos page** -- elonka.com/kryptos. The canonical
   community-maintained reference; FOIA documents, clue archives, rubbings.
3. **Richard Bean's `k4testing` GitHub repo** -- github.com/RichardBean/k4testing.
   K4 ciphertext appears verbatim as the `ciphertext` constant in
   `k4testing.py`. Authoritative for K4.
4. **CIA's official Kryptos page** -- cia.gov/legacy/headquarters/kryptos.
   Returns 403 to scripted fetches; consulted manually in browser.
5. **Gillogly 1999** -- "The Kryptos sculpture", Dr. Dobb's Journal, Dec
   1999. The first published K1/K2/K3 solutions.

Lengths used in this repo:

| Section | Length (letters) | Round-trips? | Source agreement |
|---------|------------------|--------------|------------------|
| K1      | 63               | Yes (PALIMPSEST + KRYPTOS-keyed Quagmire III) | All sources agree |
| K2      | 369              | Yes (ABSCISSA + KRYPTOS-keyed Quagmire III)   | Wikipedia + Bean's analysis; see "K2 correction" below |
| K3      | 336              | Two-pass transposition not yet implemented; cipher data is byte-exact | All sources agree |
| K4      | 97               | Unsolved by construction                                              | All sources agree |

## K2 correction

The K2 ciphertext on the Langley sculpture is 369 letters. Decrypting
it with `QuagmireIII("ABSCISSA", "KRYPTOS")` yields a 369-letter
plaintext ending `...WESTIDBYROWS`.

In April 2006 Sanborn announced via Elonka Dunin that this is NOT what
he had intended to encrypt. The intended plaintext ends
`...WESTXLAYERTWO` (370 letters; one extra X separator before LAYER).
Sanborn's account is that during encryption he dropped a letter; that
single omission shifted the keystream alignment for the rest of the
message and produced the spurious `IDBYROWS` ending.

The sculpture itself was NOT re-engraved. The 369-letter as-installed
ciphertext is therefore the actual artifact; the 370-letter "intended"
plaintext is the author's-intent version that does NOT round-trip
against the sculpture.

This repo ships both:

- `K2` = the 369-letter sculpture ciphertext.
- `K2_PLAINTEXT` = the 369-letter `...IDBYROWS` form, which is exactly
  what `QuagmireIII("ABSCISSA", "KRYPTOS").decrypt(K2)` returns. Use
  this for any round-trip / regression / library-correctness check.
- `K2_INTENDED_PLAINTEXT` = the 370-letter `...XLAYERTWO` form, which
  is Sanborn's stated authorial intent. Use this when you need the
  semantic referent ("LAYER TWO" links to Carter's "what we may call the
  second layer" on p.170 of *The Tomb of Tut-ankh-Amen*).

If you need the as-installed K2 in its original 369-letter sculpture
form for a different mechanism (e.g. a deliberate mis-encryption
hypothesis), `K2` already IS that text.

## K3 sculpture artifacts

The sculpture engraving of K3 contains four `?` characters as section
separators (and an explicit terminating `?` after `EERLB`). These are
not encrypted -- removing them yields the 336-letter ciphertext we ship.

The K3 plaintext is Howard Carter's 1922 diary entry on opening
Tutankhamen's tomb. The final `Q` is the encoded plaintext closing
mark and does decrypt; the four `?` separators are NOT encoded.

The K3 cipher is a two-step transposition (route + columnar with
KRYPTOS column order on a 7-wide grid). The implementation in
`src/kryptos/ciphers/transposition.py` is single-pass and does NOT
yet decrypt K3 cleanly; replace the placeholder in
`experiments/001_baseline_quagmire_iii_K1_K2.py` once the two-pass
decoder is in.

## K4

97 letters. Cross-verified byte-for-byte against:

  - Wikipedia inline text.
  - Richard Bean's `k4testing.py`: `ciphertext = "OBKR..."`.
  - Sanborn's August 14 2025 Open Letter (which quotes the four crib
    positions, implicitly fixing the indexing).

No source disagrees on any letter.

## Sister-work ciphertexts (NOT byte-locked)

`cyrillic_projector.txt` and `antipodes.txt` are placeholders. Populate
from verified rubbings before treating them as input data.
