# K4 plaintext inference context

Single context document for N1: LM-based plaintext-content inference on
Kryptos K4. Used as the system context for batched LM queries; what they
read before producing candidate plaintexts.

## What is known with certainty

The K4 ciphertext on the Langley sculpture is exactly 97 letters:

    Pos: 1         11        21        31        41        51        61        71        81        91
         1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567
    K4:  OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR

Four cribs have been confirmed by Jim Sanborn over fifteen years:

| Crib       | K4 positions (1-indexed) | Ciphertext  | Plaintext   |
|------------|--------------------------|-------------|-------------|
| EAST       | 22-25                    | FLRV        | EAST        |
| NORTHEAST  | 26-34                    | QQPRNGKSS   | NORTHEAST   |
| BERLIN     | 64-69                    | NYPVTT      | BERLIN      |
| CLOCK      | 70-74                    | MZFPK       | CLOCK       |

Position 74 (K -> K) is a letter encrypting to itself. The four cribs
constrain 24 of 97 positions. The other 73 positions are unknown to the
public.

Sanborn confirmed letter-by-letter at the 2013 ACA convention:
"N=B, Y=E, P=R, V=L, T=I, T=N -- Emphatically."

## The plaintext is English in Sanborn's literary register

K4 is part of a sequence with three solved sections (K1, K2, K3), all in
plain English, all in Sanborn's voice. The plaintexts of those sections:

K1 (poetic abstraction; deliberate misspelling IQLUSION):
> BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT LIES THE NUANCE OF IQLUSION

K2 (historical-technical narrative with conversational asides; spelled-out
coordinates; deliberate UNDERGRUUND):
> IT WAS TOTALLY INVISIBLE HOWS THAT POSSIBLE THEY USED THE EARTHS MAGNETIC
> FIELD X THE INFORMATION WAS GATHERED AND TRANSMITTED UNDERGRUUND TO AN
> UNKNOWN LOCATION X DOES LANGLEY KNOW ABOUT THIS THEY SHOULD ITS BURIED
> OUT THERE SOMEWHERE X WHO KNOWS THE EXACT LOCATION ONLY WW THIS WAS HIS
> LAST MESSAGE X THIRTY EIGHT DEGREES FIFTY SEVEN MINUTES SIX POINT FIVE
> SECONDS NORTH SEVENTY SEVEN DEGREES EIGHT MINUTES FORTY FOUR SECONDS
> WEST X LAYER TWO

K3 (Howard Carter's tomb-opening diary, lightly paraphrased; deliberate
DESPARATLY):
> SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT ENCUMBERED
> THE LOWER PART OF THE DOORWAY WAS REMOVED WITH TREMBLING HANDS I MADE A
> TINY BREACH IN THE UPPER LEFT HAND CORNER AND THEN WIDENING THE HOLE A
> LITTLE I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING FROM
> THE CHAMBER CAUSED THE FLAME TO FLICKER BUT PRESENTLY DETAILS OF THE
> ROOM WITHIN EMERGED FROM THE MIST X CAN YOU SEE ANYTHING Q

Note the register: descriptive, observational, slightly archaic, with X
as a phrase separator and the occasional deliberate misspelling. K4's
plaintext is in the same family.

## Themes Sanborn has confirmed publicly

From Sanborn's 12 November 2025 International Spy Museum talk:

> "Two events influenced the K4 plaintext: my second trip to Egypt in late
> 1986 and the fall of the Berlin Wall."

The "Berlin Clock" of K4 is NOT the Mengenlehreuhr ("Set Theory Clock")
that the community assumed for 15 years. Sanborn clarified in November
2025 that it refers to the **Weltzeituhr (Urania World Clock) at
Alexanderplatz**, the gathering place for the crowds that brought down
the Berlin Wall on 9 November 1989.

Sanborn was in Berlin during the Wall's fall.

From the August 2025 Open Letter (Sanborn announcing the K4 auction):
He decided to sell the K4 solution because he "no longer ha[s] the
physical, mental or financial resources" to continue the puzzle. The
auction took place 20 November 2025 at RR Auction's "Decoding History"
sale; an anonymous bidder paid $962,500 for the complete Kryptos archive
(handwritten K4 plaintext + Scheidt signed letter + 1988 copper maquette
+ original coding charts + an unpublished 1988 alternate plaintext now
identified as K5 + a private afternoon with Sanborn).

## K5 exists and shares words at the same positions as K4

From Sanborn's Spy Museum talk:

> K5 is 97 characters, will appear in a public space after K4 is
> cryptographically solved, and shares words at the same positions as K4.

This is a strong forward constraint: any candidate K4 plaintext that fits
neatly into the K5 framing (whatever that is) is more likely correct.

## What the K1-K3 design pattern suggests

K1 is poetic, abstract, about perception (subtle shading / absence of
light / nuance of illusion).

K2 is technical-historical, includes coordinates and operational language
("information was gathered and transmitted", "buried out there somewhere",
"this was his last message"), ends with "LAYER TWO" pointing to K3.

K3 is Carter's tomb diary nearly verbatim. It is observational, present-
tense, about discovery and looking inside.

The pattern: each section illuminates the next, K2's content gestures
toward K3 (Carter is "LAYER TWO"), K3's content gestures toward K4 ("can
you see anything?"). K4 plausibly continues this chain: it might gesture
toward K5, may describe what is seen, may identify a location.

## K2's geographic style

K2 contains the sculpture's own GPS coordinates spelled out:

> THIRTY EIGHT DEGREES FIFTY SEVEN MINUTES SIX POINT FIVE SECONDS NORTH
> SEVENTY SEVEN DEGREES EIGHT MINUTES FORTY FOUR SECONDS WEST

If K4 contains geographic coordinates (e.g. for the Bornholmer Strasse
crossing where the Berlin Wall first opened, ~52°33'N 13°24'E), they are
plausibly spelled out the same way.

## Position 74 is the K -> K self-encryption

The K at K4 position 74 decrypts to K (the final letter of CLOCK).
Sanborn confirmed this is exact. The plaintext at K4 positions 64-74 is
exactly BERLINCLOCK, contiguous.

## Sanborn's authorial signature: deliberate textual irregularities

- K1: IQLUSION (should be ILLUSION)
- K2: UNDERGRUUND (should be UNDERGROUND)
- K2: omitted X separator before "LAYER TWO" in original encryption
       (sculpture decrypts to "WESTIDBYROWS"; corrected reading is
       "WESTXLAYERTWO")
- K3: DESPARATLY (should be DESPERATELY)
- K3: terminating Q (a closing mark)

K4 likely contains analogous irregularities. Possible candidates:
geographical names slightly mis-spelled, a deliberate dropped letter, a
terminating mark.

## The Morse plates around the sculpture

Engraved on granite slabs around the Kryptos courtyard, in International
Morse code:

- SOS
- LUCID MEMORY
- T IS YOUR POSITION
- SHADOW FORCES
- VIRTUALLY INVISIBLE
- DIGETAL INTERPRETATIT  (deliberate misspelling)
- RQ

Read in physical order they form rough sentence fragments. Their letter
distribution does NOT match K4, so they are not the cipher key or
plaintext source directly. They are likely THEMATIC GLOSS on the K4
narrative.

## What Scheidt has said about the cipher

From Ed Scheidt at the 2011 Kryptos Dinner (Ed Hannon's notes):

> "[K4 cryptography] is not mathematical (although this does not preclude
> it being modeled mathematically), it is simple, can be remembered, and
> executed years later when used with the correct key word/s."

From Scheidt 2005 NPR interview:
He deliberately "masked" the English letter-frequency advantage in K4.

From Sanborn 2005 Wired interview:
> "I was modifying systems and developing my own which would make it
> virtually impossible for [Scheidt] to decipher all of it."

The cipher mechanism is Scheidt's classical scheme + a Sanborn-introduced
modification. The plaintext is normal English written by Sanborn.

## Difficulty grading

Scheidt rated K4's difficulty "around nine out of ten" with an intended
solve time of "five, seven or maybe ten years." That implies the cipher
IS solvable by a serious cryptanalyst -- not unsolvable by design.

## The September 2025 plaintext discovery

On 3 September 2025, journalists Jarett Kobek and Richard Byrne assembled
the K4 plaintext from taped-together coding charts Sanborn had donated to
the Smithsonian Archives of American Art during cancer treatment ~2023.
Sanborn confirmed the plaintext at the 12 November 2025 Spy Museum talk
("K4 has not been solved or decrypted" -- meaning the cryptographic
problem remains open even though the plaintext is now privately known by
Sanborn, Scheidt, Kobek, Byrne, and the anonymous auction buyer).

The Smithsonian papers are sealed until 2075. The plaintext is privately
held by those five parties.

## What we are asking the LM

Given everything above, **draft 5-10 candidate 97-character K4 plaintexts
that:**

1. Have EAST at positions 22-25, NORTHEAST at positions 26-34, BERLIN at
   positions 64-69, CLOCK at positions 70-74 (exact substring match).
2. Are written in Sanborn's literary register (modeled on K1-K3): English,
   uppercase, X-separators between phrases, descriptive observational
   prose.
3. Thematically reference the 1986 Egypt trip and/or the 1989 Berlin Wall
   fall.
4. Plausibly include a geographic reference (possibly spelled-out
   coordinates), an X-separated phrase structure, or other K1-K3-style
   elements.
5. Are exactly 97 characters total.
6. May include a deliberate Sanborn-style misspelling.

For each candidate, briefly explain which priors it satisfies and where
you think it might be wrong.

Vary the candidates substantially in tone, narrative structure, and topical
focus. Some should emphasize Berlin Wall location, some Egypt themes,
some Sanborn's first-person observation, some the K5 forward-reference.

The output of this batch query is a *probability distribution over
themes*, not a single candidate. Recurring themes across many independent
LM runs are the prior we want to extract.
