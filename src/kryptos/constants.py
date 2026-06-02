"""Hard-coded Kryptos ciphertexts and plaintexts.

These are public and unchanging. Hard-coding them here means experiment code
never depends on whether the `data/` directory is on the working tree.

Lengths:
  K1: 63    K2: 369   K3: 336   K4: 97

Notes:
  - K1, K3, K4 are byte-exact against Wikipedia + Bean's k4testing repo.
    K2 is the *post-2006-correction* form (plaintext ends "...WESTXLAYERTWO",
    369 letters). The as-installed sculpture K2 is 368 letters and decrypts
    to "...WESTIDBYROWS" because Sanborn dropped a single X at encryption
    time; the corrected form adds that X back and is what this library
    ships. Replace K2 with the 368-letter sculpture text if you need
    byte-exact agreement with the artwork itself.
  - K3 here drops the 4 sculpture-internal '?' separators (one explicit '?'
    after "EERLB" plus separators). They are scene markers, not encrypted.
  - See `data/ciphertexts/README.md` for the source-by-source comparison
    behind these choices, including where Elonka, Wikipedia, the CIA page,
    and Bean's code agree.
"""

K1: str = (
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ"
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
)

K2: str = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLGTIM"
    "VMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRRYIZ"
    "ETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZEREEVLDK"
    "FEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKFFHQNTG"
    "PUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGREDNQFMPNZ"
    "GLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)

K3: str = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNETPR"
    "NGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETFOLSED"
    "TIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBTEEFOASFIO"
    "TUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEBAECTDDHILCEI"
    "HSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHEECDMRIPFEIMEHNL"
    "SSTTRTVDOHW"
)

K4: str = (
    "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAW"
    "INFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)


# K5 placeholder.
#
# Sanborn confirmed at his 12 Nov 2025 International Spy Museum talk that
# K5 exists, is 97 characters, will appear in a public space after K4 is
# CRYPTOGRAPHICALLY solved (not just plaintext-recovered), and "shares
# words at the same positions as K4". K5 ciphertext has not been released
# as of the time of writing.
#
# When K5 drops, paste the 97-letter ciphertext into K5 below, bump the
# assertion in assert_lengths(), and add K5 to the experiment harness.
# The shared-positions clue is a powerful forward test: any K4 method that
# fits K5 too is much more likely to be correct.
K5: str | None = None
K5_LENGTH: int = 97


K1_PLAINTEXT: str = (
    "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
)

# K2_PLAINTEXT is the *as-installed* sculpture plaintext: what
# QuagmireIII("ABSCISSA","KRYPTOS").decrypt(K2) actually returns. It ends
# "...WESTIDBYROWS" because Sanborn dropped a letter at encryption time.
# Round-trips cleanly with K2.
K2_PLAINTEXT: str = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFI"
    "ELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOW"
    "NLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOM"
    "EWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRT"
    "YEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEV"
    "ENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTIDBYROWS"
)

# What Sanborn announced in April 2006 he had INTENDED to encrypt: the
# same text but ending with "...WESTXLAYERTWO" (one extra X). Does NOT
# decrypt from K2 -- it is the writer's-intent text, not the artifact's
# text. Provided here so experiments that need the "Sanborn-intended"
# corpus (the XLAYERTWO referent to Carter p.170 "what we may call the
# second layer") can pull it directly.
K2_INTENDED_PLAINTEXT: str = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFI"
    "ELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOW"
    "NLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOM"
    "EWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRT"
    "YEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEV"
    "ENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTXLAYERTWO"
)

K3_PLAINTEXT: str = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHE"
    "LOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREAC"
    "HINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDT"
    "HECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFLAME"
    "TOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHINEMERGEDFROMTHEMISTXCA"
    "NYOUSEEANYTHINGQ"
)


# Confirmed K1-K3 cipher parameters (alphabet keyword + Vigenere key).
# K1, K2 are Quagmire III with both alphabets keyed by KRYPTOS. With both
# alphabets keyed to the SAME word, Quagmire III reduces to Vigenere
# performed in the keyed-alphabet index space -- which is what
# `ciphers.quagmire.QuagmireIII` implements.
K1_ALPHABET_KEYWORD = "KRYPTOS"
K1_KEY = "PALIMPSEST"

K2_ALPHABET_KEYWORD = "KRYPTOS"
K2_KEY = "ABSCISSA"

# K3 is route/columnar transposition; the key is the column read order
# corresponding to the KRYPTOS keyword on a 7-wide grid.
K3_COLUMN_ORDER = (0, 3, 6, 2, 5, 1, 4)


def assert_lengths() -> None:
    """Sanity check; cheap, called by experiments to catch ciphertext edits.

    All four ciphertexts are byte-exact against the cross-source check
    documented in data/ciphertexts/README.md. K2 is the as-installed
    sculpture form (369 letters, decrypts to "...IDBYROWS");
    K2_INTENDED_PLAINTEXT is Sanborn's April-2006-announced intended text.
    """
    assert len(K1) == 63, len(K1)
    assert len(K2) == 369, len(K2)
    assert len(K3) == 336, len(K3)
    assert len(K4) == 97, len(K4)
    assert len(K1_PLAINTEXT) == 63, len(K1_PLAINTEXT)
    assert len(K2_PLAINTEXT) == 369, len(K2_PLAINTEXT)
    assert len(K2_INTENDED_PLAINTEXT) == 370, len(K2_INTENDED_PLAINTEXT)
    assert len(K3_PLAINTEXT) == 336, len(K3_PLAINTEXT)
