# N-gram frequency tables

These files are not committed; download them before running the scoring code.

## english_quadgrams.txt
Practical Cryptography's English quadgram log-frequency file (~389 KB).
Format: `QUAD COUNT` per line, separated by a space.

    http://practicalcryptography.com/media/cryptanalysis/files/english_quadgrams.txt.zip

## english_hexagrams.txt
Build your own from a deduplicated Project Gutenberg corpus (~100 MB). At
length 73 (the unconstrained K4 positions) quadgram fitness is noisy and
easily gamed by gibberish, which is why hexagram fitness is the recommended
default for any K4 candidate scoring.

    scripts/build_hexagrams.py  (TODO -- write this in experiments/)

## Norvig letter/bigram/trigram/quadgram frequencies
For sanity checks against Practical Cryptography.

    https://norvig.com/mayzner.html
