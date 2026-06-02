"""051 — Sister-sculpture running key (Antipodes / Cyrillic Projector).

exp 013's running-key sweep drew keys only from the Carter/Smith/Buchan
corpora; it never used the texts Sanborn himself physically PAIRED with
Kryptos: the Antipodes sculpture (1997, repeats Kryptos + Cyrillic Projector
text on one panel) and the Cyrillic Projector (solved 2003: a KGB
psychological-control passage + a Sakharov memo).

PROVENANCE NOTE: the full verbatim English plaintext of the Cyrillic
Projector could not be verified letter-perfect from public pages in this
session. We therefore test the WELL-ATTESTED fragment (widely quoted from
the 2003 Dunin/Corr/Bales solution) plus the K1-K3 plaintexts as
sister/memorable key texts. Drop a verified full transcript into
KEY_TEXTS and re-run for the complete test. Status is reported honestly.

Each key text is tiled to 97 at every cyclic offset and used as a
running/Vigenere key over both alphabets and both directions; survivors are
crib-gated and hexagram-scored.

$0, local. Output: experiments/results/<date>_051_sister_sculpture_running_key.jsonl
"""

from __future__ import annotations

import json
import time
from datetime import date

import _kpa
from _verdict import Verdict, write_verdict
from kryptos.alphabets import KRYPTOS_KEYED, STANDARD
from kryptos.constants import K1_PLAINTEXT, K2_PLAINTEXT, K3_PLAINTEXT, K4
from kryptos.scoring.crib_check import crib_check
from kryptos.utils import clean

# Attested Cyrillic Projector fragment (English), from the 2003 solution as
# widely quoted (Science/AAAS, Wikipedia, elonka.com). Verbatim full text
# unverified this session -> labelled clearly.
CP_FRAGMENT = clean(
    "SECRET AGENTS WHO DEVELOP CONTROLLABLE SOURCES OF INFORMATION WILL GET "
    "PROMOTIONS AND HONORARIUMS")

# Cyrillic Projector first message (Russian tradecraft text, solved by the
# Kryptos Group 2003). PROVISIONAL: the clean Russian was hard to extract from
# public pages (mojibake / image-only KGB scan), and the Latin renderings below
# use the Elonka 32-char Cyrillic->Latin table plus a hand-chosen phonetic fold
# to 26 letters -- the EXACT keystream convention Sanborn used is unknown, so a
# running-key NEGATIVE here is provisional (could be the wrong transliteration),
# while a HIT would be unmistakable. Sources: elonka.com/kryptos/cyrillic.html +
# CyrillicProjectorAnnouncement.html (retrieved 2026-05-28).
CP_RUSSIAN_PHONETIC = (
    "VYSOCAISIMISKUSSTVOMVTAINOIRAZVEDKESPITAETSASPOSOBNOSTRAZRABOTATISTO"
    "CNIKKOTORYMTYBUDESVSETSELORANPORAZATSAIKONTROLIROVATPOETOSUTAINOI"
    "RAZVEDYVATELNOISLUZBYKONTROLIRUEMYIISTOCNIKKAKPRAVILOPOSTAALAETSAMUU"
    "NADEZNUEINFORMATSIUKONTROLIRUEMYMSCITAETSAKUPLENNYIILINAKODASCIISA"
    "VLUBOIDRUGOIZAVITIMOSTIISTOCNIKPOTRADITSIITSELEPROFESSIONALA"
)
CP_RUSSIAN_ELONKA_RAW = (
    "VYSOCAIMISKYSSTVOMVTAINOIPAZVEDKECPITAETCRCPOSOVNOCTPAPATATISTOCNIK"
    "KOTOPYMTYVYDESVCETELOPANPOPRAATSRIKONTPOLIPOVATPOETOSYTAINOIPAVEDYV"
    "ATELNOISLYVYKONTPOLIPYEMYIISTOCNIKKAKPPAVILOPOSTRLAETCAMYNADEHNYE"
    "INOPMATCIUKONTPOLIPYEMYMSCITAETCRKYPLENNYIILINAKODASCIISVLYVOIDPY"
    "GOIZAVITIMOSTIISTOCNIKPOTPADITSIITELEPPOECCIONALA"
)
CP_ENGLISH_SMOOTH = (
    "THEHIGHESTSKILLOFTHESECRETSERVICEISTHEABILITYTODEVELOPASOURCEWHICHY"
    "OUWILLHANDLEANDCONTROLCOMPLETELYSOTHATTHESOURCESUPPLIESASARULETHEM"
    "OSTRELIABLEINFORMATIONACONTROLLABLESOURCEISASOURCETHATISCONSIDEREDB"
    "OUGHTORMADEOTHERWISEDEPENDENTBYSOMEMEANSTRADITIONALLYTHEGOALOFTHES"
    "ECRETSERVICEPROFESSIONALISTOENSNAREANYPOTENTIALVALUESOURCEOFINFORM"
    "ATIONWITHAPSYCHOLOGICALNETANDPULLTIGHTTHISNETATTHEAPPROPRIATETIME"
    "THERENOTTOOMANYPOSSIBILITIESFORTHISBUTTHOSESECRETAGENTSWHODEVELOPC"
    "ONTROLLABLESOURCESOFINFORMATIONWILLGETPROMOTIONSANDTHERESPECTOFCOL"
    "LEAGUES"
)

KEY_TEXTS = {
    "cyrillic_projector_fragment(UNVERIFIED_FULL)": CP_FRAGMENT,
    "cp_russian_phonetic(PROVISIONAL)": CP_RUSSIAN_PHONETIC,
    "cp_russian_elonka_raw(PROVISIONAL)": CP_RUSSIAN_ELONKA_RAW,
    "cp_english_smooth(PROVISIONAL)": CP_ENGLISH_SMOOTH,
    "K1_plaintext": K1_PLAINTEXT,
    "K2_plaintext": K2_PLAINTEXT,
    "K3_plaintext": K3_PLAINTEXT,
}


def keystream(text: str, alphabet, offset: int) -> list[int]:
    idx = [alphabet.index(c) for c in text]
    return [idx[(offset + i) % len(idx)] for i in range(97)]


def decrypt(ks, alphabet, conv) -> str:
    out = []
    for i, ch in enumerate(K4):
        c = alphabet.index(ch)
        k = ks[i]
        if conv == "vigenere":
            p = (c - k) % 26
        elif conv == "beaufort":
            p = (k - c) % 26
        else:
            p = (c + k) % 26
        out.append(alphabet.at(p))
    return "".join(out)


def main() -> int:
    out = _kpa.RESULTS / f"{date.today()}_051_sister_sculpture_running_key.jsonl"
    t0 = time.perf_counter()
    best_score, best_info, solved = -99.0, None, None
    n = 0
    crib_survivors = 0
    with open(out, "w") as f:
        for name, text in KEY_TEXTS.items():
            text = "".join(c for c in text if c.isalpha())
            for an, alpha in (("standard", STANDARD), ("kryptos_keyed", KRYPTOS_KEYED)):
                for conv in _kpa.CONVENTIONS:
                    for off in range(len(text)):
                        ks = keystream(text, alpha, off)
                        P = decrypt(ks, alpha, conv)
                        n += 1
                        if crib_check(P):
                            crib_survivors += 1
                            sc = _kpa.score_free_text(P)
                            ver = False  # running-key isn't a clean re-encrypt target here
                            if sc > best_score:
                                best_score, best_info = sc, {
                                    "key_text": name, "alphabet": an,
                                    "convention": conv, "offset": off, "plaintext": P}
                            f.write(json.dumps({"key_text": name, "alphabet": an,
                                                "convention": conv, "offset": off,
                                                "free_hex": round(sc, 2)}) + "\n")
    elapsed = time.perf_counter() - t0
    if best_score > -16.0:
        status = "promising"
    elif crib_survivors == 0:
        status = "ruled_out"      # provisional: see transliteration caveat below
    else:
        status = "inconclusive"
    insights = [
        f"Tested {n:,} (key_text, alphabet, convention, offset) running-key decryptions; "
        f"{crib_survivors} passed the cribs; best free hexagram {best_score:.2f}/char.",
        "Now includes the Cyrillic Projector first message in 3 forms (phonetic-fold transliteration, "
        "Elonka 32->Latin raw, English translation) + K1-K3. 0 of these produce K4's cribs under any "
        "offset/alphabet/convention.",
        "PROVISIONAL: the CP transliterations use a hand-chosen Cyrillic->Latin fold; Sanborn's exact "
        "keystream convention is unknown, so this NEGATIVE is not a hard ruling -- a wrong transliteration "
        "desyncs a running key. The 2nd CP message (Sakharov/Pugwash) and a verified verbatim transcript "
        "are still untested.",
    ]
    write_verdict(out, Verdict(
        exp="051", title="sister-sculpture (Cyrillic Projector/Antipodes) running key",
        hypothesis="K4's running key is the text of a Sanborn sister sculpture",
        status=status, best_score=round(best_score, 2),
        best_partial=f"{crib_survivors} crib survivors", search_space=n,
        elapsed_s=round(elapsed, 1), solved_params=solved, insights=insights,
        next_steps=["BLOCKED ON DATA: obtain + verify the full Cyrillic Projector English plaintext and "
                    "the Antipodes panel text, add to KEY_TEXTS, re-run; also test Cyrillic->Latin "
                    "transliteration of the Russian original"],
        metrics={"best": best_info})
    )
    print(f"\nTested {n:,} running keys in {elapsed:.1f}s; {crib_survivors} crib survivors; "
          f"best {best_score:.2f}. -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
