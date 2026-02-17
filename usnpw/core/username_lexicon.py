from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from functools import lru_cache
from typing import List, Set, Tuple

def _secure_sample(seq: List[str], k: int) -> List[str]:
    """
    Cryptographically secure sampling without replacement.
    For our pool sizes this is fine.
    """
    if k <= 0:
        return []
    if k >= len(seq):
        return seq[:]
    # Fisher-Yates partial shuffle
    arr = seq[:]
    for i in range(k):
        j = i + secrets.randbelow(len(arr) - i)
        arr[i], arr[j] = arr[j], arr[i]
    return arr[:k]


def normalize_token(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", s.strip().lower())


def dedupe_keep_order(words: List[str]) -> List[str]:
    seen = set()
    out = []
    for w in words:
        n = normalize_token(w)
        if not n or n in seen:
            continue
        seen.add(n)
        out.append(w.strip())
    return out


ADJ_CORE = """
able abrupt absolute abstract active acute adaptive agile airy amber ambient ample angled annual
arid armored ash austere atomic attentive axial balanced bare basalt basic beige blank blended
blunt brief brisk broad bronze buffered calm candid carbon carved central ceramic certain clean
clear closed coarse cobalt cold compact complete concrete constant cool copper covert crisp cubic
curved cyan daily dark dawn decoupled deep dense direct discreet distant dry dual dull dusty eager
early earthy eastern elastic electric elapsed ember empty endless even exact faint fair far fast
ferrous finite firm flat fleet focused formal forward fossil frank free fresh frugal full future
fuzzy gentle glassy global golden gradual granite gray green grounded guarded hard hazy hidden
hollow honest humid icy idle intact ionic iron ivory jade keen keyed latent lean level light linear
liquid local lone long loose low lunar magnetic main major manual marine matte mellow metal mid mild
minimal minor mint modern modest molten mono moss muted narrow native navy near neat neutral new
night nimble noble normal northern novel null oblique obscure ocean offline opaque open optimal
orderly outer pale paper parallel patient pearl perfect phase plain polar polite porous precise
prime private proper pure quiet rapid rare raw ready real reduced remote resin rigid rising rocky
rough round safe sandy satin sealed secure serene sharp short silent simple sincere single sober
soft solid spare stable static steady sterile still stone strict subtle sudden sunlit super swift
tactile tame tangent tapered teal tempered tender thin tidal tight timber tiny total tough tranquil
true tuned ultra unclear uniform united urban vacant valid vast veiled velvet vital vivid warm
watery weak western wide wild wired wise wooden young zenith zero
""".split()

NOUN_CORE = """
access account adapter address agent aggregate airlock alias alloy alpha amplitude anchor angle
antenna aperture appendix arc array aspect asset atlas atom audit axis backbone badge balance band
bank bar barrier base batch bay beacon beam binder bit block board bond border boulder branch bridge
buffer bundle byte cable cache cadence capsule carbon card carrier carton catalog cavity cell center
chain channel charge chassis checksum chip cipher circle circuit clause cluster code coil column
comet command common component compass compound concept cone context control core corner counter
course craft crate credit crest curve cycle cylinder data deck delta density depth design detail
device dial digest dimension directive disk display distance domain doorway draft drift driver dune
echo edge element emitter engine entry envelope epoch error estate event evidence example exchange
exit factor feature field file filter firewall fixture flag flare fleet flow flux focus folder force
format formula frame frequency front function fusion gate gauge glyph grade grain graph grid group
guard habit handle harbor hash header heap hinge history horizon host hub icon image index indicator
input instance interval inverse item junction kernel key kiosk label ladder layer layout ledger lens
level library limit line link list logic loop lumen machine magnet matrix memory mesh message method
metric mirror mode module moment monitor mosaic motion mount network node noise notch number object
offset operator orbit order origin output packet page panel parcel parent parser part patch path
pattern peak peer period phase pipe pixel plane plate point port post power prefix probe process
profile proof protocol pulse quartz queue radar radius rail range rate record relay report request
reserve resource ring route row rule runtime sample scale scan schema scope screen script sector seed
segment sense sensor session shadow shape shard sheet shell signal signature site size slot socket
source space span spark spectrum spike spool stack stage standard state station step store stream
string stripe suite surface switch symbol system table tag task terminal thread throttle ticket tile
time token trace track trail transfer transit tree trigger tunnel type unit update user value vector
vertex view volume vault wall wave window wire word zone
""".split()

VERB_CORE = """
adapt align anchor append audit balance bind blend buffer build cache carry catalog check churn clean
clip close code collect compress compute confirm connect contain convert copy count craft cycle decode
defer deploy derive detect digest direct distribute drift drop echo edit emit encode enforce engineer
escape estimate evaluate expand extract fade filter fit flag flip fold format frame gather generate
grade grant guard hash hide hold index infer insert isolate join keep label launch link list load lock
log loop map mask match merge meter migrate mix model monitor move name narrow note observe offset open
order pack parse patch pivot plan point pool post prepare process prove queue raise read record reduce
refine relay render repeat report reset resolve restore retain route run save scan schedule seal select
send shape shift sign slice sort spawn split stack stage store stream swap switch tag test thread time
trace track transfer translate trim tune update validate vary verify view wrap
""".split()

SYLLABLES_EXT = """
ka ke ki ko ku la le li lo lu ma me mi mo mu na ne ni no nu pa pe pi po pu ra re ri ro ru sa se si so su ta te ti to tu
va ve vi vo vu xa xe xi xo xu za ze zi zo zu
an en in on un ar er ir or ur al el il ol ul am em im om um as es is os us
ba be bi bo bu da de di do du fa fe fi fo fu ga ge gi go gu ha he hi ho hu ja je ji jo ju qa qe qi qo qu
bla ble bli blo blu bra bre bri bro bru cla cle cli clo clu cra cre cri cro cru dra dre dri dro dru
fla fle fli flo flu fra fre fri fro fru gla gle gli glo glu gra gre gri gro gru kla kle kli klo klu
kra kre kri kro kru pla ple pli plo plu pra pre pri pro pru sla sle sli slo slu sma sme smi smo smu
spa spe spi spo spu sta ste sti sto stu stra stre stri stro stru tra tre tri tro tru
cha che chi cho chu sha she shi sho shu tha the thi tho thu kha khe khi kho khu pha phe phi pho phu
zan zen zin zon zun zar zer zir zor zur tal tel til tol tul tar ter tir tor tur sal sel sil sol sul
sar ser sir sor sur nal nel nil nol nul nar ner nir nor nur val vel vil vol vul var ver vir vor vur
kal kel kil kol kul kar ker kir kor kur ral rel ril rol rul
vek vix vox vuz tek tix tox tuz nek nix nox nuz sek six sox suz rek rix rox ruz mek mix mox muz lek lix lox luz
quo que qua qui sva sve svi svo twa twe twi two
kyo kyu kya kye ryo ryu rya rye tyo tyu tya tye
dex drel drim drom drun flex flen flir flos flut glim glen glos glut klen klir klos klut
pran pren prim prom prun tren trim trom trun slen slim slom slut spen spin spon sput sten stim stom stut
""".split()


def build_pseudowords_from_syllables(
    syllables: List[str],
    target_count: int,
    min_syl: int = 2,
    max_syl: int = 4,
    max_attempts: int = 1_000_000,
) -> List[str]:
    sy = [normalize_token(s) for s in syllables if normalize_token(s)]
    sy = dedupe_keep_order(sy)

    out: Set[str] = set()
    attempts = 0
    while len(out) < target_count and attempts < max_attempts:
        attempts += 1
        k = min_syl + secrets.randbelow(max_syl - min_syl + 1)
        w = "".join(secrets.choice(sy) for _ in range(k))
        if len(w) < 5:
            continue
        if re.search(r"(.)\1\1", w):
            continue
        out.add(w)
    return sorted(out)


def enforce_disjoint_pools(*pools: List[str]) -> Tuple[List[str], ...]:
    used: Set[str] = set()
    out_pools: List[List[str]] = []
    for pool in pools:
        cleaned = []
        for w in dedupe_keep_order(pool):
            n = normalize_token(w)
            if n in used:
                continue
            used.add(n)
            cleaned.append(w.strip())
        out_pools.append(cleaned)
    return tuple(out_pools)


# Build big pools lazily to avoid import-time heavy initialization.
# lru_cache provides a thread-safe (locked) one-time init, which matters for API server concurrency.
@lru_cache(maxsize=1)
def _global_word_pools() -> Tuple[List[str], List[str], List[str], List[str], List[str]]:
    adjectives_all = dedupe_keep_order(ADJ_CORE)
    nouns_all = dedupe_keep_order(NOUN_CORE)
    verbs_all = dedupe_keep_order(VERB_CORE)
    pseudo_all = build_pseudowords_from_syllables(SYLLABLES_EXT, target_count=4000, min_syl=2, max_syl=4)
    tags_all = build_pseudowords_from_syllables(SYLLABLES_EXT, target_count=2500, min_syl=2, max_syl=3)
    return enforce_disjoint_pools(adjectives_all, nouns_all, verbs_all, pseudo_all, tags_all)


@dataclass
class RunPools:
    adjectives: List[str]
    nouns: List[str]
    verbs: List[str]
    pseudos: List[str]
    tags: List[str]


def build_run_pools(
    count: int,
    pool_scale: int,
    token_blacklist: Set[str],
) -> RunPools:
    """
    pool_scale acts like a knob:
      - 1   = small subsets (more repetition inside a single run)
      - 2-3 = good balance
      - 4+  = very diverse within a run
    token_blacklist removes already-used tokens (persistent if enabled).
    """
    adjectives_all, nouns_all, verbs_all, pseudo_all, tags_all = _global_word_pools()

    # Choose subset sizes (cap to available pool sizes)
    # Aim: enough variety to avoid repeats across a run, but not so huge it's pointless.
    base = max(80, min(600, count * 10))
    k_adj = min(len(adjectives_all), base * pool_scale // 2)
    k_noun = min(len(nouns_all), base * pool_scale)
    k_verb = min(len(verbs_all), base * pool_scale // 2)
    k_pseudo = min(len(pseudo_all), max(800, base * pool_scale * 2))
    k_tag = min(len(tags_all), max(600, base * pool_scale))

    def without_blacklisted(src: List[str], pool_name: str) -> List[str]:
        if not token_blacklist:
            return src
        out = []
        for w in src:
            if normalize_token(w) not in token_blacklist:
                out.append(w)
        if out:
            return out
        raise RuntimeError(
            f"Token blacklist exhausted the '{pool_name}' pool. "
            "Use a different token blacklist file for this persona, clear/rotate it, "
            "or pass --no-token-block."
        )

    adj_src = without_blacklisted(adjectives_all, "adjectives")
    noun_src = without_blacklisted(nouns_all, "nouns")
    verb_src = without_blacklisted(verbs_all, "verbs")
    pseudo_src = without_blacklisted(pseudo_all, "pseudowords")
    tag_src = without_blacklisted(tags_all, "tags")

    return RunPools(
        adjectives=_secure_sample(adj_src, k_adj),
        nouns=_secure_sample(noun_src, k_noun),
        verbs=_secure_sample(verb_src, k_verb),
        pseudos=_secure_sample(pseudo_src, k_pseudo),
        tags=_secure_sample(tag_src, k_tag),
    )


__all__ = [
    "normalize_token",
    "dedupe_keep_order",
    "ADJ_CORE",
    "NOUN_CORE",
    "VERB_CORE",
    "SYLLABLES_EXT",
    "build_pseudowords_from_syllables",
    "enforce_disjoint_pools",
    "RunPools",
    "build_run_pools",
]
