from __future__ import annotations

import math
import secrets
import string
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, Dict, List, Optional, Set, Tuple

from usnpw.core.username_lexicon import RunPools, normalize_token


def schoice(seq):
    return seq[secrets.randbelow(len(seq))]


def rand_bool(p_true: float) -> bool:
    return secrets.randbelow(10_000) < int(p_true * 10_000)


def rand_digits(n: int) -> str:
    return "".join(schoice(string.digits) for _ in range(n))


def rand_letters(n: int) -> str:
    alphabet = string.ascii_lowercase
    return "".join(schoice(alphabet) for _ in range(n))


_BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"


def rand_base36(n: int) -> str:
    return "".join(schoice(_BASE36) for _ in range(n))


SAFE_SEPARATORS = ["", "_", "-", "."]
CASE_STYLES = ["lower", "title", "mixed"]


def apply_case_style(parts: List[str], case_style: str) -> List[str]:
    if case_style == "lower":
        return [p.lower() for p in parts]
    if case_style == "title":
        return [(p[:1].upper() + p[1:].lower()) if p else p for p in parts]
    out = []
    for p in parts:
        p = p.lower()
        out.append((p[:1].upper() + p[1:]) if rand_bool(0.35) else p)
    return out


@dataclass
class GenState:
    recent_schemes: List[str]
    recent_seps: List[str]
    recent_case_styles: List[str]
    scheme_counts: Dict[str, int]
    total_target: int
    max_scheme_pct: float

    def push(self, scheme: str, sep: str, case_style: str, history_n: int) -> None:
        def push_list(lst: List[str], val: str):
            lst.append(val)
            if len(lst) > history_n:
                del lst[0]

        push_list(self.recent_schemes, scheme)
        push_list(self.recent_seps, sep)
        push_list(self.recent_case_styles, case_style)
        self.scheme_counts[scheme] = self.scheme_counts.get(scheme, 0) + 1


def choose_nonrecent(seq: List[str], recent: List[str]) -> str:
    candidates = [x for x in seq if x not in recent]
    return schoice(candidates) if candidates else schoice(seq)


def scheme_cap(max_pct: float, total: int) -> int:
    return max(1, int(math.ceil(max_pct * total)))


def add_noise(u: str, sep: str) -> str:
    """
    Add small randomized noise in diverse ways.
    Intentionally avoids always-suffix-digits.
    """
    if not rand_bool(0.55):
        return u

    mode = schoice(["suffix_digits", "prefix_letters", "mid_digits", "suffix_base36", "wrap_tag"])
    if mode == "suffix_digits":
        # lower probability and variable length
        return u + rand_digits(schoice([1, 2, 3]))
    if mode == "prefix_letters":
        # short prefix makes it look more "organic" sometimes
        pre = rand_letters(schoice([1, 2]))
        return pre + u
    if mode == "mid_digits":
        if len(u) < 6:
            return u + rand_digits(2)
        pos = 2 + secrets.randbelow(max(1, len(u) - 3))
        return u[:pos] + rand_digits(schoice([1, 2])) + u[pos:]
    if mode == "suffix_base36":
        # tiny base36 tag
        return u + (sep if sep and rand_bool(0.4) else "") + rand_base36(schoice([2, 3]))
    # wrap_tag
    tag = rand_base36(2) if rand_bool(0.6) else rand_letters(2)
    glue = sep if sep else ""
    if rand_bool(0.5):
        return u + glue + tag
    return tag + glue + u


@dataclass(frozen=True)
class Scheme:
    name: str
    weight: float
    builder: Callable[[GenState, RunPools, int], Tuple[str, str, str, Set[str]]]
    # returns: (raw_username, sep_used, case_style_used, tokens_used)


@dataclass(frozen=True)
class SchemeTokenCosts:
    adj: int
    noun: int
    verb: int
    pseudo: int


SCHEME_TOKEN_COSTS: Dict[str, SchemeTokenCosts] = {
    "adj_noun": SchemeTokenCosts(adj=1, noun=1, verb=0, pseudo=0),
    "verb_noun_tag": SchemeTokenCosts(adj=0, noun=1, verb=1, pseudo=0),
    "pseudoword_pair": SchemeTokenCosts(adj=0, noun=0, verb=0, pseudo=1),
    "compound_3": SchemeTokenCosts(adj=1, noun=2, verb=0, pseudo=0),
    "initials_style": SchemeTokenCosts(adj=1, noun=1, verb=0, pseudo=0),
}


def scheme_adj_noun(state: GenState, pools: RunPools, history_n: int) -> Tuple[str, str, str, Set[str]]:
    sep = choose_nonrecent(SAFE_SEPARATORS, state.recent_seps)
    case_style = choose_nonrecent(CASE_STYLES, state.recent_case_styles)

    a = schoice(pools.adjectives)
    n = schoice(pools.nouns)
    parts = apply_case_style([a, n], case_style)
    u = sep.join(parts)
    u = add_noise(u, sep)

    return u, sep, case_style, {normalize_token(a), normalize_token(n)}


def scheme_verb_noun_tag(state: GenState, pools: RunPools, history_n: int) -> Tuple[str, str, str, Set[str]]:
    sep = choose_nonrecent(SAFE_SEPARATORS, state.recent_seps)
    case_style = choose_nonrecent(CASE_STYLES, state.recent_case_styles)

    v = schoice(pools.verbs)
    n = schoice(pools.nouns)
    parts = apply_case_style([v, n], case_style)
    core = sep.join(parts)

    # tag from dedicated pool or small alpha/base36
    tag = schoice([schoice(pools.tags), rand_base36(2), rand_letters(2), rand_letters(3)])
    glue = sep if sep else ""
    if rand_bool(0.55):
        u = core + glue + tag
    else:
        u = core + tag

    u = add_noise(u, sep)
    return u, sep, case_style, {normalize_token(v), normalize_token(n), normalize_token(tag)}


def scheme_pseudoword_pair(state: GenState, pools: RunPools, history_n: int) -> Tuple[str, str, str, Set[str]]:
    sep = choose_nonrecent(SAFE_SEPARATORS, state.recent_seps)
    case_style = choose_nonrecent(CASE_STYLES, state.recent_case_styles)

    w1 = schoice(pools.pseudos)
    tokens = {normalize_token(w1)}

    if rand_bool(0.45):
        w2 = schoice(pools.pseudos)
        tokens.add(normalize_token(w2))
        parts = apply_case_style([w1, w2], case_style)
        u = sep.join(parts)
    else:
        u = apply_case_style([w1], case_style)[0]

    u = add_noise(u, sep)
    return u, sep, case_style, tokens


def scheme_compound_3(state: GenState, pools: RunPools, history_n: int) -> Tuple[str, str, str, Set[str]]:
    sep = choose_nonrecent(SAFE_SEPARATORS, state.recent_seps)
    case_style = choose_nonrecent(CASE_STYLES, state.recent_case_styles)

    a = schoice(pools.adjectives)
    n1 = schoice(pools.nouns)
    n2 = schoice(pools.nouns)
    parts = apply_case_style([a, n1, n2], case_style)
    u = sep.join(parts)
    u = add_noise(u, sep)

    return u, sep, case_style, {normalize_token(a), normalize_token(n1), normalize_token(n2)}


def scheme_initials_style(state: GenState, pools: RunPools, history_n: int) -> Tuple[str, str, str, Set[str]]:
    """
    This is the most clusterable scheme, so we keep it available but low-weight by default.
    Also: we avoid the obvious "aa_word" pattern by changing structure more aggressively.
    """
    sep = choose_nonrecent(SAFE_SEPARATORS, state.recent_seps)
    case_style = choose_nonrecent(CASE_STYLES, state.recent_case_styles)

    a = schoice(pools.adjectives).lower()
    n = schoice(pools.nouns).lower()
    initials = (a[0] + n[0]).lower()

    # Use a pseudo token sometimes to break the "2 letters + English" silhouette
    core = schoice([schoice(pools.pseudos), n, a + n, n + a])

    # Add variability in placement and separators
    if rand_bool(0.5):
        parts = [initials, core]
    else:
        parts = [core, initials]

    parts = apply_case_style(parts, case_style)
    u = sep.join(parts) if sep else "".join(parts)

    # Avoid year-ish: never add 4 digits; if 2 digits start with 19/20, reroll
    if rand_bool(0.35):
        num_len = schoice([1, 2, 3])
        num = rand_digits(num_len)
        if num.startswith(("19", "20")) and len(num) >= 2:
            num = rand_digits(num_len)
        u = u + (sep + num if sep and rand_bool(0.5) else num)

    u = add_noise(u, sep)
    return u, sep, case_style, {normalize_token(a), normalize_token(n), normalize_token(core), normalize_token(initials)}


_DEFAULT_SCHEMES: List[Scheme] = [
    Scheme("adj_noun", 1.00, scheme_adj_noun),
    Scheme("verb_noun_tag", 1.00, scheme_verb_noun_tag),
    Scheme("pseudoword_pair", 1.00, scheme_pseudoword_pair),
    Scheme("compound_3", 0.90, scheme_compound_3),
    Scheme("initials_style", 0.12, scheme_initials_style),  # intentionally low
]

DEFAULT_SCHEMES: List[Scheme] = _DEFAULT_SCHEMES


def pick_scheme(state: GenState, schemes: List[Scheme]) -> Scheme:
    cap = scheme_cap(state.max_scheme_pct, state.total_target)

    eligible = [s for s in schemes if state.scheme_counts.get(s.name, 0) < cap]
    if not eligible:
        eligible = schemes[:]

    nonrecent = [s for s in eligible if s.name not in state.recent_schemes]
    pool = nonrecent if nonrecent else eligible

    # Weighted by (base weight) * (preference for less used)
    weights = []
    for s in pool:
        used = state.scheme_counts.get(s.name, 0)
        scarcity = max(1.0, (cap - used + 1))
        w = max(0.01, s.weight) * scarcity
        weights.append(w)

    total = sum(weights)
    r = secrets.randbelow(10_000_000) / 10_000_000.0 * total
    acc = 0.0
    for s, w in zip(pool, weights):
        acc += w
        if r <= acc:
            return s
    return pool[-1]


def max_token_block_count(
    pools: RunPools,
    schemes: List[Scheme],
    max_scheme_pct: float,
) -> Optional[int]:
    """
    Compute maximum feasible --count under token blocking for known schemes.
    Returns None if unknown scheme names are present.
    """
    enabled = {s.name for s in schemes}
    if any(name not in SCHEME_TOKEN_COSTS for name in enabled):
        return None

    a_total = len(pools.adjectives)
    n_total = len(pools.nouns)
    v_total = len(pools.verbs)
    p_total = len(pools.pseudos)

    no_cap_upper = 0
    if "adj_noun" in enabled:
        no_cap_upper += min(a_total, n_total)
    if "verb_noun_tag" in enabled:
        no_cap_upper += min(v_total, n_total)
    if "pseudoword_pair" in enabled:
        no_cap_upper += p_total
    if "compound_3" in enabled:
        no_cap_upper += min(a_total, n_total // 2)
    if "initials_style" in enabled:
        no_cap_upper += min(a_total, n_total)

    if no_cap_upper <= 0:
        return 0

    @lru_cache(maxsize=None)
    def feasible(target: int) -> bool:
        if target <= 0:
            return True

        cap = scheme_cap(max_scheme_pct, target)

        u_adj = min(cap, a_total, n_total) if "adj_noun" in enabled else 0
        u_verb = min(cap, v_total, n_total) if "verb_noun_tag" in enabled else 0
        u_pseudo = min(cap, p_total) if "pseudoword_pair" in enabled else 0
        u_compound = min(cap, a_total, n_total // 2) if "compound_3" in enabled else 0
        u_initials = min(cap, a_total, n_total) if "initials_style" in enabled else 0

        if target > (u_adj + u_verb + u_pseudo + u_compound + u_initials):
            return False

        # Loop over the two schemes that have unique noun pressure.
        for x_compound in range(u_compound, -1, -1):
            rem_adj = a_total - x_compound
            rem_noun = n_total - (2 * x_compound)
            if rem_adj < 0 or rem_noun < 0:
                continue

            u_verb_here = min(u_verb, rem_noun)
            for x_verb in range(u_verb_here, -1, -1):
                rem_noun2 = rem_noun - x_verb
                if rem_noun2 < 0:
                    continue

                # x_adj + x_initials share identical (adj=1, noun=1) costs.
                y_max = min(rem_adj, rem_noun2, u_adj + u_initials)
                y_min = max(0, target - x_compound - x_verb - u_pseudo)
                y_hi = min(y_max, target - x_compound - x_verb)

                if y_min <= y_hi:
                    return True

        return False

    lo, hi = 0, no_cap_upper
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if feasible(mid):
            lo = mid
        else:
            hi = mid - 1
    return lo


__all__ = [
    "SAFE_SEPARATORS",
    "CASE_STYLES",
    "GenState",
    "Scheme",
    "SchemeTokenCosts",
    "SCHEME_TOKEN_COSTS",
    "apply_case_style",
    "choose_nonrecent",
    "scheme_cap",
    "add_noise",
    "scheme_adj_noun",
    "scheme_verb_noun_tag",
    "scheme_pseudoword_pair",
    "scheme_compound_3",
    "scheme_initials_style",
    "DEFAULT_SCHEMES",
    "pick_scheme",
    "max_token_block_count",
]
