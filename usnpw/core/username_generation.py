from __future__ import annotations

import hashlib
import hmac
from typing import Callable, Dict, List, Set, Tuple

from usnpw.core import username_lexicon as lexicon
from usnpw.core import username_schemes as schemes_mod
from usnpw.core import username_stream_state as stream_state
from usnpw.core import username_uniqueness as uniqueness
from usnpw.core.username_policies import PlatformPolicy


def _encode_counter_bytes(counter: int) -> bytes:
    if counter < 0:
        raise ValueError("stream counter must be non-negative")
    width = max(1, (counter.bit_length() + 7) // 8)
    return counter.to_bytes(width, "big")


def normalize_for_platform(u: str, policy: PlatformPolicy, max_len: int) -> str:
    if policy.lowercase:
        u = u.lower()
    u = policy.disallow_re.sub("", u)
    if policy.collapse_re:
        u = policy.collapse_re.sub(lambda m: m.group(0)[0], u)
    if policy.trim_chars:
        u = u.strip(policy.trim_chars)
    u = u[:max_len]
    # Truncation can expose trailing separators again (e.g., "name.part" -> "name.").
    if policy.trim_chars:
        u = u.strip(policy.trim_chars)
    return u


def normalize_username_key(s: str, case_insensitive: bool = True) -> str:
    s = s.strip()
    if case_insensitive:
        return s.lower()
    return s


def generate_unique(
    username_blacklist_keys: Set[str],
    token_blacklist: Set[str],
    max_len: int,
    min_len: int,
    policy: PlatformPolicy,
    disallow_prefixes: Tuple[str, ...],
    disallow_substrings: Tuple[str, ...],
    state: schemes_mod.GenState,
    schemes: List[schemes_mod.Scheme],
    pools: lexicon.RunPools,
    history_n: int,
    block_tokens: bool,
    attempts: int = 80_000,
    *,
    push_state: bool = True,
    username_key_hasher: Callable[[str], str] | None = None,
) -> Tuple[str, str, str, str, Set[str]]:
    if policy.case_insensitive:
        prefixes = tuple(p.lower() for p in disallow_prefixes if p)
        subs = tuple(sub.lower() for sub in disallow_substrings if sub)
    else:
        prefixes = tuple(p for p in disallow_prefixes if p)
        subs = tuple(sub for sub in disallow_substrings if sub)

    for _ in range(attempts):
        scheme = schemes_mod.pick_scheme(state, schemes)
        raw_u, sep_used, case_style_used, tokens_used = scheme.builder(state, pools, history_n)

        u = normalize_for_platform(raw_u, policy=policy, max_len=max_len)
        if not u or len(u) < min_len:
            continue
        if uniqueness.has_repeated_component_pattern(u, normalize_token=lexicon.normalize_token):
            continue

        ul = u.lower() if policy.case_insensitive else u

        if any(ul.startswith(p) for p in prefixes):
            continue
        if any(sub in ul for sub in subs):
            continue
        u_key = normalize_username_key(u, case_insensitive=policy.case_insensitive)
        if u_key in username_blacklist_keys:
            continue
        if username_key_hasher is not None and username_key_hasher(u_key) in username_blacklist_keys:
            continue

        # Block reusable component tokens (optional, but recommended)
        comp_toks = uniqueness.extract_component_tokens(u, normalize_token=lexicon.normalize_token)
        if block_tokens:
            # include builder's internal tokens + extracted tokens
            all_toks = set(tokens_used) | comp_toks
            # if ANY token already blacklisted, reject
            if any(t in token_blacklist for t in all_toks if t):
                continue
        else:
            all_toks = set()

        if push_state:
            state.push(scheme.name, sep_used, case_style_used, history_n)
        return u, scheme.name, sep_used, case_style_used, all_toks

    raise RuntimeError(
        "Failed to generate a unique username within attempt budget. "
        "Try increasing --max-len, lowering --min-len, or relaxing constraints."
    )


def generate_stream_unique(
    stream_key: bytes,
    stream_tag_map: Dict[str, str],
    stream_counter: int,
    token_blacklist: Set[str],
    max_len: int,
    min_len: int,
    policy: PlatformPolicy,
    disallow_prefixes: Tuple[str, ...],
    disallow_substrings: Tuple[str, ...],
    state: schemes_mod.GenState,
    schemes: List[schemes_mod.Scheme],
    pools: lexicon.RunPools,
    history_n: int,
    block_tokens: bool,
    attempts: int = 2000,
) -> Tuple[str, str, str, str, Set[str], int]:
    if stream_counter < 0:
        raise ValueError("stream counter must be non-negative")

    if policy.case_insensitive:
        prefixes = tuple(p.lower() for p in disallow_prefixes if p)
        subs = tuple(s.lower() for s in disallow_substrings if s)
    else:
        prefixes = tuple(p for p in disallow_prefixes if p)
        subs = tuple(s for s in disallow_substrings if s)

    for _ in range(attempts):
        base_u, scheme_name, sep_used, case_style_used, used_tokens = generate_unique(
            username_blacklist_keys=set(),
            token_blacklist=token_blacklist,
            max_len=max_len,
            min_len=1,
            policy=policy,
            disallow_prefixes=tuple(),
            disallow_substrings=tuple(),
            state=state,
            schemes=schemes,
            pools=pools,
            history_n=history_n,
            block_tokens=block_tokens,
            attempts=1200,
            push_state=False,
        )

        counter_bytes = _encode_counter_bytes(stream_counter)
        layout_digest = hmac.new(stream_key, b"layout:" + counter_bytes, hashlib.sha256).digest()
        tag = stream_state.stream_tag(stream_tag_map, stream_counter, scramble_key=stream_key)
        stream_counter += 1

        u = uniqueness.apply_stream_tag(base_u, tag, policy, max_len=max_len, selector=layout_digest[0])
        u = normalize_for_platform(u, policy=policy, max_len=max_len)
        if not u or len(u) < min_len:
            continue
        if not uniqueness.contains_subsequence(u, tag):
            continue

        cmp_u = u.lower() if policy.case_insensitive else u

        if any(cmp_u.startswith(p) for p in prefixes):
            continue
        if any(s in cmp_u for s in subs):
            continue

        state.push(scheme_name, sep_used, case_style_used, history_n)
        return u, scheme_name, sep_used, case_style_used, used_tokens, stream_counter

    raise RuntimeError(
        "Failed to generate a stream-unique username within attempt budget. "
        "Try increasing --max-len, lowering --min-len, or relaxing constraints."
    )


__all__ = [
    "normalize_for_platform",
    "normalize_username_key",
    "generate_unique",
    "generate_stream_unique",
]
