from __future__ import annotations

import hashlib
import hmac
from typing import Callable, Dict, List, Set, Tuple

from usnpw.core import username_lexicon as lexicon
from usnpw.core import username_schemes as schemes_mod
from usnpw.core import username_stream_state as stream_state
from usnpw.core import username_uniqueness as uniqueness
from usnpw.core.username_policies import PlatformPolicy

TOKEN_BLOCK_EXHAUSTION_ERROR = "Token-block candidate space exhausted within attempt budget."
UNIQUE_ATTEMPT_BUDGET_ERROR = (
    "Failed to generate a unique username within attempt budget. "
    "Try increasing --max-len, lowering --min-len, or relaxing constraints."
)
STREAM_ATTEMPT_BUDGET_ERROR = (
    "Failed to generate a stream-unique username within attempt budget. "
    "Try increasing --max-len, lowering --min-len, or relaxing constraints."
)
_UNIQUE_ATTEMPT_BUDGET_PREFIX = "Failed to generate a unique username within attempt budget."


def _encode_counter_bytes(counter: int) -> bytes:
    if counter < 0:
        raise ValueError("stream counter must be non-negative")
    width = max(1, (counter.bit_length() + 7) // 8)
    return counter.to_bytes(width, "big")


def _normalized_disallow_filters(
    policy: PlatformPolicy,
    disallow_prefixes: Tuple[str, ...],
    disallow_substrings: Tuple[str, ...],
) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    if policy.case_insensitive:
        prefixes = tuple(p.lower() for p in disallow_prefixes if p)
        subs = tuple(sub.lower() for sub in disallow_substrings if sub)
    else:
        prefixes = tuple(p for p in disallow_prefixes if p)
        subs = tuple(sub for sub in disallow_substrings if sub)
    return prefixes, subs


def _violates_disallow_filters(value: str, prefixes: Tuple[str, ...], subs: Tuple[str, ...]) -> bool:
    if any(value.startswith(p) for p in prefixes):
        return True
    if any(sub in value for sub in subs):
        return True
    return False


def _stream_base_attempts(total_attempts: int, *, block_tokens: bool) -> int:
    """
    Allocate a bounded inner search window for each stream attempt.
    This avoids hard-failing the entire stream on one unlucky candidate window.
    """
    if total_attempts <= 0:
        return 1
    if block_tokens:
        target = min(240, max(1, total_attempts // 8))
    else:
        target = min(120, max(1, total_attempts // 10))
    return max(1, min(total_attempts, target))


def _is_unique_attempt_budget_error(msg: str) -> bool:
    return msg.startswith(_UNIQUE_ATTEMPT_BUDGET_PREFIX)


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
    if not schemes:
        raise RuntimeError("No generation schemes available for username generation.")

    prefixes, subs = _normalized_disallow_filters(policy, disallow_prefixes, disallow_substrings)

    saw_token_conflict = False
    saw_non_token_rejection = False

    for _ in range(attempts):
        scheme = schemes_mod.pick_scheme(state, schemes)
        try:
            raw_u, sep_used, case_style_used, tokens_used = scheme.builder(state, pools, history_n)
        except IndexError as exc:
            raise RuntimeError(
                "Generator pools are empty for the selected scheme; cannot build username candidate."
            ) from exc

        u = normalize_for_platform(raw_u, policy=policy, max_len=max_len)
        if not u or len(u) < min_len:
            saw_non_token_rejection = True
            continue
        if uniqueness.has_repeated_component_pattern(u, normalize_token=lexicon.normalize_token):
            saw_non_token_rejection = True
            continue

        ul = u.lower() if policy.case_insensitive else u

        if _violates_disallow_filters(ul, prefixes, subs):
            saw_non_token_rejection = True
            continue
        u_key = normalize_username_key(u, case_insensitive=policy.case_insensitive)
        if u_key in username_blacklist_keys:
            saw_non_token_rejection = True
            continue
        if username_key_hasher is not None and username_key_hasher(u_key) in username_blacklist_keys:
            saw_non_token_rejection = True
            continue

        # Block reusable component tokens (optional, but recommended)
        if block_tokens:
            comp_toks = uniqueness.extract_component_tokens(u, normalize_token=lexicon.normalize_token)
            # include builder's internal tokens + extracted tokens
            all_toks = set(tokens_used) | comp_toks
            # if ANY token already blacklisted, reject
            if any(t in token_blacklist for t in all_toks if t):
                saw_token_conflict = True
                continue
        else:
            all_toks = set()

        if push_state:
            state.push(scheme.name, sep_used, case_style_used, history_n)
        return u, scheme.name, sep_used, case_style_used, all_toks

    if block_tokens and saw_token_conflict and not saw_non_token_rejection:
        raise RuntimeError(TOKEN_BLOCK_EXHAUSTION_ERROR)

    raise RuntimeError(UNIQUE_ATTEMPT_BUDGET_ERROR)


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
    *,
    existing_username_keys: Set[str] | None = None,
) -> Tuple[str, str, str, str, Set[str], int]:
    if stream_counter < 0:
        raise ValueError("stream counter must be non-negative")

    prefixes, subs = _normalized_disallow_filters(policy, disallow_prefixes, disallow_substrings)
    empty_keys: set[str] = set()
    empty_filters: tuple[str, ...] = tuple()
    base_attempts = _stream_base_attempts(attempts, block_tokens=block_tokens)
    saw_token_exhaustion = False

    for _ in range(attempts):
        try:
            base_u, scheme_name, sep_used, case_style_used, used_tokens = generate_unique(
                username_blacklist_keys=empty_keys,
                token_blacklist=token_blacklist,
                max_len=max_len,
                min_len=1,
                policy=policy,
                disallow_prefixes=empty_filters,
                disallow_substrings=empty_filters,
                state=state,
                schemes=schemes,
                pools=pools,
                history_n=history_n,
                block_tokens=block_tokens,
                attempts=base_attempts,
                push_state=False,
            )
        except RuntimeError as exc:
            msg = str(exc)
            if block_tokens and msg == TOKEN_BLOCK_EXHAUSTION_ERROR:
                saw_token_exhaustion = True
                continue
            if _is_unique_attempt_budget_error(msg):
                continue
            raise

        counter_bytes = _encode_counter_bytes(stream_counter)
        layout_digest = hmac.new(stream_key, b"layout:" + counter_bytes, hashlib.sha256).digest()
        tag = stream_state.stream_tag(stream_tag_map, stream_counter, scramble_key=stream_key)
        if len(tag) > max_len:
            raise RuntimeError(
                "Stream counter exceeded representable space for max_len. "
                "Increase --max-len or start a new run."
            )
        stream_counter += 1

        u = uniqueness.apply_stream_tag(base_u, tag, policy, max_len=max_len, selector=layout_digest[0])
        u = normalize_for_platform(u, policy=policy, max_len=max_len)
        if not u or len(u) < min_len:
            continue
        if tag not in u:
            continue
        if uniqueness.has_repeated_component_pattern(u, normalize_token=lexicon.normalize_token):
            continue

        cmp_u = u.lower() if policy.case_insensitive else u

        if _violates_disallow_filters(cmp_u, prefixes, subs):
            continue

        u_key = normalize_username_key(u, case_insensitive=policy.case_insensitive)
        if existing_username_keys is not None and u_key in existing_username_keys:
            continue

        state.push(scheme_name, sep_used, case_style_used, history_n)
        if existing_username_keys is not None:
            existing_username_keys.add(u_key)
        return u, scheme_name, sep_used, case_style_used, used_tokens, stream_counter

    if block_tokens and saw_token_exhaustion:
        raise RuntimeError(TOKEN_BLOCK_EXHAUSTION_ERROR)

    raise RuntimeError(STREAM_ATTEMPT_BUDGET_ERROR)


__all__ = [
    "TOKEN_BLOCK_EXHAUSTION_ERROR",
    "UNIQUE_ATTEMPT_BUDGET_ERROR",
    "STREAM_ATTEMPT_BUDGET_ERROR",
    "normalize_for_platform",
    "normalize_username_key",
    "generate_unique",
    "generate_stream_unique",
]
