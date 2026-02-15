#!/usr/bin/env python3
"""Username engine compatibility facade.

This module preserves a stable import/API surface while delegating implementation
to focused core modules:
- `username_lexicon`
- `username_schemes`
- `username_generation`
- `username_uniqueness`
- `username_stream_state`
- `username_storage`
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from usnpw.core import username_generation as generation
from usnpw.core import username_lexicon as lexicon
from usnpw.core import username_schemes as schemes_mod
from usnpw.core import username_storage as storage
from usnpw.core import username_stream_state as stream_state
from usnpw.core import username_uniqueness as uniqueness
from usnpw.core.username_policies import PLATFORM_POLICIES, PlatformPolicy


# -------------------------
# Blacklist persistence
# -------------------------
load_lineset = storage.load_lineset
fsync_parent_directory = storage.fsync_parent_directory
append_line = storage.append_line


def normalize_for_platform(u: str, policy: PlatformPolicy, max_len: int) -> str:
    return generation.normalize_for_platform(u, policy, max_len)


def normalize_token(s: str) -> str:
    return lexicon.normalize_token(s)


def normalize_username_key(s: str, case_insensitive: bool = True) -> str:
    return generation.normalize_username_key(s, case_insensitive)


def dedupe_keep_order(words: List[str]) -> List[str]:
    return lexicon.dedupe_keep_order(words)


# -------------------------
# Lexicon + Pool API (re-exported from dedicated module)
# -------------------------
ADJ_CORE = lexicon.ADJ_CORE
NOUN_CORE = lexicon.NOUN_CORE
VERB_CORE = lexicon.VERB_CORE
SYLLABLES_EXT = lexicon.SYLLABLES_EXT

build_pseudowords_from_syllables = lexicon.build_pseudowords_from_syllables
enforce_disjoint_pools = lexicon.enforce_disjoint_pools

RunPools = lexicon.RunPools
build_run_pools = lexicon.build_run_pools


# -------------------------
# Scheme API (re-exported from dedicated module)
# -------------------------
SAFE_SEPARATORS = schemes_mod.SAFE_SEPARATORS
CASE_STYLES = schemes_mod.CASE_STYLES

GenState = schemes_mod.GenState
Scheme = schemes_mod.Scheme
SchemeTokenCosts = schemes_mod.SchemeTokenCosts
SCHEME_TOKEN_COSTS = schemes_mod.SCHEME_TOKEN_COSTS

apply_case_style = schemes_mod.apply_case_style
choose_nonrecent = schemes_mod.choose_nonrecent
scheme_cap = schemes_mod.scheme_cap
add_noise = schemes_mod.add_noise

scheme_adj_noun = schemes_mod.scheme_adj_noun
scheme_verb_noun_tag = schemes_mod.scheme_verb_noun_tag
scheme_pseudoword_pair = schemes_mod.scheme_pseudoword_pair
scheme_compound_3 = schemes_mod.scheme_compound_3
scheme_initials_style = schemes_mod.scheme_initials_style

DEFAULT_SCHEMES = schemes_mod.DEFAULT_SCHEMES
pick_scheme = schemes_mod.pick_scheme
max_token_block_count = schemes_mod.max_token_block_count


# -------------------------
# Token (sub-word) tracking
# -------------------------
def extract_component_tokens(username: str) -> Set[str]:
    return uniqueness.extract_component_tokens(username, normalize_token=normalize_token)


def has_repeated_component_pattern(username: str) -> bool:
    return uniqueness.has_repeated_component_pattern(username, normalize_token=normalize_token)


# -------------------------
# Stream uniqueness mode
# -------------------------
# Stream-state persistence/scrambling is delegated to a dedicated module.
# Re-exporting here keeps the public core API stable for callers/tests.
StreamStateLock = stream_state.StreamStateLock
acquire_stream_state_lock = stream_state.acquire_stream_state_lock
release_stream_state_lock = stream_state.release_stream_state_lock
touch_stream_state_lock = stream_state.touch_stream_state_lock
load_or_init_stream_state = stream_state.load_or_init_stream_state
save_stream_state = stream_state.save_stream_state
derive_stream_profile_key = stream_state.derive_stream_profile_key
derive_stream_tag_map = stream_state.derive_stream_tag_map
scramble_stream_counter = stream_state.scramble_stream_counter
stream_tag = stream_state.stream_tag


def _contains_subsequence(s: str, subseq: str) -> bool:
    return uniqueness.contains_subsequence(s, subseq)


def apply_stream_tag(core: str, tag: str, policy: PlatformPolicy, max_len: int, selector: int) -> str:
    return uniqueness.apply_stream_tag(core, tag, policy, max_len, selector)

# -------------------------
# Unique generation
# -------------------------
def generate_unique(
    username_blacklist_keys: Set[str],
    token_blacklist: Set[str],
    max_len: int,
    min_len: int,
    policy: PlatformPolicy,
    disallow_prefixes: Tuple[str, ...],
    disallow_substrings: Tuple[str, ...],
    state: GenState,
    schemes: List[Scheme],
    pools: RunPools,
    history_n: int,
    block_tokens: bool,
    attempts: int = 80_000,
) -> Tuple[str, str, str, str, Set[str]]:
    return generation.generate_unique(
        username_blacklist_keys=username_blacklist_keys,
        token_blacklist=token_blacklist,
        max_len=max_len,
        min_len=min_len,
        policy=policy,
        disallow_prefixes=disallow_prefixes,
        disallow_substrings=disallow_substrings,
        state=state,
        schemes=schemes,
        pools=pools,
        history_n=history_n,
        block_tokens=block_tokens,
        attempts=attempts,
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
    state: GenState,
    schemes: List[Scheme],
    pools: RunPools,
    history_n: int,
    block_tokens: bool,
    attempts: int = 2000,
) -> Tuple[str, str, str, str, Set[str], int]:
    return generation.generate_stream_unique(
        stream_key=stream_key,
        stream_tag_map=stream_tag_map,
        stream_counter=stream_counter,
        token_blacklist=token_blacklist,
        max_len=max_len,
        min_len=min_len,
        policy=policy,
        disallow_prefixes=disallow_prefixes,
        disallow_substrings=disallow_substrings,
        state=state,
        schemes=schemes,
        pools=pools,
        history_n=history_n,
        block_tokens=block_tokens,
        attempts=attempts,
    )


def token_saturation_message(requested: int, generated: int, token_cap: Optional[int]) -> str:
    return uniqueness.token_saturation_message(requested, generated, token_cap)
