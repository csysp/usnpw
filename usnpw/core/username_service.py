from __future__ import annotations

import os

from usnpw.core import username_generation, username_lexicon, username_policies, username_schemes
from usnpw.core import username_stream_state, username_uniqueness
from usnpw.core.models import (
    USERNAME_DEFAULT_HISTORY,
    USERNAME_DEFAULT_INITIALS_WEIGHT,
    USERNAME_DEFAULT_MAX_SCHEME_PCT,
    USERNAME_DEFAULT_NO_LEADING_DIGIT,
    USERNAME_DEFAULT_POOL_SCALE,
    UsernameRecord,
    UsernameRequest,
    UsernameResult,
)


def _validate_request(request: UsernameRequest) -> tuple[username_policies.PlatformPolicy, int, int]:
    if request.count <= 0:
        raise ValueError("count must be > 0")

    if request.min_len <= 0 or request.max_len <= 0:
        raise ValueError("min_len and max_len must be > 0")
    if request.min_len > request.max_len:
        raise ValueError("min_len cannot be greater than max_len")

    if not (0.10 <= request.max_scheme_pct <= 0.80):
        raise ValueError("max_scheme_pct must be between 0.10 and 0.80")

    if not (1 <= request.pool_scale <= 6):
        raise ValueError("pool_scale must be between 1 and 6")

    if request.profile not in username_policies.PLATFORM_POLICIES:
        raise ValueError(f"Unknown profile: {request.profile}")

    policy = username_policies.PLATFORM_POLICIES[request.profile]
    effective_min_len = max(request.min_len, policy.min_len)
    effective_max_len = min(request.max_len, policy.max_len)
    if effective_min_len > effective_max_len:
        raise ValueError(
            f"Length constraints impossible for profile '{request.profile}': "
            f"effective min {effective_min_len} > effective max {effective_max_len}."
        )
    return policy, effective_min_len, effective_max_len


def _build_schemes(initials_weight: float) -> list[username_schemes.Scheme]:
    schemes: list[username_schemes.Scheme] = []
    for scheme in username_schemes.DEFAULT_SCHEMES:
        if scheme.name != "initials_style":
            schemes.append(scheme)
            continue
        if initials_weight <= 0:
            continue
        schemes.append(username_schemes.Scheme(scheme.name, float(initials_weight), scheme.builder))
    if not schemes:
        raise ValueError("no schemes enabled after applying initials_weight")
    return schemes


def _generation_error(
    *,
    block_tokens: bool,
    requested: int,
    generated: int,
    token_cap: int | None,
    exc: RuntimeError,
) -> ValueError:
    if block_tokens and str(exc) == username_generation.TOKEN_BLOCK_EXHAUSTION_ERROR:
        return ValueError(
            username_uniqueness.token_saturation_message(
                requested=requested,
                generated=generated,
                token_cap=token_cap,
            )
        )
    return ValueError(str(exc))


def generate_usernames(request: UsernameRequest) -> UsernameResult:
    policy, effective_min_len, effective_max_len = _validate_request(request)
    schemes = _build_schemes(request.initials_weight)

    token_blacklist: set[str] = set()
    try:
        pools = username_lexicon.build_run_pools(
            count=request.count,
            pool_scale=request.pool_scale,
            token_blacklist=token_blacklist if request.block_tokens else set(),
        )
    except RuntimeError as exc:
        raise ValueError(str(exc)) from exc

    state = username_schemes.GenState(
        recent_schemes=[],
        recent_seps=[],
        recent_case_styles=[],
        scheme_counts={},
        total_target=request.count,
        max_scheme_pct=request.max_scheme_pct,
    )
    history_n = max(1, request.history)

    disallow_prefixes = list(request.disallow_prefix)
    if request.no_leading_digit:
        disallow_prefixes.extend(str(digit) for digit in range(10))
    effective_disallow_prefixes = tuple(disallow_prefixes)
    effective_disallow_substrings = tuple(request.disallow_substring)

    token_cap: int | None = None
    if request.block_tokens:
        token_cap = username_schemes.max_token_block_count(
            pools=pools,
            schemes=schemes,
            max_scheme_pct=request.max_scheme_pct,
        )
        if token_cap is not None and request.count > token_cap:
            suggested = max(1, int(token_cap * 0.82))
            raise ValueError(
                "count exceeds token-block theoretical capacity for this run: "
                f"requested={request.count}, theoretical_max={token_cap}. "
                f"Try count <= {suggested}, increase --pool-scale, or pass --allow-token-reuse."
            )

    stream_root_secret = os.urandom(32)
    stream_key = username_stream_state.derive_stream_profile_key(stream_root_secret, request.profile)
    stream_tag_map = username_stream_state.derive_stream_tag_map(stream_key)
    stream_counter = 0
    stream_username_keys: set[str] = set()

    records: list[UsernameRecord] = []
    for _ in range(request.count):
        try:
            (
                username,
                scheme_name,
                sep_used,
                case_style_used,
                used_tokens,
                stream_counter,
            ) = username_generation.generate_stream_unique(
                stream_key=stream_key,
                stream_tag_map=stream_tag_map,
                stream_counter=stream_counter,
                token_blacklist=token_blacklist,
                max_len=effective_max_len,
                min_len=effective_min_len,
                policy=policy,
                disallow_prefixes=effective_disallow_prefixes,
                disallow_substrings=effective_disallow_substrings,
                state=state,
                schemes=schemes,
                pools=pools,
                history_n=history_n,
                block_tokens=request.block_tokens,
                existing_username_keys=stream_username_keys,
            )
        except RuntimeError as exc:
            raise _generation_error(
                block_tokens=request.block_tokens,
                requested=request.count,
                generated=len(records),
                token_cap=token_cap,
                exc=exc,
            ) from exc

        records.append(
            UsernameRecord(
                username=username,
                scheme=scheme_name,
                separator=sep_used,
                case_style=case_style_used,
            )
        )
        if request.block_tokens and used_tokens:
            token_blacklist |= used_tokens

    return UsernameResult(
        records=tuple(records),
        effective_min_len=effective_min_len,
        effective_max_len=effective_max_len,
        token_cap=token_cap if request.block_tokens else None,
    )


__all__ = [
    "USERNAME_DEFAULT_NO_LEADING_DIGIT",
    "USERNAME_DEFAULT_MAX_SCHEME_PCT",
    "USERNAME_DEFAULT_HISTORY",
    "USERNAME_DEFAULT_POOL_SCALE",
    "USERNAME_DEFAULT_INITIALS_WEIGHT",
    "generate_usernames",
]
