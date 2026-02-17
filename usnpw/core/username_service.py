from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

from usnpw.core import username_generation, username_lexicon, username_policies, username_schemes
from usnpw.core import username_storage, username_stream_state, username_uniqueness
from usnpw.core.models import (
    USERNAME_DEFAULT_HISTORY,
    USERNAME_DEFAULT_INITIALS_WEIGHT,
    USERNAME_DEFAULT_MAX_SCHEME_PCT,
    USERNAME_DEFAULT_NO_LEADING_DIGIT,
    USERNAME_DEFAULT_NO_SAVE,
    USERNAME_DEFAULT_NO_TOKEN_SAVE,
    USERNAME_DEFAULT_POOL_SCALE,
    USERNAME_DEFAULT_UNIQUENESS_MODE,
    UsernameRecord,
    UsernameRequest,
    UsernameResult,
    default_stream_state_path,
)


def apply_safe_mode_overrides(request: UsernameRequest) -> UsernameRequest:
    if not request.safe_mode:
        return request
    return replace(
        request,
        uniqueness_mode=USERNAME_DEFAULT_UNIQUENESS_MODE,
        no_save=USERNAME_DEFAULT_NO_SAVE,
        no_token_save=USERNAME_DEFAULT_NO_TOKEN_SAVE,
        no_token_block=False,
        stream_save_tokens=False,
        allow_plaintext_stream_state=False,
        no_leading_digit=USERNAME_DEFAULT_NO_LEADING_DIGIT,
        max_scheme_pct=USERNAME_DEFAULT_MAX_SCHEME_PCT,
        history=USERNAME_DEFAULT_HISTORY,
        pool_scale=USERNAME_DEFAULT_POOL_SCALE,
        initials_weight=USERNAME_DEFAULT_INITIALS_WEIGHT,
        show_meta=False,
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
    if request.uniqueness_mode not in ("blacklist", "stream"):
        raise ValueError(f"Unknown uniqueness mode: {request.uniqueness_mode}")

    policy = username_policies.PLATFORM_POLICIES[request.profile]
    effective_min_len = max(request.min_len, policy.min_len)
    effective_max_len = min(request.max_len, policy.max_len)
    if effective_min_len > effective_max_len:
        raise ValueError(
            f"Length constraints impossible for profile '{request.profile}': "
            f"effective min {effective_min_len} > effective max {effective_max_len}."
        )
    return policy, effective_min_len, effective_max_len


def _load_username_blacklist(
    bl_path: Path,
    *,
    enabled: bool,
    case_insensitive: bool,
) -> set[str]:
    if not enabled:
        return set()

    username_blacklist: set[str] = set()
    for username in username_storage.load_lineset(bl_path, "username blacklist"):
        key = username_generation.normalize_username_key(username, case_insensitive=case_insensitive)
        if key:
            username_blacklist.add(key)
    return username_blacklist


def _load_token_blacklist(token_path: Path, *, enabled: bool) -> set[str]:
    if not enabled:
        return set()

    token_blacklist: set[str] = set()
    for token in username_storage.load_lineset(token_path, "token blacklist"):
        normalized = username_lexicon.normalize_token(token)
        if normalized:
            token_blacklist.add(normalized)
    return token_blacklist


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
    if block_tokens:
        return ValueError(
            username_uniqueness.token_saturation_message(
                requested=requested,
                generated=generated,
                token_cap=token_cap,
            )
        )
    return ValueError(str(exc))


def generate_usernames(request: UsernameRequest) -> UsernameResult:
    request = apply_safe_mode_overrides(request)
    policy, effective_min_len, effective_max_len = _validate_request(request)

    try:
        bl_path = Path(request.blacklist).expanduser()
        username_blacklist_lock: username_stream_state.StreamStateLock | None = None
        token_blacklist_lock: username_stream_state.StreamStateLock | None = None
        token_persist_enabled = (
            not request.no_token_block
            and not request.no_token_save
            and (request.uniqueness_mode == "blacklist" or request.stream_save_tokens)
        )
        if request.uniqueness_mode == "blacklist" and not request.no_save:
            # Threat model: in blacklist mode with persistence enabled, load+append must be
            # serialized across processes to avoid duplicate admissions from stale in-memory sets.
            try:
                username_blacklist_lock = username_stream_state.acquire_stream_state_lock(bl_path)
            except (OSError, ValueError) as exc:
                raise ValueError(f"Unable to acquire username blacklist lock '{bl_path}': {exc}") from exc

        token_path = Path(request.token_blacklist).expanduser()
        if token_persist_enabled:
            # Threat model: token-block uniqueness should remain stable across concurrent
            # writers when persistence is enabled, so load+append is serialized.
            try:
                token_blacklist_lock = username_stream_state.acquire_stream_state_lock(token_path)
            except (OSError, ValueError) as exc:
                raise ValueError(f"Unable to acquire token blacklist lock '{token_path}': {exc}") from exc

        username_blacklist = _load_username_blacklist(
            bl_path,
            enabled=request.uniqueness_mode == "blacklist",
            case_insensitive=policy.case_insensitive,
        )
        token_blacklist = _load_token_blacklist(token_path, enabled=not request.no_token_block)
        schemes = _build_schemes(request.initials_weight)

        try:
            pools = username_lexicon.build_run_pools(
                count=request.count,
                pool_scale=request.pool_scale,
                token_blacklist=token_blacklist if not request.no_token_block else set(),
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
        block_tokens = not request.no_token_block
        disallow_prefixes = list(request.disallow_prefix)
        if request.no_leading_digit:
            disallow_prefixes.extend(str(d) for d in range(10))
        effective_disallow_prefixes = tuple(disallow_prefixes)
        effective_disallow_substrings = tuple(request.disallow_substring)

        token_cap: int | None = None
        if block_tokens:
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
                    "Token blocking requires fresh component tokens per username, and the "
                    "current available token pools cannot satisfy a larger batch. "
                    f"Available pools after token filtering: adj={len(pools.adjectives)}, "
                    f"noun={len(pools.nouns)}, verb={len(pools.verbs)}, pseudo={len(pools.pseudos)}. "
                    f"Practical stable target is often lower; try count <= {suggested}. "
                    "Use a smaller count, rotate or clear token_blacklist, increase "
                    "pool_scale, or disable token blocking."
                )

        records: list[UsernameRecord] = []
        usernames_to_save: list[str] = []
        tokens_to_save: set[str] = set()
        stream_state_path: Path | None = None
        stream_state_persistent = False
        stream_root_secret = b""
        stream_key: bytes
        stream_tag_map: dict[str, str]
        stream_counter: int
        stream_lock: username_stream_state.StreamStateLock | None = None

        try:
            if request.uniqueness_mode == "stream":
                stream_state_persistent = request.stream_state_persist and (
                    os.name == "nt" or request.allow_plaintext_stream_state
                )
                if stream_state_persistent:
                    if request.stream_state:
                        stream_state_path = Path(request.stream_state).expanduser()
                    else:
                        stream_state_path = default_stream_state_path(request.profile)

                    try:
                        stream_lock = username_stream_state.acquire_stream_state_lock(stream_state_path)
                    except OSError as exc:
                        raise ValueError(f"Unable to acquire stream state lock '{stream_state_path}': {exc}") from exc
                    try:
                        stream_root_secret, stream_counter = username_stream_state.load_or_init_stream_state(
                            stream_state_path,
                            allow_plaintext=request.allow_plaintext_stream_state,
                            strict_windows_acl=request.strict_windows_acl,
                        )
                    except OSError as exc:
                        raise ValueError(f"Unable to initialize stream state '{stream_state_path}': {exc}") from exc
                else:
                    stream_root_secret = os.urandom(32)
                    stream_counter = 0
                stream_key = username_stream_state.derive_stream_profile_key(stream_root_secret, request.profile)
                stream_tag_map = username_stream_state.derive_stream_tag_map(stream_key)
                for _ in range(request.count):
                    if stream_state_persistent and stream_lock is not None:
                        username_stream_state.touch_stream_state_lock(stream_lock)
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
                            block_tokens=block_tokens,
                        )
                    except RuntimeError as exc:
                        raise _generation_error(
                            block_tokens=block_tokens,
                            requested=request.count,
                            generated=len(records),
                            token_cap=token_cap,
                            exc=exc,
                        ) from exc

                    if stream_state_persistent and stream_state_path is not None:
                        try:
                            username_stream_state.save_stream_state(
                                stream_state_path,
                                stream_root_secret,
                                stream_counter,
                                allow_plaintext=request.allow_plaintext_stream_state,
                                strict_windows_acl=request.strict_windows_acl,
                            )
                        except OSError as exc:
                            raise ValueError(f"Unable to save stream state '{stream_state_path}': {exc}") from exc
                    records.append(
                        UsernameRecord(
                            username=username,
                            scheme=scheme_name,
                            separator=sep_used,
                            case_style=case_style_used,
                        )
                    )
                    if block_tokens and used_tokens:
                        tokens_to_save |= used_tokens
                        token_blacklist |= used_tokens
            else:
                for _ in range(request.count):
                    try:
                        (
                            username,
                            scheme_name,
                            sep_used,
                            case_style_used,
                            used_tokens,
                        ) = username_generation.generate_unique(
                            username_blacklist_keys=username_blacklist,
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
                            block_tokens=block_tokens,
                        )
                    except RuntimeError as exc:
                        raise _generation_error(
                            block_tokens=block_tokens,
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
                    username_key = username_generation.normalize_username_key(
                        username,
                        case_insensitive=policy.case_insensitive,
                    )
                    username_blacklist.add(username_key)
                    if not request.no_save:
                        usernames_to_save.append(username_key)
                    if block_tokens and used_tokens:
                        tokens_to_save |= used_tokens
                        token_blacklist |= used_tokens

            should_persist_usernames = not request.no_save and usernames_to_save
            if should_persist_usernames:
                username_storage.append_lines(
                    bl_path,
                    usernames_to_save,
                    strict_windows_acl=request.strict_windows_acl,
                )

            should_persist_tokens = (
                block_tokens
                and tokens_to_save
                and not request.no_token_save
                and (request.uniqueness_mode == "blacklist" or request.stream_save_tokens)
            )
            if should_persist_tokens:
                username_storage.append_lines(
                    token_path,
                    sorted(tokens_to_save),
                    strict_windows_acl=request.strict_windows_acl,
                )

            return UsernameResult(
                records=tuple(records),
                effective_min_len=effective_min_len,
                effective_max_len=effective_max_len,
                token_cap=token_cap,
            )
        finally:
            if stream_lock is not None:
                username_stream_state.release_stream_state_lock(stream_lock)
            if token_blacklist_lock is not None:
                username_stream_state.release_stream_state_lock(token_blacklist_lock)
            if username_blacklist_lock is not None:
                username_stream_state.release_stream_state_lock(username_blacklist_lock)
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"I/O failure during username generation: {exc}") from exc
