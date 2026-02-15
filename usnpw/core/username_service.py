from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from usnpw.core import username_engine as engine
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


def generate_usernames(request: UsernameRequest) -> UsernameResult:
    request = apply_safe_mode_overrides(request)
    if request.count <= 0:
        raise ValueError("count must be > 0")

    if request.min_len <= 0 or request.max_len <= 0:
        raise ValueError("--min-len and --max-len must be > 0")
    if request.min_len > request.max_len:
        raise ValueError("--min-len cannot be greater than --max-len")

    if not (0.10 <= request.max_scheme_pct <= 0.80):
        raise ValueError("--max-scheme-pct must be between 0.10 and 0.80")

    if not (1 <= request.pool_scale <= 6):
        raise ValueError("--pool-scale must be between 1 and 6")

    if request.profile not in engine.PLATFORM_POLICIES:
        raise ValueError(f"Unknown profile: {request.profile}")
    if request.uniqueness_mode not in ("blacklist", "stream"):
        raise ValueError(f"Unknown uniqueness mode: {request.uniqueness_mode}")

    policy = engine.PLATFORM_POLICIES[request.profile]
    effective_min_len = max(request.min_len, policy.min_len)
    effective_max_len = min(request.max_len, policy.max_len)
    if effective_min_len > effective_max_len:
        raise ValueError(
            f"Length constraints impossible for profile '{request.profile}': "
            f"effective min {effective_min_len} > effective max {effective_max_len}."
        )

    try:
        bl_path = Path(request.blacklist).expanduser()
        username_blacklist_lock: Optional[engine.StreamStateLock] = None
        token_blacklist_lock: Optional[engine.StreamStateLock] = None
        token_persist_enabled = (
            not request.no_token_block
            and not request.no_token_save
            and (request.uniqueness_mode == "blacklist" or request.stream_save_tokens)
        )
        if request.uniqueness_mode == "blacklist" and not request.no_save:
            # Threat model: in blacklist mode with persistence enabled, load+append must be
            # serialized across processes to avoid duplicate admissions from stale in-memory sets.
            try:
                username_blacklist_lock = engine.acquire_stream_state_lock(bl_path)
            except (OSError, ValueError) as exc:
                raise ValueError(f"Unable to acquire username blacklist lock '{bl_path}': {exc}") from exc

        token_path = Path(request.token_blacklist).expanduser()
        if token_persist_enabled:
            # Threat model: token-block uniqueness should remain stable across concurrent
            # writers when persistence is enabled, so load+append is serialized.
            try:
                token_blacklist_lock = engine.acquire_stream_state_lock(token_path)
            except (OSError, ValueError) as exc:
                raise ValueError(f"Unable to acquire token blacklist lock '{token_path}': {exc}") from exc

        username_blacklist: Set[str] = set()
        if request.uniqueness_mode == "blacklist":
            username_blacklist = {
                engine.normalize_username_key(u, case_insensitive=policy.case_insensitive)
                for u in engine.load_lineset(bl_path, "username blacklist")
                if engine.normalize_username_key(u, case_insensitive=policy.case_insensitive)
            }

        token_blacklist: Set[str] = set()
        if not request.no_token_block:
            token_blacklist = {
                engine.normalize_token(t) for t in engine.load_lineset(token_path, "token blacklist") if engine.normalize_token(t)
            }

        schemes = []
        for scheme in engine.DEFAULT_SCHEMES:
            if scheme.name == "initials_style":
                if request.initials_weight <= 0:
                    continue
                schemes.append(engine.Scheme(scheme.name, float(request.initials_weight), scheme.builder))
            else:
                schemes.append(scheme)

        if not schemes:
            raise ValueError("No schemes enabled. (Did you set --initials-weight 0 and remove everything?)")

        try:
            pools = engine.build_run_pools(
                count=request.count,
                pool_scale=request.pool_scale,
                token_blacklist=token_blacklist if not request.no_token_block else set(),
            )
        except RuntimeError as exc:
            raise ValueError(str(exc)) from exc

        state = engine.GenState(
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

        token_cap: Optional[int] = None
        if block_tokens:
            token_cap = engine.max_token_block_count(
                pools=pools,
                schemes=schemes,
                max_scheme_pct=request.max_scheme_pct,
            )
            if token_cap is not None and request.count > token_cap:
                suggested = max(1, int(token_cap * 0.82))
                raise ValueError(
                    "Requested --count exceeds token-block theoretical capacity for this run: "
                    f"requested={request.count}, theoretical_max={token_cap}. "
                    "Token blocking requires fresh component tokens per username, and the "
                    "current scheme quota + pool sizes cannot satisfy a larger batch. "
                    f"Available pools after token filtering: adj={len(pools.adjectives)}, "
                    f"noun={len(pools.nouns)}, verb={len(pools.verbs)}, pseudo={len(pools.pseudos)}. "
                    f"Practical stable target is often lower; try --count <= {suggested}. "
                    "Use a smaller --count, rotate/clear --token-blacklist, increase "
                    "--max-scheme-pct, or pass --no-token-block."
                )

        records: List[UsernameRecord] = []
        tokens_to_save: Set[str] = set()
        stream_state_path: Optional[Path] = None
        stream_state_persistent = False
        stream_root_secret = b""
        stream_key = b""
        stream_tag_map: Dict[str, str] = {}
        stream_counter = 0
        stream_lock: Optional[engine.StreamStateLock] = None

        try:
            if request.uniqueness_mode == "stream":
                stream_state_persistent = request.stream_state_persist and (
                    os.name == "nt" or request.allow_plaintext_stream_state
                )
                if stream_state_persistent:
                    if request.stream_state:
                        stream_state_path = Path(request.stream_state).expanduser()
                    else:
                        stream_state_path = Path.home() / f".opsec_username_stream_{request.profile}.json"

                    try:
                        stream_lock = engine.acquire_stream_state_lock(stream_state_path)
                    except OSError as exc:
                        raise ValueError(f"Unable to acquire stream state lock '{stream_state_path}': {exc}") from exc
                    try:
                        stream_root_secret, stream_counter = engine.load_or_init_stream_state(
                            stream_state_path,
                            allow_plaintext=request.allow_plaintext_stream_state,
                        )
                    except OSError as exc:
                        raise ValueError(f"Unable to initialize stream state '{stream_state_path}': {exc}") from exc
                else:
                    stream_root_secret = os.urandom(32)
                    stream_counter = 0
                stream_key = engine.derive_stream_profile_key(stream_root_secret, request.profile)
                stream_tag_map = engine.derive_stream_tag_map(stream_key)

            for _ in range(request.count):
                if request.uniqueness_mode == "stream":
                    if stream_state_persistent and stream_lock is not None:
                        engine.touch_stream_state_lock(stream_lock)
                    try:
                        (
                            username,
                            scheme_name,
                            sep_used,
                            case_style_used,
                            used_tokens,
                            stream_counter,
                        ) = engine.generate_stream_unique(
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
                        if block_tokens:
                            raise ValueError(
                                engine.token_saturation_message(
                                    requested=request.count,
                                    generated=len(records),
                                    token_cap=token_cap,
                                )
                            ) from exc
                        raise ValueError(str(exc)) from exc

                    if stream_state_persistent and stream_state_path is not None:
                        try:
                            engine.save_stream_state(
                                stream_state_path,
                                stream_root_secret,
                                stream_counter,
                                allow_plaintext=request.allow_plaintext_stream_state,
                            )
                        except OSError as exc:
                            raise ValueError(f"Unable to save stream state '{stream_state_path}': {exc}") from exc
                else:
                    try:
                        username, scheme_name, sep_used, case_style_used, used_tokens = engine.generate_unique(
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
                        if block_tokens:
                            raise ValueError(
                                engine.token_saturation_message(
                                    requested=request.count,
                                    generated=len(records),
                                    token_cap=token_cap,
                                )
                            ) from exc
                        raise ValueError(str(exc)) from exc

                records.append(
                    UsernameRecord(
                        username=username,
                        scheme=scheme_name,
                        separator=sep_used,
                        case_style=case_style_used,
                    )
                )

                if request.uniqueness_mode == "blacklist":
                    username_key = engine.normalize_username_key(username, case_insensitive=policy.case_insensitive)
                    username_blacklist.add(username_key)
                    if not request.no_save:
                        engine.append_line(bl_path, username_key)

                if block_tokens and used_tokens:
                    tokens_to_save |= used_tokens
                    token_blacklist |= used_tokens

            should_persist_tokens = (
                block_tokens
                and tokens_to_save
                and not request.no_token_save
                and (request.uniqueness_mode == "blacklist" or request.stream_save_tokens)
            )
            if should_persist_tokens:
                token_path.parent.mkdir(parents=True, exist_ok=True)
                with token_path.open("a", encoding="utf-8", newline="\n") as handle:
                    for token in sorted(tokens_to_save):
                        handle.write(token + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                engine.fsync_parent_directory(token_path)

            return UsernameResult(
                records=tuple(records),
                effective_min_len=effective_min_len,
                effective_max_len=effective_max_len,
                token_cap=token_cap,
            )
        finally:
            if stream_lock is not None:
                engine.release_stream_state_lock(stream_lock)
            if token_blacklist_lock is not None:
                engine.release_stream_state_lock(token_blacklist_lock)
            if username_blacklist_lock is not None:
                engine.release_stream_state_lock(username_blacklist_lock)
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"I/O failure during username generation: {exc}") from exc
