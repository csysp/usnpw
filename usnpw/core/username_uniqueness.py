from __future__ import annotations

import re
from typing import Callable, Set

from usnpw.core.username_policies import PlatformPolicy

_RE_IMMEDIATE_REPEAT = re.compile(r"([a-z0-9]{3,10})\1")


def extract_component_tokens(username: str, *, normalize_token: Callable[[str], str]) -> Set[str]:
    """
    Split by separators and normalize pieces.
    This helps prevent reusing recognizable component tokens across runs.
    """
    parts = re.split(r"[._-]+", username)
    toks = set()
    for p in parts:
        t = normalize_token(p)
        if t and len(t) >= 3:
            toks.add(t)
    return toks


def has_repeated_component_pattern(username: str, *, normalize_token: Callable[[str], str]) -> bool:
    """
    Reject obvious immediate repetition patterns that are easy to cluster.
    Examples: "axis_axis", "axisaxis", "token-token".
    """
    parts = [normalize_token(p) for p in re.split(r"[._-]+", username) if normalize_token(p)]
    for i in range(1, len(parts)):
        if parts[i] == parts[i - 1] and len(parts[i]) >= 3:
            return True

    compact = normalize_token(username)
    if len(compact) >= 6 and _RE_IMMEDIATE_REPEAT.search(compact):
        return True
    return False


def contains_subsequence(s: str, subseq: str) -> bool:
    if not subseq:
        return True
    i = 0
    for ch in s:
        if ch == subseq[i]:
            i += 1
            if i == len(subseq):
                return True
    return False


def apply_stream_tag(core: str, tag: str, policy: PlatformPolicy, max_len: int, selector: int) -> str:
    if max_len <= 0:
        return ""

    sep = policy.separators[selector % len(policy.separators)]
    mode = selector % 4

    # Mode 0/1: classic prefix/suffix, but randomized.
    if mode in (0, 1):
        reserved = len(tag) + (len(sep) if sep else 0)
        if reserved > max_len:
            return tag[:max_len]
        core_budget = max_len - reserved
        core = core[:core_budget]
        if not core:
            return tag
        if mode == 0:
            return f"{core}{sep}{tag}" if sep else f"{core}{tag}"
        return f"{tag}{sep}{core}" if sep else f"{tag}{core}"

    # Mode 2: split tag around core to avoid a single obvious suffix/prefix shape.
    if mode == 2:
        if len(tag) > max_len:
            return tag[:max_len]
        core_budget = max_len - len(tag)
        core = core[:core_budget]
        cut = len(tag) // 2
        return f"{tag[:cut]}{core}{tag[cut:]}"

    # Mode 3: split tag into three segments and weave across core.
    extra_sep = len(sep) * 2 if sep else 0
    reserved = len(tag) + extra_sep
    if reserved > max_len:
        return tag[:max_len]
    core_budget = max_len - reserved
    core = core[:core_budget]
    cut1 = len(tag) // 3
    cut2 = (2 * len(tag)) // 3
    t1 = tag[:cut1]
    t2 = tag[cut1:cut2]
    t3 = tag[cut2:]
    ccut = len(core) // 2
    c1 = core[:ccut]
    c2 = core[ccut:]
    if sep:
        return f"{t1}{c1}{sep}{t2}{c2}{sep}{t3}"
    return f"{t1}{c1}{t2}{c2}{t3}"


def token_saturation_message(requested: int, generated: int, token_cap: int | None) -> str:
    suggested = max(1, int((token_cap or requested) * 0.82))
    cap_part = f"Computed token cap={token_cap}; " if token_cap is not None else ""
    return (
        "Token-block saturation reached before target count. "
        f"requested={requested}, generated={generated}. "
        f"{cap_part}try --count <= {suggested}, rotate/clear --token-blacklist, "
        "increase --max-scheme-pct, or pass --no-token-block."
    )


__all__ = [
    "extract_component_tokens",
    "has_repeated_component_pattern",
    "contains_subsequence",
    "apply_stream_tag",
    "token_saturation_message",
]
