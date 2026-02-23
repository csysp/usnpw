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

    # Stream uniqueness depends on carrying an untruncated counter tag into output.
    # If the tag no longer fits the allowed max length, fail closed for this attempt.
    if len(tag) > max_len:
        return ""

    non_empty_separators = tuple(sep for sep in policy.separators if sep)
    sep = non_empty_separators[selector % len(non_empty_separators)] if non_empty_separators else ""

    # Use three layouts with full contiguous tag placement.
    # This keeps anti-fingerprint variability while preserving a unique tag component.
    mode = selector % 3

    def _compose_without_separator(local_mode: int) -> str:
        core_budget = max_len - len(tag)
        if core_budget <= 0:
            return tag
        core_part = core[:core_budget]
        if local_mode == 0:
            return f"{core_part}{tag}"
        if local_mode == 1:
            return f"{tag}{core_part}"
        left_budget = core_budget // 2
        right_budget = core_budget - left_budget
        left = core_part[:left_budget]
        right = core_part[left_budget : left_budget + right_budget]
        return f"{left}{tag}{right}"

    if mode == 0:
        reserved = len(tag) + (len(sep) if sep else 0)
        if reserved > max_len:
            return _compose_without_separator(0)
        core_budget = max_len - reserved
        core = core[:core_budget]
        return f"{core}{sep}{tag}" if core else tag

    if mode == 1:
        reserved = len(tag) + (len(sep) if sep else 0)
        if reserved > max_len:
            return _compose_without_separator(1)
        core_budget = max_len - reserved
        core = core[:core_budget]
        return f"{tag}{sep}{core}" if core else tag

    if not sep:
        return _compose_without_separator(2)

    reserved = len(tag) + (2 * len(sep))
    if reserved > max_len:
        return _compose_without_separator(2)
    core_budget = max_len - reserved
    left_budget = core_budget // 2
    right_budget = core_budget - left_budget
    left = core[:left_budget]
    right = core[-right_budget:] if right_budget > 0 else ""
    return f"{left}{sep}{tag}{sep}{right}" if (left or right) else tag


def token_saturation_message(requested: int, generated: int, token_cap: int | None) -> str:
    suggested = max(1, int((token_cap or requested) * 0.82))
    cap_part = f"Computed token cap={token_cap}; " if token_cap is not None else ""
    return (
        "Token-block saturation reached before target count. "
        f"requested={requested}, generated={generated}. "
        f"{cap_part}try --count <= {suggested}, increase --pool-scale, "
        "or pass --allow-token-reuse."
    )


__all__ = [
    "extract_component_tokens",
    "has_repeated_component_pattern",
    "contains_subsequence",
    "apply_stream_tag",
    "token_saturation_message",
]
