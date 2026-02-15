from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Optional, Pattern, Tuple


@dataclass(frozen=True)
class PlatformPolicy:
    min_len: int
    max_len: int
    lowercase: bool
    case_insensitive: bool
    disallow_re: Pattern[str]
    collapse_re: Optional[Pattern[str]]
    trim_chars: str
    separators: Tuple[str, ...]


PLATFORM_POLICIES: Dict[str, PlatformPolicy] = {
    "generic": PlatformPolicy(
        min_len=1,
        max_len=32,
        lowercase=False,
        case_insensitive=True,
        disallow_re=re.compile(r"[^A-Za-z0-9._-]+"),
        collapse_re=re.compile(r"[._-]{2,}"),
        trim_chars="._-",
        separators=("", "_", "-", "."),
    ),
    "reddit": PlatformPolicy(
        min_len=3,
        max_len=20,
        lowercase=False,
        case_insensitive=True,
        disallow_re=re.compile(r"[^A-Za-z0-9_-]+"),
        collapse_re=re.compile(r"[_-]{2,}"),
        trim_chars="_-",
        separators=("", "_", "-"),
    ),
    "x": PlatformPolicy(
        min_len=4,
        max_len=15,
        lowercase=True,
        case_insensitive=True,
        disallow_re=re.compile(r"[^A-Za-z0-9_]+"),
        collapse_re=re.compile(r"[_]{2,}"),
        trim_chars="_",
        separators=("", "_"),
    ),
    "github": PlatformPolicy(
        min_len=1,
        max_len=39,
        lowercase=True,
        case_insensitive=True,
        disallow_re=re.compile(r"[^a-z0-9-]+"),
        collapse_re=re.compile(r"[-]{2,}"),
        trim_chars="-",
        separators=("", "-"),
    ),
    "discord": PlatformPolicy(
        min_len=2,
        max_len=32,
        lowercase=True,
        case_insensitive=True,
        disallow_re=re.compile(r"[^a-z0-9._]+"),
        collapse_re=re.compile(r"[._]{2,}"),
        trim_chars="._",
        separators=("", "_", "."),
    ),
    "facebook": PlatformPolicy(
        min_len=5,
        max_len=50,
        lowercase=True,
        case_insensitive=True,
        disallow_re=re.compile(r"[^a-z0-9.]+"),
        collapse_re=re.compile(r"[.]{2,}"),
        trim_chars=".",
        separators=("", "."),
    ),
    "linkedin": PlatformPolicy(
        min_len=3,
        max_len=100,
        lowercase=True,
        case_insensitive=True,
        disallow_re=re.compile(r"[^a-z0-9-]+"),
        collapse_re=re.compile(r"[-]{2,}"),
        trim_chars="-",
        separators=("", "-"),
    ),
    "instagram": PlatformPolicy(
        min_len=3,
        max_len=30,
        lowercase=True,
        case_insensitive=True,
        disallow_re=re.compile(r"[^a-z0-9._]+"),
        collapse_re=re.compile(r"[._]{2,}"),
        trim_chars="._",
        separators=("", "_", "."),
    ),
    "tiktok": PlatformPolicy(
        min_len=2,
        max_len=24,
        lowercase=True,
        case_insensitive=True,
        disallow_re=re.compile(r"[^a-z0-9._]+"),
        collapse_re=re.compile(r"[._]{2,}"),
        trim_chars="._",
        separators=("", "_", "."),
    ),
    "pinterest": PlatformPolicy(
        min_len=3,
        max_len=30,
        lowercase=True,
        case_insensitive=True,
        disallow_re=re.compile(r"[^a-z0-9_]+"),
        collapse_re=re.compile(r"[_]{2,}"),
        trim_chars="_",
        separators=("", "_"),
    ),
    "snapchat": PlatformPolicy(
        min_len=3,
        max_len=15,
        lowercase=True,
        case_insensitive=True,
        disallow_re=re.compile(r"[^a-z0-9._-]+"),
        collapse_re=re.compile(r"[._-]{2,}"),
        trim_chars="._-",
        separators=("", "_", "-", "."),
    ),
    "telegram": PlatformPolicy(
        min_len=5,
        max_len=32,
        lowercase=True,
        case_insensitive=True,
        disallow_re=re.compile(r"[^a-z0-9_]+"),
        collapse_re=re.compile(r"[_]{2,}"),
        trim_chars="_",
        separators=("", "_"),
    ),
    "douyin": PlatformPolicy(
        min_len=2,
        max_len=24,
        lowercase=True,
        case_insensitive=True,
        disallow_re=re.compile(r"[^a-z0-9._]+"),
        collapse_re=re.compile(r"[._]{2,}"),
        trim_chars="._",
        separators=("", "_", "."),
    ),
    "vk": PlatformPolicy(
        min_len=5,
        max_len=32,
        lowercase=True,
        case_insensitive=True,
        disallow_re=re.compile(r"[^a-z0-9._]+"),
        collapse_re=re.compile(r"[._]{2,}"),
        trim_chars="._",
        separators=("", "_", "."),
    ),
    "youtube": PlatformPolicy(
        min_len=3,
        max_len=30,
        lowercase=True,
        case_insensitive=True,
        disallow_re=re.compile(r"[^a-z0-9._-]+"),
        collapse_re=re.compile(r"[._-]{2,}"),
        trim_chars="._-",
        separators=("", "_", "-", "."),
    ),
}


__all__ = ["PlatformPolicy", "PLATFORM_POLICIES"]
