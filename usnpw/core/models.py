from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple


DEFAULT_USERNAME_BLACKLIST = str(Path.home() / ".opsec_username_blacklist.txt")
DEFAULT_USERNAME_TOKENS = str(Path.home() / ".opsec_username_tokens.txt")
USERNAME_DEFAULT_UNIQUENESS_MODE = "stream"
USERNAME_DEFAULT_NO_SAVE = True
USERNAME_DEFAULT_NO_TOKEN_SAVE = True
USERNAME_DEFAULT_NO_LEADING_DIGIT = True
USERNAME_DEFAULT_MAX_SCHEME_PCT = 0.28
USERNAME_DEFAULT_HISTORY = 10
USERNAME_DEFAULT_POOL_SCALE = 4
USERNAME_DEFAULT_INITIALS_WEIGHT = 0.0


def default_stream_state_path(profile: str) -> Path:
    return Path.home() / f".opsec_username_stream_{profile}.json"


@dataclass(frozen=True)
class PasswordRequest:
    count: int = 1
    length: int = 20
    charset: str = ""
    symbols: str = "!@#$%^&*()-_=+[]{};:,?/"
    no_symbols: bool = False
    max_entropy: bool = False
    format: str = "password"
    entropy_bytes: int = 0
    bits: int = 0
    out_enc: str = "hex"
    group: int = 0
    group_sep: str = "-"
    group_pad: str = ""
    words: int = 24
    delim: str = " "
    bip39_wordlist: str = ""


@dataclass(frozen=True)
class PasswordResult:
    outputs: Tuple[str, ...]


@dataclass(frozen=True)
class UsernameRequest:
    count: int = 10
    min_len: int = 8
    max_len: int = 16
    profile: str = "generic"
    safe_mode: bool = False
    uniqueness_mode: str = USERNAME_DEFAULT_UNIQUENESS_MODE
    blacklist: str = DEFAULT_USERNAME_BLACKLIST
    no_save: bool = USERNAME_DEFAULT_NO_SAVE
    token_blacklist: str = DEFAULT_USERNAME_TOKENS
    no_token_save: bool = USERNAME_DEFAULT_NO_TOKEN_SAVE
    no_token_block: bool = False
    stream_save_tokens: bool = False
    stream_state: str = ""
    stream_state_persist: bool = True
    allow_plaintext_stream_state: bool = False
    disallow_prefix: Tuple[str, ...] = ()
    disallow_substring: Tuple[str, ...] = ()
    no_leading_digit: bool = USERNAME_DEFAULT_NO_LEADING_DIGIT
    max_scheme_pct: float = USERNAME_DEFAULT_MAX_SCHEME_PCT
    history: int = USERNAME_DEFAULT_HISTORY
    pool_scale: int = USERNAME_DEFAULT_POOL_SCALE
    initials_weight: float = USERNAME_DEFAULT_INITIALS_WEIGHT
    show_meta: bool = False


@dataclass(frozen=True)
class UsernameRecord:
    username: str
    scheme: str
    separator: str
    case_style: str


@dataclass(frozen=True)
class UsernameResult:
    records: Tuple[UsernameRecord, ...]
    effective_min_len: int
    effective_max_len: int
    token_cap: Optional[int]

    def as_lines(self, show_meta: bool = False) -> Tuple[str, ...]:
        if not show_meta:
            return tuple(r.username for r in self.records)
        return tuple(
            f"{r.username}\t[{r.scheme}] sep='{r.separator}' case='{r.case_style}'"
            for r in self.records
        )
