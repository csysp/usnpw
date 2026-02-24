from __future__ import annotations

from dataclasses import dataclass
import math
import string


LOG2_10 = math.log2(10.0)
SEGMENT_PENALTY_LOG10 = math.log10(10.0)
MAX_MATCH_SEQUENCE_LENGTH = 96
MAX_REPEAT_BLOCK_SCAN = 24

# Clean-room weak-token list inspired by common credential audit findings.
# Threat model rationale:
# - These tokens are heavily over-represented in leaked credentials.
# - Matching them reduces estimated entropy to fail closed on known-bad structure.
COMMON_TOKENS: tuple[str, ...] = (
    "password",
    "passw0rd",
    "admin",
    "administrator",
    "root",
    "user",
    "guest",
    "qwerty",
    "qwertyuiop",
    "asdf",
    "asdfgh",
    "zxcvbn",
    "letmein",
    "welcome",
    "secret",
    "changeme",
    "default",
    "testing",
    "test",
    "demo",
    "temp",
    "iloveyou",
    "monkey",
    "dragon",
    "baseball",
    "football",
    "soccer",
    "master",
    "shadow",
    "sunshine",
    "princess",
    "trustno1",
    "abc123",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "111111",
    "000000",
    "access",
    "login",
    "system",
    "server",
    "network",
    "internet",
    "security",
    "private",
    "public",
    "backup",
    "manager",
    "service",
    "operator",
    "winter",
    "spring",
    "summer",
    "autumn",
    "fall",
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
)
COMMON_TOKEN_RANK = {token: idx + 1 for idx, token in enumerate(COMMON_TOKENS)}

LEET_MAP: dict[str, str] = {
    "0": "o",
    "1": "l",
    "2": "z",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
    "!": "i",
}

_QWERTY_ROWS = ("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm")
_QWERTY_ADJ_CACHE: dict[str, set[str]] | None = None
_QWERTY_START_POSITIONS_CACHE: int | None = None
_QWERTY_AVG_DEGREE_CACHE: float | None = None


@dataclass(frozen=True)
class _Match:
    start: int
    end: int
    log10_guesses: float
    pattern: str


def quality_from_entropy_bits(entropy_bits: float) -> str:
    """Mirror KeePassXC quality bands used by PasswordHealth::quality()."""
    if entropy_bits <= 0:
        return "bad"
    if entropy_bits < 40:
        return "poor"
    if entropy_bits < 75:
        return "weak"
    if entropy_bits < 100:
        return "good"
    return "excellent"


def estimate_theoretical_password_bits(length: int, alphabet: str) -> float:
    unique_hint = len(set(alphabet))
    if length <= 0 or unique_hint < 2:
        return 0.0
    return float(length) * math.log2(unique_hint)


def estimate_pattern_aware_entropy_bits(password: str, alphabet_hint: str) -> float:
    """Estimate per-password entropy using a clean-room match-sequence model.

    Model structure (inspired by zxcvbn concepts, implemented independently):
    - Enumerate pattern matches (dictionary/leet, repeats, sequences, keyboard walks, dates)
    - Add brute-force matches for all substrings
    - Use dynamic programming to select the minimum-guess segmentation
    - Convert guesses to bits, capped by generator-space upper bound from `alphabet_hint`
    """
    if not password:
        return 0.0

    theoretical_bits = estimate_theoretical_password_bits(len(password), alphabet_hint)
    if theoretical_bits <= 0.0:
        return 0.0

    if len(password) > MAX_MATCH_SEQUENCE_LENGTH:
        return _estimate_long_input_entropy_bits(password, theoretical_bits)

    matches = _enumerate_matches(password)
    log10_guesses = _minimum_log10_guesses(password, matches)
    bits = max(0.0, log10_guesses * LOG2_10)
    return min(bits, theoretical_bits)


def _estimate_long_input_entropy_bits(password: str, theoretical_bits: float) -> float:
    """Linear-time fallback for long inputs to keep CLI throughput bounded."""
    bits = theoretical_bits
    bits -= _linear_repeated_run_penalty(password)
    bits -= _linear_sequence_penalty(password)
    bits -= _repeated_block_penalty_lite(password)
    if bits < 0.0:
        return 0.0
    return min(bits, theoretical_bits)


def _enumerate_matches(password: str) -> tuple[_Match, ...]:
    n = len(password)
    dedup: dict[tuple[int, int, str], float] = {}

    for match in _dictionary_matches(password):
        _keep_best_match(dedup, match)
    for match in _repeat_matches(password):
        _keep_best_match(dedup, match)
    for match in _sequence_matches(password):
        _keep_best_match(dedup, match)
    for match in _spatial_matches(password):
        _keep_best_match(dedup, match)
    for match in _date_matches(password):
        _keep_best_match(dedup, match)

    # Brute-force fallback matches for all substrings.
    for start in range(n):
        for end in range(start, n):
            token = password[start : end + 1]
            brute_log10 = _bruteforce_log10(token)
            _keep_best_match(dedup, _Match(start, end, brute_log10, "bruteforce"))

    return tuple(_Match(s, e, lg, p) for (s, e, p), lg in dedup.items())


def _minimum_log10_guesses(password: str, matches: tuple[_Match, ...]) -> float:
    n = len(password)
    by_end: list[list[_Match]] = [[] for _ in range(n)]
    for match in matches:
        by_end[match.end].append(match)

    inf = float("inf")
    dp: list[float] = [inf] * (n + 1)
    dp[0] = 0.0

    for end_idx in range(n):
        best = dp[end_idx + 1]
        for match in by_end[end_idx]:
            prev = dp[match.start]
            if not math.isfinite(prev):
                continue
            # Penalize over-segmentation so fragmented matches do not look artificially strong.
            cand = prev + match.log10_guesses + SEGMENT_PENALTY_LOG10
            if cand < best:
                best = cand
        dp[end_idx + 1] = best

    out = dp[n]
    if not math.isfinite(out):
        # Should be unreachable due to brute-force fallback.
        return _bruteforce_log10(password)
    return out


def _dictionary_matches(password: str) -> tuple[_Match, ...]:
    lowered = password.lower()
    n = len(password)
    out: list[_Match] = []
    for start in range(n):
        for end in range(start + 2, n):
            token = password[start : end + 1]
            token_lc = lowered[start : end + 1]
            rank = COMMON_TOKEN_RANK.get(token_lc)
            leet_hit = False
            if rank is None:
                normalized = _normalize_l33t(token_lc)
                rank = COMMON_TOKEN_RANK.get(normalized)
                leet_hit = rank is not None and normalized != token_lc
            if rank is None:
                continue

            case_var = _case_variations(token)
            leet_var = _leet_variations(token) if leet_hit else 1.0
            guesses = max(1.0, float(rank) * case_var * leet_var)
            out.append(
                _Match(
                    start=start,
                    end=end,
                    log10_guesses=math.log10(guesses),
                    pattern="dictionary",
                )
            )
    return tuple(out)


def _repeat_matches(password: str) -> tuple[_Match, ...]:
    n = len(password)
    out: list[_Match] = []

    # Same-character runs (e.g., "aaaa", "1111")
    i = 0
    while i < n:
        j = i + 1
        while j < n and password[j] == password[i]:
            j += 1
        run_len = j - i
        if run_len >= 3:
            symbol_space = max(2, len(set(password[i:j])))
            guesses = max(1.0, float(symbol_space) * run_len)
            out.append(_Match(i, j - 1, math.log10(guesses), "repeat"))
        i = j

    # Repeated blocks (e.g., "abcabc", "xYxYxY")
    for start in range(n):
        max_block = (n - start) // 2
        for block_size in range(1, max_block + 1):
            block = password[start : start + block_size]
            repeat_count = 1
            pos = start + block_size
            while pos + block_size <= n and password[pos : pos + block_size] == block:
                repeat_count += 1
                pos += block_size
            if repeat_count < 2:
                continue
            end = start + (repeat_count * block_size) - 1
            base_cardinality = max(2, len(set(block)))
            base_log10 = len(block) * math.log10(float(base_cardinality))
            guesses_log10 = base_log10 + math.log10(float(repeat_count))
            out.append(_Match(start, end, guesses_log10, "repeat"))
    return tuple(out)


def _linear_repeated_run_penalty(password: str) -> float:
    if len(password) < 3:
        return 0.0
    penalty = 0.0
    run_len = 1
    for i in range(1, len(password)):
        if password[i] == password[i - 1]:
            run_len += 1
        else:
            if run_len >= 3:
                penalty += (run_len - 2) * 1.5
            run_len = 1
    if run_len >= 3:
        penalty += (run_len - 2) * 1.5
    return penalty


def _sequence_matches(password: str) -> tuple[_Match, ...]:
    n = len(password)
    out: list[_Match] = []
    if n < 3:
        return ()

    run_start = 0
    prev_delta = _sequence_delta(password[0], password[1])
    run_len = 2 if abs(prev_delta) == 1 else 1
    if run_len == 1:
        run_start = 1

    for i in range(2, n):
        delta = _sequence_delta(password[i - 1], password[i])
        if abs(delta) == 1 and delta == prev_delta and run_len >= 2:
            run_len += 1
        elif abs(delta) == 1:
            run_start = i - 1
            run_len = 2
        else:
            if run_len >= 3 and abs(prev_delta) == 1:
                run_end = i - 1
                token = password[run_start : run_end + 1]
                space = _sequence_space(token)
                guesses = max(1.0, float(space) * len(token))
                out.append(_Match(run_start, run_end, math.log10(guesses), "sequence"))
            run_start = i
            run_len = 1
        prev_delta = delta

    if run_len >= 3 and abs(prev_delta) == 1:
        run_end = n - 1
        token = password[run_start : run_end + 1]
        space = _sequence_space(token)
        guesses = max(1.0, float(space) * len(token))
        out.append(_Match(run_start, run_end, math.log10(guesses), "sequence"))
    return tuple(out)


def _linear_sequence_penalty(password: str) -> float:
    if len(password) < 3:
        return 0.0
    penalty = 0.0
    run_len = 1
    prev_delta = 0
    for i in range(1, len(password)):
        delta = _sequence_delta(password[i - 1], password[i])
        if abs(delta) == 1 and delta == prev_delta and run_len >= 2:
            run_len += 1
        elif abs(delta) == 1:
            run_len = 2
        else:
            if run_len >= 3 and abs(prev_delta) == 1:
                penalty += (run_len - 2) * 1.75
            run_len = 1
        prev_delta = delta
    if run_len >= 3 and abs(prev_delta) == 1:
        penalty += (run_len - 2) * 1.75
    return penalty


def _spatial_matches(password: str) -> tuple[_Match, ...]:
    n = len(password)
    out: list[_Match] = []
    if n < 3:
        return ()

    i = 0
    while i < n - 2:
        j = i
        while j + 1 < n and _is_qwerty_adjacent(password[j], password[j + 1]):
            j += 1
        run_len = j - i + 1
        if run_len >= 3:
            guesses = _qwerty_guesses(run_len)
            out.append(_Match(i, j, math.log10(max(1.0, guesses)), "spatial"))
            i = j
        i += 1
    return tuple(out)


def _date_matches(password: str) -> tuple[_Match, ...]:
    n = len(password)
    out: list[_Match] = []
    for start in range(n):
        # Year pattern (1900-2099)
        if start + 4 <= n:
            token4 = password[start : start + 4]
            if token4.isdigit():
                year = int(token4)
                if 1900 <= year <= 2099:
                    out.append(_Match(start, start + 3, math.log10(200.0), "date"))

        # Compact date pattern (ddmmyyyy / yyyymmdd)
        if start + 8 <= n:
            token8 = password[start : start + 8]
            if token8.isdigit():
                out.append(_Match(start, start + 7, math.log10(31.0 * 12.0 * 200.0), "date"))
    return tuple(out)


def _keep_best_match(store: dict[tuple[int, int, str], float], match: _Match) -> None:
    key = (match.start, match.end, match.pattern)
    prev = store.get(key)
    if prev is None or match.log10_guesses < prev:
        store[key] = match.log10_guesses


def _normalize_l33t(token_lc: str) -> str:
    return "".join(LEET_MAP.get(ch, ch) for ch in token_lc)


def _case_variations(token: str) -> float:
    if token.islower():
        return 1.0
    if token.isupper():
        return 2.0
    upper = sum(1 for ch in token if ch.isupper())
    lower = sum(1 for ch in token if ch.islower())
    alpha = upper + lower
    if alpha == 0:
        return 1.0
    # Conservative approximation: each mixed-case alpha char doubles pattern space.
    return float(2 ** min(alpha, 12))


def _leet_variations(token: str) -> float:
    leet_count = sum(1 for ch in token if ch in LEET_MAP)
    if leet_count == 0:
        return 1.0
    return float(2 ** min(leet_count, 10))


def _sequence_delta(prev: str, curr: str) -> int:
    if prev.isdigit() and curr.isdigit():
        return ord(curr) - ord(prev)
    if prev.isalpha() and curr.isalpha():
        return ord(curr.lower()) - ord(prev.lower())
    return 0


def _sequence_space(token: str) -> int:
    if token.isdigit():
        return 10
    return 26


def _qwerty_guesses(length: int) -> float:
    _ensure_qwerty_cache()
    assert _QWERTY_START_POSITIONS_CACHE is not None
    assert _QWERTY_AVG_DEGREE_CACHE is not None
    return float(_QWERTY_START_POSITIONS_CACHE) * (_QWERTY_AVG_DEGREE_CACHE ** max(0, length - 1))


def _is_qwerty_adjacent(a: str, b: str) -> bool:
    _ensure_qwerty_cache()
    assert _QWERTY_ADJ_CACHE is not None
    a_l = a.lower()
    b_l = b.lower()
    return b_l in _QWERTY_ADJ_CACHE.get(a_l, ())


def _ensure_qwerty_cache() -> None:
    global _QWERTY_ADJ_CACHE
    global _QWERTY_START_POSITIONS_CACHE
    global _QWERTY_AVG_DEGREE_CACHE
    if _QWERTY_ADJ_CACHE is not None:
        return

    graph = _build_qwerty_adjacency(_QWERTY_ROWS)
    start_positions = len(graph)
    avg_degree = sum(len(v) for v in graph.values()) / float(start_positions)

    _QWERTY_ADJ_CACHE = graph
    _QWERTY_START_POSITIONS_CACHE = start_positions
    _QWERTY_AVG_DEGREE_CACHE = avg_degree


def _build_qwerty_adjacency(rows: tuple[str, ...]) -> dict[str, set[str]]:
    pos: dict[str, tuple[int, int]] = {}
    for r, row in enumerate(rows):
        for c, ch in enumerate(row):
            pos[ch] = (r, c)

    out: dict[str, set[str]] = {ch: set() for ch in pos}
    for ch, (r, c) in pos.items():
        for rr in range(max(0, r - 1), min(len(rows), r + 2)):
            row = rows[rr]
            for cc in range(max(0, c - 1), min(len(row), c + 2)):
                other = row[cc]
                if other != ch:
                    out[ch].add(other)
    return out


def _repeated_block_penalty_lite(password: str) -> float:
    """Bounded scan for full-string repeated blocks."""
    n = len(password)
    if n < 4:
        return 0.0
    max_block = min(MAX_REPEAT_BLOCK_SCAN, n // 2)
    for block_size in range(1, max_block + 1):
        if n % block_size != 0:
            continue
        repeats = n // block_size
        if repeats < 2:
            continue
        block = password[:block_size]
        if block * repeats == password:
            return math.log2(repeats) * 3.0
    return 0.0


def _bruteforce_log10(token: str) -> float:
    space = _char_space(token)
    return len(token) * math.log10(float(space))


def _char_space(token: str) -> int:
    if not token:
        return 1
    has_lower = any(ch in string.ascii_lowercase for ch in token)
    has_upper = any(ch in string.ascii_uppercase for ch in token)
    has_digit = any(ch in string.digits for ch in token)
    has_symbol = any(ch in string.punctuation for ch in token)
    has_other = any(
        ch not in string.ascii_lowercase
        and ch not in string.ascii_uppercase
        and ch not in string.digits
        and ch not in string.punctuation
        for ch in token
    )

    space = 0
    if has_lower:
        space += 26
    if has_upper:
        space += 26
    if has_digit:
        space += 10
    if has_symbol:
        space += 33
    if has_other:
        # Conservative extension for non-ASCII code points.
        space += 100
    return max(space, 1)
