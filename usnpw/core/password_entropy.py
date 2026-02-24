from __future__ import annotations

from dataclasses import dataclass
import math
import string


LOG2_10 = math.log2(10.0)
SEGMENT_PENALTY_LOG10 = math.log10(10.0)
MAX_MATCH_SEQUENCE_LENGTH = 96
MAX_REPEAT_BLOCK_SCAN = 24
DATE_SEPARATORS = "-/_."

# Clean-room weak-token list inspired by common credential audit findings.
# Threat model rationale:
# - These tokens are heavily over-represented in leaked credentials.
# - Matching them reduces estimated entropy to fail closed on known-bad structure.
# Source reference for curation (compact subset only, to avoid repo bloat):
# - SecLists/Passwords/Common-Credentials/top-passwords-shortlist.txt
# - SecLists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt
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
    "footbal",
    "soccer",
    "master",
    "shadow",
    "sunshine",
    "princess",
    "trustno1",
    "abc123",
    "abc123456",
    "123123",
    "123123123",
    "654321",
    "987654321",
    "qwerty123",
    "qazwsx",
    "zaq12wsx",
    "1q2w3e",
    "1q2w3e4r",
    "1q2w3e4r5t",
    "123456",
    "12345",
    "1234",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "111111",
    "000000",
    "toor",
    "raspberry",
    "dietpi",
    "uploader",
    "webadmin",
    "webmaster",
    "maintenance",
    "techsupport",
    "logon",
    "alpine",
    "marketing",
    "querty",
    "passw@rd",
    "root123",
    "admin123",
    "password1",
    "pass123",
    "welcome1",
    "changeme123",
    "adminadmin",
    "login123",
    "qwerty1",
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
_QWERTY_POS_CACHE: dict[str, tuple[int, int]] | None = None


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
    n = len(password)
    out: list[_Match] = []
    for start in range(n):
        for end in range(start + 2, n):
            token = password[start : end + 1]
            guesses = _dictionary_guesses_for_token(token)
            if guesses is None:
                continue
            out.append(
                _Match(
                    start=start,
                    end=end,
                    log10_guesses=math.log10(guesses),
                    pattern="dictionary",
                )
            )
    return tuple(out)


def _dictionary_guesses_for_token(token: str) -> float | None:
    token_lc = token.lower()
    normalized = _normalize_l33t(token_lc)
    reversed_token = token_lc[::-1]
    reversed_normalized = _normalize_l33t(reversed_token)

    candidates: tuple[tuple[str, bool, bool], ...] = (
        (token_lc, False, False),
        (normalized, normalized != token_lc, False),
        (reversed_token, False, True),
        (normalized[::-1], normalized != token_lc, True),
        (reversed_normalized, reversed_normalized != reversed_token, True),
    )

    case_var = _case_variations(token)
    leet_var = _leet_variations(token)
    best: float | None = None
    for candidate, leet_hit, reversed_hit in candidates:
        rank = COMMON_TOKEN_RANK.get(candidate)
        if rank is None:
            continue
        leet_factor = leet_var if leet_hit else 1.0
        reversed_var = 2.0 if reversed_hit else 1.0
        guesses = max(1.0, float(rank) * case_var * leet_factor * reversed_var)
        if best is None or guesses < best:
            best = guesses
    return best


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
                guesses = max(1.0, float(space) * 2.0 * len(token))
                out.append(_Match(run_start, run_end, math.log10(guesses), "sequence"))
            run_start = i
            run_len = 1
        prev_delta = delta

    if run_len >= 3 and abs(prev_delta) == 1:
        run_end = n - 1
        token = password[run_start : run_end + 1]
        space = _sequence_space(token)
        guesses = max(1.0, float(space) * 2.0 * len(token))
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
            token = password[i : j + 1]
            guesses = _spatial_guesses(token)
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

        for width in (6, 8):
            if start + width > n:
                continue
            token = password[start : start + width]
            if not token.isdigit():
                continue
            guesses = _compact_date_guesses(token)
            if guesses is not None:
                out.append(_Match(start, start + width - 1, math.log10(guesses), "date"))

        max_end = min(n, start + 10)
        for end in range(start + 6, max_end + 1):
            token = password[start:end]
            guesses = _separated_date_guesses(token)
            if guesses is not None:
                out.append(_Match(start, end - 1, math.log10(guesses), "date"))
    return tuple(out)


def _compact_date_guesses(token: str) -> float | None:
    if len(token) not in (6, 8):
        return None

    valid_orders = 0
    year_digits = 4 if len(token) == 8 else 2

    if len(token) == 8:
        if _is_valid_date_parts(token[6:8], token[4:6], token[0:4]):
            valid_orders += 1  # yyyymmdd
        if _is_valid_date_parts(token[0:2], token[2:4], token[4:8]):
            valid_orders += 1  # ddmmyyyy
        if _is_valid_date_parts(token[2:4], token[0:2], token[4:8]):
            valid_orders += 1  # mmddyyyy
    else:
        if _is_valid_date_parts(token[4:6], token[2:4], token[0:2]):
            valid_orders += 1  # yymmdd
        if _is_valid_date_parts(token[0:2], token[2:4], token[4:6]):
            valid_orders += 1  # ddmmyy
        if _is_valid_date_parts(token[2:4], token[0:2], token[4:6]):
            valid_orders += 1  # mmddyy

    if valid_orders == 0:
        return None

    year_space = 200.0 if year_digits == 4 else 100.0
    return 31.0 * 12.0 * year_space * float(valid_orders)


def _separated_date_guesses(token: str) -> float | None:
    parts: list[str] = []
    separators: list[str] = []
    buf: list[str] = []

    for ch in token:
        if ch.isdigit():
            buf.append(ch)
            continue
        if ch not in DATE_SEPARATORS:
            return None
        if not buf:
            return None
        parts.append("".join(buf))
        separators.append(ch)
        buf = []

    if not buf:
        return None
    parts.append("".join(buf))

    if len(parts) != 3 or len(separators) != 2:
        return None
    if any(len(part) < 1 or len(part) > 4 for part in parts):
        return None

    valid_orders = 0
    year_digits = 0

    first, second, third = parts
    if len(first) in (2, 4) and len(second) <= 2 and len(third) <= 2:
        if _is_valid_date_parts(third, second, first):
            valid_orders += 1  # yy(yy)-mm-dd
            year_digits = max(year_digits, len(first))

    if len(third) in (2, 4) and len(first) <= 2 and len(second) <= 2:
        if _is_valid_date_parts(first, second, third):
            valid_orders += 1  # dd-mm-yy(yy)
            year_digits = max(year_digits, len(third))
        if _is_valid_date_parts(second, first, third):
            valid_orders += 1  # mm-dd-yy(yy)
            year_digits = max(year_digits, len(third))

    if valid_orders == 0:
        return None

    year_space = 200.0 if year_digits == 4 else 100.0
    separator_space = 4.0 if separators[0] == separators[1] else 16.0
    return 31.0 * 12.0 * year_space * float(valid_orders) * separator_space


def _is_valid_date_parts(day_s: str, month_s: str, year_s: str) -> bool:
    if not (day_s.isdigit() and month_s.isdigit() and year_s.isdigit()):
        return False
    day = int(day_s)
    month = int(month_s)
    year = _parse_year(year_s)
    if year is None:
        return False
    if month < 1 or month > 12:
        return False
    if day < 1:
        return False
    return day <= _days_in_month(year, month)


def _parse_year(year_s: str) -> int | None:
    if len(year_s) == 4:
        year = int(year_s)
        if 1900 <= year <= 2099:
            return year
        return None
    if len(year_s) == 2:
        year = int(year_s)
        if year <= 49:
            return 2000 + year
        return 1900 + year
    return None


def _days_in_month(year: int, month: int) -> int:
    if month == 2:
        if _is_leap_year(year):
            return 29
        return 28
    if month in (4, 6, 9, 11):
        return 30
    return 31


def _is_leap_year(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def _keep_best_match(store: dict[tuple[int, int, str], float], match: _Match) -> None:
    key = (match.start, match.end, match.pattern)
    prev = store.get(key)
    if prev is None or match.log10_guesses < prev:
        store[key] = match.log10_guesses


def _normalize_l33t(token_lc: str) -> str:
    return "".join(LEET_MAP.get(ch, ch) for ch in token_lc)


def _case_variations(token: str) -> float:
    alpha = [ch for ch in token if ch.isalpha()]
    if not alpha:
        return 1.0
    if all(ch.islower() for ch in alpha):
        return 1.0
    if all(ch.isupper() for ch in alpha):
        return 2.0
    if alpha[0].isupper() and all(ch.islower() for ch in alpha[1:]):
        return 2.0

    upper = sum(1 for ch in alpha if ch.isupper())
    lower = sum(1 for ch in alpha if ch.islower())
    if upper == 0 or lower == 0:
        return 2.0

    variations = 0
    total = upper + lower
    for i in range(1, min(upper, lower) + 1):
        variations += _n_choose_k(total, i)
    return float(max(1, variations))


def _leet_variations(token: str) -> float:
    token_lc = token.lower()
    subbed: dict[str, int] = {}
    plain: dict[str, int] = {}

    for ch in token_lc:
        mapped = LEET_MAP.get(ch)
        if mapped is not None and ch != mapped:
            subbed[mapped] = subbed.get(mapped, 0) + 1
        elif "a" <= ch <= "z":
            plain[ch] = plain.get(ch, 0) + 1

    variations = 1.0
    for letter, subbed_count in subbed.items():
        plain_count = plain.get(letter, 0)
        if plain_count == 0:
            variations *= 2.0
            continue

        total = subbed_count + plain_count
        per_letter = 0
        for i in range(1, min(subbed_count, plain_count) + 1):
            per_letter += _n_choose_k(total, i)
        variations *= float(max(1, per_letter))

    return variations


def _n_choose_k(n: int, k: int) -> int:
    if k < 0 or k > n:
        return 0
    return math.comb(n, k)


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


def _spatial_guesses(token: str) -> float:
    length = len(token)
    base = _qwerty_guesses(length)
    turns = _spatial_turn_count(token)
    return base * float(max(1, turns + 1))


def _spatial_turn_count(token: str) -> int:
    if len(token) < 3:
        return 0
    positions = _qwerty_positions()
    prev_dx: int | None = None
    prev_dy: int | None = None
    turns = 0
    for i in range(1, len(token)):
        curr = token[i].lower()
        prev = token[i - 1].lower()
        curr_pos = positions.get(curr)
        prev_pos = positions.get(prev)
        if curr_pos is None or prev_pos is None:
            prev_dx = None
            prev_dy = None
            continue
        dx = curr_pos[0] - prev_pos[0]
        dy = curr_pos[1] - prev_pos[1]
        if dx == 0 and dy == 0:
            continue
        if prev_dx is not None and prev_dy is not None and (dx != prev_dx or dy != prev_dy):
            turns += 1
        prev_dx = dx
        prev_dy = dy
    return turns


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
    global _QWERTY_POS_CACHE
    if _QWERTY_ADJ_CACHE is not None:
        return

    positions = _build_qwerty_positions(_QWERTY_ROWS)
    graph = _build_qwerty_adjacency(positions, _QWERTY_ROWS)
    start_positions = len(graph)
    avg_degree = sum(len(v) for v in graph.values()) / float(start_positions)

    _QWERTY_POS_CACHE = positions
    _QWERTY_ADJ_CACHE = graph
    _QWERTY_START_POSITIONS_CACHE = start_positions
    _QWERTY_AVG_DEGREE_CACHE = avg_degree


def _qwerty_positions() -> dict[str, tuple[int, int]]:
    _ensure_qwerty_cache()
    assert _QWERTY_POS_CACHE is not None
    return _QWERTY_POS_CACHE


def _build_qwerty_positions(rows: tuple[str, ...]) -> dict[str, tuple[int, int]]:
    pos: dict[str, tuple[int, int]] = {}
    for r, row in enumerate(rows):
        for c, ch in enumerate(row):
            pos[ch] = (r, c)
    return pos


def _build_qwerty_adjacency(
    pos: dict[str, tuple[int, int]],
    rows: tuple[str, ...],
) -> dict[str, set[str]]:
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
