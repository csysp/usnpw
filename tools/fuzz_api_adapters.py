from __future__ import annotations

import argparse
import random
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from usnpw.api.adapters import build_password_request, build_username_request


def _rand_text(rng: random.Random, max_len: int = 64) -> str:
    n = rng.randint(0, max_len)
    alphabet = string.ascii_letters + string.digits + " _-./\\:;,+*'\""
    return "".join(rng.choice(alphabet) for _ in range(n))


def _rand_json_value(rng: random.Random, depth: int = 0) -> object:
    if depth > 2:
        return _rand_text(rng, 16)
    choices: list[object] = [
        None,
        True,
        False,
        rng.randint(-10_000, 10_000),
        rng.random() * rng.randint(-1000, 1000),
        _rand_text(rng, 64),
        [_rand_json_value(rng, depth + 1) for _ in range(rng.randint(0, 6))],
    ]
    return rng.choice(choices)


def fuzz(iterations: int, seed: int) -> int:
    rng = random.Random(seed)
    failures = 0

    for i in range(iterations):
        # Sometimes pass a non-object payload to ensure type checks are safe.
        pw_payload: object
        if rng.random() < 0.15:
            pw_payload = _rand_json_value(rng)
        else:
            pw_payload = {
                "count": _rand_json_value(rng),
                "length": _rand_json_value(rng),
                "charset": _rand_text(rng),
                "symbols": _rand_text(rng),
                "no_symbols": _rand_json_value(rng),
                "max_entropy": _rand_json_value(rng),
                "format": rng.choice(
                    [
                        "password",
                        "hex",
                        "base64",
                        "base64url",
                        "crock32",
                        "crock32check",
                        "base58",
                        "base58check",
                        "uuid",
                        "bip39",
                        "sha256",
                        "sha512",
                        "sha3_256",
                        "sha3_512",
                        "blake2b",
                        "blake2s",
                        _rand_text(rng, 24),
                    ]
                ),
                "entropy_bytes": _rand_json_value(rng),
                "bits": _rand_json_value(rng),
                "out_enc": rng.choice(
                    [
                        "hex",
                        "base64",
                        "base64url",
                        "crock32",
                        "crock32check",
                        "base58",
                        "base58check",
                        _rand_text(rng, 16),
                    ]
                ),
                "group": _rand_json_value(rng),
                "group_sep": _rand_text(rng, 3),
                "group_pad": _rand_text(rng, 2),
                "words": _rand_json_value(rng),
                "delim": _rand_text(rng, 3),
                "bip39_wordlist": _rand_text(rng, 96),
            }
            if rng.random() < 0.25:
                # Unknown fields should be rejected cleanly.
                pw_payload["unknown"] = _rand_json_value(rng)

        u_payload: object
        if rng.random() < 0.15:
            u_payload = _rand_json_value(rng)
        else:
            u_payload = {
                "count": _rand_json_value(rng),
                "min_len": _rand_json_value(rng),
                "max_len": _rand_json_value(rng),
                "profile": _rand_text(rng, 16),
                "safe_mode": _rand_json_value(rng),
                "uniqueness_mode": rng.choice(["stream", "blacklist", _rand_text(rng, 8)]),
                "blacklist": _rand_text(rng, 96),
                "no_save": _rand_json_value(rng),
                "token_blacklist": _rand_text(rng, 96),
                "no_token_save": _rand_json_value(rng),
                "no_token_block": _rand_json_value(rng),
                "stream_save_tokens": _rand_json_value(rng),
                "stream_state": _rand_text(rng, 96),
                "stream_state_persist": _rand_json_value(rng),
                "allow_plaintext_stream_state": _rand_json_value(rng),
                "disallow_prefix": rng.choice([_rand_text(rng, 48), [_rand_text(rng, 12) for _ in range(rng.randint(0, 6))]]),
                "disallow_substring": rng.choice(
                    [_rand_text(rng, 48), [_rand_text(rng, 12) for _ in range(rng.randint(0, 6))]]
                ),
                "no_leading_digit": _rand_json_value(rng),
                "max_scheme_pct": _rand_json_value(rng),
                "history": _rand_json_value(rng),
                "pool_scale": _rand_json_value(rng),
                "initials_weight": _rand_json_value(rng),
                "show_meta": _rand_json_value(rng),
            }
            if rng.random() < 0.25:
                u_payload["unknown"] = _rand_json_value(rng)

        try:
            build_password_request(pw_payload)
        except ValueError:
            pass

        try:
            build_username_request(u_payload)
        except ValueError:
            pass

    if failures:
        print(f"[fuzz] failures={failures}", file=sys.stderr)
        return 2
    print(f"[fuzz] ok iterations={iterations} seed={seed}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Quick fuzz harness for API adapters (stdlib-only).")
    parser.add_argument("--iterations", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)
    return fuzz(iterations=args.iterations, seed=args.seed)


if __name__ == "__main__":
    raise SystemExit(main())
