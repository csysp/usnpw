from __future__ import annotations

import argparse
import random
import string
import sys

from usnpw.gui.adapters import build_password_request, build_username_request


def _rand_text(rng: random.Random, max_len: int = 64) -> str:
    n = rng.randint(0, max_len)
    alphabet = string.ascii_letters + string.digits + " _-./\\:;,+*'\""
    return "".join(rng.choice(alphabet) for _ in range(n))


def _rand_boolish(rng: random.Random) -> object:
    choices: list[object] = [True, False, 0, 1, "", "true", "false", "0", "1", None]
    return rng.choice(choices)


def _rand_numish(rng: random.Random) -> object:
    choices: list[object] = [
        rng.randint(-10_000, 10_000),
        rng.random() * rng.randint(-1000, 1000),
        _rand_text(rng, 12),
        "",
        None,
    ]
    return rng.choice(choices)


def fuzz(iterations: int, seed: int) -> int:
    rng = random.Random(seed)
    failures = 0

    for i in range(iterations):
        pw_fields: dict[str, object] = {
            "count": _rand_numish(rng),
            "length": _rand_numish(rng),
            "charset": _rand_text(rng),
            "symbols": _rand_text(rng),
            "no_symbols": _rand_boolish(rng),
            "max_entropy": _rand_boolish(rng),
            "format": _rand_text(rng, 16),
            "entropy_bytes": _rand_numish(rng),
            "bits": _rand_numish(rng),
            "out_enc": _rand_text(rng, 12),
            "group": _rand_numish(rng),
            "group_sep": _rand_text(rng, 3),
            "group_pad": _rand_text(rng, 2),
            "words": _rand_numish(rng),
            "delim": _rand_text(rng, 3),
            "bip39_wordlist": _rand_text(rng, 64),
        }

        u_fields: dict[str, object] = {
            "count": _rand_numish(rng),
            "min_len": _rand_numish(rng),
            "max_len": _rand_numish(rng),
            "profile": _rand_text(rng, 12),
            "safe_mode": _rand_boolish(rng),
            "uniqueness_mode": rng.choice(["stream", "blacklist", _rand_text(rng, 8)]),
            "blacklist": _rand_text(rng, 48),
            "no_save": _rand_boolish(rng),
            "token_blacklist": _rand_text(rng, 48),
            "no_token_save": _rand_boolish(rng),
            "no_token_block": _rand_boolish(rng),
            "stream_save_tokens": _rand_boolish(rng),
            "stream_state": _rand_text(rng, 48),
            "stream_state_persist": _rand_boolish(rng),
            "allow_plaintext_stream_state": _rand_boolish(rng),
            "disallow_prefix": _rand_text(rng, 48),
            "disallow_substring": _rand_text(rng, 48),
            "no_leading_digit": _rand_boolish(rng),
            "max_scheme_pct": _rand_numish(rng),
            "history": _rand_numish(rng),
            "pool_scale": _rand_numish(rng),
            "initials_weight": _rand_numish(rng),
            "show_meta": _rand_boolish(rng),
        }

        try:
            build_password_request(pw_fields)
        except ValueError:
            pass
        except Exception as exc:  # pragma: no cover
            failures += 1
            print(f"[unexpected] build_password_request i={i} exc={exc!r}", file=sys.stderr)

        try:
            build_username_request(u_fields)
        except ValueError:
            pass
        except Exception as exc:  # pragma: no cover
            failures += 1
            print(f"[unexpected] build_username_request i={i} exc={exc!r}", file=sys.stderr)

    if failures:
        print(f"[fuzz] failures={failures}", file=sys.stderr)
        return 2
    print(f"[fuzz] ok iterations={iterations} seed={seed}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Quick fuzz harness for GUI adapters (stdlib-only).")
    parser.add_argument("--iterations", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)
    return fuzz(iterations=args.iterations, seed=args.seed)


if __name__ == "__main__":
    raise SystemExit(main())

