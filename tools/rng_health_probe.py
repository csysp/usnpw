#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from usnpw.core.password_engine import assert_csprng_ready, secure_random_bytes


def _estimated_collision_upper_bound(samples: int, chunk_bytes: int) -> int:
    # Birthday-bound estimate for expected collisions with a conservative safety margin.
    space_size = 1 << (8 * chunk_bytes)
    expected = (samples * (samples - 1)) / (2.0 * space_size)
    return max(2, int(math.ceil(expected * 20.0 + 5.0)))


def _run_probe(
    *,
    samples: int,
    chunk_bytes: int,
    min_unique_ratio: float,
    min_ones_ratio: float,
    max_ones_ratio: float,
) -> tuple[float, float, int, int]:
    assert_csprng_ready()

    if samples <= 0:
        raise ValueError("samples must be > 0")
    if chunk_bytes <= 0:
        raise ValueError("chunk-bytes must be > 0")
    if not (0.0 < min_unique_ratio <= 1.0):
        raise ValueError("min-unique-ratio must be within (0, 1]")
    if not (0.0 <= min_ones_ratio <= 1.0 and 0.0 <= max_ones_ratio <= 1.0 and min_ones_ratio < max_ones_ratio):
        raise ValueError("ones-ratio bounds must satisfy 0 <= min < max <= 1")

    unique_blocks: set[bytes] = set()
    total_one_bits = 0
    total_bits = samples * chunk_bytes * 8

    for _ in range(samples):
        block = secure_random_bytes(chunk_bytes)
        unique_blocks.add(block)
        total_one_bits += sum(byte.bit_count() for byte in block)

    unique_count = len(unique_blocks)
    collision_count = samples - unique_count
    unique_ratio = unique_count / samples
    ones_ratio = total_one_bits / total_bits

    if unique_ratio < min_unique_ratio:
        raise RuntimeError(
            f"RNG health probe failed: unique ratio {unique_ratio:.6f} below threshold {min_unique_ratio:.6f}"
        )
    if ones_ratio < min_ones_ratio or ones_ratio > max_ones_ratio:
        raise RuntimeError(
            f"RNG health probe failed: one-bit ratio {ones_ratio:.6f} outside [{min_ones_ratio:.6f}, {max_ones_ratio:.6f}]"
        )

    collision_upper_bound = _estimated_collision_upper_bound(samples, chunk_bytes)
    if collision_count > collision_upper_bound:
        raise RuntimeError(
            "RNG health probe failed: observed collisions exceed conservative birthday bound "
            f"({collision_count} > {collision_upper_bound})"
        )

    return unique_ratio, ones_ratio, collision_count, collision_upper_bound


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Local RNG health probe for OS CSPRNG. "
            "This is a sanity check, not a cryptographic certification."
        )
    )
    parser.add_argument("--samples", type=int, default=4096, help="Number of random blocks to sample (default: 4096).")
    parser.add_argument("--chunk-bytes", type=int, default=32, help="Bytes per sampled block (default: 32).")
    parser.add_argument(
        "--min-unique-ratio",
        type=float,
        default=0.999,
        help="Minimum required unique block ratio (default: 0.999).",
    )
    parser.add_argument(
        "--min-ones-ratio",
        type=float,
        default=0.47,
        help="Minimum one-bit ratio bound (default: 0.47).",
    )
    parser.add_argument(
        "--max-ones-ratio",
        type=float,
        default=0.53,
        help="Maximum one-bit ratio bound (default: 0.53).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        unique_ratio, ones_ratio, collisions, collision_bound = _run_probe(
            samples=args.samples,
            chunk_bytes=args.chunk_bytes,
            min_unique_ratio=args.min_unique_ratio,
            min_ones_ratio=args.min_ones_ratio,
            max_ones_ratio=args.max_ones_ratio,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"[rng] probe failed: {exc}", file=sys.stderr)
        return 1

    print(f"[rng] samples={args.samples} chunk_bytes={args.chunk_bytes}")
    print(f"[rng] unique_ratio={unique_ratio:.6f}")
    print(f"[rng] one_bit_ratio={ones_ratio:.6f}")
    print(f"[rng] collisions={collisions} (bound={collision_bound})")
    print("[rng] probe ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
