"""Measure how long chain verification takes (the latency metric).

Builds clean chains of 100, 1,000 and 10,000 blocks from the engine fixtures,
verifies each one a few times, and prints a table for docs/test-results.md.

Run from the repo root:
    python -m scripts.benchmark_engine
"""

import statistics
import tempfile
import time

from app.engine.verify import verify_chain
from fixtures.engine_fixtures import build_long_chain

SIZES = (100, 1_000, 10_000)
RUNS = 3


def main() -> None:
    print(f"{'Blocks':>8} | {'Median (ms)':>11} | {'Per block (ms)':>14} | Status")
    print("-" * 52)

    for size in SIZES:
        # Build a clean chain of this size in a throwaway folder.
        with tempfile.TemporaryDirectory() as folder:
            chain = build_long_chain(size, folder)

            # Time several runs and take the middle value (less noisy).
            timings = []
            for _ in range(RUNS):
                start = time.perf_counter()
                result = verify_chain(chain["blocks"], chain["public_keys"], chain["evidence_files"])
                timings.append((time.perf_counter() - start) * 1000)

        median = statistics.median(timings)
        count = result["blocks_checked"]
        print(f"{count:>8} | {median:>11.1f} | {median / count:>14.3f} | {result['status']}")


if __name__ == "__main__":
    main()
