# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx[http2]"]
# ///
"""Benchmark and soak-test a siglog transparency log deployment.

Measures whether the log "holds up" end to end:

  1. Write path   — concurrent POST /add: throughput, latency percentiles,
                    error/rate-limit counts.
  2. Integration  — time until all written entries are integrated into the
                    Merkle tree (pending_count back to 0) and the checkpoint
                    advances to cover them.
  3. Read path    — GET /checkpoint, tile fetches, and vindex lookups:
                    latency percentiles.
  4. Correctness  — every sampled written entry must be findable through the
                    vindex at the index the server assigned at write time,
                    and the final checkpoint must cover all writes.

Usage:
    uv run scripts/bench.py --url https://conda-transparency-log.fly.dev \
        --api-key-file /path/to/key --entries 2000 --concurrency 32
"""

import argparse
import asyncio
import json
import random
import statistics
import string
import sys
import time

import httpx


def pct(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    values = sorted(values)
    k = min(len(values) - 1, max(0, round(p / 100 * (len(values) - 1))))
    return values[k]


def fmt_ms(seconds: float) -> str:
    return f"{seconds * 1000:.1f}ms"


class Stats:
    def __init__(self) -> None:
        self.latencies: list[float] = []
        self.ok = 0
        self.rate_limited = 0
        self.errors: dict[str, int] = {}

    def error(self, kind: str) -> None:
        self.errors[kind] = self.errors.get(kind, 0) + 1

    def summary(self, name: str, duration: float | None = None) -> str:
        lines = [f"  requests ok:      {self.ok}"]
        if duration and self.ok:
            lines.append(f"  throughput:       {self.ok / duration:.1f} req/s")
        if self.latencies:
            lines.append(
                "  latency p50/p95/p99/max: "
                f"{fmt_ms(pct(self.latencies, 50))} / {fmt_ms(pct(self.latencies, 95))} / "
                f"{fmt_ms(pct(self.latencies, 99))} / {fmt_ms(max(self.latencies))}"
            )
        if self.rate_limited:
            lines.append(f"  rate-limited (429): {self.rate_limited}")
        for kind, count in sorted(self.errors.items()):
            lines.append(f"  ERROR {kind}: {count}")
        return f"{name}\n" + "\n".join(lines)


async def write_phase(
    client: httpx.AsyncClient,
    url: str,
    api_key: str,
    n_entries: int,
    concurrency: int,
    run_id: str,
) -> tuple[Stats, dict[str, int], float]:
    """POST /add for n_entries; returns stats and name → assigned index."""
    stats = Stats()
    assigned: dict[str, int] = {}
    sem = asyncio.Semaphore(concurrency)
    headers = {"Authorization": f"Bearer {api_key}"}

    async def submit(i: int) -> None:
        name = f"bench-{run_id}-pkg-{i:06d}"
        body = json.dumps(
            {
                "name": name,
                "version": "1.0.0",
                "build": "py311_0",
                "build_number": 0,
                "subdir": "linux-64",
                "filename": f"{name}-1.0.0-py311_0.conda",
                "sha256": "".join(random.choices("0123456789abcdef", k=64)),
                "size": random.randint(10_000, 90_000_000),
                "depends": ["python >=3.11,<3.12.0a0"],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        async with sem:
            # Retry on 429 with backoff so rate limiting degrades throughput
            # instead of failing the run.
            for attempt in range(6):
                start = time.monotonic()
                try:
                    resp = await client.post(f"{url}/add", content=body, headers=headers)
                except httpx.HTTPError as e:
                    stats.error(type(e).__name__)
                    return
                elapsed = time.monotonic() - start
                if resp.status_code == 200:
                    stats.ok += 1
                    stats.latencies.append(elapsed)
                    assigned[name] = int(resp.text.strip())
                    return
                if resp.status_code == 429:
                    stats.rate_limited += 1
                    # Honor Retry-After but cap it: a misconfigured limiter
                    # can advertise huge values and stall the whole run.
                    retry_after = min(float(resp.headers.get("retry-after", 0) or 0), 10.0)
                    await asyncio.sleep(max(retry_after, 0.2 * (attempt + 1)))
                    continue
                stats.error(f"HTTP {resp.status_code}")
                return
            stats.error("gave up after 429 retries")

    start = time.monotonic()
    await asyncio.gather(*(submit(i) for i in range(n_entries)))
    duration = time.monotonic() - start
    return stats, assigned, duration


def parse_checkpoint(text: str) -> tuple[str, int, int]:
    """Return (origin, tree_size, signature_count)."""
    body, _, sigs = text.partition("\n\n")
    lines = body.splitlines()
    n_sigs = sum(1 for l in sigs.splitlines() if l.startswith("— "))
    return lines[0], int(lines[1]), n_sigs


async def wait_for_integration(
    client: httpx.AsyncClient, url: str, target_size: int, timeout: float
) -> tuple[float | None, float | None]:
    """Wait until /ready reports integrated_size >= target and /checkpoint
    covers it. Returns (integration_lag, checkpoint_lag) in seconds."""
    start = time.monotonic()
    integrated_at = None
    while time.monotonic() - start < timeout:
        resp = await client.get(f"{url}/ready")
        if resp.status_code == 200:
            data = resp.json()
            if data["integrated_size"] >= target_size and data["pending_count"] == 0:
                integrated_at = time.monotonic() - start
                break
        elif resp.status_code == 429:
            # Back off so polling doesn't keep the bucket empty forever.
            await asyncio.sleep(2.0)
            continue
        await asyncio.sleep(0.25)
    if integrated_at is None:
        return None, None

    while time.monotonic() - start < timeout:
        resp = await client.get(f"{url}/checkpoint")
        if resp.status_code == 200:
            _, size, _ = parse_checkpoint(resp.text)
            if size >= target_size:
                return integrated_at, time.monotonic() - start
        elif resp.status_code == 429:
            await asyncio.sleep(2.0)
            continue
        await asyncio.sleep(0.25)
    return integrated_at, None


async def read_phase(
    client: httpx.AsyncClient,
    url: str,
    assigned: dict[str, int],
    n_lookups: int,
    concurrency: int,
) -> tuple[Stats, Stats, Stats, int]:
    """Checkpoint fetches, vindex lookups (with correctness check), tile reads."""
    ckpt_stats, vindex_stats, tile_stats = Stats(), Stats(), Stats()
    mismatches = 0
    sem = asyncio.Semaphore(concurrency)

    async def timed_get(path: str, stats: Stats) -> httpx.Response | None:
        async with sem:
            start = time.monotonic()
            try:
                resp = await client.get(f"{url}{path}")
            except httpx.HTTPError as e:
                stats.error(type(e).__name__)
                return None
            if resp.status_code == 200:
                stats.ok += 1
                stats.latencies.append(time.monotonic() - start)
                return resp
            if resp.status_code == 429:
                stats.rate_limited += 1
            else:
                stats.error(f"HTTP {resp.status_code} {path}")
            return None

    async def check_lookup(name: str, expected_idx: int) -> None:
        nonlocal mismatches
        resp = await timed_get(f"/vindex/lookup/key/{name}", vindex_stats)
        if resp is None:
            return
        data = resp.json()
        if not data["found"] or expected_idx not in data["indices"]:
            mismatches += 1

    sample = random.sample(sorted(assigned.items()), min(n_lookups, len(assigned)))

    tasks = [check_lookup(name, idx) for name, idx in sample]
    tasks += [timed_get("/checkpoint", ckpt_stats) for _ in range(50)]
    # Tile reads across the tree (entry bundles for sampled indices).
    max_idx = max(assigned.values()) if assigned else 0
    tree_size = max_idx + 1
    bundles = sorted({idx // 256 for _, idx in sample})
    for b in bundles[:50]:
        partial = tree_size % 256 if b == tree_size // 256 else 0
        path = f"/tile/entries/{b:03d}" + (f".p/{partial}" if partial else "")
        tasks.append(timed_get(path, tile_stats))

    await asyncio.gather(*tasks)
    return ckpt_stats, vindex_stats, tile_stats, mismatches


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="Log base URL")
    parser.add_argument("--api-key", help="API key for POST /add")
    parser.add_argument("--api-key-file", help="File containing the API key")
    parser.add_argument("--entries", type=int, default=1000)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--lookups", type=int, default=200)
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="Max seconds to wait for integration/checkpoint")
    args = parser.parse_args()

    api_key = args.api_key
    if not api_key and args.api_key_file:
        api_key = open(args.api_key_file).read().strip()
    if not api_key:
        parser.error("--api-key or --api-key-file is required")

    url = args.url.rstrip("/")
    run_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))

    # HTTP/1.1 with a connection pool sized to the concurrency: multiplexing
    # all requests onto one HTTP/2 connection collapses to ~1 in-flight
    # request behind some proxies (observed on Fly's edge).
    limits = httpx.Limits(
        max_connections=args.concurrency + 8,
        max_keepalive_connections=args.concurrency + 8,
    )
    async with httpx.AsyncClient(timeout=30.0, limits=limits) as client:
        # Baseline state
        resp = await client.get(f"{url}/ready")
        resp.raise_for_status()
        baseline = resp.json()
        print(f"target: {url}  (run id {run_id})")
        print(f"baseline: integrated_size={baseline['integrated_size']} "
              f"pending={baseline['pending_count']}\n")

        # Phase 1: writes
        print(f"phase 1: writing {args.entries} entries, concurrency {args.concurrency} ...")
        write_stats, assigned, write_duration = await write_phase(
            client, url, api_key, args.entries, args.concurrency, run_id
        )
        print(write_stats.summary("write /add", write_duration))
        if not assigned:
            print("no successful writes; aborting")
            return 1

        # Phase 2: integration + checkpoint lag
        target = max(assigned.values()) + 1
        print(f"\nphase 2: waiting for integration to size {target} ...")
        integ_lag, ckpt_lag = await wait_for_integration(client, url, target, args.timeout)
        if integ_lag is None:
            print(f"  FAIL: not integrated within {args.timeout}s")
            return 1
        print(f"  integration lag after last ack: {integ_lag:.2f}s")
        if ckpt_lag is None:
            print(f"  FAIL: checkpoint did not cover size {target} within {args.timeout}s")
            return 1
        print(f"  checkpoint covering all writes:  {ckpt_lag:.2f}s")

        resp = await client.get(f"{url}/checkpoint")
        origin, size, n_sigs = parse_checkpoint(resp.text)
        print(f"  checkpoint: origin={origin} size={size} signatures={n_sigs}")

        # Phase 3: reads + correctness
        print(f"\nphase 3: {min(args.lookups, len(assigned))} vindex lookups, "
              f"50 checkpoint fetches, tile reads ...")
        ckpt_stats, vindex_stats, tile_stats, mismatches = await read_phase(
            client, url, assigned, args.lookups, args.concurrency
        )
        print(ckpt_stats.summary("read /checkpoint"))
        print(vindex_stats.summary("read /vindex/lookup/key"))
        print(tile_stats.summary("read /tile/entries"))

        # Verdict
        print("\n=== verdict ===")
        failures = []
        if write_stats.errors:
            failures.append(f"write errors: {write_stats.errors}")
        if mismatches:
            failures.append(f"{mismatches} vindex lookups missing the assigned index")
        if any(s.errors for s in (ckpt_stats, vindex_stats, tile_stats)):
            failures.append("read errors (see above)")
        if size < target:
            failures.append(f"checkpoint size {size} < target {target}")
        if failures:
            for f in failures:
                print(f"  FAIL: {f}")
            return 1
        print(f"  PASS: {len(assigned)} entries written, integrated, checkpointed, "
              f"and all {min(args.lookups, len(assigned))} sampled lookups verified")
        return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
