#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = ["requests>=2.31.0"]
# ///
"""Submit packages from a conda channel to the local transparency log.

Usage:
    uv run scripts/submit_packages.py                      # Submit 10 packages
    uv run scripts/submit_packages.py --limit 100          # Submit 100 packages
    uv run scripts/submit_packages.py --channel conda-forge --subdir osx-arm64
"""

import argparse
import json
import sys

import requests


def normalize_entry(filename: str, subdir: str, entry: dict) -> dict | None:
    """Normalize a repodata entry to the CEP spec format."""
    try:
        normalized = {
            "build": entry["build"],
            "build_number": entry["build_number"],
            "filename": filename,
            "name": entry["name"],
            "sha256": entry["sha256"],
            "size": entry["size"],
            "subdir": subdir,
            "version": entry["version"],
        }
        if entry.get("depends"):
            normalized["depends"] = entry["depends"]
        if entry.get("license"):
            normalized["license"] = entry["license"]
        if entry.get("md5"):
            normalized["md5"] = entry["md5"]
        if entry.get("timestamp"):
            normalized["timestamp"] = entry["timestamp"]
        return dict(sorted(normalized.items()))
    except KeyError:
        return None


def main():
    parser = argparse.ArgumentParser(description="Submit conda packages to transparency log")
    parser.add_argument("--channel", default="robostack-staging", help="Conda channel")
    parser.add_argument("--subdir", default="linux-64", help="Platform subdir")
    parser.add_argument("--limit", type=int, default=10, help="Number of packages")
    parser.add_argument("--log-url", default="http://localhost:8080", help="Log server URL")
    args = parser.parse_args()

    # Fetch repodata
    url = f"https://conda.anaconda.org/{args.channel}/{args.subdir}/repodata.json"
    print(f"Fetching {url}...")
    repodata = requests.get(url, timeout=60).json()

    # Collect packages
    packages = {**repodata.get("packages", {}), **repodata.get("packages.conda", {})}
    print(f"Found {len(packages)} packages, submitting {args.limit}")

    # Submit
    success, errors = 0, 0
    for i, (filename, entry) in enumerate(packages.items()):
        if i >= args.limit:
            break
        normalized = normalize_entry(filename, args.subdir, entry)
        if not normalized:
            continue

        resp = requests.post(f"{args.log_url}/add", json=normalized, timeout=10)
        if resp.status_code == 200:
            success += 1
            print(f"  ✓ {filename}")
        else:
            errors += 1
            print(f"  ✗ {filename}: {resp.status_code}", file=sys.stderr)

    print(f"\nDone: {success} submitted, {errors} errors")


if __name__ == "__main__":
    main()
