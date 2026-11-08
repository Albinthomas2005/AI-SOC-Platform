#!/usr/bin/env python3
"""Small authenticated concurrency check for the loopback training API."""

import argparse
import concurrent.futures
import os
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def request_once(url, token):
    request = Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urlopen(request, timeout=10) as response:
            response.read(1024)
            return response.status
    except HTTPError as error:
        return error.code
    except URLError:
        return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--url", default=None)
    args = parser.parse_args()
    if not 1 <= args.requests <= 10000 or not 1 <= args.concurrency <= 500:
        parser.error("requests must be 1-10000 and concurrency must be 1-500")

    token = os.environ.get("SOC_AI_INTERNAL_TOKEN", "")
    if not token:
        parser.error("SOC_AI_INTERNAL_TOKEN must be set in the environment")
    port = os.environ.get("SOC_AI_PORT", "5000")
    base_url = args.url or f"http://127.0.0.1:{port}"
    url = base_url.rstrip("/") + "/training/scenarios"

    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        statuses = list(pool.map(lambda _: request_once(url, token), range(args.requests)))
    elapsed = time.monotonic() - started
    successes = sum(status == 200 for status in statuses)
    rate_limited = sum(status == 429 for status in statuses)
    failures = len(statuses) - successes - rate_limited
    print(f"requests: {len(statuses)}")
    print(f"successes: {successes}")
    print(f"rate_limited: {rate_limited}")
    print(f"other_failures: {failures}")
    print(f"elapsed_seconds: {elapsed:.2f}")
    print(f"requests_per_second: {len(statuses) / elapsed:.2f}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
