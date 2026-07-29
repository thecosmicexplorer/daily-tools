#!/usr/bin/env python3
"""
FastAPI Command Injection Scanner
=================================
This scanner checks for FastAPI endpoints vulnerable to command injection, a critical
security issue where unsanitized user input is used in system commands, allowing attackers
to execute arbitrary code. This vulnerability can lead to full compromise of the application
and underlying system, especially in scenarios where input validation and sanitization are
missing or insufficient.

Multi-CVE references:
  - Affected systems: FastAPI-based applications improperly handling user-supplied input
  - Vulnerable endpoints are typically exposed via API routes or parameters passed to
    system commands like subprocess or os.system without sanitization.

Usage:
  # Scan a single FastAPI application
  python fastapi_command_injection_scanner.py --target http://fastapi.example.com

  # Bulk scan from a target list file
  python fastapi_command_injection_scanner.py --list targets.txt --output results.json

  # Detection-only mode (no exploitation)
  python fastapi_command_injection_scanner.py --target http://fastapi.example.com --safe

  # Adjust concurrency and disable TLS verification
  python fastapi_command_injection_scanner.py --list targets.txt --concurrency 20 --no-verify

References:
  - https://owasp.org/www-community/attacks/Command_Injection
  - https://fastapi.tiangolo.com/security/
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

TOOL_NAME       = "fastapi_command_injection_scanner"
REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 20  # concurrency limit

# Common indicators for FastAPI applications
FASTAPI_FINGERPRINTS = [
    "FastAPI",
    "OpenAPI schema",
    '"application/json"',
]

# Command injection payloads for active probing
COMMAND_PAYLOADS = [
    {"input": "ping -c 1 127.0.0.1 && echo 'VULNERABLE'"},
    {"input": "$(echo VULNERABLE)"},
    {"input": "`echo VULNERABLE`"}
]

# ── Async Functions ──────────────────────────────────────────────────────────

async def fingerprint_fastapi(client: httpx.AsyncClient, url: str) -> Optional[str]:
    """Fingerprint the FastAPI service and determine if it matches FastAPI characteristics."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200 and any(fp in response.text for fp in FASTAPI_FINGERPRINTS):
            return "FastAPI"
    except Exception as e:
        pass
    return None

async def check_vulnerability(client: httpx.AsyncClient, base_url: str, safe: bool, sem: asyncio.Semaphore) -> Optional[dict]:
    """Check if a target is vulnerable to command injection."""
    async with sem:
        for payload in COMMAND_PAYLOADS:
            if safe:
                return {"url": base_url, "vulnerable": False}
            try:
                response = await client.post(base_url, json=payload, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200 and "VULNERABLE" in response.text:
                    return {"url": base_url, "vulnerable": True, "payload": payload}
            except Exception as e:
                pass
        return {"url": base_url, "vulnerable": False}

# ── Main Scanner Logic ────────────────────────────────────────────────────────

async def bulk_scan(target_list: str, concurrency: int, output: str, safe: bool, no_verify: bool) -> None:
    """Perform bulk scanning of multiple targets from a file."""
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(verify=not no_verify) as client:
        tasks = []
        with open(target_list, "r") as f:
            for target in f.read().splitlines():
                tasks.append(scan_target(client, target, sem, safe))
        results = await asyncio.gather(*tasks)
        if output:
            with open(output, "w") as outfile:
                json.dump({"results": results}, outfile, indent=4)

async def scan_target(client: httpx.AsyncClient, target: str, sem: asyncio.Semaphore, safe: bool) -> dict:
    """Scan a single target for the vulnerability."""
    base_url = target.strip()
    if not base_url.startswith(("http://", "https://")):
        base_url = f"http://{base_url}"

    print(c(CYAN, f"[INFO] Scanning {base_url}..."))

    service = await fingerprint_fastapi(client, base_url)
    if not service:
        print(c(YELLOW, f"[INFO] {base_url} does not appear to be FastAPI. Skipping."))
        return {"url": base_url, "fingerprint": None, "vulnerable": False}

    print(c(GREEN, f"[INFO] Identified FastAPI service at {base_url}. Fingerprint: {service}"))
    result = await check_vulnerability(client, base_url, safe, sem)
    if result["vulnerable"]:
        print(c(RED, f"[CRITICAL] Vulnerability detected at {base_url} with payload: {result['payload']}"))
    return result

# ── Command-Line Interface ────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="FastAPI Command Injection Scanner")
    parser.add_argument("--target", help="Target URL for scanning (e.g., http://example.com)")
    parser.add_argument("--list", help="Path to a file containing multiple targets")
    parser.add_argument("--output", help="Path to save the JSON scan results")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode (no payload execution)")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Number of concurrent requests (default: 20)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS verification")
    args = parser.parse_args()

    if args.target:
        asyncio.run(scan_target(args.target, semaphore=args.concurrency))
    elif args.list:
        asyncio.run(bulk_scan(args.list, args.concurrency, args.output, args.safe, args.no_verify))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
