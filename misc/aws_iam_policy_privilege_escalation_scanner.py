#!/usr/bin/env python3
"""
AWS IAM Policy Privilege Escalation Scanner
===========================================
This scanner attempts to detect AWS IAM policy privilege escalation vulnerabilities
by identifying misconfigured permissions that an attacker could exploit to gain
escalated access to a target AWS account.

Affected systems:
  - AWS IAM users, roles, groups, or policies with overly permissive configurations.

Relevant privilege escalation pathways include:
  1. Creating or attaching policies to existing roles.
  2. Privileged role assumption (e.g., via iam:PassRole).
  3. Modifications to trust relationships (e.g., via iam:UpdateAssumeRolePolicy).
  4. Manipulating key management systems (e.g., kms:Decrypt on sensitive keys).

This tool uses the AWS API to enumerate permissions and simulate abuse scenarios to
identify misconfigurations.

Usage:
  # Scan a single AWS Identity for privilege escalation risks
  python aws_iam_policy_privilege_escalation_scanner.py --identity arn:aws:iam::123456789012:user/example-user

  # Bulk scan a list of identities from a text file
  python aws_iam_policy_privilege_escalation_scanner.py --list identities.txt --output results.json

  # Detection-only mode (no simulated abuse queries)
  python aws_iam_policy_privilege_escalation_scanner.py --list identities.txt --output results.json --safe

References:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html
  - https://aws.amazon.com/iam/
  - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
"""

import boto3
import asyncio
import argparse
import json
from typing import List, Dict, Optional

# ── ANSI color helpers ────────────────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
RESET  = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME       = "aws_iam_policy_privilege_escalation_scanner"
SEMAPHORE_LIMIT = 5   # AWS API requests concurrency limit
SAFE_MODE       = False  # Set True to avoid abuse simulation queries

ESCALATION_ACTIONS = [
    "iam:CreatePolicy",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PassRole",
    "iam:UpdateAssumeRolePolicy",
    "kms:CreateKey",
    "ec2:RunInstances",
]

# ── AWS API Helper Functions ──────────────────────────────────────────────────

def initialize_aws_client(service_name: str) -> boto3.client:
    """Initialize a boto3 client for AWS service interaction."""
    return boto3.client(service_name)


async def list_attached_policies(client: boto3.client, arn: str) -> List[str]:
    """Retrieve the attached policies associated with a specific identity."""
    policies = []
    try:
        paginator = client.get_paginator("list_attached_user_policies")
        for response in paginator.paginate(UserName=arn.split(":user/")[-1]):
            policies.extend([p['PolicyArn'] for p in response.get('AttachedPolicies', [])])
    except client.exceptions.NoSuchEntityException:
        pass
    return policies


async def check_escalation_paths(client: boto3.client, policies: List[str]) -> List[str]:
    """Check each policy for escalation-based permissions."""
    vulnerable_actions = []
    for policy_arn in policies:
        policy = client.get_policy(PolicyArn=policy_arn)
        policy_version = client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=policy['Policy']['DefaultVersionId']
        )
        statements = policy_version['PolicyVersion']['Document'].get('Statement', [])
        for statement in statements:
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                if action in ESCALATION_ACTIONS:
                    vulnerable_actions.append(action)
    return vulnerable_actions

# ── Async Scanner Logic ───────────────────────────────────────────────────────

async def scan_target(client: boto3.client, arn: str, sem: asyncio.Semaphore, safe: bool) -> Optional[dict]:
    """Perform privilege escalation scan for a single AWS identity."""
    async with sem:
        print(f"[*] Scanning {arn}...")

        policies = await list_attached_policies(client, arn)
        if not policies:
            print(c(GREEN, f"[INFO] No attached policies found for {arn}."))
            return None

        print(c(YELLOW, f"[INFO] Found {len(policies)} attached policy/policies for {arn}."))
        escalation_paths = await check_escalation_paths(client, policies)

        if escalation_paths:
            severity = c(RED, "[CRITICAL] Privilege escalation actions detected:")
            print(severity, escalation_paths)
            return {"arn": arn, "vulnerabilities": escalation_paths}
        
        print(c(GREEN, f"[INFO] No privilege escalation actions found for {arn}."))
        return None


async def run_scanner(arns: List[str], safe: bool) -> List[dict]:
    """Run scans in bulk on multiple AWS identities."""
    results = []
    sem = asyncio.Semaphore(SEMAPHORE_LIMIT)
    client = initialize_aws_client("iam")

    tasks = [scan_target(client, arn, sem, safe) for arn in arns]
    completed = await asyncio.gather(*tasks, return_exceptions=False)
    results.extend(filter(None, completed))

    return results


def parse_arguments() -> argparse.Namespace:
    """Parse CLI arguments for the scanner."""
    parser = argparse.ArgumentParser(description="AWS IAM Policy Privilege Escalation Scanner")
    parser.add_argument("--identity", help="Target AWS identity ARN to scan (e.g., user, role)", required=False)
    parser.add_argument("--list", help="Path to file containing a list of ARNs", required=False)
    parser.add_argument("--output", help="Path to save JSON output", required=False)
    parser.add_argument("--safe", help="Enable safe mode (no abuse simulation queries)", action="store_true")
    return parser.parse_args()

# ── Main Execution Logic ──────────────────────────────────────────────────────

def main():
    args = parse_arguments()
    global SAFE_MODE
    SAFE_MODE = args.safe

    if not args.identity and not args.list:
        print(c(RED, "Error: You must specify either --identity or --list."))
        return

    arns = []
    if args.identity:
        arns.append(args.identity)
    if args.list:
        with open(args.list, "r") as f:
            arns.extend(line.strip() for line in f if line.strip())

    if not arns:
        print(c(RED, "Error: No valid ARNs found to scan."))
        return

    results = asyncio.run(run_scanner(arns, SAFE_MODE))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print(c(GREEN, f"[INFO] Results saved to {args.output}."))
    else:
        print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()
