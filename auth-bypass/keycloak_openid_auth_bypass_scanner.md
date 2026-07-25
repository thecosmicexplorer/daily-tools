# Keycloak OpenID Connect Authentication Bypass Scanner

This tool scans for instances of Keycloak vulnerable to CVE-2026-77890, an authentication bypass flaw in the OpenID Connect protocol token issuance process.

## Overview

- **Vulnerability**: CVE-2026-77890
- **Impact**: Unauthenticated attackers can impersonate users by bypassing authentication mechanisms and obtaining tokens.
- **Risk**: Critical (CVSS 9.6)
- **Affected Versions**: Keycloak <= 22.0.3

## Features

- **Detection**: Fingerprints and detects Keycloak servers.
- **Active Probing**: Checks for token issuance flaws unless `--safe` flag is used.
- **Concurrency Control**: Scans multiple targets simultaneously.
- **JSON Output**: Saves detailed results for automated processing.

## Usage

### Single Target Scan

