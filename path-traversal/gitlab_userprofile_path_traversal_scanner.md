# GitLab User Profile Path Traversal Scanner (CVE-2025-12345)

## Overview

This tool scans for GitLab instances vulnerable to the User Profile Path Traversal
vulnerability (CVE-2025-12345). The flaw allows unauthorized access to server-side files
via improper sanitization of file path inputs. Attackers may potentially leak sensitive
data such as credentials, configurations, or SSH keys.

## CVE Details

- **CVE**: [CVE-2025-12345](https://nvd.nist.gov/vuln/detail/CVE-2025-12345)
- **Vulnerable Systems**: GitLab CE/EE <= 15.11.6 and <= 16.0.1
- **CVSS**: 9.5 (Critical)
- **Impact**: Exposes server-side files via crafted requests to the avatar upload API.

## Usage

Examples of how to run the scanner:

### Single Target Scan
