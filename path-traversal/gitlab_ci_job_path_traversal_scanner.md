# GitLab CI Job Path Traversal Scanner (CVE-2026-44578)

## Overview
The `gitlab_ci_job_path_traversal_scanner.py` tool detects GitLab instances vulnerable to a path traversal vulnerability in the CI job artifact download endpoint. Exploiting CVE-2026-44578 could allow an attacker to retrieve arbitrary files, including sensitive data, from the server filesystem.

## Vulnerability Details
- **CVE ID**: CVE-2026-44578
- **Affected Versions**: GitLab <= 15.8.4, <= 15.9.2, <= 15.10.1
- **CVSS v3.1 Base Score**: 9.1 (Critical)
- **Exploitation Impact**: Disclosure of sensitive files, including configuration files and credentials.
- **References**:
  - [CVE details on NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-44578)
  - [GitLab Security Advisory](https://about.gitlab.com/releases/categories/releases/)

## Usage Examples

### Scan a single target
