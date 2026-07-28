# AWS IAM Policy Privilege Escalation Scanner

This tool scans AWS IAM identities (users, roles, groups) and attached policies to identify 
potential privilege escalation pathways that could be exploited in an AWS environment. It helps 
security professionals assess IAM configurations for vulnerabilities.

## Features

- **Target scanning:** Analyze specific AWS IAM identities (e.g., user, role).
- **Policy evaluation:** Identify risky actions that enable privilege escalation.
- **Safe mode:** Detection-only mode without abuse workflows.
- **Bulk scanning:** Scan multiple identities from a file.
- **JSON reports:** Save output in structured JSON format.
- **Concurrency control:** Adjustable parallel request limits for efficient scanning.

## Usage

### Scan a Single Identity
