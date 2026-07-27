# Kubernetes Dashboard Unauthenticated RCE Scanner (CVE-2018-18264)

This tool scans for Kubernetes Dashboard instances that are vulnerable to CVE-2018-18264, 
an unauthenticated remote code execution vulnerability. Misconfigured dashboards 
allow attackers to interact with the Kubernetes API using dashboard service account 
permissions, potentially leading to privilege escalation and remote command execution.

## Usage

### Single Target Scan:
