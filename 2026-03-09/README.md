# Daily Security Tool — 2026-03-09

## CVE-2026-22719: VMware Aria Operations Unauthenticated Command Injection Scanner

### Threat Overview

**CVE-2026-22719** is a command injection vulnerability (CVSS 8.1) in **VMware Aria Operations** (formerly vRealize Operations), published and actively exploited as of March 2026. Broadcom disclosed the flaw and CISA immediately added it to the [Known Exploited Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), mandating that all U.S. Federal Civilian Executive Branch agencies apply the patch by **March 24, 2026**.

**Attack primitive:** An unauthenticated remote attacker sends a specially crafted HTTP request to the Aria Operations REST API. A lack of input sanitisation in the operations backend allows injected shell metacharacters to be executed as OS commands under the service account. No credentials are required, making this trivially wormable in environments where the management plane is reachable from the network.

### Why It Matters

- Aria Operations is the de-facto cloud/hybrid-infrastructure monitoring platform in large enterprises and government networks.
- Compromise of an Aria Operations node gives an attacker a privileged vantage point over **all monitored vSphere, AWS, Azure, and GCP workloads** — credentials, topology, alerts.
- CISA has confirmed active in-the-wild exploitation at the time of KEV listing.
- Many organisations expose the Aria Operations web UI to broad network segments, expanding the attack surface.

### Source Links

- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [The Hacker News — CISA Adds Actively Exploited VMware Aria Operations Flaw CVE-2026-22719 to KEV Catalog](https://thehackernews.com/2026/03/cisa-adds-actively-exploited-vmware.html)
- [Broadcom Support Portal (patch download)](https://support.broadcom.com/)

---

## Tool: `vmware_aria_cve_2026_22719_scanner.py`

A Python 3 CLI scanner that:

1. Probes one or more Aria Operations hosts over HTTPS.
2. Identifies whether the host is running Aria Operations (via API banner and version endpoint).
3. Extracts the running version and compares it against the first patched release (`8.18.2`).
4. Reports `VULNERABLE`, `PATCHED / NOT AFFECTED`, or `UNDETERMINED` per host.
5. Flags suspicious HTTP response headers that may indicate prior exploitation.
6. Outputs a machine-readable JSON report for SIEM/ticketing ingestion.

**No exploit code is included.** The tool performs safe, read-only probes.

### Requirements

- Python 3.8+
- Standard library only (no third-party packages needed)

### Usage Examples

```bash
# Scan a single host (default port 443)
python3 vmware_aria_cve_2026_22719_scanner.py --host aria.corp.local

# Scan with a non-standard port and verbose output
python3 vmware_aria_cve_2026_22719_scanner.py --host 10.10.5.20 --port 8443 --verbose

# Scan a list of hosts from a file
python3 vmware_aria_cve_2026_22719_scanner.py --file hosts.txt

# Save JSON report for SIEM ingestion
python3 vmware_aria_cve_2026_22719_scanner.py --file hosts.txt --output aria_scan_report.json

# Disable TLS verification for lab environments with self-signed certs
python3 vmware_aria_cve_2026_22719_scanner.py --host 192.168.1.50 --no-verify-tls

# Combine: file + JSON output + verbose
python3 vmware_aria_cve_2026_22719_scanner.py --file hosts.txt --output report.json --verbose
```

### Sample hosts.txt format

```
# VMware Aria Operations instances to scan
aria-prod.corp.local
10.0.1.100
monitoring.internal
# 10.0.1.200  <- commented out, skipped
```

### Sample Output

```
CVE-2026-22719 VMware Aria Operations Scanner
Scanning 2 host(s) on port 443 ...
------------------------------------------------------------
  aria-prod.corp.local:443  [Aria Operations detected]  version=8.17.0
    Status: VULNERABLE
  aria-staging.corp.local:443  [Aria Operations detected]  version=8.18.2
    Status: PATCHED / NOT AFFECTED

============================================================
SCAN SUMMARY — CVE-2026-22719 (VMware Aria Operations)
============================================================
  Hosts scanned   : 2
  Reachable       : 2
  VULNERABLE      : 1
  Patched/N/A     : 1
  Undetermined    : 0

  ACTION REQUIRED: Apply Broadcom patch immediately.
  Reference: https://support.broadcom.com/
  CISA KEV deadline: 2026-03-24 (federal agencies)
============================================================
```

### Patching Guidance

1. Log in to the [Broadcom Support Portal](https://support.broadcom.com/).
2. Download the patch for VMware Aria Operations >= **8.18.2**.
3. Follow the in-product update workflow or the offline patch procedure documented in the Broadcom advisory.
4. Re-run this scanner after patching to confirm the version is no longer vulnerable.
5. If you cannot patch immediately: restrict network access to the Aria Operations UI/API to management VLANs only.
