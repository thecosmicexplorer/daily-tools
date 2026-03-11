# Code Scan Report — 2026-03-11

**Status: 🟡 REVIEW RECOMMENDED**

| Metric | Count |
|--------|-------|
| Files scanned | 4 |
| Total issues  | 1 |
| 🔴 High severity vulnerabilities | 0 |
| 🟡 Medium severity vulnerabilities | 1 |
| ⚪ Low severity vulnerabilities | 0 |
| 🔑 Secrets / tokens detected | 0 |
| 👤 PII patterns detected | 0 |

## 🟡 Medium Severity Vulnerabilities

- **2026-03-09/vmware_aria_cve_2026_22719_scanner.py** line 140 — `B310`: Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

---
*Scanned by automated pipeline on 2026-03-11. Powered by [bandit](https://bandit.readthedocs.io) + custom regex checks.*