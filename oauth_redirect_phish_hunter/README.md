# oauth_redirect_phish_hunter

A CLI tool for detecting and analyzing **OAuth Redirection Abuse** phishing URLs — the active campaign technique first documented by Microsoft Defender on March 2, 2026, in which threat actors weaponize legitimate OAuth authorization endpoints (primarily Microsoft Entra ID / Azure AD) to silently redirect victims to attacker-controlled infrastructure for malware delivery or adversary-in-the-middle (AitM) credential theft.

---

## Threat Context

### What is OAuth Redirection Abuse?

Attackers craft malicious OAuth 2.0 authorization request URLs that look like legitimate sign-in links from trusted identity providers. Instead of completing a real login, the URLs are specifically engineered to **fail silently** and **redirect the victim's browser** to an attacker-controlled URL — all through the trusted Microsoft or Google OAuth endpoint.

The technique is dangerous because:

- **The link hostname is genuine** (`login.microsoftonline.com`) — URL-reputation and anti-phishing filters pass it.
- **No successful authentication is required.** The attacker uses parameters like `prompt=none` or intentionally invalid scopes to force an OAuth error code (`65001 interaction_required`), which causes Entra ID to redirect the victim to the attacker's registered `redirect_uri`.
- **Victim email is pre-populated.** Actors encode the target's email address in the `state` parameter (base64, URL-encoding, hex) so the phishing page auto-fills the victim's email — increasing conversion.
- **Lure themes** include e-signature requests, Social Security notices, Teams meeting invitations, and financial documents.
- **Payload delivery:** Victims land on a `/download/XXXX` path that auto-serves a malicious ZIP containing `.LNK` shortcut files and HTML smuggling loaders. Opening the `.LNK` runs PowerShell recon, then DLL side-loading via a legitimate `steam_monitor.exe` binary, with `crashhandler.dll` decrypting a C2-connected RAT payload.
- **AitM variant:** Some redirects go to EvilProxy-style adversary-in-the-middle kits to steal session cookies and bypass MFA.

### Why It Matters Right Now (March 2026)

- **Primary targets:** Government and public-sector organizations, confirmed by Microsoft Defender telemetry.
- **CISA awareness:** Active exploitation of OAuth abuse techniques was flagged as part of the broader March 2026 identity-infrastructure threat cluster.
- **Scale:** Campaigns used mass-sending tools built in Python and Node.js, cloud VMs, and cloud email services to distribute at scale.
- **Persistence:** Microsoft has disabled observed malicious OAuth applications in Entra ID, but related OAuth activity continues to emerge.

### Source Links

- [Microsoft Security Blog — OAuth redirection abuse enables phishing and malware delivery (Mar 2, 2026)](https://www.microsoft.com/en-us/security/blog/2026/03/02/oauth-redirection-abuse-enables-phishing-malware-delivery/)
- [The Hacker News — Microsoft Warns OAuth Redirect Abuse Delivers Malware to Government Targets](https://thehackernews.com/2026/03/microsoft-warns-oauth-redirect-abuse.html)
- [Help Net Security — Threat actors weaponize OAuth redirection logic to deliver malware (Mar 3, 2026)](https://www.helpnetsecurity.com/2026/03/03/attackers-abusing-oauth-redirection-phishing-malware/)
- [Bleeping Computer — Microsoft: Hackers abuse OAuth error flows to spread malware](https://www.bleepingcomputer.com/news/security/microsoft-hackers-abuse-oauth-error-flows-to-spread-malware/)
- [Malwarebytes — Attackers abuse OAuth's built-in redirects (Mar 2026)](https://www.malwarebytes.com/blog/news/2026/03/attackers-abuse-oauths-built-in-redirects-to-launch-phishing-and-malware-attacks)

---

## What This Tool Does

`oauth_redirect_phish_hunter` performs **static analysis** of OAuth authorization URLs to surface indicators of abuse. It does **not** make network requests or follow redirects — safe to run on air-gapped analyst workstations.

### Detection Checks

| Check | Severity | What it finds |
|---|---|---|
| `OAUTH_URL_DETECTED` | INFO | URL matches known OAuth authorization endpoint patterns |
| `SILENT_FLOW_ABUSE` | HIGH | `prompt=none` or similar forces silent error redirect |
| `SUSPICIOUS_REDIRECT_URI` | CRITICAL | `redirect_uri` points to ngrok, Cloudflare tunnel, raw IP, etc. |
| `AITM_DOWNLOAD_PATH` | CRITICAL | `redirect_uri` contains `/download/XXXX` (campaign signature) |
| `PII_IN_OAUTH_PARAM` | HIGH | `state` / `login_hint` contains encoded victim email address |
| `STRUCTURED_STATE_PARAM` | MEDIUM | `state` decodes to readable/structured content instead of random nonce |
| `MISSING_CLIENT_ID` | MEDIUM | Absent `client_id` forces predictable error redirect |
| `OAUTH_DOMAIN_SPOOFING` | HIGH | OAuth path on a domain typosquatting a legitimate IdP |

### Decoding

The tool automatically attempts URL decoding, Base64 (standard + URL-safe), and hex decoding on parameter values to surface obfuscated victim email addresses.

---

## Install

No external dependencies — requires only Python 3.8+.

```bash
git clone <repo-url>
cd oauth_redirect_phish_hunter
python3 oauth_redirect_phish_hunter.py --help
```

---

## Usage & Sample Output

### Analyze a single URL

```bash
python3 oauth_redirect_phish_hunter.py url \
  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc123&prompt=none&redirect_uri=https://198.51.100.5/download/Xk9mQ&state=dXNlckBleGFtcGxlLmNvbQ==&scope=openid" \
  --verbose
```

**Sample output:**
```
========================================================================
  URL    : https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc123&prompt=none&...
  OAuth  : Yes
  Risk   : CRITICAL  (score: 95/100)
  !! Email in state param: user@example.com
  Findings (4):
    [INFO] OAUTH_URL_DETECTED
         URL matches an OAuth authorization endpoint pattern.
    [HIGH] SILENT_FLOW_ABUSE
         Parameter 'prompt=none' forces silent authentication. In the 2026 campaign,
         this triggers an error+redirect to redirect_uri without user interaction.
         Evidence: prompt=none
    [CRITICAL] SUSPICIOUS_REDIRECT_URI
         redirect_uri matches suspicious pattern '...\d{1,3}\.\d{1,3}...' — raw IP address.
         Evidence: redirect_uri=https://198.51.100.5/download/Xk9mQ
    [CRITICAL] AITM_DOWNLOAD_PATH
         redirect_uri contains an AitM/malware-delivery path pattern '/download/[A-Za-z0-9_-]{4,}'.
         The March 2026 campaign used /download/XXXX paths to auto-deliver malicious ZIP archives.
    [HIGH] PII_IN_OAUTH_PARAM
         Parameter 'state' contains or encodes an email address ('user@example.com').
         Evidence: state decoded value: user@example.com
========================================================================
```

### Scan a file of URLs (e.g., from proxy logs)

```bash
python3 oauth_redirect_phish_hunter.py scan proxy_logs_oauth_urls.txt -o results.json
```

**Sample output:**
```
[*] Scanning 412 URLs from proxy_logs_oauth_urls.txt

  [... flagged entries printed ...]

[SUMMARY] 412 URLs scanned
  CLEAN: 398
  LOW: 3
  MEDIUM: 4
  HIGH: 5
  CRITICAL: 2
[*] JSON report written to results.json
```

### Analyze a phishing email (.eml)

```bash
python3 oauth_redirect_phish_hunter.py email suspicious_esignature_request.eml --verbose
```

**Sample output:**
```
[*] Analyzing email: suspicious_esignature_request.eml

[SUMMARY] Email analysis: suspicious_esignature_request.eml
  Total URLs found          : 23
  Suspicious OAuth URLs     : 2
  Lure keywords detected    : e-signature, action required

========================================================================
  URL    : https://login.microsoftonline.com/common/oauth2/v2.0/authorize?...
  OAuth  : Yes
  Risk   : HIGH  (score: 65/100)
  !! Email in state param: victim@agency.gov
  Findings (3):
    [INFO]  OAUTH_URL_DETECTED ...
    [HIGH]  SILENT_FLOW_ABUSE ...
    [HIGH]  PII_IN_OAUTH_PARAM ...
========================================================================
```

### Decode a state parameter value

```bash
python3 oauth_redirect_phish_hunter.py decode-state "dXNlckBhZ2VuY3kuZ292"
```

**Sample output:**
```
[*] Input    : dXNlckBhZ2VuY3kuZ292
[*] Decoded  : user@agency.gov
[!] Email address found in state: user@agency.gov
```

### Generate a structured JSON report

```bash
python3 oauth_redirect_phish_hunter.py report \
  --input extracted_urls.txt \
  --output oauth_phish_report.json
```

---

## Integrating with SOC Workflows

**From proxy/firewall logs:** Extract URLs where the host is `login.microsoftonline.com` or `accounts.google.com`, feed them to `scan`, and alert on CRITICAL/HIGH results.

**From email gateways:** Export suspicious emails as `.eml` and pipe through `email` subcommand.

**SIEM rule hint:** Alert when OAuth authorization requests contain both `prompt=none` AND a `redirect_uri` that does not match your organization's registered application URIs.

---

## Limitations

- This tool performs **static, offline analysis only** — it does not visit URLs or follow redirects.
- Detection is heuristic-based; novel campaign variants may use different parameter abuse patterns.
- Legitimate applications occasionally use `prompt=none` for SSO flows — cross-reference `client_id` against your organization's registered app inventory.
