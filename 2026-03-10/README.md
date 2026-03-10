# oauth_phish_hunter — OAuth Redirection Abuse Phishing Detector

**Date:** 2026-03-10
**Threat:** Active OAuth phishing campaign abusing Microsoft Entra ID's error-redirect flow (March 2026)
**Status:** Actively exploited in the wild against government and enterprise targets

---

## Threat Context

On **March 2, 2026**, Microsoft's Defender threat intelligence team published research documenting a sophisticated phishing campaign that weaponises the legitimate OAuth 2.0 authorization protocol to bypass email and browser-based phishing defences.

### How the attack works

1. The attacker registers a malicious application in an Azure/Entra ID tenant they control, setting the `redirect_uri` to their malware-serving infrastructure.
2. A phishing email (with a convincing subject — shared document, password reset, HR notice, etc.) is sent to the victim. The email contains a crafted OAuth authorization URL targeting Entra ID.
3. The URL includes `prompt=none`, requesting **silent authentication**. When the user clicks the link, the browser silently attempts to authenticate.
4. Because the scope is deliberately invalid or the user has not already consented, Entra ID returns **error code 65001** (`interaction_required`) and **redirects the browser to the attacker's `redirect_uri`**.
5. The attacker pre-populated the victim's email address in the OAuth `state` parameter (using plaintext, hex, Base64, or custom encoding) so the phishing landing page is automatically filled in.
6. The landing page delivers a ZIP file containing a Windows shortcut (LNK) that runs PowerShell → DLL side-loading → hands-on-keyboard ransomware activity.

### Why it bypasses defences

- The initial OAuth URL points to `login.microsoftonline.com` — a fully trusted Microsoft domain. Secure Email Gateways (SEGs) and browsers do not flag it.
- The malicious redirect only happens client-side after Entra ID issues the 65001 error; the attacker's domain never appears directly in the email.

### Targets & attribution

Microsoft observed targeting of **government and public-sector organisations**. The campaign is tracked by multiple vendors including Rapid7, Arctic Wolf, SOCRadar, and Talos.

### Sources

- [Microsoft Security Blog — OAuth redirection abuse enables phishing and malware delivery (2026-03-02)](https://www.microsoft.com/en-us/security/blog/2026/03/02/oauth-redirection-abuse-enables-phishing-malware-delivery/)
- [The Hacker News — Microsoft Warns OAuth Redirect Abuse Delivers Malware to Government Targets](https://thehackernews.com/2026/03/microsoft-warns-oauth-redirect-abuse.html)
- [BleepingComputer — Microsoft: Hackers abuse OAuth error flows to spread malware](https://www.bleepingcomputer.com/news/security/microsoft-hackers-abuse-oauth-error-flows-to-spread-malware/)
- [Rapid7 — ETR: Critical OAuth Abuse Exploited In The Wild](https://www.rapid7.com/blog/post/etr-critical-cisco-catalyst-vulnerability-exploited-in-the-wild-cve-2026-20127/)
- [Security Affairs — Phishing campaign exploits OAuth redirection to bypass defenses](https://securityaffairs.com/188829/hacking/phishing-campaign-exploits-oauth-redirection-to-bypass-defenses/)
- [Help Net Security — Threat actors weaponize OAuth redirection logic to deliver malware](https://www.helpnetsecurity.com/2026/03/03/attackers-abusing-oauth-redirection-phishing-malware/)

---

## Tool: oauth_phish_hunter.py

A purpose-built static analyser and log hunter that detects the **specific indicators** of this OAuth redirection abuse campaign. Unlike generic URL scanners, it understands the exact mechanics of the attack and scores findings accordingly.

### What it detects

| Indicator | Score | Description |
|-----------|-------|-------------|
| `prompt=none` in OAuth URL | +30 | Core attack primitive — triggers silent auth attempt |
| `state` param encodes victim email | +40 | High-confidence indicator; all known encodings tried (plain, URL-encoded, Base64, hex) |
| `redirect_uri` outside Microsoft domains | +25 | The payload delivery endpoint |
| Invalid/unusual OAuth scope | +20 | Deliberately malformed to force 65001 error |
| Entra ID sign-in log error 65001 | +35 | Direct evidence of the error-redirect being triggered |
| Phishing-themed email subject | +15 | Correlating indicator |

**Verdict thresholds:**
- Score ≥ 80 → HIGH CONFIDENCE — PHISHING
- Score ≥ 40 → MEDIUM CONFIDENCE — SUSPICIOUS
- Score ≥ 15 → LOW CONFIDENCE — WORTH REVIEWING

### Requirements

Python 3.8+ — standard library only, no dependencies to install.

---

## Installation

```bash
# No pip install needed — stdlib only
git clone <this-repo>
cd daily-tools-repo/2026-03-10
python3 oauth_phish_hunter.py --help
```

---

## Usage Examples

### 1. Analyse a single suspicious OAuth URL

```bash
python3 oauth_phish_hunter.py url \
  --url "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc123&response_type=code&redirect_uri=https://evil.example.com/callback&scope=garbage_scope&prompt=none&state=dXNlckBleGFtcGxlLmNvbQ=="
```

Expected output:
```
======================================================================
  VERDICT : HIGH CONFIDENCE — PHISHING
  SCORE   : 115
  FINDINGS: 4
======================================================================

[+ 30]  prompt=none in OAuth URL
       Source  : cli
       Detail  : Attackers use prompt=none to attempt silent authentication...

[+ 40]  state parameter encodes victim email
       Source  : cli
       Victim  : user@example.com

[+ 25]  redirect_uri points to non-Microsoft domain
       Source  : cli
       Detail  : redirect_uri resolves to 'evil.example.com'...

[+ 20]  Unusual / invalid OAuth scope
       Source  : cli
       Detail  : The scope parameter contains values that do not match...
```

### 2. Scan a suspicious email file

```bash
python3 oauth_phish_hunter.py emails --input /path/to/suspicious.eml --verbose
```

### 3. Scan an entire mbox export

```bash
python3 oauth_phish_hunter.py emails --input ~/Downloads/Inbox.mbox
```

### 4. Scan a URL list (e.g., exported from your SEG logs)

```bash
python3 oauth_phish_hunter.py urls --input clicked_links.txt
```

### 5. Scan Entra ID sign-in logs (JSON export from Azure Portal)

```bash
# Export from: Azure Portal > Entra ID > Sign-in logs > Download > JSON
python3 oauth_phish_hunter.py logs --input signin_logs.json
```

### 6. Scan Entra ID sign-in logs (CSV export)

```bash
python3 oauth_phish_hunter.py logs --input signin_logs.csv
```

### 7. JSON output (for SIEM / pipeline integration)

```bash
python3 oauth_phish_hunter.py url \
  --url "https://login.microsoftonline.com/..." \
  --json | jq '.findings[] | select(.score >= 30)'
```

### 8. Use in a shell pipeline (exit code 1 = findings present)

```bash
# Alert if any phishing indicators found across multiple mbox files
for f in /mail/exports/*.mbox; do
  python3 oauth_phish_hunter.py emails --input "$f" --json >> all_findings.json && \
    echo "CLEAN: $f" || echo "ALERT: $f"
done
```

---

## Obtaining Entra ID Sign-In Logs

1. Sign in to the [Azure Portal](https://portal.azure.com)
2. Navigate to **Microsoft Entra ID** → **Monitoring** → **Sign-in logs**
3. Filter by date range and optionally by **Status = Failure**
4. Click **Download** → choose **JSON** or **CSV**
5. Pass the downloaded file to `oauth_phish_hunter.py logs --input <file>`

---

## Limitations

- Does not perform live network requests or dereference URLs.
- Does not decrypt S/MIME or PGP-encrypted emails.
- Entra ID CSV export column names may vary by region/portal version; the tool attempts common variants.
- The `state` decoder covers encodings observed in the wild as of March 2026; novel encodings may be missed.

---

## Mitigation Recommendations

1. **Restrict OAuth app consent**: Enforce admin-only consent policies in Entra ID.
2. **Conditional Access**: Block sign-ins from unmanaged devices for sensitive apps.
3. **Monitor error 65001**: Alert on sign-in log entries with `resultType=65001` from unrecognised app IDs.
4. **MCAS / Defender for Cloud Apps**: Enable anomaly detection policies for OAuth apps.
5. **User training**: Train users to treat any OAuth consent prompt appearing after clicking an email link as suspicious.
