# MDO Threat Policy Analyzer

Assess Microsoft Defender for Office 365 (MDO) threat protection settings against Microsoft's recommended **Standard** and **Strict** baselines.

`MDOThreatPolicyAnalyzer.ps1` connects to Exchange Online, reviews your tenant's email threat protection policies, and produces an interactive HTML report with optional CSV exports so administrators can quickly spot gaps and prioritize remediation.

## Key Features

- Baseline analysis for:
  - Anti-phishing
  - Inbound anti-spam
  - Outbound anti-spam
  - Anti-malware
  - Safe Links
  - Safe Attachments
  - Global ATP settings
- Additional security checks for coverage gaps, bypass risks, authentication posture, audit logging, and related controls
- Interactive HTML report with sidebar navigation and per-section export buttons
- Optional CSV export of collected policy objects, rules, assessment results, and additional findings
- Friendly output for administrators who want actionable recommendations, not just raw configuration data

## Requirements

- Windows PowerShell **5.1 or later**
- **ExchangeOnlineManagement** PowerShell module
- Microsoft 365 permissions sufficient to read Exchange Online / Defender for Office 365 policy configuration
- Ability to authenticate to:
  - Exchange Online PowerShell
  - Security & Compliance PowerShell
  - …interactively (default), **or** unattended via app-only certificate authentication (`-AppId` / `-Organization` / `-CertificateThumbprint`)

## 🔒 Security Notice

- **Least privilege** — run with a read-only role such as **Global Reader** or **Security Reader**; do not use Global Administrator. The script only reads policy configuration and never changes tenant settings.
- **App-only auth for automation** — prefer certificate-based app-only authentication (`-AppId` / `-Organization` / `-CertificateThumbprint`) for unattended runs. It avoids interactive prompts and supports least-privilege service principals.
- **Output classification** — the HTML report, `.log`, and companion CSVs are **CONFIDENTIAL**. They contain policy names, accepted domains, mailbox/UPN references, connector details, and other security-relevant configuration. Apply your organization's sensitivity label and share only via protected channels.
- **Input & injection hardening** — CSV / Excel exports are hardened against spreadsheet formula injection. String values beginning with `=`, `+`, `-`, `@`, tab, or carriage return are neutralized (prefixed with `'`) in both the server-side CSVs and the in-report *Export to Excel* feature, so a maliciously named policy or rule cannot execute a formula when opened.
- **Location** — run the script from a non-synced local directory (avoid OneDrive/SharePoint/Desktop sync folders), and store the `Output` folder in an access-controlled location.
- **Cleanup** — delete report and CSV output after review per your retention policy, and disconnect sessions when finished:

  ```powershell
  Disconnect-ExchangeOnline -Confirm:$false
  ```

- **Integrity** — the script is Authenticode signed for tamper detection. Verify the signature before running (Subject `CN=AbdullahZmailiCodeSigningMDOThreatPolicyAnalyzer`, Thumbprint `697A6E565CD9B3B93E3CD2435B8AFE1A24D99672`):

  ```powershell
  Get-AuthenticodeSignature .\MDOThreatPolicyAnalyzer.ps1
  ```

## Quick Install / Usage

```powershell
# 1) Open PowerShell
# 2) Download or clone this repository
# 3) Optional: install the module yourself
Install-Module ExchangeOnlineManagement -Scope CurrentUser

# 4) Run the analyzer
.\MDOThreatPolicyAnalyzer.ps1
```

Example with common options:

```powershell
.\MDOThreatPolicyAnalyzer.ps1 `
  -AdminUPN admin@contoso.com `
  -OutputPath "C:\Reports\MDO" `
  -InstallModuleIfMissing `
  -SkipBrowserOpen
```

Unattended run with app-only certificate authentication (no interactive prompt):

```powershell
.\MDOThreatPolicyAnalyzer.ps1 `
  -AppId "00000000-0000-0000-0000-000000000000" `
  -Organization "contoso.onmicrosoft.com" `
  -CertificateThumbprint "AABBCCDDEEFF00112233445566778899AABBCCDD" `
  -OutputPath "C:\Reports\MDO" `
  -SkipBrowserOpen -Quiet
```

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `-OutputPath` | String | Saves the HTML report, log, and CSV exports to a custom folder. Default: `Output` under the script directory. |
| `-SkipCsvExport` | Switch | Skips CSV export and only generates the HTML report and log file. |
| `-SkipBrowserOpen` | Switch | Prevents the report from opening automatically after the run completes. |
| `-AdminUPN` | String | Supplies a UPN hint for interactive sign-in, such as `admin@contoso.com`. |
| `-AppId` | String | Application (client) ID for unattended **app-only certificate authentication**. Must be used together with `-Organization` and `-CertificateThumbprint`. |
| `-Organization` | String | Tenant organization for app-only auth, e.g. `contoso.onmicrosoft.com`. Required with `-AppId` / `-CertificateThumbprint`. |
| `-CertificateThumbprint` | String | Thumbprint of the certificate (in the current user/machine store) used for app-only auth. Required with `-AppId` / `-Organization`. |
| `-InstallModuleIfMissing` | Switch | Automatically installs `ExchangeOnlineManagement` (minimum v3.0.0) for the current user if it is missing. |
| `-Version` | Switch | Displays version information and exits. |
| `-Quiet` | Switch | Reduces console output and leaves errors plus final summary visible. |

## What the Script Analyzes

### Core policy areas

- Anti-phishing policies and rules
- Inbound anti-spam policies and rules
- Outbound anti-spam policies and rules
- Anti-malware policies and rules
- Safe Attachments policies and rules
- Safe Links policies and rules
- Global ATP settings

### Additional security checks

- Quarantine policy reference validation
- Rule coverage and tenant-wide scope checks
- Preset security policy detection
- Policy priority review
- DKIM and DMARC posture checks
- Transport rule bypass detection
- Inbound connector security checks
- Impersonation protection coverage
- Tenant Allow/Block List audit
- Advanced Delivery checks
- Unified audit log verification
- Safe Links / Safe Attachments coverage validation
- Zero-Hour Auto Purge (ZAP) checks
- Outbound spam notification checks

## Output

The script produces:

- **HTML report**: `MDOThreatPolicyAnalyzer-Report-<timestamp>.html`
- **Optional CSV exports** when `-SkipCsvExport` is not used
- **Execution log**: `MDOThreatPolicyAnalyzer-<timestamp>.log`

By default, files are written to the `Output` folder beside the script. Use `-OutputPath` to choose another location.
