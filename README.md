# MDO Threat Policy Analyzer

Assess Microsoft Defender for Office 365 (MDO) threat protection settings against Microsoft's recommended **Standard** and **Strict** baselines.

`MDOThreatPolicyAnalyzer.ps1` connects to Exchange Online, reviews your tenant's email threat protection policies, and produces a polished HTML report with optional CSV exports so administrators can quickly spot gaps and prioritize remediation.

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

## Screenshots

> _Screenshot placeholders — add report images here before publishing._

- Executive summary view
- Category scorecards
- Detailed findings section
- Additional security checks section

## Requirements

- Windows PowerShell **5.1 or later**
- **ExchangeOnlineManagement** PowerShell module
- Microsoft 365 permissions sufficient to read Exchange Online / Defender for Office 365 policy configuration
- Ability to authenticate interactively to:
  - Exchange Online PowerShell
  - Security & Compliance PowerShell

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

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `-OutputPath` | String | Saves the HTML report, log, and CSV exports to a custom folder. Default: `Output` under the script directory. |
| `-SkipCsvExport` | Switch | Skips CSV export and only generates the HTML report and log file. |
| `-SkipBrowserOpen` | Switch | Prevents the report from opening automatically after the run completes. |
| `-AdminUPN` | String | Supplies a UPN hint for interactive sign-in, such as `admin@contoso.com`. |
| `-InstallModuleIfMissing` | Switch | Automatically installs `ExchangeOnlineManagement` for the current user if it is missing. |
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

### CSV exports include

- Raw policy and rule collections
- `AssessmentResults.csv`
- `AdditionalSecurityFindings.csv`
- Supporting exports such as DKIM configs, accepted domains, transport rules, connectors, and quarantine policies

## Contributing

Contributions are welcome. If you want to improve report formatting, expand policy coverage, or enhance validation logic:

1. Fork the repository
2. Create a feature branch
3. Make and test your changes
4. Open a pull request with a clear description of the improvement

## License

> License placeholder — add your preferred license before publishing.
