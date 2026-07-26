# Detailed Usage Instructions

This guide explains how to run `MDOThreatPolicyAnalyzer.ps1`, what it evaluates, and how to interpret the generated output.

## Overview

`MDOThreatPolicyAnalyzer.ps1` reviews Microsoft Defender for Office 365 threat protection configuration and compares your tenant against Microsoft's published **Standard** and **Strict** recommended settings. The script focuses on practical administrator output: where protection matches, where it does not, and what to review next.

## Full Parameter Reference

### `-OutputPath <String>`

Writes the HTML report, log file, and any CSV exports to a custom folder.

**Example**

```powershell
.\MDOThreatPolicyAnalyzer.ps1 -OutputPath "C:\Reports\MDO"
```

### `-SkipCsvExport`

Skips CSV export. Use this when you only want the HTML report.

**Example**

```powershell
.\MDOThreatPolicyAnalyzer.ps1 -SkipCsvExport
```

### `-SkipBrowserOpen`

Prevents the script from opening the generated HTML report automatically.

**Example**

```powershell
.\MDOThreatPolicyAnalyzer.ps1 -SkipBrowserOpen
```

### `-AdminUPN <String>`

Supplies a User Principal Name as a sign-in hint for interactive authentication.

**Example**

```powershell
.\MDOThreatPolicyAnalyzer.ps1 -AdminUPN admin@contoso.com
```

### `-AppId <String>`

Application (client) ID for unattended **app-only certificate authentication**. Must be used together with `-Organization` and `-CertificateThumbprint`.

### `-Organization <String>`

Tenant organization for app-only authentication, for example `contoso.onmicrosoft.com`. Required with `-AppId` and `-CertificateThumbprint`.

### `-CertificateThumbprint <String>`

Thumbprint of the certificate (in the current user or machine store) used for app-only authentication. Required with `-AppId` and `-Organization`.

**Example (app-only)**

```powershell
.\MDOThreatPolicyAnalyzer.ps1 `
  -AppId "00000000-0000-0000-0000-000000000000" `
  -Organization "contoso.onmicrosoft.com" `
  -CertificateThumbprint "AABBCCDDEEFF00112233445566778899AABBCCDD"
```

### `-InstallModuleIfMissing`

If `ExchangeOnlineManagement` is not installed, the script installs it for the current user.

**Example**

```powershell
.\MDOThreatPolicyAnalyzer.ps1 -InstallModuleIfMissing
```

### `-Version`

Displays the script version and exits.

**Example**

```powershell
.\MDOThreatPolicyAnalyzer.ps1 -Version
```

### `-Quiet`

Reduces console output. Errors and the final summary remain visible.

**Example**

```powershell
.\MDOThreatPolicyAnalyzer.ps1 -Quiet
```

## Example Command Combinations

### Standard interactive run

```powershell
.\MDOThreatPolicyAnalyzer.ps1
```

### Run with sign-in hint and custom output path

```powershell
.\MDOThreatPolicyAnalyzer.ps1 -AdminUPN admin@contoso.com -OutputPath "C:\Reports\MDO"
```

### Generate HTML only for a remote session or jump box

```powershell
.\MDOThreatPolicyAnalyzer.ps1 -SkipCsvExport -SkipBrowserOpen
```

### Low-noise run

```powershell
.\MDOThreatPolicyAnalyzer.ps1 -Quiet -SkipBrowserOpen
```

### Convenience run when prerequisites may be missing

```powershell
.\MDOThreatPolicyAnalyzer.ps1 -InstallModuleIfMissing -AdminUPN admin@contoso.com
```

### Unattended run with app-only certificate authentication

```powershell
.\MDOThreatPolicyAnalyzer.ps1 `
  -AppId "00000000-0000-0000-0000-000000000000" `
  -Organization "contoso.onmicrosoft.com" `
  -CertificateThumbprint "AABBCCDDEEFF00112233445566778899AABBCCDD" `
  -OutputPath "C:\Reports\MDO" -Quiet -SkipBrowserOpen
```

## Authentication Flow

The script supports two authentication modes: **interactive** (default) and **app-only certificate authentication** (unattended).

1. It checks whether the `ExchangeOnlineManagement` module is available.
2. It connects to **Exchange Online**.
3. It connects to **Security & Compliance PowerShell**.
4. It uses the same identity for data collection.

When `-AppId`, `-Organization`, and `-CertificateThumbprint` are all supplied, the script connects non-interactively using the certificate. If only some of those parameters are provided, the script stops with an error because all three are required together. Otherwise, the script falls back to interactive sign-in.

### What `-AdminUPN` does

`-AdminUPN` is a **sign-in hint**, not a stored credential and not a full unattended authentication method. It simply tells the connection commands which account you expect to use.

This is helpful when:

- you administer multiple tenants
- several work/school accounts are signed in on the same workstation
- you want the sign-in window pre-populated with the correct admin identity

### Important note for automation

Without app-only parameters, the script still expects an interactive sign-in experience even with `-AdminUPN`. If your environment enforces MFA or Conditional Access, you must be able to complete that prompt. For fully unattended runs, use app-only certificate authentication with `-AppId`, `-Organization`, and `-CertificateThumbprint`.

## What the Script Analyzes

### Baseline comparison areas

The script compares collected settings against Microsoft's recommended **Standard** and **Strict** baselines for:

- Anti-phishing
- Anti-spam (inbound)
- Anti-spam (outbound)
- Anti-malware
- Safe Attachments
- Safe Links
- Global ATP settings

### Supporting data that is collected

The script also collects related configuration objects to support analysis and exports, including:

- Quarantine policies
- Email tenant settings
- EOP preset policy rules
- ATP preset policy rules
- DKIM signing configurations
- Accepted domains
- Transport rules
- Inbound connectors

> Email tenant settings are exported for review, but they are not scored in the baseline comparison because the script does not define a Microsoft Learn mapping for them.

### Additional security checks

Beyond baseline comparison, the script performs extra operational checks in these areas:

- Quarantine policy references
- Policy rule coverage and tenant-wide scope
- Preset security policy presence and scope
- Policy priority order
- DKIM coverage and DMARC handling posture
- Transport rule bypass patterns
- Inbound connector trust, TLS, and spam-bypass risks
- Impersonation protection coverage for targeted users and domains
- Tenant Allow/Block List usage
- Advanced Delivery configuration for SecOps and phishing simulation
- Unified audit logging status
- Safe Links and Safe Attachments coverage gaps
- Zero-Hour Auto Purge (ZAP) effectiveness
- Outbound spam notification or alert coverage

## Understanding the HTML Report

The primary output is an HTML report designed for easy review.

### Main sections

- **Executive Summary** — overall matched vs. not matched counts for Standard and Strict baselines
- **Category Scorecards** — visual scorecards for each analyzed category
- **Detailed Findings** — expandable policy-level breakdowns showing current value, recommended values, and status
- **Additional Security Checks** — operational findings that go beyond the baseline mapping

### Navigation

The report includes an interactive sidebar so you can jump directly to:

- the summary
- category scorecards
- each policy area
- the additional security checks section

### Color coding and status labels

You will see status badges such as:

- **Matched** — current setting matches the compared baseline
- **Not Matched** — the setting differs from the baseline and should be reviewed
- **Pass** — an additional security check did not identify a material problem
- **Warning** — there may be a gap, partial coverage issue, or a condition that needs review
- **Critical** — the script found a high-risk condition or a serious protection gap

### Policy detail tables

Each policy section can contain:

- policy name
- policy status / priority indicators
- current configuration value
- recommended Standard value
- Standard result
- recommended Strict value
- Strict result
- Microsoft Learn reference links

## Export Features

If you do **not** use `-SkipCsvExport`, the script writes CSV files for both raw collections and processed findings.

### Common exports

- `AssessmentResults.csv`
- `AdditionalSecurityFindings.csv`
- `AntiPhishPolicies.csv`
- `AntiPhishRules.csv`
- `AntiSpamInboundPolicies.csv`
- `AntiSpamInboundRules.csv`
- `AntiSpamOutboundPolicies.csv`
- `AntiSpamOutboundRules.csv`
- `AntiMalwarePolicies.csv`
- `AntiMalwareRules.csv`
- `SafeAttachmentsPolicies.csv`
- `SafeAttachmentsRules.csv`
- `SafeLinksPolicies.csv`
- `SafeLinksRules.csv`
- `AtpGlobal.csv`
- `EmailTenantSettings.csv`
- `QuarantinePolicies.csv`
- `EOPProtectionPolicyRules.csv`
- `ATPProtectionPolicyRules.csv`
- `DkimSigningConfigs.csv`
- `AcceptedDomains.csv`
- `TransportRules.csv`
- `InboundConnectors.csv`

### HTML export buttons

Inside the HTML report, each detail section includes an **Export to Excel** button. This is intended to make section data easy to save from the report view.

## Running in Automated or Scheduled Scenarios

The script can run fully unattended using app-only certificate authentication, or in an interactive admin context for manual runs.

### Recommended flags for repeatable runs

```powershell
.\MDOThreatPolicyAnalyzer.ps1 -SkipBrowserOpen -Quiet -OutputPath "C:\Reports\MDO"
```

For a non-interactive scheduled task or pipeline, add app-only authentication:

```powershell
.\MDOThreatPolicyAnalyzer.ps1 `
  -AppId "00000000-0000-0000-0000-000000000000" `
  -Organization "contoso.onmicrosoft.com" `
  -CertificateThumbprint "AABBCCDDEEFF00112233445566778899AABBCCDD" `
  -SkipBrowserOpen -Quiet -OutputPath "C:\Reports\MDO"
```

### Suggested use cases

- admin workstation scheduled tasks that run in a signed-in admin context
- unattended scheduled tasks or pipelines using app-only certificate authentication
- remote administration jump servers
- periodic health checks performed manually but with predictable output paths

### Limitations

- interactive mode requires an Exchange Online / Security & Compliance sign-in, and MFA and Conditional Access still apply
- app-only certificate authentication requires all three of `-AppId`, `-Organization`, and `-CertificateThumbprint`, plus a service principal with the necessary read permissions
- if the module is missing and `-InstallModuleIfMissing` is not used, the script may prompt to install it
- browser auto-open is usually undesirable in scheduled or remote scenarios, so `-SkipBrowserOpen` is recommended

## Security Considerations

- The script requires access to read security policy configuration from Microsoft 365 services.
- It does **not** change tenant settings; it performs assessment and reporting.
- Output files may contain policy names, rule names, accepted domains, connector details, and other security-relevant configuration data.
- Store reports and CSV exports in a location appropriate for administrative or security review.
- Review who can access the output directory, especially if you export CSV files.
- If you use `-InstallModuleIfMissing`, the module is installed for the **current user**.

## FAQ

### Does the script make any changes to my tenant?

No. It is an assessment and reporting script.

### Do I need Defender for Office 365 licensing?

You need access to the cmdlets and data the script reads. In practice, the relevant Exchange Online and Defender for Office 365 functionality must be available in your tenant.

### What is the difference between Standard and Strict?

They are Microsoft's recommended baseline levels. **Strict** is generally more aggressive and security-focused than **Standard**.

### Why are some sections empty or full of warnings?

Usually this means one of the following:

- the related policy type is not configured
- the cmdlet returned no data
- your account could not read that part of the configuration
- a Defender-specific cmdlet was unavailable in the session

### Why does the report mention email tenant settings but not score them?

The script exports email tenant settings for review, but it does not define a baseline mapping for scoring them.

### Can I use this in a non-interactive pipeline?

Yes. Supply `-AppId`, `-Organization`, and `-CertificateThumbprint` to authenticate non-interactively with app-only certificate authentication. Without those parameters, the script uses interactive sign-in.

### Where are output files written?

By default, to an `Output` folder beside the script. You can change that with `-OutputPath`.

### What if I only want the report?

Use:

```powershell
.\MDOThreatPolicyAnalyzer.ps1 -SkipCsvExport
```

## Related Files

- [README.md](README.md)
- [quickstart.md](quickstart.md)
