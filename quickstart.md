# Quick Start

Use this guide to get `MDOThreatPolicyAnalyzer.ps1` running quickly and generate your first Microsoft Defender for Office 365 assessment report.

## Prerequisites Checklist

Before you begin, make sure you have:

- [ ] Windows PowerShell 5.1 or later
- [ ] Access to the `MDOThreatPolicyAnalyzer.ps1` script
- [ ] Internet access to install PowerShell modules if needed
- [ ] The `ExchangeOnlineManagement` module installed, or permission to install it for your current user
- [ ] An account with permission to read Exchange Online and Defender for Office 365 policy settings

## Step-by-Step

### 1. Download the script

Download or clone the repository to a local folder, then open PowerShell in that folder.

```powershell
cd C:\Path\To\MDOAnalyzer
```

### 2. Run the script

For a first run, use the default behavior:

```powershell
.\MDOThreatPolicyAnalyzer.ps1
```

What happens next:

1. The script checks for the `ExchangeOnlineManagement` module.
2. It connects to Exchange Online.
3. It connects to Security & Compliance PowerShell.
4. It collects MDO policy settings.
5. It compares them against Microsoft's recommended Standard and Strict baselines.
6. It builds an HTML report and optional CSV exports.
7. It opens the HTML report in your default browser unless you tell it not to.

### 3. View the report

By default, output is saved to:

```text
.\Output
```

Open the generated HTML report if it did not open automatically:

```text
MDOThreatPolicyAnalyzer-Report-<timestamp>.html
```

## Common Scenarios

### Basic run

```powershell
.\MDOThreatPolicyAnalyzer.ps1
```

### Use a specific admin sign-in hint

```powershell
.\MDOThreatPolicyAnalyzer.ps1 -AdminUPN admin@contoso.com
```

### Generate the report without opening a browser

```powershell
.\MDOThreatPolicyAnalyzer.ps1 -SkipBrowserOpen
```

### Save output to a custom location

```powershell
.\MDOThreatPolicyAnalyzer.ps1 -OutputPath "C:\Reports\MDO"
```

### Install the module automatically if it is missing

```powershell
.\MDOThreatPolicyAnalyzer.ps1 -InstallModuleIfMissing
```

### Quiet run with a custom output path

```powershell
.\MDOThreatPolicyAnalyzer.ps1 -OutputPath "C:\Reports\MDO" -Quiet -SkipBrowserOpen
```

### Unattended run with app-only certificate authentication

For scheduled tasks or pipelines with no interactive sign-in, use app-only certificate authentication. All three parameters are required together:

```powershell
.\MDOThreatPolicyAnalyzer.ps1 `
  -AppId "00000000-0000-0000-0000-000000000000" `
  -Organization "contoso.onmicrosoft.com" `
  -CertificateThumbprint "AABBCCDDEEFF00112233445566778899AABBCCDD" `
  -OutputPath "C:\Reports\MDO" -Quiet -SkipBrowserOpen
```

## Troubleshooting

### The ExchangeOnlineManagement module is not installed

**Symptom:** The script stops before connecting.

**Fix:** Install the module manually, or rerun with automatic installation enabled.

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

or

```powershell
.\MDOThreatPolicyAnalyzer.ps1 -InstallModuleIfMissing
```

### Authentication fails

**Symptom:** Sign-in does not complete, or the connection fails.

**Things to try:**

- Confirm you can sign in to Exchange Online PowerShell manually
- Use `-AdminUPN` to prefill the account you want to use
- Make sure MFA or Conditional Access requirements can be satisfied interactively
- Update the `ExchangeOnlineManagement` module if sign-in behavior seems outdated

### Permissions are insufficient

**Symptom:** The script runs, but some areas return no data or warnings.

**Things to check:**

- Your admin account can read Defender for Office 365 and Exchange Online policy settings
- You have access to Security & Compliance PowerShell
- Your role assignments allow read access to the policy cmdlets the script uses

### The report does not open automatically

**Symptom:** The run finishes, but no browser window appears.

**Fix:** Open the report manually from the output folder. You can also use `-SkipBrowserOpen` intentionally for server or remote sessions.

## Next Step

For more detail, see [instructions.md](instructions.md) and the main [README.md](README.md).
