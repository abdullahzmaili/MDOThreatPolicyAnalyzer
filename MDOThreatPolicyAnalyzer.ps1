<#
.SYNOPSIS
    Analyzes Microsoft Defender for Office 365 (MDO) threat protection policies against Microsoft's recommended baselines.

.DESCRIPTION
    This script connects to Exchange Online and evaluates your organization's MDO threat protection policies
    (Anti-Phishing, Anti-Spam, Anti-Malware, Safe Links, and Safe Attachments) against Microsoft's recommended
    Standard and Strict security baselines. It generates an HTML report highlighting configuration gaps,
    compliance status, and actionable recommendations to strengthen your email security posture.

.DISCLAIMER
    This script has been thoroughly tested across various environments and scenarios, and all tests have passed
    successfully. However, by using this script, you acknowledge and agree that:
    1. You are responsible for how you use the script and any outcomes resulting from its execution.
    2. The entire risk arising out of the use or performance of the script remains with you.
    3. The author and contributors are not liable for any damages, including data loss, business interruption,
       or other losses, even if warned of the risks.

.NOTES
    File Name      : MDOThreatPolicyAnalyzer.ps1
    Author         : Abdullah Zmaili
    Version        : 1.0
    Date Created   : 2026-April-30
    Date Updated   : 2026-July-26
    Prerequisite   : PowerShell 5.1 or later, Administrator privileges for some checks

    SECURITY NOTES:
    - This script uses the ExchangeOnlineManagement module (Connect-ExchangeOnline and
      Connect-IPPSSession) with interactive modern authentication (delegated admin permissions).
    - Access tokens are managed by the ExchangeOnlineManagement module and are not stored in plain text.
    - For automated/service scenarios, consider using certificate-based app-only authentication
      (or a Managed Identity where supported) instead of interactive sign-in.
    - HTML output is encoded (via System.Net.WebUtility.HtmlEncode) to help prevent XSS
      vulnerabilities in the generated reports.
    - Review and audit exported CSV/HTML files before sharing - they may contain sensitive
      tenant configuration data.

.EXAMPLE
    .\MDOThreatPolicyAnalyzer.ps1
    Runs the analyzer with default settings. Connects to Exchange Online, generates an HTML report, and opens it in the browser.

.EXAMPLE
    .\MDOThreatPolicyAnalyzer.ps1 -OutputPath "C:\Reports\MDO"
    Saves the report and CSV exports to the specified output directory.

.EXAMPLE
    .\MDOThreatPolicyAnalyzer.ps1 -AdminUPN "admin@contoso.com"
    Connects to Exchange Online using the specified admin UPN for authentication.

.EXAMPLE
    .\MDOThreatPolicyAnalyzer.ps1 -AdminUPN admin@contoso.com
    Uses the specified UPN as a hint for interactive authentication.

.EXAMPLE
    .\MDOThreatPolicyAnalyzer.ps1 -SkipCsvExport -SkipBrowserOpen
    Generates the HTML report without exporting CSV files and without automatically opening the report in a browser.

.EXAMPLE
    .\MDOThreatPolicyAnalyzer.ps1 -InstallModuleIfMissing
    Automatically installs the ExchangeOnlineManagement module if it is not already installed.

.EXAMPLE
    .\MDOThreatPolicyAnalyzer.ps1 -Quiet
    Suppresses verbose console output; only shows errors and the final summary.

.EXAMPLE
    .\MDOThreatPolicyAnalyzer.ps1 -Version
    Displays the script version information and exits without running the assessment.

.EXAMPLE
    .\MDOThreatPolicyAnalyzer.ps1 -OutputPath "C:\Reports" -AdminUPN "admin@contoso.com" -InstallModuleIfMissing -Quiet -SkipBrowserOpen
    Full automated run: installs modules if needed, connects with specified UPN, saves output to C:\Reports, suppresses console output, and does not open the browser.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$SkipCsvExport,
    [switch]$SkipBrowserOpen,
    [string]$AdminUPN,
    [string]$AppId,
    [string]$Organization,
    [string]$CertificateThumbprint,
    [switch]$InstallModuleIfMissing,
    [switch]$Version,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ToolName = 'MDO Threat Policy Analyzer'
$script:ToolVersion = '1.0.0'
$script:MinExoModuleVersion = [Version]'3.0.0'
$script:CachedReportTemplate = $null

if ($Version) {
    Write-Host ('{0} v{1}' -f $script:ToolName, $script:ToolVersion)
    return
}

$script:Quiet = $Quiet.IsPresent
$script:IsInteractive = [Environment]::UserInteractive -and -not ([Environment]::GetCommandLineArgs() -match '-NonInteractive')

$script:BaseReferenceUrl = 'https://learn.microsoft.com/defender-office-365/recommended-settings-for-eop-and-office365'
$script:ExecutionIssues = New-Object 'System.Collections.Generic.List[object]'
$script:ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Path $MyInvocation.MyCommand.Path -Parent }
$script:OutputRoot = if ($OutputPath) { $OutputPath } else { Join-Path -Path $script:ScriptRoot -ChildPath 'Output' }
$script:LogPath = Join-Path -Path $script:OutputRoot -ChildPath ('MDOThreatPolicyAnalyzer-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

$propertyAliases = @{
    'DisableURLRewrite' = @('DisableURLRewrite', 'DisableUrlRewrite')
    'EnableSafeLinksForOffice' = @('EnableSafeLinksForOffice', 'EnableSafeLinksForO365App')
    'EnableATPForSPOTeamsODB' = @('EnableATPForSPOTeamsODB')
}

$RecommendedBaselines = [ordered]@{
    AntiPhish = @{
        DisplayName = 'Anti-Phishing'
        ReferenceUrl = "$($script:BaseReferenceUrl)#anti-phishing-policy-settings-for-all-cloud-mailboxes"
        Settings = [ordered]@{
            PhishThresholdLevel = @{ Standard = 3; Strict = 4 }
            EnableMailboxIntelligence = @{ Standard = $true; Strict = $true }
            EnableMailboxIntelligenceProtection = @{ Standard = $true; Strict = $true }
            EnableSpoofIntelligence = @{ Standard = $true; Strict = $true }
            EnableFirstContactSafetyTips = @{ Standard = $true; Strict = $true }
            EnableSimilarUsersSafetyTips = @{ Standard = $true; Strict = $true }
            EnableSimilarDomainsSafetyTips = @{ Standard = $true; Strict = $true }
            EnableUnusualCharactersSafetyTips = @{ Standard = $true; Strict = $true }
            MailboxIntelligenceProtectionAction = @{ Standard = 'MoveToJmf'; Strict = 'Quarantine' }
            TargetedUserProtectionAction = @{ Standard = 'Quarantine'; Strict = 'Quarantine' }
            TargetedDomainProtectionAction = @{ Standard = 'Quarantine'; Strict = 'Quarantine' }
            AuthenticationFailAction = @{ Standard = 'MoveToJmf'; Strict = 'Quarantine' }
            HonorDmarcPolicy = @{ Standard = $true; Strict = $true }
            DmarcQuarantineAction = @{ Standard = 'Quarantine'; Strict = 'Quarantine' }
            DmarcRejectAction = @{ Standard = 'Reject'; Strict = 'Reject' }
        }
    }
    AntiSpamInbound = @{
        DisplayName = 'Anti-Spam (Inbound)'
        ReferenceUrl = "$($script:BaseReferenceUrl)#anti-spam-policy-settings"
        Settings = [ordered]@{
            SpamAction = @{ Standard = 'MoveToJmf'; Strict = 'Quarantine' }
            HighConfidenceSpamAction = @{ Standard = 'Quarantine'; Strict = 'Quarantine' }
            PhishSpamAction = @{ Standard = 'Quarantine'; Strict = 'Quarantine' }
            HighConfidencePhishAction = @{ Standard = 'Quarantine'; Strict = 'Quarantine' }
            BulkSpamAction = @{ Standard = 'MoveToJmf'; Strict = 'Quarantine' }
            BulkThreshold = @{ Standard = 6; Strict = 5 }
            QuarantineRetentionPeriod = @{ Standard = 30; Strict = 30 }
            InlineSafetyTipsEnabled = @{ Standard = $true; Strict = $true }
            SpamZapEnabled = @{ Standard = $true; Strict = $true }
            PhishZapEnabled = @{ Standard = $true; Strict = $true }
        }
    }
    AntiSpamOutbound = @{
        DisplayName = 'Anti-Spam (Outbound)'
        ReferenceUrl = "$($script:BaseReferenceUrl)#outbound-spam-policy-settings"
        Settings = [ordered]@{
            RecipientLimitExternalPerHour = @{ Standard = 500; Strict = 400 }
            RecipientLimitInternalPerHour = @{ Standard = 1000; Strict = 800 }
            RecipientLimitPerDay = @{ Standard = 1000; Strict = 800 }
            ActionWhenThresholdReached = @{ Standard = 'BlockUser'; Strict = 'BlockUser' }
            AutoForwardingMode = @{ Standard = 'Automatic'; Strict = 'Automatic' }
            BccSuspiciousOutboundMail = @{ Standard = $false; Strict = $false }
            NotifyOutboundSpam = @{ Standard = $false; Strict = $false }
        }
    }
    AntiMalware = @{
        DisplayName = 'Anti-Malware'
        ReferenceUrl = "$($script:BaseReferenceUrl)#anti-malware-policy-settings"
        Settings = [ordered]@{
            EnableFileFilter = @{ Standard = $true; Strict = $true }
            FileTypeAction = @{ Standard = 'Reject'; Strict = 'Reject' }
            ZapEnabled = @{ Standard = $true; Strict = $true }
            QuarantineTag = @{ Standard = 'AdminOnlyAccessPolicy'; Strict = 'AdminOnlyAccessPolicy' }
            EnableInternalSenderAdminNotifications = @{ Standard = $false; Strict = $false }
            EnableExternalSenderAdminNotifications = @{ Standard = $false; Strict = $false }
        }
    }
    SafeAttachments = @{
        DisplayName = 'Safe Attachments'
        ReferenceUrl = "$($script:BaseReferenceUrl)#safe-attachments-policy-settings"
        Settings = [ordered]@{
            Action = @{ Standard = 'Block'; Strict = 'Block' }
            Enable = @{ Standard = $true; Strict = $true }
            QuarantineTag = @{ Standard = 'AdminOnlyAccessPolicy'; Strict = 'AdminOnlyAccessPolicy' }
            Redirect = @{ Standard = $false; Strict = $false }
        }
    }
    SafeLinks = @{
        DisplayName = 'Safe Links'
        ReferenceUrl = "$($script:BaseReferenceUrl)#safe-links-policy-settings"
        Settings = [ordered]@{
            EnableSafeLinksForEmail = @{ Standard = $true; Strict = $true }
            EnableSafeLinksForTeams = @{ Standard = $true; Strict = $true }
            EnableSafeLinksForOffice = @{ Standard = $true; Strict = $true }
            ScanUrls = @{ Standard = $true; Strict = $true }
            DeliverMessageAfterScan = @{ Standard = $true; Strict = $true }
            DisableURLRewrite = @{ Standard = $false; Strict = $false }
            EnableForInternalSenders = @{ Standard = $true; Strict = $true }
            TrackClicks = @{ Standard = $true; Strict = $true }
            AllowClickThrough = @{ Standard = $false; Strict = $false }
            EnableOrganizationBranding = @{ Standard = $false; Strict = $false }
        }
    }
    AtpGlobal = @{
        DisplayName = 'Global ATP Settings'
        ReferenceUrl = "$($script:BaseReferenceUrl)#global-settings-for-safe-attachments"
        Settings = [ordered]@{
            EnableATPForSPOTeamsODB = @{ Standard = $true; Strict = $true }
            EnableSafeDocs = @{ Standard = $true; Strict = $true }
            AllowSafeDocsOpen = @{ Standard = $false; Strict = $false }
        }
    }
}

# Security feature names from the Microsoft Learn article
# Maps PowerShell parameter names to their human-readable security feature names
$SecurityFeatureNames = @{
    # Anti-Malware
    EnableFileFilter                        = 'Enable the common attachments filter'
    FileTypeAction                          = 'Common attachment filter notifications: When these file types are found'
    ZapEnabled                              = 'Enable zero-hour auto purge (ZAP)'
    QuarantineTag                           = 'Quarantine policy'
    EnableInternalSenderAdminNotifications  = 'Notify an admin about undelivered messages from internal senders'
    EnableExternalSenderAdminNotifications  = 'Notify an admin about undelivered messages from external senders'

    # Anti-Spam (Inbound)
    BulkThreshold                           = 'Bulk email threshold'
    SpamAction                              = 'Spam detection action'
    HighConfidenceSpamAction                = 'High confidence spam detection action'
    PhishSpamAction                         = 'Phishing detection action'
    HighConfidencePhishAction               = 'High confidence phishing detection action'
    BulkSpamAction                          = 'Bulk compliant level (BCL) met or exceeded'
    QuarantineRetentionPeriod               = 'Retain spam in quarantine for this many days'
    InlineSafetyTipsEnabled                 = 'Enable spam safety tips'
    SpamZapEnabled                          = 'Enable ZAP for spam messages'
    PhishZapEnabled                         = 'Enable zero-hour auto purge (ZAP) for phishing messages'

    # Anti-Spam (Outbound)
    RecipientLimitExternalPerHour           = 'Set an external message limit'
    RecipientLimitInternalPerHour           = 'Set an internal message limit'
    RecipientLimitPerDay                    = 'Set a daily message limit'
    ActionWhenThresholdReached              = 'Restriction placed on users who reach the message limit'
    AutoForwardingMode                      = 'Automatic forwarding rules'
    BccSuspiciousOutboundMail               = 'Send a copy of outbound messages that exceed these limits'
    NotifyOutboundSpam                      = 'Notify these users and groups if a sender is blocked due to sending outbound spam'

    # Anti-Phishing
    PhishThresholdLevel                     = 'Phishing email threshold'
    EnableMailboxIntelligence               = 'Enable mailbox intelligence'
    EnableMailboxIntelligenceProtection     = 'Enable intelligence for impersonation protection'
    EnableSpoofIntelligence                 = 'Enable spoof intelligence'
    EnableFirstContactSafetyTips            = 'Show first contact safety tip'
    EnableSimilarUsersSafetyTips            = 'Show user impersonation safety tip'
    EnableSimilarDomainsSafetyTips          = 'Show domain impersonation safety tip'
    EnableUnusualCharactersSafetyTips       = 'Show user impersonation unusual characters safety tip'
    MailboxIntelligenceProtectionAction     = 'If mailbox intelligence detects an impersonated user'
    TargetedUserProtectionAction            = 'If a message is detected as user impersonation'
    TargetedDomainProtectionAction          = 'If a message is detected as domain impersonation'
    AuthenticationFailAction                = 'If the message is detected as spoof by spoof intelligence'
    HonorDmarcPolicy                        = 'Honor DMARC record policy when the message is detected as spoof'
    DmarcQuarantineAction                   = 'If the message is detected as spoof and DMARC Policy is set as p=quarantine'
    DmarcRejectAction                       = 'If the message is detected as spoof and DMARC Policy is set as p=reject'

    # Safe Attachments
    Action                                  = 'Safe Attachments unknown malware response'
    Enable                                  = 'Safe Attachments unknown malware response'
    Redirect                                = 'Redirect attachment with detected attachments: Enable redirect'

    # Safe Links
    EnableSafeLinksForEmail                 = 'Safe Links checks a list of known, malicious links when users click links in email'
    EnableSafeLinksForTeams                 = 'Safe Links checks a list of known, malicious links when users click links in Microsoft Teams'
    EnableSafeLinksForOffice                = 'Safe Links checks a list of known, malicious links when users click links in Microsoft Office apps'
    ScanUrls                                = 'Apply real-time URL scanning for suspicious links and links that point to files'
    DeliverMessageAfterScan                 = 'Wait for URL scanning to complete before delivering the message'
    DisableURLRewrite                       = 'Do not rewrite URLs, do checks via Safe Links API only'
    EnableForInternalSenders                = 'Apply Safe Links to email messages sent within the organization'
    TrackClicks                             = 'Track user clicks'
    AllowClickThrough                       = 'Let users click through to the original URL'
    EnableOrganizationBranding              = 'Display the organization branding on notification and warning pages'

    # Global ATP Settings
    EnableATPForSPOTeamsODB                 = 'Turn on Defender for Office 365 for SharePoint, OneDrive, and Microsoft Teams'
    EnableSafeDocs                          = 'Turn on Safe Documents for Office clients'
    AllowSafeDocsOpen                       = 'Allow people to click through Protected View even if Safe Documents identified the file as malicious'
}

$script:IdentifierProperties = @('Name', 'Identity', 'DisplayName', 'Domain', 'DomainName')
$script:StateProperties = @('State', 'Enabled', 'Mode', 'IsEnabled')
$script:PolicyRuleReferenceProperties = @('AntiPhishPolicy', 'HostedContentFilterPolicy', 'HostedOutboundSpamFilterPolicy', 'MalwareFilterPolicy', 'SafeAttachmentPolicy', 'SafeLinksPolicy')
$script:PolicyMappingDefinitions = @(
    @{ Category = 'Anti-Phishing'; CategoryKey = 'AntiPhish'; PoliciesProperty = 'AntiPhishPolicies'; RulesProperty = 'AntiPhishRules'; RulePolicyProperties = @('AntiPhishPolicy') }
    @{ Category = 'Inbound Anti-Spam'; CategoryKey = 'AntiSpamInbound'; PoliciesProperty = 'InboundSpamPolicies'; RulesProperty = 'InboundSpamRules'; RulePolicyProperties = @('HostedContentFilterPolicy') }
    @{ Category = 'Outbound Anti-Spam'; CategoryKey = 'AntiSpamOutbound'; PoliciesProperty = 'OutboundSpamPolicies'; RulesProperty = 'OutboundSpamRules'; RulePolicyProperties = @('HostedOutboundSpamFilterPolicy', 'HostedContentFilterPolicy') }
    @{ Category = 'Anti-Malware'; CategoryKey = 'AntiMalware'; PoliciesProperty = 'AntiMalwarePolicies'; RulesProperty = 'AntiMalwareRules'; RulePolicyProperties = @('MalwareFilterPolicy') }
    @{ Category = 'Safe Attachments'; CategoryKey = 'SafeAttachments'; PoliciesProperty = 'SafeAttachmentPolicies'; RulesProperty = 'SafeAttachmentRules'; RulePolicyProperties = @('SafeAttachmentPolicy') }
    @{ Category = 'Safe Links'; CategoryKey = 'SafeLinks'; PoliciesProperty = 'SafeLinkPolicies'; RulesProperty = 'SafeLinkRules'; RulePolicyProperties = @('SafeLinksPolicy') }
)

#region Write-Log
function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO',
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = '[{0}] [{1}] {2}' -f $timestamp, $Level, $Message
    if (-not $script:Quiet -or $Level -eq 'ERROR') {
        Write-Host $entry -ForegroundColor $Color
    }
    Add-Content -Path $script:LogPath -Value $entry
}
#endregion

#region Add-ExecutionIssue
function Add-ExecutionIssue {
    param(
        [string]$Category,
        [string]$Stage,
        [string]$Message,
        [string]$Severity = 'Warning'
    )

    [void]$script:ExecutionIssues.Add([pscustomobject]@{
            Category = $Category
            Stage = $Stage
            Message = $Message
            Severity = $Severity
        })
}
#endregion

#region Write-Banner
function Write-Banner {
    if ($script:Quiet) { return }
    $banner = @(
        '============================================================',
        (' {0} v{1}' -f $script:ToolName, $script:ToolVersion),
        ' Microsoft Defender for Office 365 Configuration Analyzer',
        '============================================================'
    )

    foreach ($line in $banner) {
        Write-Host $line -ForegroundColor Cyan
    }
}
#endregion

#region Ensure-OutputFolder
function Ensure-OutputFolder {
    if ($OutputPath) {
        if ($OutputPath.IndexOfAny([System.IO.Path]::GetInvalidPathChars()) -ge 0) {
            throw ('The provided -OutputPath contains invalid path characters: {0}' -f $OutputPath)
        }
    }

    if (-not (Test-Path -Path $script:OutputRoot)) {
        try {
            $null = New-Item -Path $script:OutputRoot -ItemType Directory -Force -ErrorAction Stop
        }
        catch {
            throw ('Unable to create output directory ''{0}'': {1}' -f $script:OutputRoot, $_.Exception.Message)
        }
    }

    if (-not (Test-Path -Path $script:LogPath)) {
        $null = New-Item -Path $script:LogPath -ItemType File -Force
    }
}
#endregion

#region Get-Utf8EncodingName
function Get-Utf8EncodingName {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        return 'utf8NoBOM'
    }

    return 'UTF8'
}
#endregion

#region Ensure-ExchangeOnlineModule
function Ensure-ExchangeOnlineModule {
    Write-Log -Message 'Checking ExchangeOnlineManagement module.' -Color Yellow
    $installedModule = Get-Module -ListAvailable -Name ExchangeOnlineManagement | Sort-Object Version -Descending | Select-Object -First 1

    if ($installedModule -and $installedModule.Version -ge $script:MinExoModuleVersion) {
        Import-Module ExchangeOnlineManagement -MinimumVersion $script:MinExoModuleVersion -ErrorAction Stop
        Write-Log -Message ('Loaded ExchangeOnlineManagement {0}.' -f $installedModule.Version) -Level SUCCESS -Color Green
        return
    }

    if ($installedModule) {
        Write-Log -Message ('Installed ExchangeOnlineManagement {0} is older than the required minimum {1}; an update will be attempted.' -f $installedModule.Version, $script:MinExoModuleVersion) -Level WARN -Color DarkYellow
    }

    if (-not $InstallModuleIfMissing) {
        $answer = Read-Host 'ExchangeOnlineManagement is not installed. Install it now from PSGallery? (Y/N)'
        if ($answer -notmatch '^(Y|YES)$') {
            throw 'ExchangeOnlineManagement is required to continue.'
        }
    }

    Write-Log -Message 'Installing ExchangeOnlineManagement module for current user.' -Color Yellow
    # Ensure TLS 1.2 for PSGallery connectivity
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Ensure NuGet provider is available (required for Install-Module)
    $nuget = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1
    if (-not $nuget -or $nuget.Version -lt [Version]'2.8.5.201') {
        Write-Log -Message 'Installing NuGet package provider...' -Color Yellow
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -ErrorAction Stop
    }

    Install-Module -Name ExchangeOnlineManagement -MinimumVersion $script:MinExoModuleVersion -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop

    # Refresh module path so Import-Module can find the newly installed module
    $userModulePath = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'PowerShell\Modules'
    $userModulePathWinPS = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Modules'
    foreach ($p in @($userModulePath, $userModulePathWinPS)) {
        if ((Test-Path $p) -and ($env:PSModulePath -notlike "*$p*")) {
            $env:PSModulePath = "$p;$env:PSModulePath"
        }
    }

    Import-Module ExchangeOnlineManagement -MinimumVersion $script:MinExoModuleVersion -ErrorAction Stop
    $loaded = Get-Module -Name ExchangeOnlineManagement | Sort-Object Version -Descending | Select-Object -First 1
    Write-Log -Message ('ExchangeOnlineManagement {0} installed successfully.' -f ($loaded.Version)) -Level SUCCESS -Color Green
}
#endregion

#region Get-AuthenticationContext
function Get-AuthenticationContext {
    $usingAppAuth = [bool]($AppId -and $Organization -and $CertificateThumbprint)

    if (-not $usingAppAuth -and ($AppId -or $Organization -or $CertificateThumbprint)) {
        throw 'App-only authentication requires all of -AppId, -Organization and -CertificateThumbprint.'
    }

    $context = [ordered]@{
        UserPrincipalName     = if ($AdminUPN) { $AdminUPN } else { $null }
        AppId                 = if ($AppId) { $AppId } else { $null }
        Organization          = if ($Organization) { $Organization } else { $null }
        CertificateThumbprint = if ($CertificateThumbprint) { $CertificateThumbprint } else { $null }
        UseAppOnly            = $usingAppAuth
    }
    return [pscustomobject]$context
}
#endregion

#region Connect-MdoServices
function Connect-MdoServices {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$AuthContext
    )

    # Newer ExchangeOnlineManagement versions (3.7.0+) default to WAM (Web Account Manager)
    # broker authentication, which requires a parent window handle. In hosts where a handle
    # is unavailable (e.g. some console/remoting sessions) this fails with:
    #   "A window handle must be configured. See https://aka.ms/msal-net-wam#parent-window-handles"
    # Disabling WAM falls back to the standard interactive browser flow. The switch only exists
    # on module versions that support WAM, so we add it conditionally.
    $exoConnectParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
    $ippsConnectParams = @{ ErrorAction = 'Stop' }

    if ($AuthContext.UseAppOnly) {
        # Non-interactive app-only certificate authentication. This also enables
        # unattended/scheduled execution and per-runspace connections.
        foreach ($p in @($exoConnectParams, $ippsConnectParams)) {
            $p['AppId'] = $AuthContext.AppId
            $p['Organization'] = $AuthContext.Organization
            $p['CertificateThumbprint'] = $AuthContext.CertificateThumbprint
        }
    }
    else {
        if ($AuthContext.UserPrincipalName) {
            $exoConnectParams['UserPrincipalName'] = $AuthContext.UserPrincipalName
            $ippsConnectParams['UserPrincipalName'] = $AuthContext.UserPrincipalName
        }
    }

    $connectExoCommand = Get-Command -Name Connect-ExchangeOnline -ErrorAction SilentlyContinue
    if ($connectExoCommand -and $connectExoCommand.Parameters.ContainsKey('DisableWAM')) {
        $exoConnectParams['DisableWAM'] = $true
    }

    $connectIppsCommand = Get-Command -Name Connect-IPPSSession -ErrorAction SilentlyContinue
    if ($connectIppsCommand -and $connectIppsCommand.Parameters.ContainsKey('DisableWAM')) {
        $ippsConnectParams['DisableWAM'] = $true
    }

    Write-Log -Message 'Connecting to Exchange Online.' -Color Yellow
    Connect-ExchangeOnline @exoConnectParams | Out-Null

    Write-Log -Message 'Connected to Exchange Online.' -Level SUCCESS -Color Green
    Write-Log -Message 'Connecting to Security & Compliance PowerShell.' -Color Yellow

    Connect-IPPSSession @ippsConnectParams | Out-Null

    Write-Log -Message 'Connected to Security & Compliance PowerShell.' -Level SUCCESS -Color Green
}
#endregion

#region Disconnect-MdoServices
function Disconnect-MdoServices {
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        Write-Log -Message ('Disconnect warning: {0}' -f $_.Exception.Message) -Level WARN -Color DarkYellow
    }
}
#endregion

#region Get-PropertyValue
function Get-PropertyValue {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $candidateNames = @($Name)
    if ($propertyAliases.ContainsKey($Name)) {
        $candidateNames = $propertyAliases[$Name]
    }

    foreach ($candidateName in $candidateNames) {
        $property = $InputObject.PSObject.Properties[$candidateName]
        if ($property) {
            return $property.Value
        }
    }

    return $null
}
#endregion

#region Convert-ValueToString
function Convert-ValueToString {
    param([object]$Value)

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [bool]) {
        return $Value.ToString().ToLowerInvariant()
    }

    if ($Value -is [datetime]) {
        return $Value.ToString('s')
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = foreach ($item in $Value) {
            if ($null -ne $item) { [string]$item }
        }

        return ($items | Sort-Object) -join '; '
    }

    return [string]$Value
}
#endregion

#region ConvertTo-Slug
function ConvertTo-Slug {
    param(
        [AllowNull()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    return ($Text -replace '[^a-zA-Z0-9]+', '-').ToLowerInvariant().Trim('-')
}
#endregion

#region Test-EquivalentValue
function Test-EquivalentValue {
    param(
        [object]$CurrentValue,
        [object]$RecommendedValue
    )

    $currentNormalized = Convert-ValueToString -Value $CurrentValue
    $recommendedNormalized = Convert-ValueToString -Value $RecommendedValue

    if ($currentNormalized -eq $recommendedNormalized) {
        return $true
    }

    if ($currentNormalized -eq 'off' -and $recommendedNormalized -eq 'automatic') {
        return $true
    }

    if ($currentNormalized -eq 'automatic' -and $recommendedNormalized -eq 'off') {
        return $true
    }

    return $false
}
#endregion

#region Invoke-CollectionCommand
function Invoke-CollectionCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Category,
        [Parameter(Mandatory = $true)]
        [string]$CmdletName,
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        [int]$PercentComplete
    )

    if ($script:IsInteractive -and -not $script:Quiet) {
        Write-Progress -Activity 'Collecting Microsoft Defender for Office 365 settings' -Status $Category -PercentComplete $PercentComplete
    }
    Write-Log -Message ('Collecting {0} using {1}.' -f $Category, $CmdletName) -Color Cyan

    if (-not (Get-Command -Name $CmdletName -ErrorAction SilentlyContinue)) {
        $message = ('Cmdlet {0} is unavailable in the current session.' -f $CmdletName)
        Write-Log -Message $message -Level WARN -Color DarkYellow
        Add-ExecutionIssue -Category $Category -Stage 'DataCollection' -Message $message
        return @()
    }

    try {
        $data = & $ScriptBlock
        if ($null -eq $data) {
            $data = @()
        }

        $count = @($data).Count
        Write-Log -Message ('Collected {0} item(s) for {1}.' -f $count, $Category) -Level SUCCESS -Color Green
        return @($data)
    }
    catch {
        $message = ('{0} failed: {1}' -f $CmdletName, $_.Exception.Message)
        Write-Log -Message $message -Level WARN -Color DarkYellow
        Add-ExecutionIssue -Category $Category -Stage 'DataCollection' -Message $message
        return @()
    }
}
#endregion

#region Get-PreferredPolicy
function Get-PreferredPolicy {
    param([object[]]$Policies)

    if (-not $Policies -or @($Policies).Count -eq 0) {
        return $null
    }

    $selectionChecks = @(
        { param($item) (Get-PropertyValue -InputObject $item -Name 'IsDefault') -eq $true },
        { param($item) (Get-PropertyValue -InputObject $item -Name 'Default') -eq $true },
        { param($item) (Get-PropertyValue -InputObject $item -Name 'IsBuiltinProtection') -eq $true },
        { param($item) (Get-PropertyValue -InputObject $item -Name 'IsBuiltInProtection') -eq $true },
        { param($item) (Get-PropertyValue -InputObject $item -Name 'IsPresetPolicy') -eq $true },
        { param($item) ($item.Name -as [string]) -match '^Default' },
        { param($item) ($item.Name -as [string]) -match 'Built-?in' }
    )

    foreach ($check in $selectionChecks) {
        $match = $Policies | Where-Object { & $check $_ } | Select-Object -First 1
        if ($match) {
            return $match
        }
    }

    return $Policies | Select-Object -First 1
}
#endregion

#region Add-ComparisonResult
function Add-ComparisonResult {
    param(
        [System.Collections.Generic.List[object]]$Results,
        [string]$Category,
        [string]$SettingName,
        [object]$CurrentValue,
        [object]$RecommendedStandardValue,
        [string]$StandardStatus,
        [object]$RecommendedStrictValue,
        [string]$StrictStatus,
        [string]$ReferenceUrl,
        [string]$PolicyName,
        [string]$PolicyStatus = 'N/A',
        [string]$PolicyPriority = 'N/A'
    )

    $featureName = if ($SecurityFeatureNames.ContainsKey($SettingName)) { $SecurityFeatureNames[$SettingName] } else { '' }

    [void]$Results.Add([pscustomobject]@{
            Category = $Category
            PolicyName = $PolicyName
            PolicyStatus = $PolicyStatus
            PolicyPriority = $PolicyPriority
            FeatureName = $featureName
            SettingName = $SettingName
            CurrentValue = Convert-ValueToString -Value $CurrentValue
            RecommendedStandardValue = Convert-ValueToString -Value $RecommendedStandardValue
            StandardStatus = $StandardStatus
            RecommendedStrictValue = Convert-ValueToString -Value $RecommendedStrictValue
            StrictStatus = $StrictStatus
            ReferenceUrl = $ReferenceUrl
        })
}
#endregion

#region Get-PolicyIdentityInfo
function Get-PolicyIdentityInfo {
    param(
        [AllowNull()]
        [object]$Policy
    )

    $policyName = ''
    if ($null -ne $Policy) {
        if ($Policy.Name) {
            $policyName = $Policy.Name
        }
        elseif ($Policy.Identity) {
            $policyName = $Policy.Identity
        }
    }

    $isDefault = $false
    if ($null -ne $Policy) {
        $isDefault = (Get-PropertyValue -InputObject $Policy -Name 'IsDefault') -eq $true
    }

    return [pscustomobject]@{
        PolicyName = $policyName
        ContainsDefault = $policyName -match 'Default'
        ContainsStandard = $policyName -match 'Standard'
        ContainsStrict = $policyName -match 'Strict'
        IsDefault = $isDefault
        IsBuiltInDefault = $isDefault -or $policyName -match '(Default|Built-In|Office365)'
    }
}
#endregion

#region Get-MatchingRuleForPolicy
function Get-MatchingRuleForPolicy {
    param(
        [AllowNull()]
        [object]$Policy,
        [object[]]$Rules
    )

    if ($null -eq $Policy -or -not $Rules -or @($Rules).Count -eq 0) {
        return $null
    }

    $policyIdentity = Get-PolicyIdentityInfo -Policy $Policy
    if ([string]::IsNullOrWhiteSpace($policyIdentity.PolicyName)) {
        return $null
    }

    foreach ($rule in @($Rules)) {
        foreach ($propertyName in $script:PolicyRuleReferenceProperties) {
            $ruleTargetPolicy = Get-PropertyValue -InputObject $rule -Name $propertyName
            if ($ruleTargetPolicy -and $ruleTargetPolicy -eq $policyIdentity.PolicyName) {
                return $rule
            }
        }

        if ($rule.Name -and $rule.Name -eq $policyIdentity.PolicyName) {
            return $rule
        }
    }

    return $null
}
#endregion

#region Get-PolicyMappings
function Get-PolicyMappings {
    param(
        [hashtable]$AllData
    )

    $policyMappings = foreach ($definition in $script:PolicyMappingDefinitions) {
        @{
            Category = $definition.Category
            CategoryKey = $definition.CategoryKey
            Policies = @($AllData[$definition.PoliciesProperty])
            Rules = @($AllData[$definition.RulesProperty])
            RulePolicyProperties = $definition.RulePolicyProperties
        }
    }

    return @($policyMappings)
}
#endregion

#region Compare-PolicyToBaseline
function Compare-PolicyToBaseline {
    param(
        [System.Collections.Generic.List[object]]$Results,
        [string]$CategoryKey,
        [object]$PolicyObject,
        [string]$PolicyStatus = 'N/A',
        [string]$PolicyPriority = 'N/A'
    )

    $baseline = $RecommendedBaselines[$CategoryKey]
    if (-not $baseline) {
        return
    }

    $displayName = $baseline.DisplayName
    $referenceUrl = $baseline.ReferenceUrl

    # Extract policy name from PolicyObject
    $policyName = 'N/A'
    if ($PolicyObject) {
        if ($PolicyObject.Name) {
            $policyName = $PolicyObject.Name
        }
        elseif ($PolicyObject.Identity) {
            $policyName = $PolicyObject.Identity
        }
        elseif ($PolicyObject.DisplayName) {
            $policyName = $PolicyObject.DisplayName
        }
    }

    if (-not $PolicyObject) {
        foreach ($settingName in $baseline.Settings.Keys) {
            $recommendedSetting = $baseline.Settings[$settingName]
            Add-ComparisonResult -Results $Results -Category $displayName -SettingName $settingName -CurrentValue $null -RecommendedStandardValue $recommendedSetting.Standard -StandardStatus 'NotMatched' -RecommendedStrictValue $recommendedSetting.Strict -StrictStatus 'NotMatched' -ReferenceUrl $referenceUrl -PolicyName $policyName -PolicyStatus 'Off' -PolicyPriority $PolicyPriority
        }

        Add-ExecutionIssue -Category $displayName -Stage 'Comparison' -Message 'No policy object was available for comparison.'
        return
    }

    foreach ($settingName in $baseline.Settings.Keys) {
        $recommendedSetting = $baseline.Settings[$settingName]
        $recommendedStandard = $recommendedSetting.Standard
        $recommendedStrict = $recommendedSetting.Strict
        $currentValue = Get-PropertyValue -InputObject $PolicyObject -Name $settingName

        if ($null -eq $currentValue -or ((Convert-ValueToString -Value $currentValue) -eq '')) {
            Add-ComparisonResult -Results $Results -Category $displayName -SettingName $settingName -CurrentValue $null -RecommendedStandardValue $recommendedStandard -StandardStatus 'NotMatched' -RecommendedStrictValue $recommendedStrict -StrictStatus 'NotMatched' -ReferenceUrl $referenceUrl -PolicyName $policyName -PolicyStatus $PolicyStatus -PolicyPriority $PolicyPriority
            continue
        }

        $statusStandard = if (Test-EquivalentValue -CurrentValue $currentValue -RecommendedValue $recommendedStandard) { 'Matched' } else { 'NotMatched' }
        $statusStrict = if (Test-EquivalentValue -CurrentValue $currentValue -RecommendedValue $recommendedStrict) { 'Matched' } else { 'NotMatched' }
        Add-ComparisonResult -Results $Results -Category $displayName -SettingName $settingName -CurrentValue $currentValue -RecommendedStandardValue $recommendedStandard -StandardStatus $statusStandard -RecommendedStrictValue $recommendedStrict -StrictStatus $statusStrict -ReferenceUrl $referenceUrl -PolicyName $policyName -PolicyStatus $PolicyStatus -PolicyPriority $PolicyPriority
    }
}
#endregion

#region Compare-AllPoliciesToBaseline
function Compare-AllPoliciesToBaseline {
    param(
        [System.Collections.Generic.List[object]]$Results,
        [string]$CategoryKey,
        [object[]]$Policies,
        [object[]]$Rules
    )

    $baseline = $RecommendedBaselines[$CategoryKey]
    if (-not $baseline) {
        return
    }

    if (-not $Policies -or @($Policies).Count -eq 0) {
        Compare-PolicyToBaseline -Results $Results -CategoryKey $CategoryKey -PolicyObject $null -PolicyStatus 'Off' -PolicyPriority 'N/A'
        return
    }

    foreach ($policy in @($Policies)) {
        # Determine policy status and priority from associated rule
        $policyStatus = Get-PolicyStatus -Policy $policy -Rules $Rules -CategoryKey $CategoryKey
        $policyPriority = Get-PolicyPriority -Policy $policy -Rules $Rules -CategoryKey $CategoryKey
        Compare-PolicyToBaseline -Results $Results -CategoryKey $CategoryKey -PolicyObject $policy -PolicyStatus $policyStatus -PolicyPriority $policyPriority
    }

    Write-Log -Message ('Compared {0} policies in category: {1}.' -f @($Policies).Count, $baseline.DisplayName) -Level SUCCESS -Color Green
}
#endregion

#region Get-PolicyStatus
function Get-PolicyStatus {
    param(
        [object]$Policy,
        [object[]]$Rules,
        [string]$CategoryKey
    )

    if (-not $Policy) { return 'Off' }

    # Global ATP Settings and tenant-wide settings are always on
    if ($CategoryKey -eq 'AtpGlobal') { return 'Always On' }

    # Default/built-in policies are always on
    $policyIdentity = Get-PolicyIdentityInfo -Policy $Policy
    if ($policyIdentity.IsBuiltInDefault) {
        return 'Always On'
    }

    # Look up the associated rule's State property
    $matchingRule = Get-MatchingRuleForPolicy -Policy $Policy -Rules $Rules
    if ($matchingRule) {
        $state = Get-PropertyValue -InputObject $matchingRule -Name 'State'
        if ($state -eq 'Enabled') { return 'On' }
        elseif ($state -eq 'Disabled') { return 'Off' }
    }

    # If no rule found, check if policy has an Enabled property
    $enabled = Get-PropertyValue -InputObject $Policy -Name 'Enabled'
    if ($null -ne $enabled) {
        if ($enabled -eq $true) { return 'On' }
        else { return 'Off' }
    }

    return 'N/A'
}
#endregion

#region Get-PolicyPriority
function Get-PolicyPriority {
    param(
        [object]$Policy,
        [object[]]$Rules,
        [string]$CategoryKey
    )

    if (-not $Policy) { return 'N/A' }
    if ($CategoryKey -eq 'AtpGlobal') { return 'N/A' }

    $policyIdentity = Get-PolicyIdentityInfo -Policy $Policy
    if ($policyIdentity.IsBuiltInDefault) {
        return 'Lowest (Default)'
    }

    $matchingRule = Get-MatchingRuleForPolicy -Policy $Policy -Rules $Rules
    if ($matchingRule) {
        $priority = Get-PropertyValue -InputObject $matchingRule -Name 'Priority'
        if ($null -ne $priority) { return [string]$priority }
    }

    return 'N/A'
}
#endregion

#region Protect-CsvValue
function Protect-CsvValue {
    # Mitigates spreadsheet formula (CSV) injection (CWE-1236). Tenant-controlled
    # string values that begin with a formula trigger character are prefixed with a
    # single quote so Excel/Sheets treat them as inert text. Non-string values
    # (numbers, booleans, dates) are returned unchanged to avoid corrupting them.
    param([object]$Value)

    if ($Value -is [string] -and $Value.Length -gt 0) {
        if ([regex]::IsMatch($Value, "^[=+\-@\t\r\n]")) {
            return "'" + $Value
        }
    }

    return $Value
}
#endregion

#region Export-ObjectsToCsv
function Export-ObjectsToCsv {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName,
        [Parameter(Mandatory = $false)]
        [object[]]$InputObject
    )

    if ($SkipCsvExport) {
        return
    }

    $csvPath = Join-Path -Path $script:OutputRoot -ChildPath $FileName
    if (-not $InputObject -or @($InputObject).Count -eq 0) {
        Write-Log -Message ('Skipping CSV export for {0}; no data returned.' -f $FileName) -Level WARN -Color DarkYellow
        return
    }

    $exportParams = @{
        Path = $csvPath
        NoTypeInformation = $true
        Encoding = Get-Utf8EncodingName
    }

    $sanitized = foreach ($item in $InputObject) {
        if ($null -eq $item) { continue }
        $ordered = [ordered]@{}
        foreach ($prop in $item.PSObject.Properties) {
            $ordered[$prop.Name] = Protect-CsvValue -Value $prop.Value
        }
        [pscustomobject]$ordered
    }

    $sanitized | Export-Csv @exportParams
    Write-Log -Message ('Exported {0}.' -f $csvPath) -Level SUCCESS -Color Green
}
#endregion

#region Add-AdditionalFinding
function Add-AdditionalFinding {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [string]$Category,
        [string]$CheckName,
        [ValidateSet('Pass', 'Warning', 'Critical')]
        [string]$Status,
        [string]$Details,
        [string]$Recommendation
    )

    [void]$Findings.Add([pscustomobject]@{
            Category = $Category
            CheckName = $CheckName
            Status = $Status
            Details = $Details
            Recommendation = $Recommendation
        })
}
#endregion

#region Get-ObjectDisplayName
function Get-ObjectDisplayName {
    param(
        [AllowNull()]
        [object]$InputObject,
        [string]$Fallback = 'Unknown'
    )

    if ($null -eq $InputObject) {
        return $Fallback
    }

    foreach ($propertyName in $script:IdentifierProperties) {
        $value = Get-FirstPropertyValue -InputObject $InputObject -Names @($propertyName)
        if ($null -ne $value) {
            $text = Convert-ValueToString -Value $value
            if (-not [string]::IsNullOrWhiteSpace($text)) {
                return $text
            }
        }
    }

    return $Fallback
}
#endregion

#region Get-FirstPropertyValue
function Get-FirstPropertyValue {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,
        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    foreach ($name in $Names) {
        $value = Get-PropertyValue -InputObject $InputObject -Name $name
        if ($null -ne $value) {
            return $value
        }
    }

    return $null
}
#endregion

#region Get-ObjectIdentifiers
function Get-ObjectIdentifiers {
    param(
        [AllowNull()]
        [object]$InputObject
    )

    $identifiers = New-Object 'System.Collections.Generic.List[string]'
    if ($null -eq $InputObject) {
        return @()
    }

    foreach ($propertyName in $script:IdentifierProperties) {
        $value = Get-FirstPropertyValue -InputObject $InputObject -Names @($propertyName)
        if ($null -eq $value) {
            continue
        }

        foreach ($item in @($value)) {
            $text = Convert-ValueToString -Value $item
            if (-not [string]::IsNullOrWhiteSpace($text) -and -not $identifiers.Contains($text)) {
                [void]$identifiers.Add($text)
            }
        }
    }

    return @($identifiers)
}
#endregion

#region Test-IdentifierMatch
function Test-IdentifierMatch {
    param(
        [string[]]$LeftIdentifiers,
        [string]$RightValue
    )

    if (-not $LeftIdentifiers -or [string]::IsNullOrWhiteSpace($RightValue)) {
        return $false
    }

    $rightNormalized = $RightValue.Trim().ToLowerInvariant()
    foreach ($identifier in $LeftIdentifiers) {
        if ([string]::IsNullOrWhiteSpace($identifier)) {
            continue
        }

        $leftNormalized = $identifier.Trim().ToLowerInvariant()
        if ($leftNormalized -eq $rightNormalized) {
            return $true
        }

        if ($leftNormalized.Contains($rightNormalized) -or $rightNormalized.Contains($leftNormalized)) {
            return $true
        }
    }

    return $false
}
#endregion

#region Test-IsProtectionEnabled
function Test-IsProtectionEnabled {
    param(
        [AllowNull()]
        [object]$InputObject
    )

    if ($null -eq $InputObject) {
        return $false
    }

    $stateValue = Get-FirstPropertyValue -InputObject $InputObject -Names $script:StateProperties
    if ($null -eq $stateValue) {
        return $true
    }

    if ($stateValue -is [bool]) {
        return [bool]$stateValue
    }

    $stateText = (Convert-ValueToString -Value $stateValue).Trim().ToLowerInvariant()
    switch ($stateText) {
        'enabled' { return $true }
        'enable' { return $true }
        'true' { return $true }
        'on' { return $true }
        'enforce' { return $true }
        'enforced' { return $true }
        'disabled' { return $false }
        'disable' { return $false }
        'false' { return $false }
        'off' { return $false }
        'audit' { return $false }
        'test' { return $false }
        default { return $true }
    }
}
#endregion

#region Get-ProtectionStateText
function Get-ProtectionStateText {
    param(
        [AllowNull()]
        [object]$InputObject,
        [string]$DefaultText = 'Enabled'
    )

    if ($null -eq $InputObject) {
        return $DefaultText
    }

    $stateValue = Get-FirstPropertyValue -InputObject $InputObject -Names $script:StateProperties
    if ($null -eq $stateValue) {
        return $DefaultText
    }

    return Convert-ValueToString -Value $stateValue
}
#endregion

#region Get-RulePriorityValue
function Get-RulePriorityValue {
    param(
        [AllowNull()]
        [object]$RuleObject
    )

    if ($null -eq $RuleObject) {
        return [int]::MaxValue
    }

    $priorityValue = Get-FirstPropertyValue -InputObject $RuleObject -Names @('Priority')
    if ($null -eq $priorityValue) {
        return [int]::MaxValue
    }

    $parsedPriority = 0
    if ([int]::TryParse((Convert-ValueToString -Value $priorityValue), [ref]$parsedPriority)) {
        return $parsedPriority
    }

    return [int]::MaxValue
}
#endregion

#region Get-RuleScopeSummary
function Get-RuleScopeSummary {
    param(
        [AllowNull()]
        [object]$RuleObject
    )

    $includeProperties = @(
        'SentTo', 'SentToMemberOf', 'SentToScope', 'RecipientDomainIs', 'From', 'FromMemberOf', 'FromScope',
        'ExceptIfSentTo', 'ExceptIfSentToMemberOf', 'ExceptIfSentToScope', 'ExceptIfRecipientDomainIs', 'ExceptIfFrom', 'ExceptIfFromMemberOf', 'ExceptIfFromScope'
    )
    $scopeDetails = New-Object 'System.Collections.Generic.List[string]'

    foreach ($propertyName in $includeProperties) {
        $value = Get-FirstPropertyValue -InputObject $RuleObject -Names @($propertyName)
        if ($null -eq $value) {
            continue
        }

        $text = Convert-ValueToString -Value $value
        if (-not [string]::IsNullOrWhiteSpace($text)) {
            [void]$scopeDetails.Add(('{0} = {1}' -f $propertyName, $text))
        }
    }

    if ($scopeDetails.Count -eq 0) {
        return [pscustomobject]@{
            IsOrgWide = $true
            Details = 'Applies tenant-wide.'
        }
    }

    return [pscustomobject]@{
        IsOrgWide = $false
        Details = ('Scoped conditions detected: {0}.' -f ($scopeDetails -join '; '))
    }
}
#endregion

#region Get-QuarantinePolicyReferences
function Get-QuarantinePolicyReferences {
    param(
        [AllowNull()]
        [object]$PolicyObject
    )

    $references = New-Object 'System.Collections.Generic.List[object]'
    if ($null -eq $PolicyObject) {
        return $references
    }

    foreach ($property in $PolicyObject.PSObject.Properties) {
        if ($property.Name -notmatch 'Quarantine(Tag|Policy)') {
            continue
        }

        $valueText = Convert-ValueToString -Value $property.Value
        if ([string]::IsNullOrWhiteSpace($valueText)) {
            continue
        }

        if ($valueText.Trim().ToLowerInvariant() -eq 'quarantine') {
            continue
        }

        [void]$references.Add([pscustomobject]@{
            PropertyName = $property.Name
            ReferencedPolicy = $valueText
        })
    }

    return $references
}
#endregion

#region Get-LinkedRulesForPolicy
function Get-LinkedRulesForPolicy {
    param(
        [AllowNull()]
        [object]$PolicyObject,
        [object[]]$Rules,
        [string[]]$RulePolicyProperties
    )

    if ($null -eq $PolicyObject -or -not $Rules -or @($Rules).Count -eq 0) {
        return @()
    }

    $policyIdentifiers = Get-ObjectIdentifiers -InputObject $PolicyObject
    $linkedRules = foreach ($rule in @($Rules)) {
        foreach ($propertyName in $RulePolicyProperties) {
            $linkedPolicyName = Get-FirstPropertyValue -InputObject $rule -Names @($propertyName)
            if ($null -eq $linkedPolicyName) {
                continue
            }

            $linkedPolicyText = Convert-ValueToString -Value $linkedPolicyName
            if (Test-IdentifierMatch -LeftIdentifiers $policyIdentifiers -RightValue $linkedPolicyText) {
                $rule
                break
            }
        }
    }

    return @($linkedRules)
}
#endregion

#region Get-PolicyBaselineScore
function Get-PolicyBaselineScore {
    param(
        [string]$CategoryKey,
        [AllowNull()]
        [object]$PolicyObject
    )

    $baseline = $RecommendedBaselines[$CategoryKey]
    if (-not $baseline -or $null -eq $PolicyObject) {
        return [pscustomobject]@{
            Matched = 0
            Total = 0
            Percentage = 0
        }
    }

    $matched = 0
    $total = @($baseline.Settings.Keys).Count
    foreach ($settingName in $baseline.Settings.Keys) {
        $recommendedValue = $baseline.Settings[$settingName].Standard
        $currentValue = Get-PropertyValue -InputObject $PolicyObject -Name $settingName
        if ($null -ne $currentValue -and (Test-EquivalentValue -CurrentValue $currentValue -RecommendedValue $recommendedValue)) {
            $matched++
        }
    }

    $percentage = if ($total -gt 0) { [math]::Round(($matched / $total) * 100, 0) } else { 0 }
    return [pscustomobject]@{
        Matched = $matched
        Total = $total
        Percentage = $percentage
    }
}
#endregion

#region Invoke-QuarantinePolicyValidation
function Invoke-QuarantinePolicyValidation {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [hashtable]$AllData
    )

    try {
        $quarantinePolicies = @($AllData.QuarantinePolicies)
        $policySets = @(
            @{ Category = 'Anti-Phishing'; Policies = @($AllData.AntiPhishPolicies) }
            @{ Category = 'Inbound Anti-Spam'; Policies = @($AllData.InboundSpamPolicies) }
            @{ Category = 'Anti-Malware'; Policies = @($AllData.AntiMalwarePolicies) }
            @{ Category = 'Safe Attachments'; Policies = @($AllData.SafeAttachmentPolicies) }
        )

        if ($quarantinePolicies.Count -eq 0) {
            Add-AdditionalFinding -Findings $Findings -Category 'Quarantine Policies' -CheckName 'Referenced quarantine policies exist' -Status 'Warning' -Details 'No quarantine policies were collected, so referenced quarantine tags could not be validated.' -Recommendation 'Verify Get-QuarantinePolicy is available and review quarantine policy objects directly.'
            return
        }

        $knownNames = foreach ($policy in $quarantinePolicies) {
            Get-ObjectIdentifiers -InputObject $policy
        }
        $missingReferences = New-Object 'System.Collections.Generic.List[string]'
        $validatedCount = 0

        foreach ($policySet in $policySets) {
            foreach ($policy in $policySet.Policies) {
                $policyName = Get-ObjectDisplayName -InputObject $policy
                foreach ($reference in (Get-QuarantinePolicyReferences -PolicyObject $policy)) {
                    $validatedCount++
                    if (-not (Test-IdentifierMatch -LeftIdentifiers $knownNames -RightValue $reference.ReferencedPolicy)) {
                        [void]$missingReferences.Add(('{0} policy "{1}" references missing quarantine policy "{2}" via {3}' -f $policySet.Category, $policyName, $reference.ReferencedPolicy, $reference.PropertyName))
                    }
                }
            }
        }

        if ($missingReferences.Count -gt 0) {
            Add-AdditionalFinding -Findings $Findings -Category 'Quarantine Policies' -CheckName 'Referenced quarantine policies exist' -Status 'Critical' -Details ($missingReferences -join '; ') -Recommendation 'Create the missing quarantine policies or update each policy to reference a valid quarantine policy name.'
            return
        }

        $detailMessage = if ($validatedCount -gt 0) {
            ('Validated {0} quarantine policy reference(s) against {1} existing quarantine policy object(s).' -f $validatedCount, $quarantinePolicies.Count)
        }
        else {
            ('No explicit quarantine policy references were found across the collected threat policies. {0} quarantine policy object(s) were still collected successfully.' -f $quarantinePolicies.Count)
        }

        Add-AdditionalFinding -Findings $Findings -Category 'Quarantine Policies' -CheckName 'Referenced quarantine policies exist' -Status 'Pass' -Details $detailMessage -Recommendation 'No action required unless you intended to use custom quarantine policies.'
    }
    catch {
        $message = ('Additional quarantine policy validation failed: {0}' -f $_.Exception.Message)
        Add-ExecutionIssue -Category 'Additional Security Checks' -Stage 'QuarantineValidation' -Message $message
        Add-AdditionalFinding -Findings $Findings -Category 'Quarantine Policies' -CheckName 'Referenced quarantine policies exist' -Status 'Warning' -Details $message -Recommendation 'Review quarantine policy names manually in Exchange Online.'
    }
}
#endregion

#region Invoke-RuleCoverageAnalysis
function Invoke-RuleCoverageAnalysis {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [hashtable]$AllData
    )

    try {
        $policyMappings = Get-PolicyMappings -AllData $AllData

        foreach ($mapping in $policyMappings) {
            if (-not $mapping.Policies -or @($mapping.Policies).Count -eq 0) {
                Add-AdditionalFinding -Findings $Findings -Category 'Rule Coverage' -CheckName ('{0} rule coverage' -f $mapping.Category) -Status 'Warning' -Details ('No {0} policies were collected, so rule coverage could not be assessed.' -f $mapping.Category) -Recommendation 'Confirm the related Exchange Online cmdlets returned data and review rule assignments manually.'
                continue
            }

            if (-not $mapping.Rules -or @($mapping.Rules).Count -eq 0) {
                Add-AdditionalFinding -Findings $Findings -Category 'Rule Coverage' -CheckName ('{0} rule coverage' -f $mapping.Category) -Status 'Warning' -Details ('No {0} rules were collected, so policy assignments and coverage gaps could not be validated.' -f $mapping.Category) -Recommendation 'Confirm the related rule cmdlet is available and rerun the assessment before treating these policies as unassigned.'
                continue
            }

            foreach ($policy in $mapping.Policies) {
                $policyName = Get-ObjectDisplayName -InputObject $policy
                $linkedRules = @(Get-LinkedRulesForPolicy -PolicyObject $policy -Rules $mapping.Rules -RulePolicyProperties $mapping.RulePolicyProperties)
                $enabledRules = @($linkedRules | Where-Object { Test-IsProtectionEnabled -InputObject $_ })

                if ($enabledRules.Count -eq 0) {
                    Add-AdditionalFinding -Findings $Findings -Category 'Rule Coverage' -CheckName ('{0} policy assignment' -f $mapping.Category) -Status 'Critical' -Details ('Policy "{0}" has no enabled rule, so it is not actively protecting any recipients.' -f $policyName) -Recommendation ('Create or enable a {0} rule that targets the intended recipients for policy "{1}".' -f $mapping.Category, $policyName)
                    continue
                }

                $scopeSummaries = @($enabledRules | ForEach-Object { Get-RuleScopeSummary -RuleObject $_ })
                $orgWideRule = $scopeSummaries | Where-Object { $_.IsOrgWide } | Select-Object -First 1
                $ruleNames = @($enabledRules | ForEach-Object { Get-ObjectDisplayName -InputObject $_ })
                $coverageDetails = if ($orgWideRule) {
                    ('Enabled rules: {0}. At least one enabled rule applies tenant-wide.' -f ($ruleNames -join ', '))
                }
                else {
                    ('Enabled rules: {0}. {1}' -f ($ruleNames -join ', '), (($scopeSummaries | ForEach-Object { $_.Details }) -join ' '))
                }

                if ($orgWideRule) {
                    Add-AdditionalFinding -Findings $Findings -Category 'Rule Coverage' -CheckName ('{0} policy assignment' -f $mapping.Category) -Status 'Pass' -Details ('Policy "{0}" is backed by {1}. {2}' -f $policyName, $enabledRules.Count, $coverageDetails) -Recommendation 'No action required.'
                }
                else {
                    Add-AdditionalFinding -Findings $Findings -Category 'Rule Coverage' -CheckName ('{0} policy assignment' -f $mapping.Category) -Status 'Warning' -Details ('Policy "{0}" is active, but its enabled rules are scoped and may leave parts of the organization uncovered. {1}' -f $policyName, $coverageDetails) -Recommendation ('Review {0} rules for policy "{1}" and confirm whether the scoped assignments intentionally exclude users or domains.' -f $mapping.Category, $policyName)
                }
            }
        }
    }
    catch {
        $message = ('Rule coverage analysis failed: {0}' -f $_.Exception.Message)
        Add-ExecutionIssue -Category 'Additional Security Checks' -Stage 'RuleCoverage' -Message $message
        Add-AdditionalFinding -Findings $Findings -Category 'Rule Coverage' -CheckName 'Rule coverage analysis' -Status 'Warning' -Details $message -Recommendation 'Review policy-to-rule assignments manually.'
    }
}
#endregion

#region Invoke-PresetSecurityPolicyChecks
function Invoke-PresetSecurityPolicyChecks {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [hashtable]$AllData
    )

    try {
        $presetSets = @(
            @{ Label = 'EOP preset policies'; Rules = @($AllData.EopProtectionPolicyRules) }
            @{ Label = 'ATP preset policies'; Rules = @($AllData.AtpProtectionPolicyRules) }
        )

        foreach ($presetSet in $presetSets) {
            foreach ($presetName in 'Standard', 'Strict') {
                $matchingRules = @($presetSet.Rules | Where-Object {
                        $ruleName = Get-ObjectDisplayName -InputObject $_
                        $ruleName -match $presetName
                    })

                if ($matchingRules.Count -eq 0) {
                    Add-AdditionalFinding -Findings $Findings -Category 'Preset Security Policies' -CheckName ('{0} - {1}' -f $presetSet.Label, $presetName) -Status 'Warning' -Details ('No {0} rule was detected in {1}.' -f $presetName, $presetSet.Label) -Recommendation ('If you intend to rely on Microsoft preset security policies, enable the {0} preset policy and confirm its scope.' -f $presetName)
                    continue
                }

                $enabledRules = @($matchingRules | Where-Object { Test-IsProtectionEnabled -InputObject $_ })
                $scopeSummary = @($enabledRules | ForEach-Object { Get-RuleScopeSummary -RuleObject $_ })
                $ruleDescriptions = @($matchingRules | ForEach-Object {
                        '{0} (state: {1})' -f (Get-ObjectDisplayName -InputObject $_), (Get-ProtectionStateText -InputObject $_)
                    })

                if ($enabledRules.Count -eq 0) {
                    Add-AdditionalFinding -Findings $Findings -Category 'Preset Security Policies' -CheckName ('{0} - {1}' -f $presetSet.Label, $presetName) -Status 'Warning' -Details ('{0} was found, but it is not enforcing protection. Rules detected: {1}.' -f $presetName, ($ruleDescriptions -join '; ')) -Recommendation ('Enable the {0} preset policy or move it into an enforcing mode if you want Microsoft-managed coverage.' -f $presetName)
                    continue
                }

                $orgWideRule = $scopeSummary | Where-Object { $_.IsOrgWide } | Select-Object -First 1
                if ($orgWideRule) {
                    Add-AdditionalFinding -Findings $Findings -Category 'Preset Security Policies' -CheckName ('{0} - {1}' -f $presetSet.Label, $presetName) -Status 'Pass' -Details ('{0} is enabled in {1} and at least one rule applies tenant-wide. Rules detected: {2}.' -f $presetName, $presetSet.Label, ($ruleDescriptions -join '; ')) -Recommendation 'No action required.'
                }
                else {
                    Add-AdditionalFinding -Findings $Findings -Category 'Preset Security Policies' -CheckName ('{0} - {1}' -f $presetSet.Label, $presetName) -Status 'Warning' -Details ('{0} is enabled in {1}, but all detected rules are scoped. Rules detected: {2}. Scope details: {3}' -f $presetName, $presetSet.Label, ($ruleDescriptions -join '; '), (($scopeSummary | ForEach-Object { $_.Details }) -join ' ')) -Recommendation ('Confirm the {0} preset policy is assigned to every intended user, group, and domain.' -f $presetName)
                }
            }
        }
    }
    catch {
        $message = ('Preset security policy detection failed: {0}' -f $_.Exception.Message)
        Add-ExecutionIssue -Category 'Additional Security Checks' -Stage 'PresetPolicies' -Message $message
        Add-AdditionalFinding -Findings $Findings -Category 'Preset Security Policies' -CheckName 'Preset policy detection' -Status 'Warning' -Details $message -Recommendation 'Review preset security policies manually in Exchange Online.'
    }
}
#endregion

#region Invoke-PriorityOrderAnalysis
function Invoke-PriorityOrderAnalysis {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [hashtable]$AllData
    )

    try {
        $policyMappings = Get-PolicyMappings -AllData $AllData

        foreach ($mapping in $policyMappings) {
            if (@($mapping.Policies).Count -le 1) {
                continue
            }

            $orderedPolicies = foreach ($policy in $mapping.Policies) {
                $policyName = Get-ObjectDisplayName -InputObject $policy
                $linkedRules = @(Get-LinkedRulesForPolicy -PolicyObject $policy -Rules $mapping.Rules -RulePolicyProperties $mapping.RulePolicyProperties)
                $enabledRules = @($linkedRules | Where-Object { Test-IsProtectionEnabled -InputObject $_ })
                $priority = [int]::MaxValue
                if ($enabledRules.Count -gt 0) {
                    $priority = ($enabledRules | ForEach-Object { Get-RulePriorityValue -RuleObject $_ } | Measure-Object -Minimum).Minimum
                }

                $baselineScore = Get-PolicyBaselineScore -CategoryKey $mapping.CategoryKey -PolicyObject $policy
                [pscustomobject]@{
                    PolicyName = $policyName
                    Priority = $priority
                    Score = $baselineScore.Percentage
                    IsDefault = ($policy -eq (Get-PreferredPolicy -Policies $mapping.Policies))
                }
            }

            $orderedPolicies = @($orderedPolicies | Sort-Object Priority, PolicyName)
            $priorityDetails = @($orderedPolicies | ForEach-Object {
                    $priorityText = if ($_.Priority -eq [int]::MaxValue) { 'no enabled rule' } else { ('priority {0}' -f $_.Priority) }
                    $defaultMarker = if ($_.IsDefault) { ', default/built-in' } else { '' }
                    '{0} ({1}, standard score {2}%{3})' -f $_.PolicyName, $priorityText, $_.Score, $defaultMarker
                })

            $defaultPolicy = $orderedPolicies | Where-Object { $_.IsDefault } | Select-Object -First 1
            $higherPriorityWeakerPolicy = $null
            if ($defaultPolicy -and $defaultPolicy.Priority -ne [int]::MaxValue) {
                $higherPriorityWeakerPolicy = $orderedPolicies | Where-Object {
                    -not $_.IsDefault -and $_.Priority -lt $defaultPolicy.Priority -and $_.Score -lt $defaultPolicy.Score
                } | Select-Object -First 1
            }

            if (@($orderedPolicies | Where-Object { $_.Priority -ne [int]::MaxValue }).Count -eq 0) {
                Add-AdditionalFinding -Findings $Findings -Category 'Policy Priority' -CheckName ('{0} priority order' -f $mapping.Category) -Status 'Warning' -Details ('Multiple {0} policies exist, but no enabled rule priorities were available to determine effective precedence. Policies reviewed: {1}.' -f $mapping.Category, ($priorityDetails -join '; ')) -Recommendation ('Enable and validate the related {0} rules so effective policy precedence can be assessed.' -f $mapping.Category)
            }
            elseif ($higherPriorityWeakerPolicy) {
                Add-AdditionalFinding -Findings $Findings -Category 'Policy Priority' -CheckName ('{0} priority order' -f $mapping.Category) -Status 'Warning' -Details ('A less secure custom policy is evaluated before the default/built-in policy. Priority order: {0}.' -f ($priorityDetails -join '; ')) -Recommendation ('Review {0} rule priorities so stronger protection is evaluated before weaker custom policies.' -f $mapping.Category)
            }
            else {
                Add-AdditionalFinding -Findings $Findings -Category 'Policy Priority' -CheckName ('{0} priority order' -f $mapping.Category) -Status 'Pass' -Details ('Priority order reviewed: {0}.' -f ($priorityDetails -join '; ')) -Recommendation 'No action required unless policy precedence should be adjusted for business scope.'
            }
        }
    }
    catch {
        $message = ('Priority order analysis failed: {0}' -f $_.Exception.Message)
        Add-ExecutionIssue -Category 'Additional Security Checks' -Stage 'PriorityAnalysis' -Message $message
        Add-AdditionalFinding -Findings $Findings -Category 'Policy Priority' -CheckName 'Policy priority analysis' -Status 'Warning' -Details $message -Recommendation 'Review rule priority values manually.'
    }
}
#endregion

#region Invoke-DkimAndDmarcChecks
function Invoke-DkimAndDmarcChecks {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [hashtable]$AllData
    )

    try {
        $acceptedDomains = @($AllData.AcceptedDomains)
        $dkimConfigs = @($AllData.DkimSigningConfigs)
        if ($acceptedDomains.Count -eq 0) {
            Add-AdditionalFinding -Findings $Findings -Category 'Email Authentication' -CheckName 'DKIM coverage for accepted domains' -Status 'Warning' -Details 'No accepted domains were collected, so DKIM coverage could not be evaluated.' -Recommendation 'Confirm Get-AcceptedDomain ran successfully and validate DKIM manually.'
        }
        else {
            $domainsWithoutDkim = New-Object 'System.Collections.Generic.List[string]'
            foreach ($domain in $acceptedDomains) {
                $domainName = Get-ObjectDisplayName -InputObject $domain
                $matchingConfig = $dkimConfigs | Where-Object {
                    Test-IdentifierMatch -LeftIdentifiers (Get-ObjectIdentifiers -InputObject $_) -RightValue $domainName
                } | Select-Object -First 1

                if (-not $matchingConfig) {
                    [void]$domainsWithoutDkim.Add(('{0} (no DKIM config found)' -f $domainName))
                    continue
                }

                if (-not (Test-IsProtectionEnabled -InputObject $matchingConfig)) {
                    [void]$domainsWithoutDkim.Add(('{0} (DKIM disabled)' -f $domainName))
                }
            }

            if ($domainsWithoutDkim.Count -gt 0) {
                $enabledDomainCount = $acceptedDomains.Count - $domainsWithoutDkim.Count
                $status = if ($enabledDomainCount -eq 0) { 'Critical' } else { 'Warning' }
                Add-AdditionalFinding -Findings $Findings -Category 'Email Authentication' -CheckName 'DKIM coverage for accepted domains' -Status $status -Details ('DKIM is not fully enabled for all accepted domains. Gaps detected: {0}.' -f ($domainsWithoutDkim -join '; ')) -Recommendation 'Enable DKIM signing for every accepted domain that sends mail from Microsoft 365.'
            }
            else {
                Add-AdditionalFinding -Findings $Findings -Category 'Email Authentication' -CheckName 'DKIM coverage for accepted domains' -Status 'Pass' -Details ('DKIM is enabled for all {0} accepted domain(s) that were collected.' -f $acceptedDomains.Count) -Recommendation 'No action required.'
            }
        }

        $antiPhishPolicy = Get-PreferredPolicy -Policies @($AllData.AntiPhishPolicies)
        if (-not $antiPhishPolicy) {
            Add-AdditionalFinding -Findings $Findings -Category 'Email Authentication' -CheckName 'DMARC handling posture' -Status 'Warning' -Details 'No anti-phishing policy was available to review DMARC handling behavior.' -Recommendation 'Confirm anti-phishing policies are present and that DMARC actions are enforced.'
        }
        else {
            $honorDmarc = Get-PropertyValue -InputObject $antiPhishPolicy -Name 'HonorDmarcPolicy'
            $quarantineAction = Get-PropertyValue -InputObject $antiPhishPolicy -Name 'DmarcQuarantineAction'
            $rejectAction = Get-PropertyValue -InputObject $antiPhishPolicy -Name 'DmarcRejectAction'
            $policyName = Get-ObjectDisplayName -InputObject $antiPhishPolicy

            if ($honorDmarc -eq $true -and (Convert-ValueToString -Value $quarantineAction) -eq 'Quarantine' -and (Convert-ValueToString -Value $rejectAction) -eq 'Reject') {
                Add-AdditionalFinding -Findings $Findings -Category 'Email Authentication' -CheckName 'DMARC handling posture' -Status 'Pass' -Details ('Preferred anti-phishing policy "{0}" honors DMARC and uses Quarantine/Reject actions for DMARC verdicts.' -f $policyName) -Recommendation 'No action required.'
            }
            else {
                Add-AdditionalFinding -Findings $Findings -Category 'Email Authentication' -CheckName 'DMARC handling posture' -Status 'Warning' -Details ('Preferred anti-phishing policy "{0}" does not fully enforce the expected DMARC actions. HonorDmarcPolicy = {1}; DmarcQuarantineAction = {2}; DmarcRejectAction = {3}.' -f $policyName, (Convert-ValueToString -Value $honorDmarc), (Convert-ValueToString -Value $quarantineAction), (Convert-ValueToString -Value $rejectAction)) -Recommendation 'Enable HonorDmarcPolicy and configure DMARC quarantine/reject actions to enforce sender authentication failures.'
            }
        }
    }
    catch {
        $message = ('DKIM and DMARC status check failed: {0}' -f $_.Exception.Message)
        Add-ExecutionIssue -Category 'Additional Security Checks' -Stage 'DkimDmarc' -Message $message
        Add-AdditionalFinding -Findings $Findings -Category 'Email Authentication' -CheckName 'DKIM and DMARC status' -Status 'Warning' -Details $message -Recommendation 'Review DKIM and DMARC posture manually.'
    }
}
#endregion

#region Invoke-TransportRuleBypassChecks
function Invoke-TransportRuleBypassChecks {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [hashtable]$AllData
    )

    try {
        $transportRules = @($AllData.TransportRules | Where-Object { Test-IsProtectionEnabled -InputObject $_ })
        if ($transportRules.Count -eq 0) {
            Add-AdditionalFinding -Findings $Findings -Category 'Transport Rules' -CheckName 'Security bypass detection' -Status 'Pass' -Details 'No enabled transport rules were collected, so no obvious bypass patterns were found.' -Recommendation 'No action required.'
            return
        }

        $riskyRules = New-Object 'System.Collections.Generic.List[string]'
        foreach ($rule in $transportRules) {
            $ruleName = Get-ObjectDisplayName -InputObject $rule
            $reasons = New-Object 'System.Collections.Generic.List[string]'
            $sclValue = Get-FirstPropertyValue -InputObject $rule -Names @('SetSCL', 'SetScl')
            if ($null -ne $sclValue) {
                $sclText = Convert-ValueToString -Value $sclValue
                if ($sclText -eq '-1' -or $sclText -eq 'BypassSpamFiltering') {
                    [void]$reasons.Add('forces SCL to -1 / bypass spam filtering')
                }
            }

            $headerName = Convert-ValueToString -Value (Get-FirstPropertyValue -InputObject $rule -Names @('SetHeaderName'))
            $headerValue = Convert-ValueToString -Value (Get-FirstPropertyValue -InputObject $rule -Names @('SetHeaderValue'))
            if ($headerName -match 'SkipSafeLinksProcessing' -or $headerName -match 'SkipSafeAttachmentProcessing' -or $headerName -match 'BypassClutter' -or $headerName -match 'BypassFocusedInbox') {
                [void]$reasons.Add(('sets header {0} = {1}' -f $headerName, $headerValue))
            }

            if ($reasons.Count -gt 0) {
                [void]$riskyRules.Add(('{0}: {1}' -f $ruleName, ($reasons -join ', ')))
            }
        }

        if ($riskyRules.Count -gt 0) {
            Add-AdditionalFinding -Findings $Findings -Category 'Transport Rules' -CheckName 'Security bypass detection' -Status 'Critical' -Details ('Enabled transport rules with bypass patterns were found: {0}.' -f ($riskyRules -join '; ')) -Recommendation 'Remove or tightly scope transport rules that bypass spam filtering, Safe Links, or Safe Attachments.'
        }
        else {
            Add-AdditionalFinding -Findings $Findings -Category 'Transport Rules' -CheckName 'Security bypass detection' -Status 'Pass' -Details ('Reviewed {0} enabled transport rule(s) and found no obvious spam or Safe Links/Safe Attachments bypass patterns.' -f $transportRules.Count) -Recommendation 'No action required.'
        }
    }
    catch {
        $message = ('Transport rule bypass detection failed: {0}' -f $_.Exception.Message)
        Add-ExecutionIssue -Category 'Additional Security Checks' -Stage 'TransportRules' -Message $message
        Add-AdditionalFinding -Findings $Findings -Category 'Transport Rules' -CheckName 'Security bypass detection' -Status 'Warning' -Details $message -Recommendation 'Review enabled transport rules manually for bypass behavior.'
    }
}
#endregion

#region Invoke-ConnectorSecurityChecks
function Invoke-ConnectorSecurityChecks {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [hashtable]$AllData
    )

    try {
        $connectors = @($AllData.InboundConnectors)
        if ($connectors.Count -eq 0) {
            Add-AdditionalFinding -Findings $Findings -Category 'Inbound Connectors' -CheckName 'Connector security validation' -Status 'Pass' -Details 'No inbound connectors were collected.' -Recommendation 'No action required unless inbound connectors are expected in this tenant.'
            return
        }

        foreach ($connector in $connectors) {
            if (-not (Test-IsProtectionEnabled -InputObject $connector)) {
                continue
            }

            $connectorName = Get-ObjectDisplayName -InputObject $connector
            $issues = New-Object 'System.Collections.Generic.List[string]'
            $bypassSpam = Get-FirstPropertyValue -InputObject $connector -Names @('BypassSpamFiltering')
            $requireTls = Get-FirstPropertyValue -InputObject $connector -Names @('RequireTls', 'RequireTLS')
            $connectorType = Convert-ValueToString -Value (Get-FirstPropertyValue -InputObject $connector -Names @('ConnectorType'))
            $certificateName = Convert-ValueToString -Value (Get-FirstPropertyValue -InputObject $connector -Names @('TlsSenderCertificateName'))
            $bypassSpamEnabled = ((Convert-ValueToString -Value $bypassSpam).Trim().ToLowerInvariant() -eq 'true')
            $tlsRequired = ((Convert-ValueToString -Value $requireTls).Trim().ToLowerInvariant() -eq 'true')

            if ($bypassSpamEnabled) {
                [void]$issues.Add('bypasses spam filtering')
            }

            if (-not $tlsRequired) {
                [void]$issues.Add('does not require TLS')
            }

            if ($connectorType -match 'Partner' -and [string]::IsNullOrWhiteSpace($certificateName)) {
                [void]$issues.Add('partner connector has no sender certificate validation configured')
            }

            if ($issues.Count -eq 0) {
                Add-AdditionalFinding -Findings $Findings -Category 'Inbound Connectors' -CheckName ('Connector security - {0}' -f $connectorName) -Status 'Pass' -Details ('Inbound connector "{0}" does not show obvious spam bypass or TLS validation gaps.' -f $connectorName) -Recommendation 'No action required.'
            }
            else {
                $status = if ($bypassSpamEnabled) { 'Critical' } else { 'Warning' }
                Add-AdditionalFinding -Findings $Findings -Category 'Inbound Connectors' -CheckName ('Connector security - {0}' -f $connectorName) -Status $status -Details ('Inbound connector "{0}" has the following risk indicators: {1}.' -f $connectorName, ($issues -join '; ')) -Recommendation 'Review connector trust settings, require TLS, and remove unnecessary spam filtering bypasses.'
            }
        }
    }
    catch {
        $message = ('Connector security validation failed: {0}' -f $_.Exception.Message)
        Add-ExecutionIssue -Category 'Additional Security Checks' -Stage 'InboundConnectors' -Message $message
        Add-AdditionalFinding -Findings $Findings -Category 'Inbound Connectors' -CheckName 'Connector security validation' -Status 'Warning' -Details $message -Recommendation 'Review inbound connectors manually in Exchange Online.'
    }
}
#endregion

#region Phase 5 — Impersonation Protection
function Invoke-ImpersonationProtectionChecks {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [hashtable]$AllData
    )

    try {
        $antiPhishPolicies = @($AllData.AntiPhishPolicies)
        if ($antiPhishPolicies.Count -eq 0) {
            Add-AdditionalFinding -Findings $Findings -Category 'Impersonation Protection' -CheckName 'Anti-Phish policies present' -Status 'Warning' -Details 'No anti-phish policies were collected, so impersonation protection coverage could not be validated.' -Recommendation 'Confirm Microsoft Defender for Office 365 anti-phishing policies exist and are accessible.'
            return
        }

        foreach ($policy in $antiPhishPolicies) {
            $policyName = Get-ObjectDisplayName -InputObject $policy

            # Targeted user protection
            $targetedUserEnabled = $false
            $prop = $policy.PSObject.Properties['EnableTargetedUserProtection']
            if ($prop) { $targetedUserEnabled = [bool]$prop.Value }

            $targetedUsers = @()
            foreach ($propName in @('TargetedUsersToProtect', 'TargetedUsers')) {
                $p = $policy.PSObject.Properties[$propName]
                if ($p -and $p.Value) {
                    $targetedUsers = @($p.Value | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                    break
                }
            }

            if ($targetedUserEnabled -and $targetedUsers.Count -eq 0) {
                Add-AdditionalFinding -Findings $Findings -Category 'Impersonation Protection' -CheckName ('Targeted users configured - {0}' -f $policyName) -Status 'Warning' -Details ('Policy "{0}" has targeted user protection enabled but no protected users are configured.' -f $policyName) -Recommendation 'Add high-value targets such as executives, finance staff, and administrators to the targeted users list.'
            }
            elseif ($targetedUserEnabled) {
                Add-AdditionalFinding -Findings $Findings -Category 'Impersonation Protection' -CheckName ('Targeted users configured - {0}' -f $policyName) -Status 'Pass' -Details ('Policy "{0}" protects {1} targeted user(s).' -f $policyName, $targetedUsers.Count) -Recommendation 'Keep the targeted users list current as roles and risk profiles change.'
            }

            # Targeted domain protection
            $targetedDomainEnabled = $false
            foreach ($propName in @('EnableTargetedDomainsProtection', 'EnableTargetedDomainProtection')) {
                $p = $policy.PSObject.Properties[$propName]
                if ($p) { $targetedDomainEnabled = [bool]$p.Value; break }
            }

            $targetedDomains = @()
            foreach ($propName in @('TargetedDomainsToProtect', 'TargetedDomains')) {
                $p = $policy.PSObject.Properties[$propName]
                if ($p -and $p.Value) {
                    $targetedDomains = @($p.Value | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                    break
                }
            }

            if ($targetedDomainEnabled -and $targetedDomains.Count -eq 0) {
                Add-AdditionalFinding -Findings $Findings -Category 'Impersonation Protection' -CheckName ('Targeted domains configured - {0}' -f $policyName) -Status 'Warning' -Details ('Policy "{0}" has targeted domain protection enabled but no custom domains are configured.' -f $policyName) -Recommendation 'Add all accepted custom domains that attackers could impersonate.'
            }
            elseif ($targetedDomainEnabled) {
                Add-AdditionalFinding -Findings $Findings -Category 'Impersonation Protection' -CheckName ('Targeted domains configured - {0}' -f $policyName) -Status 'Pass' -Details ('Policy "{0}" protects {1} targeted domain(s).' -f $policyName, $targetedDomains.Count) -Recommendation 'Review the protected domain list whenever new accepted domains are introduced.'
            }

            # Mailbox intelligence exclusions
            $exclusions = @()
            $p = $policy.PSObject.Properties['MailboxIntelligenceExcludedSenders']
            if ($p -and $p.Value) {
                $exclusions = @($p.Value | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            }

            if ($exclusions.Count -gt 20) {
                Add-AdditionalFinding -Findings $Findings -Category 'Impersonation Protection' -CheckName ('Mailbox intelligence exclusions - {0}' -f $policyName) -Status 'Warning' -Details ('Policy "{0}" excludes {1} sender(s) from mailbox intelligence, which may be overly broad.' -f $policyName, $exclusions.Count) -Recommendation 'Review and reduce mailbox intelligence exclusions to only the senders that genuinely require bypass.'
            }
            elseif ($exclusions.Count -gt 0) {
                Add-AdditionalFinding -Findings $Findings -Category 'Impersonation Protection' -CheckName ('Mailbox intelligence exclusions - {0}' -f $policyName) -Status 'Pass' -Details ('Policy "{0}" has {1} mailbox intelligence exclusion(s).' -f $policyName, $exclusions.Count) -Recommendation 'Validate that each excluded sender still requires an impersonation protection exception.'
            }
        }
    }
    catch {
        $message = ('Impersonation protection check failed: {0}' -f $_.Exception.Message)
        Add-ExecutionIssue -Category 'Additional Security Checks' -Stage 'ImpersonationProtection' -Message $message
        Add-AdditionalFinding -Findings $Findings -Category 'Impersonation Protection' -CheckName 'Impersonation protection analysis' -Status 'Warning' -Details $message -Recommendation 'Review impersonation protection settings manually in anti-phishing policies.'
    }
}
#endregion

#region Phase 5 — Allow/Block List Audit
function Invoke-AllowBlockListAudit {
    param(
        [System.Collections.Generic.List[object]]$Findings
    )

    try {
        if (-not (Get-Command -Name 'Get-TenantAllowBlockListItems' -ErrorAction SilentlyContinue)) {
            Add-AdditionalFinding -Findings $Findings -Category 'Tenant Allow/Block List' -CheckName 'Allow/Block list availability' -Status 'Warning' -Details 'Get-TenantAllowBlockListItems is not available in this session.' -Recommendation 'Run this check from an Exchange Online session with Defender permissions.'
            return
        }

        $listTypes = @('Sender', 'Url', 'FileHash')
        foreach ($listType in $listTypes) {
            try {
                $items = @(Get-TenantAllowBlockListItems -ListType $listType -ErrorAction Stop)
            }
            catch {
                Add-AdditionalFinding -Findings $Findings -Category 'Tenant Allow/Block List' -CheckName ('{0} list retrieval' -f $listType) -Status 'Warning' -Details ('Unable to retrieve {0} allow/block list entries: {1}' -f $listType.ToLower(), $_.Exception.Message) -Recommendation 'Verify Defender for Office 365 permissions and rerun the audit.'
                continue
            }

            $allowItems = @($items | Where-Object { ([string]$_.Action) -eq 'Allow' })
            $blockItems = @($items | Where-Object { ([string]$_.Action) -eq 'Block' })

            if ($listType -eq 'Sender' -and $allowItems.Count -gt 0) {
                $domainAllows = @($allowItems | Where-Object { $entry = [string]$_.Entry; ($entry -match '^\*?@[^@]+$') -or ($entry -notmatch '@') })
                Add-AdditionalFinding -Findings $Findings -Category 'Tenant Allow/Block List' -CheckName 'Sender allow entries' -Status 'Warning' -Details ('Tenant allow/block list contains {0} sender allow entry(ies) ({1} domain-level allows). Block entries: {2}.' -f $allowItems.Count, $domainAllows.Count, $blockItems.Count) -Recommendation 'Review sender allow entries and remove broad domain-level allows that bypass spoof and phishing protections.'
            }
            elseif ($allowItems.Count -gt 0) {
                Add-AdditionalFinding -Findings $Findings -Category 'Tenant Allow/Block List' -CheckName ('{0} allow entries' -f $listType) -Status 'Warning' -Details ('Tenant allow/block list contains {0} {1} allow entry(ies), which can weaken native protection.' -f $allowItems.Count, $listType.ToLower()) -Recommendation ('Review {0} allow entries and remove any temporary or no-longer-needed overrides.' -f $listType.ToLower())
            }
            else {
                Add-AdditionalFinding -Findings $Findings -Category 'Tenant Allow/Block List' -CheckName ('{0} allow entries' -f $listType) -Status 'Pass' -Details ('No {0} allow entries found. Block entries: {1}.' -f $listType.ToLower(), $blockItems.Count) -Recommendation ('Continue using the {0} list primarily for targeted blocking.' -f $listType.ToLower())
            }
        }
    }
    catch {
        $message = ('Allow/Block list audit failed: {0}' -f $_.Exception.Message)
        Add-ExecutionIssue -Category 'Additional Security Checks' -Stage 'AllowBlockList' -Message $message
        Add-AdditionalFinding -Findings $Findings -Category 'Tenant Allow/Block List' -CheckName 'Allow/Block list audit' -Status 'Warning' -Details $message -Recommendation 'Review tenant allow/block list manually.'
    }
}
#endregion

#region Phase 5 — Advanced Delivery Policy Check
function Invoke-AdvancedDeliveryChecks {
    param(
        [System.Collections.Generic.List[object]]$Findings
    )

    try {
        $secOpsMailboxCount = 0
        $phishSimUrlCount = 0

        # Check SecOps Override Policy
        if (Get-Command -Name 'Get-SecOpsOverridePolicy' -ErrorAction SilentlyContinue) {
            try {
                $secOpsPolicies = @(Get-SecOpsOverridePolicy -ErrorAction Stop)
                foreach ($policy in $secOpsPolicies) {
                    $mailboxes = $policy.PSObject.Properties['SecOpsMailboxes']
                    if ($mailboxes -and $mailboxes.Value) {
                        $secOpsMailboxCount += @($mailboxes.Value | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
                    }
                }
            }
            catch { }
        }

        # Check Phishing Simulation Override Policy
        if (Get-Command -Name 'Get-PhishSimOverridePolicy' -ErrorAction SilentlyContinue) {
            try {
                $phishSimPolicies = @(Get-PhishSimOverridePolicy -ErrorAction Stop)
                foreach ($policy in $phishSimPolicies) {
                    foreach ($propName in @('SimulationUrls', 'Urls', 'URLs', 'PhishSimUrls')) {
                        $p = $policy.PSObject.Properties[$propName]
                        if ($p -and $p.Value) {
                            $phishSimUrlCount += @($p.Value | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
                            break
                        }
                    }
                }
            }
            catch { }
        }

        if ($secOpsMailboxCount -gt 0) {
            Add-AdditionalFinding -Findings $Findings -Category 'Advanced Delivery' -CheckName 'SecOps mailboxes via Advanced Delivery' -Status 'Pass' -Details ('Advanced Delivery is configured for {0} SecOps mailbox(es).' -f $secOpsMailboxCount) -Recommendation 'Keep SecOps mailbox definitions in Advanced Delivery instead of transport rule bypasses.'
        }
        else {
            Add-AdditionalFinding -Findings $Findings -Category 'Advanced Delivery' -CheckName 'SecOps mailboxes via Advanced Delivery' -Status 'Warning' -Details 'No SecOps mailboxes found in Advanced Delivery policies.' -Recommendation 'Configure SecOps mailboxes in Advanced Delivery if your investigation team requires unfiltered mail delivery.'
        }

        if ($phishSimUrlCount -gt 0) {
            Add-AdditionalFinding -Findings $Findings -Category 'Advanced Delivery' -CheckName 'Phishing simulation Advanced Delivery' -Status 'Pass' -Details ('Advanced Delivery includes {0} phishing simulation URL(s).' -f $phishSimUrlCount) -Recommendation 'Use Advanced Delivery for simulation platforms instead of mail flow rule bypasses.'
        }
        else {
            Add-AdditionalFinding -Findings $Findings -Category 'Advanced Delivery' -CheckName 'Phishing simulation Advanced Delivery' -Status 'Warning' -Details 'No phishing simulation Advanced Delivery entries found.' -Recommendation 'Configure phishing simulation URLs in Advanced Delivery instead of bypassing protections with transport rules.'
        }
    }
    catch {
        $message = ('Advanced Delivery check failed: {0}' -f $_.Exception.Message)
        Add-ExecutionIssue -Category 'Additional Security Checks' -Stage 'AdvancedDelivery' -Message $message
        Add-AdditionalFinding -Findings $Findings -Category 'Advanced Delivery' -CheckName 'Advanced Delivery analysis' -Status 'Warning' -Details $message -Recommendation 'Review Advanced Delivery configuration manually.'
    }
}
#endregion

#region Phase 5 — Audit Log Verification
function Invoke-AuditLogChecks {
    param(
        [System.Collections.Generic.List[object]]$Findings
    )

    try {
        if (-not (Get-Command -Name 'Get-AdminAuditLogConfig' -ErrorAction SilentlyContinue)) {
            Add-AdditionalFinding -Findings $Findings -Category 'Audit Logging' -CheckName 'Unified audit log enabled' -Status 'Warning' -Details 'Get-AdminAuditLogConfig is not available in this session.' -Recommendation 'Run this check from a session with the necessary Exchange Online permissions.'
            return
        }

        $config = Get-AdminAuditLogConfig -ErrorAction Stop
        $enabled = $false
        $prop = $config.PSObject.Properties['UnifiedAuditLogIngestionEnabled']
        if ($prop) { $enabled = [bool]$prop.Value }

        if ($enabled) {
            Add-AdditionalFinding -Findings $Findings -Category 'Audit Logging' -CheckName 'Unified audit log enabled' -Status 'Pass' -Details 'Unified audit log ingestion is enabled for the tenant.' -Recommendation 'Continue monitoring audit events and ensure retention meets investigation requirements.'
        }
        else {
            Add-AdditionalFinding -Findings $Findings -Category 'Audit Logging' -CheckName 'Unified audit log enabled' -Status 'Critical' -Details 'Unified audit log ingestion is disabled, which severely hampers security incident investigation.' -Recommendation 'Enable unified audit logging to preserve mailbox and security event telemetry.'
        }
    }
    catch {
        $message = ('Audit log check failed: {0}' -f $_.Exception.Message)
        Add-ExecutionIssue -Category 'Additional Security Checks' -Stage 'AuditLog' -Message $message
        Add-AdditionalFinding -Findings $Findings -Category 'Audit Logging' -CheckName 'Unified audit log enabled' -Status 'Warning' -Details $message -Recommendation 'Verify audit logging status manually via Get-AdminAuditLogConfig.'
    }
}
#endregion

#region Phase 5 — ATP Coverage Gap Detection
function Invoke-AtpCoverageGapChecks {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [hashtable]$AllData
    )

    try {
        $ruleSets = @(
            @{ Name = 'Safe Attachments'; Rules = @($AllData.SafeAttachmentRules) },
            @{ Name = 'Safe Links'; Rules = @($AllData.SafeLinkRules) }
        )

        foreach ($ruleSet in $ruleSets) {
            $rules = @($ruleSet.Rules | Where-Object { $_ -ne $null })
            if ($rules.Count -eq 0) {
                Add-AdditionalFinding -Findings $Findings -Category 'ATP Coverage' -CheckName ('{0} rule coverage' -f $ruleSet.Name) -Status 'Critical' -Details ('No enabled {0} rules found. Tenant-wide coverage cannot be assumed.' -f $ruleSet.Name) -Recommendation ('Create at least one enabled {0} rule that covers all intended recipients.' -f $ruleSet.Name)
                continue
            }

            # Check for rules covering all recipients
            $hasGlobalCoverage = $false
            foreach ($rule in $rules) {
                $enabled = $true
                $ep = $rule.PSObject.Properties['State']
                if ($ep) { $enabled = ([string]$ep.Value) -ne 'Disabled' }

                if (-not $enabled) { continue }

                $scoped = $false
                foreach ($scopeProp in @('SentTo', 'SentToMemberOf', 'RecipientDomainIs')) {
                    $sp = $rule.PSObject.Properties[$scopeProp]
                    if ($sp -and $sp.Value -and @($sp.Value).Count -gt 0) {
                        $scoped = $true
                        break
                    }
                }

                if (-not $scoped) {
                    $hasGlobalCoverage = $true
                }
            }

            if ($hasGlobalCoverage) {
                Add-AdditionalFinding -Findings $Findings -Category 'ATP Coverage' -CheckName ('{0} rule coverage' -f $ruleSet.Name) -Status 'Pass' -Details ('{0} has at least one enabled rule covering all recipients.' -f $ruleSet.Name) -Recommendation ('Review rule priority and exceptions periodically to confirm tenant-wide {0} coverage remains intact.' -f $ruleSet.Name)
            }
            else {
                Add-AdditionalFinding -Findings $Findings -Category 'ATP Coverage' -CheckName ('{0} rule coverage' -f $ruleSet.Name) -Status 'Warning' -Details ('All enabled {0} rules are scoped to specific recipients. Some mailboxes may lack {0} protection.' -f $ruleSet.Name) -Recommendation ('Review {0} rules to ensure every mailbox, group, and accepted domain is covered.' -f $ruleSet.Name)
            }
        }
    }
    catch {
        $message = ('ATP coverage gap check failed: {0}' -f $_.Exception.Message)
        Add-ExecutionIssue -Category 'Additional Security Checks' -Stage 'AtpCoverageGaps' -Message $message
        Add-AdditionalFinding -Findings $Findings -Category 'ATP Coverage' -CheckName 'ATP coverage analysis' -Status 'Warning' -Details $message -Recommendation 'Review Safe Links and Safe Attachments rule coverage manually.'
    }
}
#endregion

#region Phase 5 — Zero-Hour Auto Purge (ZAP) Effectiveness
function Invoke-ZapEffectivenessChecks {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [hashtable]$AllData
    )

    try {
        # Check ZAP in inbound spam policies
        $spamPolicies = @($AllData.InboundSpamPolicies | Where-Object { $_ -ne $null })
        foreach ($policy in $spamPolicies) {
            $policyName = Get-ObjectDisplayName -InputObject $policy

            $spamZapEnabled = $false
            $phishZapEnabled = $false
            $szProp = $policy.PSObject.Properties['SpamZapEnabled']
            $pzProp = $policy.PSObject.Properties['PhishZapEnabled']
            if ($szProp) { $spamZapEnabled = [bool]$szProp.Value }
            if ($pzProp) { $phishZapEnabled = [bool]$pzProp.Value }

            if ($spamZapEnabled -and $phishZapEnabled) {
                Add-AdditionalFinding -Findings $Findings -Category 'Zero-Hour Auto Purge' -CheckName ('Inbound spam ZAP - {0}' -f $policyName) -Status 'Pass' -Details ('Policy "{0}" has spam and phish ZAP enabled.' -f $policyName) -Recommendation 'Keep ZAP enabled for post-delivery remediation.'
            }
            elseif (-not $spamZapEnabled -and -not $phishZapEnabled) {
                Add-AdditionalFinding -Findings $Findings -Category 'Zero-Hour Auto Purge' -CheckName ('Inbound spam ZAP - {0}' -f $policyName) -Status 'Critical' -Details ('Policy "{0}" has both SpamZapEnabled and PhishZapEnabled disabled.' -f $policyName) -Recommendation 'Enable both spam and phish ZAP to improve post-delivery remediation.'
            }
            else {
                $missing = @()
                if (-not $spamZapEnabled) { $missing += 'spam' }
                if (-not $phishZapEnabled) { $missing += 'phish' }
                Add-AdditionalFinding -Findings $Findings -Category 'Zero-Hour Auto Purge' -CheckName ('Inbound spam ZAP - {0}' -f $policyName) -Status 'Warning' -Details ('Policy "{0}" does not have ZAP enabled for: {1}.' -f $policyName, ($missing -join ', ')) -Recommendation 'Enable both SpamZapEnabled and PhishZapEnabled for consistent post-delivery protection.'
            }
        }

        # Check ZAP in anti-malware policies
        $malwarePolicies = @($AllData.AntiMalwarePolicies | Where-Object { $_ -ne $null })
        foreach ($policy in $malwarePolicies) {
            $policyName = Get-ObjectDisplayName -InputObject $policy
            $zapEnabled = $false
            $zProp = $policy.PSObject.Properties['ZapEnabled']
            if ($zProp) { $zapEnabled = [bool]$zProp.Value }

            if ($zapEnabled) {
                Add-AdditionalFinding -Findings $Findings -Category 'Zero-Hour Auto Purge' -CheckName ('Malware ZAP - {0}' -f $policyName) -Status 'Pass' -Details ('Policy "{0}" has ZAP enabled.' -f $policyName) -Recommendation 'Continue using malware ZAP for rapid cleanup.'
            }
            else {
                Add-AdditionalFinding -Findings $Findings -Category 'Zero-Hour Auto Purge' -CheckName ('Malware ZAP - {0}' -f $policyName) -Status 'Warning' -Details ('Policy "{0}" has ZapEnabled disabled.' -f $policyName) -Recommendation 'Enable ZapEnabled in anti-malware policies for post-delivery malware remediation.'
            }
        }
    }
    catch {
        $message = ('ZAP effectiveness check failed: {0}' -f $_.Exception.Message)
        Add-ExecutionIssue -Category 'Additional Security Checks' -Stage 'ZapEffectiveness' -Message $message
        Add-AdditionalFinding -Findings $Findings -Category 'Zero-Hour Auto Purge' -CheckName 'ZAP effectiveness analysis' -Status 'Warning' -Details $message -Recommendation 'Review ZAP settings manually in spam and malware policies.'
    }
}
#endregion

#region Phase 5 — Outbound Spam Notification Validation
function Invoke-OutboundSpamNotificationChecks {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [hashtable]$AllData
    )

    try {
        $outboundPolicies = @($AllData.OutboundSpamPolicies | Where-Object { $_ -ne $null })
        if ($outboundPolicies.Count -eq 0) {
            Add-AdditionalFinding -Findings $Findings -Category 'Outbound Spam Notifications' -CheckName 'Outbound spam policies present' -Status 'Warning' -Details 'No outbound spam policies were collected.' -Recommendation 'Verify outbound spam policies are accessible and rerun the assessment.'
            return
        }

        $notificationConfigured = $false
        foreach ($policy in $outboundPolicies) {
            $policyName = Get-ObjectDisplayName -InputObject $policy
            $bccEnabled = $false
            $notifyEnabled = $false

            $bccProp = $policy.PSObject.Properties['BccSuspiciousOutboundMail']
            $notifyProp = $policy.PSObject.Properties['NotifyOutboundSpam']
            $recipientsProp = $policy.PSObject.Properties['NotifyOutboundSpamRecipients']

            if ($bccProp) { $bccEnabled = [bool]$bccProp.Value }
            if ($notifyProp) { $notifyEnabled = [bool]$notifyProp.Value }
            $recipients = @()
            if ($recipientsProp -and $recipientsProp.Value) {
                $recipients = @($recipientsProp.Value | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            }

            if ($bccEnabled -or $notifyEnabled -or $recipients.Count -gt 0) {
                $notificationConfigured = $true
                Add-AdditionalFinding -Findings $Findings -Category 'Outbound Spam Notifications' -CheckName ('Notification config - {0}' -f $policyName) -Status 'Pass' -Details ('Policy "{0}" has outbound spam notification settings configured.' -f $policyName) -Recommendation 'Ensure notification recipients are monitored by the messaging or security team.'
            }
            else {
                Add-AdditionalFinding -Findings $Findings -Category 'Outbound Spam Notifications' -CheckName ('Notification config - {0}' -f $policyName) -Status 'Warning' -Details ('Policy "{0}" does not have Bcc or notification settings configured for outbound spam.' -f $policyName) -Recommendation 'Configure BccSuspiciousOutboundMail or NotifyOutboundSpam for outbound spam events.'
            }
        }

        # If no policy-level notification found, check alert policies as fallback
        if (-not $notificationConfigured -and (Get-Command -Name 'Get-ProtectionAlert' -ErrorAction SilentlyContinue)) {
            try {
                $alertPolicies = @(Get-ProtectionAlert -ErrorAction Stop)
                $matchingAlerts = @($alertPolicies | Where-Object {
                    $text = @($_.Name, $_.Comment) -join ' '
                    $text -match '(?i)outbound|restricted|spam'
                })
                if ($matchingAlerts.Count -gt 0) {
                    Add-AdditionalFinding -Findings $Findings -Category 'Outbound Spam Notifications' -CheckName 'Alert policy coverage' -Status 'Pass' -Details ('Found {0} alert policy(ies) related to outbound spam or restricted users.' -f $matchingAlerts.Count) -Recommendation 'Confirm those alerts are routed to an actively monitored team mailbox.'
                }
                else {
                    Add-AdditionalFinding -Findings $Findings -Category 'Outbound Spam Notifications' -CheckName 'Alert policy coverage' -Status 'Warning' -Details 'No matching alert policies found for outbound spam or restricted-user events.' -Recommendation 'Create alert policies or outbound spam notifications so blocked senders are investigated quickly.'
                }
            }
            catch { }
        }
    }
    catch {
        $message = ('Outbound spam notification check failed: {0}' -f $_.Exception.Message)
        Add-ExecutionIssue -Category 'Additional Security Checks' -Stage 'OutboundSpamNotification' -Message $message
        Add-AdditionalFinding -Findings $Findings -Category 'Outbound Spam Notifications' -CheckName 'Outbound spam notification analysis' -Status 'Warning' -Details $message -Recommendation 'Review outbound spam notification settings manually.'
    }
}
#endregion

#region Invoke-AdditionalSecurityChecks
function Invoke-AdditionalSecurityChecks {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [hashtable]$AllData
    )

    # Phase 2 checks
    Invoke-QuarantinePolicyValidation -Findings $Findings -AllData $AllData
    Invoke-RuleCoverageAnalysis -Findings $Findings -AllData $AllData
    Invoke-PresetSecurityPolicyChecks -Findings $Findings -AllData $AllData
    Invoke-PriorityOrderAnalysis -Findings $Findings -AllData $AllData
    Invoke-DkimAndDmarcChecks -Findings $Findings -AllData $AllData
    Invoke-TransportRuleBypassChecks -Findings $Findings -AllData $AllData
    Invoke-ConnectorSecurityChecks -Findings $Findings -AllData $AllData

    # Phase 5 checks — Extra Protection Layers
    Invoke-ImpersonationProtectionChecks -Findings $Findings -AllData $AllData
    Invoke-AllowBlockListAudit -Findings $Findings
    Invoke-AdvancedDeliveryChecks -Findings $Findings
    Invoke-AuditLogChecks -Findings $Findings
    Invoke-AtpCoverageGapChecks -Findings $Findings -AllData $AllData
    Invoke-ZapEffectivenessChecks -Findings $Findings -AllData $AllData
    Invoke-OutboundSpamNotificationChecks -Findings $Findings -AllData $AllData
}
#endregion

#region HtmlEncode
function HtmlEncode {
    param([string]$Text)
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}
#endregion

#region ConvertTo-SafeUrl
function ConvertTo-SafeUrl {
    # Returns an HTML-attribute-safe URL. Only http/https schemes are allowed;
    # anything else (e.g. javascript:) is dropped to '#' to prevent stored XSS via
    # href attributes. The result is HTML-encoded for safe attribute interpolation.
    param([string]$Url)

    if ([string]::IsNullOrWhiteSpace($Url)) {
        return '#'
    }

    if ($Url -notmatch '^(https?):\/\/') {
        return '#'
    }

    return [System.Net.WebUtility]::HtmlEncode($Url)
}
#endregion

#region Get-StatusCssClass
function Get-StatusCssClass {
    param([string]$Status)

    switch ($Status) {
        'Matched' { return 'status-matched' }
        'NotMatched' { return 'status-not-matched' }
        'Pass' { return 'status-pass' }
        'Warning' { return 'status-warning' }
        'Critical' { return 'status-critical' }
        default { return 'status-unknown' }
    }
}
#endregion

#region New-StatusBadgeHtml
function New-StatusBadgeHtml {
    param([string]$Status)
    $cssClass = Get-StatusCssClass -Status $Status
    $displayText = switch ($Status) {
        'Matched'    { '&#10004; Matched' }
        'NotMatched' { '&#10060; Not Matched' }
        'Pass'       { '&#10004; Pass' }
        'Warning'    { '&#9888; Warning' }
        'Critical'   { '&#10060; Critical' }
        default      { HtmlEncode -Text $Status }
    }
    return ('<span class="status-badge {0}">{1}</span>' -f $cssClass, $displayText)
}
#endregion

#region New-PolicyStatusBadgeHtml
function New-PolicyStatusBadgeHtml {
    param([string]$Status)
    $cssClass = switch ($Status) {
        'On'        { 'policy-on' }
        'Always On' { 'policy-always-on' }
        'Off'       { 'policy-off' }
        default     { 'policy-na' }
    }
    return ('<span class="pill {0}">Policy Status: {1}</span>' -f $cssClass, (HtmlEncode -Text $Status))
}
#endregion

#region New-PolicyPriorityBadgeHtml
function New-PolicyPriorityBadgeHtml {
    param([string]$Priority)
    if (-not $Priority -or $Priority -eq 'N/A') { return '' }
    return ('<span class="pill priority">Priority: {0}</span>' -f (HtmlEncode -Text $Priority))
}
#endregion

#region New-ScoreRingSvg
function New-ScoreRingSvg {
    param(
        [int]$Score,
        [int]$Size = 100
    )

    $radius = [int]($Size * 0.4)
    $circumference = [math]::Round(2 * [math]::PI * $radius, 2)
    $offset = [math]::Round($circumference * (1 - $Score / 100.0), 2)
    $color = if ($Score -ge 80) { '#10b981' } elseif ($Score -ge 50) { '#f59e0b' } else { '#ef4444' }
    $centerX = $Size / 2
    $centerY = $Size / 2
    $textY = $centerY + 6

    return @"
<svg width="$Size" height="$Size" viewBox="0 0 $Size $Size" style="display: block; margin: 0 auto;">
    <circle cx="$centerX" cy="$centerY" r="$radius" fill="none" stroke="#1f2937" stroke-width="8"/>
    <circle cx="$centerX" cy="$centerY" r="$radius" fill="none" stroke="$color" stroke-width="8" 
            stroke-dasharray="$circumference" stroke-dashoffset="$offset" 
            stroke-linecap="round" transform="rotate(-90 $centerX $centerY)"/>
    <text x="$centerX" y="$textY" text-anchor="middle" font-size="18" font-weight="700" fill="$color">$Score%</text>
</svg>
"@
}
#endregion

#region New-NavItemsHtml
function New-NavItemsHtml {
    param([object[]]$Results)

    if (-not $Results -or @($Results).Count -eq 0) {
        return ''
    }

    $navItems = New-Object 'System.Collections.Generic.List[string]'
    [void]$navItems.Add("<a class=`"sidebar-item active`" href=`"#section-summary`" onclick=`"scrollToSection('section-summary', this); return false;`">Executive Summary</a>")
    [void]$navItems.Add("<a class=`"sidebar-item`" href=`"#section-categories`" onclick=`"scrollToSection('section-categories', this); return false;`">Category Scorecards</a>")
    $categories = $Results | Group-Object -Property Category | Sort-Object @{ Expression = { if ($_.Name -eq 'Global ATP Settings') { 1 } else { 0 } } }, Name
    foreach ($group in $categories) {
        $categorySlug = ConvertTo-Slug -Text $group.Name
        $sectionId = "section-$categorySlug"
        $categoryName = HtmlEncode -Text $group.Name
        [void]$navItems.Add("<a class=`"sidebar-item`" href=`"#$sectionId`" onclick=`"scrollToSection('$sectionId', this); return false;`">$categoryName</a>")
    }
    [void]$navItems.Add("<a class=`"sidebar-item`" href=`"#section-additional-security-checks`" onclick=`"scrollToSection('section-additional-security-checks', this); return false;`">Additional Security Checks</a>")

    return ($navItems -join [Environment]::NewLine)
}
#endregion

#region New-CategoryCardHtml
function New-CategoryCardHtml {
    param(
        [string]$Category,
        [int]$StandardCompliant,
        [int]$StandardNonCompliant,
        [int]$StrictCompliant,
        [int]$StrictNonCompliant
    )

    $standardTotal = $StandardCompliant + $StandardNonCompliant
    $standardScore = if ($standardTotal -gt 0) { [math]::Round(($StandardCompliant / $standardTotal) * 100, 0) } else { 0 }
    $strictTotal = $StrictCompliant + $StrictNonCompliant
    $strictScore = if ($strictTotal -gt 0) { [math]::Round(($StrictCompliant / $strictTotal) * 100, 0) } else { 0 }
    $standardSvg = New-ScoreRingSvg -Score $standardScore -Size 70
    $strictSvg = New-ScoreRingSvg -Score $strictScore -Size 70

    return @"
<div class="category-card">
    <div class="category-card-title">$(HtmlEncode -Text $Category)</div>
    <div class="category-card-charts">
        <div class="category-chart-group">
            <div class="category-chart-label">Standard</div>
            $standardSvg
            <div class="category-chart-detail">$StandardCompliant / $standardTotal matched</div>
        </div>
        <div class="category-chart-group">
            <div class="category-chart-label">Strict</div>
            $strictSvg
            <div class="category-chart-detail">$StrictCompliant / $strictTotal matched</div>
        </div>
    </div>
</div>
"@
}
#endregion

#region New-AdditionalFindingsSectionHtml
function New-AdditionalFindingsSectionHtml {
    param([object[]]$AdditionalFindings)

    $categoryReferenceMap = @{
        'Quarantine Policies'        = 'https://learn.microsoft.com/defender-office-365/quarantine-policies'
        'Rule Coverage'              = 'https://learn.microsoft.com/defender-office-365/preset-security-policies'
        'Preset Security Policies'   = 'https://learn.microsoft.com/defender-office-365/preset-security-policies'
        'Policy Priority'            = 'https://learn.microsoft.com/defender-office-365/preset-security-policies#order-of-precedence-for-preset-security-policies-and-other-policies'
        'Email Authentication'       = 'https://learn.microsoft.com/defender-office-365/email-authentication-about'
        'Transport Rules'            = 'https://learn.microsoft.com/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules'
        'Inbound Connectors'         = 'https://learn.microsoft.com/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/use-connectors-to-configure-mail-flow'
        'Impersonation Protection'   = 'https://learn.microsoft.com/defender-office-365/anti-phishing-policies-about#impersonation-settings-in-anti-phishing-policies-in-microsoft-defender-for-office-365'
        'Tenant Allow/Block List'    = 'https://learn.microsoft.com/defender-office-365/tenant-allow-block-list-about'
        'Advanced Delivery'          = 'https://learn.microsoft.com/defender-office-365/advanced-delivery-policy-configure'
        'Audit Logging'              = 'https://learn.microsoft.com/purview/audit-log-enable-disable'
        'ATP Coverage'               = 'https://learn.microsoft.com/defender-office-365/safe-links-about'
        'Zero-Hour Auto Purge'       = 'https://learn.microsoft.com/defender-office-365/zero-hour-auto-purge'
        'Outbound Spam Notifications' = 'https://learn.microsoft.com/defender-office-365/outbound-spam-policies-configure'
    }

    $passCount = @($AdditionalFindings | Where-Object { $_.Status -eq 'Pass' }).Count
    $warningCount = @($AdditionalFindings | Where-Object { $_.Status -eq 'Warning' }).Count
    $criticalCount = @($AdditionalFindings | Where-Object { $_.Status -eq 'Critical' }).Count

    if (-not $AdditionalFindings -or @($AdditionalFindings).Count -eq 0) {
        return @"
<section class="panel section-card detail-section" id="section-additional-security-checks" data-section="additional-security-checks">
    <div class="section-header">
        <div>
            <h2>Additional Security Checks</h2>
            <p>These findings look beyond baseline comparison and focus on operational coverage, policy health, and bypass risks.</p>
        </div>
    </div>
    <div class="notice success">No additional security findings were produced.</div>
</section>
"@
    }

    $rows = foreach ($finding in $AdditionalFindings) {
        $refUrl = $categoryReferenceMap[$finding.Category]
        $refCell = if ($refUrl) { '<a href="{0}" target="_blank" rel="noopener noreferrer">Microsoft Docs</a>' -f $refUrl } else { '-' }
        @"
<tr>
    <td>$(HtmlEncode -Text $finding.Category)</td>
    <td>$(HtmlEncode -Text $finding.CheckName)</td>
    <td>$(New-StatusBadgeHtml -Status $finding.Status)</td>
    <td>$(HtmlEncode -Text $finding.Details)</td>
    <td>$(HtmlEncode -Text $finding.Recommendation)</td>
    <td>$refCell</td>
</tr>
"@
    }

    return @"
<section class="panel section-card detail-section" id="section-additional-security-checks" data-section="additional-security-checks">
    <div class="section-header">
        <div>
            <h2>Additional Security Checks</h2>
            <p>These findings go beyond the Microsoft baseline and highlight coverage gaps, bypass opportunities, and tenant-wide protection risks.</p>
        </div>
        <button type="button" class="export-btn" onclick="exportSectionToCsv('section-additional-security-checks')">&#128196; Export to Excel</button>
    </div>
    <div class="detail-meta">
        <span class="pill success">Pass: $passCount</span>
        <span class="pill warning">Warning: $warningCount</span>
        <span class="pill danger">Critical: $criticalCount</span>
    </div>
    <div class="findings-table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Check Name</th>
                    <th>Status</th>
                    <th>Details</th>
                    <th>Recommendation</th>
                    <th>Reference</th>
                </tr>
            </thead>
            <tbody>
                $(($rows -join [Environment]::NewLine))
            </tbody>
        </table>
    </div>
</section>
"@
}
#endregion

#region New-DetailSectionsHtml
function New-DetailSectionsHtml {
    param([object[]]$Results)

    if (-not $Results -or @($Results).Count -eq 0) {
        return '<section class="detail-section" id="section-no-data"><h2>No assessment data was produced.</h2></section>'
    }

    $sections = foreach ($group in ($Results | Group-Object -Property Category | Sort-Object @{ Expression = { if ($_.Name -eq 'Global ATP Settings') { 1 } else { 0 } } }, Name)) {
        $categorySlug = ConvertTo-Slug -Text $group.Name
        $sectionId = "section-$categorySlug"

        $policyBlocks = foreach ($policyGroup in ($group.Group | Group-Object -Property PolicyName | Sort-Object Name)) {
            $policySlug = ConvertTo-Slug -Text $policyGroup.Name
            $policyId = "$sectionId-$policySlug"
            $matchedCount = @($policyGroup.Group | Where-Object { $_.StandardStatus -eq 'Matched' }).Count
            $strictMatchedCount = @($policyGroup.Group | Where-Object { $_.StrictStatus -eq 'Matched' }).Count
            $totalCount = @($policyGroup.Group).Count
            $policyStatus = ($policyGroup.Group | Select-Object -First 1).PolicyStatus
            $policyPriority = ($policyGroup.Group | Select-Object -First 1).PolicyPriority
            $policyRows = foreach ($item in $policyGroup.Group) {
                $settingDisplay = if ($item.FeatureName) {
                    "$(HtmlEncode -Text $item.FeatureName)<br><span class=`"setting-param`">($(HtmlEncode -Text $item.SettingName))</span>"
                } else {
                    HtmlEncode -Text $item.SettingName
                }
                @"
<tr>
    <td>$settingDisplay</td>
    <td>$(HtmlEncode -Text $item.CurrentValue)</td>
    <td>$(HtmlEncode -Text $item.RecommendedStandardValue)</td>
    <td>$(New-StatusBadgeHtml -Status $item.StandardStatus)</td>
    <td>$(HtmlEncode -Text $item.RecommendedStrictValue)</td>
    <td>$(New-StatusBadgeHtml -Status $item.StrictStatus)</td>
    <td><a href="$(ConvertTo-SafeUrl -Url $item.ReferenceUrl)" target="_blank" rel="noopener noreferrer">Microsoft Learn</a></td>
</tr>
"@
            }
            @"
<div class="policy-collapsible collapsed" id="$policyId">
    <div class="policy-header" onclick="togglePolicy('$policyId')">
        <span class="policy-toggle-icon">&#9660;</span>
        <span class="policy-title">$(HtmlEncode -Text $policyGroup.Name)</span>
        $(New-PolicyStatusBadgeHtml -Status $policyStatus)
        $(New-PolicyPriorityBadgeHtml -Priority $policyPriority)
        <span class="pill info">Standard: $matchedCount / $totalCount</span>
        <span class="pill info">Strict: $strictMatchedCount / $totalCount</span>
    </div>
    <div class="policy-content">
        <div class="findings-table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Setting Name</th>
                    <th>Current Value</th>
                    <th>Recommended Standard Value</th>
                    <th>Standard Status</th>
                    <th>Recommended Strict Value</th>
                    <th>Strict Status</th>
                    <th>Reference</th>
                </tr>
            </thead>
            <tbody>
                $(($policyRows -join [Environment]::NewLine))
            </tbody>
        </table>
        </div>
    </div>
</div>
"@
        }

        @"
<section class="detail-section" id="$sectionId" data-section="$categorySlug">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <h2>$(HtmlEncode -Text $group.Name)</h2>
        <button type="button" class="export-btn" onclick="exportSectionToCsv('$sectionId')">&#128196; Export to Excel</button>
    </div>
    <div class="detail-meta">
        <span class="pill success">&#10004; Matched = baseline met</span>
        <span class="pill danger">&#10060; Not Matched = remediation advised</span>
    </div>
    $(($policyBlocks -join [Environment]::NewLine))
</section>
"@
    }

    return ($sections -join [Environment]::NewLine)
}
#endregion

#region Get-TenantDisplayName
function Get-TenantDisplayName {
    try {
        if (Get-Command -Name Get-OrganizationConfig -ErrorAction SilentlyContinue) {
            $organization = Get-OrganizationConfig -ErrorAction Stop
            foreach ($propertyName in 'DisplayName', 'Name', 'Identity') {
                $value = Get-PropertyValue -InputObject $organization -Name $propertyName
                if ($value) {
                    return [string]$value
                }
            }
        }
    }
    catch {
        Add-ExecutionIssue -Category 'Reporting' -Stage 'TenantLookup' -Message ('Unable to resolve tenant display name automatically: {0}' -f $_.Exception.Message) -Severity 'Info'
    }

    if ($AdminUPN) {
        return $AdminUPN
    }

    return 'Current Tenant'
}
#endregion

#region Get-DefaultReportTemplate
function Get-DefaultReportTemplate {
    if ($script:CachedReportTemplate) { return $script:CachedReportTemplate }
    $script:CachedReportTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{{TENANT_NAME}} - MDO Assessment Report</title>
    <style>
        :root {
            --ms-blue: #0f6cbd;
            --ms-blue-dark: #0b3b69;
            --header-dark: #111827;
            --surface: #ffffff;
            --surface-alt: #f5f7fb;
            --surface-muted: #eef2f7;
            --border: #dbe2ea;
            --text: #1f2937;
            --text-muted: #5f6a7d;
            --success: #107c10;
            --danger: #d13438;
            --warning: #ff8c00;
            --shadow: 0 12px 32px rgba(15, 23, 42, 0.08);
            --radius: 18px;
            --ring-score: {{OVERALL_SCORE}};
            --sidebar-bg: #ffffff;
            --sidebar-border: #e7edf3;
            --sidebar-border-soft: #eef2f6;
            --sidebar-text: #475467;
            --sidebar-text-strong: #111827;
            --sidebar-muted: #98a2b3;
            --sidebar-hover: #f1f5f9;
            --sidebar-active-bg: #eef6ff;
            --sidebar-indicator: var(--ms-blue);
            --sidebar-shadow: 0 18px 40px rgba(15, 23, 42, 0.06);
        }

        * { box-sizing: border-box; }

        html {
            scroll-behavior: smooth;
            background: #e8edf4;
        }

        body {
            margin: 0;
            font-family: "Inter", "Segoe UI Variable", "Segoe UI", Arial, Helvetica, sans-serif;
            color: var(--text);
            background:
                radial-gradient(circle at top right, rgba(15, 108, 189, 0.12), transparent 26%),
                linear-gradient(180deg, #eef3f9 0%, #f7f9fc 240px, #eef2f7 100%);
        }

        a {
            color: var(--ms-blue);
            text-decoration: none;
        }

        a:hover,
        a:focus {
            text-decoration: underline;
        }

        code {
            padding: 2px 6px;
            border-radius: 6px;
            background: rgba(15, 108, 189, 0.08);
            color: var(--ms-blue-dark);
            font-family: Consolas, "Courier New", monospace;
            font-size: 0.95em;
        }

        .muted {
            color: var(--text-muted);
        }

        .topbar {
            background: linear-gradient(135deg, #0b1220 0%, #15233b 52%, #0f6cbd 140%);
            color: #ffffff;
            padding: 22px 0;
            box-shadow: 0 12px 28px rgba(11, 18, 32, 0.28);
        }

        .topbar-inner {
            width: min(1440px, calc(100% - 40px));
            margin: 0 auto;
        }

        .brand-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .brand-mark {
            display: grid;
            grid-template-columns: repeat(2, 14px);
            gap: 4px;
            padding: 6px;
            border-radius: 10px;
            background: rgba(255, 255, 255, 0.08);
        }

        .brand-mark span {
            display: block;
            width: 14px;
            height: 14px;
            border-radius: 3px;
        }

        .brand-mark span:nth-child(1) { background: #f25022; }
        .brand-mark span:nth-child(2) { background: #7fba00; }
        .brand-mark span:nth-child(3) { background: #00a4ef; }
        .brand-mark span:nth-child(4) { background: #ffb900; }

        .eyebrow {
            margin: 0 0 6px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            font-size: 12px;
            font-weight: 700;
            color: rgba(255, 255, 255, 0.72);
        }

        .topbar h1 {
            margin: 0;
            font-size: clamp(28px, 4vw, 42px);
            font-weight: 700;
        }

        .topbar p {
            margin: 6px 0 0;
            color: rgba(255, 255, 255, 0.82);
            font-size: 15px;
        }

        .meta-chip {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 14px;
            border: 1px solid rgba(255, 255, 255, 0.16);
            border-radius: 999px;
            background: rgba(255, 255, 255, 0.08);
            font-size: 13px;
            white-space: nowrap;
        }

        .page {
            margin-left: 296px;
            padding: 28px 20px 36px;
        }

        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: 272px;
            height: 100vh;
            background: var(--sidebar-bg);
            z-index: 1000;
            border-right: 1px solid var(--sidebar-border);
            display: flex;
            flex-direction: column;
            overflow: hidden;
            transition: transform 0.3s ease;
            box-shadow: var(--sidebar-shadow);
        }

        .sidebar .panel {
            padding: 0;
            background: transparent;
            border: none;
            border-radius: 0;
            box-shadow: none;
            backdrop-filter: none;
            flex: 1;
            display: flex;
            flex-direction: column;
            min-height: 0;
        }

        .sidebar-shell {
            min-height: 100%;
            display: flex;
            flex-direction: column;
        }

        .sidebar-header {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 20px 20px 16px;
            border-bottom: 1px solid var(--sidebar-border-soft);
        }

        .sidebar-logo {
            display: flex;
            align-items: center;
            gap: 12px;
            color: inherit;
            text-decoration: none;
            min-width: 0;
        }

        .sidebar-logo:hover,
        .sidebar-logo:focus {
            text-decoration: none;
        }

        .sidebar-logo .brand-mark {
            grid-template-columns: repeat(2, 10px);
            gap: 3px;
            padding: 5px;
            border-radius: 8px;
            background: #f8fafc;
            border: 1px solid var(--sidebar-border-soft);
            flex-shrink: 0;
        }

        .sidebar-logo .brand-mark span {
            width: 10px;
            height: 10px;
            border-radius: 2px;
        }

        .sidebar-brand-copy {
            min-width: 0;
        }

        .sidebar-brand-kicker {
            margin: 0 0 2px;
            font-size: 11px;
            line-height: 1.2;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            font-weight: 700;
            color: var(--sidebar-muted);
        }

        .sidebar-brand-name {
            margin: 0;
            font-size: 17px;
            line-height: 1.2;
            font-weight: 700;
            letter-spacing: -0.02em;
            color: var(--sidebar-text-strong);
        }

        .sidebar-brand-subtitle {
            margin: 3px 0 0;
            font-size: 12px;
            color: var(--text-muted);
        }

        .sidebar-body {
            flex: 1;
            min-height: 0;
            display: flex;
            flex-direction: column;
            gap: 18px;
            padding: 14px 12px 18px;
        }

        .sidebar-nav-wrap {
            flex: 1;
            min-height: 0;
            display: flex;
            flex-direction: column;
        }

        .sidebar-section-title {
            padding: 0 12px;
            margin: 0 0 10px;
            font-size: 11px;
            font-weight: 700;
            color: var(--sidebar-muted);
            text-transform: uppercase;
            letter-spacing: 0.16em;
        }

        .sidebar-menu {
            flex: 1;
            min-height: 0;
            overflow-y: auto;
            padding-right: 4px;
            scrollbar-width: none;
            -ms-overflow-style: none;
        }

        .sidebar-menu::-webkit-scrollbar,
        .sidebar::-webkit-scrollbar {
            width: 0;
            height: 0;
        }

        .sidebar-toggle {
            display: none;
            position: fixed;
            top: 16px;
            left: 16px;
            z-index: 1001;
            background: #ffffff;
            color: var(--sidebar-text-strong);
            border: 1px solid var(--sidebar-border);
            border-radius: 10px;
            padding: 10px 14px;
            font-size: 20px;
            cursor: pointer;
            box-shadow: 0 10px 24px rgba(15, 23, 42, 0.12);
            transition: background 0.15s ease, color 0.15s ease, border-color 0.15s ease;
        }

        .sidebar-toggle:hover,
        .sidebar-toggle:focus {
            background: var(--sidebar-hover);
            color: var(--ms-blue);
            border-color: rgba(15, 108, 189, 0.2);
            outline: none;
        }

        .sidebar-overlay {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(15, 23, 42, 0.32);
            z-index: 999;
            backdrop-filter: blur(2px);
        }

        .panel {
            background: rgba(255, 255, 255, 0.92);
            border: 1px solid rgba(219, 226, 234, 0.88);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            backdrop-filter: blur(10px);
            overflow: hidden;
        }

        .disclaimer {
            background: #fff8ed;
            border: 1px solid #f6d9a8;
            border-left: 5px solid var(--warning);
            border-radius: 14px;
            padding: 18px 22px;
            margin-bottom: 22px;
            color: #5c4a24;
            box-shadow: var(--shadow);
        }

        .disclaimer .disclaimer-title {
            display: flex;
            align-items: center;
            gap: 8px;
            font-weight: 700;
            font-size: 15px;
            color: #8a5a00;
            margin: 0 0 8px;
        }

        .disclaimer p {
            margin: 0 0 10px;
            font-size: 14px;
            line-height: 1.6;
        }

        .disclaimer p:last-child {
            margin-bottom: 0;
        }

        .disclaimer a {
            font-weight: 600;
        }

        .content h2 {
            margin: 0 0 16px;
            font-size: 20px;
        }

        .sidebar-nav {
            display: flex;
            flex-direction: column;
            gap: 6px;
            flex: 1;
        }

        .sidebar-nav button,
        .sidebar-nav a,
        .sidebar-nav .sidebar-item,
        .sidebar-nav summary {
            width: 100%;
            border: none;
            background-color: transparent;
            color: var(--sidebar-text);
            padding: 11px 14px;
            border-radius: 10px;
            text-align: left;
            font: inherit;
            font-size: 13.5px;
            font-weight: 500;
            line-height: 1.4;
            cursor: pointer;
            transition: background-color 0.15s ease, color 0.15s ease, transform 0.15s ease;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 10px;
            position: relative;
            min-height: 42px;
        }

        .sidebar-nav button::before,
        .sidebar-nav a::before,
        .sidebar-nav .sidebar-item::before,
        .sidebar-nav summary::before {
            content: "";
            position: absolute;
            left: -12px;
            top: 8px;
            bottom: 8px;
            width: 4px;
            border-radius: 0 999px 999px 0;
            background: var(--sidebar-indicator);
            opacity: 0;
            transform: scaleY(0.65);
            transition: opacity 0.15s ease, transform 0.15s ease;
        }

        .sidebar-nav button:hover,
        .sidebar-nav button:focus,
        .sidebar-nav a:hover,
        .sidebar-nav a:focus,
        .sidebar-nav .sidebar-item:hover,
        .sidebar-nav .sidebar-item:focus,
        .sidebar-nav summary:hover,
        .sidebar-nav summary:focus {
            background-color: var(--sidebar-hover);
            color: var(--ms-blue);
            outline: none;
            text-decoration: none;
        }

        .sidebar-nav button.active,
        .sidebar-nav a.active,
        .sidebar-nav .sidebar-item.active,
        .sidebar-nav details[open] > summary {
            color: var(--ms-blue);
            background-color: var(--sidebar-active-bg);
            font-weight: 600;
        }

        .sidebar-nav button.active::before,
        .sidebar-nav a.active::before,
        .sidebar-nav .sidebar-item.active::before,
        .sidebar-nav details[open] > summary::before {
            opacity: 1;
            transform: scaleY(1);
        }

        .sidebar-nav details {
            display: grid;
            gap: 6px;
        }

        .sidebar-nav details > summary {
            list-style: none;
            padding-right: 36px;
        }

        .sidebar-nav details > summary::-webkit-details-marker {
            display: none;
        }

        .sidebar-nav details > summary::after {
            content: "\203A";
            position: absolute;
            right: 14px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--sidebar-muted);
            font-size: 16px;
            font-weight: 700;
            transition: transform 0.15s ease, color 0.15s ease;
        }

        .sidebar-nav details[open] > summary::after {
            transform: translateY(-50%) rotate(90deg);
            color: var(--ms-blue);
        }

        .sidebar-nav details > *:not(summary) {
            margin-left: 12px;
        }

        .sidebar-nav .sidebar-icon {
            width: 14px;
            text-align: center;
            color: var(--sidebar-muted);
            font-size: 13px;
            flex-shrink: 0;
        }

        .sidebar-nav .active .sidebar-icon,
        .sidebar-nav button:hover .sidebar-icon,
        .sidebar-nav a:hover .sidebar-icon,
        .sidebar-nav summary:hover .sidebar-icon {
            color: var(--ms-blue);
        }

        .sidebar-footer {
            margin-top: auto;
            padding-top: 4px;
        }

        .sidebar-note {
            display: grid;
            gap: 10px;
            padding: 16px;
            border-radius: 16px;
            background: linear-gradient(180deg, #f8fbff 0%, #f4f7fb 100%);
            border: 1px solid var(--sidebar-border);
            color: var(--text-muted);
            font-size: 13px;
            line-height: 1.6;
            box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.7);
        }

        .sidebar-note-label {
            margin: 0;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.14em;
            color: var(--sidebar-muted);
        }

        .sidebar-note-text {
            margin: 0;
        }

        .sidebar-note-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            font-size: 11px;
            font-weight: 600;
            color: var(--sidebar-text);
        }

        .sidebar-note-meta span {
            display: inline-flex;
            align-items: center;
            padding: 5px 9px;
            border-radius: 999px;
            background: rgba(255, 255, 255, 0.85);
            border: 1px solid var(--sidebar-border-soft);
        }

        .content {
            display: flex;
            flex-direction: column;
            gap: 24px;
            width: 100%;
            max-width: 100%;
            min-width: 0;
        }

        .hero {
            padding: 28px;
        }

        .hero-grid {
            display: grid;
            grid-template-columns: minmax(260px, 340px) minmax(0, 1fr);
            gap: 28px;
            align-items: center;
        }

        .score-tile {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 260px;
            border-radius: 24px;
            background: linear-gradient(180deg, #ffffff 0%, #f5f8fc 100%);
            border: 1px solid var(--border);
        }

        .score-ring {
            --score: var(--ring-score);
            width: 176px;
            height: 176px;
            position: relative;
        }

        .score-ring svg {
            width: 100%;
            height: 100%;
        }

        .score-ring-bg {
            fill: none;
            stroke: #dbe5f0;
            stroke-width: 16;
        }

        .score-ring-fill {
            fill: none;
            stroke: var(--ms-blue);
            stroke-width: 16;
            stroke-linecap: round;
            transform: rotate(-90deg);
            transform-origin: center;
        }

        .score-ring-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }

        .score-ring-text strong {
            font-size: 42px;
            line-height: 1;
            display: block;
        }

        .score-ring-text span {
            margin-top: 6px;
            font-size: 13px;
            color: var(--text-muted);
            letter-spacing: 0.02em;
            display: block;
        }

        .score-caption {
            margin-top: 16px;
            font-size: 15px;
            color: var(--text-muted);
        }

        .executive-summary-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-top: 20px;
        }

        .executive-panel {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 16px;
            padding: 24px;
            border-radius: 18px;
            background: #f8fafc;
            border: 1px solid var(--border);
        }

        .executive-panel.standard {
            border-color: var(--success);
        }

        .executive-panel.strict {
            border-color: var(--warning);
        }

        .executive-panel-title {
            font-size: 14px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--text-muted);
        }

        .executive-panel.standard .executive-panel-title {
            color: var(--success);
        }

        .executive-panel.strict .executive-panel-title {
            color: var(--warning);
        }

        .executive-panel .score-ring-fill.strict-fill {
            stroke: var(--warning);
        }

        .executive-stats {
            display: flex;
            gap: 16px;
        }

        .executive-center {
            text-align: center;
            margin-bottom: 8px;
        }

        .executive-center .value {
            font-size: 28px;
            font-weight: 700;
            display: block;
        }

        .executive-center .label {
            font-size: 13px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }

        .hero-copy h2 {
            margin: 0 0 10px;
            font-size: clamp(24px, 3vw, 34px);
        }

        .hero-copy p {
            margin: 0 0 20px;
            color: var(--text-muted);
            line-height: 1.65;
            font-size: 15px;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 14px;
        }

        .stat-card {
            padding: 18px;
            border-radius: 16px;
            background: #f8fafc;
            border: 1px solid var(--border);
        }

        .stat-card .label {
            display: block;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--text-muted);
            margin-bottom: 8px;
        }

        .stat-card .value {
            display: block;
            font-size: 30px;
            font-weight: 700;
        }

        .stat-card.success .value { color: var(--success); }
        .stat-card.danger .value { color: var(--danger); }
        .stat-card.warning .value { color: var(--warning); }
        .stat-card.info .value { color: var(--ms-blue); }

        .section-card {
            padding: 24px 26px;
            overflow: hidden;
        }

        .section-header {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 14px;
            margin-bottom: 18px;
        }

        .section-header p {
            margin: 8px 0 0;
            color: var(--text-muted);
            line-height: 1.6;
        }

        .legend {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 10px;
        }

        .legend-item,
        .pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            border-radius: 999px;
            font-size: 13px;
            font-weight: 600;
        }

        .legend-item::before,
        .pill::before {
            content: "";
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: currentColor;
        }

        .legend-item.success,
        .pill.success {
            color: var(--success);
            background: rgba(16, 124, 16, 0.1);
        }

        .legend-item.danger,
        .pill.danger {
            color: var(--danger);
            background: rgba(209, 52, 56, 0.1);
        }

        .legend-item.warning,
        .pill.warning {
            color: var(--warning);
            background: rgba(255, 140, 0, 0.12);
        }

        .pill.info {
            color: var(--ms-blue);
            background: rgba(15, 108, 189, 0.1);
        }

        .pill.priority {
            color: #b45309;
            background: rgba(251, 191, 36, 0.15);
            border: 1px solid #fbbf24;
        }

        .pill.policy-on { background: rgba(76, 175, 80, 0.15); color: #2e7d32; border: 1px solid #4caf50; }
        .pill.policy-always-on { background: rgba(15, 108, 189, 0.1); color: #0f6cbd; border: 1px solid #0f6cbd; }
        .pill.policy-off { background: rgba(239, 83, 80, 0.15); color: #c62828; border: 1px solid #ef5350; }
        .pill.policy-na { background: rgba(148, 163, 184, 0.15); color: #64748b; border: 1px solid #94a3b8; }

        .export-btn { background: rgba(15, 108, 189, 0.1); color: #0f6cbd; border: 1px solid #0f6cbd; border-radius: 8px; padding: 6px 14px; font-size: 12px; font-weight: 600; cursor: pointer; transition: background 0.2s, transform 0.1s; }
        .export-btn:hover { background: rgba(15, 108, 189, 0.2); transform: translateY(-1px); }
        .export-btn:active { transform: translateY(0); }

        .category-card-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 18px;
        }

        .category-card {
            display: flex;
            flex-direction: column;
            gap: 14px;
            padding: 20px;
            border-radius: 18px;
            border: 1px solid var(--border);
            background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
            box-shadow: 0 10px 26px rgba(15, 23, 42, 0.06);
        }

        .category-card .card-top {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
        }

        .category-card .icon {
            width: 44px;
            height: 44px;
            border-radius: 14px;
            display: grid;
            place-items: center;
            font-size: 22px;
            background: #eef5fc;
        }

        .category-card h3 {
            margin: 0;
            font-size: 18px;
        }

        .category-card .muted {
            color: var(--text-muted);
            font-size: 13px;
        }

        .mini-progress {
            height: 10px;
            border-radius: 999px;
            overflow: hidden;
            background: #dfe7f0;
        }

        .mini-progress span {
            display: block;
            height: 100%;
            border-radius: inherit;
            background: linear-gradient(90deg, var(--ms-blue-dark), var(--ms-blue));
        }

        .card-metrics {
            display: flex;
            justify-content: space-between;
            gap: 10px;
            color: var(--text-muted);
            font-size: 13px;
        }

        .category-card-charts {
            display: flex;
            gap: 16px;
            justify-content: center;
            margin-top: 8px;
        }

        .category-chart-group {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 4px;
        }

        .category-chart-label {
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
        }

        .category-chart-detail {
            font-size: 12px;
            color: var(--text-muted);
        }

        .detail-section {
            display: grid;
            gap: 18px;
            scroll-margin-top: 20px;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
            margin-top: 24px;
            overflow: hidden;
        }

        .detail-header {
            display: grid;
            grid-template-columns: minmax(0, 1fr) auto;
            gap: 14px;
            align-items: center;
        }

        .detail-header h3 {
            margin: 0;
            font-size: 24px;
        }

        .detail-header p {
            margin: 8px 0 0;
            color: var(--text-muted);
        }

        .detail-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .ghost-button,
        .toggle-button {
            appearance: none;
            border: 1px solid var(--border);
            background: #ffffff;
            color: var(--text);
            border-radius: 999px;
            padding: 10px 14px;
            font: inherit;
            font-weight: 600;
            cursor: pointer;
        }

        .detail-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }

        .policy-collapsible {
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-bottom: 12px;
            overflow: hidden;
        }

        .policy-header {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 14px 18px;
            cursor: pointer;
            background: #f4f8fc;
            transition: background 0.2s;
        }

        .policy-header:hover {
            background: #e8f0f8;
        }

        .policy-toggle-icon {
            font-size: 12px;
            transition: transform 0.2s;
            color: var(--text-muted);
        }

        .policy-collapsible.collapsed .policy-toggle-icon {
            transform: rotate(-90deg);
        }

        .policy-title {
            font-weight: 600;
            font-size: 15px;
            flex: 1;
        }

        .setting-param {
            font-size: 12px;
            color: var(--text-muted);
            font-family: 'Courier New', monospace;
        }

        .policy-content {
            padding: 12px 18px 18px;
        }

        .policy-collapsible.collapsed .policy-content {
            display: none;
        }

        .findings-table-wrap {
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
            border: 1px solid var(--border);
            border-radius: 18px;
            background: #ffffff;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 1100px;
        }

        thead {
            background: #edf4fb;
        }

        th,
        td {
            padding: 16px 18px;
            text-align: left;
            vertical-align: top;
            border-bottom: 1px solid #e7edf4;
            font-size: 14px;
            white-space: nowrap;
        }

        td:nth-child(2),
        td:nth-child(3),
        td:nth-child(4),
        td:nth-child(6) {
            white-space: normal;
            word-break: break-word;
        }

        th {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--text-muted);
        }

        tbody tr:hover {
            background: #fbfdff;
        }

        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
            padding: 4px 10px;
            border: 1px solid transparent;
            white-space: nowrap;
        }

        .status-badge.matched,
        .status-badge.status-matched,
        .status-badge.status-pass {
            background: rgba(76, 175, 80, 0.15);
            color: #4caf50;
            border-color: #4caf50;
        }

        .status-badge.not-matched,
        .status-badge.status-not-matched,
        .status-badge.status-critical {
            background: rgba(239, 83, 80, 0.15);
            color: #ef5350;
            border-color: #ef5350;
        }

        .status-badge.status-warning {
            background: rgba(255, 140, 0, 0.15);
            color: #ff8c00;
            border-color: #ff8c00;
        }

        .reference-link {
            font-weight: 600;
        }

        .footer {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 24px;
            text-align: center;
            margin-top: 40px;
            border-top: 4px solid #3498db;
        }

        .footer-inner {
            max-width: 1400px;
            margin: 0 auto;
        }

        .footer-title {
            font-size: 15px;
            font-weight: 600;
            margin-bottom: 8px;
        }

        .footer-date {
            font-size: 13px;
            color: #bdc3c7;
        }

        .footer-disclaimer {
            font-size: 12px;
            color: #95a5a6;
            margin-top: 12px;
            max-width: 920px;
            margin-left: auto;
            margin-right: auto;
            line-height: 1.6;
        }

        .collapsed .collapsible-content {
            display: none;
        }

        .collapsed .toggle-button::after {
            content: " Show";
        }

        .toggle-button::after {
            content: " Hide";
        }

        .sr-only {
            position: absolute;
            width: 1px;
            height: 1px;
            padding: 0;
            margin: -1px;
            overflow: hidden;
            clip: rect(0, 0, 0, 0);
            white-space: nowrap;
            border: 0;
        }

        @media (max-width: 1120px) {
            .sidebar {
                transform: translateX(-100%);
            }

            .sidebar.open {
                transform: translateX(0);
            }

            .sidebar-toggle {
                display: block;
            }

            .sidebar-overlay.open {
                display: block;
            }

            .page {
                margin-left: 0;
                padding: 28px 20px 36px;
            }

            .sidebar-nav {
                display: flex;
                flex-direction: column;
            }
        }

        @media (max-width: 820px) {
            .topbar-inner {
                width: min(100% - 24px, 1440px);
            }

            .page {
                padding: 16px 12px 36px;
            }

            .brand-row,
            .hero-grid,
            .detail-header {
                grid-template-columns: 1fr;
                display: grid;
            }

            .stats-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }

            .executive-summary-grid {
                grid-template-columns: 1fr;
            }

            .hero,
            .section-card {
                padding: 20px;
            }

            .sidebar-header {
                padding: 18px 18px 14px;
            }

            .sidebar-body {
                padding: 12px 10px 16px;
            }
        }

        @media (max-width: 560px) {
            .stats-grid {
                grid-template-columns: 1fr;
            }

            .score-ring {
                width: 148px;
                height: 148px;
            }

            .score-ring::before {
                inset: 14px;
            }

            .score-ring strong {
                font-size: 36px;
            }
        }

        @media print {
            :root {
                --shadow: none;
            }

            html,
            body {
                background: #ffffff !important;
            }

            .topbar {
                box-shadow: none;
                print-color-adjust: exact;
                -webkit-print-color-adjust: exact;
            }

            .sidebar,
            .sidebar-toggle,
            .sidebar-overlay {
                display: none !important;
            }

            .page {
                margin-left: 0 !important;
                padding-top: 20px;
                width: 100%;
            }

            .sidebar-nav button,
            .sidebar-nav a {
                border-color: #ccd5df;
                background: #ffffff !important;
                color: #111827 !important;
                box-shadow: none !important;
                background-image: none !important;
            }

            .sidebar-note,
            .ghost-button,
            .toggle-button {
                display: none !important;
            }

            .panel,
            .category-card,
            .findings-table-wrap,
            .score-tile,
            .stat-card {
                box-shadow: none !important;
                break-inside: avoid;
                page-break-inside: avoid;
            }

            .detail-section {
                display: grid !important;
                margin-top: 22px;
            }

            .detail-section + .detail-section {
                page-break-before: always;
            }

            .collapsible-content {
                display: block !important;
            }

            .footer {
                padding-bottom: 0;
            }

            a {
                color: inherit;
                text-decoration: none;
            }
        }
    </style>
</head>
<body>
    <button class="sidebar-toggle" onclick="toggleSidebar()">&#9776;</button>
    <div class="sidebar-overlay" id="sidebarOverlay" onclick="toggleSidebar()"></div>
    
    <aside class="sidebar" id="sidebar" aria-label="Category navigation">
        <div class="panel sidebar-shell">
            <div class="sidebar-header">
                <a class="sidebar-logo" href="#section-summary" onclick="scrollToSection('section-summary', null)">
                    <div class="brand-mark" aria-hidden="true">
                        <span></span><span></span><span></span><span></span>
                    </div>
                    <div class="sidebar-brand-copy">
                        <p class="sidebar-brand-kicker">Microsoft Defender</p>
                        <h2 class="sidebar-brand-name">MDO Analyzer</h2>
                        <p class="sidebar-brand-subtitle">Threat policy review</p>
                    </div>
                </a>
            </div>
            <div class="sidebar-body">
                <div class="sidebar-nav-wrap">
                    <div class="sidebar-section-title">Navigation</div>
                    <div class="sidebar-menu">
                        <nav class="sidebar-nav" id="categoryNav">
                            {{NAV_ITEMS}}
                        </nav>
                    </div>
                </div>
                <div class="sidebar-footer">
                    <div class="sidebar-note">
                        <p class="sidebar-note-label">Quick Tip</p>
                        <p class="sidebar-note-text">Use the menu to jump between policy categories and review findings, gaps, and remediation guidance in a single flow.</p>
                        <div class="sidebar-note-meta">
                            <span>Standalone HTML</span>
                            <span>{{GENERATION_DATE}}</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </aside>

    <header class="topbar">
        <div class="topbar-inner">
            <div class="brand-row">
                <div class="brand">
                    <div class="brand-mark" aria-hidden="true">
                        <span></span><span></span><span></span><span></span>
                    </div>
                    <div>
                        <p class="eyebrow">Microsoft Defender for Office 365</p>
                        <h1>MDO Threat Policy Analyzer</h1>
                        <p>{{TENANT_NAME}} &middot; Executive-ready compliance analysis</p>
                    </div>
                </div>
                <div class="meta-chip"><strong>Generated:</strong> <span>{{GENERATION_DATE}}</span></div>
            </div>
        </div>
    </header>

    <main class="page">
        <section class="content">
            <div class="disclaimer" role="note">
                <p class="disclaimer-title">&#9888; Important &mdash; Please read before acting on this report</p>
                <p>This report evaluates the tenant against Microsoft's recommended security baselines and presents recommendations at two levels defined by Microsoft: <strong>Standard</strong> and <strong>Strict</strong>. While these recommendations reflect Microsoft best practices, they may not align with every organization's policies, risk tolerance, or operational requirements.</p>
                <p>Before changing any settings based on these recommendations, review them with your security team and validate the impact in a test environment first. Do not apply a recommendation if it conflicts with your organization's policies or if your team follows a different, well-founded best practice.</p>
                <p>You can automatically apply the Standard or Strict configuration to users using preset security policies. For details, see <a href="https://learn.microsoft.com/defender-office-365/preset-security-policies" target="_blank" rel="noopener noreferrer">Preset security policies in Microsoft Defender for Office 365</a>.</p>
            </div>
            <section class="panel hero" id="section-summary">
                <h2>Executive Summary</h2>
                <p>This assessment compares the tenant's Microsoft Defender for Office 365 configuration against Microsoft's recommended cloud security baseline. Use the scorecard below to understand coverage, identify high-impact configuration gaps, and prioritize remediation activity.</p>
                <div class="executive-center">
                    <span class="value">{{TOTAL_SETTINGS}}</span>
                    <span class="label">Settings Assessed</span>
                </div>
                <div class="executive-summary-grid">
                    <div class="executive-panel standard">
                        <div class="executive-panel-title">Recommended Standard</div>
                        <div class="score-ring" aria-label="Standard compliance score">
                            <svg viewBox="0 0 176 176">
                                <circle cx="88" cy="88" r="70" class="score-ring-bg"/>
                                <circle cx="88" cy="88" r="70" class="score-ring-fill"
                                        stroke-dasharray="439.82"
                                        stroke-dashoffset="calc(439.82 * (1 - {{OVERALL_SCORE}} / 100))"/>
                            </svg>
                            <div class="score-ring-text">
                                <strong>{{OVERALL_SCORE}}%</strong>
                                <span>Compliance</span>
                            </div>
                        </div>
                        <div class="executive-stats">
                            <div class="stat-card success">
                                <span class="label">Matched</span>
                                <span class="value">{{COMPLIANT_COUNT}}</span>
                            </div>
                            <div class="stat-card danger">
                                <span class="label">Not Matched</span>
                                <span class="value">{{NON_COMPLIANT_COUNT}}</span>
                            </div>
                        </div>
                    </div>
                    <div class="executive-panel strict">
                        <div class="executive-panel-title">Recommended Strict</div>
                        <div class="score-ring" aria-label="Strict compliance score">
                            <svg viewBox="0 0 176 176">
                                <circle cx="88" cy="88" r="70" class="score-ring-bg"/>
                                <circle cx="88" cy="88" r="70" class="score-ring-fill strict-fill"
                                        stroke-dasharray="439.82"
                                        stroke-dashoffset="calc(439.82 * (1 - {{OVERALL_STRICT_SCORE}} / 100))"/>
                            </svg>
                            <div class="score-ring-text">
                                <strong>{{OVERALL_STRICT_SCORE}}%</strong>
                                <span>Compliance</span>
                            </div>
                        </div>
                        <div class="executive-stats">
                            <div class="stat-card success">
                                <span class="label">Matched</span>
                                <span class="value">{{STRICT_COMPLIANT_COUNT}}</span>
                            </div>
                            <div class="stat-card danger">
                                <span class="label">Not Matched</span>
                                <span class="value">{{STRICT_NONCOMPLIANT_COUNT}}</span>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <div style="text-align: right; margin-bottom: 16px;">
                <button type="button" class="export-btn" onclick="exportAllToExcel()">&#128196; Export All to Excel</button>
            </div>

            <section class="panel section-card" id="section-categories">
                <div class="section-header">
                    <div>
                        <h2>Category Scorecards</h2>
                        <p>Each card summarizes a control area, including its compliance trend and the number of controls meeting the recommended baseline.</p>
                    </div>
                    <div class="legend" aria-label="Status legend">
                        <span class="legend-item success">&#10004; Matched</span>
                        <span class="legend-item danger">&#10060; Not Matched</span>
                    </div>
                </div>
                <div class="category-card-grid" id="categoryCards">
                    {{CATEGORY_CARDS}}
                </div>
            </section>

            <section class="panel section-card" id="detailsPanel">
                <div class="section-header">
                    <div>
                        <h2>Detailed Findings</h2>
                        <p>Control-level evidence, recommended values, and reference links for remediation planning and executive review.</p>
                    </div>
                </div>
                <div id="detailSections">
                    {{DETAIL_SECTIONS}}
                </div>
            </section>

            {{ADDITIONAL_SECURITY_SECTION}}
        </section>
    </main>

    <footer class="footer">
        <div class="footer-inner">
            <div class="footer-title">MDO Threat Policy Analyzer</div>
            <div class="footer-date">Report generated at {{GENERATION_DATE}}</div>
            <div class="footer-disclaimer">This assessment reflects configuration state at the time of collection and should be reviewed alongside operational context, compensating controls, and Microsoft guidance before final risk decisions are made.</div>
        </div>
    </footer>

    <script>
        function exportSectionToCsv(sectionId) {
            var section = document.getElementById(sectionId);
            if (!section) return;
            var tables = section.querySelectorAll('table');
            if (tables.length === 0) return;
            var csvRows = [];
            var headerAdded = false;
            var includePolicyName = (sectionId !== 'section-additional-security-checks');
            var forceSkipReference = (sectionId === 'section-additional-security-checks');
            for (var t = 0; t < tables.length; t++) {
                var policyBlock = tables[t].closest('.policy-collapsible');
                var policyName = policyBlock ? (policyBlock.querySelector('.policy-title') || {}).innerText || '' : '';
                var headers = tables[t].querySelectorAll('th');
                var skipLast = forceSkipReference || (headers.length > 0 && headers[headers.length - 1].innerText.trim() === 'Reference');
                var rows = tables[t].querySelectorAll('tr');
                for (var i = 0; i < rows.length; i++) {
                    var cells = rows[i].querySelectorAll('th, td');
                    if (cells.length === 0) continue;
                    var colCount = skipLast ? cells.length - 1 : cells.length;
                    if (rows[i].querySelectorAll('th').length > 0) {
                        if (!headerAdded) {
                            var headerData = includePolicyName ? ['"Policy Name"'] : [];
                            for (var j = 0; j < colCount; j++) {
                                headerData.push('"' + cells[j].innerText.replace(/"/g, '""').trim() + '"');
                            }
                            csvRows.push(headerData.join(','));
                            headerAdded = true;
                        }
                        continue;
                    }
                    var rowData = includePolicyName ? ['"' + policyName.replace(/"/g, '""') + '"'] : [];
                    for (var j = 0; j < colCount; j++) {
                        var text = cells[j].innerText.replace(/"/g, '""').replace(/\n/g, ' ').trim();
                        rowData.push('"' + text + '"');
                    }
                    csvRows.push(rowData.join(','));
                }
            }
            if (csvRows.length === 0) return;
            var csvContent = '\uFEFF' + csvRows.join('\n');
            var blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            var link = document.createElement('a');
            var sectionTitle = section.querySelector('h2, h3') || { innerText: sectionId };
            var fileName = (sectionTitle.innerText || sectionId).replace(/[^a-z0-9]/gi, '_') + '.csv';
            link.href = URL.createObjectURL(blob);
            link.download = fileName;
            link.style.display = 'none';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
        function exportAllToExcel() {
            function cellText(el) {
                return (el && el.textContent ? el.textContent : '').replace(/\s+/g, ' ').trim();
            }
            function xmlEsc(s) {
                return String(s == null ? '' : s)
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;');
            }
            function textCell(v) {
                var s = String(v == null ? '' : v);
                if (s.length && '=+-@\t\r'.indexOf(s.charAt(0)) !== -1) { s = "'" + s; }
                return '<Cell><Data ss:Type="String">' + xmlEsc(s) + '</Data></Cell>';
            }
            function headerCell(v) {
                return '<Cell ss:StyleID="hdr"><Data ss:Type="String">' + xmlEsc(v) + '</Data></Cell>';
            }
            function linkCell(url, label) {
                url = (url || '').trim();
                if (!url) { return textCell(label || ''); }
                return '<Cell ss:StyleID="lnk" ss:HRef="' + xmlEsc(url) + '"><Data ss:Type="String">' + xmlEsc(label || url) + '</Data></Cell>';
            }
            function getRef(cell) {
                if (!cell) { return { url: '', label: '' }; }
                var a = cell.querySelector('a');
                if (a) { return { url: a.getAttribute('href') || '', label: cellText(a) || 'Reference' }; }
                return { url: '', label: cellText(cell) };
            }

            // Sheet 1: Detailed Findings (7 policy columns + Category + Policy Name)
            var detailRows = ['<Row>' +
                headerCell('Category') + headerCell('Policy Name') + headerCell('Setting Name') +
                headerCell('Current Value') + headerCell('Recommended Standard Value') + headerCell('Standard Status') +
                headerCell('Recommended Strict Value') + headerCell('Strict Status') + headerCell('Reference') + '</Row>'];
            var detailSections = document.querySelectorAll('.detail-section');
            for (var s = 0; s < detailSections.length; s++) {
                if (detailSections[s].id === 'section-additional-security-checks') { continue; }
                var sTitle = detailSections[s].querySelector('h2, h3');
                var sectionName = sTitle ? cellText(sTitle) : 'Unknown';
                var tables = detailSections[s].querySelectorAll('table');
                for (var t = 0; t < tables.length; t++) {
                    var policyBlock = tables[t].closest('.policy-collapsible');
                    var policyName = policyBlock ? cellText(policyBlock.querySelector('.policy-title')) : '';
                    var rows = tables[t].querySelectorAll('tbody tr');
                    for (var i = 0; i < rows.length; i++) {
                        var cells = rows[i].querySelectorAll('td');
                        if (cells.length === 0) { continue; }
                        var ref = getRef(cells[cells.length - 1]);
                        var rowXml = '<Row>' + textCell(sectionName) + textCell(policyName);
                        for (var j = 0; j < cells.length - 1; j++) { rowXml += textCell(cellText(cells[j])); }
                        rowXml += linkCell(ref.url, ref.label || 'Microsoft Learn') + '</Row>';
                        detailRows.push(rowXml);
                    }
                }
            }

            // Sheet 2: Additional Security Checks (dedicated columns + clickable Reference)
            var addlRows = ['<Row>' +
                headerCell('Category') + headerCell('Check Name') + headerCell('Status') +
                headerCell('Details') + headerCell('Recommendation') + headerCell('Reference') + '</Row>'];
            var addlSection = document.getElementById('section-additional-security-checks');
            if (addlSection) {
                var addlTables = addlSection.querySelectorAll('table');
                for (var at = 0; at < addlTables.length; at++) {
                    var arows = addlTables[at].querySelectorAll('tbody tr');
                    for (var k = 0; k < arows.length; k++) {
                        var acells = arows[k].querySelectorAll('td');
                        if (acells.length === 0) { continue; }
                        var aref = getRef(acells[acells.length - 1]);
                        var arowXml = '<Row>';
                        for (var m = 0; m < acells.length - 1; m++) { arowXml += textCell(cellText(acells[m])); }
                        arowXml += linkCell(aref.url, aref.label || 'Microsoft Docs') + '</Row>';
                        addlRows.push(arowXml);
                    }
                }
            }

            var workbook =
                '<?xml version="1.0"?>\r\n' +
                '<?mso-application progid="Excel.Sheet"?>\r\n' +
                '<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"' +
                ' xmlns:o="urn:schemas-microsoft-com:office:office"' +
                ' xmlns:x="urn:schemas-microsoft-com:office:excel"' +
                ' xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"' +
                ' xmlns:html="http://www.w3.org/TR/REC-html40">' +
                '<Styles>' +
                '<Style ss:ID="hdr"><Font ss:Bold="1"/><Interior ss:Color="#DDEBF7" ss:Pattern="Solid"/></Style>' +
                '<Style ss:ID="lnk"><Font ss:Color="#0563C1" ss:Underline="Single"/></Style>' +
                '</Styles>' +
                '<Worksheet ss:Name="Detailed Findings"><Table>' + detailRows.join('') + '</Table></Worksheet>' +
                '<Worksheet ss:Name="Additional Security Checks"><Table>' + addlRows.join('') + '</Table></Worksheet>' +
                '</Workbook>';

            var blob = new Blob([workbook], { type: 'application/vnd.ms-excel;charset=utf-8;' });
            var link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = 'MDO_Full_Report.xls';
            link.style.display = 'none';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
        function togglePolicy(policyId) {
            var el = document.getElementById(policyId);
            if (el) el.classList.toggle('collapsed');
        }

        function toggleSidebar() {
            document.getElementById('sidebar').classList.toggle('open');
            document.getElementById('sidebarOverlay').classList.toggle('open');
        }

        function scrollToSection(sectionId, el) {
            var target = document.getElementById(sectionId);
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
            var items = document.querySelectorAll('#categoryNav .sidebar-item');
            items.forEach(function(i) { i.classList.remove('active'); });
            if (el) el.classList.add('active');
            if (window.innerWidth <= 1120) toggleSidebar();
        }

        (function () {
            var sections = Array.prototype.slice.call(document.querySelectorAll('[id^="section-"]'));
            var observer = new IntersectionObserver(function(entries) {
                entries.forEach(function(entry) {
                    if (entry.isIntersecting) {
                        var id = entry.target.id;
                        var items = document.querySelectorAll('#categoryNav .sidebar-item');
                        items.forEach(function(i) { i.classList.remove('active'); });
                        var activeLink = document.querySelector('#categoryNav .sidebar-item[href="#' + id + '"]');
                        if (activeLink) activeLink.classList.add('active');
                    }
                });
            }, { threshold: 0.2 });
            sections.forEach(function(s) { observer.observe(s); });

            var cardButtons = Array.prototype.slice.call(document.querySelectorAll("[data-open-section]"));
            cardButtons.forEach(function(button) {
                button.addEventListener("click", function() {
                    var target = button.getAttribute("data-open-section");
                    var section = document.getElementById("section-" + target);
                    if (section) section.scrollIntoView({ behavior: "smooth", block: "start" });
                });
            });

            document.addEventListener("click", function(event) {
                var trigger = event.target.closest("[data-collapse-target]");
                if (!trigger) return;
                var targetId = trigger.getAttribute("data-collapse-target");
                if (!targetId) return;
                var section = document.getElementById(targetId);
                if (!section) return;
                var collapsed = section.classList.toggle("collapsed");
                trigger.setAttribute("aria-expanded", String(!collapsed));
            });
        }());
    </script>
</body>
</html>
'@
    return $script:CachedReportTemplate
}
#endregion

#region Apply-TemplateReplacements
function Apply-TemplateReplacements {
    param(
        [string]$TemplateContent,
        [hashtable]$Replacements
    )

    $output = $TemplateContent
    foreach ($key in $Replacements.Keys) {
        $value = [string]$Replacements[$key]
        $patterns = @(
            ('{{' + $key + '}}'),
            ('[[' + $key + ']]'),
            ('__' + $key + '__')
        )

        foreach ($pattern in $patterns) {
            $escapedPattern = [regex]::Escape($pattern)
            $regex = New-Object System.Text.RegularExpressions.Regex($escapedPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $output = $regex.Replace($output, [System.Text.RegularExpressions.MatchEvaluator]{ param($match) $value })
        }
    }

    return $output
}
#endregion

#region New-AssessmentReport
function New-AssessmentReport {
    param(
        [object[]]$Results,
        [object[]]$AdditionalFindings,
        [object[]]$Issues,
        [string]$TenantName = 'Current Tenant'
    )

    $generatedOn = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $compliantCount = @($Results | Where-Object { $_.StandardStatus -eq 'Matched' }).Count
    $nonCompliantCount = @($Results | Where-Object { $_.StandardStatus -eq 'NotMatched' }).Count
    $strictCompliantCount = @($Results | Where-Object { $_.StrictStatus -eq 'Matched' }).Count
    $strictNonCompliantCount = @($Results | Where-Object { $_.StrictStatus -eq 'NotMatched' }).Count
    $totalCount = @($Results).Count
    $overallScore = if ($totalCount -gt 0) { [math]::Round(($compliantCount / $totalCount) * 100, 0) } else { 0 }
    $overallStrictScore = if ($totalCount -gt 0) { [math]::Round(($strictCompliantCount / $totalCount) * 100, 0) } else { 0 }
    $detailSections = New-DetailSectionsHtml -Results $Results
    $additionalSecuritySection = New-AdditionalFindingsSectionHtml -AdditionalFindings $AdditionalFindings
    $navItems = New-NavItemsHtml -Results $Results

    $categoryCards = foreach ($group in ($Results | Group-Object -Property Category | Sort-Object @{ Expression = { if ($_.Name -eq 'Global ATP Settings') { 1 } else { 0 } } }, Name)) {
        $groupStandardCompliant = @($group.Group | Where-Object { $_.StandardStatus -eq 'Matched' }).Count
        $groupStandardNonCompliant = @($group.Group | Where-Object { $_.StandardStatus -eq 'NotMatched' }).Count
        $groupStrictCompliant = @($group.Group | Where-Object { $_.StrictStatus -eq 'Matched' }).Count
        $groupStrictNonCompliant = @($group.Group | Where-Object { $_.StrictStatus -eq 'NotMatched' }).Count
        New-CategoryCardHtml -Category $group.Name -StandardCompliant $groupStandardCompliant -StandardNonCompliant $groupStandardNonCompliant -StrictCompliant $groupStrictCompliant -StrictNonCompliant $groupStrictNonCompliant
    }

    # The report template is embedded in this script (see Get-DefaultReportTemplate),
    # so no external ReportTemplate.html file is required. This keeps the script standalone.
    Write-Log -Message 'Using built-in report template.' -Color Cyan
    $template = Get-DefaultReportTemplate

    $replacements = @{
        REPORT_TITLE = $script:ToolName
        TENANT_NAME = $TenantName
        GENERATED_ON = $generatedOn
        GENERATION_DATE = $generatedOn
        BASELINE_URL = $script:BaseReferenceUrl
        OVERALL_SCORE = $overallScore
        OVERALL_STRICT_SCORE = $overallStrictScore
        TOTAL_SETTINGS = $totalCount
        COMPLIANT_COUNT = $compliantCount
        NON_COMPLIANT_COUNT = $nonCompliantCount
        NONCOMPLIANT_COUNT = $nonCompliantCount
        STRICT_COMPLIANT_COUNT = $strictCompliantCount
        STRICT_NONCOMPLIANT_COUNT = $strictNonCompliantCount
        CATEGORY_CARDS = ($categoryCards -join [Environment]::NewLine)
        DETAIL_SECTIONS = $detailSections
        ADDITIONAL_SECURITY_SECTION = $additionalSecuritySection
        NAV_ITEMS = $navItems
    }

    return Apply-TemplateReplacements -TemplateContent $template -Replacements $replacements
}
#endregion

Ensure-OutputFolder
Write-Banner

$allData = [ordered]@{}
$results = New-Object 'System.Collections.Generic.List[object]'
$additionalFindings = New-Object 'System.Collections.Generic.List[object]'
$reportPath = $null

try {
    Write-Log -Message ('Output directory: {0}' -f $script:OutputRoot) -Color Cyan
    Ensure-ExchangeOnlineModule

    $authContext = Get-AuthenticationContext

    try {
        Connect-MdoServices -AuthContext $authContext
    }
    catch {
        $message = ('Authentication failed: {0}' -f $_.Exception.Message)
        Write-Log -Message $message -Level ERROR -Color Red
        Add-ExecutionIssue -Category 'Authentication' -Stage 'Connect' -Message $message -Severity 'Error'
        throw
    }

    $collectionPlan = @(
        @{ Key = 'AntiPhishPolicies'; Category = 'Anti-Phishing Policies'; Cmdlet = 'Get-AntiPhishPolicy'; Percent = 5; Script = { Get-AntiPhishPolicy -ErrorAction Stop } }
        @{ Key = 'AntiPhishRules'; Category = 'Anti-Phishing Rules'; Cmdlet = 'Get-AntiPhishRule'; Percent = 10; Script = { Get-AntiPhishRule -ErrorAction Stop } }
        @{ Key = 'InboundSpamPolicies'; Category = 'Inbound Anti-Spam Policies'; Cmdlet = 'Get-HostedContentFilterPolicy'; Percent = 15; Script = { Get-HostedContentFilterPolicy -ErrorAction Stop } }
        @{ Key = 'InboundSpamRules'; Category = 'Inbound Anti-Spam Rules'; Cmdlet = 'Get-HostedContentFilterRule'; Percent = 20; Script = { Get-HostedContentFilterRule -ErrorAction Stop } }
        @{ Key = 'OutboundSpamPolicies'; Category = 'Outbound Anti-Spam Policies'; Cmdlet = 'Get-HostedOutboundSpamFilterPolicy'; Percent = 25; Script = { Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop } }
        @{ Key = 'OutboundSpamRules'; Category = 'Outbound Anti-Spam Rules'; Cmdlet = 'Get-HostedOutboundSpamFilterRule'; Percent = 30; Script = { Get-HostedOutboundSpamFilterRule -ErrorAction Stop } }
        @{ Key = 'AntiMalwarePolicies'; Category = 'Anti-Malware Policies'; Cmdlet = 'Get-MalwareFilterPolicy'; Percent = 35; Script = { Get-MalwareFilterPolicy -ErrorAction Stop } }
        @{ Key = 'AntiMalwareRules'; Category = 'Anti-Malware Rules'; Cmdlet = 'Get-MalwareFilterRule'; Percent = 40; Script = { Get-MalwareFilterRule -ErrorAction Stop } }
        @{ Key = 'SafeAttachmentPolicies'; Category = 'Safe Attachments Policies'; Cmdlet = 'Get-SafeAttachmentPolicy'; Percent = 45; Script = { Get-SafeAttachmentPolicy -ErrorAction Stop } }
        @{ Key = 'SafeAttachmentRules'; Category = 'Safe Attachments Rules'; Cmdlet = 'Get-SafeAttachmentRule'; Percent = 50; Script = { Get-SafeAttachmentRule -ErrorAction Stop } }
        @{ Key = 'SafeLinkPolicies'; Category = 'Safe Links Policies'; Cmdlet = 'Get-SafeLinksPolicy'; Percent = 55; Script = { Get-SafeLinksPolicy -ErrorAction Stop } }
        @{ Key = 'SafeLinkRules'; Category = 'Safe Links Rules'; Cmdlet = 'Get-SafeLinksRule'; Percent = 60; Script = { Get-SafeLinksRule -ErrorAction Stop } }
        @{ Key = 'AtpGlobalSettings'; Category = 'Global ATP Settings'; Cmdlet = 'Get-AtpPolicyForO365'; Percent = 65; Script = { Get-AtpPolicyForO365 -ErrorAction Stop } }
        @{ Key = 'EmailTenantSettings'; Category = 'Email Tenant Settings'; Cmdlet = 'Get-EmailTenantSettings'; Percent = 70; Script = { Get-EmailTenantSettings -ErrorAction Stop } }
        @{ Key = 'QuarantinePolicies'; Category = 'Quarantine Policies'; Cmdlet = 'Get-QuarantinePolicy'; Percent = 75; Script = { Get-QuarantinePolicy -ErrorAction Stop } }
        @{ Key = 'EopProtectionPolicyRules'; Category = 'EOP Preset Policy Rules'; Cmdlet = 'Get-EOPProtectionPolicyRule'; Percent = 80; Script = { Get-EOPProtectionPolicyRule -ErrorAction Stop } }
        @{ Key = 'AtpProtectionPolicyRules'; Category = 'ATP Preset Policy Rules'; Cmdlet = 'Get-ATPProtectionPolicyRule'; Percent = 85; Script = { Get-ATPProtectionPolicyRule -ErrorAction Stop } }
        @{ Key = 'DkimSigningConfigs'; Category = 'DKIM Signing Configurations'; Cmdlet = 'Get-DkimSigningConfig'; Percent = 90; Script = { Get-DkimSigningConfig -ErrorAction Stop } }
        @{ Key = 'AcceptedDomains'; Category = 'Accepted Domains'; Cmdlet = 'Get-AcceptedDomain'; Percent = 94; Script = { Get-AcceptedDomain -ErrorAction Stop } }
        @{ Key = 'TransportRules'; Category = 'Transport Rules'; Cmdlet = 'Get-TransportRule'; Percent = 97; Script = { Get-TransportRule -ErrorAction Stop } }
        @{ Key = 'InboundConnectors'; Category = 'Inbound Connectors'; Cmdlet = 'Get-InboundConnector'; Percent = 100; Script = { Get-InboundConnector -ErrorAction Stop } }
    )

    foreach ($step in $collectionPlan) {
        $allData[$step.Key] = Invoke-CollectionCommand -Category $step.Category -CmdletName $step.Cmdlet -ScriptBlock $step.Script -PercentComplete $step.Percent
    }

    if ($script:IsInteractive -and -not $script:Quiet) {
        Write-Progress -Activity 'Collecting Microsoft Defender for Office 365 settings' -Completed
    }

    if (-not $SkipCsvExport) {
        Write-Log -Message 'Exporting collected settings to CSV.' -Color Yellow
    }

    Export-ObjectsToCsv -FileName 'AntiPhishPolicies.csv' -InputObject $allData.AntiPhishPolicies
    Export-ObjectsToCsv -FileName 'AntiPhishRules.csv' -InputObject $allData.AntiPhishRules
    Export-ObjectsToCsv -FileName 'AntiSpamInboundPolicies.csv' -InputObject $allData.InboundSpamPolicies
    Export-ObjectsToCsv -FileName 'AntiSpamInboundRules.csv' -InputObject $allData.InboundSpamRules
    Export-ObjectsToCsv -FileName 'AntiSpamOutboundPolicies.csv' -InputObject $allData.OutboundSpamPolicies
    Export-ObjectsToCsv -FileName 'AntiSpamOutboundRules.csv' -InputObject $allData.OutboundSpamRules
    Export-ObjectsToCsv -FileName 'AntiMalwarePolicies.csv' -InputObject $allData.AntiMalwarePolicies
    Export-ObjectsToCsv -FileName 'AntiMalwareRules.csv' -InputObject $allData.AntiMalwareRules
    Export-ObjectsToCsv -FileName 'SafeAttachmentsPolicies.csv' -InputObject $allData.SafeAttachmentPolicies
    Export-ObjectsToCsv -FileName 'SafeAttachmentsRules.csv' -InputObject $allData.SafeAttachmentRules
    Export-ObjectsToCsv -FileName 'SafeLinksPolicies.csv' -InputObject $allData.SafeLinkPolicies
    Export-ObjectsToCsv -FileName 'SafeLinksRules.csv' -InputObject $allData.SafeLinkRules
    Export-ObjectsToCsv -FileName 'AtpGlobal.csv' -InputObject $allData.AtpGlobalSettings
    Export-ObjectsToCsv -FileName 'EmailTenantSettings.csv' -InputObject $allData.EmailTenantSettings
    Export-ObjectsToCsv -FileName 'QuarantinePolicies.csv' -InputObject $allData.QuarantinePolicies
    Export-ObjectsToCsv -FileName 'EOPProtectionPolicyRules.csv' -InputObject $allData.EopProtectionPolicyRules
    Export-ObjectsToCsv -FileName 'ATPProtectionPolicyRules.csv' -InputObject $allData.AtpProtectionPolicyRules
    Export-ObjectsToCsv -FileName 'DkimSigningConfigs.csv' -InputObject $allData.DkimSigningConfigs
    Export-ObjectsToCsv -FileName 'AcceptedDomains.csv' -InputObject $allData.AcceptedDomains
    Export-ObjectsToCsv -FileName 'TransportRules.csv' -InputObject $allData.TransportRules
    Export-ObjectsToCsv -FileName 'InboundConnectors.csv' -InputObject $allData.InboundConnectors

    Write-Log -Message 'Comparing current settings to Microsoft recommended Standard and Strict baselines.' -Color Yellow
    Compare-AllPoliciesToBaseline -Results $results -CategoryKey 'AntiPhish' -Policies $allData.AntiPhishPolicies -Rules $allData.AntiPhishRules
    Compare-AllPoliciesToBaseline -Results $results -CategoryKey 'AntiSpamInbound' -Policies $allData.InboundSpamPolicies -Rules $allData.InboundSpamRules
    Compare-AllPoliciesToBaseline -Results $results -CategoryKey 'AntiSpamOutbound' -Policies $allData.OutboundSpamPolicies -Rules $allData.OutboundSpamRules
    Compare-AllPoliciesToBaseline -Results $results -CategoryKey 'AntiMalware' -Policies $allData.AntiMalwarePolicies -Rules $allData.AntiMalwareRules
    Compare-AllPoliciesToBaseline -Results $results -CategoryKey 'SafeAttachments' -Policies $allData.SafeAttachmentPolicies -Rules $allData.SafeAttachmentRules
    Compare-AllPoliciesToBaseline -Results $results -CategoryKey 'SafeLinks' -Policies $allData.SafeLinkPolicies -Rules $allData.SafeLinkRules
    Compare-AllPoliciesToBaseline -Results $results -CategoryKey 'AtpGlobal' -Policies $allData.AtpGlobalSettings

    if (@($allData.EmailTenantSettings).Count -gt 0) {
        Add-ExecutionIssue -Category 'Email Tenant Settings' -Stage 'Comparison' -Message 'Email tenant settings were exported for review, but no Microsoft Learn baseline mapping was defined in the requirements, so they were excluded from scoring.' -Severity 'Info'
    }
    else {
        Add-ExecutionIssue -Category 'Email Tenant Settings' -Stage 'Comparison' -Message 'Email tenant settings were unavailable and were excluded from scoring.'
    }

    Write-Log -Message 'Running additional security checks.' -Color Yellow
    Invoke-AdditionalSecurityChecks -Findings $additionalFindings -AllData $allData

    Export-ObjectsToCsv -FileName 'AssessmentResults.csv' -InputObject $results
    Export-ObjectsToCsv -FileName 'AdditionalSecurityFindings.csv' -InputObject $additionalFindings

    Write-Log -Message 'Generating HTML assessment report.' -Color Yellow
    $tenantName = Get-TenantDisplayName
    $reportHtml = New-AssessmentReport -Results $results -AdditionalFindings $additionalFindings -Issues $script:ExecutionIssues -TenantName $tenantName
    $reportPath = Join-Path -Path $script:OutputRoot -ChildPath ('MDOThreatPolicyAnalyzer-Report-{0}.html' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Set-Content -Path $reportPath -Value $reportHtml -Encoding (Get-Utf8EncodingName)
    Write-Log -Message ('Report created: {0}' -f $reportPath) -Level SUCCESS -Color Green

    if (-not $SkipBrowserOpen -and $script:IsInteractive) {
        try {
            Start-Process -FilePath $reportPath | Out-Null
            Write-Log -Message 'Opened report in the default browser.' -Level SUCCESS -Color Green
        }
        catch {
            $message = ('Unable to auto-open report: {0}' -f $_.Exception.Message)
            Write-Log -Message $message -Level WARN -Color DarkYellow
            Add-ExecutionIssue -Category 'Reporting' -Stage 'OpenReport' -Message $message
        }
    }

    $compliant = 0; $nonCompliant = 0; $strictCompliant = 0; $strictNonCompliant = 0
    foreach ($r in $results) {
        switch ($r.StandardStatus) {
            'Matched'    { $compliant++ }
            'NotMatched' { $nonCompliant++ }
        }
        switch ($r.StrictStatus) {
            'Matched'    { $strictCompliant++ }
            'NotMatched' { $strictNonCompliant++ }
        }
    }
    $additionalPass = 0; $additionalWarnings = 0; $additionalCritical = 0
    foreach ($f in $additionalFindings) {
        switch ($f.Status) {
            'Pass'     { $additionalPass++ }
            'Warning'  { $additionalWarnings++ }
            'Critical' { $additionalCritical++ }
        }
    }

    Write-Host ''
    Write-Host 'Assessment Summary' -ForegroundColor Cyan
    Write-Host '------------------' -ForegroundColor Cyan
    Write-Host ('Matched (Standard):       {0}' -f $compliant) -ForegroundColor Green
    Write-Host ('Not Matched (Standard):   {0}' -f $nonCompliant) -ForegroundColor Yellow
    Write-Host ('Matched (Strict):         {0}' -f $strictCompliant) -ForegroundColor Green
    Write-Host ('Not Matched (Strict):     {0}' -f $strictNonCompliant) -ForegroundColor Yellow
    Write-Host ('Additional Pass:          {0}' -f $additionalPass) -ForegroundColor Green
    Write-Host ('Additional Warnings:      {0}' -f $additionalWarnings) -ForegroundColor Yellow
    Write-Host ('Additional Critical:      {0}' -f $additionalCritical) -ForegroundColor Red
    Write-Host ('Report:                   {0}' -f $reportPath) -ForegroundColor White
}
catch {
    Write-Log -Message ('Fatal error: {0}' -f $_.Exception.Message) -Level ERROR -Color Red
    throw
}
finally {
    Disconnect-MdoServices
}

# SIG # Begin signature block
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUTQA7oFunWG2UCoAhcmfg4m+1
# 6G+gggNKMIIDRjCCAi6gAwIBAgIQQ6HqgjDvOohK4mxwPhpDZDANBgkqhkiG9w0B
# AQsFADA7MTkwNwYDVQQDDDBBYmR1bGxhaFptYWlsaUNvZGVTaWduaW5nTURPVGhy
# ZWF0UG9saWN5QW5hbHl6ZXIwHhcNMjYwNTAzMTAwNjE1WhcNMjcwNTAzMTAyNjE1
# WjA7MTkwNwYDVQQDDDBBYmR1bGxhaFptYWlsaUNvZGVTaWduaW5nTURPVGhyZWF0
# UG9saWN5QW5hbHl6ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDa
# +U7E/MWIQP58JDEltKj8RA7QDajAsLuaGU+q0ysjeJoog5ybGV9j0nn8orZzbWgE
# R++tsG8675VLee9Nai5X06W0ZgSDl4vaTcYJkSthNTrZ2aAv4wrp+4Cly8tbXQ3c
# y4ZEWfiWfBTKXTn6akeOVBpx8Zq2wLGMr2yNh4cdxY1KwDRkPWDV8LxBR266/gyv
# 4eRpyeLGKlhuLxjS7uk04wXmjVyHMl+JQa4hkU9zd4ngt73fAfnGKlu++BNDcC4Q
# csvHppWxj7FsZgtF7Ycl+tymrx32EWdBmEvyBDRo1nuJQHyDhpV3tiUKhdRP6orM
# HWeE3v5htIoFeF3i1qqhAgMBAAGjRjBEMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
# DDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUheO6LAjFsJ5nx6DP+q6bDRtdHI0wDQYJ
# KoZIhvcNAQELBQADggEBANQfoKKWbkVR6Tc5MQguS4vzfcL5yItaZ04csBOMGJMB
# +gk5T5LpCv/R37NpJVKjm/67YpL5tVrdbGxWQ3QdmnvvbngmT3pTYJ1u/QePUIad
# EYx4FTjNB4TYV2gpSXpnFSEjlqhJJWJuxQBH+bCmVjtU6wus2v52sc/+kcNO5V1S
# eZkqlcRpGaCy9zzA6zmv4sqwqLPLlGE63Ka5lm6QxthB3HOf+L717JNA6G4WmO6j
# 04m++9yl02TsFzq/sqiSxp7VLm4xDEQvSZD4umGmld1QUch5kNPBXAG7YN/YIsnp
# VcGK8+9IyjFYxoxdaFbE2Ew97wwUgZzsJgnJ9Ntf1VwxggHwMIIB7AIBATBPMDsx
# OTA3BgNVBAMMMEFiZHVsbGFoWm1haWxpQ29kZVNpZ25pbmdNRE9UaHJlYXRQb2xp
# Y3lBbmFseXplcgIQQ6HqgjDvOohK4mxwPhpDZDAJBgUrDgMCGgUAoHgwGAYKKwYB
# BAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAc
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUpCBn
# yN1MUU3Bvhpi4u9v0GNDGCcwDQYJKoZIhvcNAQEBBQAEggEAEMAfplEWSP1iiNj0
# AyKru8u2YbgzIIJ/sKtarxT0tWTz2z6m+qsM4RGQlGSGzxvqEbcJ2pEM1qhL1r85
# EYBn2mUdspE62tX7p+go/pSYWSJ/bRisbVoLzOiHJEXHNR8VbOlkfA+zkTnZ3hrj
# R9GO4Jn6pE+1CoIH9CqI7hwuXRm2IpfBNSgDXp8IqEv9ar2uejtd2dwxOcED7lY1
# 75nIW/UVCmPkzLgkTqbv39I0fmINHvXvHZB4SGU9VsEP2Fn6s0UWG95/BguuKELy
# iagyunA251l/pUlYB1390kkrBRBVvaRPhpj2bsawcQEdjY8psU58u/kqGSD1fU09
# +06cAA==
# SIG # End signature block
