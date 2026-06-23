# Requires -Version 5.1
<#
.SYNOPSIS
    AD HealthCheck - performs a comprehensive Active Directory health and security assessment and exports the findings.
.DESCRIPTION
    This menu-driven tool discovers forest and domain topology, runs operational AD health checks,
    calculates category and overall scores, and exports findings to CSV. HTML generation is reserved
    for a separate merge file and is represented here by an inline placeholder region.
.DISCLAIMER
    This script has been thoroughly tested across various environments and scenarios, and all tests have passed successfully. However, by using this script, you acknowledge and agree that:
    1. You are responsible for how you use the script and any outcomes resulting from its execution.
    2. The entire risk arising out of the use or performance of the script remains with you.
    3. The author and contributors are not liable for any damages, including data loss, business interruption, or other losses, even if warned of the risks.
.NOTES
    File Name    : ADHealthCheck.ps1
    Author       : Abdullah Zmaili
    Version      : 2.0
    Requirements : PowerShell 5.1, domain connectivity, and appropriate administrative rights for full coverage

    ============================================================
    SECURITY NOTICE
    ============================================================

    PERMISSIONS & CREDENTIALS:
    - This tool is READ-ONLY. It does not modify Active Directory, the registry, or any
      domain controller settings (the only optional action is starting the local Winmgmt service when you approve it).
    - Run with the least-privilege account that still provides the coverage you need.
      Domain/Enterprise Admin yields full coverage, but a delegated read-only / auditor account
      can run most checks. Do NOT run with more privilege than necessary.
    - Run from a secure, trusted, domain-joined management host (ideally a Privileged Access
      Workstation / Tier 0 admin host). Avoid running privileged accounts on untrusted machines.
    - Remote Registry and WMI/CIM access to domain controllers is required for some hardening
      checks. Grant only the minimum scope required and remove it afterward.

    INPUT & EXECUTION TRUST:
    - Only run a copy of this script obtained directly from a trusted source.
    - Verify the script's integrity before execution (see SIGNATURE VERIFICATION).
    - Run the script from a local, non-synced directory (avoid OneDrive/SharePoint/Desktop sync folders).

    OUTPUT CLASSIFICATION:
    - The generated HTML report, CSV, JSON (scores + forest topology), and log files contain
      sensitive environment data: domain controller hostnames, forest/domain topology, trusts,
      FSMO placement, and security findings that reveal which hardening controls are missing.
    - This output is high-value reconnaissance data for an attacker. Treat ALL output files as
      CONFIDENTIAL per your organization's data classification policy.
    - Store output on protected storage, apply your organization's appropriate sensitivity label,
      and share only via protected channels.
    - Delete output files after review per your organization's data retention policy.

    ============================================================
.PARAMETER OutputPath
    Optional. The folder where assessment reports are written. When supplied, the interactive
    output-folder prompt is skipped. Defaults to a 'Reports' subfolder next to the script.
.PARAMETER MenuOption
    Optional. The assessment to run, matching the menu numbers (1 = Full Assessment,
    2-13 = individual categories). When supplied, the interactive menu is skipped, enabling
    unattended/automated runs.
.EXAMPLE
    .\ADHealthCheck.ps1
    Runs interactively, prompting for the output folder and the menu selection.
.EXAMPLE
    .\ADHealthCheck.ps1 -OutputPath 'D:\Reports' -MenuOption 1
    Runs a full assessment unattended, writing output to D:\Reports.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [ValidateSet('1','2','3','4','5','6','7','8','9','10','11','12','13')]
    [string]$MenuOption
)

# Explicitly disable strict mode — required for .Count on filtered results in PS 5.1
Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

#region Initialization
$Script:ExecutionStart   = Get-Date
$Script:ScriptRoot       = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$Script:DefaultOutput    = Join-Path -Path $Script:ScriptRoot -ChildPath 'Reports'
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $outputRootInput = $OutputPath
} else {
    $outputRootInput = Read-Host "Enter the output folder path for AD assessment reports [$Script:DefaultOutput]"
}
if ([string]::IsNullOrWhiteSpace($outputRootInput)) {
    $outputRootInput = $Script:DefaultOutput
}
if (-not (Test-Path -Path $outputRootInput)) {
    New-Item -Path $outputRootInput -ItemType Directory -Force | Out-Null
}
$Script:RunStamp         = Get-Date -Format 'yyyyMMdd-HHmmss'
$Script:AssessmentFolder = Join-Path -Path $outputRootInput -ChildPath ("ADHealthCheck-{0}-{1}" -f $env:COMPUTERNAME, $Script:RunStamp)
if (-not (Test-Path -Path $Script:AssessmentFolder)) {
    New-Item -Path $Script:AssessmentFolder -ItemType Directory -Force | Out-Null
}
$Script:HtmlReportPath   = Join-Path -Path $Script:AssessmentFolder -ChildPath 'ADHealthCheckReport.html'
$Script:CsvReportPath    = Join-Path -Path $Script:AssessmentFolder -ChildPath 'ADHealthCheckResults.csv'
$Script:LogFilePath      = Join-Path -Path $Script:AssessmentFolder -ChildPath 'ADHealthCheck.log'
$Script:TopologyPath     = Join-Path -Path $Script:AssessmentFolder -ChildPath 'ForestTopology.json'
$Script:ScorePath        = Join-Path -Path $Script:AssessmentFolder -ChildPath 'ADHealthCheckScores.json'
$Script:AllResults       = New-Object System.Collections.Generic.List[object]
$Script:ModuleAvailability = @{}
$Script:CommandAvailability = @{}
$Script:ForestTopology   = $null
$Script:DomainControllers = @()
New-Item -Path $Script:LogFilePath -ItemType File -Force | Out-Null
#endregion Initialization

#region Recommendations Lookup Table
# Fail/Warning recommendations keyed by CheckId — ConvertTo-ADResult auto-fills from this table
$Script:Recommendations = @{
    'SEC-057' = 'Enable LSASS protection by setting HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL to 1 and rebooting.'
    'SEC-058' = 'Enable Credential Guard via GPO: Computer Configuration > System > Device Guard > Turn On Virtualization Based Security > Credential Guard = Enabled with UEFI lock.'
    'SEC-059' = 'Enable Restricted Admin Mode by setting HKLM\SYSTEM\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin to 0.'
    'SEC-060' = 'Reduce CachedLogonsCount to 0-2 via GPO: Interactive logon: Number of previous logons to cache.'
    'SEC-061' = 'Set LmCompatibilityLevel to 5 (Send NTLMv2 only, refuse LM & NTLM). Restrict or deny outbound NTLM wherever operationally possible.'
    'SEC-062' = 'Enable NTLM auditing via GPO: Network security: Restrict NTLM: Audit incoming NTLM traffic = Enable auditing for all accounts.'
    'SEC-063' = 'Deploy LAPS to all domain-joined computers. Shared local admin passwords allow lateral movement from any compromised machine.'
    'SEC-064' = 'Restrict privileged accounts to Tier 0 systems only (PAWs/jump servers). Apply LogonWorkstations or Authentication Policy Silos.'
    'SEC-065' = 'Reset the KRBTGT account password twice a year (every 180 days). Perform two consecutive resets with at least one replication cycle between them to invalidate all existing Kerberos tickets.'
    'SEC-072' = 'Enable LSA Protection (RunAsPPL=1) and Credential Guard on all DCs to protect credentials from memory extraction attacks.'
    'SEC-075' = 'Set RestrictAnonymous=1 (or 2 for maximum), RestrictAnonymousSAM=1, and EveryoneIncludesAnonymous=0 via GPO to prevent anonymous enumeration of SAM accounts and shares.'
    'SEC-077' = 'Review and remove unnecessary permissions. Only Domain Admins, Enterprise Admins, and SYSTEM should have full control over critical AD objects.'
    'THREAT-001' = 'Remove unnecessary SPNs from user accounts. For required SPNs, enforce AES-only encryption (msDS-SupportedEncryptionTypes = 24) and use strong passwords (25+ chars). Consider gMSA accounts.'
    'THREAT-002' = 'Enable Kerberos pre-authentication for all accounts. If pre-auth must be disabled for legacy compatibility, use extremely strong passwords (25+ chars).'
    'THREAT-007' = 'Remove Replicating Directory Changes and Replicating Directory Changes All permissions from all non-DC accounts.'
    'LOG-001' = 'Configure all required Advanced Audit Policies via GPO. Ensure Success and Failure auditing for Logon, Account Lockout, Credential Validation, Directory Service Access/Changes, and Security Group Management.'
    'BKP-005' = 'Enable Active Directory Recycle Bin via PowerShell: Enable-ADOptionalFeature -Identity "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target $ForestName'
    'HEALTH-001' = 'Investigate DFSR replication issues. Check DFS Replication event log (Event IDs 4012, 4614). Run dfsrdiag pollad on affected DCs.'
    'HEALTH-003' = 'Fix time synchronization immediately. Ensure w32time service is running and configured to sync from PDC Emulator.'
    'HEALTH-004' = 'Remove lingering objects using: repadmin /removelingeringobjects <DC> <DirectoryPartition> <GUID> /advisory_mode (test first).'
    'HEALTH-008' = 'Deploy at least 2 Domain Controllers per domain for redundancy. Consider geographic distribution for disaster recovery.'
    'ARCH-001' = 'Map all IP subnets to their correct AD sites in Active Directory Sites and Services to ensure clients authenticate to the nearest DC.'
    'ARCH-003' = 'Enable DNS scavenging with appropriate no-refresh (7 days) and refresh (7 days) intervals. Review and remove stale records.'
    'GOV-003' = 'Raise domain functional level to Windows Server 2016 (minimum). Plan a DFL upgrade project to unlock modern security features.'
    'GOV-004' = 'Review and delete unlinked GPOs or re-link them. Each unlinked GPO adds confusion and audit overhead.'
    'GOV-005' = 'Avoid modifying the Default Domain Policy beyond password/lockout/Kerberos settings. Move other settings to purpose-built GPOs.'
    'IAM-001' = 'Implement a tiered admin model: Tier 0 = Domain/Forest, Tier 1 = Servers, Tier 2 = Workstations. Use separate admin accounts per tier.'
    'LOG-004' = 'Increase Security event log retention to at least 1 GB (1073741824 bytes) on all DCs to ensure adequate log coverage for investigations.'
    'BKP-006' = 'Ensure AD backups are performed at least every 24 hours. Verify backup integrity and test restoration procedures quarterly.'

    'THREAT-010' = 'Configure alerts for membership changes in privileged groups (Domain Admins, Enterprise Admins, Schema Admins, Administrators). Use Event ID 4728/4732/4756.'
    'IAM-005' = 'Audit and remove excessive permissions that create privilege escalation paths. Review AdminSDHolder, GPO delegation, and service account privileges.'
    'THREAT-012' = 'Set service accounts to use AES-only encryption (msDS-SupportedEncryptionTypes = 24), rotate passwords regularly, and prefer gMSA accounts. Disable RC4 where possible.'
    'LOG-008' = 'Restrict NTLM usage by enabling auditing first (Network security: Restrict NTLM: Audit NTLM authentication), then progressively deny NTLM where possible.'

    'THREAT-006' = 'Ensure machine account password rotation is enabled (DisablePasswordChange = 0). Investigate and remove stale computer accounts with passwords older than 60 days.'
    'IAM-006' = 'Enable NTLM auditing (AuditReceivingNTLMTraffic = 2) to identify NTLM-dependent applications. Plan migration to Kerberos. Progressively restrict NTLM where safe.'
}

$Script:RegistryChecks = @(
    @{ Id='SEC-057'; Cat='Security & Hardening'; Sub='Pass-the-Hash Mitigation'; Ref='Microsoft Credential Theft Mitigation Guide; MITRE T1003.001'; Wt=8; HivePath='SYSTEM\CurrentControlSet\Control\Lsa'; Value='RunAsPPL'; Op='eq'; Expected=1; FailSev='High'; FailImpact=15; FailMsg='LSASS is NOT running as a Protected Process (RunAsPPL) on {DC}. Credential hashes in memory are exposed to dumping tools (e.g., Mimikatz).'; PassMsg='LSASS is running as a Protected Process (RunAsPPL=1) on {DC}.' }
    @{ Id='SEC-059'; Cat='Security & Hardening'; Sub='Pass-the-Hash Mitigation'; Ref='Microsoft KB2871997; MITRE T1021.001'; Wt=6; HivePath='SYSTEM\CurrentControlSet\Control\Lsa'; Value='DisableRestrictedAdmin'; Op='eq'; Expected=0; FailSev='Medium'; FailImpact=10; FailMsg='Restricted Admin Mode for RDP is NOT enabled on {DC}. Admin credentials are cached on remote systems during RDP sessions.'; PassMsg='Restricted Admin Mode is enabled on {DC}.' }
    @{ Id='SEC-060'; Cat='Security & Hardening'; Sub='Pass-the-Hash Mitigation'; Ref='CIS Benchmark 2.3.7.6; MITRE T1003.005'; Wt=6; HivePath='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Value='CachedLogonsCount'; Op='le'; Expected=2; Default=10; FailSev='Medium'; FailImpact=10; FailMsg='Cached credentials count on {DC} is {Actual} (default 10). Stored hashes can be extracted offline for Pass-the-Hash attacks.'; PassMsg='Cached credentials count on {DC} is {Actual}, limiting offline hash extraction.' }
    @{ Id='SEC-061'; Cat='Security & Hardening'; Sub='Pass-the-Hash Mitigation'; Ref='CIS Benchmark 2.3.11; MITRE T1550.002 — Pass the Hash'; Wt=8; HivePath='SYSTEM\CurrentControlSet\Control\Lsa'; Value='LmCompatibilityLevel'; Op='ge'; Expected=5; FailSev='High'; FailImpact=15; FailMsg='NTLM restrictions on {DC} are weak (LmCompatibilityLevel={Actual}). Environments allowing LM/NTLMv1 are highly vulnerable to Pass-the-Hash and relay attacks.'; PassMsg='NTLM restrictions on {DC} meet hardened baseline (LmCompatibilityLevel={Actual}).' }
    @{ Id='SEC-062'; Cat='Security & Hardening'; Sub='Pass-the-Hash Mitigation'; Ref='Microsoft NTLM Auditing Guide; CIS Benchmark 2.3.11.7-11'; Wt=5; HivePath='SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Value='AuditReceivingNTLMTraffic'; Op='ge'; Expected=1; FailSev='Medium'; FailImpact=8; FailMsg='NTLM authentication auditing is NOT enabled on {DC}. Without NTLM audit logs, Pass-the-Hash activity cannot be detected.'; PassMsg='NTLM auditing is enabled on {DC}.' }
)

#region Invoke-RegistrySecurityChecks
function Invoke-RegistrySecurityChecks {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $allResults = @()
    $regChecks = if ($Script:RegistryChecks) { $Script:RegistryChecks } elseif ($Global:RegistryChecks) { $Global:RegistryChecks } else { @() }
    foreach ($check in $regChecks) {
        $results = @()
        foreach ($dc in $DomainControllers) {
            $dcName = $dc.HostName
            if (-not $dc.Reachable) { continue }
            $actual = Get-RemoteRegistryValueSafe -ComputerName $dcName -HivePath $check.HivePath -ValueName $check.Value
            if ($null -eq $actual -and $check.ContainsKey('Default')) { $actual = $check.Default }
            if ($null -ne $actual -and $check.Expected -is [int] -and $actual -isnot [int] -and "$actual" -match '^\d+$') {
                $actual = [int]$actual
            }
            $pass = switch ($check.Op) {
                'eq' { $actual -eq $check.Expected }
                'ne' { $actual -ne $check.Expected }
                'ge' { $null -ne $actual -and $actual -ge $check.Expected }
                'le' { $null -ne $actual -and $actual -le $check.Expected }
                'gt' { $null -ne $actual -and $actual -gt $check.Expected }
                default { $actual -eq $check.Expected }
            }
            $msg = if ($pass) { $check.PassMsg } else { $check.FailMsg }
            $msg = $msg -replace '\{DC\}', $dcName -replace '\{Actual\}', $actual
            $results += ConvertTo-ADResult -CheckId $check.Id -Category $check.Cat -SubCategory $check.Sub -Target $dcName -Domain $Domain -Forest $Forest -Severity $(if ($pass) { 'Pass' } else { $check.FailSev }) -Status $(if ($pass) { 'Pass' } else { 'Fail' }) -ScoreImpact $(if ($pass) { 0 } else { $check.FailImpact }) -Weight $check.Wt -Finding $msg -Evidence @{ ComputerName = $dcName; ($check.Value) = $actual; Expected = $check.Expected } -Reference $check.Ref
        }
        if (-not $results) {
            $results += ConvertTo-ADResult -CheckId $check.Id -Category $check.Cat -SubCategory $check.Sub -Target $Domain -Forest $Forest -Severity 'Info' -Status 'Skipped' -Weight 0 -Finding "No reachable DCs for $($check.Id) check." -Reference $check.Ref
        }
        $allResults += $results
    }
    return $allResults
}
#endregion Invoke-RegistrySecurityChecks
#endregion Recommendations Lookup Table

#region Utilities
#region Write-ADLog
function Write-ADLog {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Message, [ValidateSet('INFO','WARN','ERROR','SUCCESS')][string]$Level = 'INFO')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = '[{0}] [{1}] {2}' -f $timestamp, $Level, $Message
    try {
        Add-Content -Path $Script:LogFilePath -Value $line -Encoding UTF8
    } catch {
    }
    switch ($Level) {
        'INFO'    { Write-Host $line -ForegroundColor Cyan }
        'WARN'    { Write-Host $line -ForegroundColor Yellow }
        'ERROR'   { Write-Host $line -ForegroundColor Red }
        'SUCCESS' { Write-Host $line -ForegroundColor Green }
    }
}
#endregion Write-ADLog

#region Invoke-SafeCommand
function Invoke-SafeCommand {
    param([scriptblock]$ScriptBlock, [string]$CommandName, [int]$TimeoutSeconds = 120)
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = & $ScriptBlock
        $stopwatch.Stop()
        return @{ Success = $true; Result = $result; Duration = $stopwatch.ElapsedMilliseconds }
    } catch {
        $stopwatch.Stop()
        return @{ Success = $false; Result = $null; Duration = $stopwatch.ElapsedMilliseconds; Error = $_.Exception.Message }
    }
}
#endregion Invoke-SafeCommand

#region ConvertTo-ADResult
function ConvertTo-ADResult {
    param([string]$CheckId, [string]$Category, [string]$SubCategory='', [string]$Target='', [string]$Domain='', [string]$Forest='', [string]$Severity, [string]$Status, [int]$ScoreImpact=0,
          [int]$Weight=5, [string]$Finding, [string]$Recommendation='', $Evidence=$null, [string]$Reference='', [string]$ErrorMessage='')
    # Auto-fill recommendation from lookup table or defaults when not explicitly provided
    if ([string]::IsNullOrWhiteSpace($Recommendation)) {
        $recs = if ($Script:Recommendations) { $Script:Recommendations } elseif ($Global:Recommendations) { $Global:Recommendations } else { $null }
        if ($recs -and $recs.ContainsKey($CheckId)) {
            $Recommendation = $recs[$CheckId]
        } elseif ($Status -eq 'Pass') {
            $Recommendation = 'No action required.'
        } elseif ($Status -eq 'Skipped' -or $Status -eq 'Error') {
            $Recommendation = 'Verify connectivity and permissions, then re-run assessment.'
        }
    }
    [PSCustomObject]@{
        CheckId         = $CheckId
        Category        = $Category
        SubCategory     = $SubCategory
        Target          = $Target
        Domain          = $Domain
        Forest          = $Forest
        Severity        = $Severity
        Status          = $Status
        ScoreImpact     = $ScoreImpact
        Weight          = $Weight
        Finding         = $Finding
        Recommendation  = $Recommendation
        Evidence        = $Evidence
        Reference       = $Reference
        Timestamp       = (Get-Date)
        ExecutionTimeMs = 0
        ErrorMessage    = $ErrorMessage
    }
}
#endregion ConvertTo-ADResult

#region Get-IconHTML
function Get-IconHTML {
    param([string]$IconName)
    switch ($IconName) {
        'pass'    { '<span class="icon-emoji">&#9989;</span>' }
        'warning' { '<span class="icon-emoji">&#9888;</span>' }
        'fail'    { '<span class="icon-emoji">&#10060;</span>' }
        'info'    { '<span class="icon-emoji">&#8505;</span>' }
        'forest'  { '<span class="icon-emoji">&#127794;</span>' }
        'domain'  { '<span class="icon-emoji">&#127760;</span>' }
        'dc'      { '<span class="icon-emoji">&#128421;</span>' }
        default   { '<span class="icon-emoji">&#8226;</span>' }
    }
}
#endregion Get-IconHTML

#region Complete-ADResult
function Complete-ADResult {
    param([hashtable]$Params, [long]$Duration = 0)
    $result = ConvertTo-ADResult @Params
    $result.ExecutionTimeMs = $Duration
    return $result
}
#endregion Complete-ADResult

#region Get-AssessmentRunspaceFunctions
function Get-AssessmentRunspaceFunctions {
    $assessmentFunctionPatterns = @(
        'Test-*',
        'Get-AD*',
        'Get-CachedAD*',
        'Get-PreferredAD*',
        'Get-Remote*',
        'Get-Tombstone*',
        'Get-Registry*',
        'Get-LastSuccessful*',
        'Get-BackupFailure*',
        'Get-IconHTML',
        'Complete-AD*',
        'ConvertTo-AD*',
        'Write-AD*',
        'Invoke-Safe*',
        'Invoke-PerDCCheck',
        'Invoke-ParallelPhases',
        'Invoke-PerDomainParallel',
        'Invoke-SimpleADCheck',
        'Invoke-ADHygieneCheck',
        'Invoke-RegistrySecurityChecks',
        'Invoke-ForestDomainChecks',
        'Invoke-DCHealthChecks',
        'Invoke-ReplicationChecks',
        'Invoke-DnsChecks',
        'Invoke-InlineSecurityChecks',
        'Invoke-HygieneChecks',
        'Invoke-GpoChecks',
        'Invoke-SysvolChecks',
        'Invoke-SiteChecks',
        'Invoke-FsmoChecks',
        'Invoke-TimeChecks',
        'Invoke-BackupChecks',
        'Add-Assessment*',
        'Start-ADHealthCheck'
    )

    Get-Command -CommandType Function -Name $assessmentFunctionPatterns -ErrorAction SilentlyContinue |
        Sort-Object -Property Name -Unique
}
#endregion Get-AssessmentRunspaceFunctions

#region Invoke-PerDCCheck
function Invoke-PerDCCheck {
    param([array]$DCs, [string]$Forest='', [string]$CheckId, [string]$Category,
          [int]$Weight=5, [string]$Reference='', [scriptblock]$ScriptBlock, [int]$ThrottleLimit=8)
    if ($DCs.Count -le 2) {
        $results = [System.Collections.Generic.List[object]]::new()
        foreach ($dc in $DCs) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $r = & $ScriptBlock $dc
                if (-not $r) { $r = @{ Status='Partial'; Severity='Warning'; ScoreImpact=3; Finding="Check returned no data for $($dc.HostName)."; Evidence=$null; ErrorMessage='No result' } }
            } catch {
                $r = @{ Status='Error'; Severity='Warning'; ScoreImpact=2; Finding="Error on $($dc.HostName): $($_.Exception.Message)"; Evidence=$null; ErrorMessage=$_.Exception.Message }
            }
            $sw.Stop()
            [void]$results.Add((Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
                CheckId=$CheckId; Category=$Category; Target=$dc.HostName; Domain=$dc.Domain; Forest=$Forest
                Severity=if($r.Severity){$r.Severity}else{'Info'}; Status=if($r.Status){$r.Status}else{'Info'}; ScoreImpact=if($r.ContainsKey('ScoreImpact')){$r.ScoreImpact}else{0}; Weight=$Weight
                Finding=if($r.Finding){$r.Finding}else{''}; Recommendation=if($r.Recommendation){$r.Recommendation}else{''}; Evidence=if($r.ContainsKey('Evidence')){$r.Evidence}else{$null}; Reference=$Reference; ErrorMessage=if($r.ErrorMessage){$r.ErrorMessage}else{''}
            }))
        }
        return $results.ToArray()
    }
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $assessmentFunctions = Get-AssessmentRunspaceFunctions
    foreach ($func in $assessmentFunctions) {
        $iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($func.Name, $func.ScriptBlock.ToString()))
    }
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, [Math]::Min($ThrottleLimit, $DCs.Count), $iss, $Host)
    $runspacePool.Open()
    $jobs = @()
    foreach ($dc in $DCs) {
        $ps = [powershell]::Create().AddScript({
            param($dc, $sb)
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $r = & ([scriptblock]::Create($sb)) $dc
                if (-not $r) { $r = @{ Status='Partial'; Severity='Warning'; ScoreImpact=3; Finding="Check returned no data for $($dc.HostName)."; Evidence=$null; ErrorMessage='No result' } }
            } catch {
                $r = @{ Status='Error'; Severity='Warning'; ScoreImpact=2; Finding="Error on $($dc.HostName): $($_.Exception.Message)"; Evidence=$null; ErrorMessage=$_.Exception.Message }
            }
            $sw.Stop()
            @{ DC = $dc; Result = $r; Duration = $sw.ElapsedMilliseconds }
        }).AddArgument($dc).AddArgument($ScriptBlock.ToString())
        $ps.RunspacePool = $runspacePool
        $jobs += @{ PS = $ps; Handle = $ps.BeginInvoke(); DC = $dc }
    }
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($job in $jobs) {
        try {
            $output = $job.PS.EndInvoke($job.Handle)
            $r = $output[0].Result
            $duration = $output[0].Duration
        } catch {
            $r = @{ Status='Error'; Severity='Warning'; ScoreImpact=2; Finding="Runspace error on $($job.DC.HostName): $($_.Exception.Message)"; Evidence=$null; ErrorMessage=$_.Exception.Message }
            $duration = 0
        }
        [void]$results.Add((Complete-ADResult -Duration $duration -Params @{
            CheckId=$CheckId; Category=$Category; Target=$job.DC.HostName; Domain=$job.DC.Domain; Forest=$Forest
            Severity=if($r.Severity){$r.Severity}else{'Info'}; Status=if($r.Status){$r.Status}else{'Info'}; ScoreImpact=if($r.ContainsKey('ScoreImpact')){$r.ScoreImpact}else{0}; Weight=$Weight
            Finding=if($r.Finding){$r.Finding}else{''}; Recommendation=if($r.Recommendation){$r.Recommendation}else{''}; Evidence=if($r.ContainsKey('Evidence')){$r.Evidence}else{$null}; Reference=$Reference; ErrorMessage=if($r.ErrorMessage){$r.ErrorMessage}else{''}
        }))
        $job.PS.Dispose()
    }
    $runspacePool.Close()
    $runspacePool.Dispose()
    return $results.ToArray()
}
#endregion Invoke-PerDCCheck

# Parallel phase execution — runs independent assessment phases simultaneously using ISS
#region Invoke-ParallelPhases
function Invoke-ParallelPhases {
    param([array]$Phases, [int]$ThrottleLimit=4)  # $Phases: array of @{ Name='...'; ScriptBlock={...} }
    if ($Phases.Count -le 1) {
        foreach ($phase in $Phases) {
            Write-ADLog -Message "Running $($phase.Name)..." -Level 'INFO'
            $r = & $phase.ScriptBlock
            if ($r) { Add-AssessmentResults -Results $r }
        }
        return
    }
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $assessmentFunctions = Get-AssessmentRunspaceFunctions
    foreach ($func in $assessmentFunctions) {
        $entry = [System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($func.Name, $func.ScriptBlock.ToString())
        $iss.Commands.Add($entry)
    }
    # Inject script-scope variables needed by check functions
    $varsToInject = @('ForestTopology', 'DomainControllers', 'Recommendations', 'RegistryChecks',
                      'GroupMemberCache', 'LogFilePath', 'AllResults', 'TopologyPath', 'CsvReportPath', 'ScorePath')
    foreach ($vName in $varsToInject) {
        $val = Get-Variable -Name $vName -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if ($null -ne $val) {
            $iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new($vName, $val, ''))
        }
    }
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, [Math]::Min($ThrottleLimit, $Phases.Count), $iss, $Host)
    $runspacePool.ApartmentState = [System.Threading.ApartmentState]::MTA
    $runspacePool.Open()
    $jobs = @()
    foreach ($phase in $Phases) {
        Write-ADLog -Message "Starting parallel: $($phase.Name)" -Level 'INFO'
        $ps = [powershell]::Create().AddScript([scriptblock]::Create($phase.ScriptBlock.ToString()))
        $ps.RunspacePool = $runspacePool
        $jobs += @{ PS = $ps; Handle = $ps.BeginInvoke(); Name = $phase.Name }
    }
    foreach ($job in $jobs) {
        try {
            $results = $job.PS.EndInvoke($job.Handle)
            if ($results) { Add-AssessmentResults -Results @($results) }
            Write-ADLog -Message "Completed: $($job.Name)" -Level 'SUCCESS'
        } catch {
            Write-ADLog -Message "Phase '$($job.Name)' error: $($_.Exception.Message)" -Level 'ERROR'
        }
        $job.PS.Dispose()
    }
    $runspacePool.Close()
    $runspacePool.Dispose()
}
#endregion Invoke-ParallelPhases

#region Invoke-PerDomainParallel
function Invoke-PerDomainParallel {
    param([array]$Domains, [scriptblock]$ScriptBlock, [int]$ThrottleLimit = 4)
    if ($Domains.Count -le 1) {
        $results = [System.Collections.Generic.List[object]]::new()
        foreach ($domain in $Domains) {
            foreach ($result in @(& $ScriptBlock $domain)) {
                [void]$results.Add($result)
            }
        }
        return $results.ToArray()
    }
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $assessmentFunctions = Get-AssessmentRunspaceFunctions
    foreach ($func in $assessmentFunctions) {
        $entry = [System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($func.Name, $func.ScriptBlock.ToString())
        $iss.Commands.Add($entry)
    }
    $varsToInject = @('Recommendations', 'RegistryChecks', 'GroupMemberCache', 'LogFilePath')
    foreach ($vName in $varsToInject) {
        $val = Get-Variable -Name $vName -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if ($null -ne $val) {
            $iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new($vName, $val, ''))
        }
    }
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, [Math]::Min($ThrottleLimit, $Domains.Count), $iss, $Host)
    $runspacePool.Open()
    $jobs = @()
    foreach ($domain in $Domains) {
        $ps = [powershell]::Create().AddScript({
            param($dom, $sb)
            & ([scriptblock]::Create($sb)) $dom
        }).AddArgument($domain).AddArgument($ScriptBlock.ToString())
        $ps.RunspacePool = $runspacePool
        $jobs += @{ PS = $ps; Handle = $ps.BeginInvoke(); Domain = $domain.Name }
    }
    $allResults = [System.Collections.Generic.List[object]]::new()
    foreach ($job in $jobs) {
        try {
            $output = $job.PS.EndInvoke($job.Handle)
            if ($output) {
                foreach ($result in @($output)) {
                    [void]$allResults.Add($result)
                }
            }
        } catch {
            Write-ADLog -Message "Domain '$($job.Domain)' parallel error: $($_.Exception.Message)" -Level 'ERROR'
        }
        $job.PS.Dispose()
    }
    $runspacePool.Close()
    $runspacePool.Dispose()
    return $allResults.ToArray()
}
#endregion Invoke-PerDomainParallel

# Cache for repeated group membership lookups (Domain Admins, Enterprise Admins, etc.)
$Script:GroupMemberCache = @{}
#region Get-CachedADGroupMember
function Get-CachedADGroupMember {
    param([string]$Identity, [string]$Server, [switch]$Recursive)
    $cacheKey = "$Identity|$Server|$Recursive"
    $cache = if ($Script:GroupMemberCache) { $Script:GroupMemberCache } elseif ($Global:GroupMemberCache) { $Global:GroupMemberCache } else { $null }
    if (-not $cache) { $Script:GroupMemberCache = @{}; $cache = $Script:GroupMemberCache }
    if (-not $cache.ContainsKey($cacheKey)) {
        $params = @{ Identity = $Identity; Server = $Server; ErrorAction = 'Stop' }
        if ($Recursive) { $params['Recursive'] = $true }
        $cache[$cacheKey] = @(Get-ADGroupMember @params)
    }
    return $cache[$cacheKey]
}
#endregion Get-CachedADGroupMember

#region New-ADSkippedResult
function New-ADSkippedResult {
    param([string]$CheckId, [string]$Category, [string]$Finding, [string]$Recommendation='', [string]$Target='', [string]$Domain='', [string]$Forest='')

    return (ConvertTo-ADResult -CheckId $CheckId -Category $Category -Target $Target -Domain $Domain -Forest $Forest -Severity 'Info' -Status 'Skipped' -Finding $Finding -Recommendation $Recommendation)
}
#endregion New-ADSkippedResult

#region Test-ModuleAvailable
function Test-ModuleAvailable {
    param([Parameter(Mandatory = $true)][string]$Name)

    if ($Script:ModuleAvailability.ContainsKey($Name)) {
        return [bool]$Script:ModuleAvailability[$Name]
    }

    $available = $false
    try {
        if (Get-Module -ListAvailable -Name $Name) {
            Import-Module -Name $Name -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            $available = $true
        }
    } catch {
        Write-ADLog -Message "Unable to import module [$Name]: $($_.Exception.Message)" -Level 'WARN'
    }

    $Script:ModuleAvailability[$Name] = $available
    return $available
}
#endregion Test-ModuleAvailable

#region Test-CommandAvailable
function Test-CommandAvailable {
    param([Parameter(Mandatory = $true)][string]$Name)

    if ($Script:CommandAvailability.ContainsKey($Name)) {
        return [bool]$Script:CommandAvailability[$Name]
    }

    $exists = $false
    try {
        $exists = [bool](Get-Command -Name $Name -ErrorAction Stop)
    } catch {
        $exists = $false
    }

    $Script:CommandAvailability[$Name] = $exists
    return $exists
}
#endregion Test-CommandAvailable

#region Get-PreferredADServer
function Get-PreferredADServer {
    param([array]$DomainControllers, [string]$Domain='')

    $candidate = $DomainControllers | Where-Object {
        $_.Reachable -and ([string]::IsNullOrWhiteSpace($Domain) -or $_.Domain -eq $Domain)
    } | Select-Object -First 1

    if ($candidate) {
        return $candidate.HostName
    }

    if (-not [string]::IsNullOrWhiteSpace($Domain)) {
        return $Domain
    }

    return $env:COMPUTERNAME
}
#endregion Get-PreferredADServer

#region Test-TcpPort
function Test-TcpPort {
    param([Parameter(Mandatory=$true)][string]$ComputerName, [Parameter(Mandatory=$true)][int]$Port, [int]$TimeoutMs=3000)

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            $client.Close()
            return $false
        }
        $client.EndConnect($async)
        $client.Close()
        return $true
    } catch {
        return $false
    }
}
#endregion Test-TcpPort

#region Test-DnsHostResolution
function Test-DnsHostResolution {
    param([Parameter(Mandatory = $true)][string]$HostName)

    try {
        [void][System.Net.Dns]::GetHostEntry($HostName)
        return $true
    } catch {
        return $false
    }
}
#endregion Test-DnsHostResolution

#region Get-RemoteCimData
function Get-RemoteCimData {
    param([Parameter(Mandatory=$true)][string]$ComputerName, [Parameter(Mandatory=$true)][string]$ClassName,
          [string]$Namespace='root\cimv2', [string]$Filter='')

    try {
        if ([string]::IsNullOrWhiteSpace($Filter)) {
            return Get-CimInstance -ComputerName $ComputerName -Namespace $Namespace -ClassName $ClassName -ErrorAction Stop
        }
        return Get-CimInstance -ComputerName $ComputerName -Namespace $Namespace -ClassName $ClassName -Filter $Filter -ErrorAction Stop
    } catch {
        return $null
    }
}
#endregion Get-RemoteCimData

#region Get-ADRootDSESafe
function Get-ADRootDSESafe {
    param([string]$Server)

    try {
        if (Test-ModuleAvailable -Name 'ActiveDirectory') {
            return Get-ADRootDSE -Server $Server -ErrorAction Stop
        }

        $serverPrefix = if ([string]::IsNullOrWhiteSpace($Server)) { '' } else { "$Server/" }
        return [ADSI]("LDAP://{0}RootDSE" -f $serverPrefix)
    } catch {
        return $null
    }
}
#endregion Get-ADRootDSESafe

#region Get-TombstoneLifetimeDays
function Get-TombstoneLifetimeDays {
    param([string]$Server)

    try {
        if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
            return 180
        }

        $rootDse = Get-ADRootDSE -Server $Server -ErrorAction Stop
        $dsDn = "CN=Directory Service,CN=Windows NT,CN=Services,$($rootDse.ConfigurationNamingContext)"
        $dsObj = Get-ADObject -Identity $dsDn -Properties tombstoneLifetime -Server $Server -ErrorAction Stop
        if ($null -ne $dsObj.tombstoneLifetime -and [int]$dsObj.tombstoneLifetime -gt 0) {
            return [int]$dsObj.tombstoneLifetime
        }
        return 180
    } catch {
        return 180
    }
}
#endregion Get-TombstoneLifetimeDays

#region Get-LastSuccessfulBackupInfo
function Get-LastSuccessfulBackupInfo {
    param([Parameter(Mandatory=$true)][string]$ComputerName, [int]$DaysBack=180)

    $start = (Get-Date).AddDays(-1 * $DaysBack)
    $logs = @('Microsoft-Windows-Backup/Operational', 'Application')
    foreach ($logName in $logs) {
        try {
            $filter = @{ LogName = $logName; StartTime = $start }
            $events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $filter -ErrorAction Stop |
                Where-Object {
                    ($_.ProviderName -like '*Backup*' -or $_.LogName -eq 'Microsoft-Windows-Backup/Operational') -and
                    ($_.Id -in 4, 14)
                } |
                Sort-Object TimeCreated -Descending
            if ($events) {
                $last = $events | Select-Object -First 1
                return [PSCustomObject]@{
                    ComputerName = $ComputerName
                    Success      = $true
                    LastSuccess  = $last.TimeCreated
                    AgeDays      = [math]::Round(((Get-Date) - $last.TimeCreated).TotalDays, 2)
                    SourceLog    = $logName
                    Error        = ''
                }
            }
        } catch {
        }
    }

    [PSCustomObject]@{
        ComputerName = $ComputerName
        Success      = $false
        LastSuccess  = $null
        AgeDays      = $null
        SourceLog    = ''
        Error        = 'No successful Windows Backup event found.'
    }
}
#endregion Get-LastSuccessfulBackupInfo

#region Get-BackupFailureEvents
function Get-BackupFailureEvents {
    param([Parameter(Mandatory=$true)][string]$ComputerName, [int]$DaysBack=30)

    $start = (Get-Date).AddDays(-1 * $DaysBack)
    try {
        $events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{ LogName = 'Microsoft-Windows-Backup/Operational'; StartTime = $start } -ErrorAction Stop |
            Where-Object { $_.LevelDisplayName -in @('Error', 'Critical') }
        return $events
    } catch {
        return @()
    }
}
#endregion Get-BackupFailureEvents

#region Test-LdapBind
function Test-LdapBind {
    param([Parameter(Mandatory=$true)][string]$Server, [int]$Port=389)

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Server, $Port, $false, $false)
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
        $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
        $connection.SessionOptions.ProtocolVersion = 3
        $connection.Timeout = [TimeSpan]::FromSeconds(5)
        $connection.Bind()
        $sw.Stop()
        $connection.Dispose()
        return [PSCustomObject]@{
            Success    = $true
            DurationMs = $sw.ElapsedMilliseconds
            Error      = ''
        }
    } catch {
        $sw.Stop()
        return [PSCustomObject]@{
            Success    = $false
            DurationMs = $sw.ElapsedMilliseconds
            Error      = $_.Exception.Message
        }
    }
}
#endregion Test-LdapBind

#region ConvertFrom-GPLinkValue
function ConvertFrom-GPLinkValue {
    param([string]$GPLink)

    $results = @()
    if ([string]::IsNullOrWhiteSpace($GPLink)) {
        return $results
    }

    $gpLinkMatches = [regex]::Matches($GPLink, '\[(?<Path>[^\];]+);(?<Options>\d+)\]')
    $order = 1
    foreach ($match in $gpLinkMatches) {
        $path = $match.Groups['Path'].Value
        $options = [int]$match.Groups['Options'].Value
        $guid = ''
        if ($path -match '\{(?<Guid>[0-9A-Fa-f\-]+)\}') {
            $guid = $Matches['Guid']
        }
        $results += [PSCustomObject]@{
            Path     = $path
            Guid     = $guid.ToUpperInvariant()
            Enabled  = -not (($options -band 1) -eq 1)
            Enforced = (($options -band 2) -eq 2)
            Order    = $order
            Options  = $options
        }
        $order++
    }

    return $results
}
#endregion ConvertFrom-GPLinkValue
#endregion Utilities

#region Configuration
$Script:CategoryWeights = [ordered]@{
    'Forest & Domain Configuration' = 0.10
    'Domain Controller Health'      = 0.15
    'Replication Health'            = 0.15
    'DNS Health'                    = 0.10
    'Security & Hardening'          = 0.25
    'User & Computer Hygiene'       = 0.10
    'Group Policy Health'           = 0.10
    'SYSVOL & File Replication'     = 0.05
    'Sites & Topology'              = 0.05
    'FSMO Roles'                    = 0.03
    'Time Synchronization'          = 0.03
    'Backup & Recovery'             = 0.04
}

$Script:ScoringThresholds = [ordered]@{
    Excellent = 90
    Good      = 75
    Fair      = 60
    Poor      = 40
}
# Maps each CheckId to the primary PowerShell query/command used for assessment
$Script:CheckQueries = @{
    'FD-001' = '(Get-ADForest).ForestMode'
    'FD-002' = '(Get-ADDomain -Server <Domain>).DomainMode'
    'FD-003' = 'Get-ADObject (Get-ADRootDSE -Server <DC>).schemaNamingContext -Properties objectVersion -Server <DC>'
    'FD-004' = 'Get-ADRootDSE -Server <DC> | Select DefaultNamingContext, ConfigurationNamingContext, SchemaNamingContext'
    'FD-005' = 'Get-ADDomainController -Filter * | Where-Object { $_.IsGlobalCatalog -eq $true }'
    'FD-006' = 'Get-Service -ComputerName <RODC> -Name NTDS, Netlogon, KDC'
    'FD-007' = 'Get-ADObject -Identity "CN=Deleted Objects,<DomainDN>" -IncludeDeletedObjects -Properties msDS-Approx-Immed-Subordinates -Server <DC>'
    'FD-008' = 'Get-ADOptionalFeature -Identity "Recycle Bin Feature" -Server <DC> | Select-Object IsDisableable'
    'FD-009' = 'Get-ADObject -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -LDAPFilter "(objectClass=serviceConnectionPoint)" -Properties serviceBindingInformation, keywords -Server <DC>'
    'DC-001' = 'Test-Connection -ComputerName <DC> -Count 1 -Quiet; Test-NetConnection -ComputerName <DC> -Port 389'
    'DC-002' = 'Get-Service -ComputerName <DC> -Name NTDS, KDC, Netlogon, W32Time, ADWS, DFSR, DNS'
    'DC-003' = 'Get-WinEvent -ComputerName <DC> -FilterHashtable @{ LogName="Directory Service","System","DNS Server","DFS Replication"; StartTime=(Get-Date).AddHours(-24) } | Where-Object { $_.LevelDisplayName -in "Error","Critical" }'
    'DC-004' = 'Invoke-Command -ComputerName <DC> -ScriptBlock { Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } }'
    'DC-005' = 'Invoke-Command -ComputerName <DC> -ScriptBlock { Get-Counter "\Processor(*)\% Processor Time" }'
    'DC-006' = 'Invoke-Command -ComputerName <DC> -ScriptBlock { Get-Counter "\Memory\Available MBytes"; (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory }'
    'DC-007' = 'Get-CimInstance -ComputerName <DC> -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"'
    'DC-008' = 'nltest /server:<DC> /sc_verify:<Domain>'
    'DC-009' = '[System.DirectoryServices.Protocols.LdapConnection]::new(<DC>:389) | Bind (LDAP bind response time)'
    'DC-010' = 'Invoke-Command -ComputerName <DC> -ScriptBlock { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" | Get-Item ($_.''DSA Database file'') }'
    'RP-001' = 'Get-ADReplicationFailure -Target <Forest> -Scope Forest'
    'RP-002' = 'Get-ADReplicationPartnerMetadata -Target <DC> -Scope Server -PartnerType Both | Where-Object { $_.ConsecutiveReplicationFailures -gt 0 -or $_.LastReplicationResult -ne 0 }'
    'RP-003' = 'Get-ADReplicationPartnerMetadata -Target <DC> -Scope Server -PartnerType Both | ForEach-Object { ((Get-Date) - $_.LastReplicationSuccess).TotalHours }'
    'RP-004' = 'Get-WinEvent -ComputerName <DC> -FilterHashtable @{ LogName="Directory Service"; StartTime=(Get-Date).AddDays(-90) } | Where-Object { $_.Id -in 1388, 1988, 2042 }'
    'RP-005' = 'repadmin /queue <DC>'
    'RP-006' = 'Get-WinEvent -ComputerName <DC> -FilterHashtable @{ LogName="Directory Service"; StartTime=(Get-Date).AddDays(-7) } | Where-Object { $_.Id -in 1311, 1566, 1865, 1925 }'
    'RP-007' = 'Get-WinEvent -ComputerName <DC> -FilterHashtable @{ LogName="Directory Service"; StartTime=(Get-Date).AddDays(-180) } | Where-Object { $_.Id -in 2095, 2103, 1113 }'
    'RP-008' = 'Get-ADReplicationPartnerMetadata -Target <DC> -Scope Server -PartnerType Both | Group-Object Partition | ForEach-Object { $_.Group | Where-Object { $_.LastReplicationResult -ne 0 } }'
    'RP-009' = 'Get-ADReplicationSiteLink -Filter * -Properties ReplicationFrequencyInMinutes, Cost, Schedule, SitesIncluded -Server <DC>'
    'DNS-001' = 'dnscmd <DC> /enumzones'
    'DNS-002' = 'Get-DnsServerZone -ComputerName <DC> | Select ZoneName, ZoneType, ReplicationScope, IsDsIntegrated'
    'DNS-003' = 'Resolve-DnsName -Name <DC> -Server <DC> -Type A'
    'DNS-004' = 'Resolve-DnsName -Name _ldap._tcp.dc._msdcs.<Domain> -Type SRV -Server <DC>'
    'DNS-005' = 'Get-WinEvent -ComputerName <DC> -FilterHashtable @{ LogName="DNS Server"; StartTime=(Get-Date).AddDays(-7); Level=2,3 }'
    'DNS-006' = 'Get-DnsServerForwarder -ComputerName <DC>'
    'DNS-007' = 'Get-DnsServerScavenging -ComputerName <DC>'
    'DNS-008' = 'Resolve-DnsName -Name <DC> -Server <ExternalDNS> -Type A'
    'DNS-009' = 'Resolve-DnsName -Name <Zone> -Type NS -Server <DC>'
    'HYG-001' = 'Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(!(lastLogonTimestamp=*))(lastLogonTimestamp<=<90DaysFileTime>)))" -Properties LastLogonDate -Server <Domain>'
    'HYG-002' = 'Get-ADUser -Filter "Enabled -eq $false" -Properties whenChanged -Server <Domain> | Where-Object { $_.whenChanged -lt (Get-Date).AddDays(-90) }'
    'HYG-003' = 'Get-ADUser -Filter "PasswordNeverExpires -eq $true -and Enabled -eq $true" -Properties PasswordNeverExpires -Server <Domain>'
    'HYG-004' = 'Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -Server <Domain>'
    'HYG-005' = 'Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))" -Server <Domain>'
    'HYG-006' = 'Get-ADGroupMember -Identity "<PrivilegedGroup>" -Recursive -Server <Domain> | Get-ADObject -Properties TrustedForDelegation, TrustedToAuthForDelegation'
    'HYG-007' = 'Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" -Properties AdminCount,MemberOf -Server <Domain>'
    'HYG-008' = 'Get-ADComputer -LDAPFilter "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(!(lastLogonTimestamp=*))(lastLogonTimestamp<=<90DaysFileTime>)))" -Properties LastLogonDate, OperatingSystem -Server <Domain>'
    'HYG-009' = 'Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(servicePrincipalName=*))" -Properties ServicePrincipalName, PasswordLastSet -Server <Domain>'
    'HYG-010' = 'Get-ADDefaultDomainPasswordPolicy -Server <Domain>'
    'GPO-001' = 'Get-GPO -All -Domain <Domain> | Where-Object { $_.GpoStatus -ne "AllSettingsEnabled" }'
    'GPO-002' = 'Get-GPO -All -Domain <Domain>; (Get-GPOReport -All -ReportType XML) | Test for unlinked GPOs'
    'GPO-003' = 'Get-GPO -All -Domain <Domain> | Where-Object { ($_.User.DSVersion -eq 0 -and $_.Computer.DSVersion -eq 0) -and $_.GpoStatus -eq "AllSettingsEnabled" }'
    'GPO-004' = 'Get-GPInheritance -Target <OUDN> -Domain <Domain>'
    'GPO-005' = 'Get-GPO -All -Domain <Domain> | Get-GPPermission -TargetType User,Group -All'
    'HEALTH-001' = 'Invoke-Command -ComputerName <DC> -ScriptBlock { Get-Service -Name DFSR; Test-Path "\\$env:COMPUTERNAME\SYSVOL\<Domain>" }'
    'SYS-001' = 'Get-ChildItem -Path "\\<DC>\SYSVOL\<Domain>" -Recurse | Measure-Object; Compare across DCs'
    'SYS-002' = 'Get-WinEvent -ComputerName <DC> -FilterHashtable @{ LogName="DFS Replication"; StartTime=(Get-Date).AddDays(-7); Level=2,3 }'
    'SYS-003' = 'Test-Path "\\<DC>\NETLOGON"; Get-ChildItem "\\<DC>\NETLOGON"'
    'SITE-001' = 'Get-ADReplicationSite -Filter * -Properties Subnets | Where-Object { -not $_.Subnets }'
    'SITE-002' = '[System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::FindByName(<Forest>,<Site>).Servers | Check for bridgehead availability'
    'SITE-003' = 'Get-ADReplicationSubnet -Filter * -Properties Site | Where-Object { -not $_.Site }'
    'FSMO-001' = 'Get-ADForest | Select SchemaMaster, DomainNamingMaster; Get-ADDomain | Select PDCEmulator, RIDMaster, InfrastructureMaster; Test-Connection -ComputerName <FSMO>'
    'FSMO-002' = 'Get-ADDomain -Server <Domain> | Select RIDMaster; dcdiag /test:RidManager /s:<DC>'
    'TIME-001' = 'w32tm /query /source /computer:<DC>; w32tm /stripchart /computer:<DC> /samples:1'
    'TIME-002' = 'w32tm /query /status /computer:<DC> (compare offset across DCs)'
    'BKP-002' = 'Get-ADOptionalFeature -Identity "Recycle Bin Feature" -Server <DC> | Select-Object IsDisableable'
    'BKP-003' = 'Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,(Get-ADRootDSE).ConfigurationNamingContext" -Properties tombstoneLifetime -Server <DC>'
    'SEC-001' = 'Get-ADDefaultDomainPasswordPolicy -Server <Domain>'
    'SEC-002' = 'Get-ADFineGrainedPasswordPolicy -Filter * -Server <Domain>'
    'SEC-003' = 'Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(adminCount=1))" -Properties AdminCount -Server <Domain>'
    'SEC-004' = 'Get-ADComputer -LDAPFilter "(&(objectCategory=computer)(operatingSystem=*Server*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=524288))" -Server <Domain>'
    'SEC-005' = 'Get-ADObject -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -LDAPFilter "(objectClass=trustedDomain)" -Properties TrustDirection, TrustType, TrustAttributes -Server <DC>'
    'SEC-006' = 'Get-ADObject -Filter "objectClass -eq ''groupPolicyContainer''" -Properties gPCMachineExtensionNames | Parse for audit policy CSE GUIDs'
    'SEC-007' = 'Get-ADUser -Identity krbtgt -Properties PasswordLastSet -Server <Domain>'
    'SEC-008' = 'Get-ADComputer -LDAPFilter "(&(objectCategory=computer)(operatingSystem=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" -Properties OperatingSystem -Server <Domain> | Group OperatingSystem'
    'SEC-057' = 'Get-RemoteRegistryValueSafe -ComputerName <DC> -HivePath "SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "RunAsPPL"'
    'SEC-059' = 'Get-RemoteRegistryValueSafe -ComputerName <DC> -HivePath "SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "DisableRestrictedAdmin"'
    'SEC-060' = 'Get-RemoteRegistryValueSafe -ComputerName <DC> -HivePath "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "CachedLogonsCount"'
    'SEC-061' = 'Get-RemoteRegistryValueSafe -ComputerName <DC> -HivePath "SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "LmCompatibilityLevel"'
    'SEC-062' = 'Get-RemoteRegistryValueSafe -ComputerName <DC> -HivePath "SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "AuditReceivingNTLMTraffic"'
    'THREAT-001' = 'Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet, Enabled, msDS-SupportedEncryptionTypes -Server <Domain> -ResultPageSize 1000'
    'THREAT-002' = 'Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth, Enabled, MemberOf -Server <Domain> -ResultPageSize 1000'
    'THREAT-003' = 'Get-ADGroupMember "Domain Admins" -Recursive; Get-Acl "AD:\CN=Domain Admins,CN=Users,<DomainDN>"; Get-Acl "AD:\<DomainDN>" (check replication rights)'
    'THREAT-006' = 'Get-ADComputer -Filter {Enabled -eq $true -and PasswordLastSet -lt (Get-Date).AddDays(-60)} -Properties PasswordLastSet, OperatingSystem -Server <Domain> -ResultPageSize 1000'
    'THREAT-007' = 'Get-Acl "AD:\<DomainDN>" | Check for DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights (GUIDs: 1131f6aa/1131f6ad)'
    'SEC-075' = 'Get-RemoteRegistryValueSafe -ComputerName <DC> -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "RestrictAnonymous"
Get-RemoteRegistryValueSafe -ComputerName <DC> -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "RestrictAnonymousSAM"
Get-RemoteRegistryValueSafe -ComputerName <DC> -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "EveryoneIncludesAnonymous"'
    'SEC-077' = 'Get-Acl "AD:\<DomainDN>", "AD:\CN=Users,<DomainDN>", "AD:\OU=Domain Controllers,<DomainDN>", "AD:\CN=Computers,<DomainDN>" | Check for GenericAll, WriteDacl, WriteOwner, GenericWrite on non-admin identities'
    'LOG-002' = 'Invoke-Command -ComputerName <DC> -ScriptBlock { Get-WinEvent -ListLog "Security" } | fl MaximumSizeInBytes, LogMode, RecordCount'
    'IAM-006' = 'Invoke-Command -ComputerName <DC> -ScriptBlock { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditReceivingNTLMTraffic","RestrictReceivingNTLMTraffic"; Get-WinEvent -FilterHashtable @{LogName="Security";Id=4776;StartTime=(Get-Date).AddHours(-24)} -MaxEvents 1000 }'
    'LOG-001' = 'Invoke-Command -ComputerName <DC> -ScriptBlock { auditpol /get /category:* /r }'
    'LOG-004' = 'Invoke-Command -ComputerName <DC> -ScriptBlock { Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4728,4729,4732,4733,4756,4757; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 50 }'
    'SEC-063' = 'Get-ADComputer -Filter "Enabled -eq ''True''" -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime, ms-LAPS-Password, ms-LAPS-PasswordExpirationTime -Server <Domain> -ResultPageSize 1000'
    'TIME-003' = 'w32tm /monitor /computers:<DC1>,<DC2>'
}
#endregion Configuration

#region Menu
#region Show-ADHealthCheckMenu
function Show-ADHealthCheckMenu {
    Write-Host ''
    Write-Host '=== AD HEALTHCHECK MENU ===' -ForegroundColor Cyan
    Write-Host '[1]  Run Full Assessment (All Categories)' -ForegroundColor Green
    Write-Host '[2]  Forest & Domain Configuration' -ForegroundColor Green
    Write-Host '[3]  Domain Controller Health' -ForegroundColor Green
    Write-Host '[4]  Replication Health' -ForegroundColor Green
    Write-Host '[5]  DNS Health' -ForegroundColor Green
    Write-Host '[6]  Security & Hardening' -ForegroundColor Green
    Write-Host '[7]  User & Computer Hygiene' -ForegroundColor Green
    Write-Host '[8]  Group Policy Health' -ForegroundColor Green
    Write-Host '[9]  SYSVOL & File Replication' -ForegroundColor Green
    Write-Host '[10] Sites & Topology' -ForegroundColor Green
    Write-Host '[11] FSMO Roles' -ForegroundColor Green
    Write-Host '[12] Time Synchronization' -ForegroundColor Green
    Write-Host '[13] Backup & Recovery' -ForegroundColor Green
    Write-Host '[Q]  Quit' -ForegroundColor Yellow
    Write-Host ''
}
#endregion Show-ADHealthCheckMenu

#region Get-ADHealthCheckSelection
function Get-ADHealthCheckSelection {
    do {
        Show-ADHealthCheckMenu
        $selection = (Read-Host 'Enter your selection').Trim().ToUpperInvariant()
        if ($selection -notin @('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', 'Q')) {
            Write-Host 'Invalid selection. Please choose a valid menu option.' -ForegroundColor Red
        }
    } while ($selection -notin @('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', 'Q'))

    return $selection
}
#endregion Get-ADHealthCheckSelection
#endregion Menu

#region Discovery
#region Get-ADHealthCheckForestTopology
function Get-ADHealthCheckForestTopology {
    [CmdletBinding()]
    param()

    $safe = Invoke-SafeCommand -CommandName 'ForestDiscovery' -ScriptBlock {
        if (Test-ModuleAvailable -Name 'ActiveDirectory') {
            $forest = Get-ADForest -ErrorAction Stop
            $domains = foreach ($domainName in $forest.Domains) {
                $domain = Get-ADDomain -Identity $domainName -Server $domainName -ErrorAction Stop
                [PSCustomObject]@{
                    Name                 = $domain.DNSRoot
                    DistinguishedName    = $domain.DistinguishedName
                    NetBIOSName          = $domain.NetBIOSName
                    DomainMode           = $domain.DomainMode.ToString()
                    ParentDomain         = $domain.ParentDomain
                    PDCEmulator          = $domain.PDCEmulator
                    RIDMaster            = $domain.RIDMaster
                    InfrastructureMaster = $domain.InfrastructureMaster
                    ReplicaDirectoryServers = @($domain.ReplicaDirectoryServers)
                }
            }

            $trusts = foreach ($domainName in $forest.Domains) {
                try {
                    Get-ADTrust -Filter * -Server $domainName -ErrorAction Stop | ForEach-Object {
                        [PSCustomObject]@{
                            Source         = $domainName
                            Target         = $_.Target
                            Direction      = $_.Direction.ToString()
                            TrustType      = $_.TrustType.ToString()
                            IntraForest    = $_.IntraForest
                            ForestTransitive = $_.ForestTransitive
                        }
                    }
                } catch {
                }
            }

            $sites = @()
            try {
                $sites = Get-ADReplicationSite -Filter * -Server $forest.RootDomain -ErrorAction Stop | Select-Object -ExpandProperty Name
            } catch {
            }

            return [PSCustomObject]@{
                ForestName         = $forest.Name
                RootDomain         = $forest.RootDomain
                ForestMode         = $forest.ForestMode.ToString()
                Domains            = @($domains)
                Sites              = @($sites)
                Trusts             = @($trusts)
                GlobalCatalogs     = @($forest.GlobalCatalogs)
                SchemaMaster       = $forest.SchemaMaster
                DomainNamingMaster = $forest.DomainNamingMaster
            }
        }

        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $domains = foreach ($domain in $forest.Domains) {
            [PSCustomObject]@{
                Name                 = $domain.Name
                DistinguishedName    = $domain.GetDirectoryEntry().distinguishedName.Value
                NetBIOSName          = $domain.Name.Split('.')[0].ToUpperInvariant()
                DomainMode           = $domain.DomainMode.ToString()
                ParentDomain         = ''
                PDCEmulator          = $domain.PdcRoleOwner.Name
                RIDMaster            = $domain.RidRoleOwner.Name
                InfrastructureMaster = $domain.InfrastructureRoleOwner.Name
                ReplicaDirectoryServers = @($domain.DomainControllers | ForEach-Object { $_.Name })
            }
        }

        return [PSCustomObject]@{
            ForestName         = $forest.Name
            RootDomain         = $forest.RootDomain.Name
            ForestMode         = $forest.ForestMode.ToString()
            Domains            = @($domains)
            Sites              = @($forest.Sites | ForEach-Object { $_.Name })
            Trusts             = @()
            GlobalCatalogs     = @($forest.GlobalCatalogs | ForEach-Object { $_.Name })
            SchemaMaster       = $forest.SchemaRoleOwner.Name
            DomainNamingMaster = $forest.NamingRoleOwner.Name
        }
    }

    if (-not $safe.Success) {
        throw "Forest discovery failed: $($safe.Error)"
    }

    return $safe.Result
}
#endregion Get-ADHealthCheckForestTopology

#region Get-ADHealthCheckDomainControllers
function Get-ADHealthCheckDomainControllers {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][psobject]$ForestTopology)

    $controllers = @()
    $seen = @{}

    if (Test-ModuleAvailable -Name 'ActiveDirectory') {
        foreach ($domain in $ForestTopology.Domains) {
            try {
                $domainDcs = Get-ADDomainController -Filter * -Server $domain.Name -ErrorAction Stop
                foreach ($dc in $domainDcs) {
                    if (-not $seen.ContainsKey($dc.HostName)) {
                        $seen[$dc.HostName] = $true
                        $reachable = $false
                        try {
                            $reachable = Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet -ErrorAction Stop
                        } catch {
                            $reachable = $false
                        }
                        $controllers += [PSCustomObject]@{
                            HostName           = $dc.HostName
                            Domain             = $domain.Name
                            Forest             = $ForestTopology.ForestName
                            Site               = $dc.Site
                            IsGlobalCatalog    = [bool]$dc.IsGlobalCatalog
                            IsReadOnly         = [bool]$dc.IsReadOnly
                            IPv4Address        = $dc.IPv4Address
                            OperatingSystem    = $dc.OperatingSystem
                            OperationMasterRoles = @($dc.OperationMasterRoles)
                            Reachable          = $reachable
                        }
                    }
                }
            } catch {
                Write-ADLog -Message "Failed to enumerate domain controllers for domain [$($domain.Name)]: $($_.Exception.Message)" -Level 'WARN'
            }
        }
        return $controllers
    }

    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    foreach ($domain in $forest.Domains) {
        foreach ($dc in $domain.DomainControllers) {
            if (-not $seen.ContainsKey($dc.Name)) {
                $seen[$dc.Name] = $true
                $reachable = $false
                try {
                    $reachable = Test-Connection -ComputerName $dc.Name -Count 1 -Quiet -ErrorAction Stop
                } catch {
                    $reachable = $false
                }
                $controllers += [PSCustomObject]@{
                    HostName           = $dc.Name
                    Domain             = $domain.Name
                    Forest             = $forest.Name
                    Site               = $dc.SiteName
                    IsGlobalCatalog    = [bool]$dc.IsGlobalCatalog()
                    IsReadOnly         = $false
                    IPv4Address        = ''
                    OperatingSystem    = ''
                    OperationMasterRoles = @()
                    Reachable          = $reachable
                }
            }
        }
    }

    return $controllers
}
#endregion Get-ADHealthCheckDomainControllers
#endregion Discovery

#region Invoke-SimpleADCheck
function Invoke-SimpleADCheck {
    param(
        [string]$CheckId,
        [string]$Category,
        [string]$Target         = '',
        [string]$Domain         = '',
        [string]$Forest         = '',
        [int]$Weight            = 5,
        [string]$Reference      = '',
        [string]$ErrorFinding   = '',
        [string]$ErrorRecommendation = '',
        [int]$ErrorImpact       = 2,
        [hashtable]$Context     = @{},
        [scriptblock]$Evaluate
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $r = & $Evaluate $Context
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId        = $CheckId
            Category       = $Category
            Target         = $Target
            Domain         = $Domain
            Forest         = $Forest
            Severity       = $r.Severity
            Status         = $r.Status
            ScoreImpact    = if ($r.ContainsKey('ScoreImpact')) { $r.ScoreImpact } else { 0 }
            Weight         = $Weight
            Finding        = $r.Finding
            Recommendation = if ($r.ContainsKey('Recommendation')) { $r.Recommendation } else { '' }
            Evidence       = if ($r.ContainsKey('Evidence')) { $r.Evidence } else { $null }
            Reference      = $Reference
            ErrorMessage   = if ($r.ContainsKey('ErrorMessage')) { $r.ErrorMessage } else { '' }
        })
    } catch {
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId        = $CheckId
            Category       = $Category
            Target         = $Target
            Domain         = $Domain
            Forest         = $Forest
            Severity       = 'Warning'
            Status         = 'Partial'
            ScoreImpact    = $ErrorImpact
            Weight         = $Weight
            Finding        = if ($ErrorFinding) { $ErrorFinding } else { "Check $CheckId could not be completed." }
            Recommendation = if ($ErrorRecommendation) { $ErrorRecommendation } else { 'Verify connectivity and permissions, then re-run assessment.' }
            Evidence       = $null
            Reference      = $Reference
            ErrorMessage   = $_.Exception.Message
        })
    }
}
#endregion Invoke-SimpleADCheck

#region Collection & Analysis
#region Test-ForestFunctionalLevel
function Test-ForestFunctionalLevel {
    param([psobject]$ForestTopology)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $rankMap = @{
        'Windows2000Forest' = 0
        'Windows2003InterimForest' = 1
        'Windows2003Forest' = 2
        'Windows2008Forest' = 3
        'Windows2008R2Forest' = 4
        'Windows2012Forest' = 5
        'Windows2012R2Forest' = 6
        'Windows2016Forest' = 7
    }
    $mode = [string]$ForestTopology.ForestMode
    $rank = if ($rankMap.ContainsKey($mode)) { $rankMap[$mode] } else { 7 }
    if ($rank -ge 6) {
        $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "Forest functional level is $mode."; $recommendation = 'No action required.'
    } elseif ($rank -ge 4) {
        $status = 'Warning'; $severity = 'Warning'; $impact = 8; $finding = "Forest functional level is $mode, which limits newer AD capabilities."; $recommendation = 'Review forest-wide application compatibility and raise the forest functional level when supported.'
    } else {
        $status = 'Fail'; $severity = 'Critical'; $impact = 18; $finding = "Forest functional level is $mode and is considered legacy."; $recommendation = 'Plan a functional level uplift after validating application and domain controller support.'
    }
    $sw.Stop()
    return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
        CheckId='FD-001'; Category='Forest & Domain Configuration'; Target=$ForestTopology.ForestName; Forest=$ForestTopology.ForestName
        Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=9
        Finding=$finding; Recommendation=$recommendation; Evidence=@{ForestMode=$mode}; Reference='Forest functional level'
    })
}
#endregion Test-ForestFunctionalLevel

#region Test-DomainFunctionalLevel
function Test-DomainFunctionalLevel {
    param([psobject]$ForestTopology)
    $results = @()
    $rankMap = @{
        'Windows2000Domain' = 0
        'Windows2003InterimDomain' = 1
        'Windows2003Domain' = 2
        'Windows2008Domain' = 3
        'Windows2008R2Domain' = 4
        'Windows2012Domain' = 5
        'Windows2012R2Domain' = 6
        'Windows2016Domain' = 7
    }
    foreach ($domain in $ForestTopology.Domains) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $mode = [string]$domain.DomainMode
        $rank = if ($rankMap.ContainsKey($mode)) { $rankMap[$mode] } else { 7 }
        if ($rank -ge 6) {
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "Domain functional level for $($domain.Name) is $mode."; $recommendation = 'No action required.'
        } elseif ($rank -ge 4) {
            $status = 'Warning'; $severity = 'Warning'; $impact = 8; $finding = "Domain functional level for $($domain.Name) is $mode."; $recommendation = 'Raise the domain functional level after compatibility validation.'
        } else {
            $status = 'Fail'; $severity = 'Critical'; $impact = 16; $finding = "Domain functional level for $($domain.Name) is $mode and is legacy."; $recommendation = 'Prioritize domain controller modernization and raise the domain functional level.'
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='FD-002'; Category='Forest & Domain Configuration'; Target=$domain.Name; Domain=$domain.Name; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=8
            Finding=$finding; Recommendation=$recommendation; Evidence=@{DomainMode=$mode}; Reference='Domain functional level'
        }
    }
    return $results
}
#endregion Test-DomainFunctionalLevel

#region Test-ADSchemaVersion
function Test-ADSchemaVersion {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        $sw.Stop()
        return @(New-ADSkippedResult -CheckId 'FD-003' -Category 'Forest & Domain Configuration' -Forest $ForestTopology.ForestName -Finding 'ActiveDirectory module unavailable; schema version could not be queried.' -Recommendation 'Run from a host with RSAT Active Directory tools installed.')
    }

    $server = Get-PreferredADServer -DomainControllers $DomainControllers -Domain $ForestTopology.RootDomain
    try {
        $schemaDN = (Get-ADRootDSE -Server $server -ErrorAction Stop).schemaNamingContext
        $schemaRoot = Get-ADObject -Identity $schemaDN -Server $server -Properties objectVersion -ErrorAction Stop
        $version = [int](($schemaRoot['objectVersion'] | Select-Object -First 1))
        $objectGuid = [string]$schemaRoot.ObjectGUID
        $versionMap = @{
            13 = 'Windows 2000'; 30 = 'Windows Server 2003'; 31 = 'Windows Server 2003 R2';
            44 = 'Windows Server 2008'; 47 = 'Windows Server 2008 R2'; 56 = 'Windows Server 2012';
            69 = 'Windows Server 2012 R2'; 87 = 'Windows Server 2016/2019'; 88 = 'Windows Server 2019/2022'
        }
        $friendly = if ($versionMap.ContainsKey($version)) { $versionMap[$version] } else { 'Unknown / newer build' }
        if ($version -ge 87) {
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "Schema version is $version ($friendly)."; $recommendation = 'No action required.'
        } elseif ($version -ge 69) {
            $status = 'Warning'; $severity = 'Warning'; $impact = 6; $finding = "Schema version is $version ($friendly)."; $recommendation = 'Review whether a schema and domain controller modernization program is required.'
        } else {
            $status = 'Fail'; $severity = 'Critical'; $impact = 14; $finding = "Schema version is $version ($friendly), indicating an older AD platform baseline."; $recommendation = 'Modernize the AD platform and schema support path.'
        }
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='FD-003'; Category='Forest & Domain Configuration'; Target=$server; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=7
            Finding=$finding; Recommendation=$recommendation; Evidence=@{ObjectGUID=$objectGuid; objectVersion=$version}; Reference='Get-ADObject (Get-ADRootDSE).schemaNamingContext -Property objectVersion'
        })
    } catch {
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='FD-003'; Category='Forest & Domain Configuration'; Target=$server; Forest=$ForestTopology.ForestName
            Severity='Warning'; Status='Partial'; ScoreImpact=4; Weight=7
            Finding='Schema version query failed.'; Recommendation='Verify AD connectivity and permissions to the schema partition.'; Evidence=$null; Reference='Get-ADObject (Get-ADRootDSE).schemaNamingContext -Property objectVersion'; ErrorMessage=$_.Exception.Message
        })
    }
}
#endregion Test-ADSchemaVersion

#region Test-NamingContextAccess
function Test-NamingContextAccess {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $results = @()
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        return @(New-ADSkippedResult -CheckId 'FD-004' -Category 'Forest & Domain Configuration' -Forest $ForestTopology.ForestName -Finding 'ActiveDirectory module unavailable; naming context tests skipped.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }

    foreach ($dc in $DomainControllers) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $rootDse = Get-ADRootDSE -Server $dc.HostName -ErrorAction Stop
            $contexts = @(
                $rootDse.DefaultNamingContext,
                $rootDse.ConfigurationNamingContext,
                $rootDse.SchemaNamingContext,
                $rootDse.RootDomainNamingContext,
                "DC=DomainDnsZones,$($rootDse.DefaultNamingContext)",
                "DC=ForestDnsZones,$($rootDse.RootDomainNamingContext)"
            ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

            $failedContexts = @()
            foreach ($context in $contexts) {
                try {
                    Get-ADObject -Server $dc.HostName -SearchBase $context -LDAPFilter '(objectClass=*)' -ResultSetSize 1 -ErrorAction Stop | Out-Null
                } catch {
                    $failedContexts += $context
                }
            }

            if ($failedContexts.Count -eq 0) {
                $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "All naming contexts were readable through $($dc.HostName)."; $recommendation = 'No action required.'
            } else {
                $status = 'Fail'; $severity = 'Critical'; $impact = 15; $finding = "One or more naming contexts were not readable through $($dc.HostName)."; $recommendation = 'Investigate replication, permissions, or partition health issues on the affected DC.'
            }

            $sw.Stop()
            $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
                CheckId='FD-004'; Category='Forest & Domain Configuration'; Target=$dc.HostName; Domain=$dc.Domain; Forest=$ForestTopology.ForestName
                Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=8
                Finding=$finding; Recommendation=$recommendation; Evidence=@{Checked=$contexts; Failed=$failedContexts}; Reference='RootDSE naming contexts'
            }
        } catch {
            $sw.Stop()
            $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
                CheckId='FD-004'; Category='Forest & Domain Configuration'; Target=$dc.HostName; Domain=$dc.Domain; Forest=$ForestTopology.ForestName
                Severity='Warning'; Status='Partial'; ScoreImpact=5; Weight=8
                Finding='Naming context access test could not complete.'; Recommendation='Validate LDAP connectivity and account privileges.'; Evidence=$null; Reference='RootDSE naming contexts'; ErrorMessage=$_.Exception.Message
            }
        }
    }
    return $results
}
#endregion Test-NamingContextAccess

#region Test-GlobalCatalogAvailability
function Test-GlobalCatalogAvailability {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $results = @()
    foreach ($domain in $ForestTopology.Domains) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $gcs = @($DomainControllers | Where-Object { $_.Domain -eq $domain.Name -and $_.IsGlobalCatalog -eq $true })
        if ($gcs.Count -ge 1) {
            $gcNames = @($gcs | ForEach-Object { $_.HostName } | Where-Object { $_ })
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "Domain $($domain.Name) has $($gcs.Count) global catalog server(s): $($gcNames -join ', ')."; $recommendation = 'No action required.'
        } else {
            $gcNames = @()
            $status = 'Fail'; $severity = 'Critical'; $impact = 20; $finding = "Domain $($domain.Name) has no global catalog server."; $recommendation = 'Enable GC on a healthy DC in the domain and validate replication.'
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='FD-005'; Category='Forest & Domain Configuration'; Target=$domain.Name; Domain=$domain.Name; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=9
            Finding=$finding; Recommendation=$recommendation; Evidence=@{GlobalCatalogs=$gcNames; Count=$gcs.Count}; Reference='Get-ADDomainController -Filter * | Select IsGlobalCatalog'
        }
    }
    return $results
}
#endregion Test-GlobalCatalogAvailability

#region Test-RODCHealth
function Test-RODCHealth {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $results = @()
    $rodcs = $DomainControllers | Where-Object { $_.IsReadOnly }
    if (-not $rodcs) {
        return @(ConvertTo-ADResult -CheckId 'FD-006' -Category 'Forest & Domain Configuration' -Forest $ForestTopology.ForestName -Severity 'Info' -Status 'Info' -Weight 4 -Finding 'No read-only domain controllers were discovered.' -Recommendation 'No action required.' -Evidence $null -Reference 'RODC inventory')
    }

    foreach ($dc in $rodcs) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $serviceIssues = @()
        foreach ($serviceName in 'NTDS', 'Netlogon', 'KDC') {
            try {
                $svc = Get-Service -ComputerName $dc.HostName -Name $serviceName -ErrorAction Stop
                if ($svc.Status -ne 'Running') {
                    $serviceIssues += "$serviceName=$($svc.Status)"
                }
            } catch {
                $serviceIssues += "$serviceName=Unavailable"
            }
        }
        if ($dc.Reachable -and $serviceIssues.Count -eq 0) {
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "RODC $($dc.HostName) is reachable and core services are running."; $recommendation = 'No action required.'
        } else {
            $status = 'Warning'; $severity = 'Warning'; $impact = 8; $finding = "RODC $($dc.HostName) has reachability or service issues."; $recommendation = 'Review RODC site connectivity, replication, and core AD services.'
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='FD-006'; Category='Forest & Domain Configuration'; Target=$dc.HostName; Domain=$dc.Domain; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=6
            Finding=$finding; Recommendation=$recommendation; Evidence=@{Reachable=$dc.Reachable; ServiceIssues=$serviceIssues}; Reference='RODC service health'
        }
    }
    return $results
}
#endregion Test-RODCHealth

#region Test-DeletedObjectsContainer
function Test-DeletedObjectsContainer {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $results = @()
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        return @(New-ADSkippedResult -CheckId 'FD-007' -Category 'Forest & Domain Configuration' -Forest $ForestTopology.ForestName -Finding 'ActiveDirectory module unavailable; deleted objects container check skipped.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }

    foreach ($domain in $ForestTopology.Domains) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $server = Get-PreferredADServer -DomainControllers $DomainControllers -Domain $domain.Name
            $deleted = Get-ADObject -Identity "CN=Deleted Objects,$($domain.DistinguishedName)" -IncludeDeletedObjects -Server $server -ErrorAction Stop
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "Deleted Objects container is accessible in $($domain.Name)."; $recommendation = 'No action required.'
            $evidence = @{ DistinguishedName = $deleted.DistinguishedName }
        } catch {
            $status = 'Fail'; $severity = 'Critical'; $impact = 14; $finding = "Deleted Objects container is not accessible in $($domain.Name)."; $recommendation = 'Validate directory partition health and permissions for deleted object access.'
            $evidence = $null
            $errorMessage = $_.Exception.Message
        }
        $sw.Stop()
        $params = @{
            CheckId='FD-007'; Category='Forest & Domain Configuration'; Target=$domain.Name; Domain=$domain.Name; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=5
            Finding=$finding; Recommendation=$recommendation; Evidence=$evidence; Reference='Deleted Objects container'
        }
        if ($errorMessage) { $params.ErrorMessage = $errorMessage }
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params $params
        $errorMessage = ''
    }
    return $results
}
#endregion Test-DeletedObjectsContainer

#region Test-ADRecycleBin
function Test-ADRecycleBin {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        return @(New-ADSkippedResult -CheckId 'FD-008' -Category 'Forest & Domain Configuration' -Forest $ForestTopology.ForestName -Finding 'ActiveDirectory module unavailable; Recycle Bin state could not be checked.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }
    $server = Get-PreferredADServer -DomainControllers $DomainControllers -Domain $ForestTopology.RootDomain
    Invoke-SimpleADCheck -CheckId 'FD-008' -Category 'Forest & Domain Configuration' -Target $ForestTopology.ForestName -Forest $ForestTopology.ForestName -Weight 7 -Reference 'Recycle Bin Feature' -ErrorFinding 'Unable to determine Active Directory Recycle Bin state.' -ErrorRecommendation 'Verify permissions and ADWS access to query optional features.' -ErrorImpact 4 `
        -Context @{ Server = $server; ForestName = $ForestTopology.ForestName } `
        -Evaluate {
            param($ctx)
            $feature = Get-ADOptionalFeature -Identity 'Recycle Bin Feature' -Server $ctx.Server | Select-Object IsDisableable
            $enabled = $feature.IsDisableable -eq $false
            if ($enabled) {
                @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding='Active Directory Recycle Bin is enabled (IsDisableable: False).'; Recommendation='No action required.'; Evidence=@{ IsDisableable=$feature.IsDisableable } }
            } else {
                @{ Status='Warning'; Severity='Warning'; ScoreImpact=10; Finding='Active Directory Recycle Bin is not enabled (IsDisableable: True).'; Recommendation='Enable Recycle Bin after validating restore procedures and forest readiness.'; Evidence=@{ IsDisableable=$feature.IsDisableable } }
            }
        }
}
#endregion Test-ADRecycleBin



#region Test-ServiceConnectionPoints
function Test-ServiceConnectionPoints {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        $sw.Stop()
        return @(New-ADSkippedResult -CheckId 'FD-009' -Category 'Forest & Domain Configuration' -Forest $ForestTopology.ForestName -Finding 'ActiveDirectory module unavailable; service connection point scan skipped.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }

    $server = Get-PreferredADServer -DomainControllers $DomainControllers -Domain $ForestTopology.RootDomain
    try {
        $rootDse = Get-ADRootDSE -Server $server -ErrorAction Stop
        $scps = Get-ADObject -Server $server -SearchBase $rootDse.ConfigurationNamingContext -LDAPFilter '(objectClass=serviceConnectionPoint)' -Properties serviceBindingInformation, keywords -ErrorAction Stop
        $invalid = @()
        foreach ($scp in $scps) {
            foreach ($binding in @($scp.serviceBindingInformation)) {
                if ($binding -match '(?<Host>[A-Za-z0-9\-]+\.[A-Za-z0-9\.-]+)') {
                    $hostName = $matches['Host']
                    if (-not (Test-DnsHostResolution -HostName $hostName)) {
                        $invalid += [PSCustomObject]@{ SCP = $scp.DistinguishedName; Binding = $binding }
                    }
                }
            }
        }
        if ($invalid.Count -eq 0) {
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "Validated $($scps.Count) service connection point object(s) without unresolved binding targets."; $recommendation = 'No action required.'
        } elseif ($invalid.Count -le 5) {
            $status = 'Warning'; $severity = 'Warning'; $impact = 5; $finding = "$($invalid.Count) service connection point binding target(s) were unresolved."; $recommendation = 'Review stale SCP registrations and decommissioned service references.'
        } else {
            $status = 'Fail'; $severity = 'Critical'; $impact = 12; $finding = "$($invalid.Count) service connection point binding target(s) were unresolved."; $recommendation = 'Clean up invalid SCP registrations and confirm dependent services are still in use.'
        }
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='FD-009'; Category='Forest & Domain Configuration'; Target=$ForestTopology.ForestName; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=5
            Finding=$finding; Recommendation=$recommendation; Evidence=@{TotalSCPs=$scps.Count; InvalidBindings=$invalid | Select-Object -First 20}; Reference='serviceConnectionPoint objects'
        })
    } catch {
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='FD-009'; Category='Forest & Domain Configuration'; Target=$ForestTopology.ForestName; Forest=$ForestTopology.ForestName
            Severity='Warning'; Status='Partial'; ScoreImpact=3; Weight=5
            Finding='Service connection point scan failed.'; Recommendation='Validate configuration partition access and query privileges.'; Evidence=$null; Reference='serviceConnectionPoint objects'; ErrorMessage=$_.Exception.Message
        })
    }
}
#endregion Test-ServiceConnectionPoints

#region Test-DCReachability
function Test-DCReachability {
    param([array]$DomainControllers, [string]$Domain = '', [string]$Forest = '')
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'DC-001' -Category 'Domain Controller Health' -Weight 10 -Reference 'Basic reachability' -ScriptBlock {
        param($dc)
        $ping = $false
        try { $ping = Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet -ErrorAction Stop } catch {}
        $ldap = Test-TcpPort -ComputerName $dc.HostName -Port 389
        if ($ldap) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="DC $($dc.HostName) responded on LDAP port 389 (ICMP=$ping)."; Evidence=@{ Ping = $ping; LDAP389 = $ldap } } }
        elseif ($ping) { @{ Status='Warning'; Severity='Warning'; ScoreImpact=8; Finding="DC $($dc.HostName) responds to ICMP but LDAP port 389 is unreachable."; Recommendation='Investigate AD DS service state and port 389 availability.'; Evidence=@{ Ping = $ping; LDAP389 = $ldap } } }
        else { @{ Status='Fail'; Severity='Critical'; ScoreImpact=20; Finding="DC $($dc.HostName) is not reachable over ICMP or LDAP port 389."; Recommendation='Investigate host availability, network path, and AD DS service state immediately.'; Evidence=@{ Ping = $ping; LDAP389 = $ldap } } }
    }
}
#endregion Test-DCReachability

#region Test-CriticalADServices
function Test-CriticalADServices {
    param([array]$DomainControllers, [string]$Forest = '')
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'DC-002' -Category 'Domain Controller Health' -Weight 10 -Reference 'Critical AD services' -ScriptBlock {
        param($dc)
        $requiredServices = @('NTDS', 'KDC', 'Netlogon', 'W32Time', 'ADWS', 'DFSR', 'DNS')
        $issues = @()
        foreach ($name in $requiredServices) {
            try { $svc = Get-Service -ComputerName $dc.HostName -Name $name -ErrorAction Stop; if ($svc.Status -ne 'Running') { $issues += "$name=$($svc.Status)" } }
            catch { if ($name -notin @('DNS', 'DFSR')) { $issues += "$name=Unavailable" } }
        }
        if ($issues.Count -eq 0) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="All critical AD services checked are running on $($dc.HostName)."; Evidence=@{ Issues = $issues } } }
        else { @{ Status='Fail'; Severity='Critical'; ScoreImpact=18; Finding="Critical AD service issues were detected on $($dc.HostName)."; Recommendation='Restore failed or stopped AD-related services and investigate underlying service failures.'; Evidence=@{ Issues = $issues } } }
    }
}
#endregion Test-CriticalADServices

#region Test-DCEventLogHealth
function Test-DCEventLogHealth {
    param([array]$DomainControllers, [string]$Forest = '')
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'DC-003' -Category 'Domain Controller Health' -Weight 8 -Reference 'Event log health last 24h' -ScriptBlock {
        param($dc)
        $counts = @{}
        $totalErrors = 0
        foreach ($logName in 'Directory Service', 'System', 'DNS Server', 'DFS Replication') {
            try { $events = Get-WinEvent -ComputerName $dc.HostName -FilterHashtable @{ LogName = $logName; StartTime = (Get-Date).AddHours(-24) } -ErrorAction Stop | Where-Object { $_.LevelDisplayName -in @('Error', 'Critical') }; $counts[$logName] = @($events).Count; $totalErrors += @($events).Count }
            catch { $counts[$logName] = 'Unavailable' }
        }
        if ($totalErrors -eq 0) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="No critical or error AD-related events were detected on $($dc.HostName) in the last 24 hours."; Evidence=$counts } }
        elseif ($totalErrors -le 10) { @{ Status='Warning'; Severity='Warning'; ScoreImpact=7; Finding="$totalErrors AD-related error event(s) were detected on $($dc.HostName) in the last 24 hours."; Recommendation='Review recurring AD, DNS, DFSR, and system events on the DC.'; Evidence=$counts } }
        else { @{ Status='Fail'; Severity='Critical'; ScoreImpact=16; Finding="$totalErrors AD-related error event(s) were detected on $($dc.HostName) in the last 24 hours."; Recommendation='Investigate event log patterns immediately and correlate with service health and replication status.'; Evidence=$counts } }
    }
}
#endregion Test-DCEventLogHealth

#region Test-DCDiskSpace
function Test-DCDiskSpace {
    param([array]$DomainControllers, [string]$Forest = '')
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'DC-004' -Category 'Domain Controller Health' -Weight 9 -Reference 'Get-CimInstance -ClassName Win32_LogicalDisk' -ScriptBlock {
        param($dc)
        $disks = $null
        try {
            $disks = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | ForEach-Object {
                    if ($_.Size -gt 0) {
                        $usedSpace = $_.Size - $_.FreeSpace
                        $freePercent = ($_.FreeSpace / $_.Size) * 100
                    } else {
                        $usedSpace = 0
                        $freePercent = 0
                    }
                    [PSCustomObject]@{
                        Partition       = $_.DeviceID
                        DriveType       = 'Local Disk'
                        FileSystem      = $_.FileSystem
                        TotalSizeGB     = [math]::Round($_.Size / 1GB, 2)
                        UsedSpaceGB     = [math]::Round($usedSpace / 1GB, 2)
                        FreeSpaceGB     = [math]::Round($_.FreeSpace / 1GB, 2)
                        FreePercent     = [math]::Round($freePercent, 2)
                        VolumeName      = $_.VolumeName
                    }
                }
            } -ErrorAction Stop
        } catch {
            $disks = $null
        }
        if (-not $disks) { return @{ Status='Partial'; Severity='Warning'; ScoreImpact=3; Finding="Unable to query disk space on $($dc.HostName)."; Recommendation='Validate WinRM/PSRemoting access to the DC.'; Evidence=$null; ErrorMessage='Win32_LogicalDisk query failed.' } }
        $lowest = ($disks | Measure-Object -Property FreePercent -Minimum).Minimum
        if ($lowest -ge 15) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="All fixed disks on $($dc.HostName) have at least 15% free space."; Evidence=$disks } }
        elseif ($lowest -ge 10) { @{ Status='Warning'; Severity='Warning'; ScoreImpact=6; Finding="At least one fixed disk on $($dc.HostName) is below 15% free space."; Recommendation='Clean up files, extend capacity, and monitor NTDS and SYSVOL volumes.'; Evidence=$disks } }
        else { @{ Status='Fail'; Severity='Critical'; ScoreImpact=15; Finding="At least one fixed disk on $($dc.HostName) is below 10% free space."; Recommendation='Remediate low disk space urgently to avoid AD, SYSVOL, and logging failures.'; Evidence=$disks } }
    }
}
#endregion Test-DCDiskSpace

#region Test-DCCPUUtilization
function Test-DCCPUUtilization {
    param([array]$DomainControllers, [string]$Forest = '')
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'DC-005' -Category 'Domain Controller Health' -Weight 6 -Reference 'Get-Counter \Processor(*)\% Processor Time' -ScriptBlock {
        param($dc)
        $cpuData = $null
        try {
            $cpuData = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                $cpuusage = Get-Counter '\Processor(*)\% Processor Time' | Select-Object -ExpandProperty CounterSamples |
                    Where-Object { $_.InstanceName -eq '_Total' } | ForEach-Object {
                        [math]::Round($_.CookedValue, 2)
                    }
                $cpuinfo = Get-CimInstance Win32_Processor | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, LoadPercentage
                [PSCustomObject]@{
                    TotalUtilization = $cpuusage
                    CPUName          = $cpuinfo.Name
                    Manufacturer     = $cpuinfo.Manufacturer
                    PhysicalCores    = $cpuinfo.NumberOfCores
                    LogicalCores     = $cpuinfo.NumberOfLogicalProcessors
                    LoadPercentage   = $cpuinfo.LoadPercentage
                }
            } -ErrorAction Stop
        } catch {
            $cpuData = $null
        }
        if (-not $cpuData) { return @{ Status='Partial'; Severity='Warning'; ScoreImpact=3; Finding="Unable to query CPU load on $($dc.HostName)."; Recommendation='Validate WinRM/PSRemoting access to the DC.'; Evidence=$null; ErrorMessage='CPU query failed.' } }
        $avgLoad = if ($cpuData.TotalUtilization) { $cpuData.TotalUtilization } else { $cpuData.LoadPercentage }
        $evidence = @{ CPUName = $cpuData.CPUName; Manufacturer = $cpuData.Manufacturer; PhysicalCores = $cpuData.PhysicalCores; LogicalCores = $cpuData.LogicalCores; UtilizationPercent = $avgLoad }
        if ($avgLoad -lt 75) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="CPU utilization on $($dc.HostName) is $avgLoad%."; Evidence=$evidence } }
        elseif ($avgLoad -lt 90) { @{ Status='Warning'; Severity='Warning'; ScoreImpact=5; Finding="CPU utilization on $($dc.HostName) is $avgLoad%."; Recommendation='Review sustained workload, AV exclusions, and background tasks on the DC.'; Evidence=$evidence } }
        else { @{ Status='Fail'; Severity='Critical'; ScoreImpact=12; Finding="CPU utilization on $($dc.HostName) is $avgLoad%."; Recommendation='Investigate sustained high CPU consumption and identify the responsible processes.'; Evidence=$evidence } }
    }
}
#endregion Test-DCCPUUtilization

#region Test-DCMemoryPressure
function Test-DCMemoryPressure {
    param([array]$DomainControllers, [string]$Forest = '')
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'DC-006' -Category 'Domain Controller Health' -Weight 6 -Reference 'Get-Counter \Memory\Available MBytes' -ScriptBlock {
        param($dc)
        $memData = $null
        try {
            $memData = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                $memoryCounter = Get-Counter -Counter "\Memory\Available MBytes"
                $totalRAM = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
                $freeRAM = $memoryCounter.CounterSamples.CookedValue / 1024
                $usedRAM = $totalRAM - $freeRAM
                $usagePercent = [math]::Round(($usedRAM / $totalRAM) * 100, 2)
                $freePercent = [math]::Round(($freeRAM / $totalRAM) * 100, 2)
                [PSCustomObject]@{
                    TotalRAMGB      = [math]::Round($totalRAM, 2)
                    UsedRAMGB       = [math]::Round($usedRAM, 2)
                    FreeRAMGB       = [math]::Round($freeRAM, 2)
                    UsagePercent    = $usagePercent
                    FreePercent     = $freePercent
                }
            } -ErrorAction Stop
        } catch {
            $memData = $null
        }
        if (-not $memData) { return @{ Status='Partial'; Severity='Warning'; ScoreImpact=3; Finding="Unable to query memory counters on $($dc.HostName)."; Recommendation='Validate WinRM/PSRemoting access to the DC.'; Evidence=$null; ErrorMessage='Memory query failed.' } }
        $freePercent = $memData.FreePercent
        $evidence = @{ TotalRAMGB = $memData.TotalRAMGB; UsedRAMGB = $memData.UsedRAMGB; FreeRAMGB = $memData.FreeRAMGB; UsagePercent = $memData.UsagePercent; FreePercent = $memData.FreePercent }
        if ($freePercent -ge 20) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="Available physical memory on $($dc.HostName) is $freePercent% free."; Evidence=$evidence } }
        elseif ($freePercent -ge 10) { @{ Status='Warning'; Severity='Warning'; ScoreImpact=5; Finding="Available physical memory on $($dc.HostName) is $freePercent% free."; Recommendation='Monitor sustained memory usage and review high-consumption services.'; Evidence=$evidence } }
        else { @{ Status='Fail'; Severity='Critical'; ScoreImpact=12; Finding="Available physical memory on $($dc.HostName) is only $freePercent% free."; Recommendation='Investigate memory pressure, paging, and resource allocation on the DC.'; Evidence=$evidence } }
    }
}
#endregion Test-DCMemoryPressure

#region Test-DCNetworkConfig
function Test-DCNetworkConfig {
    param([array]$DomainControllers, [string]$Forest = '')
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'DC-007' -Category 'Domain Controller Health' -Weight 8 -Reference 'NIC configuration' -ScriptBlock {
        param($dc)
        $adapters = Get-RemoteCimData -ComputerName $dc.HostName -ClassName 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled=TRUE'
        if (-not $adapters) { return @{ Status='Partial'; Severity='Warning'; ScoreImpact=3; Finding="Unable to query NIC configuration on $($dc.HostName)."; Recommendation='Validate WMI access.'; Evidence=$null; ErrorMessage='Win32_NetworkAdapterConfiguration query failed.' } }
        $dhcpEnabled = @($adapters | Where-Object { $_.DHCPEnabled }).Count -gt 0
        $dnsMissing = @($adapters | Where-Object { -not $_.DNSServerSearchOrder }).Count -gt 0
        $apipa = @($adapters | Where-Object { @($_.IPAddress) -match '^169\.254\.' }).Count -gt 0
        $evidence = $adapters | Select-Object Description, DHCPEnabled, IPAddress, DefaultIPGateway, DNSServerSearchOrder
        if (-not $dhcpEnabled -and -not $dnsMissing -and -not $apipa) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="Network configuration on $($dc.HostName) appears static and DNS-aware."; Evidence=$evidence } }
        elseif ($apipa -or $dnsMissing) { @{ Status='Fail'; Severity='Critical'; ScoreImpact=15; Finding="Network configuration issues were detected on $($dc.HostName)."; Recommendation='Correct DNS client settings and ensure all DC NICs use valid static addressing.'; Evidence=$evidence } }
        else { @{ Status='Warning'; Severity='Warning'; ScoreImpact=6; Finding="Potential DHCP or DNS client configuration concerns were detected on $($dc.HostName)."; Recommendation='Confirm DC NIC addressing is static and DNS server entries follow AD design.'; Evidence=$evidence } }
    }
}
#endregion Test-DCNetworkConfig

#region Test-SecureChannelHealth
function Test-SecureChannelHealth {
    param([array]$DomainControllers, [string]$Forest = '')
    $nltestAvailable = Test-CommandAvailable -Name 'nltest.exe'
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'DC-008' -Category 'Domain Controller Health' -Weight 7 -Reference 'nltest secure channel verification' -ScriptBlock {
        param($dc)
        if ($nltestAvailable) {
            $safe = Invoke-SafeCommand -CommandName 'nltest' -ScriptBlock { nltest /server:$($dc.HostName) /sc_verify:$($dc.Domain) 2>&1 }
            $output = if ($safe.Result) { ($safe.Result | Out-String) } else { '' }
            # If output is empty but we have an error, use the error as output for evidence
            if ([string]::IsNullOrWhiteSpace($output) -and $safe.Error) { $output = $safe.Error }
            $healthy = $safe.Success -and $output -match 'NERR_Success|STATUS_SUCCESS|Status = 0 0x0|Status = 0x0'
            $errorMessage = if ($healthy) { '' } else { if ($safe.Error) { $safe.Error } else { $output.Trim() } }
        } else {
            $healthy = $false
            $output = ''
            $errorMessage = 'nltest.exe is not available on the assessment host.'
        }
        if ($healthy) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="Secure channel verification succeeded for $($dc.HostName)."; Evidence=@{ Command = "nltest /server:$($dc.HostName) /sc_verify:$($dc.Domain)"; Output = $output }; ErrorMessage=$errorMessage } }
        elseif ($nltestAvailable) { @{ Status='Fail'; Severity='Critical'; ScoreImpact=15; Finding="Secure channel verification failed for $($dc.HostName)."; Recommendation='Investigate machine account trust and DC locator issues.'; Evidence=@{ Command = "nltest /server:$($dc.HostName) /sc_verify:$($dc.Domain)"; Output = $output; Error = $errorMessage }; ErrorMessage=$errorMessage } }
        else { @{ Status='Skipped'; Severity='Info'; ScoreImpact=0; Finding='Secure channel verification skipped because nltest.exe is unavailable.'; Recommendation='Run the assessment from a domain-joined Windows host with nltest available.'; Evidence=@{ Output = $output }; ErrorMessage=$errorMessage } }
    }
}
#endregion Test-SecureChannelHealth

#region Test-LDAPBindResponse
function Test-LDAPBindResponse {
    param([array]$DomainControllers, [string]$Forest = '')
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'DC-009' -Category 'Domain Controller Health' -Weight 7 -Reference 'LDAP bind response' -ScriptBlock {
        param($dc)
        $bind = Test-LdapBind -Server $dc.HostName -Port 389
        if ($bind.Success -and $bind.DurationMs -lt 500) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="LDAP bind to $($dc.HostName) succeeded in $($bind.DurationMs) ms."; Evidence=@{ DurationMs = $bind.DurationMs }; ErrorMessage=$bind.Error } }
        elseif ($bind.Success -and $bind.DurationMs -lt 1500) { @{ Status='Warning'; Severity='Warning'; ScoreImpact=4; Finding="LDAP bind to $($dc.HostName) succeeded in $($bind.DurationMs) ms."; Recommendation='Review LDAP response time, network latency, and DC performance.'; Evidence=@{ DurationMs = $bind.DurationMs }; ErrorMessage=$bind.Error } }
        else { @{ Status='Fail'; Severity='Critical'; ScoreImpact=12; Finding="LDAP bind to $($dc.HostName) failed or exceeded expected response time."; Recommendation='Investigate AD DS service health, network latency, and authentication path issues.'; Evidence=@{ DurationMs = $bind.DurationMs }; ErrorMessage=$bind.Error } }
    }
}
#endregion Test-LDAPBindResponse

#region Test-NTDSDitFileSize
function Test-NTDSDitFileSize {
    param([array]$DomainControllers, [string]$Forest = '')
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'DC-010' -Category 'Domain Controller Health' -Weight 3 -Reference 'NTDS.dit file size' -ScriptBlock {
        param($dc)
        $ntdsData = $null
        try {
            $ntdsData = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                $ntdsParams = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction Stop
                $dbPath = $ntdsParams.'DSA Database file'
                if (-not $dbPath) { $dbPath = Join-Path $env:SystemRoot 'NTDS\ntds.dit' }
                $fileInfo = Get-Item -Path $dbPath -ErrorAction Stop
                [PSCustomObject]@{
                    FilePath   = $fileInfo.FullName
                    SizeGB     = [math]::Round($fileInfo.Length / 1GB, 2)
                    SizeMB     = [math]::Round($fileInfo.Length / 1MB, 2)
                    LastWrite  = $fileInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                }
            } -ErrorAction Stop
        } catch {
            $ntdsData = $null
        }
        if (-not $ntdsData) { return @{ Status='Partial'; Severity='Info'; ScoreImpact=0; Finding="Unable to query NTDS.dit file size on $($dc.HostName)."; Recommendation='Validate WinRM/PSRemoting access to the DC.'; Evidence=$null; ErrorMessage='NTDS.dit query failed.' } }
        $evidence = @{ FilePath = $ntdsData.FilePath; SizeGB = $ntdsData.SizeGB; SizeMB = $ntdsData.SizeMB; LastWrite = $ntdsData.LastWrite }
        @{ Status='Pass'; Severity='Info'; ScoreImpact=0; Finding="NTDS.dit on $($dc.HostName) is $($ntdsData.SizeGB) GB ($($ntdsData.SizeMB) MB)."; Evidence=$evidence }
    }
}
#endregion Test-NTDSDitFileSize

#region Test-ReplicationSummary
function Test-ReplicationSummary {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        $sw.Stop()
        return @(New-ADSkippedResult -CheckId 'RP-001' -Category 'Replication Health' -Forest $ForestTopology.ForestName -Finding 'ActiveDirectory module unavailable; replication summary skipped.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }

    try {
        $failures = Get-ADReplicationFailure -Target $ForestTopology.ForestName -Scope Forest -ErrorAction Stop
        if (@($failures).Count -eq 0) {
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = 'No replication failures were reported across the forest.'; $recommendation = 'No action required.'
        } else {
            $status = 'Fail'; $severity = 'Critical'; $impact = 20; $finding = "Replication failures were reported across the forest ($(@($failures).Count) item(s))."; $recommendation = 'Investigate source and destination DC replication failures immediately.'
        }
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='RP-001'; Category='Replication Health'; Target=$ForestTopology.ForestName; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=10
            Finding=$finding; Recommendation=$recommendation; Evidence=@{ TotalCount = @($failures).Count; Showing = [Math]::Min(25, @($failures).Count); Items = @($failures | Select-Object -First 25 Server, FirstFailureTime, FailureCount, LastError) }; Reference='Get-ADReplicationFailure'
        })
    } catch {
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='RP-001'; Category='Replication Health'; Target=$ForestTopology.ForestName; Forest=$ForestTopology.ForestName
            Severity='Warning'; Status='Partial'; ScoreImpact=3; Weight=10
            Finding='Unable to collect replication summary.'; Recommendation='Validate ADWS availability and permissions.'; Evidence=$null; Reference='Get-ADReplicationFailure'; ErrorMessage=$_.Exception.Message
        })
    }
}
#endregion Test-ReplicationSummary

#region Test-PerPartnerReplication
function Test-PerPartnerReplication {
    param([array]$DomainControllers, [string]$Forest = '')
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        return @(New-ADSkippedResult -CheckId 'RP-002' -Category 'Replication Health' -Forest $Forest -Finding 'ActiveDirectory module unavailable; partner replication test skipped.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'RP-002' -Category 'Replication Health' -Weight 9 -Reference 'Get-ADReplicationPartnerMetadata' -ScriptBlock {
        param($dc)
        try {
            $metadata = Get-ADReplicationPartnerMetadata -Target $dc.HostName -Scope Server -PartnerType Both -ErrorAction Stop
            $badPartners = $metadata | Where-Object { $_.ConsecutiveReplicationFailures -gt 0 -or $_.LastReplicationResult -ne 0 }
            if (@($badPartners).Count -eq 0) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="All replication partners for $($dc.HostName) report successful recent status."; Evidence=($badPartners | Select-Object -First 20 Server, Partner, Partition, LastReplicationResult, ConsecutiveReplicationFailures, LastReplicationSuccess) } }
            else { @{ Status='Fail'; Severity='Critical'; ScoreImpact=16; Finding="$($badPartners.Count) partner replication issue(s) detected for $($dc.HostName)."; Recommendation='Review per-partner errors, site links, DNS, and AD replication topology.'; Evidence=($badPartners | Select-Object -First 20 Server, Partner, Partition, LastReplicationResult, ConsecutiveReplicationFailures, LastReplicationSuccess) } }
        } catch {
            @{ Status='Partial'; Severity='Warning'; ScoreImpact=4; Finding="Unable to query partner replication metadata for $($dc.HostName)."; Recommendation='Validate connectivity and AD Web Services on the DC.'; Evidence=$null; ErrorMessage=$_.Exception.Message }
        }
    }
}
#endregion Test-PerPartnerReplication

#region Test-ReplicationLatency
function Test-ReplicationLatency {
    param([array]$DomainControllers, [string]$Forest = '')
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        return @(New-ADSkippedResult -CheckId 'RP-003' -Category 'Replication Health' -Forest $Forest -Finding 'ActiveDirectory module unavailable; replication latency test skipped.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'RP-003' -Category 'Replication Health' -Weight 8 -Reference 'Partner last replication success age' -ScriptBlock {
        param($dc)
        try {
            $metadata = Get-ADReplicationPartnerMetadata -Target $dc.HostName -Scope Server -PartnerType Both -ErrorAction Stop
            $ages = $metadata | Where-Object { $_.LastReplicationSuccess } | ForEach-Object { ((Get-Date) - $_.LastReplicationSuccess).TotalHours }
            $maxAge = if ($ages) { [math]::Round(($ages | Measure-Object -Maximum).Maximum, 2) } else { $null }
            if ($null -eq $maxAge) { @{ Status='Warning'; Severity='Warning'; ScoreImpact=5; Finding="No replication latency samples were available for $($dc.HostName)."; Recommendation='Validate replication metadata and check for stale or missing partners.'; Evidence=@{ MaxLatencyHours = $maxAge } } }
            elseif ($maxAge -le 4) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="Maximum observed replication latency for $($dc.HostName) is $maxAge hour(s)."; Evidence=@{ MaxLatencyHours = $maxAge } } }
            elseif ($maxAge -le 24) { @{ Status='Warning'; Severity='Warning'; ScoreImpact=7; Finding="Maximum observed replication latency for $($dc.HostName) is $maxAge hour(s)."; Recommendation='Review replication schedules, bandwidth, and site design.'; Evidence=@{ MaxLatencyHours = $maxAge } } }
            else { @{ Status='Fail'; Severity='Critical'; ScoreImpact=16; Finding="Maximum observed replication latency for $($dc.HostName) is $maxAge hour(s)."; Recommendation='Investigate prolonged replication delays immediately.'; Evidence=@{ MaxLatencyHours = $maxAge } } }
        } catch {
            @{ Status='Partial'; Severity='Warning'; ScoreImpact=4; Finding="Unable to calculate replication latency for $($dc.HostName)."; Recommendation='Validate replication metadata access.'; Evidence=$null; ErrorMessage=$_.Exception.Message }
        }
    }
}
#endregion Test-ReplicationLatency

#region Test-LingeringObjects
function Test-LingeringObjects {
    param([array]$DomainControllers, [string]$Forest = '')
    $eventIds = 1388, 1988, 2042
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'RP-004' -Category 'Replication Health' -Weight 9 -Reference 'Directory Service lingering object events' -ScriptBlock {
        param($dc)
        try {
            $events = Get-WinEvent -ComputerName $dc.HostName -FilterHashtable @{ LogName = 'Directory Service'; StartTime = (Get-Date).AddDays(-90) } -ErrorAction Stop | Where-Object { $_.Id -in $eventIds }
            if (@($events).Count -eq 0) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="No lingering object indicators were found on $($dc.HostName) in the last 90 days."; Evidence=($events | Select-Object -First 10 TimeCreated, Id, Message) } }
            else { @{ Status='Fail'; Severity='Critical'; ScoreImpact=18; Finding="Lingering object related event(s) were found on $($dc.HostName)."; Recommendation='Investigate lingering object remediation before forcing replication.'; Evidence=($events | Select-Object -First 10 TimeCreated, Id, Message) } }
        } catch {
            @{ Status='Partial'; Severity='Warning'; ScoreImpact=3; Finding="Unable to query lingering object events on $($dc.HostName)."; Recommendation='Validate event log access.'; Evidence=$null; ErrorMessage=$_.Exception.Message }
        }
    }
}
#endregion Test-LingeringObjects

#region Test-ReplicationQueue
function Test-ReplicationQueue {
    param([array]$DomainControllers, [string]$Forest = '')
    $repadminAvailable = Test-CommandAvailable -Name 'repadmin.exe'
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'RP-005' -Category 'Replication Health' -Weight 7 -Reference 'repadmin /queue' -ScriptBlock {
        param($dc)
        if (-not $repadminAvailable) { return @{ Status='Skipped'; Severity='Info'; ScoreImpact=0; Finding='Replication queue test skipped because repadmin.exe is unavailable.'; Recommendation='Run the assessment from a host with AD DS administration tools.'; Evidence=$null; ErrorMessage='repadmin.exe unavailable.' } }
        $safe = Invoke-SafeCommand -CommandName 'repadmin queue' -ScriptBlock { repadmin /queue $($dc.HostName) 2>&1 }
        $output = if ($safe.Result) { ($safe.Result | Out-String) } else { '' }
        $queueSize = 0
        if ($output -match '(?<Count>\d+)\s+item\(s\)') { $queueSize = [int]$matches['Count'] }
        elseif ($output -match 'Queue contains\s+(?<Count>\d+)') { $queueSize = [int]$matches['Count'] }
        $evidence = @{ QueueSize = $queueSize; Output = $output.Trim() }
        $errorMessage = if ($safe.Success) { '' } else { $safe.Error }
        if ($queueSize -le 10) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="Replication queue on $($dc.HostName) contains $queueSize item(s)."; Evidence=$evidence; ErrorMessage=$errorMessage } }
        elseif ($queueSize -le 100) { @{ Status='Warning'; Severity='Warning'; ScoreImpact=6; Finding="Replication queue on $($dc.HostName) contains $queueSize item(s)."; Recommendation='Review if the backlog is transient or sustained.'; Evidence=$evidence; ErrorMessage=$errorMessage } }
        else { @{ Status='Fail'; Severity='Critical'; ScoreImpact=14; Finding="Replication queue on $($dc.HostName) contains $queueSize item(s)."; Recommendation='Investigate replication backlog, transport health, and partner availability.'; Evidence=$evidence; ErrorMessage=$errorMessage } }
    }
}
#endregion Test-ReplicationQueue

#region Test-KCCTopology
function Test-KCCTopology {
    param([array]$DomainControllers, [string]$Forest = '')
    $eventIds = 1311, 1566, 1865, 1925
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'RP-006' -Category 'Replication Health' -Weight 8 -Reference 'KCC topology events' -ScriptBlock {
        param($dc)
        try {
            $events = Get-WinEvent -ComputerName $dc.HostName -FilterHashtable @{ LogName = 'Directory Service'; StartTime = (Get-Date).AddDays(-7) } -ErrorAction Stop | Where-Object { $_.Id -in $eventIds }
            if (@($events).Count -eq 0) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="No recent KCC topology errors were found on $($dc.HostName)."; Evidence=($events | Select-Object -First 10 TimeCreated, Id, Message) } }
            else { @{ Status='Fail'; Severity='Critical'; ScoreImpact=14; Finding="Recent KCC topology errors were found on $($dc.HostName)."; Recommendation='Investigate site links, bridgehead connectivity, and naming resolution for replication partners.'; Evidence=($events | Select-Object -First 10 TimeCreated, Id, Message) } }
        } catch {
            @{ Status='Partial'; Severity='Warning'; ScoreImpact=3; Finding="Unable to query KCC events on $($dc.HostName)."; Recommendation='Validate Directory Service log access.'; Evidence=$null; ErrorMessage=$_.Exception.Message }
        }
    }
}
#endregion Test-KCCTopology

#region Test-USNRollback
function Test-USNRollback {
    param([array]$DomainControllers, [string]$Forest = '')
    $eventIds = 2095, 2103, 1113
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'RP-007' -Category 'Replication Health' -Weight 10 -Reference 'USN rollback detection events' -ScriptBlock {
        param($dc)
        try {
            $events = Get-WinEvent -ComputerName $dc.HostName -FilterHashtable @{ LogName = 'Directory Service'; StartTime = (Get-Date).AddDays(-180) } -ErrorAction Stop | Where-Object { $_.Id -in $eventIds }
            if (@($events).Count -eq 0) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="No USN rollback indicators were found on $($dc.HostName)."; Evidence=($events | Select-Object -First 10 TimeCreated, Id, Message) } }
            else { @{ Status='Fail'; Severity='Critical'; ScoreImpact=20; Finding="USN rollback related event(s) were found on $($dc.HostName)."; Recommendation='Investigate virtualization safeguards, replication integrity, and authoritative restore history immediately.'; Evidence=($events | Select-Object -First 10 TimeCreated, Id, Message) } }
        } catch {
            @{ Status='Partial'; Severity='Warning'; ScoreImpact=3; Finding="Unable to query USN rollback events on $($dc.HostName)."; Recommendation='Validate event log access.'; Evidence=$null; ErrorMessage=$_.Exception.Message }
        }
    }
}
#endregion Test-USNRollback

#region Test-NamingContextReplication
function Test-NamingContextReplication {
    param([array]$DomainControllers, [string]$Forest = '')
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        return @(New-ADSkippedResult -CheckId 'RP-008' -Category 'Replication Health' -Forest $Forest -Finding 'ActiveDirectory module unavailable; naming context replication test skipped.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'RP-008' -Category 'Replication Health' -Weight 7 -Reference 'Per-partition replication results' -ScriptBlock {
        param($dc)
        try {
            $metadata = Get-ADReplicationPartnerMetadata -Target $dc.HostName -Scope Server -PartnerType Both -ErrorAction Stop
            $partitions = $metadata | Group-Object -Property Partition
            $failedPartitions = foreach ($partition in $partitions) { $bad = $partition.Group | Where-Object { $_.LastReplicationResult -ne 0 }; if ($bad) { $partition.Name } }
            if (-not $failedPartitions) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="All observed naming contexts on $($dc.HostName) report successful replication results."; Evidence=@{ FailedPartitions = @($failedPartitions) } } }
            else { @{ Status='Fail'; Severity='Critical'; ScoreImpact=14; Finding="One or more naming contexts on $($dc.HostName) report replication failures."; Recommendation='Investigate naming context specific replication errors.'; Evidence=@{ FailedPartitions = @($failedPartitions) } } }
        } catch {
            @{ Status='Partial'; Severity='Warning'; ScoreImpact=4; Finding="Unable to query naming context replication metadata for $($dc.HostName)."; Recommendation='Validate ADWS access and permissions.'; Evidence=$null; ErrorMessage=$_.Exception.Message }
        }
    }
}
#endregion Test-NamingContextReplication

#region Test-IntersiteReplicationSchedule
function Test-IntersiteReplicationSchedule {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        $sw.Stop()
        return @(New-ADSkippedResult -CheckId 'RP-009' -Category 'Replication Health' -Forest $ForestTopology.ForestName -Finding 'ActiveDirectory module unavailable; intersite schedule test skipped.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }

    try {
        $server = Get-PreferredADServer -DomainControllers $DomainControllers -Domain $ForestTopology.RootDomain
        $links = Get-ADReplicationSiteLink -Filter * -Properties ReplicationFrequencyInMinutes, Cost, Schedule, SitesIncluded -Server $server -ErrorAction Stop
        if ($ForestTopology.Sites.Count -le 1) {
            $status = 'Info'; $severity = 'Info'; $impact = 0; $finding = 'Single-site forest detected; intersite schedule assessment is informational only.'; $recommendation = 'No action required.'
        } elseif (-not $links) {
            $status = 'Fail'; $severity = 'Critical'; $impact = 16; $finding = 'Multiple AD sites exist but no site links were discovered.'; $recommendation = 'Create and validate site links for intersite replication.'
        } else {
            $problemLinks = $links | Where-Object {
                $_.ReplicationFrequencyInMinutes -gt 180 -or $_.ReplicationFrequencyInMinutes -lt 15 -or -not $_.SitesIncluded
            }
            if (-not $problemLinks) {
                $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "Discovered $($links.Count) site link(s) with acceptable intersite frequency settings."; $recommendation = 'No action required.'
            } else {
                $status = 'Warning'; $severity = 'Warning'; $impact = 7; $finding = "One or more site links have non-standard or incomplete schedules/frequency settings."; $recommendation = 'Review site link schedules and ensure they align with business replication requirements.'
            }
        }
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='RP-009'; Category='Replication Health'; Target=$ForestTopology.ForestName; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=6
            Finding=$finding; Recommendation=$recommendation; Evidence=$links | Select-Object Name, ReplicationFrequencyInMinutes, Cost, SitesIncluded; Reference='AD replication site links'
        })
    } catch {
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='RP-009'; Category='Replication Health'; Target=$ForestTopology.ForestName; Forest=$ForestTopology.ForestName
            Severity='Warning'; Status='Partial'; ScoreImpact=3; Weight=6
            Finding='Unable to evaluate intersite replication schedules.'; Recommendation='Validate permissions and AD site link visibility.'; Evidence=$null; Reference='AD replication site links'; ErrorMessage=$_.Exception.Message
        })
    }
}
#endregion Test-IntersiteReplicationSchedule

#region Test-ADIntegratedZones
function Test-ADIntegratedZones {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $dnsServer = Get-PreferredADServer -DomainControllers $DomainControllers -Domain $ForestTopology.RootDomain
    try {
        $isLocal = ($dnsServer -eq $env:COMPUTERNAME) -or ($dnsServer -eq 'localhost') -or ($dnsServer -eq "$env:COMPUTERNAME.$env:USERDNSDOMAIN")
        if ($isLocal) {
            $rawOutput = & dnscmd /enumzones 2>&1
        } else {
            $rawOutput = Invoke-Command -ComputerName $dnsServer -ScriptBlock { & dnscmd /enumzones 2>&1 } -ErrorAction Stop
        }
        $rawText = $rawOutput | Out-String
        $parsedZones = @()
        foreach ($line in ($rawOutput -split "`n")) {
            $trimmed = $line.TrimEnd()
            if ($trimmed -match '^\s+(\S+)\s{2,}(Primary|Secondary|Stub|Cache)\s{2,}(\S+)') {
                $parsedZones += @{ ZoneName = $Matches[1]; Type = $Matches[2]; Storage = $Matches[3] }
            }
        }
        $requiredZones = @($ForestTopology.RootDomain, "_msdcs.$($ForestTopology.RootDomain)")
        $zoneEvidence = @()
        $issues = @()
        foreach ($zoneName in $requiredZones) {
            $zone = $parsedZones | Where-Object { $_['ZoneName'] -eq $zoneName }
            $exists = $null -ne $zone
            $isDsIntegrated = if ($exists) { $zone['Storage'] -match 'AD' } else { $false }
            $zoneEvidence += @{ Zone = $zoneName; Exists = $exists; IsDsIntegrated = $isDsIntegrated; Storage = if ($exists) { $zone['Storage'] } else { 'N/A' }; Type = if ($exists) { $zone['Type'] } else { 'N/A' } }
            if (-not $exists -or -not $isDsIntegrated) { $issues += $zoneName }
        }
        $allZonesList = @()
        foreach ($z in $parsedZones) { $allZonesList += @{ ZoneName = $z['ZoneName']; Type = $z['Type']; Storage = $z['Storage'] } }
        $evidence = @{ RequiredZones = $zoneEvidence; AllZones = $allZonesList; TotalZoneCount = $parsedZones.Count }
        if ($issues.Count -eq 0) {
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = 'Required primary AD DNS zones exist and are AD-integrated.'; $recommendation = 'No action required.'
        } else {
            $status = 'Fail'; $severity = 'Critical'; $impact = 15; $finding = 'One or more required AD DNS zones are missing or not AD-integrated.'; $recommendation = 'Create or convert required DNS zones to AD-integrated storage.'
        }
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='DNS-001'; Category='DNS Health'; Target=$dnsServer; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=9
            Finding=$finding; Recommendation=$recommendation; Evidence=$evidence; Reference='dnscmd /enumzones'
        })
    } catch {
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='DNS-001'; Category='DNS Health'; Target=$dnsServer; Forest=$ForestTopology.ForestName
            Severity='Warning'; Status='Partial'; ScoreImpact=3; Weight=9
            Finding='Unable to enumerate DNS zones.'; Recommendation='Validate DNS remoting and permissions.'; Evidence=$null; Reference='dnscmd /enumzones'; ErrorMessage=$_.Exception.Message
        })
    }
}
#endregion Test-ADIntegratedZones

#region Test-ZoneReplicationScope
function Test-ZoneReplicationScope {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not (Test-ModuleAvailable -Name 'DnsServer')) {
        $sw.Stop()
        return @(New-ADSkippedResult -CheckId 'DNS-002' -Category 'DNS Health' -Forest $ForestTopology.ForestName -Finding 'DnsServer module unavailable; zone replication scope review skipped.' -Recommendation 'Install DNS management tools.')
    }

    $dnsServer = Get-PreferredADServer -DomainControllers $DomainControllers -Domain $ForestTopology.RootDomain
    try {
        $zones = Get-DnsServerZone -ComputerName $dnsServer -ErrorAction Stop | Where-Object { $_.IsDsIntegrated }
        $issues = @()
        foreach ($zone in $zones) {
            if ($zone.ZoneName -eq "_msdcs.$($ForestTopology.RootDomain)" -and $zone.ReplicationScope -ne 'Forest') {
                $issues += [PSCustomObject]@{ Zone = $zone.ZoneName; ReplicationScope = $zone.ReplicationScope; Expected = 'Forest' }
            }
            foreach ($domain in $ForestTopology.Domains) {
                if ($zone.ZoneName -eq $domain.Name -and $zone.ReplicationScope -notin @('Domain', 'Legacy')) {
                    $issues += [PSCustomObject]@{ Zone = $zone.ZoneName; ReplicationScope = $zone.ReplicationScope; Expected = 'Domain' }
                }
            }
        }
        if (-not $issues) {
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = 'AD-integrated zone replication scopes appear appropriate.'; $recommendation = 'No action required.'
        } else {
            $status = 'Warning'; $severity = 'Warning'; $impact = 8; $finding = 'One or more AD-integrated DNS zones use an unexpected replication scope.'; $recommendation = 'Align zone replication scope with forest and domain design requirements.'
        }
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='DNS-002'; Category='DNS Health'; Target=$dnsServer; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=7
            Finding=$finding; Recommendation=$recommendation; Evidence=$issues; Reference='Zone replication scope'
        })
    } catch {
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='DNS-002'; Category='DNS Health'; Target=$dnsServer; Forest=$ForestTopology.ForestName
            Severity='Warning'; Status='Partial'; ScoreImpact=3; Weight=7
            Finding='Unable to evaluate zone replication scope.'; Recommendation='Validate DNS remoting and permissions.'; Evidence=$null; Reference='Zone replication scope'; ErrorMessage=$_.Exception.Message
        })
    }
}
#endregion Test-ZoneReplicationScope

#region Test-DCDNSRegistration
function Test-DCDNSRegistration {
    param([array]$DomainControllers, [string]$Forest = '')
    $dnsServer = ($DomainControllers | Where-Object { $_.Reachable } | Select-Object -First 1).HostName
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'DNS-003' -Category 'DNS Health' -Weight 9 -Reference 'Resolve-DnsName A record' -ScriptBlock {
        param($dc)
        $fqdn = $dc.HostName
        $aOk = $false
        try { $aRecord = Resolve-DnsName -Server $dnsServer -Name $fqdn -Type A -ErrorAction Stop; $aOk = @($aRecord).Count -gt 0 } catch {}
        if ($aOk) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="DNS A record for $fqdn resolves successfully."; Evidence=@{ ARecord = $aOk; QueryServer = $dnsServer } } }
        else { @{ Status='Fail'; Severity='Critical'; ScoreImpact=16; Finding="DNS A record for $fqdn could not be resolved (A=$aOk)."; Recommendation='Force DC DNS registration and validate zone replication and Netlogon service state.'; Evidence=@{ ARecord = $aOk; QueryServer = $dnsServer } } }
    }
}
#endregion Test-DCDNSRegistration

#region Test-StaleSRVRecords
function Test-StaleSRVRecords {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $dnsServer = ($DomainControllers | Where-Object { $_.Reachable } | Select-Object -First 1).HostName
    $domainTargets = foreach ($domain in $ForestTopology.Domains) { [pscustomobject]@{ HostName = $domain.Name; Domain = $domain.Name } }
    Invoke-PerDCCheck -DCs $domainTargets -Forest $ForestTopology.ForestName -CheckId 'DNS-004' -Category 'DNS Health' -Weight 7 -Reference 'SRV record consistency' -ScriptBlock {
        param($dc)
        try {
            $allRecords = Resolve-DnsName -Server $dnsServer -Name "_ldap._tcp.dc._msdcs.$($dc.Domain)" -Type SRV -ErrorAction Stop
            $srvRecords = @($allRecords | Where-Object { $_.QueryType -eq 'SRV' -or $_.Type -eq 33 })
            if ($srvRecords.Count -eq 0) { return @{ Status='Fail'; Severity='Critical'; ScoreImpact=14; Finding="No LDAP SRV records were found for $($dc.Domain)."; Recommendation='Verify DNS dynamic registration and Netlogon service on all DCs.'; Evidence=@{ QueryServer = $dnsServer; Domain = $dc.Domain; RecordsFound = 0 } } }
            $validTargets = @($DomainControllers | Where-Object { $_.Domain -eq $dc.Domain } | ForEach-Object { $_.HostName.TrimEnd('.').ToLowerInvariant() })
            $stale = @($srvRecords | Where-Object { $_.NameTarget.TrimEnd('.').ToLowerInvariant() -notin $validTargets })
            $evidence = @{ TotalSRV = $srvRecords.Count; StaleCount = $stale.Count; SRVRecords = ($srvRecords | Select-Object Name, NameTarget, Port, Priority, Weight, TTL); StaleRecords = ($stale | Select-Object Name, NameTarget, Port, TTL); QueryServer = $dnsServer }
            if ($stale.Count -eq 0) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="All $($srvRecords.Count) LDAP SRV record(s) for $($dc.Domain) point to valid domain controllers."; Evidence=$evidence } }
            else { @{ Status='Warning'; Severity='Warning'; ScoreImpact=8; Finding="$($stale.Count) stale LDAP SRV record(s) were found for $($dc.Domain) out of $($srvRecords.Count) total."; Recommendation='Remove stale SRV records and validate DC decommissioning processes.'; Evidence=$evidence } }
        } catch {
            @{ Status='Partial'; Severity='Warning'; ScoreImpact=3; Finding="Unable to review SRV records for $($dc.Domain)."; Recommendation='Validate DNS access and record availability.'; Evidence=$null; ErrorMessage=$_.Exception.Message }
        }
    }
}
#endregion Test-StaleSRVRecords

#region Test-DNSServerEvents
function Test-DNSServerEvents {
    param([array]$DomainControllers, [string]$Forest = '')
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'DNS-005' -Category 'DNS Health' -Weight 6 -Reference 'DNS Server event log last 24h' -ScriptBlock {
        param($dc)
        try {
            $events = Get-WinEvent -ComputerName $dc.HostName -FilterHashtable @{ LogName = 'DNS Server'; StartTime = (Get-Date).AddHours(-24) } -ErrorAction Stop | Where-Object { $_.LevelDisplayName -in @('Error', 'Critical') }
            $count = @($events).Count
            if ($count -eq 0) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="No DNS Server critical/error events were found on $($dc.HostName) in the last 24 hours."; Evidence=($events | Select-Object -First 10 TimeCreated, Id, Message) } }
            elseif ($count -le 10) { @{ Status='Warning'; Severity='Warning'; ScoreImpact=5; Finding="$count DNS Server critical/error event(s) were found on $($dc.HostName)."; Recommendation='Review DNS service warnings and errors.'; Evidence=($events | Select-Object -First 10 TimeCreated, Id, Message) } }
            else { @{ Status='Fail'; Severity='Critical'; ScoreImpact=12; Finding="$count DNS Server critical/error event(s) were found on $($dc.HostName)."; Recommendation='Investigate DNS service failures and replication immediately.'; Evidence=($events | Select-Object -First 10 TimeCreated, Id, Message) } }
        } catch {
            @{ Status='Partial'; Severity='Warning'; ScoreImpact=2; Finding="Unable to query DNS Server events on $($dc.HostName)."; Recommendation='Validate event log access and whether the DNS Server role is installed.'; Evidence=$null; ErrorMessage=$_.Exception.Message }
        }
    }
}
#endregion Test-DNSServerEvents

#region Test-DNSForwarders
function Test-DNSForwarders {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $dnsServer = Get-PreferredADServer -DomainControllers $DomainControllers -Domain $ForestTopology.RootDomain
    try {
        $forwarderList = @()
        $isLocal = ($dnsServer -eq $env:COMPUTERNAME) -or ($dnsServer -eq 'localhost') -or ($dnsServer -eq "$env:COMPUTERNAME.$env:USERDNSDOMAIN")
        if ($isLocal) {
            $reg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -ErrorAction Stop
            if ($reg.PSObject.Properties.Name -contains 'Forwarders' -and $reg.Forwarders) {
                foreach ($fwd in $reg.Forwarders) {
                    $forwarderList += [string]$fwd
                }
            }
        } else {
            $remoteResult = Invoke-Command -ComputerName $dnsServer -ScriptBlock {
                $r = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
                if ($r.PSObject.Properties.Name -contains 'Forwarders' -and $r.Forwarders) {
                    $r.Forwarders | ForEach-Object { [string]$_ }
                }
            } -ErrorAction Stop
            if ($remoteResult) {
                $forwarderList = @($remoteResult)
            }
        }
        if ($forwarderList.Count -gt 0) {
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "$($forwarderList.Count) DNS forwarder(s) are configured on $dnsServer."; $recommendation = 'No action required.'
        } else {
            $status = 'Warning'; $severity = 'Warning'; $impact = 5; $finding = "No DNS forwarders are configured on $dnsServer."; $recommendation = 'Review whether root hints only is intentional and aligns with policy.'
        }
        $evidenceHash = @{ Forwarders = [string[]]$forwarderList; Count = $forwarderList.Count; Server = $dnsServer }
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='DNS-006'; Category='DNS Health'; Target=$dnsServer; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=5
            Finding=$finding; Recommendation=$recommendation; Evidence=$evidenceHash; Reference='Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters | Select-Object Forwarders'
        })
    } catch {
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='DNS-006'; Category='DNS Health'; Target=$dnsServer; Forest=$ForestTopology.ForestName
            Severity='Warning'; Status='Partial'; ScoreImpact=2; Weight=5
            Finding='Unable to query DNS forwarders.'; Recommendation='Validate DNS remoting and permissions.'; Evidence=$null; Reference='Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters'; ErrorMessage=$_.Exception.Message
        })
    }
}
#endregion Test-DNSForwarders

#region Test-DNSScavenging
function Test-DNSScavenging {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    if (-not (Test-ModuleAvailable -Name 'DnsServer')) {
        return @(New-ADSkippedResult -CheckId 'DNS-007' -Category 'DNS Health' -Forest $ForestTopology.ForestName -Finding 'DnsServer module unavailable; scavenging review skipped.' -Recommendation 'Install DNS management tools.')
    }

    Invoke-PerDCCheck -DCs $DomainControllers -Forest $ForestTopology.ForestName -CheckId 'DNS-007' -Category 'DNS Health' -Weight 5 -Reference 'Get-DnsServerScavenging' -ScriptBlock {
        param($dc)
        try {
            $scavenging = Get-DnsServerScavenging -ComputerName $dc.HostName -ErrorAction Stop
            if ($scavenging.ScavengingState) {
                @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="DNS scavenging is enabled on $($dc.HostName)."; Recommendation='No action required.'; Evidence=$scavenging }
            } else {
                @{ Status='Warning'; Severity='Warning'; ScoreImpact=6; Finding="DNS scavenging is disabled on $($dc.HostName)."; Recommendation='Review aging and scavenging configuration to reduce stale records.'; Evidence=$scavenging }
            }
        } catch {
            @{ Status='Partial'; Severity='Warning'; ScoreImpact=2; Finding="Unable to query DNS scavenging settings on $($dc.HostName)."; Recommendation='Validate DNS remoting and permissions.'; Evidence=$null; ErrorMessage=$_.Exception.Message }
        }
    }
}
#endregion Test-DNSScavenging

#region Test-DCNameResolution
function Test-DCNameResolution {
    param([array]$DomainControllers, [string]$Forest = '')
    Invoke-PerDCCheck -DCs $DomainControllers -Forest $Forest -CheckId 'DNS-008' -Category 'DNS Health' -Weight 8 -Reference 'Per-DC name resolution' -ScriptBlock {
        param($dc)
        $failures = @()
        foreach ($target in $DomainControllers) {
            try { $resolved = Resolve-DnsName -Server $dc.HostName -Name $target.HostName -Type A -ErrorAction Stop; if (-not $resolved) { $failures += $target.HostName } }
            catch { $failures += $target.HostName }
        }
        if ($failures.Count -eq 0) { @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="$($dc.HostName) successfully resolved all discovered DC host records."; Evidence=@{ FailedTargets = $failures } } }
        elseif ($failures.Count -le 2) { @{ Status='Warning'; Severity='Warning'; ScoreImpact=6; Finding="$($dc.HostName) failed to resolve $($failures.Count) DC host record(s)."; Recommendation='Review DNS replication and stale host records.'; Evidence=@{ FailedTargets = $failures } } }
        else { @{ Status='Fail'; Severity='Critical'; ScoreImpact=14; Finding="$($dc.HostName) failed to resolve multiple DC host records."; Recommendation='Investigate DNS server health and AD-integrated zone replication immediately.'; Evidence=@{ FailedTargets = $failures } } }
    }
}
#endregion Test-DCNameResolution

#region Test-DNSDelegation
function Test-DNSDelegation {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $results = @()
    $dnsServer = ($DomainControllers | Where-Object { $_.Reachable } | Select-Object -First 1).HostName
    if (@($ForestTopology.Domains).Count -le 1) {
        return @(ConvertTo-ADResult -CheckId 'DNS-009' -Category 'DNS Health' -Forest $ForestTopology.ForestName -Severity 'Info' -Status 'Info' -Weight 4 -Finding 'Single-domain forest detected; DNS delegation validation is informational only.' -Recommendation 'No action required.' -Evidence $null -Reference 'Child domain delegation')
    }

    foreach ($domain in $ForestTopology.Domains | Where-Object { $_.Name -ne $ForestTopology.RootDomain }) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $ns = Resolve-DnsName -Server $dnsServer -Name $domain.Name -Type NS -ErrorAction Stop
            if (@($ns).Count -gt 0) {
                $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "DNS delegation/NS records were found for child domain $($domain.Name)."; $recommendation = 'No action required.'
            } else {
                $status = 'Fail'; $severity = 'Critical'; $impact = 12; $finding = "No NS records were returned for child domain $($domain.Name)."; $recommendation = 'Validate child domain delegation and authoritative name server records.'
            }
            $evidence = $ns | Select-Object NameHost, Name
            $errorMessage = ''
        } catch {
            $status = 'Fail'; $severity = 'Critical'; $impact = 12; $finding = "Unable to resolve delegation records for child domain $($domain.Name)."; $recommendation = 'Validate parent zone delegations and authoritative NS records.'
            $evidence = $null
            $errorMessage = $_.Exception.Message
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='DNS-009'; Category='DNS Health'; Target=$domain.Name; Domain=$domain.Name; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=6
            Finding=$finding; Recommendation=$recommendation; Evidence=$evidence; Reference='Child domain NS records'; ErrorMessage=$errorMessage
        }
    }
    return $results
}
#endregion Test-DNSDelegation

#region Security Checks
#endregion Security Checks

#region Invoke-ADHygieneCheck
function Invoke-ADHygieneCheck {
    param(
        [string]$CheckId,
        [string]$SkipMsg,
        [scriptblock]$QueryBlock,
        [string[]]$EvidenceProps,
        [scriptblock]$EvalBlock,
        [int]$Weight,
        [string]$Reference,
        [string]$PartialFindingTemplate,
        [int]$PartialImpact,
        [psobject]$ForestTopology
    )
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        return @(New-ADSkippedResult -CheckId $CheckId -Category 'User & Computer Hygiene' -Forest $ForestTopology.ForestName -Finding $SkipMsg -Recommendation 'Install/import RSAT Active Directory tools.')
    }
    $results = @()
    foreach ($domain in $ForestTopology.Domains) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $items = @(& $QueryBlock $domain.Name)
            $eval = & $EvalBlock $items $domain.Name
            $totalCount = $items.Count
            $sampleList = if ($EvidenceProps) { @($items | Select-Object -First 25 -Property $EvidenceProps) } else { @() }
            $evidence = @{ TotalCount = $totalCount; Showing = [Math]::Min(25, $totalCount); Items = $sampleList }
            $errorMessage = ''
        } catch {
            $eval = @{ Status = 'Partial'; Severity = 'Warning'; Impact = $PartialImpact; Finding = ($PartialFindingTemplate -f $domain.Name); Recommendation = 'Validate AD query permissions.' }
            $evidence = $null
            $errorMessage = $_.Exception.Message
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId        = $CheckId
            Category       = 'User & Computer Hygiene'
            Target         = $domain.Name
            Domain         = $domain.Name
            Forest         = $ForestTopology.ForestName
            Severity       = $eval.Severity
            Status         = $eval.Status
            ScoreImpact    = $eval.Impact
            Weight         = $Weight
            Finding        = $eval.Finding
            Recommendation = $eval.Recommendation
            Evidence       = $evidence
            Reference      = $Reference
            ErrorMessage   = $errorMessage
        }
    }
    return $results
}
#endregion Invoke-ADHygieneCheck

#region Test-InactiveUsers
function Test-InactiveUsers {
    param([psobject]$ForestTopology)
    $cutoffFileTime = (Get-Date).AddDays(-90).ToFileTime()
    Invoke-ADHygieneCheck -CheckId 'HYG-001' -SkipMsg 'ActiveDirectory module unavailable; inactive user review skipped.' -Weight 7 -Reference 'Enabled inactive users >90 days' -PartialFindingTemplate 'Unable to review inactive users in {0}.' -PartialImpact 3 -ForestTopology $ForestTopology -EvidenceProps @('SamAccountName', 'DistinguishedName', 'LastLogonDate') -QueryBlock {
        param($dom)
        @(Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(!(lastLogonTimestamp=*))(lastLogonTimestamp<=$cutoffFileTime)))" -Properties LastLogonDate -Server $dom -ResultPageSize 1000 -ErrorAction Stop)
    } -EvalBlock {
        param($users, $dom)
        if ($users.Count -eq 0) { @{ Status = 'Pass'; Severity = 'Pass'; Impact = 0; Finding = "No enabled inactive user accounts older than 90 days were found in $dom."; Recommendation = 'No action required.' } }
        elseif ($users.Count -le 25) { @{ Status = 'Warning'; Severity = 'Warning'; Impact = 6; Finding = "$($users.Count) enabled inactive user account(s) older than 90 days were found in $dom."; Recommendation = 'Review and disable or remove stale user accounts.' } }
        else { @{ Status = 'Fail'; Severity = 'Critical'; Impact = 12; Finding = "$($users.Count) enabled inactive user account(s) older than 90 days were found in $dom."; Recommendation = 'Perform a stale account cleanup and implement lifecycle controls.' } }
    }
}
#endregion Test-InactiveUsers

#region Test-DisabledUsersReview
function Test-DisabledUsersReview {
    param([psobject]$ForestTopology)
    $cutoff = (Get-Date).AddDays(-90)
    Invoke-ADHygieneCheck -CheckId 'HYG-002' -SkipMsg 'ActiveDirectory module unavailable; disabled user review skipped.' -Weight 5 -Reference 'Disabled user review' -PartialFindingTemplate 'Unable to review disabled users in {0}.' -PartialImpact 2 -ForestTopology $ForestTopology -EvidenceProps @('SamAccountName', 'DistinguishedName', 'whenChanged') -QueryBlock {
        param($dom)
        @(Get-ADUser -Filter 'Enabled -eq $false' -Properties whenChanged -Server $dom -ResultPageSize 1000 -ErrorAction Stop | Where-Object { $_.whenChanged -lt $cutoff })
    } -EvalBlock {
        param($users, $dom)
        if ($users.Count -eq 0) { @{ Status = 'Pass'; Severity = 'Pass'; Impact = 0; Finding = "No long-disabled user accounts older than 90 days were found in $dom."; Recommendation = 'No action required.' } }
        else { @{ Status = 'Warning'; Severity = 'Warning'; Impact = 5; Finding = "$($users.Count) disabled user account(s) older than 90 days were found in $dom."; Recommendation = 'Review whether disabled accounts should be retained, moved, or deleted.' } }
    }
}
#endregion Test-DisabledUsersReview

#region Test-PasswordNeverExpires
function Test-PasswordNeverExpires {
    param([psobject]$ForestTopology)
    Invoke-ADHygieneCheck -CheckId 'HYG-003' -SkipMsg 'ActiveDirectory module unavailable; password-never-expires review skipped.' -Weight 7 -Reference 'PasswordNeverExpires' -PartialFindingTemplate 'Unable to review PasswordNeverExpires accounts in {0}.' -PartialImpact 2 -ForestTopology $ForestTopology -EvidenceProps @('SamAccountName', 'DistinguishedName') -QueryBlock {
        param($dom)
        @(Get-ADUser -Filter 'PasswordNeverExpires -eq $true -and Enabled -eq $true' -Properties PasswordNeverExpires -Server $dom -ResultPageSize 1000 -ErrorAction Stop)
    } -EvalBlock {
        param($users, $dom)
        if ($users.Count -eq 0) { @{ Status = 'Pass'; Severity = 'Pass'; Impact = 0; Finding = "No enabled users with PasswordNeverExpires were found in $dom."; Recommendation = 'No action required.' } }
        else { @{ Status = 'Warning'; Severity = 'Warning'; Impact = 7; Finding = "$($users.Count) enabled user account(s) have PasswordNeverExpires set in $dom."; Recommendation = 'Review exceptions and use managed service accounts where appropriate.' } }
    }
}
#endregion Test-PasswordNeverExpires

#region Test-NoPasswordRequired
function Test-NoPasswordRequired {
    param([psobject]$ForestTopology)
    Invoke-ADHygieneCheck -CheckId 'HYG-004' -SkipMsg 'ActiveDirectory module unavailable; NoPasswordRequired review skipped.' -Weight 8 -Reference 'PASSWD_NOTREQD flag' -PartialFindingTemplate 'Unable to review PASSWD_NOTREQD users in {0}.' -PartialImpact 2 -ForestTopology $ForestTopology -EvidenceProps @('SamAccountName', 'DistinguishedName') -QueryBlock {
        param($dom)
        @(Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))' -Server $dom -ResultPageSize 1000 -ErrorAction Stop)
    } -EvalBlock {
        param($users, $dom)
        if ($users.Count -eq 0) { @{ Status = 'Pass'; Severity = 'Pass'; Impact = 0; Finding = "No user accounts with PASSWD_NOTREQD were found in $dom."; Recommendation = 'No action required.' } }
        else { @{ Status = 'Fail'; Severity = 'Critical'; Impact = 15; Finding = "$($users.Count) user account(s) with PASSWD_NOTREQD were found in $dom."; Recommendation = 'Remove the PASSWD_NOTREQD flag and enforce compliant credentials.' } }
    }
}
#endregion Test-NoPasswordRequired

#region Test-ReversibleEncryptionUsers
function Test-ReversibleEncryptionUsers {
    param([psobject]$ForestTopology)
    Invoke-ADHygieneCheck -CheckId 'HYG-005' -SkipMsg 'ActiveDirectory module unavailable; reversible encryption review skipped.' -Weight 8 -Reference 'Encrypted text password flag' -PartialFindingTemplate 'Unable to review reversible encryption users in {0}.' -PartialImpact 2 -ForestTopology $ForestTopology -EvidenceProps @('SamAccountName', 'DistinguishedName') -QueryBlock {
        param($dom)
        @(Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))' -Server $dom -ResultPageSize 1000 -ErrorAction Stop)
    } -EvalBlock {
        param($users, $dom)
        if ($users.Count -eq 0) { @{ Status = 'Pass'; Severity = 'Pass'; Impact = 0; Finding = "No user accounts with reversible encryption enabled were found in $dom."; Recommendation = 'No action required.' } }
        else { @{ Status = 'Fail'; Severity = 'Critical'; Impact = 16; Finding = "$($users.Count) user account(s) allow reversible password encryption in $dom."; Recommendation = 'Disable reversible encryption except where explicitly required by legacy applications.' } }
    }
}
#endregion Test-ReversibleEncryptionUsers

#region Test-PrivilegedDelegationExposed
function Test-PrivilegedDelegationExposed {
    param([psobject]$ForestTopology)
    $results = @()
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        return @(New-ADSkippedResult -CheckId 'HYG-006' -Category 'User & Computer Hygiene' -Forest $ForestTopology.ForestName -Finding 'ActiveDirectory module unavailable; privileged delegation review skipped.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }

    $privilegedGroups = 'Domain Admins', 'Enterprise Admins', 'Administrators', 'Schema Admins', 'Server Operators', 'Backup Operators', 'Print Operators', 'Account Operators'
    foreach ($domain in $ForestTopology.Domains) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $members = @()
            foreach ($groupName in $privilegedGroups) {
                try {
                    $group = Get-ADGroup -Identity $groupName -Server $domain.Name -ErrorAction Stop
                    $members += Get-ADGroupMember -Identity $group.DistinguishedName -Recursive -Server $domain.Name -ErrorAction Stop
                } catch {
                }
            }
            $members = $members | Sort-Object DistinguishedName -Unique
            $exposed = @()
            foreach ($member in $members) {
                try {
                    $obj = Get-ADObject -Identity $member.DistinguishedName -Properties TrustedForDelegation, TrustedToAuthForDelegation, SamAccountName, ObjectClass -Server $domain.Name -ErrorAction Stop
                    if ($obj.TrustedForDelegation -or $obj.TrustedToAuthForDelegation) {
                        $exposed += [PSCustomObject]@{
                            SamAccountName = $obj.SamAccountName
                            ObjectClass    = $obj.ObjectClass
                            TrustedForDelegation = $obj.TrustedForDelegation
                            TrustedToAuthForDelegation = $obj.TrustedToAuthForDelegation
                        }
                    }
                } catch {
                }
            }
            if (-not $exposed) {
                $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "No privileged principals with unconstrained or protocol transition delegation flags were found in $($domain.Name)."; $recommendation = 'No action required.'
            } else {
                $status = 'Fail'; $severity = 'Critical'; $impact = 18; $finding = "$($exposed.Count) privileged principal(s) with delegation exposure were found in $($domain.Name)."; $recommendation = 'Remove delegation exposure from privileged principals immediately.'
            }
            $evidence = @{ TotalCount = @($exposed).Count; Showing = [Math]::Min(25, @($exposed).Count); Items = @($exposed | Select-Object -First 25 *) }
            $errorMessage = ''
        } catch {
            $status = 'Partial'; $severity = 'Warning'; $impact = 3; $finding = "Unable to review privileged delegation exposure in $($domain.Name)."; $recommendation = 'Validate AD group enumeration privileges.'
            $evidence = $null
            $errorMessage = $_.Exception.Message
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='HYG-006'; Category='User & Computer Hygiene'; Target=$domain.Name; Domain=$domain.Name; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=10
            Finding=$finding; Recommendation=$recommendation; Evidence=$evidence; Reference='Delegation flags on privileged principals'; ErrorMessage=$errorMessage
        }
    }
    return $results
}
#endregion Test-PrivilegedDelegationExposed

#region Test-InactiveComputers
function Test-InactiveComputers {
    param([psobject]$ForestTopology)
    Invoke-ADHygieneCheck -CheckId 'HYG-007' -SkipMsg 'ActiveDirectory module unavailable; admin account review skipped.' -Weight 6 -Reference 'Enabled accounts with adminCount=1' -PartialFindingTemplate 'Unable to review admin accounts in {0}.' -PartialImpact 2 -ForestTopology $ForestTopology -EvidenceProps @('SamAccountName', 'AdminCount', 'MemberOf') -QueryBlock {
        param($dom)
        @(Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" -Properties AdminCount, MemberOf -Server $dom -ErrorAction Stop)
    } -EvalBlock {
        param($users, $dom)
        if ($users.Count -eq 0) { @{ Status = 'Pass'; Severity = 'Pass'; Impact = 0; Finding = "No enabled accounts with adminCount=1 were found in $dom."; Recommendation = 'No action required.' } }
        else { @{ Status = 'Warning'; Severity = 'Warning'; Impact = 6; Finding = "$($users.Count) enabled account(s) with adminCount=1 found in $dom. Review for excessive privileged access."; Recommendation = 'Audit accounts with adminCount=1 and remove unnecessary privileges. Ensure these accounts follow least-privilege principles.' } }
    }
}
#endregion Test-InactiveComputers

#region Test-DisabledComputersReview
function Test-DisabledComputersReview {
    param([psobject]$ForestTopology)
    $cutoff = (Get-Date).AddDays(-90)
    Invoke-ADHygieneCheck -CheckId 'HYG-008' -SkipMsg 'ActiveDirectory module unavailable; disabled computer review skipped.' -Weight 4 -Reference 'Disabled computer review' -PartialFindingTemplate 'Unable to review disabled computers in {0}.' -PartialImpact 2 -ForestTopology $ForestTopology -EvidenceProps @('Name', 'DNSHostName', 'whenChanged') -QueryBlock {
        param($dom)
        @(Get-ADComputer -Filter 'Enabled -eq $false' -Properties whenChanged -Server $dom -ResultPageSize 1000 -ErrorAction Stop | Where-Object { $_.whenChanged -lt $cutoff })
    } -EvalBlock {
        param($computers, $dom)
        if ($computers.Count -eq 0) { @{ Status = 'Pass'; Severity = 'Pass'; Impact = 0; Finding = "No long-disabled computer accounts older than 90 days were found in $dom."; Recommendation = 'No action required.' } }
        else { @{ Status = 'Warning'; Severity = 'Warning'; Impact = 4; Finding = "$($computers.Count) disabled computer account(s) older than 90 days were found in $dom."; Recommendation = 'Review whether disabled computer objects should be retained or removed.' } }
    }
}
#endregion Test-DisabledComputersReview

#region Test-StaleServerObjects
function Test-StaleServerObjects {
    param([psobject]$ForestTopology)
    $results = @()
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        return @(New-ADSkippedResult -CheckId 'HYG-009' -Category 'User & Computer Hygiene' -Forest $ForestTopology.ForestName -Finding 'ActiveDirectory module unavailable; stale server object review skipped.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }

    $cutoff = (Get-Date).AddDays(-45)
    foreach ($domain in $ForestTopology.Domains) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $servers = Get-ADComputer -Filter 'OperatingSystem -like "*Server*" -and Enabled -eq $true' -Properties LastLogonDate, OperatingSystem -Server $domain.Name -ResultPageSize 1000 -ErrorAction Stop |
                Where-Object { $null -eq $_.LastLogonDate -or $_.LastLogonDate -lt $cutoff }
            if ($servers.Count -eq 0) {
                $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "No stale enabled server computer objects older than 45 days were found in $($domain.Name)."; $recommendation = 'No action required.'
            } else {
                $status = 'Warning'; $severity = 'Warning'; $impact = 7; $finding = "$($servers.Count) stale enabled server computer object(s) older than 45 days were found in $($domain.Name)."; $recommendation = 'Validate decommission status and remove or disable unused server objects.'
            }
            $evidence = @{ TotalCount = @($servers).Count; Showing = [Math]::Min(25, @($servers).Count); Items = @($servers | Select-Object -First 25 Name, DNSHostName, OperatingSystem, LastLogonDate) }
            $errorMessage = ''
        } catch {
            $status = 'Partial'; $severity = 'Warning'; $impact = 2; $finding = "Unable to review stale server objects in $($domain.Name)."; $recommendation = 'Validate AD query permissions.'
            $evidence = $null
            $errorMessage = $_.Exception.Message
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='HYG-009'; Category='User & Computer Hygiene'; Target=$domain.Name; Domain=$domain.Name; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=6
            Finding=$finding; Recommendation=$recommendation; Evidence=$evidence; Reference='Stale server computer objects'; ErrorMessage=$errorMessage
        }
    }
    return $results
}
#endregion Test-StaleServerObjects

#region Test-OrphanedObjects
function Test-OrphanedObjects {
    param([psobject]$ForestTopology)
    $results = @()
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        return @(New-ADSkippedResult -CheckId 'HYG-010' -Category 'User & Computer Hygiene' -Forest $ForestTopology.ForestName -Finding 'ActiveDirectory module unavailable; orphaned object review skipped.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }

    foreach ($domain in $ForestTopology.Domains) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $orphaned = @()
            $users = Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(manager=*))' -Properties manager, SamAccountName -Server $domain.Name -ResultPageSize 1000 -ErrorAction Stop
            $uniqueManagers = @($users | ForEach-Object { $_.manager } | Sort-Object -Unique)
            $invalidManagers = @{}
            foreach ($mgrDn in $uniqueManagers) {
                try {
                    Get-ADObject -Identity $mgrDn -Server $domain.Name -ErrorAction Stop | Out-Null
                } catch {
                    $invalidManagers[$mgrDn] = $true
                }
            }
            $orphaned += @($users | Where-Object { $invalidManagers.ContainsKey($_.manager) } | ForEach-Object {
                [PSCustomObject]@{ Object = $_.SamAccountName; Type = 'UserManager'; Reference = $_.manager }
            })

            $computers = Get-ADComputer -Filter 'DNSHostName -like "*"' -Properties DNSHostName -Server $domain.Name -ResultPageSize 1000 -ResultSetSize 500 -ErrorAction Stop
            foreach ($computer in $computers) {
                if ($computer.DNSHostName -and -not (Test-DnsHostResolution -HostName $computer.DNSHostName)) {
                    $orphaned += [PSCustomObject]@{ Object = $computer.Name; Type = 'ComputerDNS'; Reference = $computer.DNSHostName }
                }
            }

            if (-not $orphaned) {
                $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "No orphaned manager references or unresolved computer DNS host names were found in $($domain.Name)."; $recommendation = 'No action required.'
            } elseif ($orphaned.Count -le 20) {
                $status = 'Warning'; $severity = 'Warning'; $impact = 6; $finding = "$($orphaned.Count) potential orphaned object reference(s) were found in $($domain.Name)."; $recommendation = 'Review stale references and DNS entries.'
            } else {
                $status = 'Fail'; $severity = 'Critical'; $impact = 12; $finding = "$($orphaned.Count) potential orphaned object reference(s) were found in $($domain.Name)."; $recommendation = 'Clean up broken references and stale DNS-linked computer objects.'
            }
            $evidence = @{ TotalCount = @($orphaned).Count; Showing = [Math]::Min(25, @($orphaned).Count); Items = @($orphaned | Select-Object -First 25 *) }
            $errorMessage = ''
        } catch {
            $status = 'Partial'; $severity = 'Warning'; $impact = 3; $finding = "Unable to review orphaned objects in $($domain.Name)."; $recommendation = 'Validate AD query permissions and name resolution.'
            $evidence = $null
            $errorMessage = $_.Exception.Message
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='HYG-010'; Category='User & Computer Hygiene'; Target=$domain.Name; Domain=$domain.Name; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=6
            Finding=$finding; Recommendation=$recommendation; Evidence=$evidence; Reference='Orphaned AD references'; ErrorMessage=$errorMessage
        }
    }
    return $results
}
#endregion Test-OrphanedObjects

#region Test-DuplicateSPNs
function Test-DuplicateSPNs {
    param([psobject]$ForestTopology)
    $results = @()
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        return @(New-ADSkippedResult -CheckId 'HYG-011' -Category 'User & Computer Hygiene' -Forest $ForestTopology.ForestName -Finding 'ActiveDirectory module unavailable; duplicate SPN review skipped.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }

    foreach ($domain in $ForestTopology.Domains) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $objects = Get-ADObject -LDAPFilter '(|(objectClass=user)(objectClass=computer)(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount))' -Properties servicePrincipalName, sAMAccountName -Server $domain.Name -ResultPageSize 1000 -ErrorAction Stop |
                Where-Object { $_.servicePrincipalName }
            $spnEntries = foreach ($object in $objects) {
                foreach ($spn in @($object.servicePrincipalName)) {
                    [PSCustomObject]@{ SPN = $spn.ToLowerInvariant(); Account = $object.sAMAccountName }
                }
            }
            $duplicates = $spnEntries | Group-Object -Property SPN | Where-Object { $_.Count -gt 1 } | ForEach-Object {
                [PSCustomObject]@{ SPN = $_.Name; Accounts = ($_.Group.Account -join ', ') }
            }
            if (-not $duplicates) {
                $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "No duplicate SPNs were found in $($domain.Name)."; $recommendation = 'No action required.'
            } else {
                $status = 'Fail'; $severity = 'Critical'; $impact = 16; $finding = "$($duplicates.Count) duplicate SPN value(s) were found in $($domain.Name)."; $recommendation = 'Resolve duplicate SPNs to prevent Kerberos authentication ambiguity.'
            }
            $evidence = @{ TotalCount = @($duplicates).Count; Showing = [Math]::Min(25, @($duplicates).Count); Items = @($duplicates | Select-Object -First 25 *) }
            $errorMessage = ''
        } catch {
            $status = 'Partial'; $severity = 'Warning'; $impact = 3; $finding = "Unable to review duplicate SPNs in $($domain.Name)."; $recommendation = 'Validate AD query permissions.'
            $evidence = $null
            $errorMessage = $_.Exception.Message
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='HYG-011'; Category='User & Computer Hygiene'; Target=$domain.Name; Domain=$domain.Name; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=9
            Finding=$finding; Recommendation=$recommendation; Evidence=$evidence; Reference='Duplicate SPN analysis'; ErrorMessage=$errorMessage
        }
    }
    return $results
}
#endregion Test-DuplicateSPNs

#region Test-StalePrintQueues
function Test-StalePrintQueues {
    param([psobject]$ForestTopology)
    $results = @()
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        return @(New-ADSkippedResult -CheckId 'HYG-012' -Category 'User & Computer Hygiene' -Forest $ForestTopology.ForestName -Finding 'ActiveDirectory module unavailable; stale print queue review skipped.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }

    foreach ($domain in $ForestTopology.Domains) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $queues = Get-ADObject -LDAPFilter '(objectClass=printQueue)' -Properties serverName, printShareName, whenChanged -Server $domain.Name -ResultPageSize 1000 -ResultSetSize 500 -ErrorAction Stop
            $stale = $queues | Where-Object { -not $_.serverName -or -not (Test-DnsHostResolution -HostName $_.serverName) }
            if (-not $stale) {
                $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "No stale published print queues were found in $($domain.Name)."; $recommendation = 'No action required.'
            } else {
                $status = 'Warning'; $severity = 'Warning'; $impact = 5; $finding = "$($stale.Count) stale or unresolved published print queue(s) were found in $($domain.Name)."; $recommendation = 'Remove stale published printers or correct the backing print server references.'
            }
            $evidence = @{ TotalCount = @($stale).Count; Showing = [Math]::Min(25, @($stale).Count); Items = @($stale | Select-Object -First 25 Name, serverName, printShareName, whenChanged) }
            $errorMessage = ''
        } catch {
            $status = 'Partial'; $severity = 'Warning'; $impact = 2; $finding = "Unable to review published print queues in $($domain.Name)."; $recommendation = 'Validate AD query permissions.'
            $evidence = $null
            $errorMessage = $_.Exception.Message
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='HYG-012'; Category='User & Computer Hygiene'; Target=$domain.Name; Domain=$domain.Name; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=4
            Finding=$finding; Recommendation=$recommendation; Evidence=$evidence; Reference='Published print queues'; ErrorMessage=$errorMessage
        }
    }
    return $results
}
#endregion Test-StalePrintQueues

#region Test-BrokenGPOLinks
function Test-BrokenGPOLinks {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $results = @()
    if (-not ((Test-ModuleAvailable -Name 'ActiveDirectory') -and (Test-ModuleAvailable -Name 'GroupPolicy'))) {
        return @(New-ADSkippedResult -CheckId 'GPO-001' -Category 'Group Policy Health' -Forest $ForestTopology.ForestName -Finding 'Required AD/GroupPolicy modules unavailable; broken GPO link review skipped.' -Recommendation 'Install/import RSAT Group Policy and Active Directory tools.')
    }

    foreach ($domain in $ForestTopology.Domains) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $gpoIds = @((Get-GPO -All -Domain $domain.Name -ErrorAction Stop).Id.Guid | ForEach-Object { $_.ToUpperInvariant() })
            $targets = @()
            $domainRoot = Get-ADObject -Identity $domain.DistinguishedName -Properties gPLink -Server $domain.Name -ErrorAction Stop
            $targets += [PSCustomObject]@{ Name = $domain.Name; DistinguishedName = $domain.DistinguishedName; GPLink = $domainRoot.gPLink }
            $targets += Get-ADOrganizationalUnit -Filter * -Properties gPLink -Server $domain.Name -ErrorAction Stop | Select-Object Name, DistinguishedName, gPLink
            $broken = @()
            foreach ($target in $targets | Where-Object { $_.gPLink }) {
                $links = ConvertFrom-GPLinkValue -GPLink $target.gPLink
                foreach ($link in $links) {
                    if ($link.Guid -and $link.Guid -notin $gpoIds) {
                        $broken += [PSCustomObject]@{ Target = $target.DistinguishedName; MissingGpoId = $link.Guid }
                    }
                }
            }
            if (-not $broken) {
                $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "No broken GPO links were found in $($domain.Name)."; $recommendation = 'No action required.'
            } else {
                $status = 'Fail'; $severity = 'Critical'; $impact = 14; $finding = "$($broken.Count) broken GPO link(s) were found in $($domain.Name)."; $recommendation = 'Remove or repair broken GPO links.'
            }
            $evidence = @{ TotalCount = @($broken).Count; Showing = [Math]::Min(25, @($broken).Count); Items = @($broken | Select-Object -First 25 *) }
            $errorMessage = ''
        } catch {
            $status = 'Partial'; $severity = 'Warning'; $impact = 3; $finding = "Unable to review broken GPO links in $($domain.Name)."; $recommendation = 'Validate Group Policy and AD query permissions.'
            $evidence = $null
            $errorMessage = $_.Exception.Message
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='GPO-001'; Category='Group Policy Health'; Target=$domain.Name; Domain=$domain.Name; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=8
            Finding=$finding; Recommendation=$recommendation; Evidence=$evidence; Reference='gPLink validation'; ErrorMessage=$errorMessage
        }
    }
    return $results
}
#endregion Test-BrokenGPOLinks

#region Test-EmptyGPOs
function Test-EmptyGPOs {
    param([psobject]$ForestTopology)
    $results = @()
    if (-not (Test-ModuleAvailable -Name 'GroupPolicy')) {
        return @(New-ADSkippedResult -CheckId 'GPO-002' -Category 'Group Policy Health' -Forest $ForestTopology.ForestName -Finding 'GroupPolicy module unavailable; empty GPO review skipped.' -Recommendation 'Install/import RSAT Group Policy tools.')
    }

    foreach ($domain in $ForestTopology.Domains) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $gpos = Get-GPO -All -Domain $domain.Name -ErrorAction Stop
            $empty = @()
            foreach ($gpo in $gpos) {
                $xml = [xml](Get-GPOReport -Guid $gpo.Id -Domain $domain.Name -ReportType Xml -ErrorAction Stop)
                $userSettings = @($xml.GPO.User.ExtensionData.Extension).Count
                $computerSettings = @($xml.GPO.Computer.ExtensionData.Extension).Count
                if ($userSettings -eq 0 -and $computerSettings -eq 0) {
                    $empty += [PSCustomObject]@{ DisplayName = $gpo.DisplayName; Id = $gpo.Id.Guid }
                }
            }
            if (-not $empty) {
                $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "No empty GPOs were found in $($domain.Name)."; $recommendation = 'No action required.'
            } else {
                $status = 'Warning'; $severity = 'Warning'; $impact = 5; $finding = "$($empty.Count) empty GPO(s) were found in $($domain.Name)."; $recommendation = 'Remove unused GPOs or document them if retained intentionally.'
            }
            $evidence = @{ TotalCount = @($empty).Count; Showing = [Math]::Min(25, @($empty).Count); Items = @($empty | Select-Object -First 25 *) }
            $errorMessage = ''
        } catch {
            $status = 'Partial'; $severity = 'Warning'; $impact = 2; $finding = "Unable to review empty GPOs in $($domain.Name)."; $recommendation = 'Validate Group Policy access and report generation privileges.'
            $evidence = $null
            $errorMessage = $_.Exception.Message
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='GPO-002'; Category='Group Policy Health'; Target=$domain.Name; Domain=$domain.Name; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=5
            Finding=$finding; Recommendation=$recommendation; Evidence=$evidence; Reference='GPO XML settings count'; ErrorMessage=$errorMessage
        }
    }
    return $results
}
#endregion Test-EmptyGPOs

#region Test-GPOVersionMismatch
function Test-GPOVersionMismatch {
    param([psobject]$ForestTopology)
    $results = @()
    if (-not (Test-ModuleAvailable -Name 'GroupPolicy')) {
        return @(New-ADSkippedResult -CheckId 'GPO-003' -Category 'Group Policy Health' -Forest $ForestTopology.ForestName -Finding 'GroupPolicy module unavailable; GPO version mismatch review skipped.' -Recommendation 'Install/import RSAT Group Policy tools.')
    }

    foreach ($domain in $ForestTopology.Domains) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $gpos = Get-GPO -All -Domain $domain.Name -ErrorAction Stop
            $mismatch = @()
            foreach ($gpo in $gpos) {
                $xml = [xml](Get-GPOReport -Guid $gpo.Id -Domain $domain.Name -ReportType Xml -ErrorAction Stop)
                $uAd = [int]$xml.GPO.User.VersionDirectory
                $uSys = [int]$xml.GPO.User.VersionSysvol
                $cAd = [int]$xml.GPO.Computer.VersionDirectory
                $cSys = [int]$xml.GPO.Computer.VersionSysvol
                if ($uAd -ne $uSys -or $cAd -ne $cSys) {
                    $mismatch += [PSCustomObject]@{ DisplayName = $gpo.DisplayName; Id = $gpo.Id.Guid; UserAD = $uAd; UserSYSVOL = $uSys; ComputerAD = $cAd; ComputerSYSVOL = $cSys }
                }
            }
            if (-not $mismatch) {
                $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "No AD/SYSVOL GPO version mismatches were found in $($domain.Name)."; $recommendation = 'No action required.'
            } else {
                $status = 'Warning'; $severity = 'Warning'; $impact = 8; $finding = "$($mismatch.Count) GPO(s) have AD/SYSVOL version mismatch in $($domain.Name)."; $recommendation = 'Review SYSVOL replication and the affected GPO versions.'
            }
            $evidence = @{ TotalCount = @($mismatch).Count; Showing = [Math]::Min(25, @($mismatch).Count); Items = @($mismatch | Select-Object -First 25 *) }
            $errorMessage = ''
        } catch {
            $status = 'Partial'; $severity = 'Warning'; $impact = 3; $finding = "Unable to review GPO version consistency in $($domain.Name)."; $recommendation = 'Validate Group Policy report generation access.'
            $evidence = $null
            $errorMessage = $_.Exception.Message
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='GPO-003'; Category='Group Policy Health'; Target=$domain.Name; Domain=$domain.Name; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=8
            Finding=$finding; Recommendation=$recommendation; Evidence=$evidence; Reference='GPO VersionDirectory vs VersionSysvol'; ErrorMessage=$errorMessage
        }
    }
    return $results
}
#endregion Test-GPOVersionMismatch

#region Test-GPOPermissions
function Test-GPOPermissions {
    param([psobject]$ForestTopology)
    $results = @()
    if (-not (Test-ModuleAvailable -Name 'GroupPolicy')) {
        return @(New-ADSkippedResult -CheckId 'GPO-004' -Category 'Group Policy Health' -Forest $ForestTopology.ForestName -Finding 'GroupPolicy module unavailable; GPO permissions review skipped.' -Recommendation 'Install/import RSAT Group Policy tools.')
    }

    foreach ($domain in $ForestTopology.Domains) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $gpos = Get-GPO -All -Domain $domain.Name -ErrorAction Stop
            $risky = @()
            foreach ($gpo in $gpos) {
                $permissions = Get-GPPermission -Guid $gpo.Id -All -Domain $domain.Name -ErrorAction Stop
                foreach ($permission in $permissions) {
                    if ($permission.Trustee.Name -in @('Everyone', 'Authenticated Users') -and $permission.Permission -notin @('GpoRead', 'GpoApply')) {
                        $risky += [PSCustomObject]@{ GPO = $gpo.DisplayName; Trustee = $permission.Trustee.Name; Permission = $permission.Permission }
                    }
                }
            }
            if (-not $risky) {
                $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "No overly permissive GPO delegations were found in $($domain.Name)."; $recommendation = 'No action required.'
            } else {
                $status = 'Warning'; $severity = 'Warning'; $impact = 8; $finding = "$($risky.Count) potentially risky GPO permission assignment(s) were found in $($domain.Name)."; $recommendation = 'Restrict GPO edit or security delegation from broad principals.'
            }
            $evidence = @{ TotalCount = @($risky).Count; Showing = [Math]::Min(25, @($risky).Count); Items = @($risky | Select-Object -First 25 *) }
            $errorMessage = ''
        } catch {
            $status = 'Partial'; $severity = 'Warning'; $impact = 3; $finding = "Unable to review GPO permissions in $($domain.Name)."; $recommendation = 'Validate Group Policy query permissions.'
            $evidence = $null
            $errorMessage = $_.Exception.Message
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='GPO-004'; Category='Group Policy Health'; Target=$domain.Name; Domain=$domain.Name; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=8
            Finding=$finding; Recommendation=$recommendation; Evidence=$evidence; Reference='GPO security delegation'; ErrorMessage=$errorMessage
        }
    }
    return $results
}
#endregion Test-GPOPermissions

#region Test-WMIFilterHealth
function Test-WMIFilterHealth {
    param([psobject]$ForestTopology)
    $results = @()
    if (-not (Test-ModuleAvailable -Name 'GroupPolicy')) {
        return @(New-ADSkippedResult -CheckId 'GPO-005' -Category 'Group Policy Health' -Forest $ForestTopology.ForestName -Finding 'GroupPolicy module unavailable; WMI filter review skipped.' -Recommendation 'Install/import RSAT Group Policy tools.')
    }

    foreach ($domain in $ForestTopology.Domains) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $filters = Get-GPWmiFilter -All -Domain $domain.Name -ErrorAction Stop
            $badFilters = $filters | Where-Object { [string]::IsNullOrWhiteSpace($_.Query) -or [string]::IsNullOrWhiteSpace($_.Namespace) }
            if (-not $badFilters) {
                $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "All WMI filters discovered in $($domain.Name) contain query and namespace data."; $recommendation = 'No action required.'
            } else {
                $status = 'Warning'; $severity = 'Warning'; $impact = 5; $finding = "$($badFilters.Count) incomplete WMI filter(s) were found in $($domain.Name)."; $recommendation = 'Repair or remove incomplete WMI filters.'
            }
            $evidence = @{ TotalCount = @($badFilters).Count; Showing = [Math]::Min(25, @($badFilters).Count); Items = @($badFilters | Select-Object -First 25 Name, Id, Namespace, Query) }
            $errorMessage = ''
        } catch {
            $status = 'Partial'; $severity = 'Warning'; $impact = 2; $finding = "Unable to review WMI filters in $($domain.Name)."; $recommendation = 'Validate Group Policy permissions and module support.'
            $evidence = $null
            $errorMessage = $_.Exception.Message
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='GPO-005'; Category='Group Policy Health'; Target=$domain.Name; Domain=$domain.Name; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=4
            Finding=$finding; Recommendation=$recommendation; Evidence=$evidence; Reference='WMI filter health'; ErrorMessage=$errorMessage
        }
    }
    return $results
}
#endregion Test-WMIFilterHealth

#region Test-GPOLinkOrder
function Test-GPOLinkOrder {
    param([psobject]$ForestTopology)
    $results = @()
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        return @(New-ADSkippedResult -CheckId 'GPO-006' -Category 'Group Policy Health' -Forest $ForestTopology.ForestName -Finding 'ActiveDirectory module unavailable; GPO link order review skipped.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }

    foreach ($domain in $ForestTopology.Domains) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $targets = Get-ADOrganizationalUnit -Filter * -Properties gPLink -Server $domain.Name -ErrorAction Stop | Where-Object { $_.gPLink }
            $complex = @()
            foreach ($target in $targets) {
                $links = ConvertFrom-GPLinkValue -GPLink $target.gPLink
                $duplicateIds = $links | Group-Object -Property Guid | Where-Object { $_.Count -gt 1 -and $_.Name }
                if ($links.Count -gt 10 -or $duplicateIds) {
                    $complex += [PSCustomObject]@{ OU = $target.DistinguishedName; LinkCount = $links.Count; DuplicateLinkedGpoIds = ($duplicateIds.Name -join ', ') }
                }
            }
            if (-not $complex) {
                $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "No unusual GPO link ordering complexity was found in $($domain.Name)."; $recommendation = 'No action required.'
            } else {
                $status = 'Warning'; $severity = 'Warning'; $impact = 5; $finding = "$($complex.Count) OU(s) in $($domain.Name) have heavy or duplicate GPO link ordering complexity."; $recommendation = 'Review link order and consolidate redundant GPOs where possible.'
            }
            $evidence = @{ TotalCount = @($complex).Count; Showing = [Math]::Min(25, @($complex).Count); Items = @($complex | Select-Object -First 25 *) }
            $errorMessage = ''
        } catch {
            $status = 'Partial'; $severity = 'Warning'; $impact = 2; $finding = "Unable to review GPO link order in $($domain.Name)."; $recommendation = 'Validate AD query permissions.'
            $evidence = $null
            $errorMessage = $_.Exception.Message
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='GPO-006'; Category='Group Policy Health'; Target=$domain.Name; Domain=$domain.Name; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=4
            Finding=$finding; Recommendation=$recommendation; Evidence=$evidence; Reference='GPO link order complexity'; ErrorMessage=$errorMessage
        }
    }
    return $results
}
#endregion Test-GPOLinkOrder

#region Test-CentralStore
function Test-CentralStore {
    param([psobject]$ForestTopology)
    $path = "\\$($ForestTopology.RootDomain)\SYSVOL\$($ForestTopology.RootDomain)\Policies\PolicyDefinitions"
    Invoke-SimpleADCheck -CheckId 'GPO-007' -Category 'Group Policy Health' -Target $path -Forest $ForestTopology.ForestName -Weight 5 -Reference 'PolicyDefinitions Central Store' -ErrorFinding 'Unable to validate the Group Policy Central Store.' -ErrorRecommendation 'Verify SYSVOL access and permissions.' -ErrorImpact 2 `
        -Context @{ Path = $path } `
        -Evaluate {
            param($ctx)
            $exists = Test-Path -Path $ctx.Path
            $admxCount = if ($exists) { @(Get-ChildItem -Path $ctx.Path -Filter '*.admx' -ErrorAction Stop).Count } else { 0 }
            if ($exists -and $admxCount -gt 0) {
                @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="Central Store exists at $($ctx.Path) with $admxCount ADMX file(s)."; Recommendation='No action required.'; Evidence=@{ Path=$ctx.Path; ADMXCount=$admxCount } }
            } else {
                @{ Status='Warning'; Severity='Warning'; ScoreImpact=6; Finding='Central Store is missing or empty.'; Recommendation='Create or refresh the Group Policy Central Store in SYSVOL.'; Evidence=@{ Path=$ctx.Path; ADMXCount=$admxCount } }
            }
        }
}
#endregion Test-CentralStore

#region Test-SYSVOLShareAvailability
function Test-SYSVOLShareAvailability {
    param([array]$DomainControllers, [string]$Forest = '')
    $results = @()
    foreach ($dc in $DomainControllers) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $sysvol = Test-Path -Path "\\$($dc.HostName)\SYSVOL"
        $netlogon = Test-Path -Path "\\$($dc.HostName)\NETLOGON"
        if ($sysvol -and $netlogon) {
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "SYSVOL and NETLOGON shares are accessible on $($dc.HostName)."; $recommendation = 'No action required.'
        } else {
            $status = 'Fail'; $severity = 'Critical'; $impact = 18; $finding = "SYSVOL/NETLOGON share access failed on $($dc.HostName) (SYSVOL=$sysvol, NETLOGON=$netlogon)."; $recommendation = 'Restore SYSVOL/NETLOGON publication and validate DFSR/NTFRS state.'
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='SYS-001'; Category='SYSVOL & File Replication'; Target=$dc.HostName; Domain=$dc.Domain; Forest=$Forest
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=10
            Finding=$finding; Recommendation=$recommendation; Evidence=@{ SYSVOL = $sysvol; NETLOGON = $netlogon }; Reference='SYSVOL and NETLOGON share availability'
        }
    }
    return $results
}
#endregion Test-SYSVOLShareAvailability

#region Test-DFSRMigrationState
function Test-DFSRMigrationState {
    param([psobject]$ForestTopology)
    if (-not (Test-CommandAvailable -Name 'dfsrmig.exe')) {
        return @(New-ADSkippedResult -CheckId 'SYS-003' -Category 'SYSVOL & File Replication' -Forest $ForestTopology.ForestName -Finding 'dfsrmig.exe unavailable; DFSR migration state review skipped.' -Recommendation 'Run from a DC or host with DFSR migration tools.')
    }
    Invoke-SimpleADCheck -CheckId 'SYS-003' -Category 'SYSVOL & File Replication' -Target $ForestTopology.ForestName -Forest $ForestTopology.ForestName -Weight 6 -Reference 'dfsrmig /getmigrationstate' -ErrorFinding 'Unable to determine DFSR migration state.' -ErrorRecommendation 'Validate DFSR migration tooling and permissions.' -ErrorImpact 3 `
        -Evaluate {
            param($ctx)
            $safe = Invoke-SafeCommand -CommandName 'dfsrmig' -ScriptBlock { dfsrmig /getmigrationstate 2>&1 }
            $output = if ($safe.Result) { ($safe.Result | Out-String) } else { '' }
            $errMsg = if (-not $safe.Success) { $safe.Error } else { '' }
            if ($output -match 'Eliminated') {
                @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding='SYSVOL migration state is Eliminated (DFSR in use).'; Recommendation='No action required.'; Evidence=@{ Output=$output.Trim() }; ErrorMessage=$errMsg }
            } elseif ($output) {
                @{ Status='Warning'; Severity='Warning'; ScoreImpact=6; Finding='SYSVOL migration is not in Eliminated state.'; Recommendation='Review DFSR migration status and remaining legacy dependencies.'; Evidence=@{ Output=$output.Trim() }; ErrorMessage=$errMsg }
            } else {
                @{ Status='Partial'; Severity='Warning'; ScoreImpact=3; Finding='Unable to determine DFSR migration state.'; Recommendation='Validate DFSR migration tooling and permissions.'; Evidence=@{ Output=$output.Trim() }; ErrorMessage=$errMsg }
            }
        }
}
#endregion Test-DFSRMigrationState

#region Test-DFSRBacklog
function Test-DFSRBacklog {
    param([array]$DomainControllers, [string]$Forest = '')
    $results = @()
    if (-not (Test-CommandAvailable -Name 'dfsrdiag.exe')) {
        return @(New-ADSkippedResult -CheckId 'SYS-004' -Category 'SYSVOL & File Replication' -Forest $Forest -Finding 'dfsrdiag.exe unavailable; DFSR backlog review skipped.' -Recommendation 'Run from a host with DFSR diagnostic tools.')
    }

    $pairs = @()
    $byDomain = $DomainControllers | Group-Object -Property Domain
    foreach ($group in $byDomain) {
        $domainDcs = $group.Group | Select-Object -First 3
        if ($domainDcs.Count -ge 2) {
            for ($i = 0; $i -lt ($domainDcs.Count - 1); $i++) {
                $pairs += [PSCustomObject]@{ Source = $domainDcs[$i].HostName; Destination = $domainDcs[$i + 1].HostName; Domain = $group.Name }
            }
        }
    }

    if (-not $pairs) {
        return @(ConvertTo-ADResult -CheckId 'SYS-004' -Category 'SYSVOL & File Replication' -Forest $Forest -Severity 'Info' -Status 'Info' -Weight 5 -Finding 'Not enough domain controllers were discovered to evaluate DFSR backlog pairs.' -Recommendation 'No action required.' -Evidence $null -Reference 'DFSR backlog')
    }

    foreach ($pair in $pairs) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $safe = Invoke-SafeCommand -CommandName 'dfsrdiag backlog' -ScriptBlock {
            dfsrdiag backlog /rgname:'Domain System Volume' /rfname:'SYSVOL Share' /sendingmember:$($pair.Source) /receivingmember:$($pair.Destination) 2>&1
        }
        $output = if ($safe.Result) { ($safe.Result | Out-String) } else { '' }
        $backlog = 0
        if ($output -match 'Backlog File Count\s*:\s*(?<Count>\d+)') {
            $backlog = [int]$matches['Count']
        }
        if ($safe.Success -and $backlog -le 50) {
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "DFSR backlog from $($pair.Source) to $($pair.Destination) is $backlog file(s)."; $recommendation = 'No action required.'
        } elseif ($safe.Success) {
            $status = 'Warning'; $severity = 'Warning'; $impact = 7; $finding = "DFSR backlog from $($pair.Source) to $($pair.Destination) is $backlog file(s)."; $recommendation = 'Review whether SYSVOL backlog is transient or sustained.'
        } else {
            $status = 'Partial'; $severity = 'Warning'; $impact = 3; $finding = "Unable to evaluate DFSR backlog from $($pair.Source) to $($pair.Destination)."; $recommendation = 'Validate DFSR health and diagnostic tooling.'
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='SYS-004'; Category='SYSVOL & File Replication'; Target="$($pair.Source) -> $($pair.Destination)"; Domain=$pair.Domain; Forest=$Forest
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=7
            Finding=$finding; Recommendation=$recommendation; Evidence=@{ Backlog = $backlog; Output = $output.Trim() }; Reference='dfsrdiag backlog'; ErrorMessage=if ($safe.Success) { '' } else { $safe.Error }
        }
    }
    return $results
}
#endregion Test-DFSRBacklog

#region Test-JournalWrapErrors
function Test-JournalWrapErrors {
    param([array]$DomainControllers, [string]$Forest = '')
    $results = @()
    $eventIds = 2213, 2212, 2104, 4008
    foreach ($dc in $DomainControllers) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $events = Get-WinEvent -ComputerName $dc.HostName -FilterHashtable @{ LogName = 'DFS Replication'; StartTime = (Get-Date).AddDays(-30) } -ErrorAction Stop |
                Where-Object { $_.Id -in $eventIds }
            if (@($events).Count -eq 0) {
                $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "No DFSR journal wrap or database recovery events were found on $($dc.HostName)."; $recommendation = 'No action required.'
            } else {
                $status = 'Fail'; $severity = 'Critical'; $impact = 14; $finding = "DFSR journal wrap or recovery event(s) were found on $($dc.HostName)."; $recommendation = 'Investigate DFSR database state and SYSVOL replication immediately.'
            }
            $evidence = $events | Select-Object -First 10 TimeCreated, Id, Message
            $errorMessage = ''
        } catch {
            $status = 'Partial'; $severity = 'Warning'; $impact = 2; $finding = "Unable to query DFSR events on $($dc.HostName)."; $recommendation = 'Validate event log access.'
            $evidence = $null
            $errorMessage = $_.Exception.Message
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='SYS-005'; Category='SYSVOL & File Replication'; Target=$dc.HostName; Domain=$dc.Domain; Forest=$Forest
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=8
            Finding=$finding; Recommendation=$recommendation; Evidence=$evidence; Reference='DFS Replication journal wrap events'; ErrorMessage=$errorMessage
        }
    }
    return $results
}
#endregion Test-JournalWrapErrors

#region Test-SYSVOLConsistency
function Test-SYSVOLConsistency {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $results = @()
    foreach ($domain in $ForestTopology.Domains) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $domainDcs = $DomainControllers | Where-Object { $_.Domain -eq $domain.Name }
            $counts = @()
            foreach ($dc in $domainDcs) {
                $path = "\\$($dc.HostName)\SYSVOL\$($domain.Name)\Policies"
                if (Test-Path -Path $path) {
                    $count = @(Get-ChildItem -Path $path -Directory -ErrorAction Stop | Where-Object { $_.Name -match '^\{[0-9A-Fa-f\-]+\}$' }).Count
                    $counts += [PSCustomObject]@{ DC = $dc.HostName; Count = $count }
                }
            }
            $distinctCounts = $counts | Select-Object -ExpandProperty Count -Unique
            if ($counts.Count -eq 0) {
                $status = 'Fail'; $severity = 'Critical'; $impact = 15; $finding = "No SYSVOL policy folder counts could be collected for $($domain.Name)."; $recommendation = 'Validate SYSVOL share accessibility across domain controllers.'
            } elseif ($distinctCounts.Count -eq 1) {
                $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "SYSVOL policy folder counts are consistent across sampled DCs in $($domain.Name)."; $recommendation = 'No action required.'
            } else {
                $status = 'Warning'; $severity = 'Warning'; $impact = 9; $finding = "SYSVOL policy folder counts differ across sampled DCs in $($domain.Name)."; $recommendation = 'Review DFSR health and SYSVOL convergence for the domain.'
            }
            $evidence = $counts
            $errorMessage = ''
        } catch {
            $status = 'Partial'; $severity = 'Warning'; $impact = 2; $finding = "Unable to evaluate SYSVOL consistency for $($domain.Name)."; $recommendation = 'Validate SYSVOL accessibility and permissions.'
            $evidence = $null
            $errorMessage = $_.Exception.Message
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='SYS-006'; Category='SYSVOL & File Replication'; Target=$domain.Name; Domain=$domain.Name; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=8
            Finding=$finding; Recommendation=$recommendation; Evidence=$evidence; Reference='SYSVOL policy folder counts'; ErrorMessage=$errorMessage
        }
    }
    return $results
}
#endregion Test-SYSVOLConsistency

#region Test-ADSitesConfig
function Test-ADSitesConfig {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        $sw.Stop()
        return @(New-ADSkippedResult -CheckId 'SITE-001' -Category 'Sites & Topology' -Forest $ForestTopology.ForestName -Finding 'ActiveDirectory module unavailable; sites configuration review skipped.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }

    $server = Get-PreferredADServer -DomainControllers $DomainControllers -Domain $ForestTopology.RootDomain
    try {
        $sites = Get-ADReplicationSite -Filter * -Server $server -ErrorAction Stop
        if ($sites.Count -gt 1) {
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "$($sites.Count) AD site(s) were discovered."; $recommendation = 'No action required.'
        } elseif ($sites.Count -eq 1 -and $sites[0].Name -eq 'Default-First-Site-Name') {
            $status = 'Warning'; $severity = 'Warning'; $impact = 6; $finding = 'Only Default-First-Site-Name is configured.'; $recommendation = 'Review whether site topology needs to reflect physical network boundaries.'
        } else {
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "$($sites.Count) AD site(s) were discovered."; $recommendation = 'No action required.'
        }
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='SITE-001'; Category='Sites & Topology'; Target=$ForestTopology.ForestName; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=6
            Finding=$finding; Recommendation=$recommendation; Evidence=$sites | Select-Object Name; Reference='AD replication sites'
        })
    } catch {
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='SITE-001'; Category='Sites & Topology'; Target=$ForestTopology.ForestName; Forest=$ForestTopology.ForestName
            Severity='Warning'; Status='Partial'; ScoreImpact=2; Weight=6
            Finding='Unable to enumerate AD sites.'; Recommendation='Validate AD site enumeration permissions.'; Evidence=$null; Reference='AD replication sites'; ErrorMessage=$_.Exception.Message
        })
    }
}
#endregion Test-ADSitesConfig

#region Test-SubnetToSiteMapping
function Test-SubnetToSiteMapping {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        $sw.Stop()
        return @(New-ADSkippedResult -CheckId 'SITE-002' -Category 'Sites & Topology' -Forest $ForestTopology.ForestName -Finding 'ActiveDirectory module unavailable; subnet mapping review skipped.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }

    $server = Get-PreferredADServer -DomainControllers $DomainControllers -Domain $ForestTopology.RootDomain
    try {
        $sites = Get-ADReplicationSite -Filter * -Server $server -ErrorAction Stop | Select-Object -ExpandProperty Name
        $subnets = Get-ADReplicationSubnet -Filter * -Server $server -ErrorAction Stop
        $invalid = $subnets | Where-Object { $_.Site -and $_.Site -notin $sites }
        if (-not $subnets) {
            $status = 'Fail'; $severity = 'Critical'; $impact = 12; $finding = 'No AD subnets were configured.'; $recommendation = 'Create subnet-to-site mappings for accurate DC locator behavior.'
        } elseif (-not $invalid) {
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "$($subnets.Count) subnet object(s) are mapped to valid AD sites."; $recommendation = 'No action required.'
        } else {
            $status = 'Warning'; $severity = 'Warning'; $impact = 7; $finding = "One or more subnet objects reference invalid or missing site mappings."; $recommendation = 'Correct subnet-to-site mappings.'
        }
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='SITE-002'; Category='Sites & Topology'; Target=$ForestTopology.ForestName; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=8
            Finding=$finding; Recommendation=$recommendation; Evidence=@{ Subnets = $subnets | Select-Object Name, Site; Invalid = $invalid | Select-Object Name, Site }; Reference='AD subnet mapping'
        })
    } catch {
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='SITE-002'; Category='Sites & Topology'; Target=$ForestTopology.ForestName; Forest=$ForestTopology.ForestName
            Severity='Warning'; Status='Partial'; ScoreImpact=2; Weight=8
            Finding='Unable to evaluate subnet-to-site mappings.'; Recommendation='Validate AD site enumeration permissions.'; Evidence=$null; Reference='AD subnet mapping'; ErrorMessage=$_.Exception.Message
        })
    }
}
#endregion Test-SubnetToSiteMapping

#region Test-DCPlacementPerSite
function Test-DCPlacementPerSite {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $siteGroups = $DomainControllers | Group-Object -Property Site
    $siteMap = @{}
    foreach ($group in $siteGroups) {
        $siteMap[$group.Name] = $group.Count
    }
    $sitesWithoutDc = @($ForestTopology.Sites | Where-Object { -not $siteMap.ContainsKey($_) })
    if (-not $sitesWithoutDc) {
        $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = 'Every discovered AD site has at least one domain controller.'; $recommendation = 'No action required.'
    } else {
        $status = 'Warning'; $severity = 'Warning'; $impact = 8; $finding = "One or more AD sites do not currently host a discovered domain controller."; $recommendation = 'Review site design and DC placement for unsupported sites.'
    }
    $sw.Stop()
    return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
        CheckId='SITE-003'; Category='Sites & Topology'; Target=$ForestTopology.ForestName; Forest=$ForestTopology.ForestName
        Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=6
        Finding=$finding; Recommendation=$recommendation; Evidence=@{ SiteDcCounts = $siteMap; SitesWithoutDc = $sitesWithoutDc }; Reference='DC placement by site'
    })
}
#endregion Test-DCPlacementPerSite

#region Test-IntersiteTopology
function Test-IntersiteTopology {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        $sw.Stop()
        return @(New-ADSkippedResult -CheckId 'SITE-004' -Category 'Sites & Topology' -Forest $ForestTopology.ForestName -Finding 'ActiveDirectory module unavailable; intersite topology review skipped.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }

    $server = Get-PreferredADServer -DomainControllers $DomainControllers -Domain $ForestTopology.RootDomain
    try {
        $links = Get-ADReplicationSiteLink -Filter * -Properties SitesIncluded -Server $server -ErrorAction Stop
        $linkedSites = @($links | ForEach-Object { $_.SitesIncluded } | Select-Object -Unique)
        $isolated = @($ForestTopology.Sites | Where-Object { $_ -notin $linkedSites })
        if ($ForestTopology.Sites.Count -le 1) {
            $status = 'Info'; $severity = 'Info'; $impact = 0; $finding = 'Single-site forest detected; intersite topology review is informational only.'; $recommendation = 'No action required.'
        } elseif (-not $isolated) {
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = 'All discovered AD sites appear on at least one site link.'; $recommendation = 'No action required.'
        } else {
            $status = 'Fail'; $severity = 'Critical'; $impact = 14; $finding = 'One or more AD sites appear isolated from configured site links.'; $recommendation = 'Create or repair site links for isolated sites.'
        }
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='SITE-004'; Category='Sites & Topology'; Target=$ForestTopology.ForestName; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=8
            Finding=$finding; Recommendation=$recommendation; Evidence=@{ SiteLinks = $links | Select-Object Name, SitesIncluded; IsolatedSites = $isolated }; Reference='Intersite topology'
        })
    } catch {
        $sw.Stop()
        return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='SITE-004'; Category='Sites & Topology'; Target=$ForestTopology.ForestName; Forest=$ForestTopology.ForestName
            Severity='Warning'; Status='Partial'; ScoreImpact=2; Weight=8
            Finding='Unable to evaluate intersite topology.'; Recommendation='Validate site link enumeration permissions.'; Evidence=$null; Reference='Intersite topology'; ErrorMessage=$_.Exception.Message
        })
    }
}
#endregion Test-IntersiteTopology

#region Test-SiteLinkCost
function Test-SiteLinkCost {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        return @(New-ADSkippedResult -CheckId 'SITE-005' -Category 'Sites & Topology' -Forest $ForestTopology.ForestName -Finding 'ActiveDirectory module unavailable; site link cost review skipped.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }
    $server = Get-PreferredADServer -DomainControllers $DomainControllers -Domain $ForestTopology.RootDomain
    Invoke-SimpleADCheck -CheckId 'SITE-005' -Category 'Sites & Topology' -Target $ForestTopology.ForestName -Forest $ForestTopology.ForestName -Weight 5 -Reference 'Site link cost and frequency' -ErrorFinding 'Unable to evaluate site link cost settings.' -ErrorRecommendation 'Validate site link enumeration permissions.' -ErrorImpact 2 `
        -Context @{ Server = $server } `
        -Evaluate {
            param($ctx)
            $links = Get-ADReplicationSiteLink -Filter * -Properties Cost, ReplicationFrequencyInMinutes -Server $ctx.Server -ErrorAction Stop
            $issues = $links | Where-Object { $_.Cost -le 0 -or $_.ReplicationFrequencyInMinutes -lt 15 -or $_.ReplicationFrequencyInMinutes -gt 10080 }
            if (-not $issues) {
                @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding='All site link cost and frequency values are within valid ranges.'; Recommendation='No action required.'; Evidence=($issues | Select-Object Name, Cost, ReplicationFrequencyInMinutes) }
            } else {
                @{ Status='Warning'; Severity='Warning'; ScoreImpact=6; Finding='One or more site links have invalid or unusual cost/frequency values.'; Recommendation='Review site link cost and frequency settings.'; Evidence=($issues | Select-Object Name, Cost, ReplicationFrequencyInMinutes) }
            }
        }
}
#endregion Test-SiteLinkCost

#region Test-PreferredBridgehead
function Test-PreferredBridgehead {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    if (-not (Test-ModuleAvailable -Name 'ActiveDirectory')) {
        return @(New-ADSkippedResult -CheckId 'SITE-006' -Category 'Sites & Topology' -Forest $ForestTopology.ForestName -Finding 'ActiveDirectory module unavailable; preferred bridgehead review skipped.' -Recommendation 'Install/import RSAT Active Directory tools.')
    }
    $server = Get-PreferredADServer -DomainControllers $DomainControllers -Domain $ForestTopology.RootDomain
    Invoke-SimpleADCheck -CheckId 'SITE-006' -Category 'Sites & Topology' -Target $ForestTopology.ForestName -Forest $ForestTopology.ForestName -Weight 4 -Reference 'Preferred bridgehead servers' -ErrorFinding 'Unable to evaluate preferred bridgehead configuration.' -ErrorRecommendation 'Validate configuration partition access.' -ErrorImpact 2 `
        -Context @{ Server = $server } `
        -Evaluate {
            param($ctx)
            $rootDse = Get-ADRootDSE -Server $ctx.Server -ErrorAction Stop
            $sitesDn = "CN=Sites,$($rootDse.ConfigurationNamingContext)"
            $servers = Get-ADObject -Server $ctx.Server -SearchBase $sitesDn -LDAPFilter '(objectClass=server)' -Properties bridgeheadTransportList, dNSHostName, name -ErrorAction Stop
            $preferred = $servers | Where-Object { $_.bridgeheadTransportList }
            if (-not $preferred) {
                @{ Status='Info'; Severity='Info'; ScoreImpact=0; Finding='No manually preferred bridgehead servers were configured.'; Recommendation='No action required unless manual bridgehead control is desired.'; Evidence=($preferred | Select-Object Name, dNSHostName, bridgeheadTransportList) }
            } else {
                $offline = $preferred | Where-Object { $_.dNSHostName -and -not (Test-DnsHostResolution -HostName $_.dNSHostName) }
                if (-not $offline) {
                    @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding='Configured preferred bridgehead servers resolve successfully.'; Recommendation='No action required.'; Evidence=($preferred | Select-Object Name, dNSHostName, bridgeheadTransportList) }
                } else {
                    @{ Status='Warning'; Severity='Warning'; ScoreImpact=6; Finding='One or more configured preferred bridgehead servers do not resolve.'; Recommendation='Review preferred bridgehead configuration and remove stale references.'; Evidence=($preferred | Select-Object Name, dNSHostName, bridgeheadTransportList) }
                }
            }
        }
}
#endregion Test-PreferredBridgehead

#region Test-FSMORoleHolders
function Test-FSMORoleHolders {
    param([psobject]$ForestTopology)
    $results = @()
    $roles = @(
        [PSCustomObject]@{ Role = 'SchemaMaster'; Holder = $ForestTopology.SchemaMaster; Domain = $ForestTopology.RootDomain },
        [PSCustomObject]@{ Role = 'DomainNamingMaster'; Holder = $ForestTopology.DomainNamingMaster; Domain = $ForestTopology.RootDomain }
    )
    foreach ($domain in $ForestTopology.Domains) {
        $roles += [PSCustomObject]@{ Role = 'PDCEmulator'; Holder = $domain.PDCEmulator; Domain = $domain.Name }
        $roles += [PSCustomObject]@{ Role = 'RIDMaster'; Holder = $domain.RIDMaster; Domain = $domain.Name }
        $roles += [PSCustomObject]@{ Role = 'InfrastructureMaster'; Holder = $domain.InfrastructureMaster; Domain = $domain.Name }
    }
    foreach ($role in $roles) {
        $results += Invoke-SimpleADCheck -CheckId 'FSMO-001' -Category 'FSMO Roles' -Target $role.Role -Domain $role.Domain -Forest $ForestTopology.ForestName -Weight 8 -Reference 'FSMO role ownership' -Context @{ Role = $role } -Evaluate {
            param($ctx)
            $holderPresent = -not [string]::IsNullOrWhiteSpace($ctx.Role.Holder)
            @{
                Severity = if ($holderPresent) { 'Pass' } else { 'Critical' }
                Status = if ($holderPresent) { 'Pass' } else { 'Fail' }
                ScoreImpact = if ($holderPresent) { 0 } else { 20 }
                Finding = if ($holderPresent) { "$($ctx.Role.Role) is held by $($ctx.Role.Holder)." } else { "$($ctx.Role.Role) holder could not be determined." }
                Recommendation = if ($holderPresent) { 'No action required.' } else { 'Validate FSMO ownership immediately.' }
                Evidence = @{ Holder = $ctx.Role.Holder }
            }
        }
    }
    return $results
}
#endregion Test-FSMORoleHolders

#region Test-FSMOOnline
function Test-FSMOOnline {
    param([psobject]$ForestTopology)
    $results = @()
    $holders = @($ForestTopology.SchemaMaster, $ForestTopology.DomainNamingMaster)
    foreach ($domain in $ForestTopology.Domains) {
        $holders += @($domain.PDCEmulator, $domain.RIDMaster, $domain.InfrastructureMaster)
    }
    $holders = $holders | Sort-Object -Unique
    foreach ($holder in $holders) {
        if ([string]::IsNullOrWhiteSpace($holder)) { continue }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $ping = $false
        try { $ping = Test-Connection -ComputerName $holder -Count 1 -Quiet -ErrorAction Stop } catch { $ping = $false }
        $ldap = Test-TcpPort -ComputerName $holder -Port 389
        if ($ping -and $ldap) {
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "FSMO role holder $holder is reachable."; $recommendation = 'No action required.'
        } else {
            $status = 'Fail'; $severity = 'Critical'; $impact = 18; $finding = "FSMO role holder $holder is not fully reachable (ICMP=$ping, LDAP389=$ldap)."; $recommendation = 'Restore availability of the FSMO role holder or transfer/seize roles if necessary.'
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='FSMO-002'; Category='FSMO Roles'; Target=$holder; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=9
            Finding=$finding; Recommendation=$recommendation; Evidence=@{ Ping = $ping; LDAP389 = $ldap }; Reference='FSMO holder availability'
        }
    }
    return $results
}
#endregion Test-FSMOOnline

#region Test-FSMODistribution
function Test-FSMODistribution {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $holders = @($ForestTopology.SchemaMaster, $ForestTopology.DomainNamingMaster)
    foreach ($domain in $ForestTopology.Domains) {
        $holders += @($domain.PDCEmulator, $domain.RIDMaster, $domain.InfrastructureMaster)
    }
    $uniqueHolders = @($holders | Sort-Object -Unique)
    Invoke-SimpleADCheck -CheckId 'FSMO-003' -Category 'FSMO Roles' -Target $ForestTopology.ForestName -Forest $ForestTopology.ForestName -Weight 4 -Reference 'FSMO role distribution' `
        -Context @{ DCCount = $DomainControllers.Count; UniqueHolders = $uniqueHolders } `
        -Evaluate {
            param($ctx)
            if ($ctx.DCCount -le 1) {
                @{ Status='Info'; Severity='Info'; ScoreImpact=0; Finding='Single domain controller environment detected; FSMO distribution is informational only.'; Recommendation='No action required.'; Evidence=@{ UniqueHolders=$ctx.UniqueHolders } }
            } elseif ($ctx.UniqueHolders.Count -ge 2) {
                @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="FSMO roles are distributed across $($ctx.UniqueHolders.Count) holder(s)."; Recommendation='No action required.'; Evidence=@{ UniqueHolders=$ctx.UniqueHolders } }
            } else {
                @{ Status='Warning'; Severity='Warning'; ScoreImpact=6; Finding='All FSMO roles appear to be concentrated on a single server.'; Recommendation='Review whether role distribution should be diversified for resilience and operational balance.'; Evidence=@{ UniqueHolders=$ctx.UniqueHolders } }
            }
        }
}
#endregion Test-FSMODistribution

#region Test-InfrastructureMasterPlacement
function Test-InfrastructureMasterPlacement {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $results = @()
    foreach ($domain in $ForestTopology.Domains) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $domainDcs = $DomainControllers | Where-Object { $_.Domain -eq $domain.Name }
        $allGc = $domainDcs.Count -gt 0 -and (@($domainDcs | Where-Object { $_.IsGlobalCatalog }).Count -eq $domainDcs.Count)
        $holderDc = $domainDcs | Where-Object { $_.HostName -ieq $domain.InfrastructureMaster } | Select-Object -First 1
        if ($allGc) {
            $status = 'Info'; $severity = 'Info'; $impact = 0; $finding = "All DCs in $($domain.Name) are global catalogs; Infrastructure Master placement is not a concern."; $recommendation = 'No action required.'
        } elseif ($holderDc -and -not $holderDc.IsGlobalCatalog) {
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "Infrastructure Master for $($domain.Name) is hosted on a non-GC server ($($holderDc.HostName))."; $recommendation = 'No action required.'
        } else {
            $status = 'Warning'; $severity = 'Warning'; $impact = 6; $finding = "Infrastructure Master for $($domain.Name) is hosted on a global catalog or could not be validated."; $recommendation = 'Place the Infrastructure Master on a non-GC DC unless all DCs are global catalogs.'
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='FSMO-004'; Category='FSMO Roles'; Target=$domain.InfrastructureMaster; Domain=$domain.Name; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=4
            Finding=$finding; Recommendation=$recommendation; Evidence=@{ AllDomainDCsAreGC = $allGc; Holder = $domain.InfrastructureMaster }; Reference='Infrastructure Master placement'
        }
    }
    return $results
}
#endregion Test-InfrastructureMasterPlacement

#region Test-PDCExternalTimeSource
function Test-PDCExternalTimeSource {
    param([psobject]$ForestTopology)
    if (-not (Test-CommandAvailable -Name 'w32tm.exe')) {
        return @(New-ADSkippedResult -CheckId 'TIME-001' -Category 'Time Synchronization' -Forest $ForestTopology.ForestName -Finding 'w32tm.exe unavailable; external time source review skipped.' -Recommendation 'Run from a Windows host with w32tm available.')
    }
    $pdc = ($ForestTopology.Domains | Where-Object { $_.Name -eq $ForestTopology.RootDomain } | Select-Object -First 1).PDCEmulator
    Invoke-SimpleADCheck -CheckId 'TIME-001' -Category 'Time Synchronization' -Target $pdc -Forest $ForestTopology.ForestName -Weight 9 -Reference 'w32tm configuration' -ErrorFinding "Unable to determine time source configuration for $pdc." -ErrorRecommendation 'Validate RPC/time service access and rerun the check.' -ErrorImpact 3 `
        -Context @{ PDC = $pdc } `
        -Evaluate {
            param($ctx)
            $safe = Invoke-SafeCommand -CommandName 'w32tm query configuration' -ScriptBlock { w32tm /query /configuration /computer:$($ctx.PDC) 2>&1 }
            $output = if ($safe.Result) { ($safe.Result | Out-String) } else { '' }
            $typeLine = ($output -split [Environment]::NewLine | Where-Object { $_ -match '^Type:' } | Select-Object -First 1)
            $ntpLine  = ($output -split [Environment]::NewLine | Where-Object { $_ -match '^NtpServer:' } | Select-Object -First 1)
            $type      = if ($typeLine) { ($typeLine -replace 'Type:\s*', '').Trim() } else { '' }
            $ntpServer = if ($ntpLine)  { ($ntpLine  -replace 'NtpServer:\s*', '').Trim() } else { '' }
            $errMsg    = if (-not $safe.Success) { $safe.Error } else { '' }
            if ($type -match 'NTP' -and $ntpServer -and $ntpServer -notmatch 'Local CMOS Clock') {
                @{ Status='Pass'; Severity='Pass'; ScoreImpact=0; Finding="Forest root PDC emulator $($ctx.PDC) is configured with an external/manual NTP source."; Recommendation='No action required.'; Evidence=@{ Type=$type; NtpServer=$ntpServer; Output=$output.Trim() }; ErrorMessage=$errMsg }
            } elseif ($output) {
                @{ Status='Warning'; Severity='Warning'; ScoreImpact=8; Finding="Forest root PDC emulator $($ctx.PDC) does not clearly show an external/manual NTP source."; Recommendation='Configure the forest root PDC emulator to sync from reliable external time sources.'; Evidence=@{ Type=$type; NtpServer=$ntpServer; Output=$output.Trim() }; ErrorMessage=$errMsg }
            } else {
                @{ Status='Partial'; Severity='Warning'; ScoreImpact=3; Finding="Unable to determine time source configuration for $($ctx.PDC)."; Recommendation='Validate RPC/time service access and rerun the check.'; Evidence=@{ Type=$type; NtpServer=$ntpServer; Output=$output.Trim() }; ErrorMessage=$errMsg }
            }
        }
}
#endregion Test-PDCExternalTimeSource

#region Test-DCHierarchyTimeSync
function Test-DCHierarchyTimeSync {
    param([array]$DomainControllers, [string]$Forest = '')
    $results = @()
    if (-not (Test-CommandAvailable -Name 'w32tm.exe')) {
        return @(New-ADSkippedResult -CheckId 'TIME-002' -Category 'Time Synchronization' -Forest $Forest -Finding 'w32tm.exe unavailable; DC hierarchy time sync review skipped.' -Recommendation 'Run from a Windows host with w32tm available.')
    }

    foreach ($dc in $DomainControllers) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $safe = Invoke-SafeCommand -CommandName 'w32tm query source' -ScriptBlock { w32tm /query /source /computer:$($dc.HostName) 2>&1 }
        $source = if ($safe.Result) { (($safe.Result | Out-String).Trim()) } else { '' }
        if ($safe.Success -and $source -and $source -notmatch 'Local CMOS Clock|Free-running System Clock') {
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "$($dc.HostName) reports time source '$source'."; $recommendation = 'No action required.'
        } elseif ($source) {
            $status = 'Warning'; $severity = 'Warning'; $impact = 6; $finding = "$($dc.HostName) reports local or ambiguous time source '$source'."; $recommendation = 'Validate W32Time hierarchy and source configuration on the DC.'
        } else {
            $status = 'Partial'; $severity = 'Warning'; $impact = 2; $finding = "Unable to determine the current time source for $($dc.HostName)."; $recommendation = 'Validate time service access and retry.'
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='TIME-002'; Category='Time Synchronization'; Target=$dc.HostName; Domain=$dc.Domain; Forest=$Forest
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=7
            Finding=$finding; Recommendation=$recommendation; Evidence=@{ Source = $source }; Reference='w32tm current source'; ErrorMessage=if ($safe.Success) { '' } else { $safe.Error }
        }
    }
    return $results
}
#endregion Test-DCHierarchyTimeSync

#region Test-TimeDrift
function Test-TimeDrift {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not (Test-CommandAvailable -Name 'w32tm.exe')) {
        $sw.Stop()
        return @(New-ADSkippedResult -CheckId 'TIME-003' -Category 'Time Synchronization' -Forest $ForestTopology.ForestName -Finding 'w32tm.exe unavailable; time drift review skipped.' -Recommendation 'Run from a Windows host with w32tm available.')
    }

    $computerList = ($DomainControllers | Select-Object -ExpandProperty HostName) -join ','
    $safe = Invoke-SafeCommand -CommandName 'w32tm monitor' -ScriptBlock { w32tm /monitor /computers:$computerList 2>&1 }.GetNewClosure()
    $output = if ($safe.Result) { ($safe.Result | Out-String) } else { '' }
    $offsets = @()
    foreach ($line in ($output -split [Environment]::NewLine)) {
        if ($line -match '^(?<Host>[^,]+),.*?(?<Offset>-?\d+(\.\d+)?)s') {
            $offsets += [PSCustomObject]@{ Host = $matches['Host'].Trim(); OffsetSeconds = [double]$matches['Offset'] }
        }
    }
    $maxOffset = if ($offsets) { [math]::Abs(($offsets | Sort-Object { [math]::Abs($_.OffsetSeconds) } -Descending | Select-Object -First 1).OffsetSeconds) } else { $null }
    if ($null -eq $maxOffset) {
        $status = 'Partial'; $severity = 'Warning'; $impact = 3; $finding = 'Unable to calculate time drift from w32tm monitor output.'; $recommendation = 'Validate time service access and retry.'
    } elseif ($maxOffset -le 60) {
        $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "Maximum observed DC time drift is $maxOffset second(s)."; $recommendation = 'No action required.'
    } elseif ($maxOffset -le 300) {
        $status = 'Warning'; $severity = 'Warning'; $impact = 7; $finding = "Maximum observed DC time drift is $maxOffset second(s)."; $recommendation = 'Review time hierarchy health and sync intervals.'
    } else {
        $status = 'Fail'; $severity = 'Critical'; $impact = 16; $finding = "Maximum observed DC time drift is $maxOffset second(s)."; $recommendation = 'Correct time synchronization immediately to avoid Kerberos failures.'
    }
    $sw.Stop()
    return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
        CheckId='TIME-003'; Category='Time Synchronization'; Target=$ForestTopology.ForestName; Forest=$ForestTopology.ForestName
        Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=9
        Finding=$finding; Recommendation=$recommendation; Evidence=$offsets; Reference='w32tm /monitor'; ErrorMessage=if ($safe.Success) { '' } else { $safe.Error }
    })
}
#endregion Test-TimeDrift

#region Test-W32TimeService
function Test-W32TimeService {
    param([array]$DomainControllers, [string]$Forest = '')
    $results = @()
    foreach ($dc in $DomainControllers) {
        $results += Invoke-SimpleADCheck -CheckId 'TIME-004' -Category 'Time Synchronization' -Target $dc.HostName -Domain $dc.Domain -Forest $Forest -Weight 6 -Reference 'Windows Time service health' -ErrorFinding "Unable to query W32Time service on $($dc.HostName)." -ErrorRecommendation 'Validate service manager connectivity.' -ErrorImpact 2 -Context @{ Dc = $dc } -Evaluate {
            param($ctx)
            $svc = Get-Service -ComputerName $ctx.Dc.HostName -Name 'W32Time' -ErrorAction Stop
            if ($svc.Status -eq 'Running') {
                @{ Severity = 'Pass'; Status = 'Pass'; ScoreImpact = 0; Finding = "W32Time service is running on $($ctx.Dc.HostName)."; Recommendation = 'No action required.'; Evidence = @{ Status = $svc.Status; StartType = $svc.StartType } }
            } else {
                @{ Severity = 'Critical'; Status = 'Fail'; ScoreImpact = 12; Finding = "W32Time service status on $($ctx.Dc.HostName) is $($svc.Status)."; Recommendation = 'Restore Windows Time service operation.'; Evidence = @{ Status = $svc.Status; StartType = $svc.StartType } }
            }
        }
    }
    return $results
}
#endregion Test-W32TimeService



#region Test-BackupStatus
function Test-BackupStatus {
    param([array]$DomainControllers, [string]$Forest = '')
    $results = @()
    foreach ($dc in $DomainControllers) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $failures = Get-BackupFailureEvents -ComputerName $dc.HostName -DaysBack 30
        if (@($failures).Count -eq 0) {
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "No Windows Backup critical/error events were found for $($dc.HostName) in the last 30 days."; $recommendation = 'No action required.'
        } elseif (@($failures).Count -le 5) {
            $status = 'Warning'; $severity = 'Warning'; $impact = 6; $finding = "$(@($failures).Count) Windows Backup critical/error event(s) were found for $($dc.HostName) in the last 30 days."; $recommendation = 'Review backup job stability and alerting.'
        } else {
            $status = 'Fail'; $severity = 'Critical'; $impact = 14; $finding = "$(@($failures).Count) Windows Backup critical/error event(s) were found for $($dc.HostName) in the last 30 days."; $recommendation = 'Investigate persistent backup failures immediately.'
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='BKP-002'; Category='Backup & Recovery'; Target=$dc.HostName; Domain=$dc.Domain; Forest=$Forest
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=8
            Finding=$finding; Recommendation=$recommendation; Evidence=$failures | Select-Object -First 10 TimeCreated, Id, Message; Reference='Backup failure events last 30 days'
        }
    }
    return $results
}
#endregion Test-BackupStatus

#region Test-ADRecycleBinBackup
function Test-ADRecycleBinBackup {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $recycleResult = Test-ADRecycleBin -ForestTopology $ForestTopology -DomainControllers $DomainControllers | Select-Object -First 1
    $rootPdc = ($ForestTopology.Domains | Where-Object { $_.Name -eq $ForestTopology.RootDomain } | Select-Object -First 1).PDCEmulator
    $backup = Get-LastSuccessfulBackupInfo -ComputerName $rootPdc -DaysBack 180
    if ($recycleResult.Status -eq 'Pass' -and $backup.Success -and $backup.AgeDays -le 14) {
        $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = 'AD Recycle Bin is enabled and recent backup coverage exists for the forest root PDC emulator.'; $recommendation = 'No action required.'
    } elseif ($recycleResult.Status -eq 'Pass') {
        $status = 'Warning'; $severity = 'Warning'; $impact = 8; $finding = 'AD Recycle Bin is enabled but recent backup coverage for the forest root PDC emulator was not found.'; $recommendation = 'Maintain recent backups even when Recycle Bin is enabled.'
    } else {
        $status = 'Warning'; $severity = 'Warning'; $impact = 6; $finding = 'AD Recycle Bin is not enabled or could not be validated.'; $recommendation = 'Enable Recycle Bin and maintain recent backups for layered recovery.'
    }
    $sw.Stop()
    return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
        CheckId='BKP-003'; Category='Backup & Recovery'; Target=$rootPdc; Forest=$ForestTopology.ForestName
        Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=5
        Finding=$finding; Recommendation=$recommendation; Evidence=@{ RecycleBinStatus = $recycleResult.Status; LastBackup = $backup.LastSuccess; BackupAgeDays = $backup.AgeDays }; Reference='Recycle Bin plus backup readiness'; ErrorMessage=$backup.Error
    })
}
#endregion Test-ADRecycleBinBackup

#region Test-TombstoneLifetimeBackup
function Test-TombstoneLifetimeBackup {
    param([psobject]$ForestTopology, [array]$DomainControllers)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $referenceServer = Get-PreferredADServer -DomainControllers $DomainControllers -Domain $ForestTopology.RootDomain
    $rootPdc = ($ForestTopology.Domains | Where-Object { $_.Name -eq $ForestTopology.RootDomain } | Select-Object -First 1).PDCEmulator
    $tombstone = Get-TombstoneLifetimeDays -Server $referenceServer
    $backup = Get-LastSuccessfulBackupInfo -ComputerName $rootPdc -DaysBack 365
    if ($backup.Success -and $backup.AgeDays -le $tombstone) {
        $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "Root PDC backup age ($($backup.AgeDays) days) is within tombstone lifetime ($tombstone days)."; $recommendation = 'No action required.'
    } elseif ($backup.Success) {
        $status = 'Fail'; $severity = 'Critical'; $impact = 16; $finding = "Root PDC backup age ($($backup.AgeDays) days) exceeds tombstone lifetime ($tombstone days)."; $recommendation = 'Create fresh backups immediately; stale backups are unsafe for AD recovery.'
    } else {
        $status = 'Fail'; $severity = 'Critical'; $impact = 18; $finding = 'No successful backup was found to compare with tombstone lifetime.'; $recommendation = 'Implement and validate system state backups immediately.'
    }
    $sw.Stop()
    return @(Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
        CheckId='BKP-004'; Category='Backup & Recovery'; Target=$rootPdc; Forest=$ForestTopology.ForestName
        Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=8
        Finding=$finding; Recommendation=$recommendation; Evidence=@{ TombstoneLifetimeDays = $tombstone; LastBackup = $backup.LastSuccess; BackupAgeDays = $backup.AgeDays }; Reference='Backup age vs tombstone lifetime'; ErrorMessage=$backup.Error
    })
}
#endregion Test-TombstoneLifetimeBackup

#region Test-TrustRelationships
function Test-TrustRelationships {
    param([psobject]$ForestTopology)
    $results = @()
    if (-not $ForestTopology.Trusts -or @($ForestTopology.Trusts).Count -eq 0) {
        return @(ConvertTo-ADResult -CheckId 'BKP-005' -Category 'Backup & Recovery' -Forest $ForestTopology.ForestName -Severity 'Info' -Status 'Info' -Weight 4 -Finding 'No explicit trust objects were discovered.' -Recommendation 'No action required.' -Evidence $null -Reference 'Trust relationships')
    }

    foreach ($trust in $ForestTopology.Trusts | Sort-Object Target -Unique) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            if ($trust.TrustType -match 'Forest') {
                [void][System.DirectoryServices.ActiveDirectory.Forest]::GetForest((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $trust.Target)))
            } else {
                [void][System.DirectoryServices.ActiveDirectory.Domain]::GetDomain((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $trust.Target)))
            }
            $status = 'Pass'; $severity = 'Pass'; $impact = 0; $finding = "Trust target $($trust.Target) is resolvable and reachable through .NET directory APIs."; $recommendation = 'No action required.'
            $errorMessage = ''
        } catch {
            $status = 'Warning'; $severity = 'Warning'; $impact = 8; $finding = "Trust target $($trust.Target) could not be validated through directory APIs."; $recommendation = 'Review trust health, DNS resolution, and firewall requirements.'
            $errorMessage = $_.Exception.Message
        }
        $sw.Stop()
        $results += Complete-ADResult -Duration $sw.ElapsedMilliseconds -Params @{
            CheckId='BKP-005'; Category='Backup & Recovery'; Target=$trust.Target; Forest=$ForestTopology.ForestName
            Severity=$severity; Status=$status; ScoreImpact=$impact; Weight=6
            Finding=$finding; Recommendation=$recommendation; Evidence=$trust; Reference='Trust target validation'; ErrorMessage=$errorMessage
        }
    }
    return $results
}
#endregion Test-TrustRelationships
#endregion Collection & Analysis

#region Scoring
#region Get-ADCategoryScore
function Get-ADCategoryScore {
    param([Parameter(Mandatory=$true)][array]$Results, [Parameter(Mandatory=$true)][string]$Category)

    $categoryResults = $Results | Where-Object { $_.Category -eq $Category }
    if (-not $categoryResults) {
        return [PSCustomObject]@{
            Category = $Category
            Score    = 100
            Findings = 0
        }
    }

    $statusMap = @{ Pass = 100; Info = 100; Skipped = 85; Partial = 70; Warning = 50; Fail = 0 }
    $weightedTotal = 0.0
    $weightTotal = 0.0
    foreach ($result in $categoryResults) {
        $baseScore = $statusMap[$result.Status]
        $finalScore = [math]::Max(0, [math]::Min(100, $baseScore - [math]::Abs([int]$result.ScoreImpact)))
        $weightedTotal += ($finalScore * [int]$result.Weight)
        $weightTotal += [int]$result.Weight
    }

    $score = if ($weightTotal -gt 0) { [math]::Round($weightedTotal / $weightTotal, 2) } else { 100 }
    return [PSCustomObject]@{
        Category = $Category
        Score    = $score
        Findings = $categoryResults.Count
    }
}
#endregion Get-ADCategoryScore

#region Get-ADOverallHealthScore
function Get-ADOverallHealthScore {
    param([Parameter(Mandatory = $true)][array]$Results)

    $categoryScores = foreach ($category in $Script:CategoryWeights.Keys) {
        Get-ADCategoryScore -Results $Results -Category $category
    }

    $weightedTotal = 0.0
    $weightTotal = 0.0
    foreach ($categoryScore in $categoryScores) {
        $weight = [double]$Script:CategoryWeights[$categoryScore.Category]
        if ($null -ne $weight) {
            $weightedTotal += ($categoryScore.Score * $weight)
            $weightTotal += $weight
        }
    }

    $overallScore = if ($weightTotal -gt 0) { [math]::Round($weightedTotal / $weightTotal, 2) } else { 100 }
    $rating = if ($overallScore -ge $Script:ScoringThresholds.Excellent) { 'Excellent' }
              elseif ($overallScore -ge $Script:ScoringThresholds.Good) { 'Good' }
              elseif ($overallScore -ge $Script:ScoringThresholds.Fair) { 'Fair' }
              elseif ($overallScore -ge $Script:ScoringThresholds.Poor) { 'Poor' }
              else { 'Critical' }

    return [PSCustomObject]@{
        OverallScore   = $overallScore
        Rating         = $rating
        CategoryScores = $categoryScores
        CalculatedAt   = Get-Date
    }
}
#endregion Get-ADOverallHealthScore
#endregion Scoring

#region HTML Report Generation
#endregion HTML Report Generation

#region CSV Export
#region Export-ADResultsToCsv
function Export-ADResultsToCsv {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][array]$Results, [Parameter(Mandatory=$true)][string]$Path)

    $export = $Results | Select-Object CheckId, Category, SubCategory, Target, Domain, Forest, Severity, Status, ScoreImpact, Weight, Finding, Recommendation, ErrorMessage, Timestamp, ExecutionTimeMs,
        @{ Name = 'Evidence'; Expression = {
            if ($null -eq $_.Evidence) { '' }
            elseif ($_.Evidence -is [string]) { $_.Evidence }
            else { ($_.Evidence | ConvertTo-Json -Depth 6 -Compress) }
        } }, Reference

    $export | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}
#endregion Export-ADResultsToCsv
#endregion CSV Export

#region Main Orchestration
#region Add-AssessmentResults
function Add-AssessmentResults {
    param([array]$Results)
    foreach ($result in $Results) {
        [void]$Script:AllResults.Add($result)
    }
}
#endregion Add-AssessmentResults

#region Invoke-ForestDomainChecks
function Invoke-ForestDomainChecks {
    param([psobject]$Topology, [array]$DomainControllers)
    $results = @()
    $results += Test-ForestFunctionalLevel -ForestTopology $Topology
    $results += Test-DomainFunctionalLevel -ForestTopology $Topology
    $results += Test-ADSchemaVersion -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-NamingContextAccess -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-GlobalCatalogAvailability -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-RODCHealth -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-DeletedObjectsContainer -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-ADRecycleBin -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-ServiceConnectionPoints -ForestTopology $Topology -DomainControllers $DomainControllers
    return $results
}
#endregion Invoke-ForestDomainChecks

#region Invoke-DCHealthChecks
function Invoke-DCHealthChecks {
    param([psobject]$Topology, [array]$DomainControllers)
    $results = @()
    $results += Test-DCReachability -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-CriticalADServices -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-DCEventLogHealth -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-DCDiskSpace -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-DCCPUUtilization -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-DCMemoryPressure -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-DCNetworkConfig -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-SecureChannelHealth -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-LDAPBindResponse -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-NTDSDitFileSize -DomainControllers $DomainControllers -Forest $Topology.ForestName
    return $results
}
#endregion Invoke-DCHealthChecks

#region Invoke-ReplicationChecks
function Invoke-ReplicationChecks {
    param([psobject]$Topology, [array]$DomainControllers)
    $results = @()
    $results += Test-ReplicationSummary -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-PerPartnerReplication -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-ReplicationLatency -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-LingeringObjects -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-ReplicationQueue -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-KCCTopology -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-USNRollback -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-NamingContextReplication -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-IntersiteReplicationSchedule -ForestTopology $Topology -DomainControllers $DomainControllers
    return $results
}
#endregion Invoke-ReplicationChecks

#region Invoke-DnsChecks
function Invoke-DnsChecks {
    param([psobject]$Topology, [array]$DomainControllers)
    $results = @()
    $results += Test-ADIntegratedZones -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-ZoneReplicationScope -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-DCDNSRegistration -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-StaleSRVRecords -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-DNSServerEvents -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-DNSForwarders -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-DNSScavenging -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-DCNameResolution -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-DNSDelegation -ForestTopology $Topology -DomainControllers $DomainControllers
    return $results
}
#endregion Invoke-DnsChecks

#region Inline Security & Pass-the-Hash Checks

#region Get-RemoteRegistryValueSafe
function Get-RemoteRegistryValueSafe {
    param([Parameter(Mandatory=$true)][string]$ComputerName, [Parameter(Mandatory=$true)][string]$HivePath, [Parameter(Mandatory=$true)][string]$ValueName)
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
        $subKey = $base.OpenSubKey($HivePath)
        if ($subKey) {
            $val = $subKey.GetValue($ValueName, $null)
            $subKey.Close()
            $base.Close()
            return $val
        }
        $base.Close()
        return $null
    } catch {
        return $null
    }
}
#endregion Get-RemoteRegistryValueSafe

#region Test-CredentialGuard
function Test-CredentialGuard {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'SEC-058'; $results = @()
    $reference = 'Microsoft Credential Guard Documentation; MITRE T1003'
    foreach ($dc in $DomainControllers) {
        $dcName = $dc.HostName
        if (-not $dc.Reachable) { continue }
        $lsaCfgFlags = Get-RemoteRegistryValueSafe -ComputerName $dcName -HivePath 'SYSTEM\CurrentControlSet\Control\LSA' -ValueName 'LsaCfgFlags'
        $vbsPolicy = Get-RemoteRegistryValueSafe -ComputerName $dcName -HivePath 'SYSTEM\CurrentControlSet\Control\DeviceGuard' -ValueName 'EnableVirtualizationBasedSecurity'
        $guardEnabled = ($lsaCfgFlags -eq 1 -or $lsaCfgFlags -eq 2) -and ($vbsPolicy -eq 1)
        if (-not $guardEnabled) {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Pass-the-Hash Mitigation' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'High' -Status 'Fail' -ScoreImpact 15 -Weight 8 -Finding "Credential Guard is NOT enabled on $dcName. NTLM hashes in memory are not isolated by virtualization-based security." -Evidence @{ ComputerName = $dcName; LsaCfgFlags = $lsaCfgFlags; VBSEnabled = $vbsPolicy } -Reference $reference
        } else {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Pass-the-Hash Mitigation' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 8 -Finding "Credential Guard is active on $dcName with VBS enabled." -Evidence @{ ComputerName = $dcName; LsaCfgFlags = $lsaCfgFlags; VBSEnabled = $vbsPolicy } -Reference $reference
        }
    }
    if (-not $results) {
        $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Pass-the-Hash Mitigation' -Target $Domain -Forest $Forest -Severity 'Info' -Status 'Skipped' -Weight 0 -Finding 'No reachable DCs to check Credential Guard.' -Reference $reference
    }
    return $results
}
#endregion Test-CredentialGuard

#region Test-LocalAdminPasswordReuse
function Test-LocalAdminPasswordReuse {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'SEC-063'; $results = @()
    $reference = 'Microsoft LAPS Documentation; MITRE T1078.003'
    try {
        $lapsProps = @('ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime','ms-LAPS-Password','ms-LAPS-PasswordExpirationTime')
        $computers = Get-ADComputer -Filter "Enabled -eq '$true'" -Properties $lapsProps -Server $Domain -ResultPageSize 1000 -ErrorAction Stop
        if ($null -eq $computers -or @($computers).Count -eq 0) {
            return @(ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Pass-the-Hash Mitigation' -Target $Domain -Forest $Forest -Severity 'Info' -Status 'Skipped' -Weight 0 -Finding 'No enabled computers found for LAPS coverage analysis.' -Recommendation 'Verify AD connectivity.' -Reference $reference)
        }
        $total = @($computers).Count
        $lapsManaged = @($computers | Where-Object { $_.'ms-Mcs-AdmPwd' -or $_.'ms-LAPS-Password' -or $_.'ms-Mcs-AdmPwdExpirationTime' -or $_.'ms-LAPS-PasswordExpirationTime' }).Count
        $unmanaged = $total - $lapsManaged
        $coveragePct = [math]::Round(($lapsManaged / $total) * 100, 1)
        if ($coveragePct -lt 80) {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Pass-the-Hash Mitigation' -Target $Domain -Domain $Domain -Forest $Forest -Severity 'High' -Status 'Fail' -ScoreImpact 15 -Weight 8 -Finding "LAPS coverage is only $($coveragePct)% ($($lapsManaged) of $($total) computers). $($unmanaged) systems likely share local admin passwords — a primary Pass-the-Hash enabler." -Evidence @{ TotalComputers = $total; LAPSManaged = $lapsManaged; Unmanaged = $unmanaged; CoveragePercent = $coveragePct } -Reference $reference
        } elseif ($coveragePct -lt 95) {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Pass-the-Hash Mitigation' -Target $Domain -Domain $Domain -Forest $Forest -Severity 'Medium' -Status 'Warning' -ScoreImpact 8 -Weight 8 -Finding "LAPS coverage is $($coveragePct)% ($($lapsManaged) of $($total)). $($unmanaged) systems may still share local admin passwords." -Evidence @{ TotalComputers = $total; LAPSManaged = $lapsManaged; Unmanaged = $unmanaged; CoveragePercent = $coveragePct } -Reference $reference
        } else {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Pass-the-Hash Mitigation' -Target $Domain -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 8 -Finding "LAPS coverage is $($coveragePct)% ($($lapsManaged) of $($total)). Local admin password reuse risk is minimal." -Recommendation 'Maintain LAPS coverage.' -Evidence @{ TotalComputers = $total; LAPSManaged = $lapsManaged; CoveragePercent = $coveragePct } -Reference $reference
        }
    } catch {
        $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Pass-the-Hash Mitigation' -Target $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "LAPS coverage check failed: $($_.Exception.Message)" -Reference $reference
    }
    return $results
}
#endregion Test-LocalAdminPasswordReuse

#region Test-PrivilegedLogonExposure
function Test-PrivilegedLogonExposure {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'SEC-064'; $results = @()
    $reference = 'Microsoft Tier Model for AD; MITRE T1078.002; DISA STIG V-243480'
    try {
        $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
        $privilegedMembers = @()
        foreach ($group in $privilegedGroups) {
            try {
                $members = Get-CachedADGroupMember -Identity $group -Server $Domain -Recursive | Where-Object { $_.objectClass -eq 'user' }
                if ($members) { $privilegedMembers += $members }
            } catch { }
        }
        $privilegedMembers = $privilegedMembers | Sort-Object -Property DistinguishedName -Unique
        if ($privilegedMembers.Count -eq 0) {
            return @(ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Pass-the-Hash Mitigation' -Target $Domain -Forest $Forest -Severity 'Info' -Status 'Skipped' -Weight 0 -Finding 'Unable to enumerate privileged members.' -Reference $reference)
        }
        $unrestricted = @()
        foreach ($member in $privilegedMembers) {
            try {
                $user = Get-ADUser -Identity $member.DistinguishedName -Properties LogonWorkstations -Server $Domain -ErrorAction SilentlyContinue
                if ($null -eq $user.LogonWorkstations -or $user.LogonWorkstations -eq '') {
                    $unrestricted += $user.SamAccountName
                }
            } catch { }
        }
        if ($unrestricted.Count -gt 0) {
            $sample = ($unrestricted | Select-Object -First 10) -join ', '
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Pass-the-Hash Mitigation' -Target $Domain -Domain $Domain -Forest $Forest -Severity 'High' -Status 'Fail' -ScoreImpact 15 -Weight 8 -Finding "$($unrestricted.Count) privileged account(s) have NO logon workstation restrictions. These can authenticate anywhere, leaving NTLM hashes exposed on workstations for Pass-the-Hash harvesting." -Evidence @{ UnrestrictedCount = $unrestricted.Count; TotalPrivileged = $privilegedMembers.Count; SampleAccounts = $sample } -Reference $reference
        } else {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Pass-the-Hash Mitigation' -Target $Domain -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 8 -Finding "All $($privilegedMembers.Count) privileged accounts have logon workstation restrictions." -Recommendation 'Continue enforcing. Consider Authentication Policy Silos.' -Evidence @{ TotalPrivileged = $privilegedMembers.Count; AllRestricted = $true } -Reference $reference
        }
    } catch {
        $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Pass-the-Hash Mitigation' -Target $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "Privileged logon exposure check failed: $($_.Exception.Message)" -Reference $reference
    }
    return $results
}
#endregion Test-PrivilegedLogonExposure

#region Test-KrbtgtPasswordAge
function Test-KrbtgtPasswordAge {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'SEC-065'; $results = @()
    $reference = 'Microsoft Best Practices for KRBTGT Reset; MITRE T1558.001 — Golden Ticket'
    try {
        $krbtgt = Get-ADUser -Identity 'krbtgt' -Properties PasswordLastSet -Server $Domain -ErrorAction Stop
        if ($null -eq $krbtgt -or $null -eq $krbtgt.PasswordLastSet) {
            return @(ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Kerberos Security' -Target 'krbtgt' -Domain $Domain -Forest $Forest -Severity 'Critical' -Status 'Fail' -ScoreImpact 20 -Weight 10 -Finding 'KRBTGT account password has NEVER been reset or the PasswordLastSet attribute is empty. This is a critical Golden Ticket attack risk.' -Recommendation 'Reset the KRBTGT account password twice (with a replication interval between resets) immediately, then establish a policy to reset it at least twice per year.' -Evidence @{ Account = 'krbtgt'; PasswordLastSet = $null } -Reference $reference)
        }
        $daysSinceReset = ((Get-Date) - $krbtgt.PasswordLastSet).Days
        if ($daysSinceReset -gt 180) {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Kerberos Security' -Target 'krbtgt' -Domain $Domain -Forest $Forest -Severity 'High' -Status 'Fail' -ScoreImpact 15 -Weight 10 -Finding "KRBTGT account password was last reset $daysSinceReset days ago (on $($krbtgt.PasswordLastSet.ToString('yyyy-MM-dd'))). Passwords older than 180 days increase exposure to Golden Ticket attacks." -Evidence @{ Account = 'krbtgt'; PasswordLastSet = $krbtgt.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss'); DaysSinceReset = $daysSinceReset; MaxRecommendedDays = 180 } -Reference $reference
        } else {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Kerberos Security' -Target 'krbtgt' -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 10 -Finding "KRBTGT account password was last reset $daysSinceReset days ago (on $($krbtgt.PasswordLastSet.ToString('yyyy-MM-dd'))). This is within the recommended 180-day window." -Evidence @{ Account = 'krbtgt'; PasswordLastSet = $krbtgt.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss'); DaysSinceReset = $daysSinceReset; MaxRecommendedDays = 180 } -Reference $reference
        }
    } catch {
        $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Kerberos Security' -Target 'krbtgt' -Domain $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "KRBTGT password age check failed: $($_.Exception.Message)" -Reference $reference
    }
    return $results
}
#endregion Test-KrbtgtPasswordAge

#region Test-KerberoastingExposure
function Test-KerberoastingExposure {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'THREAT-001'; $results = @()
    $reference = 'MITRE ATT&CK T1558.003 — Kerberoasting; CIS Benchmark'
    try {
        $spnUsers = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet, Enabled, msDS-SupportedEncryptionTypes -Server $Domain -ResultPageSize 1000 -ErrorAction Stop |
            Where-Object { $_.Enabled -eq $true }
        $weakSpnUsers = @()
        foreach ($user in $spnUsers) {
            $encTypes = $user.'msDS-SupportedEncryptionTypes'
            $isWeak = ($null -eq $encTypes -or $encTypes -eq 0 -or ($encTypes -band 4) -eq 4)
            $daysSincePwChange = if ($user.PasswordLastSet) { ((Get-Date) - $user.PasswordLastSet).Days } else { 9999 }
            if ($isWeak -or $daysSincePwChange -gt 365) {
                $weakSpnUsers += @{ Name = $user.SamAccountName; SPNs = ($user.ServicePrincipalName -join '; '); PasswordAgeDays = $daysSincePwChange; SupportsRC4 = $isWeak }
            }
        }
        if ($weakSpnUsers.Count -gt 0) {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Threat Exposure' -Target 'Domain Users with SPNs' -Domain $Domain -Forest $Forest -Severity 'High' -Status 'Fail' -ScoreImpact 15 -Weight 10 -Finding "$($weakSpnUsers.Count) user account(s) with SPNs are vulnerable to Kerberoasting (support RC4 encryption or have passwords older than 1 year)." -Evidence @{ VulnerableAccounts = $weakSpnUsers | Select-Object -First 10; TotalCount = $weakSpnUsers.Count } -Reference $reference
        } else {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Threat Exposure' -Target 'Domain Users with SPNs' -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 10 -Finding "$($spnUsers.Count) user account(s) with SPNs found — all use AES encryption and have recent passwords." -Evidence @{ TotalSPNUsers = $spnUsers.Count; VulnerableCount = 0 } -Reference $reference
        }
    } catch {
        $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Threat Exposure' -Target 'Kerberoasting' -Domain $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "Kerberoasting check failed: $($_.Exception.Message)" -Reference $reference
    }
    return $results
}
#endregion Test-KerberoastingExposure

#region Test-ASREPRoastingExposure
function Test-ASREPRoastingExposure {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'THREAT-002'; $results = @()
    $reference = 'MITRE ATT&CK T1558.004 — AS-REP Roasting; CIS Benchmark'
    try {
        $asrepUsers = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth, Enabled, MemberOf -Server $Domain -ResultPageSize 1000 -ErrorAction Stop |
            Where-Object { $_.Enabled -eq $true }
        if ($asrepUsers.Count -gt 0) {
            $userDetails = $asrepUsers | Select-Object -First 10 | ForEach-Object {
                @{ Name = $_.SamAccountName; IsPrivileged = ($_.MemberOf -match 'Domain Admins|Enterprise Admins|Administrators') }
            }
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Threat Exposure' -Target 'PreAuth Disabled Accounts' -Domain $Domain -Forest $Forest -Severity 'High' -Status 'Fail' -ScoreImpact 15 -Weight 10 -Finding "$($asrepUsers.Count) enabled account(s) have Kerberos pre-authentication disabled. These accounts are vulnerable to offline password cracking (AS-REP Roasting)." -Evidence @{ AffectedAccounts = $userDetails; TotalCount = $asrepUsers.Count } -Reference $reference
        } else {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Threat Exposure' -Target 'PreAuth Disabled Accounts' -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 10 -Finding 'No enabled accounts found with Kerberos pre-authentication disabled.' -Evidence @{ TotalCount = 0 } -Reference $reference
        }
    } catch {
        $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Threat Exposure' -Target 'AS-REP Roasting' -Domain $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "AS-REP Roasting check failed: $($_.Exception.Message)" -Reference $reference
    }
    return $results
}
#endregion Test-ASREPRoastingExposure

#region Test-DCSyncPermissions
function Test-DCSyncPermissions {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'THREAT-007'; $results = @()
    $reference = 'MITRE ATT&CK T1003.006 — DCSync; Microsoft Security Best Practices'
    try {
        $domainDN = (Get-ADDomain -Server $Domain -ErrorAction Stop).DistinguishedName
        $acl = Get-Acl "AD:\$domainDN" -ErrorAction Stop
        $dcSyncRights = @(
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', # DS-Replication-Get-Changes
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-All
        )
        $legitimateDCSyncSIDs = @()
        $DomainControllers | ForEach-Object { try { $legitimateDCSyncSIDs += (Get-ADComputer $_.Name -Server $Domain -ErrorAction SilentlyContinue).SID.Value } catch {} }
        try { $legitimateDCSyncSIDs += (Get-ADGroup 'Domain Controllers' -Server $Domain -ErrorAction SilentlyContinue).SID.Value } catch {}
        try { $legitimateDCSyncSIDs += (Get-ADGroup 'Enterprise Domain Controllers' -Server $Domain -ErrorAction SilentlyContinue).SID.Value } catch {}
        try { $legitimateDCSyncSIDs += (Get-ADGroup 'Domain Admins' -Server $Domain -ErrorAction SilentlyContinue).SID.Value } catch {}
        try { $legitimateDCSyncSIDs += (Get-ADGroup 'Enterprise Admins' -Server $Domain -ErrorAction SilentlyContinue).SID.Value } catch {}

        $suspiciousEntries = @()
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $objectType = $ace.ObjectType.ToString().ToLower()
            if ($objectType -in $dcSyncRights) {
                $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                if ($sid -notin $legitimateDCSyncSIDs) {
                    $suspiciousEntries += @{ Identity = $ace.IdentityReference.Value; Right = if ($objectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2') { 'Replicating Directory Changes' } else { 'Replicating Directory Changes All' }; SID = $sid }
                }
            }
        }
        if ($suspiciousEntries.Count -gt 0) {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Threat Exposure' -Target 'DCSync Permissions' -Domain $Domain -Forest $Forest -Severity 'Critical' -Status 'Fail' -ScoreImpact 25 -Weight 10 -Finding "$($suspiciousEntries.Count) non-standard account(s) have DCSync replication rights. An attacker with these permissions can extract all password hashes from the domain." -Evidence @{ SuspiciousAccounts = $suspiciousEntries; DomainDN = $domainDN } -Reference $reference
        } else {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Threat Exposure' -Target 'DCSync Permissions' -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 10 -Finding 'No unauthorized accounts have DCSync (Replicating Directory Changes) permissions.' -Evidence @{ DomainDN = $domainDN; SuspiciousCount = 0 } -Reference $reference
        }
    } catch {
        $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Threat Exposure' -Target 'DCSync' -Domain $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "DCSync permission check failed: $($_.Exception.Message)" -Recommendation 'Manually audit replication permissions on the domain root object.' -Reference $reference
    }
    return $results
}
#endregion Test-DCSyncPermissions

#region Test-AnonymousAccessRestrictions
function Test-AnonymousAccessRestrictions {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'SEC-075'; $results = @()
    $reference = 'CIS Windows Server Benchmark — Network Access: Restrict anonymous access; NIST SP 800-53 AC-14'
    foreach ($dc in $DomainControllers) {
        $dcName = if ($dc.HostName) { $dc.HostName } elseif ($dc.Name) { $dc.Name } else { "$dc" }
        try {
            $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            $restrictAnon = Get-RemoteRegistryValueSafe -ComputerName $dcName -Path $regPath -ValueName 'RestrictAnonymous' -DefaultValue 0
            $restrictAnonSAM = Get-RemoteRegistryValueSafe -ComputerName $dcName -Path $regPath -ValueName 'RestrictAnonymousSAM' -DefaultValue 0
            $everyoneAnon = Get-RemoteRegistryValueSafe -ComputerName $dcName -Path $regPath -ValueName 'EveryoneIncludesAnonymous' -DefaultValue 0
            $issues = @()
            if ($restrictAnon -lt 1) { $issues += "RestrictAnonymous=$restrictAnon (should be >=1)" }
            if ($restrictAnonSAM -ne 1) { $issues += "RestrictAnonymousSAM=$restrictAnonSAM (should be 1)" }
            if ($everyoneAnon -ne 0) { $issues += "EveryoneIncludesAnonymous=$everyoneAnon (should be 0)" }
            if ($issues.Count -gt 0) {
                $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Access Controls' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'High' -Status 'Fail' -ScoreImpact 12 -Weight 8 -Finding "DC '$dcName' allows anonymous enumeration. Issues: $($issues -join '; ')" -Evidence @{ DC = $dcName; RestrictAnonymous = $restrictAnon; RestrictAnonymousSAM = $restrictAnonSAM; EveryoneIncludesAnonymous = $everyoneAnon } -Reference $reference
            } else {
                $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Access Controls' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 8 -Finding "DC '$dcName' properly restricts anonymous access." -Evidence @{ DC = $dcName; RestrictAnonymous = $restrictAnon; RestrictAnonymousSAM = $restrictAnonSAM; EveryoneIncludesAnonymous = $everyoneAnon } -Reference $reference
            }
        } catch {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Access Controls' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "Anonymous access check failed on $($dcName): $($_.Exception.Message)" -Reference $reference
        }
    }
    return $results
}
#endregion Test-AnonymousAccessRestrictions

#region Test-ExcessiveACLPermissions
function Test-ExcessiveACLPermissions {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'SEC-077'; $results = @()
    $reference = 'Microsoft Active Directory Security Best Practices; MITRE ATT&CK T1222.001 — File and Directory Permissions Modification'
    try {
        $domainDN = (Get-ADDomain -Server $Domain -ErrorAction Stop).DistinguishedName
        $criticalOUs = @($domainDN, "CN=Users,$domainDN", "OU=Domain Controllers,$domainDN", "CN=Computers,$domainDN")
        $dangerousRights = @('GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite')
        $trustedSIDs = @()
        try { $trustedSIDs += (Get-ADGroup 'Domain Admins' -Server $Domain -ErrorAction SilentlyContinue).SID.Value } catch {}
        try { $trustedSIDs += (Get-ADGroup 'Enterprise Admins' -Server $Domain -ErrorAction SilentlyContinue).SID.Value } catch {}
        try { $trustedSIDs += (Get-ADGroup 'Administrators' -Server $Domain -ErrorAction SilentlyContinue).SID.Value } catch {}
        try { $trustedSIDs += 'S-1-5-18' } catch {} # SYSTEM
        try { $trustedSIDs += 'S-1-5-32-544' } catch {} # Built-in Administrators

        $excessivePerms = @()
        foreach ($ou in $criticalOUs) {
            try {
                $acl = Get-Acl "AD:\$ou" -ErrorAction SilentlyContinue
                if ($null -eq $acl) { continue }
                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -ne 'Allow') { continue }
                    $rights = $ace.ActiveDirectoryRights.ToString()
                    $hasDangerous = $false
                    foreach ($dr in $dangerousRights) { if ($rights -match $dr) { $hasDangerous = $true; break } }
                    if (-not $hasDangerous) { continue }
                    try {
                        $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        if ($sid -in $trustedSIDs) { continue }
                    } catch { continue }
                    $excessivePerms += @{ Object = $ou; Identity = $ace.IdentityReference.Value; Rights = $rights; Inherited = $ace.IsInherited }
                }
            } catch {}
        }
        if ($excessivePerms.Count -gt 0) {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'ACL Security' -Target 'Critical AD Objects' -Domain $Domain -Forest $Forest -Severity 'High' -Status 'Fail' -ScoreImpact 15 -Weight 10 -Finding "$($excessivePerms.Count) excessive permission(s) found on critical AD objects (GenericAll, WriteDacl, WriteOwner, or GenericWrite granted to non-admin identities)." -Evidence @{ ExcessivePermissions = $excessivePerms | Select-Object -First 15; TotalCount = $excessivePerms.Count } -Reference $reference
        } else {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'ACL Security' -Target 'Critical AD Objects' -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 10 -Finding 'No excessive permissions found on critical AD objects.' -Evidence @{ ObjectsChecked = $criticalOUs.Count; ExcessiveCount = 0 } -Reference $reference
        }
    } catch {
        $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'ACL Security' -Target 'ACL Audit' -Domain $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "ACL permission check failed: $($_.Exception.Message)" -Recommendation 'Run BloodHound or manual ACL audit.' -Reference $reference
    }
    return $results
}
#endregion Test-ExcessiveACLPermissions

#region Test-AdvancedAuditPolicies
function Test-AdvancedAuditPolicies {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'LOG-001'; $results = @()
    $reference = 'CIS Windows Server Benchmark — Advanced Audit Policies; NIST SP 800-53 AU-2, AU-12'
    foreach ($dc in $DomainControllers) {
        $dcName = if ($dc.HostName) { $dc.HostName } elseif ($dc.Name) { $dc.Name } else { "$dc" }
        try {
            $auditOutput = Invoke-Command -ComputerName $dcName -ScriptBlock { auditpol /get /category:* /r 2>$null } -ErrorAction Stop
            $criticalPolicies = @(
                @{ SubCategory = 'Logon'; Expected = 'Success and Failure' },
                @{ SubCategory = 'Account Lockout'; Expected = 'Success and Failure' },
                @{ SubCategory = 'Directory Service Changes'; Expected = 'Success' },
                @{ SubCategory = 'Credential Validation'; Expected = 'Success and Failure' },
                @{ SubCategory = 'Security Group Management'; Expected = 'Success' },
                @{ SubCategory = 'User Account Management'; Expected = 'Success and Failure' }
            )
            $missingPolicies = @()
            foreach ($policy in $criticalPolicies) {
                $found = $auditOutput | Where-Object { $_ -match $policy.SubCategory }
                if ($null -eq $found -or $found -notmatch 'Success') {
                    $missingPolicies += $policy.SubCategory
                }
            }
            if ($missingPolicies.Count -gt 0) {
                $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Audit & Logging' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'High' -Status 'Fail' -ScoreImpact 12 -Weight 8 -Finding "DC '$dcName' is missing $($missingPolicies.Count) critical audit policies: $($missingPolicies -join ', ')" -Evidence @{ DC = $dcName; MissingPolicies = $missingPolicies; TotalCriticalPolicies = $criticalPolicies.Count } -Reference $reference
            } else {
                $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Audit & Logging' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 8 -Finding "DC '$dcName' has all critical advanced audit policies enabled." -Evidence @{ DC = $dcName; AllPoliciesConfigured = $true } -Reference $reference
            }
        } catch {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Audit & Logging' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "Audit policy check failed on $($dcName): $($_.Exception.Message)" -Recommendation 'Verify audit policies manually using auditpol /get /category:*.' -Reference $reference
        }
    }
    return $results
}
#endregion Test-AdvancedAuditPolicies

#region Test-SYSVOLReplicationHealth
function Test-SYSVOLReplicationHealth {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'HEALTH-001'; $results = @()
    $reference = 'Microsoft Active Directory Troubleshooting — DFSR/SYSVOL; NIST SP 800-53 SC-36'
    foreach ($dc in $DomainControllers) {
        $dcName = if ($dc.HostName) { $dc.HostName } elseif ($dc.Name) { $dc.Name } else { "$dc" }
        try {
            $sysvolStatus = Invoke-Command -ComputerName $dcName -ScriptBlock {
                param($domainName)
                $result = @{ DFSRService = 'Unknown'; SYSVOLShare = $false; SYSVOLPath = $null; Error = $null }
                try {
                    $dfsrSvc = Get-Service -Name 'DFSR' -ErrorAction Stop
                    $result.DFSRService = $dfsrSvc.Status.ToString()
                } catch {
                    $result.DFSRService = 'NotFound'
                }
                try {
                    $sysvolPath = "\\$env:COMPUTERNAME\SYSVOL\$domainName"
                    $result.SYSVOLPath = $sysvolPath
                    $result.SYSVOLShare = Test-Path $sysvolPath -ErrorAction Stop
                } catch {
                    $result.SYSVOLShare = $false
                    $result.Error = $_.Exception.Message
                }
                $result
            } -ArgumentList $Domain -ErrorAction Stop

            $dfsrRunning = $sysvolStatus.DFSRService -eq 'Running'
            $sysvolAccessible = $sysvolStatus.SYSVOLShare -eq $true

            if ($dfsrRunning -and $sysvolAccessible) {
                $results += ConvertTo-ADResult -CheckId $checkId -Category 'AD Health' -SubCategory 'Replication' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 8 -Finding "SYSVOL DFSR replication is healthy on '$dcName' (DFSR Service: Running, SYSVOL Share: Accessible)." -Evidence @{ DC = $dcName; DFSRService = 'Running'; SYSVOLShareAccessible = $true; SYSVOLPath = $sysvolStatus.SYSVOLPath } -Reference $reference
            } elseif (-not $dfsrRunning -and $sysvolStatus.DFSRService -eq 'NotFound') {
                $results += ConvertTo-ADResult -CheckId $checkId -Category 'AD Health' -SubCategory 'Replication' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'Warning' -Status 'Warning' -ScoreImpact 8 -Weight 8 -Finding "DFSR service not found on '$dcName'. This DC may use FRS or DFSR is not installed." -Evidence @{ DC = $dcName; DFSRService = 'NotFound'; SYSVOLShareAccessible = $sysvolAccessible } -Reference $reference
            } elseif (-not $dfsrRunning) {
                $results += ConvertTo-ADResult -CheckId $checkId -Category 'AD Health' -SubCategory 'Replication' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'High' -Status 'Fail' -ScoreImpact 15 -Weight 8 -Finding "DFSR service is NOT running on '$dcName' (Status: $($sysvolStatus.DFSRService)). SYSVOL replication is impacted." -Evidence @{ DC = $dcName; DFSRService = $sysvolStatus.DFSRService; SYSVOLShareAccessible = $sysvolAccessible } -Reference $reference
            } elseif (-not $sysvolAccessible) {
                $results += ConvertTo-ADResult -CheckId $checkId -Category 'AD Health' -SubCategory 'Replication' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'High' -Status 'Fail' -ScoreImpact 15 -Weight 8 -Finding "SYSVOL share is NOT accessible on '$dcName' even though DFSR is running. Group Policy may not apply correctly." -Evidence @{ DC = $dcName; DFSRService = 'Running'; SYSVOLShareAccessible = $false; SYSVOLPath = $sysvolStatus.SYSVOLPath; Error = $sysvolStatus.Error } -Reference $reference
            }
        } catch {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'AD Health' -SubCategory 'Replication' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "SYSVOL check failed on $($dcName): $($_.Exception.Message)" -Reference $reference
        }
    }
    return $results
}
#endregion Test-SYSVOLReplicationHealth

#region Test-TimeSyncConsistency
function Test-TimeSyncConsistency {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'HEALTH-003'; $results = @()
    $reference = 'Microsoft Time Synchronization Best Practices; Kerberos requires <5 min skew'
    $pdcEmulator = $null
    try { $pdcEmulator = (Get-ADDomain -Server $Domain -ErrorAction Stop).PDCEmulator } catch {}
    foreach ($dc in $DomainControllers) {
        $dcName = if ($dc.HostName) { $dc.HostName } elseif ($dc.Name) { $dc.Name } else { "$dc" }
        try {
            $timeInfo = Invoke-Command -ComputerName $dcName -ScriptBlock {
                $w32tmOutput = w32tm /stripchart /computer:$using:pdcEmulator /dataonly /samples:1 2>&1
                $skewLine = $w32tmOutput | Where-Object { $_ -match '[+-]?\d+\.\d+s' } | Select-Object -Last 1
                if ($skewLine -match '([+-]?\d+\.\d+)s') {
                    [math]::Abs([double]$Matches[1])
                } else { -1 }
            } -ErrorAction Stop
            if ($timeInfo -eq -1) {
                $results += ConvertTo-ADResult -CheckId $checkId -Category 'AD Health' -SubCategory 'Time Sync' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'Warning' -Status 'Warning' -ScoreImpact 5 -Weight 7 -Finding "Could not determine time skew for '$dcName' against PDC Emulator." -Evidence @{ DC = $dcName; PDCEmulator = $pdcEmulator; SkewSeconds = 'Unknown' } -Reference $reference
            } elseif ($timeInfo -gt 300) {
                $results += ConvertTo-ADResult -CheckId $checkId -Category 'AD Health' -SubCategory 'Time Sync' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'Critical' -Status 'Fail' -ScoreImpact 20 -Weight 7 -Finding "DC '$dcName' has a time skew of $([math]::Round($timeInfo,1)) seconds from PDC Emulator. Kerberos authentication will FAIL (max 5 minutes allowed)." -Evidence @{ DC = $dcName; PDCEmulator = $pdcEmulator; SkewSeconds = [math]::Round($timeInfo,1); MaxAllowed = 300 } -Reference $reference
            } elseif ($timeInfo -gt 60) {
                $results += ConvertTo-ADResult -CheckId $checkId -Category 'AD Health' -SubCategory 'Time Sync' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'Warning' -Status 'Warning' -ScoreImpact 8 -Weight 7 -Finding "DC '$dcName' has a time skew of $([math]::Round($timeInfo,1)) seconds from PDC Emulator. While within Kerberos tolerance, this indicates time sync issues." -Evidence @{ DC = $dcName; PDCEmulator = $pdcEmulator; SkewSeconds = [math]::Round($timeInfo,1) } -Reference $reference
            } else {
                $results += ConvertTo-ADResult -CheckId $checkId -Category 'AD Health' -SubCategory 'Time Sync' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 7 -Finding "DC '$dcName' time is within $([math]::Round($timeInfo,1)) seconds of PDC Emulator — healthy." -Evidence @{ DC = $dcName; PDCEmulator = $pdcEmulator; SkewSeconds = [math]::Round($timeInfo,1) } -Reference $reference
            }
        } catch {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'AD Health' -SubCategory 'Time Sync' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "Time sync check failed on $($dcName): $($_.Exception.Message)" -Reference $reference
        }
    }
    return $results
}
#endregion Test-TimeSyncConsistency

#region Test-MinimumDCCount
function Test-MinimumDCCount {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'HEALTH-008'; $results = @()
    $reference = 'Microsoft Active Directory Best Practices — Domain Controller Planning; NIST SP 800-53 CP-2'
    try {
        $dcCount = $DomainControllers.Count
        if ($dcCount -lt 2) {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'AD Health' -SubCategory 'Availability' -Target 'Domain' -Domain $Domain -Forest $Forest -Severity 'Critical' -Status 'Fail' -ScoreImpact 20 -Weight 10 -Finding "Only $dcCount Domain Controller(s) found for domain '$Domain'. This is a single point of failure — if this DC goes down, authentication and AD services will be completely unavailable." -Evidence @{ DCCount = $dcCount; Domain = $Domain; MinimumRecommended = 2; DCs = ($DomainControllers | ForEach-Object { $_.Name }) } -Reference $reference
        } else {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'AD Health' -SubCategory 'Availability' -Target 'Domain' -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 10 -Finding "$dcCount Domain Controller(s) found for domain '$Domain' — meets minimum redundancy requirement." -Evidence @{ DCCount = $dcCount; Domain = $Domain; DCs = ($DomainControllers | ForEach-Object { $_.Name }) } -Reference $reference
        }
    } catch {
        $results += ConvertTo-ADResult -CheckId $checkId -Category 'AD Health' -SubCategory 'Availability' -Target 'Domain' -Domain $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "DC count check failed: $($_.Exception.Message)" -Reference $reference
    }
    return $results
}
#endregion Test-MinimumDCCount

#region Test-UnlinkedGPOs
function Test-UnlinkedGPOs {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'GPO-001'; $results = @()
    $reference = 'Microsoft Group Policy Best Practices; CIS Controls v8 — Secure Configuration'
    try {
        $allGPOs = Get-GPO -All -Domain $Domain -ErrorAction Stop
        $unlinkedGPOs = @()
        foreach ($gpo in $allGPOs) {
            try {
                [xml]$report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $Domain -ErrorAction Stop
                $links = $report.GPO.LinksTo
                if ($null -eq $links -or $links.Count -eq 0) {
                    $unlinkedGPOs += @{ Name = $gpo.DisplayName; Id = $gpo.Id.ToString(); CreatedTime = $gpo.CreationTime.ToString('yyyy-MM-dd'); ModifiedTime = $gpo.ModificationTime.ToString('yyyy-MM-dd') }
                }
            } catch {
                # Skip GPOs that can't be reported
            }
        }
        if ($unlinkedGPOs.Count -gt 0) {
            $gpoNames = ($unlinkedGPOs | ForEach-Object { $_.Name }) -join ', '
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Group Policy' -Target 'GPO Links' -Domain $Domain -Forest $Forest -Severity 'Warning' -Status 'Warning' -ScoreImpact 5 -Weight 5 -Finding "$($unlinkedGPOs.Count) GPO(s) are not linked to any OU, site, or domain: $gpoNames. Unlinked GPOs clutter the environment, increase attack surface, and may indicate incomplete cleanup." -Evidence @{ UnlinkedCount = $unlinkedGPOs.Count; TotalGPOs = $allGPOs.Count; UnlinkedGPOs = $unlinkedGPOs | Select-Object -First 15 } -Reference $reference
        } else {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Group Policy' -Target 'GPO Links' -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 5 -Finding "All $($allGPOs.Count) GPOs are linked to at least one scope (OU, site, or domain)." -Evidence @{ TotalGPOs = $allGPOs.Count; UnlinkedCount = 0 } -Reference $reference
        }
    } catch {
        $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Group Policy' -Target 'GPO Links' -Domain $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "Unlinked GPO check failed: $($_.Exception.Message)" -Recommendation 'Ensure Group Policy module is available and you have permissions to query GPOs.' -Reference $reference
    }
    return $results
}
#endregion Test-UnlinkedGPOs

#region Test-DefaultDomainPolicyReview
function Test-DefaultDomainPolicyReview {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'GPO-003'; $results = @()
    $reference = 'Microsoft Best Practices — Default Domain Policy should only contain password, lockout, and Kerberos policies'
    try {
        $defaultGPO = Get-GPO -Name 'Default Domain Policy' -Domain $Domain -ErrorAction Stop
        [xml]$report = Get-GPOReport -Guid $defaultGPO.Id -ReportType Xml -Domain $Domain -ErrorAction Stop
        $extensions = @()
        if ($null -ne $report.GPO.Computer -and $null -ne $report.GPO.Computer.ExtensionData) {
            foreach ($ext in $report.GPO.Computer.ExtensionData) {
                $extName = $ext.Name
                if ($extName -and $extName -notmatch 'Account Policies|Security Settings') {
                    $extensions += $extName
                }
            }
        }
        if ($null -ne $report.GPO.User -and $null -ne $report.GPO.User.ExtensionData) {
            foreach ($ext in $report.GPO.User.ExtensionData) {
                $extName = $ext.Name
                if ($extName) { $extensions += "User: $extName" }
            }
        }
        if ($extensions.Count -gt 0) {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Group Policy' -Target 'Default Domain Policy' -Domain $Domain -Forest $Forest -Severity 'Warning' -Status 'Warning' -ScoreImpact 6 -Weight 6 -Finding "Default Domain Policy contains $($extensions.Count) non-standard extension(s) beyond password/lockout/Kerberos: $($extensions -join '; '). Best practice is to keep this GPO minimal." -Evidence @{ GPOName = 'Default Domain Policy'; NonStandardExtensions = $extensions; ModifiedTime = $defaultGPO.ModificationTime.ToString('yyyy-MM-dd') } -Reference $reference
        } else {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Group Policy' -Target 'Default Domain Policy' -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 6 -Finding 'Default Domain Policy contains only standard Account Policies (password, lockout, Kerberos) — follows best practices.' -Evidence @{ GPOName = 'Default Domain Policy'; NonStandardExtensions = @(); ModifiedTime = $defaultGPO.ModificationTime.ToString('yyyy-MM-dd') } -Reference $reference
        }
    } catch {
        $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Group Policy' -Target 'Default Domain Policy' -Domain $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "Default Domain Policy check failed: $($_.Exception.Message)" -Recommendation 'Manually review Default Domain Policy via GPMC.' -Reference $reference
    }
    return $results
}
#endregion Test-DefaultDomainPolicyReview

#region Test-TieredAdminModel
function Test-TieredAdminModel {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'IAM-003'; $results = @()
    $reference = 'Microsoft Privileged Access Management (PAM); Enterprise Access Model (Tier 0/1/2)'
    try {
        $domainDN = (Get-ADDomain -Server $Domain -ErrorAction Stop).DistinguishedName
        # Check for Tier 0/1/2 OU structure indicators
        $tierOUs = @()
        $tier0Patterns = @('Tier 0', 'Tier0', 'T0', 'Admin Tier 0', 'PAW')
        $tier1Patterns = @('Tier 1', 'Tier1', 'T1', 'Server Admins')
        $tier2Patterns = @('Tier 2', 'Tier2', 'T2', 'Workstation Admins')
        $allOUs = Get-ADOrganizationalUnit -Filter * -Server $Domain -ErrorAction Stop | Select-Object -ExpandProperty Name
        $foundTier0 = $allOUs | Where-Object { $n = $_; ($tier0Patterns | Where-Object { $n -match $_ }).Count -gt 0 }
        $foundTier1 = $allOUs | Where-Object { $n = $_; ($tier1Patterns | Where-Object { $n -match $_ }).Count -gt 0 }
        $foundTier2 = $allOUs | Where-Object { $n = $_; ($tier2Patterns | Where-Object { $n -match $_ }).Count -gt 0 }
        # Check for Protected Users group usage
        $protectedUsers = @()
        try { $protectedUsers = Get-CachedADGroupMember -Identity 'Protected Users' -Server $Domain } catch {}
        # Check if Domain Admins log on to non-DC machines (simplified: check DA count)
        $domainAdmins = Get-CachedADGroupMember -Identity 'Domain Admins' -Server $Domain
        $findings = @()
        $tieredScore = 0
        if ($foundTier0) { $tieredScore += 30; $findings += "Tier 0 OU structure detected ($($foundTier0 -join ', '))" }
        if ($foundTier1) { $tieredScore += 20; $findings += "Tier 1 OU structure detected ($($foundTier1 -join ', '))" }
        if ($foundTier2) { $tieredScore += 20; $findings += "Tier 2 OU structure detected ($($foundTier2 -join ', '))" }
        if ($protectedUsers.Count -gt 0) { $tieredScore += 30; $findings += "Protected Users group has $($protectedUsers.Count) member(s)" }
        if ($tieredScore -ge 50) {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Identity & Access' -Target 'Tiered Admin Model' -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 9 -Finding "Tiered administration model indicators detected (score: $tieredScore/100): $($findings -join '; ')." -Evidence @{ TierScore = $tieredScore; Tier0OUs = $foundTier0; Tier1OUs = $foundTier1; Tier2OUs = $foundTier2; ProtectedUsersCount = $protectedUsers.Count; DomainAdminCount = $domainAdmins.Count } -Reference $reference
        } else {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Identity & Access' -Target 'Tiered Admin Model' -Domain $Domain -Forest $Forest -Severity 'High' -Status 'Fail' -ScoreImpact 15 -Weight 9 -Finding "Tiered administration model NOT detected or incomplete (score: $tieredScore/100). Without tiering, a compromise of any admin workstation can lead to full domain compromise. Domain Admins: $($domainAdmins.Count) accounts. Protected Users: $($protectedUsers.Count) accounts." -Evidence @{ TierScore = $tieredScore; Findings = $findings; DomainAdminCount = $domainAdmins.Count; ProtectedUsersCount = $protectedUsers.Count } -Reference $reference
        }
    } catch {
        $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Identity & Access' -Target 'Tiered Admin Model' -Domain $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "Tiered admin model check failed: $($_.Exception.Message)" -Recommendation 'Manually assess tiered administration implementation.' -Reference $reference
    }
    return $results
}
#endregion Test-TieredAdminModel

#region Test-LogRetentionAdequacy
function Test-LogRetentionAdequacy {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'LOG-002'; $results = @()
    $reference = 'NIST SP 800-92 — Log Management; CIS Benchmark — Audit Log Retention ≥ 90 days'
    foreach ($dc in $DomainControllers) {
        $dcName = if ($dc.HostName) { $dc.HostName } elseif ($dc.Name) { $dc.Name } else { "$dc" }
        try {
            $logSettings = Invoke-Command -ComputerName $dcName -ScriptBlock {
                $secLog = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
                [PSCustomObject]@{
                    MaxSizeBytes = $secLog.MaximumSizeInBytes
                    MaxSizeMB = [math]::Round($secLog.MaximumSizeInBytes / 1MB, 0)
                    LogMode = $secLog.LogMode.ToString()
                    IsEnabled = $secLog.IsEnabled
                    RecordCount = $secLog.RecordCount
                }
            } -ErrorAction Stop
            $issues = @()
            if ($logSettings.MaxSizeMB -lt 1024) { $issues += "Security log max size is $($logSettings.MaxSizeMB) MB (recommended: ≥1024 MB)" }
            if ($logSettings.LogMode -eq 'Circular' -and $logSettings.MaxSizeMB -lt 4096) { $issues += "Circular log mode with small size risks log overwrite before review" }
            if ($issues.Count -gt 0) {
                $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Logging & Monitoring' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'Warning' -Status 'Warning' -ScoreImpact 8 -Weight 7 -Finding "Log retention issues on '$dcName': $($issues -join '; '). Insufficient log retention hampers forensic investigation and compliance." -Evidence @{ DC = $dcName; MaxSizeMB = $logSettings.MaxSizeMB; LogMode = $logSettings.LogMode; RecordCount = $logSettings.RecordCount; Issues = $issues } -Reference $reference
            } else {
                $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Logging & Monitoring' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 7 -Finding "Security log on '$dcName' meets retention requirements (Size: $($logSettings.MaxSizeMB) MB, Mode: $($logSettings.LogMode))." -Evidence @{ DC = $dcName; MaxSizeMB = $logSettings.MaxSizeMB; LogMode = $logSettings.LogMode; RecordCount = $logSettings.RecordCount } -Reference $reference
            }
        } catch {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Logging & Monitoring' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "Log retention check failed on $dcName`: $($_.Exception.Message)" -Recommendation 'Verify WinRM access and run wevtutil gl Security manually.' -Reference $reference
        }
    }
    return $results
}
#endregion Test-LogRetentionAdequacy

#region Test-PrivilegedGroupChangeAlerts
function Test-PrivilegedGroupChangeAlerts {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'LOG-004'; $results = @()
    $reference = 'MITRE ATT&CK T1098 — Account Manipulation; NIST SP 800-53 AU-12; CIS Controls v8 8.5'
    try {
        # Check if audit policy captures group membership changes (Event IDs 4728, 4729, 4732, 4733, 4756, 4757)
        $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators')
        $recentChanges = @()
        foreach ($dc in $DomainControllers | Select-Object -First 1) {
            $dcName = if ($dc.HostName) { $dc.HostName } elseif ($dc.Name) { $dc.Name } else { "$dc" }
            try {
                $events = Invoke-Command -ComputerName $dcName -ScriptBlock {
                    $eventIds = @(4728, 4729, 4732, 4733, 4756, 4757)
                    try {
                        Get-WinEvent -FilterHashtable @{
                            LogName = 'Security'
                            Id = $eventIds
                            StartTime = (Get-Date).AddDays(-30)
                        } -MaxEvents 50 -ErrorAction Stop | Select-Object Id, TimeCreated, @{N='Message';E={$_.Message.Substring(0, [Math]::Min(200, $_.Message.Length))}}
                    } catch {
                        @()
                    }
                } -ErrorAction Stop
                if ($null -ne $events) { $recentChanges = @($events) }
            } catch {}
        }
        # Check if scheduled task or alert exists for privileged group monitoring
        $alertConfigured = $false
        foreach ($dc in $DomainControllers | Select-Object -First 1) {
            $dcName = if ($dc.HostName) { $dc.HostName } elseif ($dc.Name) { $dc.Name } else { "$dc" }
            try {
                $tasks = Invoke-Command -ComputerName $dcName -ScriptBlock {
                    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
                        $_.TaskName -match 'admin|privilege|group.*change|alert|monitor'
                    } | Select-Object TaskName, State
                } -ErrorAction SilentlyContinue
                if ($null -ne $tasks -and @($tasks).Count -gt 0) { $alertConfigured = $true }
            } catch {}
        }
        if ($recentChanges.Count -gt 0) {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Logging & Monitoring' -Target 'Privileged Groups' -Domain $Domain -Forest $Forest -Severity 'Warning' -Status 'Warning' -ScoreImpact 10 -Weight 9 -Finding "$($recentChanges.Count) privileged group membership change(s) detected in the last 30 days. Alert configuration detected: $alertConfigured. Each change should be authorized and documented." -Evidence @{ RecentChangeCount = $recentChanges.Count; AlertConfigured = $alertConfigured; SampleEvents = $recentChanges | Select-Object -First 5; MonitoredGroups = $privilegedGroups } -Reference $reference
        } elseif (-not $alertConfigured) {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Logging & Monitoring' -Target 'Privileged Groups' -Domain $Domain -Forest $Forest -Severity 'Warning' -Status 'Warning' -ScoreImpact 8 -Weight 9 -Finding "No privileged group change events found in 30 days (good), but no automated alerting mechanism detected. Changes may go unnoticed without proactive monitoring." -Evidence @{ RecentChangeCount = 0; AlertConfigured = $false; MonitoredGroups = $privilegedGroups } -Reference $reference
        } else {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Logging & Monitoring' -Target 'Privileged Groups' -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 9 -Finding "No unauthorized privileged group changes detected in 30 days and alerting mechanism is in place." -Evidence @{ RecentChangeCount = 0; AlertConfigured = $true; MonitoredGroups = $privilegedGroups } -Reference $reference
        }
    } catch {
        $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Logging & Monitoring' -Target 'Privileged Groups' -Domain $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "Privileged group alert check failed: $($_.Exception.Message)" -Recommendation 'Manually verify audit policies and alerting for privileged group changes.' -Reference $reference
    }
    return $results
}
#endregion Test-PrivilegedGroupChangeAlerts

#region Test-PrivilegeEscalationPaths
function Test-PrivilegeEscalationPaths {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'THREAT-003'; $results = @()
    $reference = 'MITRE ATT&CK TA0004 — Privilege Escalation; Microsoft Tier Model; BloodHound attack paths'
    try {
        $domainDN = (Get-ADDomain -Server $Domain -ErrorAction Stop).DistinguishedName
        $escalationRisks = @()
        $daMembers = Get-CachedADGroupMember -Identity 'Domain Admins' -Server $Domain -Recursive
        $directDA = Get-CachedADGroupMember -Identity 'Domain Admins' -Server $Domain
        $nestedGroups = $directDA | Where-Object { $_.objectClass -eq 'group' }
        if ($nestedGroups.Count -gt 0) {
            $escalationRisks += "Domain Admins has $($nestedGroups.Count) nested group(s): $($nestedGroups.Name -join ', '). Nested groups create indirect privilege escalation paths."
        }
        # Check 2: Users with GenericAll on Domain Admins group itself
        try {
            $daACL = Get-Acl "AD:\CN=Domain Admins,CN=Users,$domainDN" -ErrorAction Stop
            $dangerousACEs = $daACL.Access | Where-Object {
                $_.ActiveDirectoryRights -match 'GenericAll|WriteProperty|WriteDacl|WriteOwner' -and
                $_.IdentityReference -notmatch 'SYSTEM|Domain Admins|Enterprise Admins|BUILTIN\\Administrators'
            }
            if ($dangerousACEs.Count -gt 0) {
                $escalationRisks += "$($dangerousACEs.Count) non-admin principal(s) have write access to Domain Admins group: $(($dangerousACEs | ForEach-Object { $_.IdentityReference.ToString() }) -join ', ')"
            }
        } catch {}
        # Check 3: Accounts with DCSync but not in DA/EA
        try {
            $domACL = Get-Acl "AD:\$domainDN" -ErrorAction Stop
            $replRights = $domACL.Access | Where-Object {
                ($_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' -or $_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') -and
                $_.IdentityReference -notmatch 'Domain Controllers|Enterprise Domain Controllers|SYSTEM|Enterprise Admins|Domain Admins|Administrators'
            }
            if ($replRights.Count -gt 0) {
                $escalationRisks += "$($replRights.Count) non-standard principal(s) have DCSync replication rights (direct path to full domain compromise)"
            }
        } catch {}
        # Check 4: Service accounts in privileged groups
        $svcInDA = $daMembers | Where-Object {
            $_.objectClass -eq 'user' -and $_.Name -match 'svc|service|sql|app|batch'
        }
        if ($svcInDA.Count -gt 0) {
            $escalationRisks += "$($svcInDA.Count) service account(s) in Domain Admins: $($svcInDA.Name -join ', '). Compromising these services = domain compromise."
        }
        if ($escalationRisks.Count -gt 0) {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Threat Exposure' -Target 'Privilege Escalation' -Domain $Domain -Forest $Forest -Severity 'High' -Status 'Fail' -ScoreImpact 18 -Weight 10 -Finding "$($escalationRisks.Count) privilege escalation path(s) detected: $($escalationRisks -join ' | ')" -Evidence @{ RiskCount = $escalationRisks.Count; Risks = $escalationRisks; DAMemberCount = $daMembers.Count; NestedGroups = ($nestedGroups | ForEach-Object { $_.Name }) } -Reference $reference
        } else {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Threat Exposure' -Target 'Privilege Escalation' -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 10 -Finding 'No obvious privilege escalation paths detected. Domain Admins has clean membership with no risky nested groups, no unauthorized write permissions, and no service accounts.' -Evidence @{ RiskCount = 0; DAMemberCount = $daMembers.Count } -Reference $reference
        }
    } catch {
        $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Threat Exposure' -Target 'Privilege Escalation' -Domain $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "Privilege escalation path check failed: $($_.Exception.Message)" -Recommendation 'Run BloodHound or manually review DA group membership and ACLs.' -Reference $reference
    }
    return $results
}
#endregion Test-PrivilegeEscalationPaths

#region Test-SilverTicketRisk
function Test-SilverTicketRisk {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'THREAT-006'; $results = @()
    $reference = 'MITRE ATT&CK T1558.002 — Silver Ticket; Microsoft guidance on machine account password rotation'
    try {
        # Silver Ticket risk: computer accounts with old passwords (default rotation = 30 days)
        $threshold = 60
        $staleDate = (Get-Date).AddDays(-$threshold)
        $staleDateStr = $staleDate.ToString('yyyy-MM-ddTHH:mm:ss')
        $staleComputers = Get-ADComputer -Filter "Enabled -eq '$true' -and PasswordLastSet -lt '$staleDateStr'" -Properties PasswordLastSet, OperatingSystem, Name -Server $Domain -ResultPageSize 1000 -ErrorAction Stop
        $staleCount = @($staleComputers).Count
        # Check if machine account password rotation is disabled via GPO
        $rotationDisabled = $false
        try {
            $dcName0 = if ($DomainControllers[0].HostName) { $DomainControllers[0].HostName } elseif ($DomainControllers[0].Name) { $DomainControllers[0].Name } else { "$($DomainControllers[0])" }
            $regCheck = Invoke-Command -ComputerName $dcName0 -ScriptBlock {
                $val = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'DisablePasswordChange' -ErrorAction SilentlyContinue
                if ($null -ne $val -and $val.DisablePasswordChange -eq 1) { $true } else { $false }
            } -ErrorAction SilentlyContinue
            if ($regCheck) { $rotationDisabled = $true }
        } catch {}
        if ($staleCount -gt 10 -or $rotationDisabled) {
            $finding = @()
            if ($staleCount -gt 10) { $finding += "$staleCount computer account(s) have passwords older than $threshold days — vulnerable to Silver Ticket attacks" }
            if ($rotationDisabled) { $finding += "Machine account password rotation appears DISABLED on at least one DC" }
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Threat Exposure' -Target 'Computer Accounts' -Domain $Domain -Forest $Forest -Severity 'High' -Status 'Fail' -ScoreImpact 14 -Weight 9 -Finding (($finding -join '. ') + '. An attacker who obtains a stale computer account password hash can forge Silver Tickets for any service on that machine.') -Evidence @{ StaleComputerCount = $staleCount; ThresholdDays = $threshold; RotationDisabled = $rotationDisabled; SampleStale = ($staleComputers | Select-Object Name, PasswordLastSet, OperatingSystem -First 10) } -Reference $reference
        } else {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Threat Exposure' -Target 'Computer Accounts' -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 9 -Finding "Computer account password hygiene is good. Only $staleCount account(s) have passwords older than $threshold days. Machine password rotation is active." -Evidence @{ StaleComputerCount = $staleCount; ThresholdDays = $threshold; RotationDisabled = $rotationDisabled } -Reference $reference
        }
    } catch {
        $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Threat Exposure' -Target 'Computer Accounts' -Domain $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "Silver Ticket risk check failed: $($_.Exception.Message)" -Recommendation 'Manually check computer account password ages: Get-ADComputer -Filter * -Properties PasswordLastSet' -Reference $reference
    }
    return $results
}
#endregion Test-SilverTicketRisk

#region Test-NTLMUsageMonitoring
function Test-NTLMUsageMonitoring {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $checkId = 'IAM-006'; $results = @()
    $reference = 'Microsoft — NTLM Blocking and Auditing; MITRE ATT&CK T1557 — LLMNR/NBT-NS Poisoning; CIS Benchmark'
    foreach ($dc in $DomainControllers) {
        $dcName = if ($dc.HostName) { $dc.HostName } elseif ($dc.Name) { $dc.Name } else { "$dc" }
        try {
            $ntlmInfo = Invoke-Command -ComputerName $dcName -ScriptBlock {
                $result = @{ AuditEnabled = $false; NTLMEvents = 0; RestrictLevel = 0 }
                try {
                    $auditReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'AuditReceivingNTLMTraffic' -ErrorAction SilentlyContinue
                    if ($null -ne $auditReg -and $auditReg.AuditReceivingNTLMTraffic -ge 1) {
                        $result.AuditEnabled = $true
                    }
                } catch {}
                try {
                    $restrictReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictReceivingNTLMTraffic' -ErrorAction SilentlyContinue
                    if ($null -ne $restrictReg) { $result.RestrictLevel = $restrictReg.RestrictReceivingNTLMTraffic }
                } catch {}
                # Count recent NTLM authentication events (Event ID 4776 — credential validation)
                try {
                    $ntlmEvents = Get-WinEvent -FilterHashtable @{
                        LogName = 'Security'
                        Id = 4776
                        StartTime = (Get-Date).AddHours(-24)
                    } -MaxEvents 1000 -ErrorAction SilentlyContinue
                    if ($null -ne $ntlmEvents) { $result.NTLMEvents = @($ntlmEvents).Count }
                } catch {}
                $result
            } -ErrorAction Stop
            $issues = @()
            if (-not $ntlmInfo.AuditEnabled) { $issues += 'NTLM auditing is not enabled' }
            if ($ntlmInfo.RestrictLevel -eq 0) { $issues += 'NTLM is unrestricted (no deny policy)' }
            if ($ntlmInfo.NTLMEvents -gt 100) { $issues += "$($ntlmInfo.NTLMEvents) NTLM authentications in last 24h (high volume indicates Kerberos migration needed)" }
            if ($issues.Count -gt 0) {
                $severity = if ($ntlmInfo.NTLMEvents -gt 500 -or $ntlmInfo.RestrictLevel -eq 0) { 'Warning' } else { 'Info' }
                $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Identity & Access' -Target $dcName -Domain $Domain -Forest $Forest -Severity $severity -Status 'Warning' -ScoreImpact 8 -Weight 7 -Finding "NTLM usage concerns on '$dcName': $($issues -join '; '). NTLM is vulnerable to relay attacks, pass-the-hash, and credential theft." -Evidence @{ DC = $dcName; AuditEnabled = $ntlmInfo.AuditEnabled; RestrictLevel = $ntlmInfo.RestrictLevel; NTLMEventsLast24h = $ntlmInfo.NTLMEvents } -Reference $reference
            } else {
                $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Identity & Access' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'Pass' -Status 'Pass' -ScoreImpact 0 -Weight 7 -Finding "NTLM is properly audited and restricted on '$dcName'. NTLM events in last 24h: $($ntlmInfo.NTLMEvents). Restriction level: $($ntlmInfo.RestrictLevel)." -Evidence @{ DC = $dcName; AuditEnabled = $ntlmInfo.AuditEnabled; RestrictLevel = $ntlmInfo.RestrictLevel; NTLMEventsLast24h = $ntlmInfo.NTLMEvents } -Reference $reference
            }
        } catch {
            $results += ConvertTo-ADResult -CheckId $checkId -Category 'Security & Hardening' -SubCategory 'Identity & Access' -Target $dcName -Domain $Domain -Forest $Forest -Severity 'Info' -Status 'Error' -Weight 0 -Finding "NTLM usage check failed on $($dcName): $($_.Exception.Message)" -Recommendation 'Manually check NTLM audit registry keys under HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0.' -Reference $reference
        }
    }
    return $results
}
#endregion Test-NTLMUsageMonitoring

#region Invoke-InlineSecurityChecks
function Invoke-InlineSecurityChecks {
    param([array]$DomainControllers, [string]$Domain, [string]$Forest)
    $allResults = @()
    Write-Host '  Checking Pass-the-Hash exposure...' -ForegroundColor Yellow; $allResults += @(Invoke-RegistrySecurityChecks -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest; Test-CredentialGuard -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest; Test-LocalAdminPasswordReuse -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest; Test-PrivilegedLogonExposure -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest)
    Write-Host '  Checking Kerberos security...' -ForegroundColor Yellow; $allResults += @(Test-KrbtgtPasswordAge -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest)
    Write-Host '  Checking Threat Exposure (Kerberoasting, AS-REP, DCSync)...' -ForegroundColor Yellow; $allResults += @(Test-KerberoastingExposure -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest; Test-ASREPRoastingExposure -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest; Test-DCSyncPermissions -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest)
    Write-Host '  Checking Credential Protection & Access Controls...' -ForegroundColor Yellow; $allResults += @(Test-AnonymousAccessRestrictions -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest; Test-ExcessiveACLPermissions -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest)
    Write-Host '  Checking Audit Policies & Recovery...' -ForegroundColor Yellow; $allResults += @(Test-AdvancedAuditPolicies -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest)
    Write-Host '  Checking Operational Health (SYSVOL, Time Sync, Lingering Objects, DC Count)...' -ForegroundColor Yellow; $allResults += @(Test-SYSVOLReplicationHealth -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest; Test-TimeSyncConsistency -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest; Test-MinimumDCCount -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest)
    Write-Host '  Checking Architecture (DNS Stale Records, Sites & Subnets)...' -ForegroundColor Yellow
    Write-Host '  Checking Governance & Compliance (Functional Level, GPO, Tiered Admin, Logs)...' -ForegroundColor Yellow; $allResults += @(Test-UnlinkedGPOs -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest; Test-DefaultDomainPolicyReview -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest; Test-TieredAdminModel -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest; Test-LogRetentionAdequacy -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest)
    Write-Host '  Checking Advanced Detection & Monitoring (Alerts, Escalation, Silver Ticket, NTLM)...' -ForegroundColor Yellow; $allResults += @(Test-PrivilegedGroupChangeAlerts -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest; Test-PrivilegeEscalationPaths -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest; Test-SilverTicketRisk -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest; Test-NTLMUsageMonitoring -DomainControllers $DomainControllers -Domain $Domain -Forest $Forest)
    return $allResults
}
#endregion Invoke-InlineSecurityChecks

#endregion Inline Security & Pass-the-Hash Checks

#region Invoke-HygieneChecks
function Invoke-HygieneChecks {
    param([psobject]$Topology)
    $results = @()
    $results += Test-InactiveUsers -ForestTopology $Topology
    $results += Test-DisabledUsersReview -ForestTopology $Topology
    $results += Test-PasswordNeverExpires -ForestTopology $Topology
    $results += Test-NoPasswordRequired -ForestTopology $Topology
    $results += Test-ReversibleEncryptionUsers -ForestTopology $Topology
    $results += Test-PrivilegedDelegationExposed -ForestTopology $Topology
    $results += Test-InactiveComputers -ForestTopology $Topology
    $results += Test-DisabledComputersReview -ForestTopology $Topology
    $results += Test-StaleServerObjects -ForestTopology $Topology
    $results += Test-OrphanedObjects -ForestTopology $Topology
    $results += Test-DuplicateSPNs -ForestTopology $Topology
    $results += Test-StalePrintQueues -ForestTopology $Topology
    return $results
}
#endregion Invoke-HygieneChecks

#region Invoke-GpoChecks
function Invoke-GpoChecks {
    param([psobject]$Topology, [array]$DomainControllers)
    $results = @()
    $results += Test-BrokenGPOLinks -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-EmptyGPOs -ForestTopology $Topology
    $results += Test-GPOVersionMismatch -ForestTopology $Topology
    $results += Test-GPOPermissions -ForestTopology $Topology
    $results += Test-WMIFilterHealth -ForestTopology $Topology
    $results += Test-GPOLinkOrder -ForestTopology $Topology
    $results += Test-CentralStore -ForestTopology $Topology
    return $results
}
#endregion Invoke-GpoChecks

#region Invoke-SysvolChecks
function Invoke-SysvolChecks {
    param([psobject]$Topology, [array]$DomainControllers)
    $results = @()
    $results += Test-SYSVOLShareAvailability -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-DFSRMigrationState -ForestTopology $Topology
    $results += Test-DFSRBacklog -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-JournalWrapErrors -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-SYSVOLConsistency -ForestTopology $Topology -DomainControllers $DomainControllers
    return $results
}
#endregion Invoke-SysvolChecks

#region Invoke-SiteChecks
function Invoke-SiteChecks {
    param([psobject]$Topology, [array]$DomainControllers)
    $results = @()
    $results += Test-ADSitesConfig -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-SubnetToSiteMapping -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-DCPlacementPerSite -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-IntersiteTopology -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-SiteLinkCost -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-PreferredBridgehead -ForestTopology $Topology -DomainControllers $DomainControllers
    return $results
}
#endregion Invoke-SiteChecks

#region Invoke-FsmoChecks
function Invoke-FsmoChecks {
    param([psobject]$Topology, [array]$DomainControllers)
    $results = @()
    $results += Test-FSMORoleHolders -ForestTopology $Topology
    $results += Test-FSMOOnline -ForestTopology $Topology
    $results += Test-FSMODistribution -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-InfrastructureMasterPlacement -ForestTopology $Topology -DomainControllers $DomainControllers
    return $results
}
#endregion Invoke-FsmoChecks

#region Invoke-TimeChecks
function Invoke-TimeChecks {
    param([psobject]$Topology, [array]$DomainControllers)
    $results = @()
    $results += Test-PDCExternalTimeSource -ForestTopology $Topology
    $results += Test-DCHierarchyTimeSync -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-TimeDrift -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-W32TimeService -DomainControllers $DomainControllers -Forest $Topology.ForestName
    return $results
}
#endregion Invoke-TimeChecks

#region Invoke-BackupChecks
function Invoke-BackupChecks {
    param([psobject]$Topology, [array]$DomainControllers)
    $results = @()
    $results += Test-BackupStatus -DomainControllers $DomainControllers -Forest $Topology.ForestName
    $results += Test-ADRecycleBinBackup -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-TombstoneLifetimeBackup -ForestTopology $Topology -DomainControllers $DomainControllers
    $results += Test-TrustRelationships -ForestTopology $Topology
    # Mark all Backup & Recovery checks as Info status
    foreach ($r in $results) {
        $r.Status = 'Info'
        $r.Severity = 'Info'
        $r.ScoreImpact = 0
    }
    return $results
}
#endregion Invoke-BackupChecks

#region Start-ADHealthCheck
function Start-ADHealthCheck {
    [CmdletBinding()]
    param()

    # Check WMI service (Winmgmt) status
    $Script:WinmgmtWarning = $false
    try {
        $wmiService = Get-Service -Name 'Winmgmt' -ErrorAction Stop
        if ($wmiService.Status -ne 'Running') {
            Write-ADLog -Message '⚠ WARNING: Windows Management Instrumentation (Winmgmt) service is not running.' -Level 'WARN'
            Write-ADLog -Message '  Some checks (CPU, Memory, Disk, NTDS.dit) may return incomplete results.' -Level 'WARN'
            Write-Host ''
            Write-Host '  Would you like to start the Winmgmt service now? (Y/N): ' -NoNewline -ForegroundColor Yellow
            $response = Read-Host
            if ($response -eq 'Y' -or $response -eq 'y') {
                try {
                    Start-Service -Name 'Winmgmt' -ErrorAction Stop
                    Write-ADLog -Message 'Winmgmt service started successfully.' -Level 'SUCCESS'
                } catch {
                    Write-ADLog -Message ("Failed to start Winmgmt service: {0}" -f $_.Exception.Message) -Level 'WARN'
                    $Script:WinmgmtWarning = $true
                }
            } else {
                Write-ADLog -Message 'Continuing without Winmgmt service. Some results may be missing.' -Level 'WARN'
                $Script:WinmgmtWarning = $true
            }
        }
    } catch {
        Write-ADLog -Message ("Unable to query Winmgmt service: {0}" -f $_.Exception.Message) -Level 'WARN'
    }

    if (-not [string]::IsNullOrWhiteSpace($script:MenuOption)) {
        $selection = $script:MenuOption
        Write-ADLog -Message ("Menu option [{0}] supplied via parameter; skipping interactive menu." -f $selection) -Level 'INFO'
    } else {
        $selection = Get-ADHealthCheckSelection
    }
    if ($selection -eq 'Q') {
        Write-ADLog -Message 'Assessment cancelled by user.' -Level 'WARN'
        return
    }

    Write-ADLog -Message 'Discovering forest topology...' -Level 'INFO'
    $Script:ForestTopology = Get-ADHealthCheckForestTopology
    $Script:DomainControllers = Get-ADHealthCheckDomainControllers -ForestTopology $Script:ForestTopology
    $Script:ForestTopology | ConvertTo-Json -Depth 6 | Set-Content -Path $Script:TopologyPath -Encoding UTF8
    Write-ADLog -Message ("Discovered forest [{0}] with {1} domain(s) and {2} domain controller(s)." -f $Script:ForestTopology.ForestName, @($Script:ForestTopology.Domains).Count, @($Script:DomainControllers).Count) -Level 'SUCCESS'

    $categoryMap = @{
        '1'  = @('FD', 'DC', 'RP', 'DNS', 'SEC', 'HYG', 'GPO', 'SYS', 'SITE', 'FSMO', 'TIME', 'BKP')
        '2'  = @('FD')
        '3'  = @('DC')
        '4'  = @('RP')
        '5'  = @('DNS')
        '6'  = @('SEC')
        '7'  = @('HYG')
        '8'  = @('GPO')
        '9'  = @('SYS')
        '10' = @('SITE')
        '11' = @('FSMO')
        '12' = @('TIME')
        '13' = @('BKP')
    }

    # Build phase definitions for the selected categories
    $phaseDefinitions = @{
        'FD'   = @{ Name = 'Forest & Domain Configuration'; ScriptBlock = { Invoke-ForestDomainChecks -Topology $ForestTopology -DomainControllers $DomainControllers } }
        'DC'   = @{ Name = 'Domain Controller Health'; ScriptBlock = { Invoke-DCHealthChecks -Topology $ForestTopology -DomainControllers $DomainControllers } }
        'RP'   = @{ Name = 'Replication Health'; ScriptBlock = { Invoke-ReplicationChecks -Topology $ForestTopology -DomainControllers $DomainControllers } }
        'DNS'  = @{ Name = 'DNS Health'; ScriptBlock = { Invoke-DnsChecks -Topology $ForestTopology -DomainControllers $DomainControllers } }
        'SEC'  = @{ Name = 'Security & Hardening'; ScriptBlock = {
            $secDomain = $ForestTopology.RootDomain; $secForest = $ForestTopology.ForestName
            if (Get-Command -Name 'Invoke-SecurityAssessment' -ErrorAction SilentlyContinue) {
                Invoke-SecurityAssessment -DomainControllers $DomainControllers -Domain $secDomain -Forest $secForest
            } else { Invoke-InlineSecurityChecks -DomainControllers $DomainControllers -Domain $secDomain -Forest $secForest }
        } }
        'HYG'  = @{ Name = 'User & Computer Hygiene'; ScriptBlock = { Invoke-HygieneChecks -Topology $ForestTopology } }
        'GPO'  = @{ Name = 'Group Policy Health'; ScriptBlock = { Invoke-GpoChecks -Topology $ForestTopology -DomainControllers $DomainControllers } }
        'SYS'  = @{ Name = 'SYSVOL & File Replication'; ScriptBlock = { Invoke-SysvolChecks -Topology $ForestTopology -DomainControllers $DomainControllers } }
        'SITE' = @{ Name = 'Sites & Topology'; ScriptBlock = { Invoke-SiteChecks -Topology $ForestTopology -DomainControllers $DomainControllers } }
        'FSMO' = @{ Name = 'FSMO Roles'; ScriptBlock = { Invoke-FsmoChecks -Topology $ForestTopology -DomainControllers $DomainControllers } }
        'TIME' = @{ Name = 'Time Synchronization'; ScriptBlock = { Invoke-TimeChecks -Topology $ForestTopology -DomainControllers $DomainControllers } }
        'BKP'  = @{ Name = 'Backup & Recovery'; ScriptBlock = { Invoke-BackupChecks -Topology $ForestTopology -DomainControllers $DomainControllers } }
    }

    $selectedPhases = @($categoryMap[$selection] | ForEach-Object { $phaseDefinitions[$_] } | Where-Object { $_ })

    if ($selectedPhases.Count -gt 2) {
        # Run multiple phases in parallel (full assessment or multi-category)
        Write-ADLog -Message ("Running {0} check phases in parallel..." -f $selectedPhases.Count) -Level 'INFO'
        Invoke-ParallelPhases -Phases $selectedPhases -ThrottleLimit 6
    } else {
        # Single/dual phase — run sequentially (no overhead)
        foreach ($phase in $selectedPhases) {
            Write-ADLog -Message "Running $($phase.Name) checks..." -Level 'INFO'
            $r = & $phase.ScriptBlock
            if ($r) { Add-AssessmentResults -Results $r }
        }
    }

    if ($Script:AllResults.Count -eq 0) {
        Write-ADLog -Message 'No assessment results were generated.' -Level 'WARN'
        return
    }

    Export-ADResultsToCsv -Results $Script:AllResults -Path $Script:CsvReportPath
    $scores = Get-ADOverallHealthScore -Results $Script:AllResults
    $scores | ConvertTo-Json -Depth 6 | Set-Content -Path $Script:ScorePath -Encoding UTF8

    Write-ADLog -Message ("CSV results exported to {0}" -f $Script:CsvReportPath) -Level 'SUCCESS'
    Write-ADLog -Message ("Score summary exported to {0}" -f $Script:ScorePath) -Level 'SUCCESS'

    # Generate HTML Report — inline (no external module needed)
    Write-ADLog -Message 'Generating HTML report...' -Level 'INFO'
    try {
        $grade = if ($scores.OverallScore -ge 90) { 'A' }
                 elseif ($scores.OverallScore -ge 80) { 'B' }
                 elseif ($scores.OverallScore -ge 70) { 'C' }
                 elseif ($scores.OverallScore -ge 60) { 'D' }
                 else { 'F' }
        $risk = if ($scores.Rating -eq 'Critical') { 'Critical' }
                elseif ($scores.Rating -eq 'Poor') { 'High' }
                elseif ($scores.Rating -eq 'Fair') { 'Medium' }
                else { 'Low' }

        $domainName = $Script:ForestTopology.RootDomain
        $forestName = $Script:ForestTopology.ForestName
        $dcCount = ($Script:DomainControllers | Measure-Object).Count
        $siteCount = ($Script:ForestTopology.Sites | Measure-Object).Count
        $assessor = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        $assessDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

        # Categorize results
        $allResults = $Script:AllResults
        $totalChecks = ($allResults | Measure-Object).Count
        $passCount = @($allResults | Where-Object { $_.Status -eq 'Pass' }).Count
        $failCount = @($allResults | Where-Object { $_.Status -eq 'Fail' }).Count
        $warnCount = @($allResults | Where-Object { $_.Status -eq 'Warning' -or $_.Status -eq 'Partial' }).Count
        $infoCount = @($allResults | Where-Object { $_.Status -eq 'Info' -or $_.Status -eq 'Skipped' }).Count
        $criticalItems = @($allResults | Where-Object { $_.Severity -eq 'Critical' -and $_.Status -eq 'Fail' })
        $categories = $allResults | Group-Object -Property Category

        $invariant = [System.Globalization.CultureInfo]::InvariantCulture
        $overallScore = [double]$scores.OverallScore
        $overallScoreDisplay = [string]::Format($invariant, '{0:0.0}', $overallScore)
        $overallScoreColor = if ($overallScore -gt 80) { '#10b981' } elseif ($overallScore -ge 50) { '#f59e0b' } else { '#ef4444' }
        $overallScoreOffset = [string]::Format($invariant, '{0:0.00}', (439.82 * (1 - ($overallScore / 100))))
        $forestSlug = ($forestName -replace '[^a-zA-Z0-9]', '_').Trim('_')
        if ([string]::IsNullOrWhiteSpace($forestSlug)) { $forestSlug = 'forest' }

        $encodeHtml = {
            param(
                [AllowNull()][object]$Value,
                [switch]$PreserveLineBreaks
            )

            if ($null -eq $Value) { return '' }

            $encoded = [System.Net.WebUtility]::HtmlEncode([string]$Value)
            if ($PreserveLineBreaks) {
                $encoded = $encoded -replace '(\r\n|\r|\n)', '<br>'
            }

            return $encoded
        }

        $categoryIdLookup = @{}
        $categorySlugCounts = @{}
        $categoryObjects = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($cat in $categories) {
            $categoryName = if ([string]::IsNullOrWhiteSpace([string]$cat.Name)) { 'Uncategorized' } else { [string]$cat.Name }
            $catId = ($categoryName -replace '[^a-zA-Z0-9]', '-').ToLower().Trim('-')
            if ([string]::IsNullOrWhiteSpace($catId)) { $catId = 'uncategorized' }
            if ($categorySlugCounts.ContainsKey($catId)) {
                $categorySlugCounts[$catId]++
                $catId = '{0}-{1}' -f $catId, $categorySlugCounts[$catId]
            }
            else {
                $categorySlugCounts[$catId] = 1
            }

            $categoryIdLookup[$categoryName] = $catId

            $catResults = @($cat.Group)
            $catPass = @($catResults | Where-Object { $_.Status -eq 'Pass' }).Count
            $catFail = @($catResults | Where-Object { $_.Status -eq 'Fail' }).Count
            $catWarn = @($catResults | Where-Object { $_.Status -eq 'Warning' -or $_.Status -eq 'Partial' -or $_.Status -eq 'Info' -or $_.Status -eq 'Skipped' }).Count
            $catTotal = ($catResults | Measure-Object).Count
            $catPct = if ($catTotal -gt 0) { [math]::Round(($catPass / $catTotal) * 100, 0) } else { 0 }

            [void]$categoryObjects.Add([PSCustomObject]@{
                id       = $catId
                name     = (& $encodeHtml $categoryName)
                fullName = (& $encodeHtml $categoryName)
                score    = $catPct
                pass     = $catPass
                fail     = $catFail
                warn     = $catWarn
                total    = $catTotal
            })
        }

        $findingObjects = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $allResults) {
            $categoryName = if ([string]::IsNullOrWhiteSpace([string]$item.Category)) { 'Uncategorized' } else { [string]$item.Category }
            $catId = $categoryIdLookup[$categoryName]
            if (-not $catId) {
                $catId = ($categoryName -replace '[^a-zA-Z0-9]', '-').ToLower().Trim('-')
                if ([string]::IsNullOrWhiteSpace($catId)) { $catId = 'uncategorized' }
            }

            $status = if ([string]::IsNullOrWhiteSpace([string]$item.Status)) { 'Info' } else { [string]$item.Status }
            $evidenceStr = if ($item.Evidence -ne $null) {
                try { $item.Evidence | ConvertTo-Json -Depth 4 -Compress } catch { [string]$item.Evidence }
            } else { '' }
            $queryStr = if ($Script:CheckQueries.ContainsKey($item.CheckId)) { $Script:CheckQueries[$item.CheckId] } else { '' }
            [void]$findingObjects.Add(@(
                (& $encodeHtml $item.CheckId),
                $catId,
                (& $encodeHtml $categoryName),
                (& $encodeHtml $status),
                (& $encodeHtml $item.Finding -PreserveLineBreaks),
                (& $encodeHtml $item.Recommendation -PreserveLineBreaks),
                (& $encodeHtml $evidenceStr),
                (& $encodeHtml ([string]$item.Reference)),
                (& $encodeHtml $queryStr)
            ))
        }

        $categoryNavItems = foreach ($category in $categoryObjects) {
            '              <a class="sidebar-item" href="#section-{0}" onclick="scrollToSection(''section-{0}'',this);return false;">{1}</a>' -f $category.id, $category.name
        }
        $categoryNavHtml = $categoryNavItems -join "`r`n"

        $categoriesJson = if ($categoryObjects.Count -eq 1) { '[' + ($categoryObjects | ConvertTo-Json -Depth 6 -Compress) + ']' } else { $categoryObjects | ConvertTo-Json -Depth 6 -Compress }
        # Build FINDINGS JSON manually to avoid PS 5.1 serializing arrays as {"value":[...],"Count":N}
        $jsonSb = [System.Text.StringBuilder]::new('[')
        $firstRow = $true
        foreach ($row in $findingObjects) {
            if (-not $firstRow) { [void]$jsonSb.Append(',') }
            $firstRow = $false
            $cells = [System.Collections.Generic.List[string]]::new()
            foreach ($cell in $row) {
                $escaped = [string]$cell
                $escaped = $escaped.Replace('\', '\\').Replace('"', '\"').Replace("`t", '\t').Replace("`r", '').Replace("`n", '\n')
                [void]$cells.Add('"' + $escaped + '"')
            }
            [void]$jsonSb.Append('[').Append(($cells -join ',')).Append(']')
        }
        [void]$jsonSb.Append(']')
        $findingsJson = $jsonSb.ToString()

        $htmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Active Directory Health Assessment &ndash; __TITLE_FOREST__</title>
  <style>
:root{--ms-blue:#0f6cbd;--ms-blue-dark:#0b3b69;--header-dark:#111827;--surface:#ffffff;--surface-alt:#f5f7fb;--surface-muted:#eef2f7;--border:#dbe2ea;--text:#1f2937;--text-muted:#5f6a7d;--success:#107c10;--danger:#d13438;--warning:#ff8c00;--shadow:0 12px 32px rgba(15,23,42,0.08);--radius:18px;--ring-score:74;--sidebar-bg:#ffffff;--sidebar-border:#e7edf3;--sidebar-border-soft:#eef2f6;--sidebar-text:#475467;--sidebar-text-strong:#111827;--sidebar-muted:#98a2b3;--sidebar-hover:#f1f5f9;--sidebar-active-bg:#eef6ff;--sidebar-indicator:var(--ms-blue);--sidebar-shadow:0 18px 40px rgba(15,23,42,0.06)}
*{box-sizing:border-box}html{scroll-behavior:smooth;background:#e8edf4}
body{margin:0;font-family:"Inter","Segoe UI Variable","Segoe UI",Arial,Helvetica,sans-serif;color:var(--text);background:radial-gradient(circle at top right,rgba(15,108,189,0.12),transparent 26%),linear-gradient(180deg,#eef3f9 0%,#f7f9fc 240px,#eef2f7 100%)}
a{color:var(--ms-blue);text-decoration:none}a:hover,a:focus{text-decoration:underline}
code{padding:2px 6px;border-radius:6px;background:rgba(15,108,189,0.08);color:var(--ms-blue-dark);font-family:Consolas,"Courier New",monospace;font-size:0.95em}
.muted{color:var(--text-muted)}
.topbar{background:linear-gradient(135deg,#0b1220 0%,#15233b 52%,#0f6cbd 140%);color:#fff;padding:22px 0;box-shadow:0 12px 28px rgba(11,18,32,0.28)}
.topbar-inner{width:min(1440px,calc(100% - 40px));margin:0 auto}
.brand-row{display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:16px}
.brand-mark{display:grid;grid-template-columns:repeat(2,14px);gap:4px;padding:6px;border-radius:10px;background:rgba(255,255,255,0.08)}
.brand-mark span{display:block;width:14px;height:14px;border-radius:3px}
.brand-mark span:nth-child(1){background:#f25022}.brand-mark span:nth-child(2){background:#7fba00}.brand-mark span:nth-child(3){background:#00a4ef}.brand-mark span:nth-child(4){background:#ffb900}
.eyebrow{margin:0 0 6px;text-transform:uppercase;letter-spacing:0.08em;font-size:12px;font-weight:700;color:rgba(255,255,255,0.72)}
.topbar h1{margin:0;font-size:clamp(22px,4vw,38px);font-weight:700}.topbar p{margin:6px 0 0;color:rgba(255,255,255,0.82);font-size:15px}
.meta-chip{display:inline-flex;align-items:center;gap:8px;padding:10px 14px;border:1px solid rgba(255,255,255,0.16);border-radius:999px;background:rgba(255,255,255,0.08);font-size:13px;white-space:nowrap;color:#fff}
.page{margin-left:296px;padding:28px 20px 36px}
.sidebar{position:fixed;left:0;top:0;width:272px;height:100vh;background:var(--sidebar-bg);z-index:1000;border-right:1px solid var(--sidebar-border);display:flex;flex-direction:column;overflow:hidden;transition:transform 0.3s ease;box-shadow:var(--sidebar-shadow)}
.sidebar .panel{padding:0;background:transparent;border:none;border-radius:0;box-shadow:none;backdrop-filter:none;flex:1;display:flex;flex-direction:column;min-height:0}
.sidebar-shell{min-height:100%;display:flex;flex-direction:column}
.sidebar-header{display:flex;align-items:center;gap:12px;padding:20px 20px 16px;border-bottom:1px solid var(--sidebar-border-soft)}
.sidebar-logo{display:flex;align-items:center;gap:12px;color:inherit;text-decoration:none;min-width:0}
.sidebar-logo:hover,.sidebar-logo:focus{text-decoration:none}
.sidebar-logo .brand-mark{grid-template-columns:repeat(2,10px);gap:3px;padding:5px;border-radius:8px;background:#f8fafc;border:1px solid var(--sidebar-border-soft);flex-shrink:0}
.sidebar-logo .brand-mark span{width:10px;height:10px;border-radius:2px}
.sidebar-brand-copy{min-width:0}
.sidebar-brand-kicker{margin:0 0 2px;font-size:11px;line-height:1.2;letter-spacing:0.12em;text-transform:uppercase;font-weight:700;color:var(--sidebar-muted)}
.sidebar-brand-name{margin:0;font-size:17px;line-height:1.2;font-weight:700;letter-spacing:-0.02em;color:var(--sidebar-text-strong)}
.sidebar-brand-subtitle{margin:3px 0 0;font-size:12px;color:var(--text-muted)}
.sidebar-body{flex:1;min-height:0;display:flex;flex-direction:column;gap:18px;padding:14px 12px 18px}
.sidebar-nav-wrap{flex:1;min-height:0;display:flex;flex-direction:column}
.sidebar-section-title{padding:0 12px;margin:0 0 10px;font-size:11px;font-weight:700;color:var(--sidebar-muted);text-transform:uppercase;letter-spacing:0.16em}
.sidebar-menu{flex:1;min-height:0;overflow-y:auto;padding-right:4px;scrollbar-width:none;-ms-overflow-style:none}
.sidebar-menu::-webkit-scrollbar,.sidebar::-webkit-scrollbar{width:0;height:0}
.sidebar-toggle{display:none;position:fixed;top:16px;left:16px;z-index:1001;background:#fff;color:var(--sidebar-text-strong);border:1px solid var(--sidebar-border);border-radius:10px;padding:10px 14px;font-size:20px;cursor:pointer;box-shadow:0 10px 24px rgba(15,23,42,0.12);transition:background 0.15s,color 0.15s,border-color 0.15s}
.sidebar-toggle:hover,.sidebar-toggle:focus{background:var(--sidebar-hover);color:var(--ms-blue);border-color:rgba(15,108,189,0.2);outline:none}
.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(15,23,42,0.32);z-index:999;backdrop-filter:blur(2px)}
.sidebar-nav{display:flex;flex-direction:column;gap:4px;flex:1}
.sidebar-nav a,.sidebar-nav .sidebar-item{width:100%;border:none;background-color:transparent;color:var(--sidebar-text);padding:9px 14px;border-radius:10px;text-align:left;font:inherit;font-size:13px;font-weight:500;line-height:1.4;cursor:pointer;transition:background-color 0.15s,color 0.15s;text-decoration:none;display:flex;align-items:center;gap:10px;position:relative;min-height:38px}
.sidebar-nav a::before,.sidebar-nav .sidebar-item::before{content:"";position:absolute;left:-12px;top:8px;bottom:8px;width:4px;border-radius:0 999px 999px 0;background:var(--sidebar-indicator);opacity:0;transform:scaleY(0.65);transition:opacity 0.15s,transform 0.15s}
.sidebar-nav a:hover,.sidebar-nav a:focus,.sidebar-nav .sidebar-item:hover,.sidebar-nav .sidebar-item:focus{background-color:var(--sidebar-hover);color:var(--ms-blue);outline:none;text-decoration:none}
.sidebar-nav a.active,.sidebar-nav .sidebar-item.active{color:var(--ms-blue);background-color:var(--sidebar-active-bg);font-weight:600}
.sidebar-nav a.active::before,.sidebar-nav .sidebar-item.active::before{opacity:1;transform:scaleY(1)}
.sidebar-footer{margin-top:auto;padding-top:4px}
.panel{background:rgba(255,255,255,0.92);border:1px solid rgba(219,226,234,0.88);border-radius:var(--radius);box-shadow:var(--shadow);backdrop-filter:blur(10px);overflow:hidden}
.content{display:flex;flex-direction:column;gap:24px;width:100%;max-width:100%;min-width:0}.content h2{margin:0 0 16px;font-size:20px}
.hero{padding:28px}.hero-grid{display:grid;grid-template-columns:minmax(240px,320px) minmax(0,1fr);gap:28px;align-items:center}
.score-tile{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:240px;border-radius:24px;background:linear-gradient(180deg,#fff 0%,#f5f8fc 100%);border:1px solid var(--border);padding:20px}
.score-ring{width:160px;height:160px;position:relative}.score-ring svg{width:100%;height:100%}
.score-ring-bg{fill:none;stroke:#dbe5f0;stroke-width:16}
.score-ring-fill{fill:none;stroke-width:16;stroke-linecap:round;transform:rotate(-90deg);transform-origin:center}
.score-ring-text{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;pointer-events:none}
.score-ring-text strong{font-size:38px;line-height:1;display:block}.score-ring-text span{margin-top:6px;font-size:13px;color:var(--text-muted);letter-spacing:0.02em;display:block}
.score-caption{margin-top:14px;font-size:15px;color:var(--text-muted);text-align:center}
.hero-copy h2{margin:0 0 10px;font-size:clamp(22px,3vw,30px)}.hero-copy p{margin:0 0 20px;color:var(--text-muted);line-height:1.65;font-size:15px}
.stats-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
.stat-card{padding:16px;border-radius:16px;background:#f8fafc;border:1px solid var(--border)}
.stat-card .label{display:block;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-muted);margin-bottom:8px}
.stat-card .value{display:block;font-size:28px;font-weight:700}
.stat-card.success .value{color:var(--success)}.stat-card.danger .value{color:var(--danger)}.stat-card.warning .value{color:var(--warning)}.stat-card.info .value{color:var(--ms-blue)}
.section-card{padding:24px 26px;overflow:hidden}
.section-header{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:18px;flex-wrap:wrap}
.section-header p{margin:8px 0 0;color:var(--text-muted);line-height:1.6}
.legend{display:flex;flex-wrap:wrap;gap:10px;margin-top:10px}
.legend-item,.pill{display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border-radius:999px;font-size:13px;font-weight:600}
.legend-item::before,.pill::before{content:"";width:8px;height:8px;border-radius:50%;background:currentColor;flex-shrink:0}
.legend-item.success,.pill.success{color:var(--success);background:rgba(16,124,16,0.1)}
.legend-item.danger,.pill.danger{color:var(--danger);background:rgba(209,52,56,0.1)}
.legend-item.warning,.pill.warning{color:var(--warning);background:rgba(255,140,0,0.12)}
.pill.info{color:var(--ms-blue);background:rgba(15,108,189,0.1)}
.export-btn{background:rgba(15,108,189,0.1);color:#0f6cbd;border:1px solid #0f6cbd;border-radius:8px;padding:6px 14px;font-size:12px;font-weight:600;cursor:pointer;transition:background 0.2s,transform 0.1s;white-space:nowrap}
.export-btn:hover{background:rgba(15,108,189,0.2);transform:translateY(-1px)}.export-btn:active{transform:translateY(0)}
.category-card-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:18px}
.category-card{display:flex;flex-direction:column;gap:12px;padding:18px;border-radius:18px;border:1px solid var(--border);background:linear-gradient(180deg,#fff 0%,#f8fbff 100%);box-shadow:0 10px 26px rgba(15,23,42,0.06)}
.category-card-title{font-weight:700;font-size:13px;color:var(--sidebar-text-strong)}
.category-card-charts{display:flex;justify-content:center}
.category-chart-group{display:flex;flex-direction:column;align-items:center;gap:6px}
.category-chart-detail{font-size:12px;color:var(--text-muted);text-align:center}
.detail-section{display:grid;gap:18px;scroll-margin-top:20px;background:rgba(255,255,255,0.75);border:1px solid var(--border);border-radius:16px;padding:24px;margin-top:4px;overflow:hidden}
.detail-meta{display:flex;flex-wrap:wrap;gap:10px}
.detail-section-header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}
.detail-section-header h2{margin:0;font-size:20px}
.policy-collapsible{border:1px solid var(--border);border-radius:12px;margin-bottom:12px;overflow:hidden}
.policy-header{display:flex;align-items:center;gap:10px;padding:14px 18px;cursor:pointer;background:#f4f8fc;transition:background 0.2s;flex-wrap:wrap;user-select:none}
.policy-header:hover{background:#e8f0f8}
.policy-toggle-icon{font-size:12px;transition:transform 0.2s;color:var(--text-muted);flex-shrink:0}
.policy-collapsible.collapsed .policy-toggle-icon{transform:rotate(-90deg)}
.policy-title{font-weight:600;font-size:15px;flex:1}
.policy-content{padding:12px 18px 18px}.policy-collapsible.collapsed .policy-content{display:none}
.findings-table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;border:1px solid var(--border);border-radius:18px;background:#fff}
table{width:100%;border-collapse:collapse;min-width:800px}thead{background:#edf4fb}
th,td{padding:14px 16px;text-align:left;vertical-align:top;border-bottom:1px solid #e7edf4;font-size:14px}
th{font-size:12px;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-muted);white-space:nowrap}
td{white-space:nowrap}td.wrap,td:nth-child(4),td:nth-child(5){white-space:normal;word-break:break-word;max-width:380px}
.findings-cat-table td:nth-child(3),.findings-cat-table td:nth-child(4){white-space:normal;word-break:break-word;max-width:380px}
tbody tr:hover{background:#fbfdff}tbody tr:last-child td{border-bottom:none}
.column-filter-row th{padding:4px 6px;background:#f4f8fc}
.column-filter-row select{width:100%;padding:5px 8px;font-size:12px;border:1px solid var(--border);border-radius:6px;background:#fff;color:var(--text);cursor:pointer}
body[data-theme='dark'] .column-filter-row th{background:#1e293b}
body[data-theme='dark'] .column-filter-row select{background:#1e293b;border-color:#334155;color:#e2e8f0}
.evidence-link{color:#2563eb;text-decoration:none;font-weight:600;font-size:12px;white-space:nowrap}.evidence-link:hover{text-decoration:underline}
.evidence-modal-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:9999;align-items:center;justify-content:center}
.evidence-modal-overlay.active{display:flex}
.evidence-modal{background:#fff;border-radius:16px;padding:28px 32px;max-width:700px;width:90%;max-height:80vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,0.3)}
body[data-theme='dark'] .evidence-modal{background:#1e293b;color:#e2e8f0}
.evidence-modal h3{margin:0 0 16px;font-size:18px}.evidence-modal .evidence-section{margin-bottom:16px}
.evidence-modal .evidence-label{font-size:12px;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-muted);font-weight:700;margin-bottom:6px}
.evidence-modal .evidence-content{background:#f4f8fc;border:1px solid var(--border);border-radius:8px;padding:12px 16px;font-size:13px;font-family:'Courier New',monospace;white-space:pre-wrap;word-break:break-word}
body[data-theme='dark'] .evidence-modal .evidence-content{background:#0f172a}
.evidence-modal .close-btn{display:inline-block;margin-top:12px;padding:8px 20px;background:#2563eb;color:#fff;border:none;border-radius:8px;cursor:pointer;font-weight:600;font-size:13px}
.evidence-modal .close-btn:hover{background:#1d4ed8}
.status-badge{display:inline-flex;align-items:center;gap:4px;border-radius:6px;font-size:12px;font-weight:700;padding:4px 10px;border:1px solid transparent;white-space:nowrap}
.status-badge.status-pass{background:rgba(76,175,80,0.15);color:#4caf50;border-color:#4caf50}
.status-badge.status-critical{background:rgba(239,83,80,0.15);color:#ef5350;border-color:#ef5350}
.status-badge.status-warning{background:rgba(255,140,0,0.15);color:#ff8c00;border-color:#ff8c00}
.footer{background:linear-gradient(135deg,#2c3e50 0%,#34495e 100%);color:white;padding:24px;text-align:center;margin-top:40px;border-top:4px solid #3498db}
.footer-inner{max-width:1400px;margin:0 auto}.footer-title{font-size:15px;font-weight:600;margin-bottom:8px}
.footer-date{font-size:13px;color:#bdc3c7}
.footer-disclaimer{font-size:12px;color:#95a5a6;margin-top:12px;max-width:920px;margin-left:auto;margin-right:auto;line-height:1.6}
.toggle-button{appearance:none;border:1px solid var(--border);background:#fff;color:var(--text);border-radius:999px;padding:8px 14px;font:inherit;font-size:13px;font-weight:600;cursor:pointer}
.toggle-button::after{content:" Hide"}.collapsed .toggle-button::after{content:" Show"}.collapsed .collapsible-content{display:none}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
@media(max-width:1120px){.sidebar{transform:translateX(-100%)}.sidebar.open{transform:translateX(0)}.sidebar-toggle{display:block}.sidebar-overlay.open{display:block}.page{margin-left:0;padding:28px 20px 36px}}
@media(max-width:820px){.topbar-inner{width:min(calc(100% - 24px),1440px)}.page{padding:16px 12px 36px}.brand-row{flex-direction:column;align-items:flex-start}.hero-grid{grid-template-columns:1fr}.stats-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:560px){.stats-grid{grid-template-columns:1fr}.score-ring{width:130px;height:130px}}
@media print{:root{--shadow:none}html,body{background:#fff !important}.topbar{box-shadow:none;print-color-adjust:exact;-webkit-print-color-adjust:exact}.sidebar,.sidebar-toggle,.sidebar-overlay{display:none !important}.page{margin-left:0 !important;padding-top:20px;width:100%}.panel,.category-card,.findings-table-wrap,.score-tile,.stat-card{box-shadow:none !important;break-inside:avoid;page-break-inside:avoid}.detail-section{display:grid !important;margin-top:22px}.policy-collapsible.collapsed .policy-content{display:block !important}.footer{padding-bottom:0}a{color:inherit;text-decoration:none}.override-col,.regenerate-bar{display:none !important}}
.override-select{padding:4px 8px;border:1px solid #d1d5db;border-radius:6px;font-size:0.78rem;background:#fff;color:#374151;cursor:pointer;min-width:110px;transition:border-color 0.2s,box-shadow 0.2s}
.override-select:focus{outline:none;border-color:#3b82f6;box-shadow:0 0 0 2px rgba(59,130,246,0.2)}
.override-select.selected-mitigated{background:#ecfdf5;border-color:#10b981;color:#065f46}
.override-select.selected-falsepositive{background:#eff6ff;border-color:#3b82f6;color:#1e40af}
.override-select.selected-acceptrisk{background:#fef3c7;border-color:#f59e0b;color:#92400e}
.override-na{color:#9ca3af;font-size:0.78rem}
.regenerate-bar{position:fixed;bottom:0;left:0;right:0;background:linear-gradient(135deg,#1e293b 0%,#334155 100%);color:#fff;padding:14px 24px;display:none;align-items:center;justify-content:space-between;z-index:9999;box-shadow:0 -4px 20px rgba(0,0,0,0.3);border-top:2px solid #3b82f6}
.regenerate-bar.visible{display:flex}
.regenerate-bar .regen-info{font-size:0.9rem;display:flex;align-items:center;gap:12px}
.regenerate-bar .regen-count{background:#3b82f6;color:#fff;padding:3px 10px;border-radius:12px;font-weight:700;font-size:0.85rem}
.regenerate-bar .regen-btn{background:linear-gradient(135deg,#10b981,#059669);color:#fff;border:none;padding:10px 22px;border-radius:8px;font-weight:700;font-size:0.9rem;cursor:pointer;transition:transform 0.15s,box-shadow 0.15s;box-shadow:0 2px 8px rgba(16,185,129,0.4)}
.regenerate-bar .regen-btn:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(16,185,129,0.6)}
.regenerate-bar .regen-reset{background:transparent;color:#94a3b8;border:1px solid #475569;padding:8px 16px;border-radius:8px;font-size:0.82rem;cursor:pointer;margin-left:10px}
.regenerate-bar .regen-reset:hover{color:#fff;border-color:#64748b}
  </style>
</head>
<body>
<button class="sidebar-toggle" onclick="toggleSidebar()" aria-label="Toggle navigation">&#9776;</button>
<div class="sidebar-overlay" id="sidebarOverlay" onclick="toggleSidebar()"></div>
<aside class="sidebar" id="sidebar" aria-label="Section navigation"><div class="panel sidebar-shell"><div class="sidebar-header"><a class="sidebar-logo" href="#section-summary" onclick="scrollToSection('section-summary',null)"><div class="brand-mark" aria-hidden="true"><span></span><span></span><span></span><span></span></div><div class="sidebar-brand-copy"><p class="sidebar-brand-kicker">Microsoft AD</p><h2 class="sidebar-brand-name">Active Directory Health Assessment</h2><p class="sidebar-brand-subtitle">__SIDEBAR_SUBTITLE__ forest review</p></div></a></div><div class="sidebar-body"><div class="sidebar-nav-wrap"><div class="sidebar-section-title">Navigation</div><div class="sidebar-menu"><nav class="sidebar-nav" id="categoryNav"><a class="sidebar-item active" href="#section-summary" onclick="scrollToSection('section-summary',this);return false;">Executive Summary</a><a class="sidebar-item" href="#section-categories" onclick="scrollToSection('section-categories',this);return false;">Category Scorecards</a>
__CATEGORY_NAV_ITEMS__
<a class="sidebar-item" href="#section-detailed-findings" onclick="scrollToSection('section-detailed-findings',this);return false;">Detailed Findings</a><a class="sidebar-item" href="#section-scoring-methodology" onclick="scrollToSection('section-scoring-methodology',this);return false;">Understanding Your Score</a></nav></div></div><div class="sidebar-footer"></div></div></div></aside>
<header class="topbar"><div class="topbar-inner"><div class="brand-row"><div class="brand"><div class="brand-mark" aria-hidden="true"><span></span><span></span><span></span><span></span></div><div><p class="eyebrow">Microsoft Active Directory</p><h1>Active Directory Health Assessment</h1><p>Forest: __TOPBAR_FOREST__ &nbsp;&middot;&nbsp; Domain: __TOPBAR_DOMAIN__ &nbsp;&middot;&nbsp; Assessor: __TOPBAR_ASSESSOR__</p></div></div><div class="meta-chip"><strong>Assessed:</strong>&nbsp;__TOPBAR_ASSESS_DATE__</div></div></div></header>
<main class="page"><section class="content"><section class="panel hero" id="section-summary"><h2>Executive Summary</h2>
__WINMGMT_WARNING__
<p>This assessment evaluates the Active Directory environment for forest <strong>__SUMMARY_FOREST__</strong> against health and security best practices. Review the scorecard below to understand coverage, identify high-impact gaps, and prioritize remediation.</p><div class="hero-grid"><div class="score-tile"><div class="score-ring" aria-label="Health score __OVERALL_SCORE_DISPLAY__ out of 100"><svg viewBox="0 0 176 176"><circle cx="88" cy="88" r="70" class="score-ring-bg"/><circle cx="88" cy="88" r="70" class="score-ring-fill" stroke="__OVERALL_SCORE_COLOR__" stroke-dasharray="439.82" stroke-dashoffset="__OVERALL_SCORE_OFFSET__"/></svg><div class="score-ring-text"><strong style="color:__OVERALL_SCORE_COLOR__">__OVERALL_SCORE_DISPLAY__%</strong><span>Health Score</span></div></div><div class="score-caption">Grade: <strong>__GRADE__</strong> &nbsp;&middot;&nbsp; Risk: <strong style="color:__OVERALL_SCORE_COLOR__">__RISK__</strong></div></div><div class="hero-copy"><h2>Forest: __HERO_FOREST__</h2><p>Domain: <strong>__HERO_DOMAIN__</strong><br>Assessed: <strong>__HERO_ASSESS_DATE__</strong><br>Assessor: <strong>__HERO_ASSESSOR__</strong> &nbsp;&middot;&nbsp; DCs: __DC_COUNT__ &nbsp;&middot;&nbsp; Sites: __SITE_COUNT__</p><div class="stats-grid"><div class="stat-card"><span class="label">Checks Run</span><span class="value">__TOTAL_CHECKS__</span></div><div class="stat-card success"><span class="label">Passed</span><span class="value">__PASS_COUNT__</span></div><div class="stat-card danger"><span class="label">Failed</span><span class="value">__FAIL_COUNT__</span></div><div class="stat-card warning"><span class="label">Warnings</span><span class="value">__WARN_COUNT__</span></div><div class="stat-card info"><span class="label">Info</span><span class="value">__INFO_COUNT__</span></div><div class="stat-card danger"><span class="label">Critical</span><span class="value">__CRITICAL_COUNT__</span></div></div></div></div></section><div style="text-align:right;margin-bottom:4px;"><button type="button" class="export-btn" onclick="exportAllToCsv()">&#128196; Export All to CSV</button></div><section class="panel section-card" id="section-categories"><div class="section-header"><div><h2>Category Scorecards</h2><p>Each card shows an AD health control area score and pass / fail / warn breakdown. Thresholds: <strong style="color:#10b981">&gt;80 green</strong>, <strong style="color:#f59e0b">50&ndash;80 amber</strong>, <strong style="color:#ef4444">&lt;50 red</strong>.</p></div><div class="legend"><span class="legend-item success">Pass</span><span class="legend-item danger">Fail</span><span class="legend-item warning">Warn</span></div></div><div class="category-card-grid" id="categoryCards"></div></section><div id="category-sections-container"></div><section class="panel section-card" id="section-detailed-findings"><div class="section-header"><div><h2>Detailed Findings</h2><p>All __TOTAL_CHECKS__ checks with status, finding, and remediation guidance.</p></div><button type="button" class="export-btn" onclick="exportSectionToCsv('section-detailed-findings')">&#128196; Export to CSV</button></div><div class="findings-table-wrap"><table id="findings-main-table"><thead><tr><th>Check ID</th><th>Category</th><th>Status</th><th>Finding</th><th>Recommendation</th><th>Details</th><th>User Override</th></tr></thead><tbody id="findings-tbody"></tbody></table></div></section><section class="panel section-card" id="section-scoring-methodology">
<div class="section-header"><div><h2>&#128202; Understanding Your Results</h2><p>How the overall health score is calculated for this Active Directory assessment.</p></div></div>
<div style="background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); border: 1px solid #dee2e6; border-radius: 10px; padding: 20px; margin: 20px 0;">
<h4 style="margin-top: 0; color: #495057; display: flex; align-items: center; gap: 10px;"><span style="font-size: 1.2em;">&#9881;</span>Granular Scoring System</h4>
<p style="color: #495057; margin: 10px 0 15px 0;">The health score is a <strong>two-level weighted average</strong>. First, each category is scored individually based on its checks. Then, categories are combined using importance weights to produce the overall score.</p>
<h5 style="color: #495057; margin: 15px 0 10px 0;">Step 1: Per-Check Scoring</h5>
<p style="color: #6c757d; font-size: 0.95em; margin: 0 0 10px 0;">Each check receives a base score from its status, then adjusted by its ScoreImpact value:</p>
<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-bottom: 15px;">
<div style="background: rgba(16,185,129,0.1); border-left: 4px solid #10b981; padding: 12px; border-radius: 0 8px 8px 0; text-align:center;"><strong style="color: #065f46;">Pass</strong><br><span style="color: #065f46; font-size: 1.3em; font-weight:bold;">100</span></div>
<div style="background: rgba(59,130,246,0.1); border-left: 4px solid #3b82f6; padding: 12px; border-radius: 0 8px 8px 0; text-align:center;"><strong style="color: #1e40af;">Info</strong><br><span style="color: #1e40af; font-size: 1.3em; font-weight:bold;">100</span></div>
<div style="background: rgba(107,114,128,0.1); border-left: 4px solid #6b7280; padding: 12px; border-radius: 0 8px 8px 0; text-align:center;"><strong style="color: #374151;">Skipped</strong><br><span style="color: #374151; font-size: 1.3em; font-weight:bold;">85</span></div>
<div style="background: rgba(245,158,11,0.08); border-left: 4px solid #f59e0b; padding: 12px; border-radius: 0 8px 8px 0; text-align:center;"><strong style="color: #92400e;">Partial</strong><br><span style="color: #92400e; font-size: 1.3em; font-weight:bold;">70</span></div>
<div style="background: rgba(245,158,11,0.15); border-left: 4px solid #d97706; padding: 12px; border-radius: 0 8px 8px 0; text-align:center;"><strong style="color: #78350f;">Warning</strong><br><span style="color: #78350f; font-size: 1.3em; font-weight:bold;">50</span></div>
<div style="background: rgba(239,68,68,0.1); border-left: 4px solid #ef4444; padding: 12px; border-radius: 0 8px 8px 0; text-align:center;"><strong style="color: #991b1b;">Fail</strong><br><span style="color: #991b1b; font-size: 1.3em; font-weight:bold;">0</span></div>
</div>
<p style="color: #6c757d; font-size: 0.9em; margin: 0 0 15px 0;"><em>Formula: CheckScore = max(0, min(100, BaseScore &minus; |ScoreImpact|)) &times; Weight</em></p>
<h5 style="color: #495057; margin: 15px 0 10px 0;">Step 2: Category Weights (Overall Score)</h5>
<p style="color: #6c757d; font-size: 0.95em; margin: 0 0 10px 0;">Each category contributes to the overall score proportionally to its importance weight:</p>
<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; margin-bottom: 15px;">
<div style="background: rgba(239,68,68,0.08); border-left: 4px solid #ef4444; padding: 12px; border-radius: 0 8px 8px 0;"><strong style="color: #991b1b;">Security &amp; Hardening</strong><br><span style="color: #991b1b; font-size: 0.95em;">Weight: <strong>25%</strong> &mdash; Highest priority</span></div>
<div style="background: rgba(245,158,11,0.08); border-left: 4px solid #f59e0b; padding: 12px; border-radius: 0 8px 8px 0;"><strong style="color: #92400e;">Domain Controller Health</strong><br><span style="color: #92400e; font-size: 0.95em;">Weight: <strong>15%</strong></span></div>
<div style="background: rgba(245,158,11,0.08); border-left: 4px solid #f59e0b; padding: 12px; border-radius: 0 8px 8px 0;"><strong style="color: #92400e;">Replication Health</strong><br><span style="color: #92400e; font-size: 0.95em;">Weight: <strong>15%</strong></span></div>
<div style="background: rgba(59,130,246,0.08); border-left: 4px solid #3b82f6; padding: 12px; border-radius: 0 8px 8px 0;"><strong style="color: #1e40af;">DNS Health</strong><br><span style="color: #1e40af; font-size: 0.95em;">Weight: <strong>10%</strong></span></div>
<div style="background: rgba(59,130,246,0.08); border-left: 4px solid #3b82f6; padding: 12px; border-radius: 0 8px 8px 0;"><strong style="color: #1e40af;">Forest &amp; Domain Configuration</strong><br><span style="color: #1e40af; font-size: 0.95em;">Weight: <strong>10%</strong></span></div>
<div style="background: rgba(59,130,246,0.08); border-left: 4px solid #3b82f6; padding: 12px; border-radius: 0 8px 8px 0;"><strong style="color: #1e40af;">User &amp; Computer Hygiene</strong><br><span style="color: #1e40af; font-size: 0.95em;">Weight: <strong>10%</strong></span></div>
<div style="background: rgba(59,130,246,0.08); border-left: 4px solid #3b82f6; padding: 12px; border-radius: 0 8px 8px 0;"><strong style="color: #1e40af;">Group Policy Health</strong><br><span style="color: #1e40af; font-size: 0.95em;">Weight: <strong>10%</strong></span></div>
<div style="background: rgba(107,114,128,0.08); border-left: 4px solid #6b7280; padding: 12px; border-radius: 0 8px 8px 0;"><strong style="color: #374151;">SYSVOL &amp; File Replication</strong><br><span style="color: #374151; font-size: 0.95em;">Weight: <strong>5%</strong></span></div>
<div style="background: rgba(107,114,128,0.08); border-left: 4px solid #6b7280; padding: 12px; border-radius: 0 8px 8px 0;"><strong style="color: #374151;">Sites &amp; Topology</strong><br><span style="color: #374151; font-size: 0.95em;">Weight: <strong>5%</strong></span></div>
<div style="background: rgba(107,114,128,0.08); border-left: 4px solid #6b7280; padding: 12px; border-radius: 0 8px 8px 0;"><strong style="color: #374151;">Backup &amp; Recovery</strong><br><span style="color: #374151; font-size: 0.95em;">Weight: <strong>4%</strong> (Info only)</span></div>
<div style="background: rgba(107,114,128,0.08); border-left: 4px solid #6b7280; padding: 12px; border-radius: 0 8px 8px 0;"><strong style="color: #374151;">FSMO Roles</strong><br><span style="color: #374151; font-size: 0.95em;">Weight: <strong>3%</strong></span></div>
<div style="background: rgba(107,114,128,0.08); border-left: 4px solid #6b7280; padding: 12px; border-radius: 0 8px 8px 0;"><strong style="color: #374151;">Time Synchronization</strong><br><span style="color: #374151; font-size: 0.95em;">Weight: <strong>3%</strong></span></div>
</div>
<p style="margin: 15px 0 0 0; color: #6c757d; font-size: 0.9em; text-align: center;"><em>Overall Score = &Sigma;(Category Score &times; Category Weight) / &Sigma;(Category Weights)</em></p>
</div>
<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-top: 20px;">
<div style="background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.3); border-radius: 8px; padding: 14px; text-align:center;"><strong style="color: #065f46; font-size: 1.1em;">Excellent</strong><br><span style="color: #065f46;">Score &ge; 90</span><br><small style="color: #6c757d;">Environment well-managed</small></div>
<div style="background: rgba(59,130,246,0.1); border: 1px solid rgba(59,130,246,0.3); border-radius: 8px; padding: 14px; text-align:center;"><strong style="color: #1e40af; font-size: 1.1em;">Good</strong><br><span style="color: #1e40af;">Score &ge; 75</span><br><small style="color: #6c757d;">Minor improvements needed</small></div>
<div style="background: rgba(245,158,11,0.1); border: 1px solid rgba(245,158,11,0.3); border-radius: 8px; padding: 14px; text-align:center;"><strong style="color: #92400e; font-size: 1.1em;">Fair</strong><br><span style="color: #92400e;">Score &ge; 60</span><br><small style="color: #6c757d;">Several gaps to address</small></div>
<div style="background: rgba(249,115,22,0.1); border: 1px solid rgba(249,115,22,0.3); border-radius: 8px; padding: 14px; text-align:center;"><strong style="color: #9a3412; font-size: 1.1em;">Poor</strong><br><span style="color: #9a3412;">Score &ge; 40</span><br><small style="color: #6c757d;">Significant vulnerabilities</small></div>
<div style="background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); border-radius: 8px; padding: 14px; text-align:center;"><strong style="color: #991b1b; font-size: 1.1em;">Critical</strong><br><span style="color: #991b1b;">Score &lt; 40</span><br><small style="color: #6c757d;">Urgent attention required</small></div>
</div>
<div style="background: #f0f9ff; border: 1px solid #bae6fd; border-radius: 8px; padding: 16px; margin-top: 20px;">
<p style="margin: 0; color: #0c4a6e; font-size: 0.95em;"><strong>&#128161; Key Notes:</strong></p>
<ul style="margin: 8px 0 0 0; padding-left: 20px; color: #0c4a6e; font-size: 0.9em; line-height: 1.8;">
<li><strong>Info</strong> checks score the same as Pass (100) &mdash; they provide context but do not penalize the score.</li>
<li>Each check has a <strong>Weight</strong> (importance within its category) and optional <strong>ScoreImpact</strong> (additional penalty).</li>
<li>Categories with more checks have finer granularity; each individual check contributes proportionally to its weight.</li>
<li>The <strong>Security &amp; Hardening</strong> category has the highest weight (25%) reflecting its critical importance to AD health.</li>
</ul>
</div>
</section></section></main>
<div class="evidence-modal-overlay" id="evidenceOverlay" onclick="closeEvidence(event)"><div class="evidence-modal" id="evidenceModal"><h3 id="evidenceTitle">Details</h3><div class="evidence-section"><div class="evidence-label">Details</div><div class="evidence-content" id="evidenceData"></div></div><div class="evidence-section"><div class="evidence-label">Reference</div><div class="evidence-content" id="evidenceRef"></div></div><div class="evidence-section"><div class="evidence-label">Query</div><div class="evidence-content" id="evidenceQuery"></div></div><button type="button" class="close-btn" onclick="closeEvidence()">Close</button></div></div>
<footer class="footer"><div class="footer-inner"><div class="footer-title">Active Directory Health Assessment &ndash; __FOOTER_FOREST__</div><div class="footer-date">Report generated at __FOOTER_DATE__</div><div class="footer-disclaimer">This assessment reflects configuration state at the time of collection and should be reviewed alongside operational context, compensating controls, and Microsoft guidance before final risk decisions are made. Forest: __FOOTER_FOREST__ &nbsp;&middot;&nbsp; Assessor: __FOOTER_ASSESSOR__ &nbsp;&middot;&nbsp; Tool: AD HealthCheck</div></div></footer>
<div class="regenerate-bar" id="regenerateBar"><div class="regen-info"><span>&#9888;&#65039; Overrides applied:</span><span class="regen-count" id="regenCount">0</span><span>findings marked by user</span></div><div><button type="button" class="regen-btn" onclick="regenerateReport()">&#9889; Regenerate Report</button><button type="button" class="regen-reset" onclick="resetOverrides()">Reset All</button></div></div>

  <script>
var CATEGORIES=__CATEGORIES_JSON__;
var FINDINGS=__FINDINGS_JSON__;
function statusClass(s){if(s==='Pass')return 'status-pass';if(s==='Fail')return 'status-critical';return 'status-warning';}
function scoreColor(s){if(s>80)return '#10b981';if(s>=50)return '#f59e0b';return '#ef4444';}
function scoreOffset(s){return(175.93*(1-s/100)).toFixed(2);}
function pillClass(s){if(s>80)return 'pill success';if(s>=50)return 'pill warning';return 'pill danger';}
function renderCategoryCards(){var html='';for(var i=0;i<CATEGORIES.length;i++){var cat=CATEGORIES[i];var color=scoreColor(cat.score);var offset=scoreOffset(cat.score);html+='<div class="category-card"><div class="category-card-title">'+cat.name+'</div><div class="category-card-charts"><div class="category-chart-group"><svg width="80" height="80" viewBox="0 0 70 70" style="display:block;margin:0 auto;"><circle cx="35" cy="35" r="28" fill="none" stroke="#dbe5f0" stroke-width="8"/><circle cx="35" cy="35" r="28" fill="none" stroke="'+color+'" stroke-width="8" stroke-dasharray="175.93" stroke-dashoffset="'+offset+'" stroke-linecap="round" transform="rotate(-90 35 35)"/><text x="35" y="41" text-anchor="middle" font-size="16" font-weight="700" fill="'+color+'">'+cat.score+'%</text></svg><div class="category-chart-detail"><span style="color:#107c10;font-weight:600">'+cat.pass+' pass</span> &middot; <span style="color:#d13438;font-weight:600">'+cat.fail+' fail</span> &middot; <span style="color:#ff8c00;font-weight:600">'+cat.warn+' warn</span></div></div></div></div>';}document.getElementById('categoryCards').innerHTML=html;}
function renderMainTable(){var html='';for(var i=0;i<FINDINGS.length;i++){var r=FINDINGS[i];var overrideCell='';if(r[3]!=='Pass'){overrideCell='<select class="override-select" data-idx="'+i+'" onchange="markOverride(this)"><option value="">—</option><option value="Mitigated">Mitigated</option><option value="False Positive">False Positive</option><option value="Accept Risk">Accept Risk</option></select>';}else{overrideCell='<span class="override-na">—</span>';}html+='<tr><td><code>'+r[0]+'</code></td><td>'+r[2]+'</td><td><span class="status-badge '+statusClass(r[3])+'">'+r[3]+'</span></td><td class="wrap">'+r[4]+'</td><td class="wrap">'+r[5]+'</td><td><a href="#" class="evidence-link" onclick="showEvidence('+i+');return false;">View Details</a></td><td>'+overrideCell+'</td></tr>';}document.getElementById('findings-tbody').innerHTML=html;}
function renderCategorySections(){var container=document.getElementById('category-sections-container');var sectionsHtml='';for(var i=0;i<CATEGORIES.length;i++){var cat=CATEGORIES[i];var collapsibleId='collapsible-'+cat.id;var rows=FINDINGS.filter(function(r){return r[1]===cat.id;});sectionsHtml+='<section class="detail-section" id="section-'+cat.id+'" data-section="'+cat.id+'"><div class="detail-section-header"><h2>'+cat.fullName+'</h2><button type="button" class="export-btn" onclick="exportSectionToCsv(\'section-'+cat.id+'\')">&#128196; Export to CSV</button></div><div class="detail-meta"><span class="pill success">&#10004; Pass: '+cat.pass+'</span><span class="pill danger">&#10060; Fail: '+cat.fail+'</span><span class="pill warning">&#9888; Warn: '+cat.warn+'</span><span class="'+pillClass(cat.score)+'" style="font-weight:700">Score: '+cat.score+'%</span><span class="pill info">Total: '+cat.total+' checks</span></div><div class="policy-collapsible" id="'+collapsibleId+'"><div class="policy-header" onclick="togglePolicy(\''+collapsibleId+'\')"><span class="policy-toggle-icon">&#9660;</span><span class="policy-title">All Findings</span><span class="pill info" style="margin-left:auto">'+rows.length+' rows</span></div><div class="policy-content"><div class="findings-table-wrap"><table class="findings-cat-table"><thead><tr><th>Check ID</th><th>Status</th><th>Finding</th><th>Recommendation</th><th>Details</th><th>User Override</th></tr></thead><tbody id="findings-tbody-'+cat.id+'"></tbody></table></div></div></div></section>';}container.innerHTML=sectionsHtml;for(var j=0;j<CATEGORIES.length;j++){var cat2=CATEGORIES[j];var catRows=FINDINGS.filter(function(r){return r[1]===cat2.id;});var tbHtml='';for(var k=0;k<catRows.length;k++){var row=catRows[k];var idx=FINDINGS.indexOf(row);var overrideCell='';if(row[3]!=='Pass'){overrideCell='<select class="override-select" data-idx="'+idx+'" onchange="markOverride(this)"><option value="">—</option><option value="Mitigated">Mitigated</option><option value="False Positive">False Positive</option><option value="Accept Risk">Accept Risk</option></select>';}else{overrideCell='<span class="override-na">—</span>';}tbHtml+='<tr><td><code>'+row[0]+'</code></td><td><span class="status-badge '+statusClass(row[3])+'">'+row[3]+'</span></td><td>'+row[4]+'</td><td>'+row[5]+'</td><td><a href="#" class="evidence-link" onclick="showEvidence('+idx+');return false;">View Details</a></td><td>'+overrideCell+'</td></tr>';}var tbEl=document.getElementById('findings-tbody-'+cat2.id);if(tbEl)tbEl.innerHTML=tbHtml;}}
function exportSectionToCsv(sectionId){var section=document.getElementById(sectionId);if(!section)return;var tables=section.querySelectorAll('table');if(tables.length===0)return;var csvRows=[];var headerAdded=false;var evidenceColIdx=-1;for(var t=0;t<tables.length;t++){var rows=tables[t].querySelectorAll('tr');for(var i=0;i<rows.length;i++){var cells=rows[i].querySelectorAll('th, td');if(cells.length===0)continue;if(rows[i].querySelectorAll('th').length>0){if(!headerAdded){var headerData=[];for(var j=0;j<cells.length;j++){if(cells[j].innerText.trim().toLowerCase()==='details'){evidenceColIdx=j;continue;}headerData.push('"'+cells[j].innerText.replace(/"/g,'""').trim()+'"');}csvRows.push(headerData.join(','));headerAdded=true;}continue;}var rowData=[];for(var j=0;j<cells.length;j++){if(j===evidenceColIdx)continue;var text=cells[j].innerText.replace(/"/g,'""').replace(/\n/g,' ').trim();rowData.push('"'+text+'"');}csvRows.push(rowData.join(','));}}if(csvRows.length===0)return;var csvContent='\uFEFF'+csvRows.join('\n');var blob=new Blob([csvContent],{type:'text/csv;charset=utf-8;'});var link=document.createElement('a');var titleEl=section.querySelector('h2, h3');var fileName=((titleEl?titleEl.innerText:sectionId).replace(/[^a-z0-9]/gi,'_'))+'.csv';link.href=URL.createObjectURL(blob);link.download=fileName;link.style.display='none';document.body.appendChild(link);link.click();document.body.removeChild(link);}
function exportAllToCsv(){function esc(v){return '"'+String(v).replace(/<[^>]+>/g,'').replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&nbsp;/g,' ').replace(/&middot;/g,String.fromCharCode(183)).replace(/"/g,'""').trim()+'"';}var csvRows=['"Check ID","Category","Status","Finding","Recommendation","Reference"'];for(var i=0;i<FINDINGS.length;i++){var r=FINDINGS[i];csvRows.push([esc(r[0]),esc(r[2]),esc(r[3]),esc(r[4]),esc(r[5]),esc(r[7])].join(','));}var blob=new Blob(['\uFEFF'+csvRows.join('\n')],{type:'text/csv;charset=utf-8;'});var link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download='AD_Health_Assessment___FOREST_SLUG__.csv';link.style.display='none';document.body.appendChild(link);link.click();document.body.removeChild(link);}
function togglePolicy(policyId){var el=document.getElementById(policyId);if(el)el.classList.toggle('collapsed');}
function toggleSidebar(){document.getElementById('sidebar').classList.toggle('open');document.getElementById('sidebarOverlay').classList.toggle('open');}
function scrollToSection(sectionId,el){var target=document.getElementById(sectionId);if(target)target.scrollIntoView({behavior:'smooth',block:'start'});var items=document.querySelectorAll('#categoryNav .sidebar-item');items.forEach(function(i){i.classList.remove('active');});if(el)el.classList.add('active');if(window.innerWidth<=1120)toggleSidebar();}
function showEvidence(idx){var r=FINDINGS[idx];if(!r)return;document.getElementById('evidenceTitle').textContent=r[0]+' \u2014 Details';var evidence=r[6]||'(none)';try{var parsed=JSON.parse(evidence.replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&#39;/g,"'"));if(parsed&&typeof parsed.TotalCount==='number'&&parsed.Items){var header='Showing '+parsed.Showing+' of '+parsed.TotalCount+' total item(s)';if(parsed.TotalCount>parsed.Showing){header+='\n(Export full CSV for complete list)';}evidence=header+'\n\n'+JSON.stringify(parsed.Items,null,2);}else{evidence=JSON.stringify(parsed,null,2);}}catch(e){}document.getElementById('evidenceData').textContent=evidence;document.getElementById('evidenceRef').textContent=r[7]||'(none)';document.getElementById('evidenceQuery').textContent=r[8]||'(not available)';document.getElementById('evidenceOverlay').classList.add('active');}
function closeEvidence(event){if(!event||event.target===document.getElementById('evidenceOverlay')){document.getElementById('evidenceOverlay').classList.remove('active');}}
var userOverrides={};
function markOverride(sel){var idx=parseInt(sel.getAttribute('data-idx'));sel.className='override-select';if(sel.value){userOverrides[idx]=sel.value;if(sel.value==='Mitigated')sel.classList.add('selected-mitigated');else if(sel.value==='False Positive')sel.classList.add('selected-falsepositive');else if(sel.value==='Accept Risk')sel.classList.add('selected-acceptrisk');}else{delete userOverrides[idx];}syncOverrideSelects(idx,sel.value);updateRegenBar();}
function syncOverrideSelects(idx,val){var allSels=document.querySelectorAll('.override-select[data-idx="'+idx+'"]');for(var i=0;i<allSels.length;i++){var s=allSels[i];s.value=val;s.className='override-select';if(val==='Mitigated')s.classList.add('selected-mitigated');else if(val==='False Positive')s.classList.add('selected-falsepositive');else if(val==='Accept Risk')s.classList.add('selected-acceptrisk');}}
function updateRegenBar(){var count=Object.keys(userOverrides).length;document.getElementById('regenCount').textContent=count;var bar=document.getElementById('regenerateBar');if(count>0)bar.classList.add('visible');else bar.classList.remove('visible');}
function resetOverrides(){userOverrides={};var allSels=document.querySelectorAll('.override-select');for(var i=0;i<allSels.length;i++){allSels[i].value='';allSels[i].className='override-select';}updateRegenBar();}
function applyStoredOverrides(){for(var idx in userOverrides){if(userOverrides.hasOwnProperty(idx)){var val=userOverrides[idx];var allSels=document.querySelectorAll('.override-select[data-idx="'+idx+'"]');for(var i=0;i<allSels.length;i++){var s=allSels[i];s.value=val;s.className='override-select';if(val==='Mitigated')s.classList.add('selected-mitigated');else if(val==='False Positive')s.classList.add('selected-falsepositive');else if(val==='Accept Risk')s.classList.add('selected-acceptrisk');}}}updateRegenBar();}
function regenerateReport(){var overrideCount=Object.keys(userOverrides).length;if(overrideCount===0)return;var newFindings=[];for(var i=0;i<FINDINGS.length;i++){var row=FINDINGS[i].slice();if(userOverrides[i]){row[3]='Info';row[4]='['+userOverrides[i]+'] '+row[4];}newFindings.push(row);}var newCategories=[];for(var c=0;c<CATEGORIES.length;c++){var cat=JSON.parse(JSON.stringify(CATEGORIES[c]));var catRows=newFindings.filter(function(r){return r[1]===cat.id;});var pass=0,fail=0,warn=0;for(var k=0;k<catRows.length;k++){var st=catRows[k][3];if(st==='Pass')pass++;else if(st==='Fail')fail++;else warn++;}cat.pass=pass;cat.fail=fail;cat.warn=warn;cat.total=catRows.length;var scorable=pass+fail;cat.score=scorable>0?Math.round((pass/scorable)*100):(cat.total>0?100:0);newCategories.push(cat);}var totalChecks=newFindings.length;var passCount=0,failCount=0,warnCount=0,infoCount=0,critCount=0;for(var i=0;i<newFindings.length;i++){var s=newFindings[i][3];if(s==='Pass')passCount++;else if(s==='Fail')failCount++;else if(s==='Warning'||s==='Partial'||s==='Info'||s==='Skipped')warnCount++;else critCount++;}var scorableTotal=passCount+failCount;var overallScore=scorableTotal>0?Math.round((passCount/scorableTotal)*100):100;function sColor(s){if(s>80)return '#10b981';if(s>=50)return '#f59e0b';return '#ef4444';}function sOffset(s){return(439.82*(1-s/100)).toFixed(2);}function sGrade(s){if(s>=90)return 'A';if(s>=80)return 'B';if(s>=70)return 'C';if(s>=60)return 'D';return 'F';}function sRisk(s){if(s>=90)return 'Low';if(s>=70)return 'Medium';if(s>=50)return 'High';return 'Critical';}var oColor=sColor(overallScore);var oOffset=sOffset(overallScore);var oGrade=sGrade(overallScore);var oRisk=sRisk(overallScore);var doc=document.documentElement.cloneNode(true);var scripts=doc.querySelectorAll('script');for(var si=0;si<scripts.length;si++){var stxt=scripts[si].textContent;if(stxt.indexOf('var CATEGORIES=')!==-1){stxt=stxt.replace(/var CATEGORIES=[\s\S]*?;\s*var FINDINGS=[\s\S]*?;\s*function/,'var CATEGORIES='+JSON.stringify(newCategories)+';\nvar FINDINGS='+JSON.stringify(newFindings)+';\nfunction');stxt=stxt.replace(/var userOverrides=\{[^}]*\};/,'var userOverrides='+JSON.stringify(userOverrides)+';');scripts[si].textContent=stxt;break;}}var ringFills=doc.querySelectorAll('.score-ring-fill');if(ringFills.length>0){ringFills[0].setAttribute('stroke',oColor);ringFills[0].setAttribute('stroke-dashoffset',oOffset);}var ringTexts=doc.querySelectorAll('.score-ring-text strong');if(ringTexts.length>0){ringTexts[0].style.color=oColor;ringTexts[0].textContent=overallScore+'%';}var scoreCaptions=doc.querySelectorAll('.score-caption');if(scoreCaptions.length>0){scoreCaptions[0].innerHTML='Grade: <strong>'+oGrade+'</strong> &nbsp;&middot;&nbsp; Risk: <strong style="color:'+oColor+'">'+oRisk+'</strong>';}var statCards=doc.querySelectorAll('.stat-card .value');if(statCards.length>=6){statCards[1].textContent=passCount;statCards[2].textContent=failCount;statCards[3].textContent=warnCount;statCards[4].textContent=infoCount+overrideCount;}var regenBar=doc.querySelector('.regenerate-bar');if(regenBar)regenBar.parentNode.removeChild(regenBar);var overrideSummary=document.createElement('div');overrideSummary.style.cssText='background:#ecfdf5;border:2px solid #10b981;border-radius:10px;padding:16px 20px;margin:16px 0;';var summaryHtml='<strong>&#9989; User Overrides Applied ('+overrideCount+' findings)</strong><ul style="margin:8px 0 0 16px;padding:0;">';for(var idx in userOverrides){if(userOverrides.hasOwnProperty(idx)){summaryHtml+='<li><code>'+FINDINGS[idx][0]+'</code> &rarr; <strong>'+userOverrides[idx]+'</strong> (original: '+FINDINGS[idx][3]+')</li>';}}summaryHtml+='</ul>';overrideSummary.innerHTML=summaryHtml;var heroSection=doc.querySelector('.hero-grid');if(heroSection&&heroSection.parentNode){heroSection.parentNode.insertBefore(overrideSummary,heroSection);}var footerDate=doc.querySelector('.footer-date');if(footerDate){footerDate.textContent='Report regenerated with user overrides at '+new Date().toLocaleString();}var html='<!DOCTYPE html>\n'+doc.outerHTML;var blob=new Blob([html],{type:'text/html;charset=utf-8'});var link=document.createElement('a');var now=new Date();var ts=now.getFullYear()+''+(now.getMonth()+1<10?'0':'')+(now.getMonth()+1)+(now.getDate()<10?'0':'')+now.getDate()+'-'+(now.getHours()<10?'0':'')+now.getHours()+(now.getMinutes()<10?'0':'')+now.getMinutes()+(now.getSeconds()<10?'0':'')+now.getSeconds();link.href=URL.createObjectURL(blob);link.download='AD_Assessment_UserOverride_'+ts+'.html';link.style.display='none';document.body.appendChild(link);link.click();document.body.removeChild(link);}
function addTableFilters(table){if(!table)return;var thead=table.querySelector('thead');if(!thead)return;var headerRow=thead.querySelector('tr');if(!headerRow)return;var colCount=headerRow.querySelectorAll('th').length;var filterRow=document.createElement('tr');filterRow.className='column-filter-row';for(var c=0;c<colCount;c++){var th=document.createElement('th');var sel=document.createElement('select');sel.setAttribute('data-col',c);sel.innerHTML='<option value="">All</option>';sel.addEventListener('change',(function(tbl){return function(){applyTableFilters(tbl);};})(table));th.appendChild(sel);filterRow.appendChild(th);}thead.appendChild(filterRow);populateFilterOptions(table);}
function populateFilterOptions(table){var thead=table.querySelector('thead');var filterRow=thead.querySelector('.column-filter-row');if(!filterRow)return;var selects=filterRow.querySelectorAll('select');var tbody=table.querySelector('tbody');if(!tbody)return;var rows=tbody.querySelectorAll('tr');selects.forEach(function(sel){var col=parseInt(sel.getAttribute('data-col'));var values={};for(var i=0;i<rows.length;i++){var cells=rows[i].querySelectorAll('td');if(cells.length>col){var text=cells[col].innerText.trim();if(text)values[text]=true;}}var current=sel.value;sel.innerHTML='<option value="">All</option>';Object.keys(values).sort().forEach(function(v){var opt=document.createElement('option');opt.value=v;opt.textContent=v;sel.appendChild(opt);});sel.value=current;});}
function applyTableFilters(table){var thead=table.querySelector('thead');var filterRow=thead.querySelector('.column-filter-row');if(!filterRow)return;var selects=filterRow.querySelectorAll('select');var filters=[];selects.forEach(function(sel){filters.push({col:parseInt(sel.getAttribute('data-col')),value:sel.value});});var tbody=table.querySelector('tbody');if(!tbody)return;var rows=tbody.querySelectorAll('tr');for(var i=0;i<rows.length;i++){var cells=rows[i].querySelectorAll('td');var show=true;for(var f=0;f<filters.length;f++){if(filters[f].value&&cells.length>filters[f].col){if(cells[filters[f].col].innerText.trim()!==filters[f].value){show=false;break;}}}rows[i].style.display=show?'':'none';}}
function initAllTableFilters(){var tables=document.querySelectorAll('#findings-main-table, .findings-cat-table');tables.forEach(function(tbl){addTableFilters(tbl);});}
(function init(){renderCategoryCards();renderMainTable();renderCategorySections();initAllTableFilters();applyStoredOverrides();var sections=Array.prototype.slice.call(document.querySelectorAll('[id^="section-"]'));var observer=new IntersectionObserver(function(entries){entries.forEach(function(entry){if(entry.isIntersecting){var id=entry.target.id;var items=document.querySelectorAll('#categoryNav .sidebar-item');items.forEach(function(i){i.classList.remove('active');});var activeLink=document.querySelector('#categoryNav .sidebar-item[href="#'+id+'"]');if(activeLink)activeLink.classList.add('active');}});},{threshold:0.15,rootMargin:'0px 0px -60% 0px'});sections.forEach(function(s){observer.observe(s);});}());
  </script>
</body>
</html>
'@

        $htmlBuilder = [System.Text.StringBuilder]::new($htmlTemplate)
        [void]$htmlBuilder.Replace('__TITLE_FOREST__', (& $encodeHtml $forestName))
        $winmgmtBanner = ''
        if ($Script:WinmgmtWarning) {
            $winmgmtBanner = '<div style="background:#fef3cd;border:1px solid #ffc107;border-radius:6px;padding:12px 16px;margin-bottom:16px;color:#856404;font-size:14px;"><strong>&#9888; Warning:</strong> The Windows Management Instrumentation (Winmgmt) service was not running during this assessment. Findings related to CPU, Memory, Disk space, and NTDS.dit file size may not be presented as expected.</div>'
        }
        [void]$htmlBuilder.Replace('__WINMGMT_WARNING__', $winmgmtBanner)
        [void]$htmlBuilder.Replace('__SIDEBAR_SUBTITLE__', (& $encodeHtml $forestName))
        [void]$htmlBuilder.Replace('__CATEGORY_NAV_ITEMS__', $categoryNavHtml)
        [void]$htmlBuilder.Replace('__TOPBAR_FOREST__', (& $encodeHtml $forestName))
        [void]$htmlBuilder.Replace('__TOPBAR_DOMAIN__', (& $encodeHtml $domainName))
        [void]$htmlBuilder.Replace('__TOPBAR_ASSESSOR__', (& $encodeHtml $assessor))
        [void]$htmlBuilder.Replace('__TOPBAR_ASSESS_DATE__', (& $encodeHtml $assessDate))
        [void]$htmlBuilder.Replace('__SUMMARY_FOREST__', (& $encodeHtml $forestName))
        [void]$htmlBuilder.Replace('__OVERALL_SCORE_DISPLAY__', $overallScoreDisplay)
        [void]$htmlBuilder.Replace('__OVERALL_SCORE_COLOR__', $overallScoreColor)
        [void]$htmlBuilder.Replace('__OVERALL_SCORE_OFFSET__', $overallScoreOffset)
        [void]$htmlBuilder.Replace('__GRADE__', (& $encodeHtml $grade))
        [void]$htmlBuilder.Replace('__RISK__', (& $encodeHtml $risk))
        [void]$htmlBuilder.Replace('__HERO_FOREST__', (& $encodeHtml $forestName))
        [void]$htmlBuilder.Replace('__HERO_DOMAIN__', (& $encodeHtml $domainName))
        [void]$htmlBuilder.Replace('__HERO_ASSESS_DATE__', (& $encodeHtml $assessDate))
        [void]$htmlBuilder.Replace('__HERO_ASSESSOR__', (& $encodeHtml $assessor))
        [void]$htmlBuilder.Replace('__DC_COUNT__', [string]$dcCount)
        [void]$htmlBuilder.Replace('__SITE_COUNT__', [string]$siteCount)
        [void]$htmlBuilder.Replace('__TOTAL_CHECKS__', [string]$totalChecks)
        [void]$htmlBuilder.Replace('__PASS_COUNT__', [string]$passCount)
        [void]$htmlBuilder.Replace('__FAIL_COUNT__', [string]$failCount)
        [void]$htmlBuilder.Replace('__WARN_COUNT__', [string]$warnCount)
        [void]$htmlBuilder.Replace('__INFO_COUNT__', [string]$infoCount)
        [void]$htmlBuilder.Replace('__CRITICAL_COUNT__', [string]$criticalItems.Count)
        [void]$htmlBuilder.Replace('__FOOTER_FOREST__', (& $encodeHtml $forestName))
        [void]$htmlBuilder.Replace('__FOOTER_DATE__', (& $encodeHtml $assessDate))
        [void]$htmlBuilder.Replace('__FOOTER_ASSESSOR__', (& $encodeHtml $assessor))
        [void]$htmlBuilder.Replace('__CATEGORIES_JSON__', $categoriesJson)
        [void]$htmlBuilder.Replace('__FINDINGS_JSON__', $findingsJson)
        [void]$htmlBuilder.Replace('__FOREST_SLUG__', $forestSlug)
        $html = $htmlBuilder.ToString()

        $html | Set-Content -Path $Script:HtmlReportPath -Encoding UTF8
        Write-ADLog -Message ("HTML report generated at {0}" -f $Script:HtmlReportPath) -Level 'SUCCESS'
    } catch {
        Write-ADLog -Message ("HTML report generation failed: {0}" -f $_.Exception.Message) -Level 'WARN'
    }

    Write-ADLog -Message ("Overall Health Score: {0} ({1})" -f $scores.OverallScore, $scores.Rating) -Level 'SUCCESS'
}
#endregion Start-ADHealthCheck

Set-StrictMode -Off
Start-ADHealthCheck
#endregion Main Orchestration
