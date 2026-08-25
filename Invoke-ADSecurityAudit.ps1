# Invoke-ADSecurityAudit.ps1 - Active Directory Security Audit Orchestrator
# Windows PowerShell 5.1 and PowerShell 7+ (Windows and Linux)
# Binds with RSAT Active Directory when available, otherwise LDAP.

<#
.SYNOPSIS
    Performs an authorized, 100% read-only Active Directory security and baseline audit.

.DESCRIPTION
    Invoke-ADSecurityAudit orchestrates a modular security audit across Active Directory:
    domain/forest baseline, DCs, privileged groups, Tier 0 ownership and control, users, computers, password policy,
    Kerberos, delegation, GPO, ACLs, schema, trusts, DNS, LDAP, LAPS, AD CS, hybrid identity, replication
    sites, gMSA, Exchange privileges, attack-path correlation, risk scoring, and reporting.

    The engine uses the RSAT Active Directory module when available, and LDAP when it is not.

.PARAMETER Domain
    Target Active Directory domain FQDN or NetBIOS name.

.PARAMETER Server
    Specific Domain Controller hostname or IP address to target for queries.

.PARAMETER Credential
    PSCredential object to execute queries under explicit alternate domain credentials.

.PARAMETER OutputPath
    Directory path where HTML, CSV, and JSON reports will be saved. Default: 'Output'.

.PARAMETER InactiveDays
    Threshold in days to classify user and computer accounts as inactive. Default: 90.

.PARAMETER PasswordAgeWarningDays
    Threshold in days for krbtgt password age warnings. Default: 180.

.PARAMETER SkipRemoteChecks
    Skip checks requiring WMI/CIM or Remote Registry access to remote DCs.

.PARAMETER GenerateHtml
    Generate self-contained HTML executive summary report. Default: $true.

.PARAMETER GenerateCsv
    Export raw findings and attack path edges as CSV. Default: $true.

.PARAMETER GenerateJson
    Export full audit structured output as JSON. Default: $true.

.PARAMETER MaxObjectsPerFinding
    Maximum affected objects rendered in HTML finding summaries. Default: 100.

.PARAMETER ConfigPath
    Path to custom AuditConfig.json file.

.PARAMETER Modules
    Optional list of module IDs to run (for example DomainForest,Kerberos). When omitted, all audit modules run.
    Risk scoring and HTML/CSV/JSON reporting always run at the end.

.PARAMETER BaselinePath
    Path to a previous AD-Security-Audit-Findings.json used as the comparison baseline. When omitted,
    an existing JSON export in OutputPath is used automatically, so repeated runs show what changed.

.PARAMETER FailOnSeverity
    Exit with code 2 when a failed finding of this severity or higher exists. Use in pipelines to
    gate a release on Active Directory risk. Default: None (always exit 0).

.EXAMPLE
    .\Invoke-ADSecurityAudit.ps1 -Domain "contoso.local" -OutputPath "C:\AD-Audit" -GenerateHtml -GenerateCsv

.EXAMPLE
    .\Invoke-ADSecurityAudit.ps1 -Domain "contoso.local" -Modules TierZero,CertificateServices -FailOnSeverity Critical

.NOTES
    Author: AD Security Audit Framework Team
    Version: 2.2.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Domain,

    [Parameter(Mandatory = $false)]
    [string]$Server,

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "Output",

    [Parameter(Mandatory = $false)]
    [int]$InactiveDays = 90,

    [Parameter(Mandatory = $false)]
    [int]$PasswordAgeWarningDays = 180,

    [Parameter(Mandatory = $false)]
    [switch]$SkipRemoteChecks,

    [Parameter(Mandatory = $false)]
    [bool]$GenerateHtml = $true,

    [Parameter(Mandatory = $false)]
    [bool]$GenerateCsv = $true,

    [Parameter(Mandatory = $false)]
    [bool]$GenerateJson = $true,

    [Parameter(Mandatory = $false)]
    [int]$MaxObjectsPerFinding = 100,

    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,

    [Parameter(Mandatory = $false)]
    [string[]]$Modules,

    [Parameter(Mandatory = $false)]
    [string]$BaselinePath,

    [Parameter(Mandatory = $false)]
    [ValidateSet("None", "Critical", "High", "Medium", "Low")]
    [string]$FailOnSeverity = "None"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Display Mandatory Legal Disclaimer
Write-Host "=========================================================================" -ForegroundColor Cyan
Write-Host "  Active Directory Security Audit Framework v2.2.0 (Read-Only)            " -ForegroundColor Cyan
Write-Host "=========================================================================" -ForegroundColor Cyan
Write-Host "This tool performs authorized, read-only Active Directory security auditing." -ForegroundColor Yellow
Write-Host "Run it only in environments where you have explicit permission." -ForegroundColor Yellow
Write-Host "=========================================================================`n" -ForegroundColor Cyan

if (-not $Credential) {
    $envUser = [Environment]::GetEnvironmentVariable("AD_AUDIT_USERNAME")
    if (-not [string]::IsNullOrWhiteSpace($envUser)) {
        $envPass = [Environment]::GetEnvironmentVariable("AD_AUDIT_PASSWORD")
        if ($null -eq $envPass) { $envPass = "" }
        $secure = ConvertTo-SecureString -String $envPass -AsPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential($envUser, $secure)
        Write-Host "[*] Using alternate credentials for user: $envUser" -ForegroundColor Green
    }
}

if ($Modules -and $Modules.Count -eq 1 -and $Modules[0] -match ",") {
    $Modules = @($Modules[0].Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Test-ShouldRunAuditModule {
    param([Parameter(Mandatory = $true)][string]$ModuleId)
    if (-not $Modules -or $Modules.Count -eq 0) { return $true }
    return ($Modules -contains $ModuleId)
}

# Audit modules bind with Get-AD* -Server. Prefer an explicit DC hostname when provided.
$bindTarget = if (-not [string]::IsNullOrWhiteSpace($Server)) { $Server } else { $Domain }

$scriptRoot = $PSScriptRoot
$modulesDir = Join-Path $scriptRoot "Modules"

# Dynamically Import Audit Modules
$moduleFiles = Get-ChildItem -Path $modulesDir -Filter "*.psm1"
foreach ($m in $moduleFiles) {
    try {
        Import-Module $m.FullName -Force -ErrorAction Stop
        Write-Verbose "Imported module: $($m.Name)"
    } catch {
        Write-Warning "Failed importing module $($m.Name): $($_.Exception.Message)"
    }
}

$configObject = $null
$resolvedConfigPath = if ($ConfigPath) { $ConfigPath } else { Join-Path $scriptRoot "Config/AuditConfig.json" }
if (Test-Path $resolvedConfigPath) {
    try {
        $configObject = Get-Content -Path $resolvedConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
        Write-Host "[*] Loaded configuration: $resolvedConfigPath" -ForegroundColor Green
    } catch {
        Write-Warning "Failed loading $resolvedConfigPath : $($_.Exception.Message)"
    }
}
$configHash = @{}
if ($configObject) {
    foreach ($p in $configObject.PSObject.Properties) { $configHash[$p.Name] = $p.Value }
    if ($configHash.ContainsKey("MaxObjectsPerFinding") -and -not $PSBoundParameters.ContainsKey("MaxObjectsPerFinding")) {
        $MaxObjectsPerFinding = [int]$configHash["MaxObjectsPerFinding"]
    }
}

$preferLdaps = $false
if ($configHash.ContainsKey("PreferLdaps")) {
    $preferLdaps = [bool]$configHash["PreferLdaps"]
}

Write-Host "[*] Binding to directory ($bindTarget)..." -ForegroundColor Green
$session = Initialize-AuditDirectorySession -Domain $Domain -Server $Server -Credential $Credential -PreferLdaps:$preferLdaps
if ($session.Provider -eq "None") {
    Write-Host "[!] Directory bind failed: $($session.Error)" -ForegroundColor Yellow
    Write-Host "[!] Checks will be marked Not Tested. Set Domain Controller, domain FQDN, and credentials if this host is not domain-joined." -ForegroundColor Yellow
} else {
    Write-Host "[*] Directory provider: $($session.Provider)  DN: $($session.DefaultNamingContext)" -ForegroundColor Green
}

$gateTripped = $false
$scoreResult = $null
try {
$allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
$edges = @()
$startTime = Get-Date

Write-Host "[*] Starting Active Directory Security Audit..." -ForegroundColor Green
if ($Modules -and $Modules.Count -gt 0) {
    Write-Host "[*] Module filter: $($Modules -join ', ')" -ForegroundColor Green
}

function Add-AuditResults {
    param(
        [System.Collections.Generic.List[PSCustomObject]]$TargetList,
        $ModuleResults
    )
    if ($null -ne $ModuleResults) {
        foreach ($res in $ModuleResults) {
            if ($null -ne $res) {
                [void]$TargetList.Add($res)
            }
        }
    }
}

function Invoke-AuditCategory {
    param(
        [Parameter(Mandatory = $true)][string]$ModuleId,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    if (-not (Test-ShouldRunAuditModule -ModuleId $ModuleId)) { return }
    Write-Host "[+] $Label..." -ForegroundColor Gray
    $moduleStart = Get-Date
    $before = $allFindings.Count
    try {
        Add-AuditResults -TargetList $allFindings -ModuleResults (& $Action)
        $elapsed = [math]::Round(((Get-Date) - $moduleStart).TotalSeconds, 1)
        Write-Host "    $($allFindings.Count - $before) checks in $elapsed s" -ForegroundColor DarkGray
    } catch {
        Write-Warning "Module $ModuleId failed: $($_.Exception.Message)"
        [void]$allFindings.Add((New-AuditFinding -CheckId "AD-ERR-001" -Category $ModuleId `
                -Title "Module execution error ($ModuleId)" `
                -Description $_.Exception.Message -Severity "Medium" -Status "Error" `
                -Recommendation "Re-run this module after correcting directory connectivity, permissions, or a module defect." `
                -DataSource "Orchestrator"))
    }
}

Invoke-AuditCategory -ModuleId "DomainForest" -Label "Category 1/25: Domain & Forest Configuration" -Action { Invoke-DomainForestAudit -Domain $bindTarget -Credential $Credential -Config $configHash }
Invoke-AuditCategory -ModuleId "DomainControllers" -Label "Category 2/25: Domain Controllers" -Action { Invoke-DomainControllersAudit -Domain $bindTarget -Credential $Credential -SkipRemoteChecks $SkipRemoteChecks -Config $configHash }
Invoke-AuditCategory -ModuleId "PrivilegedGroups" -Label "Category 3/25: Privileged Groups" -Action { Invoke-PrivilegedGroupsAudit -Domain $bindTarget -Credential $Credential -InactiveDays $InactiveDays -Config $configHash }
Invoke-AuditCategory -ModuleId "TierZero" -Label "Category 4/25: Tier 0 Attack Surface" -Action { Invoke-TierZeroAudit -Domain $bindTarget -Credential $Credential -Config $configHash }
Invoke-AuditCategory -ModuleId "UsersServiceAccounts" -Label "Category 5/25: Users & Service Accounts" -Action { Invoke-UsersServiceAccountsAudit -Domain $bindTarget -Credential $Credential -InactiveDays $InactiveDays -Config $configHash }
Invoke-AuditCategory -ModuleId "ComputersOS" -Label "Category 6/25: Computers & Operating Systems" -Action { Invoke-ComputersOperatingSystemsAudit -Domain $bindTarget -Credential $Credential -InactiveDays $InactiveDays -Config $configHash }
Invoke-AuditCategory -ModuleId "PasswordAuth" -Label "Category 7/25: Password Policy & Authentication" -Action { Invoke-PasswordAuthenticationAudit -Domain $bindTarget -Credential $Credential -Config $configHash }
Invoke-AuditCategory -ModuleId "Kerberos" -Label "Category 8/25: Kerberos Security" -Action { Invoke-KerberosAudit -Domain $bindTarget -Credential $Credential -KrbtgtWarningDays $PasswordAgeWarningDays -Config $configHash }
Invoke-AuditCategory -ModuleId "Delegation" -Label "Category 9/25: Kerberos Delegation" -Action { Invoke-DelegationAudit -Domain $bindTarget -Credential $Credential -Config $configHash }
Invoke-AuditCategory -ModuleId "GroupPolicy" -Label "Category 10/25: Group Policy Security" -Action { Invoke-GroupPolicyAudit -Domain $bindTarget -Credential $Credential -Config $configHash }
Invoke-AuditCategory -ModuleId "ADAcl" -Label "Category 11/25: AD ACL Permissions" -Action { Invoke-ADAclAudit -Domain $bindTarget -Credential $Credential -Config $configHash }
Invoke-AuditCategory -ModuleId "SchemaSecurity" -Label "Category 12/25: Schema Security" -Action { Invoke-SchemaSecurityAudit -Domain $bindTarget -Credential $Credential -Config $configHash }
Invoke-AuditCategory -ModuleId "Trusts" -Label "Category 13/25: Trust Relationships" -Action { Invoke-TrustsAudit -Domain $bindTarget -Credential $Credential -Config $configHash }
Invoke-AuditCategory -ModuleId "DNS" -Label "Category 14/25: DNS Security" -Action { Invoke-DNSAudit -Domain $bindTarget -Credential $Credential -Config $configHash }
Invoke-AuditCategory -ModuleId "LdapNtlm" -Label "Category 15/25: LDAP & NTLM Security" -Action { Invoke-LdapNtlmAudit -Domain $bindTarget -Credential $Credential -SkipRemoteChecks $SkipRemoteChecks -Config $configHash }
Invoke-AuditCategory -ModuleId "LapsLocalAdmin" -Label "Category 16/25: LAPS Security" -Action { Invoke-LapsLocalAdminAudit -Domain $bindTarget -Credential $Credential -Config $configHash }
Invoke-AuditCategory -ModuleId "CertificateServices" -Label "Category 17/25: Certificate Services (AD CS)" -Action { Invoke-CertificateServicesAudit -Domain $bindTarget -Credential $Credential -Config $configHash }
Invoke-AuditCategory -ModuleId "HybridIdentity" -Label "Category 18/25: Hybrid Identity" -Action { Invoke-HybridIdentityAudit -Domain $bindTarget -Credential $Credential -Config $configHash }
Invoke-AuditCategory -ModuleId "ReplicationSites" -Label "Category 19/25: Replication & Sites" -Action { Invoke-ReplicationSitesAudit -Domain $bindTarget -Credential $Credential -Config $configHash }
Invoke-AuditCategory -ModuleId "BuiltInPrivileges" -Label "Category 20/25: Built-in Privileges" -Action { Invoke-BuiltInPrivilegesAudit -Domain $bindTarget -Credential $Credential -Config $configHash }
Invoke-AuditCategory -ModuleId "ManagedServiceAccounts" -Label "Category 21/25: Managed Service Accounts" -Action { Invoke-ManagedServiceAccountsAudit -Domain $bindTarget -Credential $Credential -Config $configHash }
Invoke-AuditCategory -ModuleId "ExchangePrivileges" -Label "Category 22/25: Exchange & Application Privileges" -Action { Invoke-ExchangePrivilegesAudit -Domain $bindTarget -Credential $Credential -Config $configHash }

if (Test-ShouldRunAuditModule -ModuleId "AttackPaths") {
    Write-Host "[+] Category 23/25: Graph Attack Path Indicators..." -ForegroundColor Gray
    try {
        $attackPathResult = Invoke-AttackPathsAudit -Domain $bindTarget -Credential $Credential -AllFindings $allFindings -Config $configHash
        Add-AuditResults -TargetList $allFindings -ModuleResults $attackPathResult.Findings
        $edges = $attackPathResult.Edges
    } catch {
        Write-Warning "Module AttackPaths failed: $($_.Exception.Message)"
        [void]$allFindings.Add((New-AuditFinding -CheckId "AD-ERR-001" -Category "Attack Path Indicators" -Title "Attack path correlation failed" -Description $_.Exception.Message -Severity "Medium" -Status "Error"))
    }
}

Write-Host "[+] Category 24/25: Calculating Risk Score..." -ForegroundColor Gray
$scoreResult = Invoke-RiskScoring -Findings $allFindings

Write-Host "[+] Category 25/25: Generating Audit Reports..." -ForegroundColor Gray
$reportDomain = if (-not [string]::IsNullOrWhiteSpace($Domain)) { $Domain } elseif ($session.Domain) { $session.Domain } else { $bindTarget }
$reportBaseline = if ($BaselinePath) { $BaselinePath } else { "" }
Export-AuditReports -Findings $allFindings -ScoreResult $scoreResult -OutputPath $OutputPath -Edges $edges -Domain $reportDomain -GenerateHtml $GenerateHtml -GenerateCsv $GenerateCsv -GenerateJson $GenerateJson -MaxObjectsPerFinding $MaxObjectsPerFinding -BaselinePath $reportBaseline

$duration = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 2)
Write-Host "`n[*] Audit Complete in $duration seconds!" -ForegroundColor Green
Write-Host "    Overall Risk Rating: $($scoreResult.RiskRating) ($($scoreResult.NormalizedScore)/100, $($scoreResult.RiskPoints) risk points)" -ForegroundColor Yellow
Write-Host "    Compliance: $($scoreResult.CompliancePercent)%  |  Critical failed: $($scoreResult.FailedCritical)  |  High failed: $($scoreResult.FailedHigh)" -ForegroundColor Yellow
Write-Host "    Checks evaluated: $($scoreResult.TestedCount)/$($scoreResult.TotalFindings)  |  Not evaluated: $(@($scoreResult.CoverageGaps).Count)" -ForegroundColor Yellow
if (@($scoreResult.QuickWins).Count -gt 0) {
    Write-Host "    Top quick win: [$($scoreResult.QuickWins[0].CheckId)] $($scoreResult.QuickWins[0].Title)" -ForegroundColor Yellow
}
Write-Host "    Reports saved to: $OutputPath`n" -ForegroundColor Green

$gateTripped = Test-AuditSeverityGate -ScoreResult $scoreResult -FailOnSeverity $FailOnSeverity
} finally {
    Close-AuditDirectorySession
}

if ($gateTripped -and $null -ne $scoreResult) {
    Write-Host "[!] Severity gate: a failed finding at or above '$FailOnSeverity' exists (highest failed severity: $($scoreResult.HighestFailedSeverity)). Exiting with code 2." -ForegroundColor Red
    exit 2
}
