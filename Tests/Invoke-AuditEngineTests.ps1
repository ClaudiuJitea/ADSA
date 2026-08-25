# Invoke-AuditEngineTests.ps1 - Self-contained engine tests (no domain required)
# Run: pwsh -File ./Tests/Invoke-AuditEngineTests.ps1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$failed = 0
$passed = 0

function Assert-True {
    param([bool]$Condition, [string]$Name)
    if ($Condition) {
        $script:passed++
        Write-Host "  PASS  $Name" -ForegroundColor Green
    } else {
        $script:failed++
        Write-Host "  FAIL  $Name" -ForegroundColor Red
    }
}

Write-Host "`n=== Parse every PowerShell file ===" -ForegroundColor Cyan
Get-ChildItem -Path $root -Recurse -Include *.psm1, *.ps1 |
    Where-Object { $_.FullName -notmatch '[\\/](bin|obj|Publish)[\\/]' } |
    ForEach-Object {
        $parseErrors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$parseErrors)
        Assert-True ($parseErrors.Count -eq 0) "Parse $($_.Name)"
        if ($parseErrors.Count -gt 0) {
            $parseErrors | Select-Object -First 3 | ForEach-Object {
                Write-Host "        line $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor DarkRed
            }
        }
    }

Write-Host "`n=== Import modules ===" -ForegroundColor Cyan
Get-ChildItem -Path (Join-Path $root "Modules") -Filter *.psm1 | ForEach-Object {
    try {
        Import-Module $_.FullName -Force -ErrorAction Stop
        Assert-True $true "Import $($_.Name)"
    } catch {
        Assert-True $false "Import $($_.Name): $($_.Exception.Message)"
    }
}

Write-Host "`n=== Shared helpers ===" -ForegroundColor Cyan
Assert-True ((Format-AuditLdapFilterValue "CN=A(B)*C") -eq 'CN=A\28B\29\2aC') "LDAP filter escaping"
Assert-True ((Convert-ADGuidToName "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79") -match "RBCD") "GUID map includes RBCD"
Assert-True ((Convert-ADGuidToName "5b47d60f-6090-40b2-9f37-2a4de88f3063") -match "Shadow") "GUID map includes shadow credentials"
Assert-True (Test-AuditTier0Identity "CONTOSO\Domain Admins") "Domain Admins is Tier 0"
Assert-True (Test-AuditTier0Identity "S-1-5-21-1-2-3-512") "RID 512 is Tier 0"
Assert-True (-not (Test-AuditTier0Identity "CONTOSO\Account Operators")) "Account Operators is not treated as Tier 0"
Assert-True (Test-AuditUnresolvedSid "S-1-5-21-1-2-3-1111") "Bare domain SID is unresolved"
Assert-True (-not (Test-AuditUnresolvedSid "helpdesk (S-1-5-21-1-2-3-1111)")) "Resolved SID form is not unresolved"
Assert-True (Test-AuditControlRight -Mask 0x10000000 -ObjectType ([guid]::Empty)) "GenericAll is control"
Assert-True (Test-AuditControlRight -Mask 0x20 -ObjectType ([guid]"3f78c3e5-f79a-46bd-a0b8-9d18116ddc79")) "WriteProperty on RBCD is control"
Assert-True (-not (Test-AuditControlRight -Mask 0x20 -ObjectType ([guid]"bf96793f-0de6-11d0-a285-00aa003049e2"))) "WriteProperty on a harmless attribute is not control"
Assert-True ((Get-AuditAceRightNames 0x10040000) -match "WriteDacl") "ACE right names include WriteDacl"

$finding = New-AuditFinding -CheckId "AD-TEST-001" -Category "Unit" -Title "Synthetic fail" `
    -Description "Used by engine tests." -Severity "Critical" -Status "Failed" -RiskScore 25 `
    -AffectedCount 2 -AffectedObjects @("alice", "bob") -Recommendation "Fix it." -MitreTechnique "T1078"
Assert-True ($finding.CheckId -eq "AD-TEST-001") "New-AuditFinding CheckId"

Write-Host "`n=== Risk scoring and severity gate ===" -ForegroundColor Cyan
$passFinding = New-AuditFinding -CheckId "AD-TEST-002" -Category "Unit" -Title "Synthetic pass" `
    -Description "Passed." -Severity "Informational" -Status "Passed"
$warnFinding = New-AuditFinding -CheckId "AD-TEST-003" -Category "Unit" -Title "Synthetic warning" `
    -Description "Warning." -Severity "Medium" -Status "Warning" -AffectedCount 1
$score = Invoke-RiskScoring -Findings @($finding, $passFinding, $warnFinding)
Assert-True ($score.FailedCritical -eq 1) "One critical failure counted"
Assert-True ($score.CompliancePercent -eq 33) "Compliance is passed / tested"
Assert-True ($score.NormalizedScore -lt 100) "A single failure does not saturate the 0-100 score"
Assert-True ($score.RiskRating -eq "High Risk") "A critical failure rates as High Risk"
Assert-True (@($score.RemediationPlan).Count -eq 2) "Remediation plan includes failed and warning findings"
Assert-True (@($score.QuickWins).Count -ge 1) "Quick wins include the small critical finding"
Assert-True (Test-AuditSeverityGate -ScoreResult $score -FailOnSeverity Critical) "Critical gate trips"
Assert-True (-not (Test-AuditSeverityGate -ScoreResult $score -FailOnSeverity None)) "None gate does not trip"

$cleanScore = Invoke-RiskScoring -Findings @($passFinding)
Assert-True (-not (Test-AuditSeverityGate -ScoreResult $cleanScore -FailOnSeverity High)) "Passing run does not trip High gate"

Write-Host "`n=== Baseline comparison ===" -ForegroundColor Cyan
$baselineFinding = New-AuditFinding -CheckId "AD-TEST-001" -Category "Unit" -Title "Synthetic fail" `
    -Description "Used by engine tests." -Severity "Critical" -Status "Failed" -AffectedCount 1
$resolvedFinding = New-AuditFinding -CheckId "AD-TEST-OLD" -Category "Unit" -Title "Was open" `
    -Description "Resolved in current." -Severity "High" -Status "Failed" -AffectedCount 3
$delta = Compare-AuditBaseline -Current @($finding) -Baseline @($baselineFinding, $resolvedFinding)
Assert-True ($delta.IncreasedCount -eq 1) "Affected count growth is detected"
Assert-True ($delta.ResolvedCount -eq 1) "Resolved finding is detected"
Assert-True ($delta.NewCount -eq 0) "No brand-new CheckId in this fixture"

Write-Host "`n=== Reporting ===" -ForegroundColor Cyan
$outDir = Join-Path ([System.IO.Path]::GetTempPath()) ("AD-Audit-Tests-" + [guid]::NewGuid().ToString("N"))
try {
    Export-AuditReports -Findings @($finding, $passFinding, $warnFinding) -ScoreResult $score `
        -OutputPath $outDir -Edges @() -Domain "test.local" -GenerateHtml $true -GenerateCsv $true -GenerateJson $true
    Assert-True (Test-Path (Join-Path $outDir "AD-Security-Audit-Summary.html")) "HTML report written"
    Assert-True (Test-Path (Join-Path $outDir "AD-Security-Audit-Findings.json")) "JSON report written"
    Assert-True (Test-Path (Join-Path $outDir "AD-Security-Audit-Findings.csv")) "CSV report written"
    Assert-True (Test-Path (Join-Path $outDir "AD-Security-Audit-RemediationPlan.csv")) "Remediation CSV written"
    $html = Get-Content -Path (Join-Path $outDir "AD-Security-Audit-Summary.html") -Raw
    Assert-True ($html -match "Remediation Plan") "HTML includes remediation plan tab"
    Assert-True ($html -match "v2.2.0") "HTML reports framework 2.2.0"
    Assert-True ($html -match '<tr><td><strong>AD-TEST-001</strong></td><td>Unit</td>') "HTML keeps each finding on one table row"

    $json = Get-Content -Path (Join-Path $outDir "AD-Security-Audit-Findings.json") -Raw | ConvertFrom-Json
    Assert-True ($json.AuditMetadata.Version -eq "2.2.0") "JSON metadata version is 2.2.0"

    $later = New-AuditFinding -CheckId "AD-TEST-NEW" -Category "Unit" -Title "Appeared later" `
        -Description "New in second run." -Severity "High" -Status "Failed" -AffectedCount 1
    $score2 = Invoke-RiskScoring -Findings @($finding, $later, $passFinding)
    Export-AuditReports -Findings @($finding, $later, $passFinding) -ScoreResult $score2 `
        -OutputPath $outDir -Edges @() -Domain "test.local" -GenerateHtml $true -GenerateCsv $false -GenerateJson $true
    $html2 = Get-Content -Path (Join-Path $outDir "AD-Security-Audit-Summary.html") -Raw
    Assert-True ($html2 -match "AD-TEST-NEW") "Second run HTML shows the new finding"
    Assert-True ($html2 -match "Resolved") "Second run HTML includes the trend/resolved section"
} finally {
    if (Test-Path $outDir) { Remove-Item -Path $outDir -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host "`n=== Modules without a directory session ===" -ForegroundColor Cyan
foreach ($fn in @(
        "Invoke-TierZeroAudit",
        "Invoke-SchemaSecurityAudit",
        "Invoke-CertificateServicesAudit",
        "Invoke-PrivilegedGroupsAudit",
        "Invoke-KerberosAudit",
        "Invoke-DelegationAudit",
        "Invoke-GroupPolicyAudit",
        "Invoke-ADAclAudit",
        "Invoke-TrustsAudit",
        "Invoke-DomainControllersAudit",
        "Invoke-UsersServiceAccountsAudit"
    )) {
    $results = @(& $fn)
    Assert-True ($results.Count -ge 1 -and $results[0].Status -eq "Not Tested") "$fn returns Not Tested offline"
}

$paths = Invoke-AttackPathsAudit -AllFindings @($finding)
Assert-True ($paths.Findings.Count -eq 1) "Attack path module returns a finding"
Assert-True ($paths.Edges.Count -eq 0) "Synthetic unit finding is not mapped to an edge"

$csFail = New-AuditFinding -CheckId "AD-CS-001" -Category "Certificate Services" -Title "ESC1" `
    -Description "Template." -Severity "Critical" -Status "Failed" -AffectedCount 1 -AffectedObjects @("User")
$tzFail = New-AuditFinding -CheckId "AD-TZ-002" -Category "Tier 0 Attack Surface" -Title "Admin ACL" `
    -Description "Write." -Severity "Critical" -Status "Failed" -AffectedCount 1 -AffectedObjects @("helpdesk")
$mapped = Invoke-AttackPathsAudit -AllFindings @($csFail, $tzFail)
Assert-True ($mapped.Edges.Count -eq 2) "ESC1 and Tier 0 control map to attack-path edges"

Write-Host "`n=== Orchestrator surface ===" -ForegroundColor Cyan
$orch = Get-Content -Path (Join-Path $root "Invoke-ADSecurityAudit.ps1") -Raw
Assert-True ($orch -match "Invoke-TierZeroAudit") "Orchestrator runs TierZero"
Assert-True ($orch -match "Invoke-SchemaSecurityAudit") "Orchestrator runs SchemaSecurity"
Assert-True ($orch -match "FailOnSeverity") "Orchestrator exposes FailOnSeverity"
Assert-True ($orch -match "BaselinePath") "Orchestrator exposes BaselinePath"

$config = Get-Content -Path (Join-Path $root "Config/AuditConfig.json") -Raw | ConvertFrom-Json
Assert-True ($config.MaxTier0PasswordAgeDays -eq 365) "Config includes MaxTier0PasswordAgeDays"
Assert-True ($config.MinCertificateKeySize -eq 2048) "Config includes MinCertificateKeySize"

Write-Host "`n=== Result ===" -ForegroundColor Cyan
Write-Host "Passed: $passed   Failed: $failed"
if ($failed -gt 0) { exit 1 }
exit 0
