# AttackPaths.psm1 - Correlate failed findings into Tier 0 edges

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-AttackPathsAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [array]$AllFindings = @(),
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "Attack Path Indicators"
    $edges = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($f in $AllFindings) {
        if ($f.Status -ne "Failed" -or -not $f.AffectedObjects) { continue }
        $rel = $null; $sev = $f.Severity; $srcType = "Principal"; $tgt = "Tier 0"; $tgtType = "Asset"
        switch -Regex ($f.CheckId) {
            "AD-GRP-002" { $rel = "Kerberoast"; $tgt = "Privileged user"; $tgtType = "User" }
            "AD-GRP-012" { $rel = "ComputerInTier0"; $tgt = "Privileged group"; $tgtType = "Group"; $sev = "Critical" }
            "AD-USR-009" { $rel = "Kerberoast"; $tgt = "Service account"; $tgtType = "User" }
            "AD-KERB-002" { $rel = "AS-REP Roast"; $tgt = "User"; $tgtType = "User" }
            "AD-KERB-004" { $rel = "DuplicateSPN"; $tgt = "Kerberos service"; $tgtType = "SPN" }
            "AD-DEL-001" { $rel = "UnconstrainedDelegation"; $tgt = "Domain Admins TGT"; $tgtType = "Group"; $sev = "Critical" }
            "AD-DEL-004" { $rel = "RBCD"; $tgt = "Computer takeover"; $tgtType = "Computer" }
            "AD-DEL-005" { $rel = "KCD-to-DC"; $tgt = "Domain Controller"; $tgtType = "Computer"; $sev = "Critical" }
            "AD-ACL-001" { $rel = "DCSync"; $tgt = "Domain root"; $tgtType = "Domain"; $sev = "Critical" }
            "AD-TZ-002" { $rel = "WriteAdminGroup"; $tgt = "Tier 0 group or account"; $tgtType = "Group"; $sev = "Critical" }
            "AD-TZ-003" { $rel = "WriteDCObject"; $tgt = "Domain Controller"; $tgtType = "Computer"; $sev = "Critical" }
            "AD-TZ-008" { $rel = "Tier0Delegation"; $tgt = "Domain Admins TGT"; $tgtType = "Group"; $sev = "Critical" }
            "AD-SCH-004" { $rel = "WriteForestPartition"; $tgt = "Schema / Configuration"; $tgtType = "Partition"; $sev = "Critical" }
            "AD-GPO-002" { $rel = "EditGPO"; $tgt = "Linked GPO / Domain"; $tgtType = "GPO" }
            "AD-GPO-005" { $rel = "OwnGPO"; $tgt = "Linked GPO / Domain"; $tgtType = "GPO" }
            "AD-CS-001" { $rel = "ESC1-Enroll"; $tgt = "Any principal / Domain Admins"; $tgtType = "CertificateTemplate"; $sev = "Critical" }
            "AD-CS-002" { $rel = "ESC4-WriteTemplate"; $tgt = "Certificate template"; $tgtType = "CertificateTemplate"; $sev = "Critical" }
            "AD-CS-007" { $rel = "ESC7-ManageCA"; $tgt = "Enterprise CA"; $tgtType = "CertificationAuthority"; $sev = "Critical" }
            "AD-CS-009" { $rel = "ESC13-IssuancePolicy"; $tgt = "Linked group / Domain"; $tgtType = "CertificateTemplate"; $sev = "Critical" }
            "AD-CS-010" { $rel = "ESC5-WritePKI"; $tgt = "NTAuthCertificates / PKI container"; $tgtType = "PKI"; $sev = "Critical" }
            "AD-CS-012" { $rel = "OwnTemplate"; $tgt = "Certificate template"; $tgtType = "CertificateTemplate"; $sev = "Critical" }
            "AD-HYB-001" { $rel = "EntraConnect"; $tgt = "Cloud identity sync"; $tgtType = "Hybrid" }
            "AD-DNS-002" { $rel = "DnsAdmins-Plugin"; $tgt = "Domain Controller SYSTEM"; $tgtType = "Computer" }
            "AD-GMSA-002" { $rel = "ReadGmsaPassword"; $tgt = "gMSA"; $tgtType = "Account"; $sev = "Critical" }
            "AD-XCH-001" { $rel = "ExchangeWindowsPermissions"; $tgt = "Domain root / DCSync"; $tgtType = "Domain"; $sev = "Critical" }
            default { $rel = $null }
        }
        if (-not $rel) { continue }
        foreach ($obj in @($f.AffectedObjects)) {
            if ("$obj" -like "... and * more") { continue }
            $edges.Add([PSCustomObject]@{
                    SourceName   = "$obj"
                    SourceType   = $srcType
                    Relationship = $rel
                    TargetName   = $tgt
                    TargetType   = $tgtType
                    Severity     = $sev
                    Evidence     = $f.Title
                    CheckId      = $f.CheckId
                })
        }
    }

    if ($edges.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-PATH-001" -Category $category -Subcategory "Graph" `
            -Title "High-risk attack path edges targeting Tier 0" `
            -Description "Correlated $($edges.Count) edge(s) from failed checks (Kerberoast, delegation, DCSync, ESC, hybrid, DnsAdmins)." `
            -Severity "Critical" -Status "Failed" -RiskScore 25 -AffectedCount $edges.Count `
            -AffectedObjects (Limit-AuditObjects @($edges | ForEach-Object { "$($_.SourceName) -[$($_.Relationship)]-> $($_.TargetName)" })) `
            -Evidence @($edges | Select-Object -First 25 | ForEach-Object { "$($_.CheckId): $($_.SourceName) -> $($_.TargetName)" }) `
            -Recommendation "Remediate the source checks in Critical/High order. Break the shortest paths first (DCSync, ESC1, unconstrained delegation)." `
            -MitreTechnique "T1078" -DataSource "Finding correlation"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-PATH-001" -Category $category -Subcategory "Graph" `
            -Title "No critical attack-path edges correlated" `
            -Description "Failed findings did not include the high-risk relationship types this engine maps." `
            -Severity "Informational" -Status "Passed" -DataSource "Finding correlation"))
    }

    return @{ Findings = $findings; Edges = $edges }
}

Export-ModuleMember -Function Invoke-AttackPathsAudit
