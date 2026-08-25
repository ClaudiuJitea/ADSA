# BuiltInPrivileges.psm1 - Pre-Windows 2000 Compatible Access and other dangerous built-ins

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-BuiltInPrivilegesAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "Built-in Privileges"
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-BIN-000" -Category $category))
        return $findings
    }

    function Get-GroupSams([string]$Name) {
        $g = Find-AuditGroup -Name $Name
        if (-not $g) { return @() }
        @(Get-AuditGroupMembers -GroupDn (Get-AuditAttr $g "distinguishedName") -Recursive | ForEach-Object { Get-AuditSam $_ })
    }

    $pre2k = @(Get-GroupSams "Pre-Windows 2000 Compatible Access")
    $riskyPre = @($pre2k | Where-Object { $_ -match "Authenticated Users|Everyone|Anonymous|ANONYMOUS LOGON" })
    if ($riskyPre.Count -gt 0 -or $pre2k.Count -gt 4) {
        $objs = if ($riskyPre.Count -gt 0) { $riskyPre } else { $pre2k }
        [void]$findings.Add((New-AuditFinding -CheckId "AD-BIN-001" -Category $category -Subcategory "Anonymous / Pre-Win2k" `
            -Title "Pre-Windows 2000 Compatible Access is overly populated" `
            -Description "This group grants broad read rights that mimic Windows NT 4 compatibility. Authenticated Users or Everyone membership is equivalent to allowing any domain principal (and sometimes anonymous) to enumerate SAM." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $objs.Count `
            -AffectedObjects (Limit-AuditObjects $objs) -Evidence $pre2k `
            -Recommendation "Remove Authenticated Users, Everyone, and Anonymous from Pre-Windows 2000 Compatible Access. Keep it empty in modern forests." `
            -MicrosoftReference "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory" `
            -MitreTechnique "T1087.002" -DataSource "group"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-BIN-001" -Category $category -Subcategory "Anonymous / Pre-Win2k" `
            -Title "Pre-Windows 2000 Compatible Access does not include Everyone/Authenticated Users" `
            -Description "Resolved members: $($pre2k -join ', ')" `
            -Severity "Informational" -Status "Passed" -Evidence $pre2k -DataSource "group"))
    }

    $incoming = @(Get-GroupSams "Incoming Forest Trust Builders")
    if ($incoming.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-BIN-002" -Category $category -Subcategory "Trust Builders" `
            -Title "Incoming Forest Trust Builders is populated" `
            -Description "Members can create inbound forest trusts." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $incoming.Count `
            -AffectedObjects $incoming -Evidence $incoming `
            -Recommendation "Keep Incoming Forest Trust Builders empty except during a planned trust change." `
            -MitreTechnique "T1484.002" -DataSource "group"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-BIN-002" -Category $category -Subcategory "Trust Builders" `
            -Title "Incoming Forest Trust Builders is empty" `
            -Description "No nested members were resolved." `
            -Severity "Informational" -Status "Passed" -DataSource "group"))
    }

    $certPubs = @(Get-GroupSams "Cert Publishers")
    if ($certPubs.Count -gt 5) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-BIN-003" -Category $category -Subcategory "Cert Publishers" `
            -Title "Cert Publishers has $($certPubs.Count) members" `
            -Description "Cert Publishers can publish certificates into user objects. Unexpected members can facilitate authentication-related persistence." `
            -Severity "Medium" -Status "Warning" -RiskScore 8 -AffectedCount $certPubs.Count `
            -AffectedObjects (Limit-AuditObjects $certPubs) -Evidence $certPubs `
            -Recommendation "Limit Cert Publishers to enterprise CAs and documented PKI servers." `
            -DataSource "group"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-BIN-003" -Category $category -Subcategory "Cert Publishers" `
            -Title "Cert Publishers membership is small ($($certPubs.Count))" `
            -Description "Membership count is within a typical CA-server baseline." `
            -Severity "Informational" -Status "Passed" -AffectedObjects $certPubs -DataSource "group"))
    }

    $gpoOwners = @(Get-GroupSams "Group Policy Creator Owners")
    if ($gpoOwners.Count -gt 1) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-BIN-004" -Category $category -Subcategory "GPO Owners" `
            -Title "Group Policy Creator Owners is populated" `
            -Description "Members can create GPOs. Combined with linking rights this becomes domain-wide code execution." `
            -Severity "Medium" -Status "Failed" -RiskScore 8 -AffectedCount $gpoOwners.Count `
            -AffectedObjects $gpoOwners -Evidence $gpoOwners `
            -Recommendation "Remove standing members; create GPOs using a controlled admin process." `
            -MitreTechnique "T1484.001" -DataSource "group"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-BIN-004" -Category $category -Subcategory "GPO Owners" `
            -Title "Group Policy Creator Owners is empty or default" `
            -Description "Resolved members: $($gpoOwners -join ', ')" `
            -Severity "Informational" -Status "Passed" -DataSource "group"))
    }

    return $findings
}

Export-ModuleMember -Function Invoke-BuiltInPrivilegesAudit
