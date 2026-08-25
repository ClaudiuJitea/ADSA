# ComputersOperatingSystems.psm1 - Computer lifecycle and machine identity

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-ComputersOperatingSystemsAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [int]$InactiveDays = 90,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "Computers and Operating Systems"
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-CMP-000" -Category $category))
        return $findings
    }

    $computers = @(Search-AuditDirectory -LdapFilter "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" -Properties @(
            "name", "dNSHostName", "operatingSystem", "operatingSystemVersion", "lastLogonTimestamp", "pwdLastSet",
            "primaryGroupID", "userAccountControl", "servicePrincipalName"
        ))

    $eol = @(); $oldPwd = @(); $inactive = @(); $badPrimary = @()
    $pwdAge = (Get-Date).AddDays(-90)
    $inactiveThreshold = (Get-Date).AddDays(-$InactiveDays)

    foreach ($c in $computers) {
        $name = Get-AuditSam $c
        $os = [string](Get-AuditAttr $c "operatingSystem")
        if ($os -match "Windows 7|Windows 8|Windows XP|Vista|Server 2003|Server 2008|Server 2012") {
            $eol += "$name ($os)"
        }
        $pwdSet = Convert-AuditFileTime (Get-AuditAttr $c "pwdLastSet")
        if ($pwdSet -and $pwdSet -lt $pwdAge) { $oldPwd += "$name (Password set: $pwdSet)" }
        $last = Convert-AuditFileTime (Get-AuditAttr $c "lastLogonTimestamp")
        if ($last -and $last -lt $inactiveThreshold) { $inactive += "$name (Last logon: $last)" }
        $pg = Get-AuditAttr $c "primaryGroupID"
        $uac = Get-AuditAttr $c "userAccountControl"
        $isDc = Test-AuditUacFlag $uac 8192
        if ($pg -and $pg -ne 515 -and $pg -ne 516 -and -not $isDc) {
            $badPrimary += "$name (primaryGroupID=$pg)"
        }
    }

    if ($eol.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-CMP-001" -Category $category -Subcategory "Lifecycle" `
            -Title "Unsupported operating systems still domain-joined" `
            -Description "Found $($eol.Count) enabled computer(s) on EOL Windows versions." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $eol.Count `
            -AffectedObjects (Limit-AuditObjects $eol) -Evidence $eol `
            -Recommendation "Upgrade or isolate legacy systems; they accumulate unpatched remote vulnerabilities." `
            -MicrosoftReference "https://learn.microsoft.com/en-us/lifecycle/products/" -MitreTechnique "T1190" -DataSource "computer"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-CMP-001" -Category $category -Subcategory "Lifecycle" `
            -Title "No classic EOL OS strings on enabled computers" `
            -Description "No enabled computers matched Windows 7/8/XP/2003/2008/2012." `
            -Severity "Informational" -Status "Passed" -DataSource "computer"))
    }

    if ($oldPwd.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-CMP-002" -Category $category -Subcategory "Secure Channel" `
            -Title "Computer passwords older than 90 days" `
            -Description "Machine account passwords should rotate about every 30 days. Stale passwords often mean a cloned VM, broken trust, or an orphaned object." `
            -Severity "Medium" -Status "Warning" -RiskScore 8 -AffectedCount $oldPwd.Count `
            -AffectedObjects (Limit-AuditObjects $oldPwd) -Evidence $oldPwd `
            -Recommendation "Reset the secure channel or delete computer objects that no longer exist." -DataSource "pwdLastSet"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-CMP-002" -Category $category -Subcategory "Secure Channel" `
            -Title "Computer passwords are rotating" `
            -Description "No enabled computer had pwdLastSet older than 90 days." `
            -Severity "Informational" -Status "Passed" -DataSource "pwdLastSet"))
    }

    if ($inactive.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-CMP-003" -Category $category -Subcategory "Lifecycle" `
            -Title "Enabled computers inactive for over $InactiveDays days" `
            -Description "Stale computer accounts retain SPNs and can be hijacked if an attacker reuses the name (SPN conflict / Kerberos)." `
            -Severity "Medium" -Status "Failed" -RiskScore 8 -AffectedCount $inactive.Count `
            -AffectedObjects (Limit-AuditObjects $inactive) -Evidence $inactive `
            -Recommendation "Disable and eventually delete unused computer objects after an inventory review." `
            -MitreTechnique "T1078.003" -DataSource "lastLogonTimestamp"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-CMP-003" -Category $category -Subcategory "Lifecycle" `
            -Title "No inactive enabled computers detected" `
            -Description "Enabled computers have lastLogonTimestamp within $InactiveDays days, or the stamp was empty." `
            -Severity "Informational" -Status "Passed" -DataSource "lastLogonTimestamp"))
    }

    if ($badPrimary.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-CMP-004" -Category $category -Subcategory "Primary Group" `
            -Title "Computers with a non-standard primary group" `
            -Description "Changing primaryGroupID hides membership from the member attribute and is a known stealth persistence technique." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $badPrimary.Count `
            -AffectedObjects (Limit-AuditObjects $badPrimary) -Evidence $badPrimary `
            -Recommendation "Reset primaryGroupID to 515 (Domain Computers) unless the host is a DC (516)." `
            -MitreTechnique "T1098" -DataSource "primaryGroupID"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-CMP-004" -Category $category -Subcategory "Primary Group" `
            -Title "Computer primary groups look standard" `
            -Description "Enabled non-DC computers use primaryGroupID 515." `
            -Severity "Informational" -Status "Passed" -DataSource "primaryGroupID"))
    }

    return $findings
}

Export-ModuleMember -Function Invoke-ComputersOperatingSystemsAudit
