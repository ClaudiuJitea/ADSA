# LapsLocalAdmin.psm1 - Legacy and Windows LAPS schema + coverage

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-LapsLocalAdminAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "LAPS and Local Administrator Security"
    $session = Get-AuditDirectorySession
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-LAPS-000" -Category $category))
        return $findings
    }

    $schema = $session.SchemaNamingContext
    $legacy = Search-AuditDirectory -LdapFilter "(ldapDisplayName=ms-Mcs-AdmPwd)" -SearchBase $schema -Properties @("cn", "ldapDisplayName")
    $win = Search-AuditDirectory -LdapFilter "(ldapDisplayName=msLAPS-Password)" -SearchBase $schema -Properties @("cn", "ldapDisplayName")
    if (-not $legacy) { $legacy = Search-AuditDirectory -LdapFilter "(cn=ms-Mcs-AdmPwd)" -SearchBase $schema -Properties @("cn") }
    if (-not $win) { $win = Search-AuditDirectory -LdapFilter "(cn=ms-LAPS-Password)" -SearchBase $schema -Properties @("cn") }

    if (-not $legacy -and -not $win) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-LAPS-001" -Category $category -Subcategory "Deployment" `
            -Title "LAPS schema extensions are not installed" `
            -Description "Neither ms-Mcs-AdmPwd nor msLAPS-Password exists in the schema. Local administrator passwords are likely static and reused." `
            -Severity "Critical" -Status "Failed" -RiskScore 25 -AffectedCount 1 `
            -AffectedObjects @("schema") -Evidence @("ms-Mcs-AdmPwd missing", "msLAPS-Password missing") `
            -Recommendation "Deploy Windows LAPS and extend the schema; then target computers with a GPO." `
            -MicrosoftReference "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview" `
            -MitreTechnique "T1078.003" -DataSource "schema"))
        return $findings
    }

    $kind = if ($win) { "Windows LAPS" } else { "Legacy LAPS" }
    [void]$findings.Add((New-AuditFinding -CheckId "AD-LAPS-001" -Category $category -Subcategory "Deployment" `
        -Title "LAPS schema is present ($kind)" `
        -Description "The forest schema includes LAPS attributes ($kind)." `
        -Severity "Informational" -Status "Passed" -DataSource "schema"))

    $computers = @(Search-AuditDirectory -LdapFilter "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))" -Properties @("name", "distinguishedName", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime", "ms-Mcs-AdmPwd"))
    $missing = @()
    foreach ($c in $computers) {
        $legacyExp = Get-AuditAttr $c "ms-Mcs-AdmPwdExpirationTime"
        $winExp = Get-AuditAttr $c "msLAPS-PasswordExpirationTime"
        if (-not $legacyExp -and -not $winExp) { $missing += (Get-AuditSam $c) }
    }
    if ($missing.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-LAPS-003" -Category $category -Subcategory "Coverage" `
            -Title "Enabled member computers without LAPS expiration stamps" `
            -Description "Schema is present but $($missing.Count) enabled non-DC computer(s) have no LAPS expiration attribute. They may not be in the LAPS GPO scope." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $missing.Count `
            -AffectedObjects (Limit-AuditObjects $missing) -Evidence $missing `
            -Recommendation "Link Windows LAPS policy to workstation and member-server OUs; exclude DCs." `
            -MitreTechnique "T1078.003" -DataSource "computer"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-LAPS-003" -Category $category -Subcategory "Coverage" `
            -Title "LAPS expiration attributes present on enabled member computers" `
            -Description "Every enabled non-DC computer had a LAPS expiration stamp, or no computers were returned." `
            -Severity "Informational" -Status "Passed" -DataSource "computer"))
    }

    $lapsGuids = @(
        [guid]"b7b1b3de-ab09-4242-9e30-9280e721b0e6",
        [guid]"aa4e90cd-d33a-49e6-81e5-827c86510619",
        [guid]"e362ed86-b728-0842-b27d-2dea7ac6ba6c"
    )
    $approved = @()
    if ($Config.ApprovedLapsReaders) { $approved = @($Config.ApprovedLapsReaders) }
    $readers = New-Object System.Collections.Generic.List[string]
    $sample = @($computers | Select-Object -First 25)
    $targets = @($session.DefaultNamingContext) + @($sample | ForEach-Object { Get-AuditAttr $_ "distinguishedName" } | Where-Object { $_ })
    foreach ($dn in $targets) {
        foreach ($ace in @(Get-AuditAccessRules -DistinguishedName $dn)) {
            if ("$($ace.AccessControlType)" -ne "Allow") { continue }
            $id = [string]$ace.IdentityReference
            $skip = $false
            foreach ($ok in $approved) { if ($id -like "*$ok*") { $skip = $true } }
            if ($skip -or ($id -match "Domain Admins|Enterprise Admins|Administrators|SYSTEM")) { continue }
            $objGuid = $null
            try {
                if ($ace.ObjectType -and "$($ace.ObjectType)" -ne "00000000-0000-0000-0000-000000000000") {
                    $objGuid = [guid]$ace.ObjectType
                }
            } catch { }
            if ($objGuid -and ($lapsGuids -contains $objGuid) -and (Test-AuditBroadIdentity $id)) {
                [void]$readers.Add("$id can read LAPS attribute $(Convert-ADGuidToName $objGuid) on $dn")
            }
        }
    }
    Add-AuditCheckResult -Findings $findings -CheckId "AD-LAPS-002" -Category $category -Subcategory "Readers" `
        -FailTitle "Broad identities can read LAPS passwords" `
        -PassTitle "No Everyone/Authenticated Users LAPS-read ACEs on sampled objects" `
        -FailDescription "ms-Mcs-AdmPwd / msLAPS-Password readable by Authenticated Users or Everyone exposes every local admin password to the domain." `
        -Items @($readers) -Severity "High" -RiskScore 15 `
        -Recommendation "Grant LAPS read only to a dedicated workstation-admin group. Remove Authenticated Users extended rights." `
        -MitreTechnique "T1552" -DataSource "LAPS ACL"

    return $findings
}

Export-ModuleMember -Function Invoke-LapsLocalAdminAudit
