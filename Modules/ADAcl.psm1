# ADAcl.psm1 - DCSync, dangerous domain ACEs, AdminSDHolder

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-ADAclAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "AD ACL Permissions"
    $session = Get-AuditDirectorySession
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-ACL-000" -Category $category))
        return $findings
    }

    $dcsyncGuids = @(
        [guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
        [guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    )

    $domainRules = @(Get-AuditAccessRules -DistinguishedName $session.DefaultNamingContext)
    $dcsync = @()
    $dangerous = @()
    foreach ($ace in $domainRules) {
        $id = [string]$ace.IdentityReference
        if (Test-AuditTier0Identity $id) { continue }
        if ("$($ace.AccessControlType)" -ne "Allow") { continue }
        $objGuid = $null
        try {
            if ($ace.ObjectType -and "$($ace.ObjectType)" -ne "00000000-0000-0000-0000-000000000000") {
                $objGuid = [guid]$ace.ObjectType
            }
        } catch { }
        if ($objGuid -and ($dcsyncGuids -contains $objGuid)) {
            $dcsync += "$id (" + (Convert-ADGuidToName "$objGuid") + ")"
        }
        $mask = 0
        try { $mask = [int]$ace.ActiveDirectoryRights } catch { }
        if (Test-AuditDangerousAccessMask $mask) { $dangerous += "$id (mask=$mask)" }
    }

    if ($domainRules.Count -eq 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-ACL-001" -Category $category -Subcategory "DCSync" `
            -Title "Domain root ACL could not be read" `
            -Description "nTSecurityDescriptor was not returned. This is common for unprivileged LDAP binds." `
            -Severity "Medium" -Status "Not Tested" -RequiredPermission "Read nTSecurityDescriptor" -DataSource "ACL"))
        [void]$findings.Add((New-AuditFinding -CheckId "AD-ACL-002" -Category $category -Subcategory "Domain Root" `
            -Title "Domain root ACL could not be read" `
            -Description "Skipping GenericAll/WriteDacl analysis because the security descriptor was unavailable." `
            -Severity "Medium" -Status "Not Tested" -DataSource "ACL"))
    } else {
        if ($dcsync.Count -gt 0) {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-ACL-001" -Category $category -Subcategory "DCSync" `
                -Title "Non-tier-0 principals have DCSync rights" `
                -Description "DS-Replication-Get-Changes / All on the domain object allows dumping every secret." `
                -Severity "Critical" -Status "Failed" -RiskScore 25 -AffectedCount $dcsync.Count `
                -AffectedObjects (Limit-AuditObjects $dcsync) -Evidence $dcsync `
                -Recommendation "Remove replication extended rights from anything that is not a DC or a documented backup/sync product." `
                -MitreTechnique "T1003.006" -DataSource "domain ACL"))
        } else {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-ACL-001" -Category $category -Subcategory "DCSync" `
                -Title "No extra DCSync ACEs on the domain root" `
                -Description "Replication extended rights on the domain object were limited to ignored Tier 0 identities, or none were found." `
                -Severity "Informational" -Status "Passed" -DataSource "domain ACL"))
        }

        if ($dangerous.Count -gt 0) {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-ACL-002" -Category $category -Subcategory "Domain Root" `
                -Title "Dangerous GenericAll/WriteDacl-style rights on the domain root" `
                -Description "WriteDacl, WriteOwner, or GenericAll on the domain object is effectively domain takeover." `
                -Severity "Critical" -Status "Failed" -RiskScore 25 -AffectedCount $dangerous.Count `
                -AffectedObjects (Limit-AuditObjects $dangerous) -Evidence $dangerous `
                -Recommendation "Remove unexpected owner/write-DACL ACEs from the domain object." `
                -MitreTechnique "T1484" -DataSource "domain ACL"))
        } else {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-ACL-002" -Category $category -Subcategory "Domain Root" `
                -Title "No extra dangerous ACEs on the domain root" `
                -Description "Filtered domain-root ACEs did not include GenericAll/WriteDacl/WriteOwner for non-tier-0 identities." `
                -Severity "Informational" -Status "Passed" -DataSource "domain ACL"))
        }
    }

    $holder = Search-AuditDirectory -LdapFilter "(cn=AdminSDHolder)" -SearchBase $session.DefaultNamingContext -Properties @("distinguishedName")
    if ($holder) {
        $holderDn = Get-AuditAttr $holder[0] "distinguishedName"
        $holderAces = @()
        foreach ($ace in @(Get-AuditAccessRules -DistinguishedName $holderDn)) {
            $id = [string]$ace.IdentityReference
            if (Test-AuditTier0Identity $id) { continue }
            if ("$($ace.AccessControlType)" -ne "Allow") { continue }
            $mask = 0
            try { $mask = [int]$ace.ActiveDirectoryRights } catch { }
            if (Test-AuditDangerousAccessMask $mask) { $holderAces += "$id (mask=$mask)" }
        }
        if ($holderAces.Count -gt 0) {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-ACL-003" -Category $category -Subcategory "AdminSDHolder" `
                -Title "Unexpected control on AdminSDHolder" `
                -Description "SDProp copies AdminSDHolder ACLs onto privileged objects. A write ACE here persists across SDProp cycles." `
                -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $holderAces.Count `
                -AffectedObjects $holderAces -Evidence $holderAces `
                -Recommendation "Restore the default AdminSDHolder ACL and investigate how the ACE was added." `
                -MitreTechnique "T1484" -DataSource "AdminSDHolder"))
        } else {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-ACL-003" -Category $category -Subcategory "AdminSDHolder" `
                -Title "AdminSDHolder ACL has no extra dangerous ACEs (or could not be read)" `
                -Description "No extra GenericAll/WriteDacl ACEs were parsed on AdminSDHolder." `
                -Severity "Informational" -Status "Passed" -DataSource "AdminSDHolder"))
        }
    }

    $forcePwdGuid = [guid]"00299570-66d9-11d1-9027-00c04fd7d735"
    $usersDn = "CN=Users,$($session.DefaultNamingContext)"
    $forcePwd = New-Object System.Collections.Generic.List[string]
    $usersAces = @(Get-AuditAccessRules -DistinguishedName $usersDn)
    foreach ($ace in $usersAces) {
        if ("$($ace.AccessControlType)" -ne "Allow") { continue }
        $id = [string]$ace.IdentityReference
        if (Test-AuditTier0Identity $id) { continue }
        $objGuid = $null
        try {
            if ($ace.ObjectType -and "$($ace.ObjectType)" -ne "00000000-0000-0000-0000-000000000000") {
                $objGuid = [guid]$ace.ObjectType
            }
        } catch { }
        $mask = 0
        try { $mask = [int]$ace.ActiveDirectoryRights } catch { }
        if (($objGuid -and $objGuid -eq $forcePwdGuid) -or (Test-AuditDangerousAccessMask $mask -and (Test-AuditBroadIdentity $id))) {
            [void]$forcePwd.Add("$id on CN=Users (mask=$mask, objectType=$($ace.ObjectType))")
        }
    }
    if ($usersAces.Count -eq 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-ACL-004" -Category $category -Subcategory "Users Container" `
                -Title "Users container ACL could not be read" `
                -Description "nTSecurityDescriptor was not returned for CN=Users." `
                -Severity "Low" -Status "Not Tested" -DataSource "ACL"))
    } else {
        Add-AuditCheckResult -Findings $findings -CheckId "AD-ACL-004" -Category $category -Subcategory "Users Container" `
            -FailTitle "ForceChangePassword or dangerous rights on the Users container" `
            -PassTitle "No extra ForceChangePassword / dangerous ACEs on CN=Users" `
            -FailDescription "User-Force-Change-Password or GenericAll on CN=Users lets a principal reset passwords for newly created or inherited user objects." `
            -Items @($forcePwd) -Severity "High" -RiskScore 15 `
            -Recommendation "Remove unexpected reset-password and write-DACL ACEs from CN=Users." `
            -MitreTechnique "T1098" -DataSource "CN=Users ACL"
    }

    $ouHits = New-Object System.Collections.Generic.List[string]
    $ous = @(Search-AuditDirectory -LdapFilter "(objectClass=organizationalUnit)" -SearchBase $session.DefaultNamingContext -Scope OneLevel -Properties @("distinguishedName", "name"))
    foreach ($ou in $ous) {
        $dn = Get-AuditAttr $ou "distinguishedName"
        $name = Get-AuditSam $ou
        foreach ($ace in @(Get-AuditAccessRules -DistinguishedName $dn)) {
            if ("$($ace.AccessControlType)" -ne "Allow") { continue }
            $id = [string]$ace.IdentityReference
            if (Test-AuditTier0Identity $id) { continue }
            if (-not (Test-AuditBroadIdentity $id) -and $id -notmatch "Account Operators") { continue }
            $mask = 0
            try { $mask = [int]$ace.ActiveDirectoryRights } catch { }
            if (Test-AuditDangerousAccessMask $mask) { [void]$ouHits.Add("$name : $id (mask=$mask)") }
        }
    }
    Add-AuditCheckResult -Findings $findings -CheckId "AD-ACL-005" -Category $category -Subcategory "OU Delegation" `
        -FailTitle "Broad identities have dangerous rights on top-level OUs" `
        -PassTitle "No Everyone/Authenticated Users dangerous ACEs on top-level OUs (or ACLs unreadable)" `
        -FailDescription "GenericAll/WriteDacl on an OU is control of every user and computer beneath it." `
        -Items @($ouHits) -Severity "High" -RiskScore 15 `
        -Recommendation "Replace Everyone/Authenticated Users write ACEs with explicit admin groups." `
        -MitreTechnique "T1484" -DataSource "OU ACL"

    return $findings
}

Export-ModuleMember -Function Invoke-ADAclAudit
