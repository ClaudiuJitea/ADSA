# ManagedServiceAccounts.psm1 - gMSA / sMSA inventory and password-retrieval ACLs

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-ManagedServiceAccountsAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "Managed Service Accounts"
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-GMSA-000" -Category $category))
        return $findings
    }

    $approved = @()
    if ($Config.ApprovedGmsaReaders) { $approved = @($Config.ApprovedGmsaReaders) }

    $gmsa = @(Search-AuditDirectory -LdapFilter "(objectClass=msDS-GroupManagedServiceAccount)" -Properties @(
            "sAMAccountName", "name", "distinguishedName", "servicePrincipalName", "msDS-ManagedPasswordInterval",
            "userAccountControl", "objectSid"
        ))
    $smsa = @(Search-AuditDirectory -LdapFilter "(objectClass=msDS-ManagedServiceAccount)" -Properties @(
            "sAMAccountName", "name", "distinguishedName", "servicePrincipalName", "userAccountControl"
        ))

    $inventory = New-Object System.Collections.Generic.List[string]
    foreach ($a in $gmsa) {
        $spn = @((Get-AuditAttr $a "servicePrincipalName") | Where-Object { $_ })
        $interval = Get-AuditAttr $a "msDS-ManagedPasswordInterval"
        [void]$inventory.Add("$(Get-AuditSam $a) interval=$interval SPNs=$($spn.Count)")
    }

    if ($gmsa.Count -eq 0 -and $smsa.Count -eq 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-GMSA-001" -Category $category -Subcategory "Inventory" `
                -Title "No Group or standalone Managed Service Accounts found" `
                -Description "gMSA/sMSA objects were not returned. Traditional user SPNs remain Kerberoast targets if present." `
                -Severity "Informational" -Status "Informational" -DataSource "msDS-GroupManagedServiceAccount"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-GMSA-001" -Category $category -Subcategory "Inventory" `
                -Title "Managed service account inventory (gMSA=$($gmsa.Count), sMSA=$($smsa.Count))" `
                -Description "Group Managed Service Accounts rotate a 240-character password automatically and are the preferred replacement for static service accounts." `
                -Severity "Informational" -Status "Informational" -AffectedCount $gmsa.Count `
                -AffectedObjects (Limit-AuditObjects @($inventory)) -Evidence @($inventory) -DataSource "msDS-GroupManagedServiceAccount"))
    }

    $openReaders = New-Object System.Collections.Generic.List[string]
    foreach ($a in $gmsa) {
        $dn = Get-AuditAttr $a "distinguishedName"
        $sam = Get-AuditSam $a
        foreach ($ace in @(Get-AuditAccessRules -DistinguishedName $dn)) {
            if ("$($ace.AccessControlType)" -ne "Allow") { continue }
            $id = [string]$ace.IdentityReference
            $skip = $false
            foreach ($ok in $approved) { if ($id -like "*$ok*") { $skip = $true } }
            if ($skip) { continue }
            if (Test-AuditBroadIdentity $id) {
                $mask = 0
                try { $mask = [int]$ace.ActiveDirectoryRights } catch { }
                if (($mask -band 0x00000010) -ne 0 -or (Test-AuditDangerousAccessMask $mask) -or ($mask -band 0x00020000) -ne 0) {
                    [void]$openReaders.Add("$sam readable/retrievable by $id (mask=$mask)")
                }
            }
        }
    }

    Add-AuditCheckResult -Findings $findings -CheckId "AD-GMSA-002" -Category $category -Subcategory "Password Retrieval" `
        -FailTitle "gMSA password retrieval is granted to broad identities" `
        -PassTitle "No broad gMSA password-retrieval ACEs detected (or ACLs unreadable)" `
        -FailDescription "msDS-GroupMSAMembership / object ACL lets Everyone, Authenticated Users, Domain Computers, or Anonymous retrieve the managed password. Any domain principal can then impersonate the service." `
        -PassDescription "No Everyone/Authenticated Users/Domain Computers Allow ACEs were parsed on gMSA objects, ACLs were unreadable, or no gMSAs exist." `
        -Items @($openReaders) -Severity "Critical" -RiskScore 25 `
        -Recommendation "Set PrincipalsAllowedToRetrieveManagedPassword to the specific computer or group that hosts the service. Never Domain Computers or Authenticated Users." `
        -MitreTechnique "T1558.003" -DataSource "gMSA ACL" `
        -MicrosoftReference "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview"

    $legacySmsa = @($smsa | ForEach-Object { Get-AuditSam $_ })
    Add-AuditCheckResult -Findings $findings -CheckId "AD-GMSA-003" -Category $category -Subcategory "sMSA" `
        -FailTitle "Standalone Managed Service Accounts are still in use" `
        -PassTitle "No standalone sMSA objects found" `
        -FailDescription "sMSA passwords are host-bound and do not support the same automatic multi-host rotation as gMSA. Prefer gMSA unless a single host is documented." `
        -Items $legacySmsa -Severity "Medium" -RiskScore 8 -FailStatus "Warning" `
        -Recommendation "Migrate sMSA workloads to gMSA where the service runs on more than one host or needs automatic rotation." `
        -DataSource "msDS-ManagedServiceAccount"

    return $findings
}

Export-ModuleMember -Function Invoke-ManagedServiceAccountsAudit
