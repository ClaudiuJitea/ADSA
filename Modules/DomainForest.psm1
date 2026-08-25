# DomainForest.psm1 - Domain and forest baseline (ANSSI / CIS / Microsoft aligned)

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-DomainForestAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "Domain and Forest Configuration"
    $session = Get-AuditDirectorySession
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-DF-000" -Category $category -Reason $(if ($session) { $session.Error } else { $null })))
        return $findings
    }

    $domainDn = $session.DefaultNamingContext
    $configNc = $session.ConfigurationNamingContext

    # AD-DF-001 MachineAccountQuota
    try {
        $dom = Search-AuditDirectory -LdapFilter "(objectClass=domainDNS)" -SearchBase $domainDn -Scope Base -Properties @("distinguishedName", "ms-DS-MachineAccountQuota", "name")
        $maq = 0
        if ($dom) { $maq = [int](Get-AuditAttr $dom[0] "ms-DS-MachineAccountQuota") }
        if ($maq -gt 0) {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-DF-001" -Category $category -Subcategory "Baseline Security" `
                -Title "MachineAccountQuota is $maq (non-admins can join computers)" `
                -Description "ms-DS-MachineAccountQuota is $maq. Any authenticated user can join that many computers and then abuse RBCD or Kerberos relay." `
                -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount 1 `
                -AffectedObjects @($domainDn) -Evidence @("ms-DS-MachineAccountQuota = $maq") `
                -Recommendation "Set ms-DS-MachineAccountQuota to 0 on the domain object." `
                -MicrosoftReference "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/active-directory-machineaccountquota" `
                -MitreTechnique "T1078.002" -DataSource "domainDNS"))
        } else {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-DF-001" -Category $category -Subcategory "Baseline Security" `
                -Title "MachineAccountQuota is 0" `
                -Description "Standard users cannot join computers to the domain." `
                -Severity "Informational" -Status "Passed" -DataSource "domainDNS"))
        }
    } catch {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DF-001" -Category $category -Title "MachineAccountQuota check failed" -Description $_.Exception.Message -Severity "Medium" -Status "Error"))
    }

    # AD-DF-002 Recycle Bin
    try {
        $features = Search-AuditDirectory -LdapFilter "(objectClass=msDS-OptionalFeature)" -SearchBase $configNc -Properties @("name", "msDS-EnabledFeatureBL")
        $recycle = $features | Where-Object { (Get-AuditAttr $_ "name") -like "*Recycle Bin*" }
        $enabled = $false
        if ($recycle) {
            $bl = Get-AuditAttr $recycle[0] "msDS-EnabledFeatureBL"
            $enabled = [bool]$bl
        }
        if (-not $enabled) {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-DF-002" -Category $category -Subcategory "Recoverability" `
                -Title "Active Directory Recycle Bin is not enabled" `
                -Description "Deleted objects cannot be restored with original SID, group membership, and attributes without tombstone reanimation." `
                -Severity "Medium" -Status "Failed" -RiskScore 8 -AffectedCount 1 `
                -AffectedObjects @($session.Domain) -Evidence @("msDS-OptionalFeature Recycle Bin is not enabled") `
                -Recommendation "Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet." `
                -MicrosoftReference "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/active-directory-recycle-bin-step-by-step" `
                -DataSource "msDS-OptionalFeature"))
        } else {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-DF-002" -Category $category -Subcategory "Recoverability" `
                -Title "Active Directory Recycle Bin is enabled" `
                -Description "The forest Recycle Bin optional feature is enabled." `
                -Severity "Informational" -Status "Passed" -DataSource "msDS-OptionalFeature"))
        }
    } catch {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DF-002" -Category $category -Title "Recycle Bin check failed" -Description $_.Exception.Message -Severity "Low" -Status "Error"))
    }

    # AD-DF-003 Functional levels
    $dfl = Get-AuditFunctionalLevelName $session.DomainFunctionality
    $ffl = Get-AuditFunctionalLevelName $session.ForestFunctionality
    $legacy = @("Windows 2000", "Windows Server 2003", "Windows Server 2003 interim", "Windows Server 2008", "Windows Server 2008 R2", "Windows Server 2012", "Windows Server 2012 R2")
    if ($legacy -contains $dfl -or $legacy -contains $ffl) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DF-003" -Category $category -Subcategory "Functional Level" `
            -Title "Legacy domain or forest functional level ($dfl / $ffl)" `
            -Description "Domain functional level is $dfl and forest functional level is $ffl. Levels below 2016 block Protected Users, Authentication Policy Silos, and modern Kerberos hardening." `
            -Severity "Medium" -Status "Failed" -RiskScore 8 -AffectedCount 1 `
            -AffectedObjects @("Domain=$dfl", "Forest=$ffl") -Evidence @("domainFunctionality=$($session.DomainFunctionality)", "forestFunctionality=$($session.ForestFunctionality)") `
            -Recommendation "Raise domain and forest functional levels to Windows Server 2016 or later after removing legacy DCs." `
            -DataSource "RootDSE"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DF-003" -Category $category -Subcategory "Functional Level" `
            -Title "Functional levels are current ($dfl / $ffl)" `
            -Description "Domain functional level is $dfl; forest functional level is $ffl." `
            -Severity "Informational" -Status "Passed" -DataSource "RootDSE"))
    }

    # AD-DF-004 Tombstone lifetime
    try {
        $ds = Search-AuditDirectory -LdapFilter "(cn=Directory Service)" -SearchBase "CN=Windows NT,CN=Services,$configNc" -Properties @("tombstoneLifetime", "dsHeuristics")
        $lifetime = 60
        $heur = ""
        if ($ds) {
            $raw = Get-AuditAttr $ds[0] "tombstoneLifetime"
            if ($raw) { $lifetime = [int]$raw }
            $heur = [string](Get-AuditAttr $ds[0] "dsHeuristics")
        }
        if ($lifetime -lt 180) {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-DF-004" -Category $category -Subcategory "Recoverability" `
                -Title "Tombstone lifetime is $lifetime days (below 180)" `
                -Description "A short tombstone lifetime increases lingering-object risk and shortens backup usefulness. Microsoft recommends at least 180 days for modern forests." `
                -Severity "Medium" -Status "Failed" -RiskScore 8 -AffectedCount 1 `
                -AffectedObjects @("tombstoneLifetime=$lifetime") -Evidence @("tombstoneLifetime=$lifetime") `
                -Recommendation "Set tombstoneLifetime to 180 or more on CN=Directory Service,CN=Windows NT,CN=Services,Configuration." `
                -MicrosoftReference "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/determine-tombstone-lifetime" `
                -DataSource "nTDSService"))
        } else {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-DF-004" -Category $category -Subcategory "Recoverability" `
                -Title "Tombstone lifetime is $lifetime days" `
                -Description "Tombstone lifetime meets the 180-day baseline." `
                -Severity "Informational" -Status "Passed" -DataSource "nTDSService"))
        }

        # AD-DF-005 dsHeuristics anonymous
        $anon = $false
        if ($heur.Length -ge 7) {
            $ch = $heur.Substring(6, 1)
            if ($ch -eq "2" -or $ch -eq "1") { $anon = $true }
        }
        if ($anon) {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-DF-005" -Category $category -Subcategory "Anonymous Access" `
                -Title "dsHeuristics allows anonymous SAM/LDAP enumeration" `
                -Description "dsHeuristics is '$heur'. Character 7 is set in a way that can permit anonymous listing of users, groups, and other objects." `
                -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount 1 `
                -AffectedObjects @("dsHeuristics=$heur") -Evidence @("dsHeuristics=$heur") `
                -Recommendation "Clear anonymous-related dsHeuristics flags (7th character should not enable anonymous operations)." `
                -MicrosoftReference "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5899be8-949a-4c49-ae11-2b44c0b18a1e" `
                -MitreTechnique "T1087.002" -DataSource "dsHeuristics"))
        } else {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-DF-005" -Category $category -Subcategory "Anonymous Access" `
                -Title "dsHeuristics does not enable anonymous enumeration" `
                -Description "dsHeuristics is '$heur'." `
                -Severity "Informational" -Status "Passed" -Evidence @("dsHeuristics=$heur") -DataSource "dsHeuristics"))
        }
    } catch {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DF-004" -Category $category -Title "Directory Service object check failed" -Description $_.Exception.Message -Severity "Low" -Status "Error"))
    }

    # AD-DF-006 Guest enabled
    try {
        $guest = Search-AuditDirectory -LdapFilter "(&(objectClass=user)(sAMAccountName=Guest))" -Properties @("sAMAccountName", "userAccountControl", "distinguishedName")
        if ($guest) {
            $uac = Get-AuditAttr $guest[0] "userAccountControl"
            $disabled = Test-AuditUacFlag $uac 0x0002
            if (-not $disabled) {
                [void]$findings.Add((New-AuditFinding -CheckId "AD-DF-006" -Category $category -Subcategory "Built-in Accounts" `
                    -Title "Guest account is enabled" `
                    -Description "The built-in Guest account is enabled. It is a well-known RID-501 identity and a common password-spray and anonymous-access foothold." `
                    -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount 1 `
                    -AffectedObjects @("Guest") -Evidence @("userAccountControl=$uac") `
                    -Recommendation "Disable Guest and ensure it is not a member of privileged groups." `
                    -MitreTechnique "T1078.001" -DataSource "user"))
            } else {
                [void]$findings.Add((New-AuditFinding -CheckId "AD-DF-006" -Category $category -Subcategory "Built-in Accounts" `
                    -Title "Guest account is disabled" `
                    -Description "The built-in Guest account is disabled." `
                    -Severity "Informational" -Status "Passed" -DataSource "user"))
            }
        }
    } catch { }

    $silos = @(Search-AuditDirectory -LdapFilter "(objectClass=msDS-AuthNPolicySilo)" -SearchBase $configNc -Properties @("name", "cn"))
    if ($silos.Count -eq 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DF-007" -Category $category -Subcategory "Authentication Silos" `
                -Title "No Authentication Policy Silos are defined" `
                -Description "Authentication Policy Silos (DFL 2012 R2+) restrict where privileged accounts can authenticate. Their absence is common and leaves DA credentials usable from any workstation." `
                -Severity "Medium" -Status "Warning" -RiskScore 8 `
                -Recommendation "Create silos for Domain Admins / DC computer accounts so admin TGT issuance is limited to PAWs and DCs." `
                -MicrosoftReference "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos" `
                -MitreTechnique "T1078.002" -DataSource "msDS-AuthNPolicySilo"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DF-007" -Category $category -Subcategory "Authentication Silos" `
                -Title "Authentication Policy Silos are present ($($silos.Count))" `
                -Description "Silos exist. Confirm they actually include Domain Admins and DC computer accounts." `
                -Severity "Informational" -Status "Passed" -AffectedObjects @($silos | ForEach-Object { Get-AuditSam $_ }) -DataSource "msDS-AuthNPolicySilo"))
    }

    return $findings
}

Export-ModuleMember -Function Invoke-DomainForestAudit
