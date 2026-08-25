# LdapNtlm.psm1 - Anonymous bind, dsHeuristics, optional DC registry signing

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-LdapNtlmAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [bool]$SkipRemoteChecks = $false,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "LDAP and NTLM Security"
    $session = Get-AuditDirectorySession
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-LDAP-000" -Category $category))
        return $findings
    }

    $anonEnum = $false
    try { $anonEnum = Test-AuditAnonymousUserEnumeration } catch { $anonEnum = $false }
    if ($anonEnum) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-LDAP-002" -Category $category -Subcategory "Anonymous LDAP" `
            -Title "Anonymous LDAP user enumeration succeeded" `
            -Description "An unauthenticated LDAP search returned user objects. This enables reconnaissance without credentials." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount 1 `
            -AffectedObjects @($session.Server) -Evidence @("Anonymous SearchRequest for objectClass=user returned entries") `
            -Recommendation "Disable anonymous binds and anonymous SAM enumeration (RestrictAnonymous / dsHeuristics / LDAP policies)." `
            -MitreTechnique "T1087.002" -DataSource "Anonymous LDAP"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-LDAP-002" -Category $category -Subcategory "Anonymous LDAP" `
            -Title "Anonymous LDAP user enumeration did not succeed" `
            -Description "An anonymous bind/search for user objects failed or returned no entries." `
            -Severity "Informational" -Status "Passed" -DataSource "Anonymous LDAP"))
    }

    if ($SkipRemoteChecks) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-LDAP-001" -Category $category -Subcategory "LDAP Signing" `
            -Title "LDAP signing registry check skipped" `
            -Description "Remote Registry was skipped (-SkipRemoteChecks). Use a DC GPO report or registry audit for LDAPServerIntegrity=2 and LdapEnforceChannelBinding=2." `
            -Severity "Informational" -Status "Not Tested" -DataSource "Skipped"))
        return $findings
    }

    $dc = $session.DnsHostName
    if (-not $dc) { $dc = $session.Server }
    try {
        $regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $dc)
        $ldapKey = $regKey.OpenSubKey("SYSTEM\CurrentControlSet\Services\NTDS\Parameters")
        $signing = if ($ldapKey) { $ldapKey.GetValue("LDAPServerIntegrity") } else { $null }
        $cbt = if ($ldapKey) { $ldapKey.GetValue("LdapEnforceChannelBinding") } else { $null }
        if ($null -eq $signing -or [int]$signing -lt 2) {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-LDAP-001" -Category $category -Subcategory "LDAP Signing" `
                -Title "LDAP signing is not required on $dc" `
                -Description "LDAPServerIntegrity=$signing (2 = require signing). Unsigned LDAP is relayable." `
                -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount 1 `
                -AffectedObjects @("$dc LDAPServerIntegrity=$signing") -Evidence @("LDAPServerIntegrity=$signing", "LdapEnforceChannelBinding=$cbt") `
                -Recommendation "Set 'Domain controller: LDAP server signing requirements' to Require signing and enable channel binding (LdapEnforceChannelBinding=2)." `
                -MicrosoftReference "https://support.microsoft.com/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-efb872ef-554a-29af-56f5-d54c8440e94e" `
                -MitreTechnique "T1557" -RequiredPermission "Remote Registry" -DataSource "Remote Registry"))
        } else {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-LDAP-001" -Category $category -Subcategory "LDAP Signing" `
                -Title "LDAP signing is required on $dc" `
                -Description "LDAPServerIntegrity=$signing, LdapEnforceChannelBinding=$cbt." `
                -Severity "Informational" -Status "Passed" -Evidence @("LDAPServerIntegrity=$signing", "LdapEnforceChannelBinding=$cbt") -DataSource "Remote Registry"))
        }
        if ($null -eq $cbt -or [int]$cbt -lt 2) {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-LDAP-003" -Category $category -Subcategory "Channel Binding" `
                -Title "LDAP channel binding is not enforced on $dc" `
                -Description "LdapEnforceChannelBinding=$cbt (2 = always). Channel binding mitigates LDAP relay even when signing is negotiated inconsistently." `
                -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount 1 `
                -AffectedObjects @("$dc LdapEnforceChannelBinding=$cbt") `
                -Recommendation "Set LdapEnforceChannelBinding=2 via GPO after testing LDAPS clients." `
                -MitreTechnique "T1557" -RequiredPermission "Remote Registry" -DataSource "Remote Registry"))
        } else {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-LDAP-003" -Category $category -Subcategory "Channel Binding" `
                -Title "LDAP channel binding is enforced" `
                -Description "LdapEnforceChannelBinding=$cbt." `
                -Severity "Informational" -Status "Passed" -DataSource "Remote Registry"))
        }
    } catch {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-LDAP-001" -Category $category -Subcategory "LDAP Signing" `
            -Title "LDAP signing registry was not readable" `
            -Description "Remote Registry on $dc failed: $($_.Exception.Message). Linux auditors should rely on GPO/LDAP policy evidence or skip this check." `
            -Severity "Low" -Status "Not Tested" -RequiredPermission "Remote Registry" -DataSource "Remote Registry"))
    }

    return $findings
}

Export-ModuleMember -Function Invoke-LdapNtlmAudit
