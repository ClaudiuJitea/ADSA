# Delegation.psm1 - Unconstrained, protocol transition, RBCD, sensitive bit

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-DelegationAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "Delegation"
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-DEL-000" -Category $category))
        return $findings
    }

    $objects = @(Search-AuditDirectory -LdapFilter "(|(objectClass=user)(objectClass=computer))" -Properties @(
            "sAMAccountName", "name", "userAccountControl", "primaryGroupID", "msDS-AllowedToDelegateTo",
            "msDS-AllowedToActOnBehalfOfOtherIdentity", "objectClass"
        ))

    $unconstrained = @()
    $protocolTransition = @()
    $rbcd = @()
    foreach ($o in $objects) {
        $sam = Get-AuditSam $o
        $uac = Get-AuditAttr $o "userAccountControl"
        $pg = Get-AuditAttr $o "primaryGroupID"
        $isDc = ($pg -eq 516) -or (Test-AuditUacFlag $uac 8192)
        if ((Test-AuditUacFlag $uac 0x80000) -and -not $isDc) { $unconstrained += $sam }
        if (Test-AuditUacFlag $uac 0x1000000) { $protocolTransition += $sam }
        $rb = Get-AuditAttr $o "msDS-AllowedToActOnBehalfOfOtherIdentity"
        if ($rb) {
            $trustees = @(Get-AuditSecurityDescriptorTrustees $rb)
            if ($trustees.Count -gt 0) {
                $rbcd += "$sam can be impersonated to by: $($trustees -join ', ')"
            } else {
                $rbcd += "$sam (trustee list unreadable)"
            }
        }
    }

    if ($unconstrained.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DEL-001" -Category $category -Subcategory "Unconstrained Delegation" `
            -Title "Unconstrained Kerberos delegation on non-DC objects" `
            -Description "TRUSTED_FOR_DELEGATION on member servers or users lets that host cache TGTs, including Domain Admins who authenticate to it." `
            -Severity "Critical" -Status "Failed" -RiskScore 25 -AffectedCount $unconstrained.Count `
            -AffectedObjects (Limit-AuditObjects $unconstrained) -Evidence $unconstrained `
            -Recommendation "Remove unconstrained delegation. Use constrained delegation or RBCD with a tight service list." `
            -MicrosoftReference "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/trusted-for-delegation-explanation" `
            -MitreTechnique "T1558" -DataSource "userAccountControl"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DEL-001" -Category $category -Subcategory "Unconstrained Delegation" `
            -Title "No non-DC unconstrained delegation" `
            -Description "TRUSTED_FOR_DELEGATION was only seen on DC-like objects, or not at all." `
            -Severity "Informational" -Status "Passed" -DataSource "userAccountControl"))
    }

    if ($protocolTransition.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DEL-002" -Category $category -Subcategory "Protocol Transition" `
            -Title "Constrained delegation with protocol transition (S4U2Self)" `
            -Description "TRUSTED_TO_AUTH_FOR_DELEGATION allows the account to obtain tickets for users without their credentials (protocol transition)." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $protocolTransition.Count `
            -AffectedObjects (Limit-AuditObjects $protocolTransition) -Evidence $protocolTransition `
            -Recommendation "Disable 'Use any authentication protocol' unless a documented application requires S4U2Self." `
            -MitreTechnique "T1558" -DataSource "userAccountControl"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DEL-002" -Category $category -Subcategory "Protocol Transition" `
            -Title "No protocol-transition delegation flags" `
            -Description "No objects had TRUSTED_TO_AUTH_FOR_DELEGATION." `
            -Severity "Informational" -Status "Passed" -DataSource "userAccountControl"))
    }

    $unprotected = @()
    foreach ($gName in @("Domain Admins", "Enterprise Admins", "Administrators")) {
        $g = Find-AuditGroup -Name $gName
        if (-not $g) { continue }
        foreach ($m in @(Get-AuditGroupMembers -GroupDn (Get-AuditAttr $g "distinguishedName") -Recursive)) {
            $uac = Get-AuditAttr $m "userAccountControl"
            if (-not (Test-AuditUacFlag $uac 0x100000) -and -not (Test-AuditUacFlag $uac 0x0002)) {
                $unprotected += "$(Get-AuditSam $m) ($gName)"
            }
        }
    }
    if ($unprotected.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DEL-003" -Category $category -Subcategory "Delegation Protection" `
            -Title "Privileged accounts can be delegated" `
            -Description "Missing 'Account is sensitive and cannot be delegated' (NOT_DELEGATED) means a TGT can be forwarded to an unconstrained/constrained host." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $unprotected.Count `
            -AffectedObjects (Limit-AuditObjects $unprotected) -Evidence $unprotected `
            -Recommendation "Set NOT_DELEGATED and add admins to Protected Users." `
            -MitreTechnique "T1078" -DataSource "userAccountControl"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DEL-003" -Category $category -Subcategory "Delegation Protection" `
            -Title "Privileged accounts are marked sensitive / not delegated" `
            -Description "Evaluated admin group members have NOT_DELEGATED, are disabled, or did not resolve." `
            -Severity "Informational" -Status "Passed" -DataSource "userAccountControl"))
    }

    if ($rbcd.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DEL-004" -Category $category -Subcategory "RBCD" `
            -Title "Resource-based constrained delegation is configured" `
            -Description "msDS-AllowedToActOnBehalfOfOtherIdentity lets the listed principals impersonate users to this resource. Attackers who can write this attribute on a computer take over that host." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $rbcd.Count `
            -AffectedObjects (Limit-AuditObjects $rbcd) -Evidence $rbcd `
            -Recommendation "Inventory RBCD entries, remove unexpected ones, and lock down who can write msDS-AllowedToActOnBehalfOfOtherIdentity." `
            -MitreTechnique "T1558" -DataSource "msDS-AllowedToActOnBehalfOfOtherIdentity"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DEL-004" -Category $category -Subcategory "RBCD" `
            -Title "No RBCD attributes populated" `
            -Description "No user or computer had msDS-AllowedToActOnBehalfOfOtherIdentity set." `
            -Severity "Informational" -Status "Passed" -DataSource "msDS-AllowedToActOnBehalfOfOtherIdentity"))
    }

    $dcNames = New-Object System.Collections.Generic.List[string]
    $dcs = @(Search-AuditDirectory -LdapFilter "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -Properties @("dNSHostName", "name", "sAMAccountName"))
    foreach ($dc in $dcs) {
        $hostName = [string](Get-AuditAttr $dc "dNSHostName")
        if (-not $hostName) { $hostName = [string](Get-AuditAttr $dc "name") }
        if ($hostName) { [void]$dcNames.Add($hostName.ToLowerInvariant()) }
        $sam = [string](Get-AuditSam $dc)
        if ($sam) { [void]$dcNames.Add($sam.TrimEnd('$').ToLowerInvariant()) }
    }
    $kcdToDc = New-Object System.Collections.Generic.List[string]
    foreach ($o in $objects) {
        $targets = @((Get-AuditAttr $o "msDS-AllowedToDelegateTo") | Where-Object { $_ })
        if ($targets.Count -eq 0) { continue }
        $sam = Get-AuditSam $o
        foreach ($t in $targets) {
            $tl = [string]$t
            $isDcSpn = $false
            if ($tl -match '^(ldap|cifs|host|krbtgt|GC)/') {
                foreach ($dcn in $dcNames) {
                    if ($dcn -and $tl.ToLowerInvariant() -like "*$dcn*") { $isDcSpn = $true; break }
                }
                if ($tl -match '^krbtgt/') { $isDcSpn = $true }
            }
            if ($isDcSpn) { [void]$kcdToDc.Add("$sam => $tl") }
        }
    }
    Add-AuditCheckResult -Findings $findings -CheckId "AD-DEL-005" -Category $category -Subcategory "Constrained Delegation" `
        -FailTitle "Constrained delegation targets Domain Controller services" `
        -PassTitle "No constrained delegation to DC LDAP/CIFS/HOST/krbtgt" `
        -FailDescription "msDS-AllowedToDelegateTo pointing at ldap/cifs/host on a DC (or krbtgt) is a known path to domain compromise via S4U." `
        -Items @($kcdToDc) -Severity "Critical" -RiskScore 25 `
        -Recommendation "Remove KCD to Domain Controller services. Applications should not impersonate users to LDAP on a DC." `
        -MitreTechnique "T1558" -DataSource "msDS-AllowedToDelegateTo"

    return $findings
}

Export-ModuleMember -Function Invoke-DelegationAudit
