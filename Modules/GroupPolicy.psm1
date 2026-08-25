# GroupPolicy.psm1 - GPC inventory, unlinked GPOs, GPP cpassword

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-GroupPolicyAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "Group Policy Security"
    $session = Get-AuditDirectorySession
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-GPO-000" -Category $category))
        return $findings
    }

    $gpos = @(Search-AuditDirectory -LdapFilter "(objectClass=groupPolicyContainer)" -SearchBase $session.DefaultNamingContext -Properties @("displayName", "cn", "gPCFileSysPath", "flags", "name", "distinguishedName", "versionNumber", "whenCreated", "whenChanged"))
    $linkedGuids = New-Object System.Collections.Generic.HashSet[string]
    $linkSources = @(Search-AuditDirectory -LdapFilter "(gpLink=*)" -SearchBase $session.DefaultNamingContext -Properties @("gpLink", "distinguishedName"))
    foreach ($src in $linkSources) {
        $link = [string](Get-AuditAttr $src "gpLink")
        [regex]::Matches($link, "cn=(\{[^}]+\})") | ForEach-Object { [void]$linkedGuids.Add($_.Groups[1].Value.ToUpperInvariant()) }
        [regex]::Matches($link, "(\{[0-9A-Fa-f-]+\})") | ForEach-Object { [void]$linkedGuids.Add($_.Groups[1].Value.ToUpperInvariant()) }
    }

    $unlinked = @()
    foreach ($gpo in $gpos) {
        $cn = [string](Get-AuditAttr $gpo "cn")
        $disp = Get-AuditAttr $gpo "displayName"
        if (-not $disp) { $disp = $cn }
        if ($cn -and -not $linkedGuids.Contains($cn.ToUpperInvariant())) {
            $unlinked += "$disp ($cn)"
        }
    }

    $cpasswordHits = @()
    $plaintextHits = @()
    $dnsRoot = $session.Domain
    if (-not $dnsRoot -and $session.DefaultNamingContext) {
        $dnsRoot = ($session.DefaultNamingContext -replace "DC=", "" -replace ",", ".")
    }
    $sysvol = "\\$dnsRoot\SYSVOL\$dnsRoot\Policies"
    $sysvolReachable = Test-Path $sysvol
    if ($sysvolReachable) {
        $credentialPatterns = @(
            @{ Label = "cpassword attribute"; Pattern = 'cpassword\s*=' },
            @{ Label = "password assignment"; Pattern = '(?i)(password|passwd|pwd)\s*[:=]\s*\S{4,}' },
            @{ Label = "net use with credentials"; Pattern = '(?i)net\s+use\b[^\r\n]*\/user:' },
            @{ Label = "plaintext PowerShell credential"; Pattern = '(?i)convertto-securestring[^\r\n]*-asplaintext' }
        )
        try {
            Get-ChildItem -Path $sysvol -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -match '^\.(xml|bat|cmd|ps1|psm1|vbs|js|kix|ini|reg|txt|config)$' } |
                ForEach-Object {
                    $content = Get-Content -Path $_.FullName -Raw -ErrorAction SilentlyContinue
                    if (-not $content) { return }
                    if ($content -match 'cpassword\s*=') {
                        $cpasswordHits += $_.FullName
                        return
                    }
                    foreach ($candidate in $credentialPatterns) {
                        if ($content -match $candidate.Pattern) {
                            $plaintextHits += "$($_.FullName) ($($candidate.Label))"
                            break
                        }
                    }
                }
        } catch { }
    }

    if ($cpasswordHits.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-GPO-001" -Category $category -Subcategory "GPP Credentials" `
            -Title "GPP cpassword found in SYSVOL" `
            -Description "Microsoft published the AES key for Group Policy Preferences passwords. These XML files are readable by any authenticated user." `
            -Severity "Critical" -Status "Failed" -RiskScore 25 -AffectedCount $cpasswordHits.Count `
            -AffectedObjects (Limit-AuditObjects $cpasswordHits) -Evidence $cpasswordHits `
            -Recommendation "Delete the XML files, apply MS14-025, and rotate every password that was stored." `
            -MicrosoftReference "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025" `
            -MitreTechnique "T1552.006" -RequiredPermission "SYSVOL read" -DataSource "SYSVOL"))
    } else {
        $status = if ($sysvolReachable) { "Passed" } else { "Not Tested" }
        $desc = if ($sysvolReachable) { "No cpassword attributes were found in SYSVOL policy files." } else { "SYSVOL path $sysvol was not reachable from this host, so policy file contents were not inspected." }
        [void]$findings.Add((New-AuditFinding -CheckId "AD-GPO-001" -Category $category -Subcategory "GPP Credentials" `
            -Title $(if ($status -eq "Passed") { "No GPP cpassword in SYSVOL" } else { "SYSVOL cpassword scan not performed" }) `
            -Description $desc -Severity $(if ($status -eq "Passed") { "Informational" } else { "Low" }) -Status $status -DataSource "SYSVOL"))
    }

    if ($unlinked.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-GPO-003" -Category $category -Subcategory "Hygiene" `
            -Title "Unlinked Group Policy Objects" `
            -Description "Found $($unlinked.Count) GPC object(s) not referenced by any gpLink. They can still be re-linked with stale settings." `
            -Severity "Medium" -Status "Warning" -RiskScore 8 -AffectedCount $unlinked.Count `
            -AffectedObjects (Limit-AuditObjects $unlinked) -Evidence $unlinked `
            -Recommendation "Delete unused GPOs after change control." -DataSource "groupPolicyContainer / gpLink"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-GPO-003" -Category $category -Subcategory "Hygiene" `
            -Title "All discovered GPOs appear linked" `
            -Description "Every groupPolicyContainer CN was referenced in a gpLink, or no GPOs exist." `
            -Severity "Informational" -Status "Passed" -DataSource "gpLink"))
    }

    $writable = New-Object System.Collections.Generic.List[string]
    $gpoOwners = New-Object System.Collections.Generic.List[string]
    $brokenGpos = New-Object System.Collections.Generic.List[string]
    foreach ($gpo in $gpos) {
        $dn = Get-AuditAttr $gpo "distinguishedName"
        if (-not $dn) { continue }
        $disp = Get-AuditAttr $gpo "displayName"
        if (-not $disp) { $disp = Get-AuditAttr $gpo "cn" }

        $filePath = [string](Get-AuditAttr $gpo "gPCFileSysPath")
        $version = 0
        try { $version = [int](Get-AuditAttr $gpo "versionNumber") } catch { }
        if ([string]::IsNullOrWhiteSpace($filePath)) {
            [void]$brokenGpos.Add("$disp has no gPCFileSysPath (directory object without a SYSVOL folder)")
        } elseif ($version -eq 0) {
            [void]$brokenGpos.Add("$disp has versionNumber 0 (no settings have ever been applied)")
        }

        $sd = Get-AuditSecurityDescriptor -DistinguishedName $dn
        if ($sd.Owner -and -not (Test-AuditTier0Identity $sd.Owner)) {
            [void]$gpoOwners.Add("GPO '$disp' is owned by $($sd.Owner)")
        }
        foreach ($ace in @($sd.Access)) {
            if ("$($ace.AccessControlType)" -ne "Allow") { continue }
            $id = [string]$ace.IdentityReference
            if (Test-AuditTier0Identity $id) { continue }
            $mask = 0
            try { $mask = [int]$ace.ActiveDirectoryRights } catch { }
            $gpoWrite = 0x10000000 -bor 0x00040000 -bor 0x00080000 -bor 0x40000000
            if (($mask -band $gpoWrite) -ne 0) {
                [void]$writable.Add("$disp writable by $id ($(Get-AuditAceRightNames $mask))")
            }
        }
    }
    Add-AuditCheckResult -Findings $findings -CheckId "AD-GPO-002" -Category $category -Subcategory "GPO ACL" `
        -FailTitle "Unprivileged principals can modify Group Policy Objects" `
        -PassTitle "No extra dangerous GPO write ACEs detected (or ACLs unreadable)" `
        -FailDescription "Edit/Modify on a GPO is domain-wide code execution when that GPO is linked to users, computers, or Domain Controllers." `
        -Items @($writable) -Severity "High" -RiskScore 15 `
        -Recommendation "Restrict GPO edit rights to Domain Admins or a dedicated, monitored GPO admin group." `
        -MitreTechnique "T1484.001" -DataSource "groupPolicyContainer ACL"

    Add-AuditCheckResult -Findings $findings -CheckId "AD-GPO-005" -Category $category -Subcategory "GPO Ownership" `
        -FailTitle "Group Policy Objects are owned by non-Tier 0 principals" `
        -PassTitle "All readable GPOs are owned by Tier 0 principals" `
        -FailDescription "A GPO owner holds implicit WriteDacl and can therefore edit the policy regardless of the delegation shown in the Group Policy console. Ownership usually stays with whoever created the GPO." `
        -PassDescription "Owners of the evaluated GPOs resolved to Tier 0 principals." `
        -Items @($gpoOwners) -Severity "High" -RiskScore 15 `
        -Recommendation "Reassign GPO ownership to Domain Admins and use delegation for day-to-day editing." `
        -MitreTechnique "T1484.001" -DataSource "groupPolicyContainer owner"

    if ($sysvolReachable) {
        Add-AuditCheckResult -Findings $findings -CheckId "AD-GPO-006" -Category $category -Subcategory "SYSVOL Secrets" `
            -FailTitle "Policy files in SYSVOL contain credential-like content" `
            -PassTitle "No credential patterns found in SYSVOL policy files" `
            -FailDescription "Every authenticated user can read SYSVOL. Logon scripts and policy files that embed passwords, mapped-drive credentials, or plaintext PowerShell secrets hand those credentials to the whole domain." `
            -PassDescription "Scanned SYSVOL policy and script files matched no credential patterns." `
            -Items @($plaintextHits) -Severity "High" -RiskScore 15 `
            -Recommendation "Move the secret out of SYSVOL (gMSA, scheduled task with a managed identity, or a secret store), then rotate it." `
            -MitreTechnique "T1552.001" -DataSource "SYSVOL"
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-GPO-006" -Category $category -Subcategory "SYSVOL Secrets" `
                -Title "SYSVOL credential scan not performed" `
                -Description "SYSVOL was not reachable over SMB from this host, so logon scripts and policy files were not inspected for embedded credentials." `
                -Severity "Low" -Status "Not Tested" -RequiredPermission "SYSVOL read" `
                -Recommendation "Re-run from a host that can reach \\$dnsRoot\SYSVOL to complete this check." -DataSource "SYSVOL"))
    }

    Add-AuditCheckResult -Findings $findings -CheckId "AD-GPO-007" -Category $category -Subcategory "Hygiene" `
        -FailTitle "Group Policy Objects are broken or never applied" `
        -PassTitle "No broken or empty GPOs detected" `
        -FailDescription "A GPO without a SYSVOL path, or with version 0, cannot apply settings. It indicates failed replication or abandoned change work, and it hides the real policy state from administrators." `
        -PassDescription "Every GPO had a SYSVOL path and a non-zero version." `
        -Items @($brokenGpos) -Severity "Low" -RiskScore 3 -FailStatus "Warning" `
        -Recommendation "Delete abandoned GPOs, or repair SYSVOL replication so the policy folder exists on every Domain Controller." `
        -DataSource "groupPolicyContainer"

    [void]$findings.Add((New-AuditFinding -CheckId "AD-GPO-004" -Category $category -Subcategory "Inventory" `
        -Title "Group Policy inventory ($($gpos.Count) objects)" `
        -Description "Enumerated $($gpos.Count) groupPolicyContainer object(s) and $($linkSources.Count) gpLink source(s)." `
        -Severity "Informational" -Status "Informational" -AffectedCount $gpos.Count -DataSource "groupPolicyContainer"))

    return $findings
}

Export-ModuleMember -Function Invoke-GroupPolicyAudit
