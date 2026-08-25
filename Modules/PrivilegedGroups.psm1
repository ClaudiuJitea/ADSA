# PrivilegedGroups.psm1 - Tier 0 and high-risk built-in groups

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-PrivilegedGroupsAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [int]$InactiveDays = 90,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "Privileged Groups"
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-GRP-000" -Category $category))
        return $findings
    }

    $maxDa = 5
    if ($Config.MaxDomainAdmins) { $maxDa = [int]$Config.MaxDomainAdmins }
    $inactiveThreshold = (Get-Date).AddDays(-$InactiveDays)
    $tier0 = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Server Operators", "Backup Operators", "Print Operators", "DnsAdmins", "Group Policy Creator Owners", "Key Admins", "Enterprise Key Admins")

    $printOps = New-Object System.Collections.Generic.List[string]
    $backupOps = New-Object System.Collections.Generic.List[string]
    $serverOps = New-Object System.Collections.Generic.List[string]
    $computerMembers = New-Object System.Collections.Generic.List[string]
    $protectedUsers = New-Object System.Collections.Generic.List[string]
    $daSam = New-Object System.Collections.Generic.List[string]
    $stale = New-Object System.Collections.Generic.List[string]
    $spnPriv = New-Object System.Collections.Generic.List[string]
    $fsp = New-Object System.Collections.Generic.List[string]
    $daMembers = New-Object System.Collections.Generic.List[string]
    $schemaMembers = New-Object System.Collections.Generic.List[string]
    $accountOps = New-Object System.Collections.Generic.List[string]

    foreach ($groupName in $tier0 + @("Protected Users", "Remote Desktop Users")) {
        $group = Find-AuditGroup -Name $groupName
        if (-not $group) { continue }
        $dn = Get-AuditAttr $group "distinguishedName"
        $members = @(Get-AuditGroupMembers -GroupDn $dn -Recursive)
        foreach ($m in $members) {
            $sam = Get-AuditSam $m
            $className = Get-AuditMostSpecificClass $m
            if ($groupName -eq "Domain Admins") { [void]$daMembers.Add($sam); [void]$daSam.Add($sam) }
            if ($groupName -eq "Schema Admins" -and $sam -ne "Administrator") { [void]$schemaMembers.Add($sam) }
            if ($groupName -eq "Account Operators") { [void]$accountOps.Add($sam) }
            if ($groupName -eq "Print Operators") { [void]$printOps.Add($sam) }
            if ($groupName -eq "Backup Operators") { [void]$backupOps.Add($sam) }
            if ($groupName -eq "Server Operators") { [void]$serverOps.Add($sam) }
            if ($groupName -eq "Protected Users") { [void]$protectedUsers.Add($sam) }
            if ($groupName -eq "Remote Desktop Users") { continue }

            if ($className -match "computer") {
                [void]$computerMembers.Add("$sam in '$groupName'")
            }
            if ($className -eq "foreignSecurityPrincipal" -or $sam -match "^S-1-") {
                [void]$fsp.Add("$sam in '$groupName'")
                continue
            }
            $uac = Get-AuditAttr $m "userAccountControl"
            $enabled = -not (Test-AuditUacFlag $uac 0x0002)
            $last = Convert-AuditFileTime (Get-AuditAttr $m "lastLogonTimestamp")
            if ((-not $enabled) -or ($last -and $last -lt $inactiveThreshold)) {
                $stale.Add("$sam in '$groupName' (Enabled=$enabled, LastLogon=$last)") | Out-Null
            }
            $spn = @(Get-AuditAttr $m "servicePrincipalName")
            if ($spn.Count -gt 0 -and $spn[0]) {
                [void]$spnPriv.Add("$sam in '$groupName' (SPN: $($spn -join ', '))")
            }
        }
    }

    if ($stale.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-GRP-001" -Category $category -Subcategory "Membership Hygiene" `
            -Title "Disabled or inactive accounts in privileged groups" `
            -Description "Found $($stale.Count) disabled or inactive privileged member(s)." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $stale.Count `
            -AffectedObjects (Limit-AuditObjects $stale) -Evidence $stale `
            -Recommendation "Remove stale and disabled identities from Tier 0 groups immediately." `
            -MitreTechnique "T1078" -DataSource "group memberOf:1.2.840.113556.1.4.1941"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-GRP-001" -Category $category -Subcategory "Membership Hygiene" `
            -Title "No stale privileged group members detected" `
            -Description "Privileged group members that resolved as users appear enabled and recently used." `
            -Severity "Informational" -Status "Passed" -DataSource "group"))
    }

    if ($spnPriv.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-GRP-002" -Category $category -Subcategory "Kerberoasting" `
            -Title "Privileged users have Service Principal Names" `
            -Description "SPNs on admin users let any domain principal request a crackable TGS (Kerberoasting)." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $spnPriv.Count `
            -AffectedObjects (Limit-AuditObjects $spnPriv) -Evidence $spnPriv `
            -Recommendation "Remove SPNs from admin users or move the service to a gMSA." `
            -MitreTechnique "T1558.003" -DataSource "servicePrincipalName"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-GRP-002" -Category $category -Subcategory "Kerberoasting" `
            -Title "No privileged user SPNs detected" `
            -Description "No resolved privileged users had servicePrincipalName values." `
            -Severity "Informational" -Status "Passed" -DataSource "servicePrincipalName"))
    }

    if ($fsp.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-GRP-003" -Category $category -Subcategory "Cross-Trust Privilege" `
            -Title "Foreign security principals in privileged groups" `
            -Description "External SIDs nested in Tier 0 groups grant the trusted forest a path to this domain." `
            -Severity "Medium" -Status "Failed" -RiskScore 8 -AffectedCount $fsp.Count `
            -AffectedObjects (Limit-AuditObjects $fsp) -Evidence $fsp `
            -Recommendation "Remove unexplained FSPs and prefer selective authentication on the trust." `
            -MitreTechnique "T1484" -DataSource "group"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-GRP-003" -Category $category -Subcategory "Cross-Trust Privilege" `
            -Title "No foreign security principals in privileged groups" `
            -Description "No FSP-looking members were resolved in the evaluated groups." `
            -Severity "Informational" -Status "Passed" -DataSource "group"))
    }

    $rdpGroup = Find-AuditGroup -Name "Remote Desktop Users"
    if ($rdpGroup) {
        $rdpMembers = @(Get-AuditGroupMembers -GroupDn (Get-AuditAttr $rdpGroup "distinguishedName") -Recursive | ForEach-Object { Get-AuditSam $_ })
        if ($rdpMembers.Count -gt 0) {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-GRP-004" -Category $category -Subcategory "Remote Access" `
                -Title "Remote Desktop Users domain group is populated" `
                -Description "Domain-level RDP rights via this group apply broadly and are often overlooked." `
                -Severity "Medium" -Status "Warning" -RiskScore 8 -AffectedCount $rdpMembers.Count `
                -AffectedObjects (Limit-AuditObjects $rdpMembers) -Evidence $rdpMembers `
                -Recommendation "Prefer local/GPO Restricted Groups on jump hosts instead of the domain Remote Desktop Users group." `
                -MitreTechnique "T1021.001" -DataSource "group"))
        } else {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-GRP-004" -Category $category -Subcategory "Remote Access" `
                -Title "Remote Desktop Users domain group has no nested members" `
                -Description "The domain Remote Desktop Users group did not resolve nested members." `
                -Severity "Informational" -Status "Passed" -DataSource "group"))
        }
    }

    if ($daMembers.Count -gt $maxDa) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-GRP-005" -Category $category -Subcategory "Tier 0 Size" `
            -Title "Domain Admins has $($daMembers.Count) members (threshold $maxDa)" `
            -Description "Large Domain Admins membership expands the Tier 0 blast radius. Microsoft and ANSSI recommend a very small standing DA set plus JIT/PAM." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $daMembers.Count `
            -AffectedObjects (Limit-AuditObjects $daMembers) -Evidence $daMembers `
            -Recommendation "Reduce standing Domain Admins. Use PAW, Protected Users, and just-in-time elevation." `
            -MitreTechnique "T1078.002" -DataSource "Domain Admins"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-GRP-005" -Category $category -Subcategory "Tier 0 Size" `
            -Title "Domain Admins membership size is within baseline ($($daMembers.Count))" `
            -Description "Standing Domain Admins count is $(($daMembers | Select-Object -Unique).Count)." `
            -Severity "Informational" -Status "Passed" -AffectedObjects ($daMembers | Select-Object -Unique) -DataSource "Domain Admins"))
    }

    if ($schemaMembers.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-GRP-006" -Category $category -Subcategory "Schema Admins" `
            -Title "Schema Admins is populated" `
            -Description "Schema Admins should be empty except during a planned schema change. Standing membership is a persistence and forest-compromise risk." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $schemaMembers.Count `
            -AffectedObjects $schemaMembers -Evidence $schemaMembers `
            -Recommendation "Remove all standing Schema Admins members. Add them only for a controlled change window." `
            -MitreTechnique "T1098" -DataSource "Schema Admins"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-GRP-006" -Category $category -Subcategory "Schema Admins" `
            -Title "Schema Admins has no extra members" `
            -Description "No nested members other than the default Administrator were resolved." `
            -Severity "Informational" -Status "Passed" -DataSource "Schema Admins"))
    }

    $missingProtected = @($daSam | Select-Object -Unique | Where-Object { $_ -and ($protectedUsers -notcontains $_) -and $_ -ne "krbtgt" })
    if ($missingProtected.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-GRP-007" -Category $category -Subcategory "Protected Users" `
            -Title "Domain Admins members are missing from Protected Users" `
            -Description "Protected Users blocks NTLM, DES, constrained delegation, and offline caching for its members. Domain Admins should be in this group (on supported DCs)." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $missingProtected.Count `
            -AffectedObjects (Limit-AuditObjects $missingProtected) -Evidence $missingProtected `
            -Recommendation "Add administrative users to Protected Users after validating Windows 2012 R2+ DC support and authentication paths." `
            -MicrosoftReference "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group" `
            -MitreTechnique "T1558" -DataSource "Protected Users"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-GRP-007" -Category $category -Subcategory "Protected Users" `
            -Title "Domain Admins members are in Protected Users (or none resolved)" `
            -Description "No Domain Admins members were found outside Protected Users." `
            -Severity "Informational" -Status "Passed" -DataSource "Protected Users"))
    }

    foreach ($pair in @(
            @{ Id = "AD-GRP-008"; Name = "Account Operators"; Items = $accountOps; Sev = "High"; Score = 15; Rec = "Account Operators can manage most non-admin users and should be empty." },
            @{ Id = "AD-GRP-009"; Name = "Print Operators"; Items = $printOps; Sev = "High"; Score = 15; Rec = "Print Operators can load drivers on DCs. Keep this group empty." },
            @{ Id = "AD-GRP-010"; Name = "Backup Operators"; Items = $backupOps; Sev = "High"; Score = 15; Rec = "Backup Operators can read ntds.dit-equivalent data. Restrict to dedicated backup identities." },
            @{ Id = "AD-GRP-011"; Name = "Server Operators"; Items = $serverOps; Sev = "High"; Score = 15; Rec = "Server Operators can log on locally to DCs and manage services. Keep this group empty." }
        )) {
        if ($pair.Items.Count -gt 0) {
            [void]$findings.Add((New-AuditFinding -CheckId $pair.Id -Category $category -Subcategory "Built-in Operators" `
                -Title "$($pair.Name) is populated" `
                -Description "$($pair.Rec) Found $($pair.Items.Count) member(s)." `
                -Severity $pair.Sev -Status "Failed" -RiskScore $pair.Score -AffectedCount $pair.Items.Count `
                -AffectedObjects (Limit-AuditObjects $pair.Items) -Evidence $pair.Items `
                -Recommendation $pair.Rec -MitreTechnique "T1078" -DataSource $pair.Name))
        } else {
            [void]$findings.Add((New-AuditFinding -CheckId $pair.Id -Category $category -Subcategory "Built-in Operators" `
                -Title "$($pair.Name) has no nested members" `
                -Description "$($pair.Name) did not resolve nested members." `
                -Severity "Informational" -Status "Passed" -DataSource $pair.Name))
        }
    }

    Add-AuditCheckResult -Findings $findings -CheckId "AD-GRP-012" -Category $category -Subcategory "Computer Members" `
        -FailTitle "Computer objects nested in privileged groups" `
        -PassTitle "No computer objects nested in evaluated privileged groups" `
        -FailDescription "A computer in Domain Admins / Administrators / similar groups grants that host's machine account (and anyone who controls it) Tier 0 rights." `
        -Items @($computerMembers) -Severity "Critical" -RiskScore 25 `
        -Recommendation "Remove computer accounts from Tier 0 groups. Control the host via GPO and Restricted Groups instead." `
        -MitreTechnique "T1078.002" -DataSource "group"

    return $findings
}

Export-ModuleMember -Function Invoke-PrivilegedGroupsAudit
