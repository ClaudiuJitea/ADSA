# TierZero.psm1 - Ownership, control ACEs, and credential hygiene of Tier 0 assets

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-TierZeroAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "Tier 0 Attack Surface"
    $session = Get-AuditDirectorySession
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-TZ-000" -Category $category))
        return $findings
    }

    $maxPwdAge = 365
    if ($Config.MaxTier0PasswordAgeDays) { $maxPwdAge = [int]$Config.MaxTier0PasswordAgeDays }

    $domainDn = $session.DefaultNamingContext
    $tier0GroupNames = @(
        "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
        "Account Operators", "Backup Operators", "Server Operators", "Print Operators",
        "DnsAdmins", "Group Policy Creator Owners", "Key Admins", "Enterprise Key Admins",
        "Protected Users", "Cert Publishers", "Read-only Domain Controllers"
    )

    # ------------------------------------------------------------------
    # Build the Tier 0 object inventory whose security descriptors matter.
    # ------------------------------------------------------------------
    $targets = New-Object System.Collections.Generic.List[object]
    $addTarget = {
        param($Label, $Dn, $Kind)
        if ([string]::IsNullOrWhiteSpace($Dn)) { return }
        [void]$targets.Add([PSCustomObject]@{ Label = $Label; Dn = $Dn; Kind = $Kind })
    }

    & $addTarget "Domain root ($domainDn)" $domainDn "Container"
    & $addTarget "AdminSDHolder" "CN=AdminSDHolder,CN=System,$domainDn" "Container"
    & $addTarget "Domain Controllers OU" "OU=Domain Controllers,$domainDn" "Container"
    & $addTarget "System container" "CN=System,$domainDn" "Container"

    $tier0Groups = @()
    foreach ($groupName in $tier0GroupNames) {
        $group = Find-AuditGroup -Name $groupName
        if (-not $group) { continue }
        $dn = Get-AuditAttr $group "distinguishedName"
        $tier0Groups += [PSCustomObject]@{ Name = $groupName; Dn = $dn; Object = $group }
        & $addTarget "Group '$groupName'" $dn "Group"
    }

    $dcs = @(Search-AuditDirectory -LdapFilter "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -Properties @("distinguishedName", "dNSHostName", "name", "sAMAccountName"))
    foreach ($dc in $dcs) {
        $label = Get-AuditAttr $dc "dNSHostName"
        if (-not $label) { $label = Get-AuditSam $dc }
        & $addTarget "Domain Controller '$label'" (Get-AuditAttr $dc "distinguishedName") "DomainController"
    }

    # Tier 0 principals: nested members of the core admin groups plus krbtgt.
    $tier0Members = @{}
    foreach ($groupName in @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")) {
        $group = $tier0Groups | Where-Object { $_.Name -eq $groupName } | Select-Object -First 1
        if (-not $group -or -not $group.Dn) { continue }
        foreach ($member in @(Get-AuditGroupMembers -GroupDn $group.Dn -Recursive)) {
            $dn = Get-AuditAttr $member "distinguishedName"
            if (-not $dn) { continue }
            if (-not $tier0Members.ContainsKey($dn)) {
                $tier0Members[$dn] = [PSCustomObject]@{
                    Sam    = Get-AuditSam $member
                    Object = $member
                    Groups = New-Object System.Collections.Generic.List[string]
                }
            }
            [void]$tier0Members[$dn].Groups.Add($groupName)
        }
    }

    $krbtgt = @(Search-AuditDirectory -LdapFilter "(&(objectClass=user)(sAMAccountName=krbtgt))" -Properties @("distinguishedName", "sAMAccountName", "pwdLastSet", "userAccountControl"))
    foreach ($k in $krbtgt) {
        & $addTarget "krbtgt account" (Get-AuditAttr $k "distinguishedName") "Account"
    }

    foreach ($dn in $tier0Members.Keys) {
        $className = Get-AuditMostSpecificClass $tier0Members[$dn].Object
        if ($className -match "group") { continue }
        & $addTarget "Tier 0 account '$($tier0Members[$dn].Sam)'" $dn "Account"
    }

    # ------------------------------------------------------------------
    # Read each descriptor once, then classify owners, trustees, and orphans.
    # ------------------------------------------------------------------
    $badOwners = New-Object System.Collections.Generic.List[string]
    $groupControl = New-Object System.Collections.Generic.List[string]
    $dcControl = New-Object System.Collections.Generic.List[string]
    $orphanAces = New-Object System.Collections.Generic.List[string]
    $readable = 0

    foreach ($target in $targets) {
        $sd = Get-AuditSecurityDescriptor -DistinguishedName $target.Dn
        if (-not $sd.Readable) { continue }
        $readable++

        if ($sd.Owner -and -not (Test-AuditTier0Identity $sd.Owner)) {
            [void]$badOwners.Add("$($target.Label) owned by $($sd.Owner)")
        }

        foreach ($ace in @($sd.Access)) {
            if ("$($ace.AccessControlType)" -ne "Allow") { continue }
            $identity = [string]$ace.IdentityReference
            $mask = 0
            try { $mask = [int]$ace.ActiveDirectoryRights } catch { }

            if (Test-AuditUnresolvedSid $identity) {
                if (Test-AuditControlRight -Mask $mask -ObjectType $ace.ObjectType) {
                    [void]$orphanAces.Add("$($target.Label): deleted principal $identity holds $(Get-AuditAceRightNames $mask)")
                }
                continue
            }

            if (Test-AuditTier0Identity $identity) { continue }
            if (-not (Test-AuditControlRight -Mask $mask -ObjectType $ace.ObjectType)) { continue }

            $rights = Get-AuditAceRightNames $mask
            $scope = "$(Convert-ADGuidToName "$($ace.ObjectType)")"
            $detail = "$($target.Label): $identity has $rights"
            if ($scope -and $scope -ne "All objects / All properties") { $detail += " on $scope" }

            switch ($target.Kind) {
                "Group" { [void]$groupControl.Add($detail) }
                "Account" { [void]$groupControl.Add($detail) }
                "DomainController" { [void]$dcControl.Add($detail) }
                "Container" { if ($target.Label -like "Domain Controllers OU*") { [void]$dcControl.Add($detail) } }
            }
        }
    }

    if ($readable -eq 0) {
        foreach ($id in @("AD-TZ-001", "AD-TZ-002", "AD-TZ-003", "AD-TZ-004")) {
            [void]$findings.Add((New-AuditFinding -CheckId $id -Category $category -Subcategory "Security Descriptors" `
                    -Title "Tier 0 security descriptors could not be read" `
                    -Description "None of the $($targets.Count) Tier 0 object(s) returned nTSecurityDescriptor, so ownership and delegation analysis was skipped. This usually means the bind account cannot read security descriptors over this connection." `
                    -Severity "Medium" -Status "Not Tested" `
                    -Recommendation "Re-run with an account that can read nTSecurityDescriptor (any authenticated user normally can) or run on a domain-joined host with RSAT." `
                    -RequiredPermission "Read nTSecurityDescriptor" -DataSource "nTSecurityDescriptor"))
        }
    } else {
        Add-AuditCheckResult -Findings $findings -CheckId "AD-TZ-001" -Category $category -Subcategory "Ownership" `
            -FailTitle "Tier 0 objects are owned by non-Tier 0 principals" `
            -PassTitle "All readable Tier 0 objects are owned by Tier 0 principals" `
            -FailDescription "The owner of an object always holds implicit WriteDacl, so a non-Tier 0 owner of a Domain Controller, admin group, or admin account can grant itself full control at any time. Ownership is frequently left behind by whoever created the object and is missed by membership-only reviews." `
            -PassDescription "Owners of the evaluated Tier 0 objects resolved to Domain Admins, Enterprise Admins, Administrators, or SYSTEM." `
            -Items @($badOwners) -Severity "High" -RiskScore 15 `
            -Recommendation "Set the owner of every Tier 0 object to Domain Admins (or Enterprise Admins for forest-wide objects) and investigate how ownership was transferred." `
            -MitreTechnique "T1222" -DataSource "nTSecurityDescriptor owner"

        Add-AuditCheckResult -Findings $findings -CheckId "AD-TZ-002" -Category $category -Subcategory "Admin Object Control" `
            -FailTitle "Non-Tier 0 principals can modify admin groups or admin accounts" `
            -PassTitle "No non-Tier 0 control ACEs on admin groups or admin accounts" `
            -FailDescription "Write access to a Tier 0 group's membership, or to an admin account's attributes, is a one-step path to Domain Admin (add-member, shadow credentials, targeted Kerberoast, or password reset)." `
            -PassDescription "Only Tier 0 identities hold write/control rights on the evaluated admin groups and accounts." `
            -Items @($groupControl) -Severity "Critical" -RiskScore 25 `
            -Recommendation "Remove the delegation, or move the delegated task to a Tier 0 group. Protected objects should only be writable by Domain Admins, Enterprise Admins, and SYSTEM." `
            -MitreTechnique "T1098" -DataSource "nTSecurityDescriptor DACL"

        Add-AuditCheckResult -Findings $findings -CheckId "AD-TZ-003" -Category $category -Subcategory "Domain Controller Objects" `
            -FailTitle "Non-Tier 0 principals can modify Domain Controller objects" `
            -PassTitle "No non-Tier 0 control ACEs on Domain Controller objects" `
            -FailDescription "Write access to a DC computer object (or the Domain Controllers OU) allows resource-based constrained delegation or shadow credentials against a Domain Controller, which is equivalent to domain compromise." `
            -PassDescription "Only Tier 0 identities hold write/control rights on Domain Controller objects and their OU." `
            -Items @($dcControl) -Severity "Critical" -RiskScore 25 `
            -Recommendation "Remove write delegations from Domain Controller objects and the Domain Controllers OU. Restrict DC lifecycle operations to Domain Admins." `
            -MitreTechnique "T1098" -DataSource "nTSecurityDescriptor DACL"

        Add-AuditCheckResult -Findings $findings -CheckId "AD-TZ-004" -Category $category -Subcategory "Orphaned SIDs" `
            -FailTitle "Deleted principals still hold rights on Tier 0 objects" `
            -PassTitle "No unresolvable SIDs hold rights on Tier 0 objects" `
            -FailDescription "An ACE for a SID that no longer resolves means the trustee was deleted. The permission stays in place and is inherited by any principal that later obtains the same SID through SID history injection or a restored account." `
            -PassDescription "Every trustee on the evaluated Tier 0 objects resolved to an existing principal." `
            -Items @($orphanAces) -Severity "Medium" -RiskScore 8 `
            -Recommendation "Remove ACEs whose trustee SID no longer resolves. Track them as configuration drift caused by account deletion." `
            -MitreTechnique "T1134.005" -DataSource "nTSecurityDescriptor DACL"
    }

    # ------------------------------------------------------------------
    # Tier 0 credential hygiene.
    # ------------------------------------------------------------------
    $stalePasswords = New-Object System.Collections.Generic.List[string]
    foreach ($dn in $tier0Members.Keys) {
        $entry = $tier0Members[$dn]
        $className = Get-AuditMostSpecificClass $entry.Object
        if ($className -match "group") { continue }
        $uac = Get-AuditAttr $entry.Object "userAccountControl"
        if (Test-AuditUacFlag $uac 0x0002) { continue }
        $set = Convert-AuditFileTime (Get-AuditAttr $entry.Object "pwdLastSet")
        if (-not $set) { continue }
        $days = [int][math]::Round(((Get-Date) - $set).TotalDays)
        if ($days -gt $maxPwdAge) {
            [void]$stalePasswords.Add("$($entry.Sam) - password $days days old (in $($entry.Groups -join ', '))")
        }
    }
    Add-AuditCheckResult -Findings $findings -CheckId "AD-TZ-005" -Category $category -Subcategory "Credential Age" `
        -FailTitle "Tier 0 accounts have passwords older than $maxPwdAge days" `
        -PassTitle "No Tier 0 account password is older than $maxPwdAge days" `
        -FailDescription "A privileged credential that never rotates stays valid for every hash captured in the past. Tier 0 secrets should be rotated on a schedule and after every incident, and ideally issued just-in-time." `
        -PassDescription "All resolved Tier 0 account passwords are within the age threshold." `
        -Items @($stalePasswords) -Severity "High" -RiskScore 15 `
        -Recommendation "Rotate Tier 0 passwords, enforce a maximum age through a fine-grained password policy applied to admins, and move to just-in-time elevation where possible." `
        -MitreTechnique "T1078.002" -DataSource "pwdLastSet"

    # ------------------------------------------------------------------
    # Shadow credentials (msDS-KeyCredentialLink) on Tier 0 accounts.
    # ------------------------------------------------------------------
    $keyCredAccounts = @(Search-AuditDirectory -LdapFilter "(&(|(objectClass=user)(objectClass=computer))(msDS-KeyCredentialLink=*))" -Properties @("distinguishedName", "sAMAccountName", "msDS-KeyCredentialLink", "objectClass"))
    $tier0KeyCreds = New-Object System.Collections.Generic.List[string]
    foreach ($acct in $keyCredAccounts) {
        $dn = [string](Get-AuditAttr $acct "distinguishedName")
        if (-not $tier0Members.ContainsKey($dn)) { continue }
        $links = @((Get-AuditAttr $acct "msDS-KeyCredentialLink") | Where-Object { $_ })
        [void]$tier0KeyCreds.Add("$(Get-AuditSam $acct) has $($links.Count) key credential link(s)")
    }
    Add-AuditCheckResult -Findings $findings -CheckId "AD-TZ-006" -Category $category -Subcategory "Shadow Credentials" `
        -FailTitle "Tier 0 accounts have key credential links (possible shadow credentials)" `
        -PassTitle "No key credential links on Tier 0 accounts" `
        -FailDescription "msDS-KeyCredentialLink stores certificate key pairs that authenticate as the account through PKINIT. Windows Hello for Business populates it legitimately, but on an admin account that does not use WHfB it is the standard shadow-credential persistence technique and grants logon without knowing the password." `
        -PassDescription "No Tier 0 account had msDS-KeyCredentialLink populated." `
        -Items @($tier0KeyCreds) -Severity "High" -RiskScore 15 -FailStatus "Warning" `
        -Recommendation "Confirm each key credential belongs to an enrolled Windows Hello for Business device. Clear unexplained entries and audit who can write msDS-KeyCredentialLink." `
        -MitreTechnique "T1556" -DataSource "msDS-KeyCredentialLink"

    # ------------------------------------------------------------------
    # Non-Tier 0 groups nested inside Tier 0 groups.
    # ------------------------------------------------------------------
    $nested = New-Object System.Collections.Generic.List[string]
    foreach ($group in $tier0Groups) {
        if (-not $group.Dn) { continue }
        if (@("Protected Users", "Read-only Domain Controllers") -contains $group.Name) { continue }
        foreach ($member in @(Get-AuditGroupMembers -GroupDn $group.Dn)) {
            $className = Get-AuditMostSpecificClass $member
            if ($className -notmatch "group") { continue }
            $memberName = Get-AuditSam $member
            if ($tier0GroupNames -contains $memberName) { continue }
            if (Test-AuditTier0Identity $memberName) { continue }
            [void]$nested.Add("'$memberName' is nested in '$($group.Name)'")
        }
    }
    Add-AuditCheckResult -Findings $findings -CheckId "AD-TZ-007" -Category $category -Subcategory "Group Nesting" `
        -FailTitle "Non-Tier 0 groups are nested inside Tier 0 groups" `
        -PassTitle "Tier 0 groups contain no unexpected nested groups" `
        -FailDescription "Nesting a normal group inside a Tier 0 group hands Tier 0 rights to whoever can manage that group, which is usually a service desk or an application owner rather than a domain admin. Effective membership then changes without anyone editing a privileged group." `
        -PassDescription "Only accounts or other Tier 0 groups were nested in the evaluated privileged groups." `
        -Items @($nested) -Severity "High" -RiskScore 15 `
        -Recommendation "Flatten Tier 0 groups so they contain only individually reviewed admin accounts, and remove nested business or application groups." `
        -MitreTechnique "T1078.002" -DataSource "group member"

    # ------------------------------------------------------------------
    # Delegation flags on Tier 0 accounts.
    # ------------------------------------------------------------------
    $delegationFilter = "(&(|(objectClass=user)(objectClass=computer))(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*)))"
    $delegated = @(Search-AuditDirectory -LdapFilter $delegationFilter -Properties @("distinguishedName", "sAMAccountName", "userAccountControl", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity"))
    $tier0Delegation = New-Object System.Collections.Generic.List[string]
    foreach ($acct in $delegated) {
        $dn = [string](Get-AuditAttr $acct "distinguishedName")
        if (-not $tier0Members.ContainsKey($dn)) { continue }
        $sam = Get-AuditSam $acct
        $uac = Get-AuditAttr $acct "userAccountControl"
        $reasons = @()
        if (Test-AuditUacFlag $uac 0x80000) { $reasons += "TRUSTED_FOR_DELEGATION" }
        if (Test-AuditUacFlag $uac 0x1000000) { $reasons += "TRUSTED_TO_AUTH_FOR_DELEGATION" }
        $kcd = @((Get-AuditAttr $acct "msDS-AllowedToDelegateTo") | Where-Object { $_ })
        if ($kcd.Count -gt 0) { $reasons += "msDS-AllowedToDelegateTo=$($kcd -join '; ')" }
        $rbcd = Get-AuditAttr $acct "msDS-AllowedToActOnBehalfOfOtherIdentity"
        if ($rbcd) {
            $trustees = @(Get-AuditSecurityDescriptorTrustees $rbcd)
            $reasons += "RBCD trustees: $(if ($trustees.Count -gt 0) { $trustees -join ', ' } else { 'unreadable' })"
        }
        if ($reasons.Count -gt 0) { [void]$tier0Delegation.Add("$sam - $($reasons -join ' | ')") }
    }
    Add-AuditCheckResult -Findings $findings -CheckId "AD-TZ-008" -Category $category -Subcategory "Delegation on Tier 0" `
        -FailTitle "Tier 0 accounts are configured for Kerberos delegation" `
        -PassTitle "No delegation attributes on Tier 0 accounts" `
        -FailDescription "Delegation on a privileged account lets another principal obtain tickets in its name. Combined with an admin account, any of these settings turns a single compromised service into Domain Admin." `
        -PassDescription "No Tier 0 account had delegation flags, msDS-AllowedToDelegateTo, or RBCD configured." `
        -Items @($tier0Delegation) -Severity "Critical" -RiskScore 25 `
        -Recommendation "Remove delegation from admin accounts, mark them sensitive and not delegated, and add them to Protected Users." `
        -MitreTechnique "T1550.003" -DataSource "userAccountControl / delegation attributes"

    $tier0AccountCount = @($tier0Members.Keys).Count
    [void]$findings.Add((New-AuditFinding -CheckId "AD-TZ-009" -Category $category -Subcategory "Inventory" `
            -Title "Tier 0 inventory: $tier0AccountCount principals across $($targets.Count) protected objects" `
            -Description "Security descriptors were readable on $readable of $($targets.Count) Tier 0 object(s). Unreadable descriptors are not counted as compliant." `
            -Severity "Informational" -Status "Informational" -AffectedCount $tier0AccountCount `
            -AffectedObjects (Limit-AuditObjects @($tier0Members.Values | ForEach-Object { "$($_.Sam) ($($_.Groups -join ', '))" })) `
            -DataSource "Tier 0 groups"))

    return $findings
}

Export-ModuleMember -Function Invoke-TierZeroAudit
