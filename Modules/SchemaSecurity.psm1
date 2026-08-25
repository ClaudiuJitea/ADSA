# SchemaSecurity.psm1 - Schema confidentiality, tampering, and forest partition control

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Get-AuditSddlAceList {
    <#
        Splits a defaultSecurityDescriptor SDDL string into its ACE fields without
        relying on Windows SID translation, which is unavailable when the audit runs
        from a non-Windows host.
    #>
    param([string]$Sddl)
    $aces = @()
    if ([string]::IsNullOrWhiteSpace($Sddl)) { return $aces }
    foreach ($match in [regex]::Matches($Sddl, '\(([^()]*)\)')) {
        $fields = $match.Groups[1].Value.Split(';')
        if ($fields.Count -lt 6) { continue }
        $aces += [PSCustomObject]@{
            Type    = $fields[0]
            Flags   = $fields[1]
            Rights  = $fields[2]
            Trustee = $fields[5]
        }
    }
    return $aces
}

function Invoke-SchemaSecurityAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [int]$SchemaChangeWindowDays = 90,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "Schema Security"
    $session = Get-AuditDirectorySession
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-SCH-000" -Category $category))
        return $findings
    }

    $schemaNc = $session.SchemaNamingContext
    $configNc = $session.ConfigurationNamingContext
    if ($Config.SchemaChangeWindowDays) { $SchemaChangeWindowDays = [int]$Config.SchemaChangeWindowDays }

    if (-not $schemaNc) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-SCH-001" -Category $category -Subcategory "Schema Access" `
                -Title "Schema naming context is unknown" `
                -Description "RootDSE did not return schemaNamingContext, so schema checks were skipped." `
                -Severity "Low" -Status "Not Tested" -DataSource "RootDSE"))
        return $findings
    }

    # ------------------------------------------------------------------
    # LAPS password attributes must be marked confidential in the schema.
    # ------------------------------------------------------------------
    $lapsFilter = "(&(objectClass=attributeSchema)(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=msLAPS-Password)(lDAPDisplayName=msLAPS-EncryptedPassword)(lDAPDisplayName=msLAPS-EncryptedPasswordHistory)(lDAPDisplayName=msLAPS-EncryptedDSRMPassword)(lDAPDisplayName=msLAPS-EncryptedDSRMPasswordHistory)))"
    $lapsAttrs = @(Search-AuditDirectory -LdapFilter $lapsFilter -SearchBase $schemaNc -Properties @("lDAPDisplayName", "searchFlags"))
    $notConfidential = New-Object System.Collections.Generic.List[string]
    foreach ($attr in $lapsAttrs) {
        $name = [string](Get-AuditAttr $attr "lDAPDisplayName")
        $flags = 0
        try { $flags = [int](Get-AuditAttr $attr "searchFlags") } catch { }
        # searchFlags bit 7 (128) = fCONFIDENTIAL. Without it, every principal holding
        # generic read on the computer object can read the local administrator password.
        if (($flags -band 128) -ne 128) {
            [void]$notConfidential.Add("$name (searchFlags=$flags, missing fCONFIDENTIAL)")
        }
    }

    if ($lapsAttrs.Count -eq 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-SCH-001" -Category $category -Subcategory "LAPS Confidentiality" `
                -Title "No LAPS password attributes exist in the schema" `
                -Description "Neither the legacy (ms-Mcs-AdmPwd) nor the Windows LAPS (msLAPS-*) attributes are present, so there is nothing to mark confidential. LAPS deployment itself is reported by the LAPS and local administrator module." `
                -Severity "Informational" -Status "Informational" -DataSource "attributeSchema"))
    } else {
        Add-AuditCheckResult -Findings $findings -CheckId "AD-SCH-001" -Category $category -Subcategory "LAPS Confidentiality" `
            -FailTitle "LAPS password attributes are not marked confidential" `
            -PassTitle "All LAPS password attributes are marked confidential" `
            -FailDescription "The fCONFIDENTIAL search flag is what restricts a LAPS password attribute to principals holding CONTROL_ACCESS instead of plain read. Without it, anyone who can read the computer object can read the local administrator password, which defeats the purpose of LAPS." `
            -PassDescription "Every LAPS attribute in the schema has searchFlags bit 128 set." `
            -Items @($notConfidential) -Severity "Critical" -RiskScore 25 `
            -Recommendation "Set searchFlags on the attribute to include 128 (fCONFIDENTIAL). Windows LAPS sets this by default; legacy LAPS schema extensions occasionally lose it after manual schema edits." `
            -MicrosoftReference "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory" `
            -MitreTechnique "T1552" -DataSource "attributeSchema searchFlags"
    }

    # ------------------------------------------------------------------
    # Recent schema modifications.
    # ------------------------------------------------------------------
    $since = (Get-Date).AddDays(-$SchemaChangeWindowDays).ToUniversalTime().ToString("yyyyMMddHHmmss.0Z")
    $changed = @(Search-AuditDirectory -LdapFilter "(&(|(objectClass=attributeSchema)(objectClass=classSchema))(whenChanged>=$since))" -SearchBase $schemaNc -Properties @("lDAPDisplayName", "cn", "whenChanged", "whenCreated"))
    $changeList = New-Object System.Collections.Generic.List[string]
    foreach ($obj in $changed) {
        $name = Get-AuditAttr $obj "lDAPDisplayName"
        if (-not $name) { $name = Get-AuditAttr $obj "cn" }
        $when = Get-AuditAttr $obj "whenChanged"
        $created = Get-AuditAttr $obj "whenCreated"
        $kind = if ("$created" -ge "$since") { "created" } else { "modified" }
        [void]$changeList.Add("$name ($kind $when)")
    }
    Add-AuditCheckResult -Findings $findings -CheckId "AD-SCH-002" -Category $category -Subcategory "Schema Change Control" `
        -FailTitle "Schema objects changed in the last $SchemaChangeWindowDays days" `
        -PassTitle "No schema changes in the last $SchemaChangeWindowDays days" `
        -FailDescription "Schema changes are irreversible and forest-wide. Every change should map to a documented application deployment or Microsoft update; anything else is either untracked change management or an attacker adding attributes and classes for persistence." `
        -PassDescription "No attributeSchema or classSchema object reported whenChanged inside the window." `
        -Items @($changeList) -Severity "Medium" -RiskScore 8 -FailStatus "Warning" `
        -Recommendation "Match each change to a change ticket. Schema Admins should be empty outside a planned change window." `
        -MitreTechnique "T1098" -DataSource "attributeSchema / classSchema whenChanged"

    # ------------------------------------------------------------------
    # defaultSecurityDescriptor on security-relevant classes.
    # ------------------------------------------------------------------
    $watchedClasses = @("computer", "user", "group", "organizationalUnit", "groupPolicyContainer", "msDS-GroupManagedServiceAccount", "pKICertificateTemplate", "container")
    $classFilter = "(&(objectClass=classSchema)(|" + (($watchedClasses | ForEach-Object { "(lDAPDisplayName=$(Format-AuditLdapFilterValue $_))" }) -join "") + "))"
    $classes = @(Search-AuditDirectory -LdapFilter $classFilter -SearchBase $schemaNc -Properties @("lDAPDisplayName", "defaultSecurityDescriptor"))
    $broadTrustees = @("AU", "WD", "AN", "IU", "BU", "DU", "DC", "S-1-1-0", "S-1-5-11", "S-1-5-7")
    $controlRights = @("GA", "GW", "WO", "WD", "CC", "WP", "SW", "CR")
    $weakDefaults = New-Object System.Collections.Generic.List[string]
    foreach ($class in $classes) {
        $className = [string](Get-AuditAttr $class "lDAPDisplayName")
        $sddl = [string](Get-AuditAttr $class "defaultSecurityDescriptor")
        foreach ($ace in @(Get-AuditSddlAceList -Sddl $sddl)) {
            if ($ace.Type -notmatch '^O?A') { continue }
            if ($broadTrustees -notcontains $ace.Trustee) { continue }
            $granted = @()
            foreach ($right in $controlRights) {
                if ($ace.Rights -match $right) { $granted += $right }
            }
            if ($granted.Count -gt 0) {
                [void]$weakDefaults.Add("class '$className' grants $($granted -join ',') to trustee '$($ace.Trustee)' by default")
            }
        }
    }
    Add-AuditCheckResult -Findings $findings -CheckId "AD-SCH-003" -Category $category -Subcategory "Default Security Descriptors" `
        -FailTitle "Class default security descriptors grant write access to broad identities" `
        -PassTitle "Class default security descriptors do not grant broad write access" `
        -FailDescription "defaultSecurityDescriptor is stamped onto every new object of that class. A write right granted to Authenticated Users or Everyone here silently applies to every future user, computer, or GPO, and it survives cleanup of individual object ACLs." `
        -PassDescription "The evaluated classes only grant read-level rights to broad identities in their default descriptor." `
        -Items @($weakDefaults) -Severity "High" -RiskScore 15 `
        -Recommendation "Restore the Microsoft default descriptor for the affected class and re-check objects created since the change." `
        -MitreTechnique "T1098" -DataSource "classSchema defaultSecurityDescriptor"

    # ------------------------------------------------------------------
    # Control of the schema and configuration partitions.
    # ------------------------------------------------------------------
    $partitionIssues = New-Object System.Collections.Generic.List[string]
    $partitionsReadable = 0
    foreach ($partition in @(
            @{ Label = "Schema partition"; Dn = $schemaNc },
            @{ Label = "Configuration partition"; Dn = $configNc },
            @{ Label = "Sites container"; Dn = $(if ($configNc) { "CN=Sites,$configNc" } else { $null }) }
        )) {
        if (-not $partition.Dn) { continue }
        $sd = Get-AuditSecurityDescriptor -DistinguishedName $partition.Dn
        if (-not $sd.Readable) { continue }
        $partitionsReadable++
        if ($sd.Owner -and -not (Test-AuditTier0Identity $sd.Owner)) {
            [void]$partitionIssues.Add("$($partition.Label) is owned by $($sd.Owner)")
        }
        foreach ($ace in @($sd.Access)) {
            if ("$($ace.AccessControlType)" -ne "Allow") { continue }
            $identity = [string]$ace.IdentityReference
            if (Test-AuditTier0Identity $identity) { continue }
            $mask = 0
            try { $mask = [int]$ace.ActiveDirectoryRights } catch { }
            if (-not (Test-AuditControlRight -Mask $mask -ObjectType $ace.ObjectType)) { continue }
            [void]$partitionIssues.Add("$($partition.Label): $identity has $(Get-AuditAceRightNames $mask)")
        }
    }

    if ($partitionsReadable -eq 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-SCH-004" -Category $category -Subcategory "Partition Control" `
                -Title "Schema and configuration partition descriptors could not be read" `
                -Description "nTSecurityDescriptor was not returned for the schema or configuration partition heads, so forest-wide delegation was not evaluated." `
                -Severity "Medium" -Status "Not Tested" -RequiredPermission "Read nTSecurityDescriptor" -DataSource "nTSecurityDescriptor"))
    } else {
        Add-AuditCheckResult -Findings $findings -CheckId "AD-SCH-004" -Category $category -Subcategory "Partition Control" `
            -FailTitle "Non-Tier 0 principals control forest-wide partitions" `
            -PassTitle "Forest-wide partitions are controlled only by Tier 0 principals" `
            -FailDescription "Write access to the schema or configuration partition is forest-wide compromise: it allows schema edits, new sites and subnets, and changes to published services such as AD CS enrollment endpoints." `
            -PassDescription "Only Tier 0 identities hold control rights and ownership on the evaluated partitions." `
            -Items @($partitionIssues) -Severity "Critical" -RiskScore 25 `
            -Recommendation "Remove delegated write access from the schema and configuration partitions. Forest-wide changes belong to Enterprise Admins and Schema Admins only, and Schema Admins should be empty between change windows." `
            -MitreTechnique "T1484" -DataSource "nTSecurityDescriptor"
    }

    [void]$findings.Add((New-AuditFinding -CheckId "AD-SCH-005" -Category $category -Subcategory "Inventory" `
            -Title "Schema inventory: $($lapsAttrs.Count) LAPS attribute(s), $($changed.Count) recent change(s)" `
            -Description "Schema partition: $schemaNc. Evaluated $($classes.Count) security-relevant class default descriptor(s)." `
            -Severity "Informational" -Status "Informational" -DataSource "schema"))

    return $findings
}

Export-ModuleMember -Function Invoke-SchemaSecurityAudit
