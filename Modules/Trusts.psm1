# Trusts.psm1 - SID filtering, TGT delegation, SID history, inventory

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-TrustsAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "Trust Relationships"
    $session = Get-AuditDirectorySession
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-TRST-000" -Category $category))
        return $findings
    }

    $maxTrustPasswordAge = 365
    if ($Config.MaxTrustPasswordAgeDays) { $maxTrustPasswordAge = [int]$Config.MaxTrustPasswordAgeDays }

    $trusts = @(Search-AuditDirectory -LdapFilter "(objectClass=trustedDomain)" -SearchBase $session.DefaultNamingContext -Properties @(
            "name", "trustDirection", "trustType", "trustAttributes", "flatName", "trustPartner", "whenCreated"
        ))

    if ($trusts.Count -eq 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-TRST-001" -Category $category -Subcategory "Inventory" `
            -Title "No domain trusts found" `
            -Description "No trustedDomain objects were returned. This is normal for a single-domain forest." `
            -Severity "Informational" -Status "Passed" -DataSource "trustedDomain"))
        return $findings
    }

    $noFilter = @()
    $tgtDeleg = @()
    $sidHistory = @()
    $rc4Trust = @()
    $inventory = @()
    foreach ($t in $trusts) {
        $name = Get-AuditSam $t
        $attr = 0
        try { $attr = [int](Get-AuditAttr $t "trustAttributes") } catch { }
        $dir = Get-AuditAttr $t "trustDirection"
        $inventory += "$name (direction=$dir, attributes=$attr)"
        # TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x00000004
        # TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x00000010 (selective auth)
        # TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL = 0x00000040
        # TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION = 0x00000080
        # TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION = 0x00000200
        # TRUST_ATTRIBUTE_PIM_TRUST = 0x00000400
        $quarantine = ($attr -band 0x4) -eq 0x4
        $noTgt = ($attr -band 0x200) -eq 0x200
        $withinForest = ($attr -band 0x20) -eq 0x20
        if (-not $quarantine -and -not $withinForest) { $noFilter += "$name (trustAttributes=$attr)" }
        if (-not $noTgt -and -not $withinForest) { $tgtDeleg += "$name" }
        if (($attr -band 0x40) -eq 0x40) { $sidHistory += "$name (treat as external / SID history related flags)" }
        if (($attr -band 0x80) -eq 0x80) { $rc4Trust += "$name (TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION)" }
    }

    if ($noFilter.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-TRST-001" -Category $category -Subcategory "SID Filtering" `
            -Title "Trusts without SID Filtering / quarantine" `
            -Description "Without quarantine, a trusted domain can inject SID History and elevate in this domain." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $noFilter.Count `
            -AffectedObjects $noFilter -Evidence $noFilter `
            -Recommendation "Enable SID Filtering: netdom trust Trusting /domain:Trusted /quarantine:yes (understand app impact first)." `
            -MicrosoftReference "https://learn.microsoft.com/en-us/defender-for-identity/configure-sid-filtering" `
            -MitreTechnique "T1134.005" -DataSource "trustAttributes"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-TRST-001" -Category $category -Subcategory "SID Filtering" `
            -Title "External trusts appear quarantined or are intra-forest" `
            -Description "No extra-forest trustedDomain lacked the quarantine bit." `
            -Severity "Informational" -Status "Passed" -DataSource "trustAttributes"))
    }

    if ($tgtDeleg.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-TRST-002" -Category $category -Subcategory "TGT Delegation" `
            -Title "Forest/external trusts allow TGT delegation" `
            -Description "Missing CROSS_ORGANIZATION_NO_TGT_DELEGATION means Kerberos delegation may follow the trust." `
            -Severity "Medium" -Status "Failed" -RiskScore 8 -AffectedCount $tgtDeleg.Count `
            -AffectedObjects $tgtDeleg -Evidence $tgtDeleg `
            -Recommendation "Disable TGT delegation on the trust unless a documented cross-forest app requires it." `
            -DataSource "trustAttributes"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-TRST-002" -Category $category -Subcategory "TGT Delegation" `
            -Title "TGT delegation is restricted on extra-forest trusts" `
            -Description "No extra-forest trust was missing the no-TGT-delegation attribute." `
            -Severity "Informational" -Status "Passed" -DataSource "trustAttributes"))
    }

    Add-AuditCheckResult -Findings $findings -CheckId "AD-TRST-004" -Category $category -Subcategory "Encryption" `
        -FailTitle "Trusts still allow RC4 encryption" `
        -PassTitle "No trusts have TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION" `
        -FailDescription "RC4 on a trust weakens Kerberos across the trust boundary and is a Kerberoast/downgrade concern." `
        -Items $rc4Trust -Severity "Medium" -RiskScore 8 `
        -Recommendation "Remove RC4 from the trust and require AES. Coordinate with the trusted forest before changing trustAttributes." `
        -MitreTechnique "T1558.003" -DataSource "trustAttributes"

    Add-AuditCheckResult -Findings $findings -CheckId "AD-TRST-006" -Category $category -Subcategory "SID History" `
        -FailTitle "Trusts are flagged TREAT_AS_EXTERNAL" `
        -PassTitle "No trust is flagged TREAT_AS_EXTERNAL" `
        -FailDescription "TREAT_AS_EXTERNAL makes an intra-forest trust behave like an external one for SID filtering decisions, which changes how SID history from the other side is honoured and is easy to misconfigure." `
        -Items $sidHistory -Severity "Medium" -RiskScore 8 -FailStatus "Warning" `
        -Recommendation "Confirm the flag was set deliberately during a forest consolidation and remove it afterwards." `
        -MitreTechnique "T1134.005" -DataSource "trustAttributes"

    # The trust account password should rotate on the normal 30-day schedule; a very old
    # password means rotation is broken or the trust is abandoned.
    $staleTrustPasswords = New-Object System.Collections.Generic.List[string]
    foreach ($t in $trusts) {
        $flat = [string](Get-AuditAttr $t "flatName")
        if (-not $flat) { continue }
        $account = @(Search-AuditDirectory -LdapFilter "(&(objectClass=user)(sAMAccountName=$(Format-AuditLdapFilterValue "$flat`$")))" -Properties @("sAMAccountName", "pwdLastSet"))
        if ($account.Count -eq 0) { continue }
        $set = Convert-AuditFileTime (Get-AuditAttr $account[0] "pwdLastSet")
        if (-not $set) { continue }
        $days = [int][math]::Round(((Get-Date) - $set).TotalDays)
        if ($days -gt $maxTrustPasswordAge) {
            [void]$staleTrustPasswords.Add("$flat`$ - trust password $days days old (pwdLastSet=$set)")
        }
    }
    Add-AuditCheckResult -Findings $findings -CheckId "AD-TRST-005" -Category $category -Subcategory "Trust Credentials" `
        -FailTitle "Trust account passwords are older than $maxTrustPasswordAge days" `
        -PassTitle "Trust account passwords are within the age threshold" `
        -FailDescription "Windows rotates inter-domain trust passwords roughly every 30 days. A password that has not changed in over a year means rotation is failing or the trust is unused, and the trust key can be used to forge inter-realm tickets." `
        -PassDescription "Every resolvable trust account password is within the threshold." `
        -Items @($staleTrustPasswords) -Severity "Medium" -RiskScore 8 `
        -Recommendation "Validate replication and trust health, or delete trusts that are no longer required." `
        -MitreTechnique "T1558" -DataSource "trust account pwdLastSet"

    [void]$findings.Add((New-AuditFinding -CheckId "AD-TRST-003" -Category $category -Subcategory "Inventory" `
        -Title "Trust inventory ($($trusts.Count))" `
        -Description "Enumerated $($trusts.Count) trustedDomain object(s)." `
        -Severity "Informational" -Status "Informational" -AffectedCount $trusts.Count `
        -AffectedObjects $inventory -Evidence $inventory -DataSource "trustedDomain"))

    return $findings
}

Export-ModuleMember -Function Invoke-TrustsAudit
