# PasswordAuthentication.psm1 - Domain password policy and FGPP

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-PasswordAuthenticationAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "Password and Authentication Security"
    $session = Get-AuditDirectorySession
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-PWD-000" -Category $category))
        return $findings
    }

    $minLen = 14; $minHist = 24
    if ($Config.MinPasswordLength) { $minLen = [int]$Config.MinPasswordLength }
    if ($Config.MinPasswordHistory) { $minHist = [int]$Config.MinPasswordHistory }

    try {
        $policy = $null
        if ($session.Provider -eq "ActiveDirectory") {
            $ad = $session.AdParams
            $policy = Get-ADDefaultDomainPasswordPolicy @ad -ErrorAction Stop
            $length = [int]$policy.MinPasswordLength
            $history = [int]$policy.PasswordHistoryCount
            $complexity = [bool]$policy.ComplexityEnabled
            $lockout = [int]$policy.LockoutThreshold
            $reversible = [bool]$policy.ReversibleEncryptionEnabled
            $maxAgeDays = [int]$policy.MaxPasswordAge.TotalDays
        } else {
            $dom = Search-AuditDirectory -LdapFilter "(objectClass=domainDNS)" -SearchBase $session.DefaultNamingContext -Scope Base -Properties @(
                "minPwdLength", "pwdHistoryLength", "pwdProperties", "lockoutThreshold", "maxPwdAge"
            )
            $o = $dom[0]
            $length = [int](Get-AuditAttr $o "minPwdLength")
            $history = [int](Get-AuditAttr $o "pwdHistoryLength")
            $pwdProp = [int](Get-AuditAttr $o "pwdProperties")
            $complexity = ($pwdProp -band 1) -eq 1
            $reversible = ($pwdProp -band 16) -eq 16
            $lockout = [int](Get-AuditAttr $o "lockoutThreshold")
            $maxAgeRaw = Get-AuditAttr $o "maxPwdAge"
            $maxAgeDays = 0
            if ($maxAgeRaw) {
                try { $maxAgeDays = [int]((-1 * [int64]$maxAgeRaw) / 864000000000) } catch { $maxAgeDays = 0 }
            }
        }

        $weak = ($length -lt $minLen) -or ($history -lt $minHist) -or (-not $complexity) -or ($lockout -eq 0)
        $evidence = @(
            "MinPasswordLength=$length (baseline >= $minLen)",
            "PasswordHistory=$history (baseline >= $minHist)",
            "ComplexityEnabled=$complexity",
            "LockoutThreshold=$lockout (0 = no lockout)",
            "MaxPasswordAgeDays=$maxAgeDays"
        )
        if ($weak) {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-PWD-001" -Category $category -Subcategory "Domain Policy" `
                -Title "Default domain password policy is below baseline" `
                -Description "Length $length, history $history, complexity $complexity, lockout $lockout." `
                -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount 1 `
                -AffectedObjects @("Default Domain Password Policy") -Evidence $evidence `
                -Recommendation "Set minimum length $minLen+, history $minHist, complexity on, and a lockout threshold of 5–10 with a sensible duration." `
                -MicrosoftReference "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy" `
                -MitreTechnique "T1110.001" -DataSource "domainDNS policy"))
        } else {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-PWD-001" -Category $category -Subcategory "Domain Policy" `
                -Title "Default domain password policy meets baseline" `
                -Description "Length $length, history $history, lockout $lockout." `
                -Severity "Informational" -Status "Passed" -Evidence $evidence -DataSource "domainDNS policy"))
        }

        if ($reversible) {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-PWD-002" -Category $category -Subcategory "Credential Storage" `
                -Title "Reversible encryption is enabled in domain policy" `
                -Description "Store passwords using reversible encryption is enabled. Secrets can be recovered if the database is copied." `
                -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount 1 `
                -AffectedObjects @($session.DefaultNamingContext) -Evidence @("ReversibleEncryptionEnabled / pwdProperties bit 16") `
                -Recommendation "Disable reversible encryption in the Default Domain Policy." `
                -MitreTechnique "T1552" -DataSource "pwdProperties"))
        } else {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-PWD-002" -Category $category -Subcategory "Credential Storage" `
                -Title "Domain policy does not enable reversible encryption" `
                -Description "Reversible encryption is not set at the domain policy level." `
                -Severity "Informational" -Status "Passed" -DataSource "pwdProperties"))
        }

        if ($maxAgeDays -eq 0) {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-PWD-004" -Category $category -Subcategory "Domain Policy" `
                -Title "Maximum password age is 0 (passwords never expire at policy level)" `
                -Description "A zero maximum password age disables expiration for accounts that follow the domain policy." `
                -Severity "Medium" -Status "Failed" -RiskScore 8 -AffectedCount 1 `
                -Evidence @("maxPwdAge/MaxPasswordAge = 0") `
                -Recommendation "Set a maximum password age or enforce expiration via FGPP for human accounts; use gMSA for services." `
                -DataSource "maxPwdAge"))
        } else {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-PWD-004" -Category $category -Subcategory "Domain Policy" `
                -Title "Maximum password age is $maxAgeDays days" `
                -Description "Domain policy defines a finite password age." `
                -Severity "Informational" -Status "Passed" -DataSource "maxPwdAge"))
        }
    } catch {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-PWD-001" -Category $category -Title "Password policy check failed" -Description $_.Exception.Message -Severity "Medium" -Status "Error"))
    }

    $fgpp = @(Search-AuditDirectory -LdapFilter "(objectClass=msDS-PasswordSettings)" -SearchBase $session.DefaultNamingContext -Properties @(
            "name", "msDS-MinimumPasswordLength", "msDS-PasswordSettingsPrecedence", "msDS-PasswordHistoryLength",
            "msDS-LockoutThreshold", "msDS-PasswordComplexityEnabled"
        ))
    if ($fgpp.Count -gt 0) {
        $names = @($fgpp | ForEach-Object { "$(Get-AuditSam $_)" })
        [void]$findings.Add((New-AuditFinding -CheckId "AD-PWD-005" -Category $category -Subcategory "FGPP" `
            -Title "Fine-grained password policies are present ($($fgpp.Count))" `
            -Description "PSO objects override the default domain policy for linked groups/users. Weak PSOs can silently lower requirements for admins." `
            -Severity "Informational" -Status "Warning" -RiskScore 3 -AffectedCount $fgpp.Count `
            -AffectedObjects $names -Evidence $names `
            -Recommendation "Review each PSO for length, lockout, and who it applies to (especially Domain Admins)." `
            -DataSource "msDS-PasswordSettings"))
        $weakPso = New-Object System.Collections.Generic.List[string]
        foreach ($p in $fgpp) {
            $pLen = 0; $pHist = 0; $pLock = 0; $pComp = $true
            try { $pLen = [int](Get-AuditAttr $p "msDS-MinimumPasswordLength") } catch { }
            try { $pHist = [int](Get-AuditAttr $p "msDS-PasswordHistoryLength") } catch { }
            try { $pLock = [int](Get-AuditAttr $p "msDS-LockoutThreshold") } catch { }
            $rawComp = Get-AuditAttr $p "msDS-PasswordComplexityEnabled"
            if ($null -ne $rawComp -and "$rawComp" -match "FALSE|False|0") { $pComp = $false }
            if ($pLen -lt $minLen -or $pHist -lt $minHist -or $pLock -eq 0 -or -not $pComp) {
                [void]$weakPso.Add("$(Get-AuditSam $p) len=$pLen hist=$pHist lockout=$pLock complexity=$pComp")
            }
        }
        Add-AuditCheckResult -Findings $findings -CheckId "AD-PWD-006" -Category $category -Subcategory "FGPP" `
            -FailTitle "Fine-grained password policies are weaker than baseline" `
            -PassTitle "Fine-grained password policies meet length/history/lockout baseline" `
            -FailDescription "A PSO that is weaker than the domain baseline can be linked to privileged users and silently lower password quality." `
            -Items @($weakPso) -Severity "High" -RiskScore 15 `
            -Recommendation "Raise every PSO to at least the domain baseline, especially those applied to administrators." `
            -MitreTechnique "T1110.001" -DataSource "msDS-PasswordSettings"
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-PWD-005" -Category $category -Subcategory "FGPP" `
            -Title "No fine-grained password policies found" `
            -Description "Only the default domain policy applies." `
            -Severity "Informational" -Status "Passed" -DataSource "msDS-PasswordSettings"))
    }

    return $findings
}

Export-ModuleMember -Function Invoke-PasswordAuthenticationAudit
