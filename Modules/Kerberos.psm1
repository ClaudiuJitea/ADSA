# Kerberos.psm1 - krbtgt, AS-REP, encryption, Kerberoast

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-KerberosAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [int]$KrbtgtWarningDays = 180,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "Kerberos Configuration"
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-KERB-000" -Category $category))
        return $findings
    }

    $krbtgt = Search-AuditDirectory -LdapFilter "(&(objectClass=user)(sAMAccountName=krbtgt))" -Properties @("sAMAccountName", "pwdLastSet", "userAccountControl")
    if ($krbtgt) {
        $set = Convert-AuditFileTime (Get-AuditAttr $krbtgt[0] "pwdLastSet")
        if ($set) {
            $days = [int][math]::Round(((Get-Date) - $set).TotalDays)
            if ($days -gt $KrbtgtWarningDays) {
                [void]$findings.Add((New-AuditFinding -CheckId "AD-KERB-001" -Category $category -Subcategory "krbtgt" `
                    -Title "krbtgt password is $days days old" `
                    -Description "A stolen krbtgt hash forges Golden Tickets until the password is rotated twice with replication in between." `
                    -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount 1 `
                    -AffectedObjects @("krbtgt") -Evidence @("pwdLastSet=$set ($days days)") `
                    -Recommendation "Rotate krbtgt twice using Microsoft's Reset-KrbTgtPassword script, with a replication delay between attempts." `
                    -MicrosoftReference "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password" `
                    -MitreTechnique "T1558.001" -DataSource "krbtgt"))
            } else {
                [void]$findings.Add((New-AuditFinding -CheckId "AD-KERB-001" -Category $category -Subcategory "krbtgt" `
                    -Title "krbtgt password age is $days days" `
                    -Description "Password age is within the $KrbtgtWarningDays-day warning threshold." `
                    -Severity "Informational" -Status "Passed" -DataSource "krbtgt"))
            }
        }
    }

    $asrep = @()
    $weakEnc = @()
    $users = @(Search-AuditDirectory -LdapFilter "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" -Properties @("sAMAccountName", "userAccountControl", "msDS-SupportedEncryptionTypes", "servicePrincipalName"))
    foreach ($u in $users) {
        $sam = Get-AuditSam $u
        $uac = Get-AuditAttr $u "userAccountControl"
        if (Test-AuditUacFlag $uac 0x400000) { $asrep += $sam }
        if (Test-AuditUacFlag $uac 0x200000) { $weakEnc += "$sam (USE_DES_KEY_ONLY)" }
        $enc = Get-AuditAttr $u "msDS-SupportedEncryptionTypes"
        if ($enc -ne $null -and $enc -ne "") {
            try {
                $e = [int]$enc
                $hasAes = (($e -band 8) -eq 8) -or (($e -band 16) -eq 16)
                $hasRc4 = ($e -band 4) -eq 4
                $spn = Get-AuditAttr $u "servicePrincipalName"
                if ($spn -and $hasRc4 -and -not $hasAes) { $weakEnc += "$sam (RC4-only supported types=$e)" }
            } catch { }
        }
    }

    if ($asrep.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-KERB-002" -Category $category -Subcategory "AS-REP Roasting" `
            -Title "Users do not require Kerberos pre-authentication" `
            -Description "DONT_REQ_PREAUTH lets anyone request an encrypted blob and crack it offline (AS-REP roasting)." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $asrep.Count `
            -AffectedObjects (Limit-AuditObjects $asrep) -Evidence $asrep `
            -Recommendation "Clear 'Do not require Kerberos preauthentication' on every account." `
            -MitreTechnique "T1558.004" -DataSource "userAccountControl"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-KERB-002" -Category $category -Subcategory "AS-REP Roasting" `
            -Title "No AS-REP roastable users detected" `
            -Description "No enabled users had DONT_REQ_PREAUTH." `
            -Severity "Informational" -Status "Passed" -DataSource "userAccountControl"))
    }

    if ($weakEnc.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-KERB-003" -Category $category -Subcategory "Encryption" `
            -Title "Accounts allow DES or RC4-only Kerberos" `
            -Description "DES and RC4 Kerberos are weaker than AES. RC4 TGS tickets are the usual Kerberoast target." `
            -Severity "Medium" -Status "Failed" -RiskScore 8 -AffectedCount $weakEnc.Count `
            -AffectedObjects (Limit-AuditObjects $weakEnc) -Evidence $weakEnc `
            -Recommendation "Enable AES128/AES256 (msDS-SupportedEncryptionTypes) and disable DES. Prefer AES-only for service accounts." `
            -MitreTechnique "T1558.003" -DataSource "msDS-SupportedEncryptionTypes"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-KERB-003" -Category $category -Subcategory "Encryption" `
            -Title "No DES/RC4-only user encryption flags detected" `
            -Description "No enabled users were flagged USE_DES_KEY_ONLY or RC4-only supported types with an SPN." `
            -Severity "Informational" -Status "Passed" -DataSource "encryption types"))
    }

    # Domain Controllers and krbtgt must support AES: their supported encryption types
    # determine the strength of every ticket, including the TGT itself.
    $aesGaps = New-Object System.Collections.Generic.List[string]
    $kerberosPrincipals = @(Search-AuditDirectory -LdapFilter "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -Properties @("dNSHostName", "name", "sAMAccountName", "msDS-SupportedEncryptionTypes"))
    $kerberosPrincipals += @(Search-AuditDirectory -LdapFilter "(&(objectClass=user)(sAMAccountName=krbtgt*))" -Properties @("sAMAccountName", "msDS-SupportedEncryptionTypes"))
    foreach ($principal in $kerberosPrincipals) {
        $label = Get-AuditAttr $principal "dNSHostName"
        if (-not $label) { $label = Get-AuditSam $principal }
        $enc = Get-AuditAttr $principal "msDS-SupportedEncryptionTypes"
        if ($null -eq $enc -or "$enc" -eq "") { continue }
        try {
            $value = [int]$enc
            $hasAes = (($value -band 8) -eq 8) -or (($value -band 16) -eq 16)
            if (-not $hasAes) { [void]$aesGaps.Add("$label (msDS-SupportedEncryptionTypes=$value, no AES)") }
        } catch { }
    }
    Add-AuditCheckResult -Findings $findings -CheckId "AD-KERB-005" -Category $category -Subcategory "Domain Controller Encryption" `
        -FailTitle "Domain Controllers or krbtgt do not advertise AES" `
        -PassTitle "Domain Controllers and krbtgt advertise AES encryption" `
        -FailDescription "When a Domain Controller or the krbtgt account has msDS-SupportedEncryptionTypes set without the AES bits, tickets fall back to RC4. That keeps offline ticket cracking cheap and blocks the removal of RC4 from the domain." `
        -PassDescription "Every Domain Controller and krbtgt account that publishes supported encryption types includes AES128 or AES256." `
        -Items @($aesGaps) -Severity "High" -RiskScore 15 `
        -Recommendation "Set msDS-SupportedEncryptionTypes to include AES128 (8) and AES256 (16) on Domain Controllers and krbtgt, then plan RC4 removal via the Network security: Configure encryption types policy." `
        -MicrosoftReference "https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/decrypting-the-selection-of-supported-kerberos-encryption-types" `
        -MitreTechnique "T1558.003" -DataSource "msDS-SupportedEncryptionTypes"

    $spnMap = @{}
    $dupSpn = New-Object System.Collections.Generic.List[string]
    $acct = @(Search-AuditDirectory -LdapFilter "(|(objectClass=user)(objectClass=computer))" -Properties @("sAMAccountName", "servicePrincipalName"))
    foreach ($o in $acct) {
        $sam = Get-AuditSam $o
        foreach ($spn in @((Get-AuditAttr $o "servicePrincipalName") | Where-Object { $_ })) {
            $key = [string]$spn
            if (-not $spnMap.ContainsKey($key)) { $spnMap[$key] = New-Object System.Collections.Generic.List[string] }
            [void]$spnMap[$key].Add($sam)
        }
    }
    foreach ($key in $spnMap.Keys) {
        $owners = @($spnMap[$key] | Select-Object -Unique)
        if ($owners.Count -gt 1) { [void]$dupSpn.Add("$key => $($owners -join ', ')") }
    }
    Add-AuditCheckResult -Findings $findings -CheckId "AD-KERB-004" -Category $category -Subcategory "SPN Uniqueness" `
        -FailTitle "Duplicate Service Principal Names detected" `
        -PassTitle "No duplicate SPNs detected" `
        -FailDescription "Kerberos requires unique SPNs. Duplicates cause authentication failures and can be abused to steal tickets intended for another service." `
        -Items @($dupSpn) -Severity "High" -RiskScore 15 `
        -Recommendation "Remove or rename duplicate SPNs (setspn -X). Keep one owner per SPN." `
        -MitreTechnique "T1558" -DataSource "servicePrincipalName"

    return $findings
}

Export-ModuleMember -Function Invoke-KerberosAudit
