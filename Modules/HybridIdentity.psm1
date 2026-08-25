# HybridIdentity.psm1 - Entra Connect, AZUREADSSOACC, ADFS, sync accounts

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-HybridIdentityAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "Hybrid Identity"
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-HYB-000" -Category $category))
        return $findings
    }

    $users = @(Search-AuditDirectory -LdapFilter "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=MSOL_*)(sAMAccountName=Sync_*)(sAMAccountName=AAD_*)(sAMAccountName=AZUREADSSOACC)))" -Properties @("sAMAccountName", "userAccountControl", "servicePrincipalName", "description", "adminCount", "pwdLastSet"))
    $ssoComputers = @(Search-AuditDirectory -LdapFilter "(&(objectClass=computer)(sAMAccountName=AZUREADSSOACC$))" -Properties @("sAMAccountName", "name", "pwdLastSet", "userAccountControl", "servicePrincipalName"))
    $computers = @(Search-AuditDirectory -LdapFilter "(&(objectClass=computer)(|(servicePrincipalName=http/adfs*)(servicePrincipalName=host/adfs*)(name=*ADFS*)(name=*AADCONNECT*)(name=*ADCONNECT*)))" -Properties @("name", "servicePrincipalName", "operatingSystem", "userAccountControl"))

    $sso = @($users | Where-Object { (Get-AuditSam $_) -eq "AZUREADSSOACC" } | ForEach-Object { Get-AuditSam $_ })
    $sso += @($ssoComputers | ForEach-Object { Get-AuditSam $_ })
    $sso = @($sso | Select-Object -Unique)
    $msol = @($users | Where-Object { (Get-AuditSam $_) -like "MSOL_*" -or (Get-AuditSam $_) -like "Sync_*" -or (Get-AuditSam $_) -like "AAD_*" } | ForEach-Object {
            $sam = Get-AuditSam $_
            $uac = Get-AuditAttr $_ "userAccountControl"
            $pwd = Convert-AuditFileTime (Get-AuditAttr $_ "pwdLastSet")
            "$sam (pwdLastSet=$pwd, DONT_EXPIRE=$(Test-AuditUacFlag $uac 0x10000))"
        })
    $adfs = @($computers | ForEach-Object { "$(Get-AuditSam $_) SPN=$((Get-AuditAttr $_ 'servicePrincipalName') -join ', ')" })

    if ($sso.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-HYB-001" -Category $category -Subcategory "Seamless SSO" `
            -Title "AZUREADSSOACC computer/user is present" `
            -Description "Seamless SSO uses the AZUREADSSOACC account. Its Kerberos decryption key is a high-value hybrid persistence target (silver tickets toward Entra ID)." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $sso.Count `
            -AffectedObjects $sso -Evidence $sso `
            -Recommendation "Treat AZUREADSSOACC as Tier 0: restrict who can reset it, rotate the Kerberos decryption key on a schedule, and monitor its use." `
            -MicrosoftReference "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso-faq" `
            -MitreTechnique "T1558.002" -DataSource "user/computer"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-HYB-001" -Category $category -Subcategory "Seamless SSO" `
            -Title "AZUREADSSOACC was not found" `
            -Description "Seamless SSO account is absent (or not readable)." `
            -Severity "Informational" -Status "Passed" -DataSource "sAMAccountName"))
    }

    if ($msol.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-HYB-002" -Category $category -Subcategory "Entra Connect" `
            -Title "Entra Connect / DirSync service accounts detected" `
            -Description "MSOL_/Sync_/AAD_ accounts typically have Directory replication or high directory rights. Compromise of Connect is DCSync-equivalent plus cloud identity control." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $msol.Count `
            -AffectedObjects $msol -Evidence $msol `
            -Recommendation "Harden the Connect server as Tier 0, unique local admin, no extra software, and review DCSync-like rights for the sync account." `
            -MitreTechnique "T1098" -DataSource "user"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-HYB-002" -Category $category -Subcategory "Entra Connect" `
            -Title "No MSOL_/Sync_/AAD_ accounts found" `
            -Description "Classic Connect account naming was not present." `
            -Severity "Informational" -Status "Passed" -DataSource "user"))
    }

    if ($adfs.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-HYB-003" -Category $category -Subcategory "ADFS" `
            -Title "AD FS computers or SPNs detected" `
            -Description "AD FS is a Tier 0 identity provider. Token-signing certificates and the ADFS farm are Golden SAML targets." `
            -Severity "Medium" -Status "Warning" -RiskScore 8 -AffectedCount $adfs.Count `
            -AffectedObjects $adfs -Evidence $adfs `
            -Recommendation "Harden AD FS like a DC: PAW admin, restricted delegation, certificate protection, and DKM/WID backups." `
            -MitreTechnique "T1606.002" -DataSource "computer SPN"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-HYB-003" -Category $category -Subcategory "ADFS" `
            -Title "No AD FS SPNs/computers detected" `
            -Description "No http/adfs or ADFS-named computers were returned." `
            -Severity "Informational" -Status "Passed" -DataSource "computer"))
    }

    return $findings
}

Export-ModuleMember -Function Invoke-HybridIdentityAudit
