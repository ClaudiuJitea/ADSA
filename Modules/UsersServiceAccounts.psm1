# UsersServiceAccounts.psm1 - User hygiene, Kerberoast, credential disclosure

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-UsersServiceAccountsAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [int]$InactiveDays = 90,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "Users and Service Accounts"
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-USR-000" -Category $category))
        return $findings
    }

    $users = @(Search-AuditDirectory -LdapFilter "(&(objectCategory=person)(objectClass=user))" -Properties @(
            "sAMAccountName", "userAccountControl", "lastLogonTimestamp", "pwdLastSet", "servicePrincipalName",
            "description", "info", "sidHistory", "adminCount", "msDS-SupportedEncryptionTypes", "distinguishedName",
            "objectSid", "primaryGroupID", "msDS-KeyCredentialLink", "userPassword", "unixUserPassword", "userWorkstations"
        ))

    $neverExpire = New-Object System.Collections.Generic.List[string]
    $pwdNotReq = New-Object System.Collections.Generic.List[string]
    $inactive = New-Object System.Collections.Generic.List[string]
    $spnUsers = New-Object System.Collections.Generic.List[string]
    $descriptionLeak = New-Object System.Collections.Generic.List[string]
    $generic = New-Object System.Collections.Generic.List[string]
    $sidHistory = New-Object System.Collections.Generic.List[string]
    $reversible = New-Object System.Collections.Generic.List[string]
    $kerberoast = New-Object System.Collections.Generic.List[string]
    $pwdNeverSet = New-Object System.Collections.Generic.List[string]
    $orphanedAdminCount = New-Object System.Collections.Generic.List[string]
    $badPrimary = New-Object System.Collections.Generic.List[string]
    $keyCredentials = New-Object System.Collections.Generic.List[string]
    $legacyPasswordAttributes = New-Object System.Collections.Generic.List[string]
    $rid500 = $null
    $inactiveThreshold = (Get-Date).AddDays(-$InactiveDays)
    $genericNames = @("admin", "administrator", "test", "guest", "temp", "scanner", "backup", "sql", "service", "user", "support")
    $secretPattern = "pass(word)?|pwd|secret|cred|key=|pwd="
    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins", "Account Operators", "Backup Operators")
    $privilegedSams = @{}
    foreach ($gName in $privilegedGroups) {
        $g = Find-AuditGroup -Name $gName
        if (-not $g) { continue }
        foreach ($m in @(Get-AuditGroupMembers -GroupDn (Get-AuditAttr $g "distinguishedName") -Recursive)) {
            $privilegedSams[(Get-AuditSam $m)] = $true
        }
    }

    foreach ($u in $users) {
        $sam = Get-AuditSam $u
        $uac = Get-AuditAttr $u "userAccountControl"
        $sid = ConvertTo-AuditSidString (Get-AuditAttr $u "objectSid")
        if ($sid -match '-500$') {
            $rid500 = [PSCustomObject]@{
                Sam        = $sam
                Sid        = $sid
                Uac        = $uac
                PwdLastSet = (Convert-AuditFileTime (Get-AuditAttr $u "pwdLastSet"))
                LastLogon  = (Convert-AuditFileTime (Get-AuditAttr $u "lastLogonTimestamp"))
            }
        }
        $enabled = -not (Test-AuditUacFlag $uac 0x0002)
        if (-not $enabled) { continue }
        if ($sam -in @("krbtgt", "Guest")) { continue }

        if (Test-AuditUacFlag $uac 0x10000) { [void]$neverExpire.Add($sam) }
        if (Test-AuditUacFlag $uac 0x0020) { [void]$pwdNotReq.Add($sam) }
        if (Test-AuditUacFlag $uac 0x0080) { [void]$reversible.Add($sam) }

        $last = Convert-AuditFileTime (Get-AuditAttr $u "lastLogonTimestamp")
        if ($last -and $last -lt $inactiveThreshold) { [void]$inactive.Add("$sam (Last logon: $last)") }

        $rawPwd = Get-AuditAttr $u "pwdLastSet"
        if ($rawPwd -eq 0 -or $rawPwd -eq "0") { [void]$pwdNeverSet.Add($sam) }

        $spn = @((Get-AuditAttr $u "servicePrincipalName") | Where-Object { $_ })
        if ($spn.Count -gt 0) {
            [void]$spnUsers.Add($sam)
            $enc = Get-AuditAttr $u "msDS-SupportedEncryptionTypes"
            $encLabel = if ($enc) { "msDS-SupportedEncryptionTypes=$enc" } else { "default/RC4 likely" }
            [void]$kerberoast.Add("$sam ($encLabel; SPN=$($spn[0]))")
        }

        $desc = "$(Get-AuditAttr $u 'description') $(Get-AuditAttr $u 'info')"
        if ($desc -match $secretPattern) { [void]$descriptionLeak.Add("$sam") }

        if ($genericNames -contains $sam.ToLowerInvariant()) { [void]$generic.Add($sam) }

        $sidh = Get-AuditAttr $u "sidHistory"
        if ($sidh) { [void]$sidHistory.Add("$sam") }

        $adminCount = Get-AuditAttr $u "adminCount"
        if ("$adminCount" -eq "1" -and -not $privilegedSams.ContainsKey($sam)) {
            [void]$orphanedAdminCount.Add($sam)
        }

        $pg = Get-AuditAttr $u "primaryGroupID"
        if ($pg -and "$pg" -ne "513") {
            [void]$badPrimary.Add("$sam (primaryGroupID=$pg)")
        }

        $keyLinks = @((Get-AuditAttr $u "msDS-KeyCredentialLink") | Where-Object { $_ })
        if ($keyLinks.Count -gt 0) {
            [void]$keyCredentials.Add("$sam ($($keyLinks.Count) key credential link(s))")
        }

        foreach ($attrName in @("userPassword", "unixUserPassword")) {
            $legacy = @((Get-AuditAttr $u $attrName) | Where-Object { $_ })
            if ($legacy.Count -gt 0) { [void]$legacyPasswordAttributes.Add("$sam ($attrName is populated)") }
        }
    }

    function Add-UserCheck {
        param($List, $Id, $Sub, $FailTitle, $PassTitle, $FailDesc, $Items, $Sev, $Score, $Rec, $Mitre)
        if ($Items.Count -gt 0) {
            [void]$List.Add((New-AuditFinding -CheckId $Id -Category $script:categoryInner -Subcategory $Sub `
                    -Title $FailTitle -Description $FailDesc -Severity $Sev -Status "Failed" -RiskScore $Score `
                    -AffectedCount $Items.Count -AffectedObjects (Limit-AuditObjects $Items) -Evidence $Items `
                    -Recommendation $Rec -MitreTechnique $Mitre -DataSource "user"))
        } else {
            [void]$List.Add((New-AuditFinding -CheckId $Id -Category $script:categoryInner -Subcategory $Sub `
                    -Title $PassTitle -Description "No matching enabled user objects were found." `
                    -Severity "Informational" -Status "Passed" -DataSource "user"))
        }
    }

    $script:categoryInner = $category
    Add-UserCheck $findings "AD-USR-001" "Password Hygiene" "Enabled users with Password Never Expires" "No enabled users have Password Never Expires" "Found $($neverExpire.Count) enabled account(s) that never rotate passwords." $neverExpire "High" 15 "Clear DONT_EXPIRE_PASSWORD on human accounts; use gMSA or managed rotation for services." "T1078"
    Add-UserCheck $findings "AD-USR-002" "Account Flags" "Accounts with Password Not Required" "No PASSWD_NOTREQD accounts" "PASSWD_NOTREQD allows blank passwords." $pwdNotReq "Critical" 25 "Clear PASSWD_NOTREQD (UAC 0x20) on every account." "T1078"
    Add-UserCheck $findings "AD-USR-003" "Lifecycle" "Enabled users inactive for over $InactiveDays days" "No inactive enabled users" "Stale enabled accounts are persistence and password-spray inventory." $inactive "High" 15 "Disable or delete unused accounts after an owner review." "T1078.003"
    Add-UserCheck $findings "AD-USR-004" "Service Accounts" "User objects with SPNs (gMSA candidates)" "No traditional user SPNs" "User accounts with SPNs are Kerberoast targets and should usually be gMSA." $spnUsers "Medium" 8 "Migrate static-password service accounts to gMSA." "T1558.003"
    Add-UserCheck $findings "AD-USR-005" "Information Disclosure" "Possible secrets in Description or Notes" "No password-like keywords in descriptions" "Description/info attributes are readable by most domain users." $descriptionLeak "High" 15 "Strip credentials from directory attributes and rotate any exposed secret." "T1552.001"
    Add-UserCheck $findings "AD-USR-006" "Naming" "Generic enabled account names" "No generic enabled account names" "Generic names are predictable spray targets." $generic "Medium" 8 "Rename or disable generic accounts." "T1078"
    Add-UserCheck $findings "AD-USR-007" "SID History" "Enabled users with SID History" "No SID History on enabled users" "SID History is a legitimate migration tool and a SID-injection persistence primitive." $sidHistory "High" 15 "Clear stale sidHistory after migrations; keep SID filtering on trusts." "T1134.005"
    Add-UserCheck $findings "AD-USR-008" "Credential Protection" "Reversible password encryption on users" "No reversible encryption user flags" "ENCRYPTED_TEXT_PWD_ALLOWED stores a reversible secret." $reversible "Critical" 25 "Disable reversible encryption and force a password change." "T1552"
    Add-UserCheck $findings "AD-USR-009" "Kerberoasting" "Kerberoastable user accounts" "No Kerberoastable user SPNs" "Any authenticated user can request a TGS for these SPNs and crack it offline." $kerberoast "High" 15 "Use AES-only encryption, long gMSA passwords, and remove unused SPNs." "T1558.003"
    Add-UserCheck $findings "AD-USR-010" "Password State" "Enabled users that have never set a password" "No pwdLastSet=0 enabled users" "pwdLastSet=0 often means the account can be used with an initial or blank password depending on flags." $pwdNeverSet "High" 15 "Set a password or disable accounts that have never been activated." "T1078"
    Add-UserCheck $findings "AD-USR-011" "AdminSDHolder" "Orphaned adminCount=1 users" "No orphaned adminCount=1 users" "adminCount=1 remains after leaving privileged groups; SDProp no longer resets the ACL, leaving a stale protected/orphan state." $orphanedAdminCount "Medium" 8 "Clear adminCount and restore a normal ACL, or put the account back under AdminSDHolder on purpose." "T1484"
    Add-UserCheck $findings "AD-USR-014" "Shadow Credentials" "Enabled users with key credential links" "No key credential links on enabled users" "msDS-KeyCredentialLink lets the holder of the matching private key authenticate as the account through PKINIT. Windows Hello for Business writes it legitimately; on accounts that do not use WHfB it is shadow-credential persistence." $keyCredentials "Medium" 8 "Match every key credential to an enrolled Windows Hello device and clear the rest. Restrict who can write msDS-KeyCredentialLink." "T1556"
    Add-UserCheck $findings "AD-USR-015" "Credential Exposure" "Users with legacy password attributes populated" "No userPassword or unixUserPassword values" "userPassword and unixUserPassword hold credentials that are frequently readable by ordinary domain users, unlike unicodePwd which is never returned." $legacyPasswordAttributes "Critical" 25 "Clear the attribute, rotate the exposed credential, and use the directory password instead of an attribute copy." "T1552.001"
    Add-UserCheck $findings "AD-USR-013" "Primary Group" "Enabled users with a non-standard primary group" "User primary groups look standard" "Changing primaryGroupID hides membership from the member attribute and is a known stealth persistence technique." $badPrimary "High" 15 "Reset primaryGroupID to 513 (Domain Users) unless a documented exception exists." "T1098"

    if ($rid500) {
        $days = if ($rid500.PwdLastSet) { [int][math]::Round(((Get-Date) - $rid500.PwdLastSet).TotalDays) } else { -1 }
        $renamed = $rid500.Sam -ne "Administrator"
        $evidence = @("sAMAccountName=$($rid500.Sam)", "objectSid=$($rid500.Sid)", "pwdLastSet=$($rid500.PwdLastSet)", "lastLogon=$($rid500.LastLogon)", "renamed=$renamed")
        $oldPwd = ($days -ge 0 -and $days -gt 180)
        if ($oldPwd -or -not $renamed) {
            $title = if ($oldPwd) { "Built-in RID-500 Administrator password is $days days old" } else { "Built-in RID-500 account is still named Administrator" }
            [void]$findings.Add((New-AuditFinding -CheckId "AD-USR-012" -Category $category -Subcategory "Built-in Administrator" `
                    -Title $title `
                    -Description "RID-500 is the irremovable built-in administrator. A well-known name plus a stale password is a high-value break-glass target. Renaming does not change the RID." `
                    -Severity "Medium" -Status $(if ($oldPwd) { "Failed" } else { "Warning" }) -RiskScore 8 -AffectedCount 1 `
                    -AffectedObjects @($rid500.Sam) -Evidence $evidence `
                    -Recommendation "Treat RID-500 as break-glass: unique long password, vaulted use, and optionally rename it. Rotate at least as often as krbtgt." `
                    -MitreTechnique "T1078.001" -DataSource "objectSid RID 500"))
        } else {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-USR-012" -Category $category -Subcategory "Built-in Administrator" `
                    -Title "RID-500 Administrator is renamed and recently rotated" `
                    -Description "Built-in administrator sAMAccountName=$($rid500.Sam), password age $days days." `
                    -Severity "Informational" -Status "Passed" -Evidence $evidence -DataSource "objectSid RID 500"))
        }
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-USR-012" -Category $category -Subcategory "Built-in Administrator" `
                -Title "RID-500 Administrator was not found" `
                -Description "No user objectSid ending in -500 was returned. This can happen if objectSid is not readable." `
                -Severity "Low" -Status "Not Tested" -DataSource "objectSid RID 500"))
    }

    return $findings
}

Export-ModuleMember -Function Invoke-UsersServiceAccountsAudit
