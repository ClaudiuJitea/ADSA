# CertificateServices.psm1 - AD CS enrollment abuse (ESC1-ESC13) and PKI object control

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-CertificateServicesAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "Certificate Services"
    $session = Get-AuditDirectorySession
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-CS-000" -Category $category))
        return $findings
    }

    $minKeySize = 2048
    if ($Config.MinCertificateKeySize) { $minKeySize = [int]$Config.MinCertificateKeySize }

    $configNc = $session.ConfigurationNamingContext
    $pkiBase = "CN=Public Key Services,CN=Services,$configNc"
    $enroll = @(Search-AuditDirectory -LdapFilter "(objectClass=pKIEnrollmentService)" -SearchBase $pkiBase -Properties @("cn", "dNSHostName", "certificateTemplates", "msPKI-Enrollment-Servers", "cACertificateDN", "distinguishedName"))
    if ($enroll.Count -eq 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-CS-001" -Category $category -Subcategory "Inventory" `
                -Title "No enterprise Certification Authorities found" `
                -Description "No pKIEnrollmentService objects exist. AD CS ESC checks do not apply." `
                -Severity "Informational" -Status "Passed" -DataSource "pKIEnrollmentService"))
        return $findings
    }

    $caNames = New-Object System.Collections.Generic.List[string]
    $httpEnroll = New-Object System.Collections.Generic.List[string]
    $published = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($ca in $enroll) {
        $cn = Get-AuditAttr $ca "cn"
        $dns = Get-AuditAttr $ca "dNSHostName"
        [void]$caNames.Add("$cn @ $dns")
        $servers = "$(Get-AuditAttr $ca 'msPKI-Enrollment-Servers')"
        if ($servers -match "http://") { [void]$httpEnroll.Add("$cn enrollment: $servers") }
        foreach ($tName in @((Get-AuditAttr $ca "certificateTemplates") | Where-Object { $_ })) {
            [void]$published.Add("$tName".ToLowerInvariant())
        }
    }

    # Issuance policy OIDs linked to a group are the ESC13 primitive.
    $oidGroupLinks = @{}
    foreach ($oid in @(Search-AuditDirectory -LdapFilter "(&(objectClass=msPKI-Enterprise-Oid)(msDS-OIDToGroupLink=*))" -SearchBase "CN=OID,$pkiBase" -Properties @("cn", "displayName", "msPKI-Cert-Template-OID", "msDS-OIDToGroupLink"))) {
        $oidValue = [string](Get-AuditAttr $oid "msPKI-Cert-Template-OID")
        $groupDn = [string](Get-AuditAttr $oid "msDS-OIDToGroupLink")
        if ($oidValue -and $groupDn) { $oidGroupLinks[$oidValue] = $groupDn }
    }

    $templates = @(Search-AuditDirectory -LdapFilter "(objectClass=pKICertificateTemplate)" -SearchBase "CN=Certificate Templates,$pkiBase" -Properties @(
            "cn", "displayName", "msPKI-Certificate-Name-Flag", "pKIExtendedKeyUsage", "msPKI-Enrollment-Flag",
            "msPKI-RA-Signature", "msPKI-Minimal-Key-Size", "msPKI-Certificate-Policy", "msPKI-Template-Schema-Version",
            "nTSecurityDescriptor", "distinguishedName"
        ))

    $esc1 = New-Object System.Collections.Generic.List[string]
    $esc2 = New-Object System.Collections.Generic.List[string]
    $esc3 = New-Object System.Collections.Generic.List[string]
    $esc4 = New-Object System.Collections.Generic.List[string]
    $esc9 = New-Object System.Collections.Generic.List[string]
    $esc13 = New-Object System.Collections.Generic.List[string]
    $weakKeys = New-Object System.Collections.Generic.List[string]
    $templateOwners = New-Object System.Collections.Generic.List[string]
    $templateAclReadable = 0

    $clientAuth = @("1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.2.3.5")
    $anyPurpose = "2.5.29.37.0"
    $requestAgent = "1.3.6.1.4.1.311.20.2.1"
    $enrollmentRightGuids = @("0e10c968-78fb-11d2-90d4-00c04f79dc55", "a05b8cc2-17bc-4802-a710-e7c15ab866a2")

    foreach ($tmpl in $templates) {
        $name = Get-AuditAttr $tmpl "cn"
        $display = Get-AuditAttr $tmpl "displayName"
        if (-not $display) { $display = $name }
        $restrictToPublished = $published.Count -gt 0
        $isPublished = (-not $restrictToPublished) -or $published.Contains("$name".ToLowerInvariant())

        $nameFlag = 0
        try { $nameFlag = [int](Get-AuditAttr $tmpl "msPKI-Certificate-Name-Flag") } catch { }
        $enrollFlag = 0
        try { $enrollFlag = [int](Get-AuditAttr $tmpl "msPKI-Enrollment-Flag") } catch { }
        $raSignatures = 0
        try { $raSignatures = [int](Get-AuditAttr $tmpl "msPKI-RA-Signature") } catch { }

        $ekus = @((Get-AuditAttr $tmpl "pKIExtendedKeyUsage") | ForEach-Object { "$_" })
        $enrolleeSupplies = ($nameFlag -band 0x1) -eq 0x1
        $managerApproval = ($enrollFlag -band 0x2) -eq 0x2
        $noSecurityExtension = ($enrollFlag -band 0x80000) -eq 0x80000
        $hasClientAuth = ($ekus.Count -eq 0)
        foreach ($eku in $ekus) { if ($clientAuth -contains $eku -or $eku -eq $anyPurpose) { $hasClientAuth = $true } }

        # Enrollment rights decide whether a template weakness is actually reachable.
        $dn = Get-AuditAttr $tmpl "distinguishedName"
        $sd = Get-AuditSecurityDescriptor -DistinguishedName $dn
        $enrollees = New-Object System.Collections.Generic.List[string]
        $lowPrivEnrollment = $false
        if ($sd.Readable) {
            $templateAclReadable++
            if ($sd.Owner -and -not (Test-AuditTier0Identity $sd.Owner)) {
                [void]$templateOwners.Add("Template '$display' is owned by $($sd.Owner)")
            }
            foreach ($ace in @($sd.Access)) {
                if ("$($ace.AccessControlType)" -ne "Allow") { continue }
                $identity = [string]$ace.IdentityReference
                $mask = 0
                try { $mask = [int]$ace.ActiveDirectoryRights } catch { }
                $objectType = "$($ace.ObjectType)".ToLowerInvariant()

                $grantsEnrollment = (($mask -band 0x100) -ne 0 -and ($enrollmentRightGuids -contains $objectType -or $objectType -eq "00000000-0000-0000-0000-000000000000")) -or (($mask -band 0x10000000) -ne 0)
                if ($grantsEnrollment -and -not (Test-AuditTier0Identity $identity)) {
                    [void]$enrollees.Add($identity)
                    $lowPrivEnrollment = $true
                }

                if (Test-AuditTier0Identity $identity) { continue }
                if (Test-AuditDangerousAccessMask $mask) {
                    [void]$esc4.Add("Template '$display' is writable by $identity ($(Get-AuditAceRightNames $mask))")
                }
            }
        }
        $enrollText = if ($enrollees.Count -gt 0) { "enrollable by $((@($enrollees | Select-Object -Unique)) -join ', ')" } elseif ($sd.Readable) { "enrollment restricted to Tier 0" } else { "enrollment rights unreadable" }

        if (-not $isPublished) { continue }

        if ($enrolleeSupplies -and $hasClientAuth -and -not $managerApproval -and $raSignatures -lt 1) {
            [void]$esc1.Add("$display (ENROLLEE_SUPPLIES_SUBJECT + client auth, no manager approval, $enrollText)")
        }
        if ($ekus.Count -eq 0 -or ($ekus -contains $anyPurpose)) {
            [void]$esc2.Add("$display (Any Purpose / no EKU, $enrollText)")
        }
        if ($ekus -contains $requestAgent) {
            [void]$esc3.Add("$display (Certificate Request Agent, $enrollText)")
        }
        if ($noSecurityExtension -and $hasClientAuth) {
            [void]$esc9.Add("$display (CT_FLAG_NO_SECURITY_EXTENSION, $enrollText)")
        }
        foreach ($policy in @((Get-AuditAttr $tmpl "msPKI-Certificate-Policy") | Where-Object { $_ })) {
            $policyValue = [string]$policy
            if ($oidGroupLinks.ContainsKey($policyValue)) {
                [void]$esc13.Add("$display carries issuance policy $policyValue linked to group $($oidGroupLinks[$policyValue]) ($enrollText)")
            }
        }
        $keySize = 0
        try { $keySize = [int](Get-AuditAttr $tmpl "msPKI-Minimal-Key-Size") } catch { }
        if ($keySize -gt 0 -and $keySize -lt $minKeySize -and $lowPrivEnrollment) {
            [void]$weakKeys.Add("$display (minimum key size $keySize bits)")
        }
    }

    function Add-Cs {
        param($Id, $Sub, $Fail, $Pass, $Desc, $Items, $Sev, $Score, $Rec, $Mitre, $FailStatus = "Failed")
        if ($Items.Count -gt 0) {
            [void]$findings.Add((New-AuditFinding -CheckId $Id -Category $category -Subcategory $Sub -Title $Fail -Description $Desc `
                    -Severity $Sev -Status $FailStatus -RiskScore $Score -AffectedCount $Items.Count `
                    -AffectedObjects (Limit-AuditObjects $Items) -Evidence $Items -Recommendation $Rec -MitreTechnique $Mitre -DataSource "AD CS"))
        } else {
            [void]$findings.Add((New-AuditFinding -CheckId $Id -Category $category -Subcategory $Sub -Title $Pass `
                    -Description "No matching templates/CAs were identified." -Severity "Informational" -Status "Passed" -DataSource "AD CS"))
        }
    }

    Add-Cs "AD-CS-001" "ESC1" "ESC1 templates allow requester-specified SAN + client auth" "No ESC1 templates detected" `
        "ENROLLEE_SUPPLIES_SUBJECT plus Client Authentication (or Any Purpose), with no manager approval and no authorized signature requirement, lets a requester obtain a certificate as any principal, including Domain Admins." `
        $esc1 "Critical" 25 "Remove 'Supply in the request', require manager approval, or drop the Client Authentication EKU. Restrict enrollment to a dedicated group." "T1649"
    Add-Cs "AD-CS-004" "ESC2" "ESC2 templates have Any Purpose or empty EKU" "No ESC2 templates detected" `
        "An Any Purpose or empty EKU certificate can be used for client authentication, so the template behaves like ESC1 for anyone who can enroll." `
        $esc2 "High" 15 "Define explicit EKUs; avoid empty or Any Purpose on published templates." "T1649"
    Add-Cs "AD-CS-005" "ESC3" "ESC3 Certificate Request Agent templates published" "No ESC3 templates detected" `
        "Certificate Request Agent EKUs allow enrolling on behalf of another user when chained with a second template that permits agent requests." `
        $esc3 "High" 15 "Restrict enrollment and issuance of Certificate Request Agent templates, and require enrollment agent restrictions on the CA." "T1649"
    Add-Cs "AD-CS-002" "ESC4" "ESC4: non-admin principals can modify certificate templates" "No ESC4 template ACLs detected" `
        "WriteDacl, WriteOwner, WriteProperty, or GenericAll on a template is ESC4 - the principal can reconfigure the template into ESC1 and then enroll." `
        $esc4 "Critical" 25 "Restrict template write access to Enterprise Admins and a documented PKI operations group." "T1649"
    Add-Cs "AD-CS-003" "ESC8" "HTTP enrollment URLs advertised by enterprise CAs" "No HTTP enrollment URLs in msPKI-Enrollment-Servers" `
        "HTTP (not HTTPS) web enrollment is the ESC8 NTLM-relay path: coerced DC authentication can be relayed to the CA to obtain a DC certificate." `
        $httpEnroll "High" 15 "Force HTTPS with Extended Protection for Authentication, or disable the web enrollment role." "T1557"
    Add-Cs "AD-CS-008" "ESC9" "ESC9 templates omit the SID security extension" "No ESC9 templates detected" `
        "CT_FLAG_NO_SECURITY_EXTENSION removes the szOID_NTDS_CA_SECURITY_EXT SID from issued certificates. When certificate mapping is not in full enforcement mode, an attacker who can change a victim's userPrincipalName can authenticate as that victim." `
        $esc9 "High" 15 "Clear CT_FLAG_NO_SECURITY_EXTENSION and set StrongCertificateBindingEnforcement to full enforcement (2) on all Domain Controllers." "T1649"
    Add-Cs "AD-CS-009" "ESC13" "ESC13: issuance policy OIDs are linked to groups" "No issuance policy to group links on published templates" `
        "An issuance policy OID with msDS-OIDToGroupLink grants the linked group's rights to anyone holding a certificate from that template, without any group membership change in the directory." `
        $esc13 "Critical" 25 "Remove msDS-OIDToGroupLink, or restrict enrollment of templates carrying the policy OID to Tier 0 principals only." "T1649"
    Add-Cs "AD-CS-011" "Cryptography" "Templates enrollable by users allow keys below $minKeySize bits" "No published template allows weak keys to low-privileged enrollees" `
        "Certificates with keys under $minKeySize bits are below current guidance and weaken every authentication and signature that depends on them." `
        $weakKeys "Medium" 8 "Raise msPKI-Minimal-Key-Size to $minKeySize or higher and re-issue affected certificates." "T1649" "Warning"
    Add-Cs "AD-CS-012" "Template Ownership" "Certificate templates are owned by non-Tier 0 principals" "All readable templates are owned by Tier 0 principals" `
        "A template's owner holds implicit WriteDacl and can convert the template into ESC1 at any time, which makes ownership equivalent to ESC4." `
        $templateOwners "Critical" 25 "Set template ownership to Enterprise Admins and review how ownership changed." "T1649"

    [void]$findings.Add((New-AuditFinding -CheckId "AD-CS-006" -Category $category -Subcategory "Inventory" `
            -Title "Enterprise CA inventory ($($enroll.Count))" `
            -Description "Found $($enroll.Count) pKIEnrollmentService object(s) and $($templates.Count) template(s); security descriptors were readable on $templateAclReadable template(s)." `
            -Severity "Informational" -Status "Informational" -AffectedObjects $caNames -Evidence $caNames -DataSource "pKIEnrollmentService"))

    # ESC7: control of the CA object itself.
    $esc7 = New-Object System.Collections.Generic.List[string]
    foreach ($ca in $enroll) {
        $dn = Get-AuditAttr $ca "distinguishedName"
        $cn = Get-AuditAttr $ca "cn"
        if (-not $dn) { continue }
        $sd = Get-AuditSecurityDescriptor -DistinguishedName $dn
        if ($sd.Owner -and -not (Test-AuditTier0Identity $sd.Owner)) {
            [void]$esc7.Add("CA '$cn' is owned by $($sd.Owner)")
        }
        foreach ($ace in @($sd.Access)) {
            if ("$($ace.AccessControlType)" -ne "Allow") { continue }
            $identity = [string]$ace.IdentityReference
            if (Test-AuditTier0Identity $identity) { continue }
            $mask = 0
            try { $mask = [int]$ace.ActiveDirectoryRights } catch { }
            if (Test-AuditDangerousAccessMask $mask) {
                [void]$esc7.Add("CA '$cn' is controllable by $identity ($(Get-AuditAceRightNames $mask))")
            }
        }
    }
    Add-AuditCheckResult -Findings $findings -CheckId "AD-CS-007" -Category $category -Subcategory "ESC7" `
        -FailTitle "ESC7: non-admin principals can manage enterprise CAs" `
        -PassTitle "No extra dangerous ACEs on enterprise CA objects (or ACLs unreadable)" `
        -FailDescription "ManageCA or WriteDacl on a pKIEnrollmentService object is ESC7 - the principal can enable SAN requests, approve pending requests, and publish new templates." `
        -Items @($esc7) -Severity "Critical" -RiskScore 25 `
        -Recommendation "Restrict CA object ACLs and ownership to Enterprise Admins and documented PKI operators." `
        -MitreTechnique "T1649" -DataSource "pKIEnrollmentService ACL"

    # ESC5: control of the PKI containers the whole forest trusts.
    $esc5 = New-Object System.Collections.Generic.List[string]
    $containersReadable = 0
    foreach ($container in @(
            @{ Label = "Public Key Services container"; Dn = $pkiBase },
            @{ Label = "Certificate Templates container"; Dn = "CN=Certificate Templates,$pkiBase" },
            @{ Label = "Enrollment Services container"; Dn = "CN=Enrollment Services,$pkiBase" },
            @{ Label = "NTAuthCertificates"; Dn = "CN=NTAuthCertificates,$pkiBase" },
            @{ Label = "Certification Authorities container"; Dn = "CN=Certification Authorities,$pkiBase" },
            @{ Label = "AIA container"; Dn = "CN=AIA,$pkiBase" },
            @{ Label = "OID container"; Dn = "CN=OID,$pkiBase" }
        )) {
        $sd = Get-AuditSecurityDescriptor -DistinguishedName $container.Dn
        if (-not $sd.Readable) { continue }
        $containersReadable++
        if ($sd.Owner -and -not (Test-AuditTier0Identity $sd.Owner)) {
            [void]$esc5.Add("$($container.Label) is owned by $($sd.Owner)")
        }
        foreach ($ace in @($sd.Access)) {
            if ("$($ace.AccessControlType)" -ne "Allow") { continue }
            $identity = [string]$ace.IdentityReference
            if (Test-AuditTier0Identity $identity) { continue }
            $mask = 0
            try { $mask = [int]$ace.ActiveDirectoryRights } catch { }
            if (Test-AuditControlRight -Mask $mask -ObjectType $ace.ObjectType) {
                [void]$esc5.Add("$($container.Label): $identity has $(Get-AuditAceRightNames $mask)")
            }
        }
    }

    if ($containersReadable -eq 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-CS-010" -Category $category -Subcategory "ESC5" `
                -Title "PKI container security descriptors could not be read" `
                -Description "None of the Public Key Services containers returned nTSecurityDescriptor, so forest-wide PKI delegation was not evaluated." `
                -Severity "Medium" -Status "Not Tested" -RequiredPermission "Read nTSecurityDescriptor" -DataSource "nTSecurityDescriptor"))
    } else {
        Add-AuditCheckResult -Findings $findings -CheckId "AD-CS-010" -Category $category -Subcategory "ESC5" `
            -FailTitle "ESC5: non-Tier 0 principals control forest PKI containers" `
            -PassTitle "Forest PKI containers are controlled only by Tier 0 principals" `
            -FailDescription "Write access to the Public Key Services containers allows publishing a rogue CA certificate into NTAuthCertificates, which makes attacker-issued certificates valid for domain authentication across the whole forest." `
            -Items @($esc5) -Severity "Critical" -RiskScore 25 `
            -Recommendation "Remove delegated write access from CN=Public Key Services and its child containers. Only Enterprise Admins should modify forest PKI configuration." `
            -MitreTechnique "T1649" -DataSource "Public Key Services ACL"
    }

    return $findings
}

Export-ModuleMember -Function Invoke-CertificateServicesAudit
