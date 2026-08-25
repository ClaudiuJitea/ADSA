# DNS.psm1 - AD-integrated zones via LDAP, DnsAdmins, WPAD/ISATAP

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-DNSAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "DNS Security"
    $session = Get-AuditDirectorySession
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-DNS-000" -Category $category))
        return $findings
    }

    $zoneContainers = @(
        "CN=MicrosoftDNS,CN=System,$($session.DefaultNamingContext)",
        "CN=MicrosoftDNS,DC=DomainDnsZones,$($session.DefaultNamingContext)",
        "CN=MicrosoftDNS,DC=ForestDnsZones,$($session.RootDomainNamingContext)"
    )
    $insecure = @()
    $wpad = @()
    foreach ($base in $zoneContainers) {
        $zones = @(Search-AuditDirectory -LdapFilter "(objectClass=dnsZone)" -SearchBase $base -Properties @("name", "allowUpdate", "distinguishedName"))
        foreach ($z in $zones) {
            $name = Get-AuditAttr $z "name"
            $upd = Get-AuditAttr $z "allowUpdate"
            # 0 none, 1 nonsecure and secure, 2 secure only
            if ("$upd" -eq "1") { $insecure += "$name (allowUpdate=NonsecureAndSecure) at $base" }
        }
        $nodes = @(Search-AuditDirectory -LdapFilter "(|(dc=wpad)(dc=isatap)(name=wpad)(name=isatap))" -SearchBase $base -Properties @("name", "dc", "dnsRecord"))
        foreach ($n in $nodes) {
            $wpad += "$(Get-AuditSam $n) under $base"
        }
    }

    if ($insecure.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DNS-001" -Category $category -Subcategory "Dynamic Updates" `
            -Title "AD-integrated DNS zones allow non-secure dynamic updates" `
            -Description "Unauthenticated clients can overwrite records (including WPAD and server A records) and coerce authentication." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $insecure.Count `
            -AffectedObjects $insecure -Evidence $insecure `
            -Recommendation "Set every AD-integrated zone to Secure only dynamic updates." `
            -MicrosoftReference "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-dynamic-updates-windows-server" `
            -MitreTechnique "T1557.001" -DataSource "dnsZone.allowUpdate"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DNS-001" -Category $category -Subcategory "Dynamic Updates" `
            -Title "No AD-integrated zone with non-secure updates (or zones not readable)" `
            -Description "No dnsZone with allowUpdate=1 was returned. Confirm DNS partition access if you expected zones." `
            -Severity "Informational" -Status "Passed" -DataSource "dnsZone"))
    }

    $dnsAdmins = Find-AuditGroup -Name "DnsAdmins"
    $dnsMembers = @()
    if ($dnsAdmins) {
        $dnsMembers = @(Get-AuditGroupMembers -GroupDn (Get-AuditAttr $dnsAdmins "distinguishedName") -Recursive | ForEach-Object { Get-AuditSam $_ })
    }
    if ($dnsMembers.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DNS-002" -Category $category -Subcategory "DnsAdmins" `
            -Title "DnsAdmins is populated" `
            -Description "DnsAdmins can load a server-level plugin DLL on the DNS Server service, which usually runs on Domain Controllers (privilege escalation to SYSTEM on the DC)." `
            -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $dnsMembers.Count `
            -AffectedObjects $dnsMembers -Evidence $dnsMembers `
            -Recommendation "Keep DnsAdmins empty or limited to dedicated Tier 0 DNS operators. Prefer least-privilege DNS ACLs over group membership." `
            -MitreTechnique "T1547" -DataSource "DnsAdmins"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DNS-002" -Category $category -Subcategory "DnsAdmins" `
            -Title "DnsAdmins has no nested members" `
            -Description "The DnsAdmins group was empty or not found." `
            -Severity "Informational" -Status "Passed" -DataSource "DnsAdmins"))
    }

    if ($wpad.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DNS-003" -Category $category -Subcategory "Name Spoofing" `
            -Title "WPAD or ISATAP DNS records exist" `
            -Description "WPAD/ISATAP names are used for proxy and IPv6 transition auto-discovery and are common NTLM-coercion bait if they can be spoofed or point at attacker infrastructure." `
            -Severity "Medium" -Status "Failed" -RiskScore 8 -AffectedCount $wpad.Count `
            -AffectedObjects $wpad -Evidence $wpad `
            -Recommendation "Review WPAD/ISATAP records and enable the DNS global query block list for those names if unused." `
            -MitreTechnique "T1557" -DataSource "dnsNode"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DNS-003" -Category $category -Subcategory "Name Spoofing" `
            -Title "No WPAD/ISATAP nodes found in AD DNS" `
            -Description "No dnsNode named wpad or isatap was returned from MicrosoftDNS containers." `
            -Severity "Informational" -Status "Passed" -DataSource "dnsNode"))
    }

    return $findings
}

Export-ModuleMember -Function Invoke-DNSAudit
