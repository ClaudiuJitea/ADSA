# DomainControllers.psm1 - Domain controller inventory and hardening

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-DomainControllersAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [bool]$SkipRemoteChecks = $false,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "Domain Controllers"
    $session = Get-AuditDirectorySession
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-DC-000" -Category $category))
        return $findings
    }

    $dcProperties = @("dNSHostName", "name", "operatingSystem", "operatingSystemVersion", "userAccountControl", "primaryGroupID", "whenCreated", "lastLogonTimestamp", "serverReferenceBL", "distinguishedName")
    $dcs = @(Search-AuditDirectory -LdapFilter "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -Properties $dcProperties)
    if ($dcs.Count -eq 0) {
        $dcs = @(Search-AuditDirectory -LdapFilter "(&(objectClass=computer)(primaryGroupID=516))" -Properties $dcProperties)
    }

    $eol = @()
    $rodc = @()
    $names = @()
    $misplaced = New-Object System.Collections.Generic.List[string]
    $dcOu = "OU=Domain Controllers,$($session.DefaultNamingContext)"
    $dcObjectDns = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($dc in $dcs) {
        $hostName = Get-AuditAttr $dc "dNSHostName"
        if (-not $hostName) { $hostName = Get-AuditSam $dc }
        $os = [string](Get-AuditAttr $dc "operatingSystem")
        $uac = Get-AuditAttr $dc "userAccountControl"
        $names += "$hostName ($os)"
        if ($os -match "2003|2008|2012") { $eol += "$hostName ($os)" }
        if (Test-AuditUacFlag $uac 0x4000000) { $rodc += $hostName }

        $dn = [string](Get-AuditAttr $dc "distinguishedName")
        if ($dn) {
            [void]$dcObjectDns.Add($dn.ToLowerInvariant())
            if ($dn -notlike "*$dcOu") {
                [void]$misplaced.Add("$hostName is located at $dn")
            }
        }
    }

    if ($eol.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DC-001" -Category $category -Subcategory "OS Support" `
            -Title "Domain controllers running end-of-life operating systems" `
            -Description "Found $($eol.Count) DC(s) on unsupported Windows Server releases. These hosts no longer receive security updates." `
            -Severity "Critical" -Status "Failed" -RiskScore 25 -AffectedCount $eol.Count `
            -AffectedObjects (Limit-AuditObjects $eol) -Evidence $eol `
            -Recommendation "Upgrade or replace Domain Controllers with Windows Server 2019, 2022, or 2025." `
            -MicrosoftReference "https://learn.microsoft.com/en-us/lifecycle/products/" `
            -MitreTechnique "T1190" -DataSource "computer (UF_SERVER_TRUST_ACCOUNT)"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DC-001" -Category $category -Subcategory "OS Support" `
            -Title "No end-of-life Domain Controller operating systems detected" `
            -Description "Enumerated $($dcs.Count) Domain Controller(s); none matched Windows Server 2003/2008/2012 strings." `
            -Severity "Informational" -Status "Passed" -Evidence $names -DataSource "computer"))
    }

    $spoolerEnabled = @()
    if ($SkipRemoteChecks) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DC-002" -Category $category -Subcategory "Service Hardening" `
            -Title "Print Spooler remote check skipped" `
            -Description "Remote WMI/CIM was skipped (-SkipRemoteChecks)." `
            -Severity "Informational" -Status "Not Tested" -DataSource "Skipped"))
    } else {
        foreach ($dc in $dcs) {
            $hostName = Get-AuditAttr $dc "dNSHostName"
            if (-not $hostName) { continue }
            try {
                $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='Spooler'" -ComputerName $hostName -ErrorAction Stop
                if ($svc.State -eq "Running" -or $svc.StartMode -ne "Disabled") {
                    $spoolerEnabled += "$hostName (State=$($svc.State), StartMode=$($svc.StartMode))"
                }
            } catch { }
        }
        if ($spoolerEnabled.Count -gt 0) {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-DC-002" -Category $category -Subcategory "Service Hardening" `
                -Title "Print Spooler is enabled on Domain Controllers" `
                -Description "Print Spooler on DCs enables PrintNightmare and coerced authentication (PetitPotam / printerbug) toward the domain." `
                -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount $spoolerEnabled.Count `
                -AffectedObjects $spoolerEnabled -Evidence $spoolerEnabled `
                -Recommendation "Stop and disable Spooler on every DC: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled." `
                -MicrosoftReference "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527" `
                -MitreTechnique "T1068" -RequiredPermission "Remote WMI" -DataSource "Win32_Service"))
        } else {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-DC-002" -Category $category -Subcategory "Service Hardening" `
                -Title "Print Spooler not confirmed running on reachable DCs" `
                -Description "No reachable DC reported Spooler as running or auto-start. Hosts that refused WMI are not counted as passed." `
                -Severity "Informational" -Status "Passed" -DataSource "Win32_Service"))
        }
    }

    try {
        $frs = Search-AuditDirectory -LdapFilter "(cn=File Replication Service)" -SearchBase $session.ConfigurationNamingContext -Properties @("cn")
        $dfsr = Search-AuditDirectory -LdapFilter "(cn=DFSR-GlobalSettings)" -SearchBase $session.ConfigurationNamingContext -Properties @("cn")
        if ($frs -and -not $dfsr) {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-DC-004" -Category $category -Subcategory "SYSVOL Replication" `
                -Title "SYSVOL still uses legacy FRS" `
                -Description "File Replication Service objects exist without DFSR-GlobalSettings. FRS is deprecated and unstable on modern Windows." `
                -Severity "High" -Status "Failed" -RiskScore 15 -AffectedCount 1 `
                -Recommendation "Migrate SYSVOL to DFSR with dfsrmig.exe." `
                -MicrosoftReference "https://learn.microsoft.com/en-us/windows-server/storage/dfs/migrate-sysvol-to-dfsr" `
                -DataSource "configuration"))
        } else {
            [void]$findings.Add((New-AuditFinding -CheckId "AD-DC-004" -Category $category -Subcategory "SYSVOL Replication" `
                -Title "SYSVOL DFSR configuration is present" `
                -Description "DFSR-GlobalSettings was found in the configuration partition." `
                -Severity "Informational" -Status "Passed" -DataSource "configuration"))
        }
    } catch { }

    if ($rodc.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DC-005" -Category $category -Subcategory "RODC" `
            -Title "Read-only Domain Controllers are deployed" `
            -Description "Found $($rodc.Count) RODC computer object(s). RODCs are valid for branch sites but their password-replication policy and krbtgt_XXXX accounts must be tightly controlled." `
            -Severity "Informational" -Status "Warning" -RiskScore 3 -AffectedCount $rodc.Count `
            -AffectedObjects $rodc -Evidence $rodc `
            -Recommendation "Review each RODC's msDS-RevealOnDemandGroup / msDS-NeverRevealGroup and rotate RODC krbtgt if compromise is suspected." `
            -DataSource "userAccountControl PARTIAL_SECRETS_ACCOUNT"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-DC-005" -Category $category -Subcategory "RODC" `
            -Title "No RODC computer objects detected" `
            -Description "No computer accounts have the PARTIAL_SECRETS_ACCOUNT flag." `
            -Severity "Informational" -Status "Passed" -DataSource "computer"))
    }

    $rodcObjects = @(Search-AuditDirectory -LdapFilter "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=67108864))" -Properties @("name", "dNSHostName", "msDS-RevealOnDemandGroup", "msDS-NeverRevealGroup", "msDS-RevealedList"))
    $openPrp = New-Object System.Collections.Generic.List[string]
    foreach ($r in $rodcObjects) {
        $hostName = Get-AuditAttr $r "dNSHostName"
        if (-not $hostName) { $hostName = Get-AuditSam $r }
        $reveal = @((Get-AuditAttr $r "msDS-RevealOnDemandGroup") | ForEach-Object { "$_" })
        foreach ($g in $reveal) {
            if ($g -match "Authenticated Users|Everyone|Domain Users|Domain Computers") {
                [void]$openPrp.Add("$hostName reveals passwords for $g")
            }
        }
        if ($reveal.Count -gt 8) { [void]$openPrp.Add("$hostName has $($reveal.Count) allow-on-demand groups") }
    }
    Add-AuditCheckResult -Findings $findings -CheckId "AD-DC-007" -Category $category -Subcategory "RODC PRP" `
        -FailTitle "RODC password replication policy is overly broad" `
        -PassTitle "No overly broad RODC password-replication allow lists" `
        -FailDescription "msDS-RevealOnDemandGroup including Authenticated Users or a large population caches secrets on a branch RODC that is easier to steal." `
        -Items @($openPrp) -Severity "High" -RiskScore 15 `
        -Recommendation "Limit Reveal-on-demand to specific branch users. Keep Domain Admins in NeverReveal. Monitor msDS-RevealedList." `
        -MitreTechnique "T1003" -DataSource "msDS-RevealOnDemandGroup"

    Add-AuditCheckResult -Findings $findings -CheckId "AD-DC-008" -Category $category -Subcategory "Object Placement" `
        -FailTitle "Domain Controller objects are outside the Domain Controllers OU" `
        -PassTitle "All Domain Controller objects are in the Domain Controllers OU" `
        -FailDescription "A DC computer object moved out of OU=Domain Controllers stops receiving the Default Domain Controllers Policy, so its audit policy, user rights assignments, and hardening silently differ from the rest of the fleet. It is also a known way to keep a DC out of scope for monitoring." `
        -PassDescription "Every Domain Controller computer object is located under the Domain Controllers OU." `
        -Items @($misplaced) -Severity "High" -RiskScore 15 `
        -Recommendation "Move the DC computer object back into OU=Domain Controllers and confirm the Default Domain Controllers Policy applies (gpresult /r)." `
        -MitreTechnique "T1484.001" -DataSource "distinguishedName"

    $ghostServers = New-Object System.Collections.Generic.List[string]
    $servers = @(Search-AuditDirectory -LdapFilter "(objectClass=server)" -SearchBase "CN=Sites,$($session.ConfigurationNamingContext)" -Properties @("cn", "dNSHostName", "serverReference", "distinguishedName"))
    foreach ($server in $servers) {
        $serverName = Get-AuditAttr $server "cn"
        $reference = [string](Get-AuditAttr $server "serverReference")
        if ([string]::IsNullOrWhiteSpace($reference)) {
            [void]$ghostServers.Add("Server '$serverName' has no serverReference (no matching computer object)")
        } elseif (-not $dcObjectDns.Contains($reference.ToLowerInvariant())) {
            [void]$ghostServers.Add("Server '$serverName' references $reference, which is not an enabled Domain Controller object")
        }
    }
    Add-AuditCheckResult -Findings $findings -CheckId "AD-DC-009" -Category $category -Subcategory "Replication Metadata" `
        -FailTitle "Domain Controller metadata does not match the DC objects" `
        -PassTitle "Domain Controller metadata matches the DC computer objects" `
        -FailDescription "Server objects in the configuration partition without a matching Domain Controller computer object are usually leftovers from a failed demotion that still advertise as replication partners. The same pattern is what a DCShadow-style attack creates when it registers a rogue replication source." `
        -PassDescription "Every server object in CN=Sites resolves to a Domain Controller computer object." `
        -Items @($ghostServers) -Severity "Medium" -RiskScore 8 `
        -Recommendation "Run metadata cleanup (ntdsutil or Remove-ADDomainController) for demoted DCs, and investigate any server object you cannot account for." `
        -MitreTechnique "T1207" -DataSource "nTDSDSA / server objects"

    [void]$findings.Add((New-AuditFinding -CheckId "AD-DC-006" -Category $category -Subcategory "Inventory" `
        -Title "Domain Controller inventory ($($dcs.Count) hosts)" `
        -Description "Enumerated $($dcs.Count) Domain Controller computer object(s)." `
        -Severity "Informational" -Status "Informational" -AffectedCount $dcs.Count `
        -AffectedObjects (Limit-AuditObjects $names) -Evidence $names -DataSource "computer"))

    return $findings
}

Export-ModuleMember -Function Invoke-DomainControllersAudit
