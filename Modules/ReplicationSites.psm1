# ReplicationSites.psm1 - Sites, nTDSDSA, RODC PRP indicators

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-ReplicationSitesAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "Replication and Sites"
    $session = Get-AuditDirectorySession
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-REPL-000" -Category $category))
        return $findings
    }

    $configNc = $session.ConfigurationNamingContext
    $sites = @(Search-AuditDirectory -LdapFilter "(objectClass=site)" -SearchBase "CN=Sites,$configNc" -Properties @("cn", "location"))
    $ntds = @(Search-AuditDirectory -LdapFilter "(objectClass=nTDSDSA)" -SearchBase "CN=Sites,$configNc" -Properties @("cn", "options", "distinguishedName", "msDS-Behavior-Version"))
    $siteLinks = @(Search-AuditDirectory -LdapFilter "(objectClass=siteLink)" -SearchBase "CN=Sites,$configNc" -Properties @("cn", "cost", "replInterval", "siteList"))

    $emptySites = @()
    foreach ($site in $sites) {
        $cn = Get-AuditAttr $site "cn"
        $hasNtds = $false
        foreach ($n in $ntds) {
            if ((Get-AuditAttr $n "distinguishedName") -like "*CN=$cn,*" -or (Get-AuditAttr $n "distinguishedName") -like "*,CN=$cn,*") { $hasNtds = $true }
        }
        if (-not $hasNtds) { $emptySites += $cn }
    }

    [void]$findings.Add((New-AuditFinding -CheckId "AD-REPL-001" -Category $category -Subcategory "Inventory" `
        -Title "Site and DC NTDS settings inventory" `
        -Description "Sites=$($sites.Count), nTDSDSA=$($ntds.Count), siteLinks=$($siteLinks.Count)." `
        -Severity "Informational" -Status "Informational" -AffectedCount $ntds.Count `
        -AffectedObjects @($ntds | ForEach-Object { Get-AuditAttr $_ "distinguishedName" }) `
        -DataSource "configuration"))

    if ($emptySites.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-REPL-002" -Category $category -Subcategory "Sites" `
            -Title "AD sites with no Domain Controller NTDS settings" `
            -Description "Clients in empty sites use automatic site coverage and may authenticate to unexpected DCs, affecting latency and isolation assumptions." `
            -Severity "Low" -Status "Warning" -RiskScore 3 -AffectedCount $emptySites.Count `
            -AffectedObjects $emptySites -Evidence $emptySites `
            -Recommendation "Place a DC/RODC, adjust subnets, or remove unused sites." `
            -DataSource "site / nTDSDSA"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-REPL-002" -Category $category -Subcategory "Sites" `
            -Title "Every site has NTDS settings or no sites exist" `
            -Description "No site lacked a subordinate nTDSDSA object." `
            -Severity "Informational" -Status "Passed" -DataSource "site"))
    }

    $slowLinks = @()
    foreach ($l in $siteLinks) {
        $interval = 0
        try { $interval = [int](Get-AuditAttr $l "replInterval") } catch { }
        if ($interval -gt 60) { $slowLinks += "$(Get-AuditSam $l) replInterval=$interval minutes" }
    }
    if ($slowLinks.Count -gt 0) {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-REPL-003" -Category $category -Subcategory "Site Links" `
            -Title "Site links with replication interval over 60 minutes" `
            -Description "Long intervals delay password and group-policy convergence and extend the window for lingering objects after DC restores." `
            -Severity "Low" -Status "Warning" -RiskScore 3 -AffectedCount $slowLinks.Count `
            -AffectedObjects $slowLinks -Evidence $slowLinks `
            -Recommendation "Use 15–60 minute intervals unless bandwidth requires otherwise." `
            -DataSource "siteLink"))
    } else {
        [void]$findings.Add((New-AuditFinding -CheckId "AD-REPL-003" -Category $category -Subcategory "Site Links" `
            -Title "Site-link intervals are within 60 minutes" `
            -Description "No siteLink had replInterval greater than 60." `
            -Severity "Informational" -Status "Passed" -DataSource "siteLink"))
    }

    return $findings
}

Export-ModuleMember -Function Invoke-ReplicationSitesAudit
