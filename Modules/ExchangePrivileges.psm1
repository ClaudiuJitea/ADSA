# ExchangePrivileges.psm1 - Exchange / Skype / SCCM well-known privileged groups

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Invoke-ExchangePrivilegesAudit {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [PSCredential]$Credential,
        [hashtable]$Config = @{}
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $category = "Exchange and Application Privileges"
    if (-not (Test-AuditDirectoryAvailable)) {
        [void]$findings.Add((New-AuditUnavailableFinding -CheckId "AD-XCH-000" -Category $category))
        return $findings
    }

    $watch = @(
        @{ Name = "Exchange Windows Permissions"; Id = "AD-XCH-001"; Sev = "Critical"; Score = 25; Rec = "Exchange Windows Permissions often has WriteDacl on the domain object (DCSync-equivalent). Treat members as Tier 0 and remove standing user membership."; Mitre = "T1003.006" },
        @{ Name = "Exchange Trusted Subsystem"; Id = "AD-XCH-002"; Sev = "High"; Score = 15; Rec = "Exchange Trusted Subsystem is SYSTEM-equivalent on Exchange servers and frequently has broad directory rights. Limit to Exchange computer accounts."; Mitre = "T1078" },
        @{ Name = "Organization Management"; Id = "AD-XCH-003"; Sev = "High"; Score = 15; Rec = "Organization Management is the Exchange equivalent of Domain Admins for mail. Keep it empty of daily-use accounts."; Mitre = "T1078.002" },
        @{ Name = "Exchange Servers"; Id = "AD-XCH-004"; Sev = "Medium"; Score = 8; Rec = "Unexpected user (non-computer) members of Exchange Servers can inherit Exchange subsystem rights."; Mitre = "T1078" },
        @{ Name = "Public Folder Management"; Id = "AD-XCH-005"; Sev = "Medium"; Score = 8; Rec = "Review Public Folder Management for standing human membership."; Mitre = "T1078" },
        @{ Name = "RtcUniversalServerAdmins"; Id = "AD-XCH-006"; Sev = "High"; Score = 15; Rec = "Skype/Lync RTC universal admins are often forgotten Tier 0 after the product is retired."; Mitre = "T1078" }
    )

    $present = New-Object System.Collections.Generic.List[string]
    foreach ($item in $watch) {
        $group = Find-AuditGroup -Name $item.Name
        if (-not $group) {
            [void]$findings.Add((New-AuditFinding -CheckId $item.Id -Category $category -Subcategory $item.Name `
                    -Title "$($item.Name) was not found" `
                    -Description "The group does not exist in this domain (typical when the product was never installed)." `
                    -Severity "Informational" -Status "Passed" -DataSource "group"))
            continue
        }

        $members = @(Get-AuditGroupMembers -GroupDn (Get-AuditAttr $group "distinguishedName") -Recursive)
        $labels = New-Object System.Collections.Generic.List[string]
        $userMembers = New-Object System.Collections.Generic.List[string]
        foreach ($m in $members) {
            $sam = Get-AuditSam $m
            $cls = Get-AuditMostSpecificClass $m
            [void]$labels.Add("$sam ($cls)")
            if ($cls -match "user|person" -and $cls -notmatch "computer") {
                [void]$userMembers.Add($sam)
            }
        }
        [void]$present.Add("$($item.Name): $($members.Count) nested member(s)")

        $failItems = @($labels)
        $shouldFail = $false
        if ($item.Name -eq "Exchange Windows Permissions" -and $members.Count -gt 0) { $shouldFail = $true }
        elseif ($item.Name -eq "Exchange Servers") { $failItems = @($userMembers); $shouldFail = ($userMembers.Count -gt 0) }
        elseif ($members.Count -gt 0 -and $userMembers.Count -gt 0) { $shouldFail = $true; $failItems = @($userMembers) }
        elseif ($members.Count -gt 8) { $shouldFail = $true }

        if ($shouldFail -and $failItems.Count -gt 0) {
            [void]$findings.Add((New-AuditFinding -CheckId $item.Id -Category $category -Subcategory $item.Name `
                    -Title "$($item.Name) has privileged membership" `
                    -Description $item.Rec `
                    -Severity $item.Sev -Status "Failed" -RiskScore $item.Score -AffectedCount $failItems.Count `
                    -AffectedObjects (Limit-AuditObjects $failItems) -Evidence @($labels) `
                    -Recommendation $item.Rec -MitreTechnique $item.Mitre -DataSource $item.Name))
        } else {
            [void]$findings.Add((New-AuditFinding -CheckId $item.Id -Category $category -Subcategory $item.Name `
                    -Title "$($item.Name) has no unexpected human members" `
                    -Description "Resolved nested members: $($labels.Count)." `
                    -Severity "Informational" -Status "Passed" -AffectedObjects (Limit-AuditObjects @($labels)) -DataSource $item.Name))
        }
    }

    [void]$findings.Add((New-AuditFinding -CheckId "AD-XCH-007" -Category $category -Subcategory "Inventory" `
            -Title "Application privilege group inventory" `
            -Description "Evaluated Exchange / Skype well-known groups. Compromise of Exchange Windows Permissions is a documented DCSync path." `
            -Severity "Informational" -Status "Informational" -AffectedObjects @($present) -Evidence @($present) `
            -MicrosoftReference "https://learn.microsoft.com/en-us/exchange/plan-and-deploy/active-directory/ad-schema-changes" `
            -DataSource "group"))

    return $findings
}

Export-ModuleMember -Function Invoke-ExchangePrivilegesAudit
