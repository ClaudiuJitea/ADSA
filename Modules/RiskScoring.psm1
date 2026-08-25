# RiskScoring.psm1 - Risk points, compliance, remediation plan, and coverage transparency

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Get-AuditSeverityWeight {
    param([string]$Severity)
    switch ($Severity) {
        "Critical" { 25 }
        "High" { 15 }
        "Medium" { 8 }
        "Low" { 3 }
        default { 0 }
    }
}

function Invoke-RiskScoring {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][array]$Findings,
        [int]$RiskPointCap = 100
    )

    $riskPoints = 0
    $failedPoints = 0
    $warningPoints = 0
    $statusCounts = @{ Passed = 0; Failed = 0; Warning = 0; Informational = 0; "Not Tested" = 0; Error = 0 }
    $severityCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Informational = 0 }
    $categoryScores = @{}
    $mitre = @()
    $failedCritical = 0
    $failedHigh = 0

    foreach ($f in $Findings) {
        $status = [string]$f.Status
        $severity = [string]$f.Severity
        $cat = [string]$f.Category
        if (-not $statusCounts.ContainsKey($status)) { $statusCounts[$status] = 0 }
        $statusCounts[$status]++
        if (-not $severityCounts.ContainsKey($severity)) { $severityCounts[$severity] = 0 }
        $severityCounts[$severity]++
        if (-not $categoryScores.ContainsKey($cat)) {
            $categoryScores[$cat] = @{
                Category       = $cat
                Raw            = 0
                Max            = 0
                Points         = 0
                FailedCount    = 0
                WarningCount   = 0
                PassedCount    = 0
                NotTestedCount = 0
                TotalChecks    = 0
            }
        }
        $categoryScores[$cat].TotalChecks++
        $weight = Get-AuditSeverityWeight $severity

        if ($f.MitreTechnique) { $mitre += [string]$f.MitreTechnique }

        switch ($status) {
            "Failed" {
                # More affected objects means a wider blast radius, capped at double weight
                # so that one large finding cannot dominate the whole score.
                $multiplier = [double]1.0
                if ($f.AffectedCount -gt 1) { $multiplier = [Math]::Min([double]2.0, [double](1.0 + ($f.AffectedCount * 0.05))) }
                $itemScore = [int][math]::Round($weight * $multiplier)
                $failedPoints += $itemScore
                $categoryScores[$cat].Points += $itemScore
                $categoryScores[$cat].Raw += $itemScore
                $categoryScores[$cat].Max += $weight
                $categoryScores[$cat].FailedCount++
                $f.RiskScore = $itemScore
                if ($severity -eq "Critical") { $failedCritical++ }
                if ($severity -eq "High") { $failedHigh++ }
            }
            "Warning" {
                $itemScore = [int][math]::Ceiling($weight * 0.4)
                $warningPoints += $itemScore
                $categoryScores[$cat].Points += $itemScore
                $categoryScores[$cat].Max += $weight
                $categoryScores[$cat].WarningCount++
                $f.RiskScore = $itemScore
            }
            "Passed" { $categoryScores[$cat].PassedCount++ }
            "Not Tested" { $categoryScores[$cat].NotTestedCount++ }
            "Error" { $categoryScores[$cat].NotTestedCount++ }
        }
    }

    $riskPoints = $failedPoints + $warningPoints
    $normalizedScore = [int][Math]::Min([double]$RiskPointCap, [double]$riskPoints)

    $tested = $statusCounts.Passed + $statusCounts.Failed + $statusCounts.Warning
    $compliancePercent = if ($tested -gt 0) { [math]::Round(100.0 * $statusCounts.Passed / $tested) } else { 0 }

    # Rating combines accumulated risk points with the presence of critical findings:
    # a single critical finding is usually enough for full domain compromise, so it
    # cannot be averaged away by a large number of passing checks.
    $riskRating = "Low Risk"
    if ($normalizedScore -gt 15) { $riskRating = "Moderate Risk" }
    if ($normalizedScore -gt 35) { $riskRating = "Elevated Risk" }
    if ($normalizedScore -gt 60 -or $failedHigh -ge 3) { $riskRating = "High Risk" }
    if ($failedCritical -ge 1 -and $riskRating -notin @("High Risk", "Critical Risk")) { $riskRating = "High Risk" }
    if ($normalizedScore -ge 80 -or $failedCritical -ge 3) { $riskRating = "Critical Risk" }

    $failedFindings = @($Findings | Where-Object { $_.Status -eq "Failed" -or $_.Status -eq "Warning" })

    $remediationPlan = @()
    $sortedFailed = @($failedFindings | Sort-Object @(
            { switch ("$($_.Severity)") { "Critical" { 0 } "High" { 1 } "Medium" { 2 } "Low" { 3 } default { 4 } } }
            { if ($_.RiskScore) { -1 * [int]$_.RiskScore } else { 0 } }
            { if ($_.AffectedCount) { -1 * [int]$_.AffectedCount } else { 0 } }
        ))
    $priority = 1
    foreach ($f in $sortedFailed) {
        $remediationPlan += [PSCustomObject]@{
                Priority       = $priority
                CheckId        = $f.CheckId
                Category       = $f.Category
                Title          = $f.Title
                Severity       = $f.Severity
                Status         = $f.Status
                AffectedCount  = $f.AffectedCount
                RiskScore      = $f.RiskScore
                Recommendation = $f.Recommendation
            }
        $priority++
    }

    # Small, high-severity findings are the cheapest way to reduce risk first.
    $quickWins = @($remediationPlan | Where-Object { $_.AffectedCount -le 5 -and @("Critical", "High") -contains $_.Severity } | Select-Object -First 10)

    $coverageGaps = @()
    foreach ($f in @($Findings | Where-Object { $_.Status -eq "Not Tested" -or $_.Status -eq "Error" })) {
        $coverageGaps += [PSCustomObject]@{
                CheckId            = $f.CheckId
                Category           = $f.Category
                Title              = $f.Title
                Status             = $f.Status
                Reason             = $f.Description
                RequiredPermission = $f.RequiredPermission
            }
    }

    $highestFailedSeverity = "None"
    foreach ($candidate in @("Critical", "High", "Medium", "Low")) {
        if (@($Findings | Where-Object { $_.Status -eq "Failed" -and $_.Severity -eq $candidate }).Count -gt 0) {
            $highestFailedSeverity = $candidate
            break
        }
    }

    $topFailed = @($Findings | Where-Object { $_.Status -eq "Failed" } | Sort-Object -Property RiskScore -Descending | Select-Object -First 15)

    $categorySummaries = @()
    foreach ($entry in $categoryScores.GetEnumerator()) {
        $cat = $entry.Value
        $categorySummaries += [PSCustomObject]@{
                Category       = [string]$cat.Category
                TotalChecks    = [int]$cat.TotalChecks
                PassedCount    = [int]$cat.PassedCount
                WarningCount   = [int]$cat.WarningCount
                FailedCount    = [int]$cat.FailedCount
                NotTestedCount = [int]$cat.NotTestedCount
                Points         = [int]$cat.Points
                Raw            = [int]$cat.Raw
                Max            = [int]$cat.Max
            }
    }
    $topCategories = @($categorySummaries | Sort-Object -Property Points -Descending | Select-Object -First 10)

    $mitreUnique = @()
    foreach ($technique in $mitre) {
        if ($technique -and ($mitreUnique -notcontains $technique)) { $mitreUnique += [string]$technique }
    }
    $mitreUnique = @($mitreUnique | Sort-Object)

    $result = New-Object PSObject
    Add-Member -InputObject $result -NotePropertyName RawScore -NotePropertyValue ([int]$failedPoints)
    Add-Member -InputObject $result -NotePropertyName MaxPossibleScore -NotePropertyValue ([int]($failedPoints + $warningPoints))
    Add-Member -InputObject $result -NotePropertyName RiskPoints -NotePropertyValue ([int]$riskPoints)
    Add-Member -InputObject $result -NotePropertyName FailedPoints -NotePropertyValue ([int]$failedPoints)
    Add-Member -InputObject $result -NotePropertyName WarningPoints -NotePropertyValue ([int]$warningPoints)
    Add-Member -InputObject $result -NotePropertyName NormalizedScore -NotePropertyValue ([int]$normalizedScore)
    Add-Member -InputObject $result -NotePropertyName AdditiveRiskScore -NotePropertyValue ([int]$normalizedScore)
    Add-Member -InputObject $result -NotePropertyName CompliancePercent -NotePropertyValue ([int]$compliancePercent)
    Add-Member -InputObject $result -NotePropertyName RiskRating -NotePropertyValue ([string]$riskRating)
    Add-Member -InputObject $result -NotePropertyName StatusCounts -NotePropertyValue $statusCounts
    Add-Member -InputObject $result -NotePropertyName SeverityCounts -NotePropertyValue $severityCounts
    Add-Member -InputObject $result -NotePropertyName CategoryScores -NotePropertyValue $categoryScores
    Add-Member -InputObject $result -NotePropertyName TopCategories -NotePropertyValue $topCategories
    Add-Member -InputObject $result -NotePropertyName FailedCritical -NotePropertyValue ([int]$failedCritical)
    Add-Member -InputObject $result -NotePropertyName FailedHigh -NotePropertyValue ([int]$failedHigh)
    Add-Member -InputObject $result -NotePropertyName HighestFailedSeverity -NotePropertyValue ([string]$highestFailedSeverity)
    Add-Member -InputObject $result -NotePropertyName MitreTechniques -NotePropertyValue $mitreUnique
    Add-Member -InputObject $result -NotePropertyName TopFailed -NotePropertyValue $topFailed
    Add-Member -InputObject $result -NotePropertyName RemediationPlan -NotePropertyValue $remediationPlan
    Add-Member -InputObject $result -NotePropertyName QuickWins -NotePropertyValue $quickWins
    Add-Member -InputObject $result -NotePropertyName CoverageGaps -NotePropertyValue $coverageGaps
    Add-Member -InputObject $result -NotePropertyName TestedCount -NotePropertyValue ([int]$tested)
    Add-Member -InputObject $result -NotePropertyName TotalFindings -NotePropertyValue (@($Findings).Count)
    return $result
}

function Test-AuditSeverityGate {
    <#
        Returns $true when the audit result is at or above the requested severity gate,
        which lets a pipeline fail a build on new Active Directory risk.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][PSCustomObject]$ScoreResult,
        [ValidateSet("None", "Critical", "High", "Medium", "Low")][string]$FailOnSeverity = "None"
    )
    if ($FailOnSeverity -eq "None") { return $false }
    $rank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; None = 99 }
    $highest = [string]$ScoreResult.HighestFailedSeverity
    if (-not $rank.ContainsKey($highest)) { return $false }
    return ($rank[$highest] -le $rank[$FailOnSeverity])
}

Export-ModuleMember -Function @("Invoke-RiskScoring", "Test-AuditSeverityGate", "Get-AuditSeverityWeight")
