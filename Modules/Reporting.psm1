# Reporting.psm1 - HTML, CSV, and JSON report generation
# Requires PowerShell 5.1+

Import-Module (Join-Path $PSScriptRoot "Common.psm1") -ErrorAction SilentlyContinue

function Import-AuditBaseline {
    <#
        Loads a previous JSON export so the current run can be reported as a delta.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $raw = Get-Content -Path $Path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        $data = $raw | ConvertFrom-Json -ErrorAction Stop
        $findings = @($data.Findings)
        if ($findings.Count -eq 0) { return $null }
        $imported = New-Object PSObject
        Add-Member -InputObject $imported -NotePropertyName Path -NotePropertyValue $Path
        Add-Member -InputObject $imported -NotePropertyName Findings -NotePropertyValue $findings
        Add-Member -InputObject $imported -NotePropertyName Timestamp -NotePropertyValue $(if ($data.AuditMetadata) { $data.AuditMetadata.Timestamp } else { $null })
        Add-Member -InputObject $imported -NotePropertyName Score -NotePropertyValue $(if ($data.AuditMetadata) { $data.AuditMetadata.Score } else { $null })
        return $imported
    } catch {
        return $null
    }
}

function Compare-AuditBaseline {
    <#
        Compares the open (failed or warning) findings of two runs by CheckId and
        reports what was fixed, what appeared, and where the affected count grew.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][array]$Current,
        [Parameter(Mandatory = $true)][array]$Baseline
    )

    $openStatuses = @("Failed", "Warning")
    $currentOpen = @{}
    foreach ($f in $Current) {
        if ($openStatuses -contains [string]$f.Status) { $currentOpen["$($f.CheckId)"] = $f }
    }
    $baselineOpen = @{}
    foreach ($f in $Baseline) {
        if ($openStatuses -contains [string]$f.Status) { $baselineOpen["$($f.CheckId)"] = $f }
    }

    $new = @()
    $increased = @()
    $unchanged = @()
    $resolved = @()

    foreach ($id in @($currentOpen.Keys)) {
        $currentItem = $currentOpen[$id]
        $entry = New-Object PSObject
        Add-Member -InputObject $entry -NotePropertyName CheckId -NotePropertyValue $id
        Add-Member -InputObject $entry -NotePropertyName Category -NotePropertyValue $currentItem.Category
        Add-Member -InputObject $entry -NotePropertyName Title -NotePropertyValue $currentItem.Title
        Add-Member -InputObject $entry -NotePropertyName Severity -NotePropertyValue $currentItem.Severity
        Add-Member -InputObject $entry -NotePropertyName Status -NotePropertyValue $currentItem.Status
        Add-Member -InputObject $entry -NotePropertyName AffectedCount -NotePropertyValue ([int]$currentItem.AffectedCount)
        Add-Member -InputObject $entry -NotePropertyName PreviousAffectedCount -NotePropertyValue $null
        if (-not $baselineOpen.ContainsKey($id)) {
            $new += $entry
            continue
        }
        $entry.PreviousAffectedCount = [int]$baselineOpen[$id].AffectedCount
        if ($entry.AffectedCount -gt $entry.PreviousAffectedCount) { $increased += $entry } else { $unchanged += $entry }
    }

    foreach ($id in @($baselineOpen.Keys)) {
        if ($currentOpen.ContainsKey($id)) { continue }
        $old = $baselineOpen[$id]
        $resolvedEntry = New-Object PSObject
        Add-Member -InputObject $resolvedEntry -NotePropertyName CheckId -NotePropertyValue $id
        Add-Member -InputObject $resolvedEntry -NotePropertyName Category -NotePropertyValue $old.Category
        Add-Member -InputObject $resolvedEntry -NotePropertyName Title -NotePropertyValue $old.Title
        Add-Member -InputObject $resolvedEntry -NotePropertyName Severity -NotePropertyValue $old.Severity
        Add-Member -InputObject $resolvedEntry -NotePropertyName Status -NotePropertyValue "Resolved"
        Add-Member -InputObject $resolvedEntry -NotePropertyName AffectedCount -NotePropertyValue 0
        Add-Member -InputObject $resolvedEntry -NotePropertyName PreviousAffectedCount -NotePropertyValue ([int]$old.AffectedCount)
        $resolved += $resolvedEntry
    }

    $delta = New-Object PSObject
    Add-Member -InputObject $delta -NotePropertyName New -NotePropertyValue $new
    Add-Member -InputObject $delta -NotePropertyName Increased -NotePropertyValue $increased
    Add-Member -InputObject $delta -NotePropertyName Unchanged -NotePropertyValue $unchanged
    Add-Member -InputObject $delta -NotePropertyName Resolved -NotePropertyValue $resolved
    Add-Member -InputObject $delta -NotePropertyName NewCount -NotePropertyValue @($new).Count
    Add-Member -InputObject $delta -NotePropertyName IncreasedCount -NotePropertyValue @($increased).Count
    Add-Member -InputObject $delta -NotePropertyName UnchangedCount -NotePropertyValue @($unchanged).Count
    Add-Member -InputObject $delta -NotePropertyName ResolvedCount -NotePropertyValue @($resolved).Count
    return $delta
}

function Export-AuditReports {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Findings,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ScoreResult,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [array]$Edges = @(),

        [Parameter(Mandatory = $false)]
        [string]$Domain = "Local Domain",

        [Parameter(Mandatory = $false)]
        [bool]$GenerateHtml = $true,

        [Parameter(Mandatory = $false)]
        [bool]$GenerateCsv = $true,

        [Parameter(Mandatory = $false)]
        [bool]$GenerateJson = $true,

        [Parameter(Mandatory = $false)]
        [int]$MaxObjectsPerFinding = 100,

        [Parameter(Mandatory = $false)]
        [string]$BaselinePath = ""
    )

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # Read the baseline before the JSON export overwrites it, so an unattended re-run
    # in the same folder automatically produces a comparison against the previous run.
    $jsonPath = Join-Path $OutputPath "AD-Security-Audit-Findings.json"
    $baseline = $null
    $baselineLabel = $null
    if ($BaselinePath -and (Test-Path $BaselinePath)) {
        $baseline = Import-AuditBaseline -Path $BaselinePath
        if ($baseline) { $baselineLabel = $BaselinePath }
    } elseif (Test-Path $jsonPath) {
        $baseline = Import-AuditBaseline -Path $jsonPath
        if ($baseline) { $baselineLabel = "previous run in this output folder" }
    }
    $delta = $null
    if ($baseline) {
        $delta = Compare-AuditBaseline -Current $Findings -Baseline $baseline.Findings
    }

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $user = Get-AuditCurrentIdentity
    $computer = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } elseif ($env:HOSTNAME) { $env:HOSTNAME } else { [System.Net.Dns]::GetHostName() }
    $session = Get-AuditDirectorySession
    $provider = if ($session) { $session.Provider } else { "None" }
    $auditVersion = "2.2.0"

    # 1. Export CSV Reports
    if ($GenerateCsv) {
        $csvPath = Join-Path $OutputPath "AD-Security-Audit-Findings.csv"
        $Findings | Select-Object CheckId, Category, Subcategory, Title, Severity, Status, RiskScore, AffectedCount, RequiredPermission, DataSource | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

        if ($Edges.Count -gt 0) {
            $edgesCsvPath = Join-Path $OutputPath "AD-Security-Audit-AttackPaths.csv"
            $Edges | Export-Csv -Path $edgesCsvPath -NoTypeInformation -Encoding UTF8
        }
    }

    # 2. Export JSON Report
    if ($GenerateCsv -and $ScoreResult.RemediationPlan) {
        $planCsvPath = Join-Path $OutputPath "AD-Security-Audit-RemediationPlan.csv"
        @($ScoreResult.RemediationPlan) | Export-Csv -Path $planCsvPath -NoTypeInformation -Encoding UTF8
    }

    if ($GenerateJson) {
        $reportData = @{
            AuditMetadata = @{
                Domain    = $Domain
                Timestamp = $timestamp
                Auditor   = $user
                Host      = $computer
                Version   = $auditVersion
                Provider  = $provider
                Score     = $ScoreResult
                Baseline  = $(if ($baseline) { @{ Source = $baselineLabel; Timestamp = $baseline.Timestamp } } else { $null })
                Trend     = $(if ($delta) { @{ New = $delta.NewCount; Increased = $delta.IncreasedCount; Resolved = $delta.ResolvedCount; Unchanged = $delta.UnchangedCount } } else { $null })
            }
            Findings      = $Findings
            AttackPaths   = $Edges
        }
        $reportData | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8
    }

    # 3. Export Master Tabbed HTML Report
    if ($GenerateHtml) {
        $htmlPath = Join-Path $OutputPath "AD-Security-Audit-Summary.html"

        $css = @"
<style>
    :root {
        --paper: #f3f5f7;
        --surface: #ffffff;
        --ink: #122033;
        --muted: #5b6b7c;
        --line: #d7dee6;
        --navy: #10263d;
        --navy-2: #17324d;
        --accent: #1d4f7a;
        --critical: #b42318;
        --high: #c2410c;
        --medium: #a16207;
        --low: #17663a;
        --pass: #17663a;
        --warn: #a16207;
        --skip: #5b6b7c;
    }
    * { box-sizing: border-box; }
    html { color-scheme: light; }
    body {
        margin: 0;
        background: var(--paper);
        color: var(--ink);
        font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
        font-size: 14px;
        line-height: 1.5;
    }
    .page { max-width: 1240px; margin: 0 auto; padding: 20px 20px 48px; }

    .masthead {
        background: var(--navy);
        color: #e8eef4;
        padding: 22px 28px 18px;
        border-radius: 6px;
        display: flex;
        justify-content: space-between;
        gap: 24px;
        align-items: flex-start;
    }
    .kicker {
        margin: 0 0 6px;
        font-size: 11px;
        font-weight: 650;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: #9bb0c4;
    }
    .masthead h1 {
        margin: 0 0 4px;
        font-size: 22px;
        font-weight: 650;
        color: #ffffff;
        letter-spacing: -0.02em;
    }
    .masthead .domain {
        margin: 0;
        font-size: 15px;
        color: #c5d4e3;
        font-weight: 500;
    }
    .btn-export {
        flex: 0 0 auto;
        background: transparent;
        color: #ffffff;
        border: 1px solid #6d8499;
        padding: 8px 14px;
        font-size: 13px;
        font-weight: 600;
        border-radius: 4px;
        cursor: pointer;
    }
    .btn-export:hover { background: rgba(255,255,255,0.08); border-color: #c5d4e3; }

    .meta {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 2px 24px;
        margin: 12px 0 0;
        padding: 12px 28px 16px;
        background: var(--navy-2);
        border-radius: 0 0 6px 6px;
        margin-top: -6px;
    }
    .meta div { min-width: 0; padding: 6px 0; }
    .meta dt {
        margin: 0;
        font-size: 10px;
        font-weight: 650;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: #8aa0b5;
    }
    .meta dd { margin: 2px 0 0; font-size: 13px; color: #e8eef4; word-break: break-word; }

    .nav-wrap {
        position: sticky;
        top: 0;
        z-index: 20;
        background: var(--paper);
        margin: 0 -20px;
        padding: 10px 20px 0;
        border-bottom: 1px solid var(--line);
    }
    .nav-container {
        display: flex;
        flex-wrap: nowrap;
        gap: 2px;
        overflow-x: auto;
        padding: 0 0 8px;
        scrollbar-width: thin;
    }
    .tab-btn {
        flex: 0 0 auto;
        background: transparent;
        border: none;
        border-bottom: 2px solid transparent;
        padding: 10px 12px;
        font-size: 12.5px;
        font-weight: 600;
        color: var(--muted);
        cursor: pointer;
        white-space: nowrap;
        border-radius: 0;
    }
    .tab-btn:hover { color: var(--ink); background: rgba(16,38,61,0.04); }
    .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); background: transparent; }
    .nav-count {
        display: inline-block;
        margin-left: 6px;
        padding: 0 6px;
        border-radius: 999px;
        background: #e6edf3;
        color: #334155;
        font-size: 11px;
        font-weight: 650;
        line-height: 18px;
    }
    .tab-btn.active .nav-count { background: #d7e6f4; color: var(--accent); }

    .tab-content { display: none; padding-top: 22px; }
    .tab-content.active { display: block; }

    .kpis { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; margin-bottom: 14px; }
    .kpi {
        background: var(--surface);
        border: 1px solid var(--line);
        border-left: 3px solid var(--line);
        border-radius: 6px;
        padding: 14px 16px 12px;
        min-width: 0;
    }
    .kpi.is-critical { border-left-color: var(--critical); }
    .kpi.is-high { border-left-color: var(--high); }
    .kpi.is-elevated, .kpi.is-moderate { border-left-color: var(--medium); }
    .kpi.is-low { border-left-color: var(--low); }
    .kpi.is-action { border-left-color: var(--critical); }
    .kpi.is-pass { border-left-color: var(--pass); }
    .kpi-label {
        font-size: 11px;
        font-weight: 650;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: var(--muted);
    }
    .kpi-value {
        margin: 6px 0 2px;
        font-size: 28px;
        font-weight: 700;
        letter-spacing: -0.03em;
        font-variant-numeric: tabular-nums;
        line-height: 1.15;
        color: var(--ink);
    }
    .kpi.is-critical .kpi-value { color: var(--critical); }
    .kpi.is-high .kpi-value { color: var(--high); }
    .kpi.is-action .kpi-value { color: var(--critical); }
    .kpi.is-pass .kpi-value { color: var(--pass); }
    .kpi-suffix { font-size: 14px; font-weight: 600; color: var(--muted); margin-left: 2px; }
    .kpi-meta { margin-top: 4px; font-size: 12px; color: var(--muted); }
    .meter {
        margin-top: 10px;
        height: 6px;
        background: #e8eef3;
        border-radius: 999px;
        overflow: hidden;
    }
    .meter > span { display: block; height: 100%; background: var(--accent); border-radius: 999px; }
    .kpi.is-critical .meter > span { background: var(--critical); }
    .kpi.is-high .meter > span { background: var(--high); }
    .kpi.is-pass .meter > span { background: var(--pass); }
    .kpi.is-action .meter > span { background: var(--critical); }

    .mix-panel {
        background: var(--surface);
        border: 1px solid var(--line);
        border-radius: 6px;
        padding: 12px 16px 14px;
        margin-bottom: 28px;
    }
    .mix-panel .mix-label {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        font-size: 12px;
        color: var(--muted);
        margin-bottom: 8px;
    }
    .mix { display: flex; height: 8px; border-radius: 999px; overflow: hidden; background: #e8eef3; }
    .mix span { min-width: 0; }
    .mix .fail { background: var(--critical); }
    .mix .warn { background: var(--warn); }
    .mix .pass { background: var(--pass); }
    .mix .info { background: #64748b; }
    .mix-legend .info i { background: #64748b; }
    .mix-legend { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 10px; font-size: 12px; color: var(--muted); }
    .mix-legend i { display: inline-block; width: 8px; height: 8px; border-radius: 99px; margin-right: 6px; vertical-align: middle; }
    .mix-legend .fail i { background: var(--critical); }
    .mix-legend .warn i { background: var(--warn); }
    .mix-legend .pass i { background: var(--pass); }
    .mix-legend .skip i { background: #94a3b8; }

    .section-title {
        display: block;
        font-size: 15px;
        font-weight: 650;
        color: var(--navy);
        margin: 28px 0 12px;
        padding-bottom: 8px;
        border-bottom: 1px solid var(--line);
        letter-spacing: 0;
    }
    .section-lead { margin: -4px 0 14px; font-size: 13px; color: var(--muted); max-width: 820px; }

    .badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 999px;
        font-size: 11px;
        font-weight: 650;
        letter-spacing: 0.02em;
        line-height: 1.5;
        white-space: nowrap;
    }
    .badge-critical, .Critical-bg { background: #fde8e6; color: var(--critical); }
    .badge-high, .High-bg { background: #ffedd5; color: var(--high); }
    .badge-medium, .Medium-bg { background: #fef3c7; color: var(--medium); }
    .badge-low, .Low-bg { background: #dcfce7; color: var(--low); }
    .badge-pass, .Passed-badge { background: #dcfce7; color: var(--pass); }
    .badge-fail, .Failed-badge { background: #fde8e6; color: var(--critical); }
    .badge-warn, .Warning-badge { background: #fef3c7; color: var(--warn); }
    .badge-info, .Informational-badge { background: #e8eef4; color: #334155; }
    .badge-skip, .NotTested-badge { background: #eef2f6; color: var(--skip); }
    .Critical-bg, .High-bg, .Medium-bg, .Low-bg { background: transparent; font-weight: 650; }
    .Critical-bg { color: var(--critical); }
    .High-bg { color: var(--high); }
    .Medium-bg { color: var(--medium); }
    .Low-bg { color: var(--low); }

    .pill {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }
    .kpi.is-critical .pill { background: #fde8e6; color: var(--critical); }
    .kpi.is-high .pill { background: #ffedd5; color: var(--high); }
    .kpi.is-elevated .pill, .kpi.is-moderate .pill { background: #fef3c7; color: var(--medium); }
    .kpi.is-low .pill { background: #dcfce7; color: var(--low); }

    .table-wrap { overflow-x: auto; margin-bottom: 24px; border: 1px solid var(--line); border-radius: 6px; background: var(--surface); }
    table { width: 100%; border-collapse: collapse; background: var(--surface); margin: 0; }
    th {
        background: var(--navy);
        color: #f4f7fa;
        text-align: left;
        padding: 9px 12px;
        font-size: 11px;
        font-weight: 650;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        white-space: nowrap;
    }
    td {
        padding: 9px 12px;
        border-bottom: 1px solid #edf1f5;
        font-size: 13px;
        vertical-align: top;
        word-break: break-word;
    }
    tbody tr:nth-child(even) { background: #f8fafc; }
    tbody tr:hover { background: #eef4f9; }
    tbody tr:last-child td { border-bottom: none; }
    td:first-child strong {
        font-family: ui-monospace, "SF Mono", Consolas, "Liberation Mono", monospace;
        font-size: 12px;
        font-weight: 650;
        color: var(--accent);
        white-space: nowrap;
    }
    table.nums td:nth-child(n+2) { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
    table.nums th:nth-child(n+2) { text-align: right; }
    .count-fail { color: var(--critical); font-weight: 650; }
    .count-warn { color: var(--warn); font-weight: 650; }
    .count-pass { color: var(--pass); font-weight: 650; }
    .points { display: flex; align-items: center; justify-content: flex-end; gap: 8px; }
    .points-bar { display: inline-block; width: 88px; height: 6px; background: #e8eef3; border-radius: 99px; overflow: hidden; vertical-align: middle; }
    .points-bar i { display: block; height: 100%; background: var(--navy); }
    .points-n { font-variant-numeric: tabular-nums; font-weight: 650; min-width: 2.2em; text-align: right; }

    .empty-state {
        margin: 0 0 24px;
        padding: 16px 18px;
        border: 1px dashed var(--line);
        border-radius: 6px;
        color: var(--muted);
        background: #f8fafc;
        font-size: 13px;
    }
    .search-box {
        width: 100%;
        padding: 10px 12px;
        border: 1px solid var(--line);
        border-radius: 4px;
        margin: 0 0 12px;
        font-size: 13px;
        outline: none;
        background: var(--surface);
    }
    .search-box:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(29,79,122,0.12); }

    .footer {
        text-align: center;
        font-size: 12px;
        color: var(--muted);
        margin-top: 36px;
        padding: 16px 8px 0;
        border-top: 1px solid var(--line);
    }

    @media (max-width: 980px) {
        .kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .masthead { flex-direction: column; }
    }
    @media print {
        body { background: #fff; }
        .page { max-width: none; padding: 0; }
        .nav-wrap, .btn-export, .search-box { display: none !important; }
        .tab-content { display: block !important; break-before: page; padding-top: 0; }
        #tab-indicators { break-before: auto; }
        .tab-content[data-title]::before {
            content: attr(data-title);
            display: block;
            font-size: 16px;
            font-weight: 700;
            color: var(--navy);
            margin: 0 0 14px;
            padding-bottom: 8px;
            border-bottom: 1px solid #cbd5e1;
        }
        .masthead, .meta, .kpi, .table-wrap, table { box-shadow: none !important; }
        .masthead, .meta, th { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        th { position: static; }
        tbody tr { break-inside: avoid; }
    }
</style>
"@

        $js = @"
<script>
    function downloadPdf() { window.print(); }
    function openTab(evt, tabName) {
        var i, tabcontent, tablinks;
        tabcontent = document.getElementsByClassName("tab-content");
        for (i = 0; i < tabcontent.length; i++) {
            tabcontent[i].classList.remove("active");
            tabcontent[i].style.display = "none";
        }
        tablinks = document.getElementsByClassName("tab-btn");
        for (i = 0; i < tablinks.length; i++) {
            tablinks[i].classList.remove("active");
            tablinks[i].setAttribute("aria-selected", "false");
        }
        var panel = document.getElementById(tabName);
        if (!panel) { return; }
        panel.style.display = "block";
        panel.classList.add("active");
        if (evt && evt.currentTarget) {
            evt.currentTarget.classList.add("active");
            evt.currentTarget.setAttribute("aria-selected", "true");
        }
        if (history.replaceState) { history.replaceState(null, "", "#" + tabName); }
    }
    function filterTable(inputId, tableId) {
        var input = document.getElementById(inputId);
        var filter = input.value.toUpperCase();
        var table = document.getElementById(tableId);
        if (!table) { return; }
        var tr = table.getElementsByTagName("tr");
        for (var i = 1; i < tr.length; i++) {
            var text = tr[i].textContent || tr[i].innerText;
            tr[i].style.display = text.toUpperCase().indexOf(filter) > -1 ? "" : "none";
        }
    }
    window.addEventListener("DOMContentLoaded", function () {
        var id = (location.hash || "#tab-indicators").replace("#", "");
        var btn = document.querySelector('[data-tab="' + id + '"]');
        if (btn) { btn.click(); }
    });
</script>
"@

        function Get-HtmlSeverityBadge {
            param([string]$Severity)
            $cls = switch ($Severity) {
                "Critical" { "badge badge-critical" }
                "High" { "badge badge-high" }
                "Medium" { "badge badge-medium" }
                "Low" { "badge badge-low" }
                default { "badge badge-info" }
            }
            return "<span class='$cls'>$(ConvertTo-AuditHtml $Severity)</span>"
        }

        function Get-HtmlStatusBadge {
            param([string]$Status)
            $cls = switch ($Status) {
                "Passed" { "badge badge-pass" }
                "Failed" { "badge badge-fail" }
                "Warning" { "badge badge-warn" }
                "Informational" { "badge badge-info" }
                "Resolved" { "badge badge-pass" }
                "Error" { "badge badge-fail" }
                default { "badge badge-skip" }
            }
            return "<span class='$cls'>$(ConvertTo-AuditHtml $Status)</span>"
        }

        # Helper function to construct structured table from object arrays
        function New-HtmlTable {
            param(
                [array]$Headers,
                [array]$DataRows,
                [string]$TableId = "tableId",
                [string]$TableClass = ""
            )
            if (-not $DataRows -or @($DataRows).Count -eq 0) {
                return "<div class='empty-state'>No objects or findings in this section.</div>"
            }

            # `$rows += @(a, b, c)` flattens in PowerShell. Rebuild logical rows from
            # that flat stream when callers passed one array of cells per record.
            $logicalRows = New-Object System.Collections.Generic.List[object]
            $first = $DataRows[0]
            $alreadyNested = ($first -is [System.Collections.IList] -and $first -isnot [string])
            if ($alreadyNested) {
                foreach ($row in $DataRows) { [void]$logicalRows.Add(@($row)) }
            } elseif ($Headers.Count -gt 1) {
                $flat = @($DataRows)
                for ($i = 0; $i -lt $flat.Count; $i += $Headers.Count) {
                    $end = [Math]::Min($i + $Headers.Count - 1, $flat.Count - 1)
                    [void]$logicalRows.Add(@($flat[$i..$end]))
                }
            } else {
                foreach ($row in $DataRows) { [void]$logicalRows.Add(@($row)) }
            }

            $thHtml = ($Headers | ForEach-Object { "<th>$_</th>" }) -join ""
            $trHtml = ""
            foreach ($row in $logicalRows) {
                $tds = (@($row) | ForEach-Object {
                    $cell = "$_"
                    if ($cell.StartsWith("<")) { "<td>$cell</td>" } else { "<td>$(ConvertTo-AuditHtml $cell)</td>" }
                }) -join ""
                $trHtml += "<tr>$tds</tr>"
            }
            $clsAttr = if ($TableClass) { " class='$TableClass'" } else { "" }
            return "<div class='table-wrap'><table id='$TableId'$clsAttr><thead><tr>$thHtml</tr></thead><tbody>$trHtml</tbody></table></div>"
        }

        # Helper to extract affected objects by CheckId
        function Get-ObjectsByCheckId {
            param([string]$CheckId)
            $res = @()
            foreach ($f in $Findings) {
                if ($f.CheckId -eq $CheckId -and $f.AffectedObjects -and @("Failed", "Warning") -contains [string]$f.Status) {
                    $res += $f.AffectedObjects
                }
            }
            return $res
        }

        $passedCount = 0; $failedCount = 0; $warningCount = 0; $infoCount = 0; $notTestedCount = 0; $errorCount = 0
        if ($ScoreResult.StatusCounts) {
            foreach ($statusKey in @($ScoreResult.StatusCounts.Keys)) {
                switch ([string]$statusKey) {
                    "Passed" { $passedCount = [int]$ScoreResult.StatusCounts[$statusKey] }
                    "Failed" { $failedCount = [int]$ScoreResult.StatusCounts[$statusKey] }
                    "Warning" { $warningCount = [int]$ScoreResult.StatusCounts[$statusKey] }
                    "Informational" { $infoCount = [int]$ScoreResult.StatusCounts[$statusKey] }
                    "Not Tested" { $notTestedCount = [int]$ScoreResult.StatusCounts[$statusKey] }
                    "Error" { $errorCount = [int]$ScoreResult.StatusCounts[$statusKey] }
                }
            }
        }
        $notEvaluatedCount = $notTestedCount + $errorCount
        $totalChecks = [Math]::Max(1, [int]$ScoreResult.TotalFindings)
        $ratingClass = switch -Wildcard ([string]$ScoreResult.RiskRating) {
            "Critical*" { "is-critical" }
            "High*" { "is-high" }
            "Elevated*" { "is-elevated" }
            "Moderate*" { "is-moderate" }
            default { "is-low" }
        }
        $scoreWidth = [int]$ScoreResult.NormalizedScore
        $complianceWidth = [int]$ScoreResult.CompliancePercent
        $providerLabel = if ([string]::IsNullOrWhiteSpace($provider) -or $provider -eq "None") { "Not connected" } else { $provider }
        $domainHtml = ConvertTo-AuditHtml $Domain
        $computerHtml = ConvertTo-AuditHtml $computer
        $userHtml = ConvertTo-AuditHtml $user
        $timestampHtml = ConvertTo-AuditHtml $timestamp
        $providerHtml = ConvertTo-AuditHtml $providerLabel
        $planCount = @($ScoreResult.RemediationPlan).Count
        $coverageCount = @($ScoreResult.CoverageGaps).Count
        $edgeCount = @($Edges).Count
        $findingCount = @($Findings).Count

        # TAB 1: Active Directory Indicators (Overview)
        $categoryScoresRows = @()
        $sortedCategories = @($ScoreResult.CategoryScores.GetEnumerator() | Sort-Object { $_.Value.Points } -Descending | ForEach-Object { $_.Value })
        $maxCatPoints = 1
        foreach ($catData in $sortedCategories) {
            if ([int]$catData.Points -gt $maxCatPoints) { $maxCatPoints = [int]$catData.Points }
        }
        foreach ($catData in $sortedCategories) {
            $pct = [int][Math]::Round(100.0 * [int]$catData.Points / $maxCatPoints)
            $failedCell = if ([int]$catData.FailedCount -gt 0) { "<span class='count-fail'>$($catData.FailedCount)</span>" } else { "$($catData.FailedCount)" }
            $warnCell = if ([int]$catData.WarningCount -gt 0) { "<span class='count-warn'>$($catData.WarningCount)</span>" } else { "$($catData.WarningCount)" }
            $passCell = if ([int]$catData.PassedCount -gt 0) { "<span class='count-pass'>$($catData.PassedCount)</span>" } else { "$($catData.PassedCount)" }
            $pointsCell = "<div class='points'><span class='points-bar'><i style='width:$($pct)%'></i></span><span class='points-n'>$($catData.Points)</span></div>"
            $categoryScoresRows += @(
                $catData.Category,
                $catData.TotalChecks,
                $passCell,
                $warnCell,
                $failedCell,
                $catData.NotTestedCount,
                $pointsCell
            )
        }
        $catScoreTableHtml = New-HtmlTable -Headers @("Audit Category", "Checks", "Passed", "Warning", "Failed", "Not Tested", "Risk Points") -DataRows $categoryScoresRows -TableId "catScoreTable" -TableClass "nums"

        # Prioritised remediation roadmap, quick wins, and coverage transparency.
        $roadmapRows = @()
        foreach ($item in @($ScoreResult.RemediationPlan)) {
            $roadmapRows += @(
                $item.Priority,
                "<strong>$($item.CheckId)</strong>",
                (Get-HtmlSeverityBadge $item.Severity),
                $item.Category,
                $item.Title,
                $item.AffectedCount,
                $item.Recommendation
            )
        }
        $roadmapTableHtml = New-HtmlTable -Headers @("#", "Check ID", "Severity", "Category", "Finding", "Affected", "Recommended action") -DataRows $roadmapRows -TableId "roadmapTable"

        $quickWinRows = @()
        foreach ($item in @($ScoreResult.QuickWins)) {
            $quickWinRows += @($item.CheckId, (Get-HtmlSeverityBadge $item.Severity), $item.Title, $item.AffectedCount, $item.Recommendation)
        }
        $quickWinTableHtml = New-HtmlTable -Headers @("Check ID", "Severity", "Finding", "Affected objects", "Recommended action") -DataRows $quickWinRows -TableId "quickWinTable"

        $coverageRows = @()
        foreach ($item in @($ScoreResult.CoverageGaps)) {
            $coverageRows += @($item.CheckId, $item.Category, $item.Title, (Get-HtmlStatusBadge $item.Status), $item.RequiredPermission, $item.Reason)
        }
        $coverageTableHtml = New-HtmlTable -Headers @("Check ID", "Category", "Check", "Status", "Required access", "Why it was not evaluated") -DataRows $coverageRows -TableId "coverageTable"

        $trendSummaryHtml = "<div class='empty-state'>No previous JSON export was found in this output folder, so this run establishes the baseline. Re-run the audit against the same output folder to see what changed.</div>"
        $trendNewHtml = ""
        $trendResolvedHtml = ""
        if ($delta) {
            $trendSummaryHtml = New-HtmlTable -Headers @("Comparison", "Value") -DataRows @(
                @("Baseline source", $baselineLabel),
                @("Baseline timestamp", $(if ($baseline.Timestamp) { $baseline.Timestamp } else { "unknown" })),
                @("New open findings", $delta.NewCount),
                @("Findings affecting more objects than before", $delta.IncreasedCount),
                @("Unchanged open findings", $delta.UnchangedCount),
                @("Findings resolved since the baseline", $delta.ResolvedCount)
            ) -TableId "trendSummaryTable"

            $newRows = @()
            foreach ($item in @($delta.New) + @($delta.Increased)) {
                $previous = if ($null -eq $item.PreviousAffectedCount) { "new" } else { $item.PreviousAffectedCount }
                $newRows += @($item.CheckId, (Get-HtmlSeverityBadge $item.Severity), $item.Category, $item.Title, $previous, $item.AffectedCount)
            }
            $trendNewHtml = New-HtmlTable -Headers @("Check ID", "Severity", "Category", "Finding", "Previously affected", "Now affected") -DataRows $newRows -TableId "trendNewTable"

            $resolvedRows = @()
            foreach ($item in @($delta.Resolved)) {
                $resolvedRows += @($item.CheckId, (Get-HtmlSeverityBadge $item.Severity), $item.Category, $item.Title, $item.PreviousAffectedCount)
            }
            $trendResolvedHtml = New-HtmlTable -Headers @("Check ID", "Severity", "Category", "Finding", "Objects affected in baseline") -DataRows $resolvedRows -TableId "trendResolvedTable"
        }

        # TAB 2: Rules Matched (All Findings Table)
        $allRulesRows = @()
        foreach ($f in $Findings) {
            $allRulesRows += @(
                "<strong>$($f.CheckId)</strong>",
                $f.Category,
                $f.Title,
                (Get-HtmlSeverityBadge $f.Severity),
                (Get-HtmlStatusBadge $f.Status),
                $f.RiskScore,
                $f.Recommendation
            )
        }
        $allRulesTableHtml = New-HtmlTable -Headers @("Check ID", "Category", "Title", "Severity", "Status", "Risk Score", "Recommendation") -DataRows $allRulesRows -TableId "rulesMatchedTable"

        # TAB 3: Domain Information
        $domInfoRows = @(
            @("Target Domain FQDN", $Domain),
            @("Directory provider", $providerLabel),
            @("Auditor Host", $computer),
            @("Execution User", $user),
            @("Framework version", $auditVersion),
            @("Audit Execution Time", $timestamp),
            @("Compliance (passed / tested)", "$($ScoreResult.CompliancePercent)%"),
            @("Failed Critical / High", "$($ScoreResult.FailedCritical) / $($ScoreResult.FailedHigh)"),
            @("Accumulated risk points", "$($ScoreResult.RiskPoints)"),
            @("Checks evaluated / total", "$($ScoreResult.TestedCount) / $($ScoreResult.TotalFindings)"),
            @("Checks not evaluated", "$(@($ScoreResult.CoverageGaps).Count)"),
            @("Baseline comparison", $(if ($baselineLabel) { "$baselineLabel (new: $($delta.NewCount), resolved: $($delta.ResolvedCount))" } else { "none - this run is the baseline" }))
        )
        $domInfoTableHtml = New-HtmlTable -Headers @("Property / Metric", "Configuration Value") -DataRows $domInfoRows -TableId "domInfoTable"

        # TAB 4: User Information
        $pneUsers = Get-ObjectsByCheckId "AD-USR-001" | ForEach-Object { @($_, "Password Never Expires") }
        $pwdNotReqUsers = Get-ObjectsByCheckId "AD-USR-002" | ForEach-Object { @($_, "Password Not Required (PASSWD_NOTREQD)") }
        $inactiveUsers = Get-ObjectsByCheckId "AD-USR-003" | ForEach-Object { @($_, "Inactive User Account (>90 Days)") }
        $spnUsers = Get-ObjectsByCheckId "AD-USR-004" | ForEach-Object { @($_, "Traditional Service Account (SPN Set)") }
        $descLeakUsers = Get-ObjectsByCheckId "AD-USR-005" | ForEach-Object { @($_, "Credential Leak in Description / Notes") }
        $genericUsers = Get-ObjectsByCheckId "AD-USR-006" | ForEach-Object { @($_, "Generic / Default Account Name") }
        $sidHistUsers = Get-ObjectsByCheckId "AD-USR-007" | ForEach-Object { @($_, "Active sidHistory Attribute") }
        $revEncUsers = Get-ObjectsByCheckId "AD-USR-008" | ForEach-Object { @($_, "Reversible encryption") }
        $kerberoastUsers = Get-ObjectsByCheckId "AD-USR-009" | ForEach-Object { @($_, "Kerberoastable SPN") }
        $neverSetPwd = Get-ObjectsByCheckId "AD-USR-010" | ForEach-Object { @($_, "pwdLastSet=0") }
        $orphanAdmin = Get-ObjectsByCheckId "AD-USR-011" | ForEach-Object { @($_, "Orphaned adminCount=1") }

        $pneTableHtml = New-HtmlTable -Headers @("User Account (SamAccountName)", "Security Concern") -DataRows $pneUsers -TableId "pneTable"
        $pwdNotReqTableHtml = New-HtmlTable -Headers @("User Account", "Security Concern") -DataRows $pwdNotReqUsers -TableId "pwdNotReqTable"
        $inactiveUsersTableHtml = New-HtmlTable -Headers @("Account & Last Logon Timestamp", "Security Concern") -DataRows $inactiveUsers -TableId "inactiveUsersTable"
        $spnUsersTableHtml = New-HtmlTable -Headers @("Service Account Name", "Recommendation") -DataRows $spnUsers -TableId "spnUsersTable"
        $descLeakTableHtml = New-HtmlTable -Headers @("Account & Matched Keyword", "Evidence") -DataRows $descLeakUsers -TableId "descLeakTable"
        $genericUsersTableHtml = New-HtmlTable -Headers @("Account Name", "Category") -DataRows $genericUsers -TableId "genericUsersTable"
        $sidHistTableHtml = New-HtmlTable -Headers @("Account & SID Count", "Risk") -DataRows $sidHistUsers -TableId "sidHistTable"
        $revEncTableHtml = New-HtmlTable -Headers @("Account", "Risk") -DataRows $revEncUsers -TableId "revEncTable"
        $kerberoastTableHtml = New-HtmlTable -Headers @("Account", "Risk") -DataRows $kerberoastUsers -TableId "kerberoastTable"
        $neverSetTableHtml = New-HtmlTable -Headers @("Account", "Risk") -DataRows $neverSetPwd -TableId "neverSetTable"
        $orphanAdminTableHtml = New-HtmlTable -Headers @("Account", "Risk") -DataRows $orphanAdmin -TableId "orphanAdminTable"
        $rid500Users = Get-ObjectsByCheckId "AD-USR-012" | ForEach-Object { @($_, "Built-in RID-500 Administrator") }
        $badPrimaryUsers = Get-ObjectsByCheckId "AD-USR-013" | ForEach-Object { @($_, "Non-standard primaryGroupID") }
        $keyCredUsers = Get-ObjectsByCheckId "AD-USR-014" | ForEach-Object { @($_, "msDS-KeyCredentialLink (shadow credentials / WHfB)") }
        $legacyPwdUsers = Get-ObjectsByCheckId "AD-USR-015" | ForEach-Object { @($_, "Legacy password attribute populated") }
        $rid500TableHtml = New-HtmlTable -Headers @("Account", "Risk") -DataRows $rid500Users -TableId "rid500Table"
        $badPrimaryTableHtml = New-HtmlTable -Headers @("Account", "Risk") -DataRows $badPrimaryUsers -TableId "badPrimaryTable"
        $keyCredTableHtml = New-HtmlTable -Headers @("Account", "Risk") -DataRows $keyCredUsers -TableId "keyCredTable"
        $legacyPwdTableHtml = New-HtmlTable -Headers @("Account", "Risk") -DataRows $legacyPwdUsers -TableId "legacyPwdTable"

        # TAB 5: Computer Information
        $eolComputers = Get-ObjectsByCheckId "AD-CMP-001" | ForEach-Object { @($_, "Unsupported Operating System") }
        $staleMachinePwds = Get-ObjectsByCheckId "AD-CMP-002" | ForEach-Object { @($_, "Stale Machine Password (>90 Days)") }
        $eolCompTableHtml = New-HtmlTable -Headers @("Computer Name & OS Version", "Support Lifecycle Status") -DataRows $eolComputers -TableId "eolCompTable"
        $staleMachineTableHtml = New-HtmlTable -Headers @("Machine Account Name & Password Set Date", "Status") -DataRows $staleMachinePwds -TableId "staleMachineTable"
        $inactiveComputers = Get-ObjectsByCheckId "AD-CMP-003" | ForEach-Object { @($_, "Inactive computer") }
        $inactiveCompTableHtml = New-HtmlTable -Headers @("Computer", "Status") -DataRows $inactiveComputers -TableId "inactiveCompTable"

        # TAB 6: Admin Groups
        $staleAdmins = Get-ObjectsByCheckId "AD-GRP-001" | ForEach-Object { @($_, "Stale or Disabled Administrative Member") }
        $spnAdmins = Get-ObjectsByCheckId "AD-GRP-002" | ForEach-Object { @($_, "Privileged Account with SPN (Kerberoasting Target)") }
        $fspAdmins = Get-ObjectsByCheckId "AD-GRP-003" | ForEach-Object { @($_, "Foreign Security Principal (FSP) Nesting") }
        $rdpUsers = Get-ObjectsByCheckId "AD-GRP-004" | ForEach-Object { @($_, "Remote Desktop Users Group Member") }
        $computerPriv = Get-ObjectsByCheckId "AD-GRP-012" | ForEach-Object { @($_, "Computer nested in a privileged group") }
        $tier0Owners = Get-ObjectsByCheckId "AD-TZ-001" | ForEach-Object { @($_, "Non-Tier 0 owner of a Tier 0 object") }
        $tier0Control = Get-ObjectsByCheckId "AD-TZ-002" | ForEach-Object { @($_, "Non-Tier 0 control of an admin object") }
        $tier0DcControl = Get-ObjectsByCheckId "AD-TZ-003" | ForEach-Object { @($_, "Non-Tier 0 control of a Domain Controller") }

        $staleAdminsTableHtml = New-HtmlTable -Headers @("Administrative Member Account", "Risk") -DataRows $staleAdmins -TableId "staleAdminsTable"
        $spnAdminsTableHtml = New-HtmlTable -Headers @("Privileged Account & SPN", "Vulnerability") -DataRows $spnAdmins -TableId "spnAdminsTable"
        $fspAdminsTableHtml = New-HtmlTable -Headers @("Foreign Security Principal", "Cross-Trust Risk") -DataRows $fspAdmins -TableId "fspAdminsTable"
        $rdpUsersTableHtml = New-HtmlTable -Headers @("RDP Authorized Account / Group", "Logon Scope") -DataRows $rdpUsers -TableId "rdpUsersTable"
        $computerPrivTableHtml = New-HtmlTable -Headers @("Computer / Group", "Risk") -DataRows $computerPriv -TableId "computerPrivTable"
        $tier0OwnersTableHtml = New-HtmlTable -Headers @("Object and owner", "Risk") -DataRows $tier0Owners -TableId "tier0OwnersTable"
        $tier0ControlTableHtml = New-HtmlTable -Headers @("Object and trustee", "Risk") -DataRows $tier0Control -TableId "tier0ControlTable"
        $tier0DcTableHtml = New-HtmlTable -Headers @("Domain Controller object", "Risk") -DataRows $tier0DcControl -TableId "tier0DcTable"

        # TAB 7: Trusts
        $noSidFilterTrusts = Get-ObjectsByCheckId "AD-TRST-001" | ForEach-Object { @($_, "SID Filtering Disabled") }
        $trustsTableHtml = New-HtmlTable -Headers @("Target Domain Trust & Direction", "Quarantine / SID Filter Status") -DataRows $noSidFilterTrusts -TableId "trustsTable"

        # TAB 8: Anomalies & ACLs
        $dcsyncAces = Get-ObjectsByCheckId "AD-ACL-001" | ForEach-Object { @($_, "DCSync Rights Granted on Domain Root") }
        $dangerousAces = Get-ObjectsByCheckId "AD-ACL-002" | ForEach-Object { @($_, "GenericAll / WriteDacl on Domain Root") }
        $ouDelegations = Get-ObjectsByCheckId "AD-ACL-005" | ForEach-Object { @($_, "Dangerous ACE on a top-level OU") }
        $userObjAces = Get-ObjectsByCheckId "AD-ACL-004" | ForEach-Object { @($_, "ForceChangePassword / WriteDacl on Users container") }
        $adminSdHolder = Get-ObjectsByCheckId "AD-ACL-003" | ForEach-Object { @($_, "Unexpected control on AdminSDHolder") }

        $dcsyncTableHtml = New-HtmlTable -Headers @("Principal Granted DCSync Rights", "Granted Extended Rights") -DataRows $dcsyncAces -TableId "dcsyncTable"
        $dangerousAcesTableHtml = New-HtmlTable -Headers @("Principal Granted Root Ownership", "Granted Rights") -DataRows $dangerousAces -TableId "dangerousAcesTable"
        $ouDelegationsTableHtml = New-HtmlTable -Headers @("Identity & Delegated OU Path", "Granted Rights") -DataRows $ouDelegations -TableId "ouDelegationsTable"
        $userObjAcesTableHtml = New-HtmlTable -Headers @("Identity & User Container Scope", "Granted Rights") -DataRows $userObjAces -TableId "userObjAcesTable"
        $adminSdTableHtml = New-HtmlTable -Headers @("Principal on AdminSDHolder", "Granted Rights") -DataRows $adminSdHolder -TableId "adminSdTable"

        # TAB 9: Password Policies
        $pwdPolicyFindings = @()
        foreach ($f in $Findings) {
            if ($f.Category -eq "Password and Authentication Security") {
                $pwdPolicyFindings += @($f.CheckId, $f.Title, (Get-HtmlStatusBadge $f.Status), $f.Recommendation)
            }
        }
        $pwdPolicyTableHtml = New-HtmlTable -Headers @("Check ID", "Password Policy Setting", "Status", "Recommendation") -DataRows $pwdPolicyFindings -TableId "pwdPolicyTable"

        # TAB 10: GPO & Infrastructure
        $cpasswordGpos = Get-ObjectsByCheckId "AD-GPO-001" | ForEach-Object { @($_, "Embedded GPP cpassword XML Found in SYSVOL") }
        $unlinkedGpos = Get-ObjectsByCheckId "AD-GPO-003" | ForEach-Object { @($_, "Unlinked / Empty Group Policy Object") }
        $esc1Templates = Get-ObjectsByCheckId "AD-CS-001" | ForEach-Object { @($_, "ESC1 Vulnerable PKI Certificate Template") }
        $esc4Templates = Get-ObjectsByCheckId "AD-CS-002" | ForEach-Object { @($_, "ESC4 writable certificate template") }
        $esc8Http = Get-ObjectsByCheckId "AD-CS-003" | ForEach-Object { @($_, "HTTP enrollment (ESC8)") }
        $esc9Templates = Get-ObjectsByCheckId "AD-CS-008" | ForEach-Object { @($_, "ESC9 missing SID security extension") }
        $esc13Templates = Get-ObjectsByCheckId "AD-CS-009" | ForEach-Object { @($_, "ESC13 issuance policy linked to a group") }
        $esc5Pki = Get-ObjectsByCheckId "AD-CS-010" | ForEach-Object { @($_, "ESC5 PKI container control") }
        $gpoAcl = Get-ObjectsByCheckId "AD-GPO-002" | ForEach-Object { @($_, "Dangerous GPO write ACE") }
        $gpoOwners = Get-ObjectsByCheckId "AD-GPO-005" | ForEach-Object { @($_, "Non-Tier 0 GPO owner") }
        $gpoSecrets = Get-ObjectsByCheckId "AD-GPO-006" | ForEach-Object { @($_, "Credential-like content in SYSVOL") }
        $gmsaOpen = Get-ObjectsByCheckId "AD-GMSA-002" | ForEach-Object { @($_, "Broad gMSA password retrieval") }

        $cpasswordTableHtml = New-HtmlTable -Headers @("GPO XML File Path in SYSVOL", "Vulnerability") -DataRows $cpasswordGpos -TableId "cpasswordTable"
        $unlinkedGpoTableHtml = New-HtmlTable -Headers @("Unlinked GPO Name & GUID", "Hygiene Status") -DataRows $unlinkedGpos -TableId "unlinkedGpoTable"
        $esc1TableHtml = New-HtmlTable -Headers @("Published Certificate Template Name", "PKI Vulnerability") -DataRows $esc1Templates -TableId "esc1Table"
        $esc4TableHtml = New-HtmlTable -Headers @("Template / Principal", "Risk") -DataRows $esc4Templates -TableId "esc4Table"
        $esc8TableHtml = New-HtmlTable -Headers @("CA enrollment URL", "Risk") -DataRows $esc8Http -TableId "esc8Table"
        $esc9TableHtml = New-HtmlTable -Headers @("Template", "Risk") -DataRows $esc9Templates -TableId "esc9Table"
        $esc13TableHtml = New-HtmlTable -Headers @("Template / issuance policy", "Risk") -DataRows $esc13Templates -TableId "esc13Table"
        $esc5TableHtml = New-HtmlTable -Headers @("PKI container / principal", "Risk") -DataRows $esc5Pki -TableId "esc5Table"
        $gpoAclTableHtml = New-HtmlTable -Headers @("GPO / Principal", "Risk") -DataRows $gpoAcl -TableId "gpoAclTable"
        $gpoOwnerTableHtml = New-HtmlTable -Headers @("GPO / Owner", "Risk") -DataRows $gpoOwners -TableId "gpoOwnerTable"
        $gpoSecretTableHtml = New-HtmlTable -Headers @("SYSVOL file", "Risk") -DataRows $gpoSecrets -TableId "gpoSecretTable"
        $gmsaTableHtml = New-HtmlTable -Headers @("gMSA", "Risk") -DataRows $gmsaOpen -TableId "gmsaTable"
        $hybridRows = @()
        foreach ($hid in @("AD-HYB-001", "AD-HYB-002", "AD-HYB-003", "AD-BIN-001", "AD-REPL-002", "AD-GMSA-002", "AD-XCH-001", "AD-XCH-002", "AD-GRP-012", "AD-DEL-005", "AD-KERB-004", "AD-KERB-005", "AD-CS-007", "AD-CS-010", "AD-TZ-002", "AD-TZ-003", "AD-TZ-008", "AD-SCH-001", "AD-SCH-004", "AD-DC-008", "AD-DC-009")) {
            foreach ($obj in @(Get-ObjectsByCheckId $hid)) { $hybridRows += @($hid, $obj) }
        }
        $hybridTableHtml = New-HtmlTable -Headers @("Check", "Object") -DataRows $hybridRows -TableId "hybridTable"

        $mitreRows = @()
        foreach ($f in $Findings) {
            if ($f.MitreTechnique -and $f.Status -eq "Failed") {
                $mitreRows += @($f.MitreTechnique, $f.CheckId, $f.Title, (Get-HtmlSeverityBadge $f.Severity))
            }
        }
        $mitreTableHtml = New-HtmlTable -Headers @("MITRE ATT&CK", "Check ID", "Title", "Severity") -DataRows $mitreRows -TableId "mitreTable"

        $topRows = @()
        foreach ($f in @($ScoreResult.TopFailed)) {
            $topRows += @($f.CheckId, (Get-HtmlSeverityBadge $f.Severity), $f.Title, $f.RiskScore, $f.AffectedCount)
        }
        $topTableHtml = New-HtmlTable -Headers @("Check ID", "Severity", "Title", "Risk points", "Affected") -DataRows $topRows -TableId "topFailedTable"

        # TAB 11: Attack Paths
        $attackPathRows = @()
        foreach ($e in $Edges) {
            $attackPathRows += @($e.SourceName, $e.SourceType, "<strong>$($e.Relationship)</strong>", $e.TargetName, $e.TargetType, (Get-HtmlSeverityBadge $e.Severity), $e.Evidence)
        }
        $attackPathTableHtml = New-HtmlTable -Headers @("Source Principal", "Source Type", "Relationship", "Target Asset", "Target Type", "Severity", "Risk Reason & Evidence") -DataRows $attackPathRows -TableId "attackPathTable"

        # HTML Structure Construction
        $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Active Directory Security Audit Report - $domainHtml</title>
    $css
</head>
<body>
<div class="page">
    <header class="masthead">
        <div>
            <p class="kicker">Confidential · Read-only authorized audit</p>
            <h1>Active Directory Security Assessment</h1>
            <p class="domain">$domainHtml</p>
        </div>
        <button type="button" class="btn-export" onclick="downloadPdf()">Export PDF</button>
    </header>
    <dl class="meta">
        <div><dt>Auditor host</dt><dd>$computerHtml</dd></div>
        <div><dt>Execution user</dt><dd>$userHtml</dd></div>
        <div><dt>Timestamp</dt><dd>$timestampHtml</dd></div>
        <div><dt>Version</dt><dd>v$auditVersion</dd></div>
        <div><dt>Directory provider</dt><dd>$providerHtml</dd></div>
        <div><dt>Scope</dt><dd>Read-only</dd></div>
    </dl>

    <div class="nav-wrap">
    <nav class="nav-container" role="tablist" aria-label="Report sections">
        <button type="button" class="tab-btn active" data-tab="tab-indicators" role="tab" aria-selected="true" onclick="openTab(event, 'tab-indicators')">Overview</button>
        <button type="button" class="tab-btn" data-tab="tab-priorities" role="tab" aria-selected="false" onclick="openTab(event, 'tab-priorities')">Remediation Plan <span class="nav-count">$planCount</span></button>
        <button type="button" class="tab-btn" data-tab="tab-trend" role="tab" aria-selected="false" onclick="openTab(event, 'tab-trend')">Trend</button>
        <button type="button" class="tab-btn" data-tab="tab-coverage" role="tab" aria-selected="false" onclick="openTab(event, 'tab-coverage')">Coverage <span class="nav-count">$coverageCount</span></button>
        <button type="button" class="tab-btn" data-tab="tab-rules" role="tab" aria-selected="false" onclick="openTab(event, 'tab-rules')">All checks <span class="nav-count">$findingCount</span></button>
        <button type="button" class="tab-btn" data-tab="tab-domain" role="tab" aria-selected="false" onclick="openTab(event, 'tab-domain')">Domain</button>
        <button type="button" class="tab-btn" data-tab="tab-users" role="tab" aria-selected="false" onclick="openTab(event, 'tab-users')">Users</button>
        <button type="button" class="tab-btn" data-tab="tab-computers" role="tab" aria-selected="false" onclick="openTab(event, 'tab-computers')">Computers</button>
        <button type="button" class="tab-btn" data-tab="tab-groups" role="tab" aria-selected="false" onclick="openTab(event, 'tab-groups')">Admin Groups</button>
        <button type="button" class="tab-btn" data-tab="tab-trusts" role="tab" aria-selected="false" onclick="openTab(event, 'tab-trusts')">Trusts</button>
        <button type="button" class="tab-btn" data-tab="tab-acls" role="tab" aria-selected="false" onclick="openTab(event, 'tab-acls')">ACLs</button>
        <button type="button" class="tab-btn" data-tab="tab-passwords" role="tab" aria-selected="false" onclick="openTab(event, 'tab-passwords')">Passwords</button>
        <button type="button" class="tab-btn" data-tab="tab-gpo" role="tab" aria-selected="false" onclick="openTab(event, 'tab-gpo')">GPO &amp; PKI</button>
        <button type="button" class="tab-btn" data-tab="tab-hybrid" role="tab" aria-selected="false" onclick="openTab(event, 'tab-hybrid')">Hybrid</button>
        <button type="button" class="tab-btn" data-tab="tab-mitre" role="tab" aria-selected="false" onclick="openTab(event, 'tab-mitre')">ATT&amp;CK</button>
        <button type="button" class="tab-btn" data-tab="tab-paths" role="tab" aria-selected="false" onclick="openTab(event, 'tab-paths')">Attack Paths <span class="nav-count">$edgeCount</span></button>
    </nav>
    </div>

    <div id="tab-indicators" class="tab-content active" data-title="Overview">
        <div class="kpis">
            <article class="kpi $ratingClass">
                <div class="kpi-label">Overall risk score</div>
                <div class="kpi-value">$($ScoreResult.NormalizedScore)<span class="kpi-suffix">/100</span></div>
                <div class="kpi-meta"><span class="pill">$($ScoreResult.RiskRating)</span></div>
                <div class="meter" aria-hidden="true"><span style="width:${scoreWidth}%"></span></div>
            </article>
            <article class="kpi is-high">
                <div class="kpi-label">Accumulated risk points</div>
                <div class="kpi-value">$($ScoreResult.RiskPoints)</div>
                <div class="kpi-meta">Uncapped failed + warning points</div>
            </article>
            <article class="kpi is-pass">
                <div class="kpi-label">Compliance</div>
                <div class="kpi-value">$($ScoreResult.CompliancePercent)<span class="kpi-suffix">%</span></div>
                <div class="kpi-meta">Passed / tested checks</div>
                <div class="meter" aria-hidden="true"><span style="width:${complianceWidth}%"></span></div>
            </article>
            <article class="kpi is-action">
                <div class="kpi-label">Critical / high failed</div>
                <div class="kpi-value">$($ScoreResult.FailedCritical)<span class="kpi-suffix">/ $($ScoreResult.FailedHigh)</span></div>
                <div class="kpi-meta">Immediate action</div>
            </article>
            <article class="kpi is-pass">
                <div class="kpi-label">Passed controls</div>
                <div class="kpi-value">$passedCount</div>
                <div class="kpi-meta">Compliant checks</div>
            </article>
        </div>

        <div class="mix-panel">
            <div class="mix-label">
                <span>Finding mix across $findingCount checks</span>
                <span>$failedCount failed · $warningCount warning · $passedCount passed · $infoCount informational · $notEvaluatedCount not tested</span>
            </div>
            <div class="mix" aria-hidden="true">
                <span class="fail" style="flex:$failedCount"></span>
                <span class="warn" style="flex:$warningCount"></span>
                <span class="pass" style="flex:$passedCount"></span>
                <span class="info" style="flex:$infoCount"></span>
                <span class="skip" style="flex:$notEvaluatedCount"></span>
            </div>
            <div class="mix-legend">
                <span class="fail"><i></i>Failed</span>
                <span class="warn"><i></i>Warning</span>
                <span class="pass"><i></i>Passed</span>
                <span class="info"><i></i>Informational</span>
                <span class="skip"><i></i>Not tested</span>
            </div>
        </div>

        <div class="section-title">Category risk breakdown</div>
        <p class="section-lead">Risk points accumulated by audit area. Longer bars indicate more open risk, not more checks.</p>
        $catScoreTableHtml

        <div class="section-title">Highest-scoring failed checks</div>
        $topTableHtml
    </div>

    <div id="tab-priorities" class="tab-content" data-title="Remediation Plan">
        <div class="section-title">Quick Wins (high severity, few affected objects)</div>
        $quickWinTableHtml

        <div class="section-title">Full Remediation Plan (highest risk first)</div>
        <input type="text" id="inputRoadmap" onkeyup="filterTable('inputRoadmap', 'roadmapTable')" placeholder="Search the remediation plan by check, category, or action..." class="search-box">
        $roadmapTableHtml
    </div>

    <div id="tab-trend" class="tab-content" data-title="Trend">
        <div class="section-title">Change Since the Baseline</div>
        $trendSummaryHtml

        <div class="section-title">New or Growing Findings</div>
        $trendNewHtml

        <div class="section-title">Findings Resolved Since the Baseline</div>
        $trendResolvedHtml
    </div>

    <div id="tab-coverage" class="tab-content" data-title="Coverage">
        <div class="section-title">Checks that could not be evaluated</div>
        <p class="section-lead">These checks are reported as Not Tested rather than passed. A check that could not run is not evidence of a secure configuration.</p>
        $coverageTableHtml
    </div>

    <!-- TAB 2: Rules Matched -->
    <div id="tab-rules" class="tab-content" data-title="All checks">
        <div class="section-title">All Evaluated Security Audit Rules</div>
        <input type="text" id="inputRules" onkeyup="filterTable('inputRules', 'rulesMatchedTable')" placeholder="Search rules matched by ID, Title, Category, or Status..." class="search-box">
        $allRulesTableHtml
    </div>

    <!-- TAB 3: Domain Information -->
    <div id="tab-domain" class="tab-content" data-title="Domain">
        <div class="section-title">Domain & Forest Baseline Environment</div>
        $domInfoTableHtml
    </div>

    <!-- TAB 4: User Information -->
    <div id="tab-users" class="tab-content" data-title="Users">
        <div class="section-title">Password Never Expires Accounts</div>
        $pneTableHtml

        <div class="section-title">Password Not Required Accounts (PASSWD_NOTREQD)</div>
        $pwdNotReqTableHtml

        <div class="section-title">Inactive User Accounts (>90 Days)</div>
        $inactiveUsersTableHtml

        <div class="section-title">Traditional Service Accounts (SPNs Set)</div>
        $spnUsersTableHtml

        <div class="section-title">Credential Leaks in Description / Notes</div>
        $descLeakTableHtml

        <div class="section-title">Generic or Default Account Names</div>
        $genericUsersTableHtml

        <div class="section-title">Accounts with Active sidHistory Attributes</div>
        $sidHistTableHtml

        <div class="section-title">Reversible Encryption</div>
        $revEncTableHtml

        <div class="section-title">Kerberoastable Accounts</div>
        $kerberoastTableHtml

        <div class="section-title">Never-Set Passwords (pwdLastSet=0)</div>
        $neverSetTableHtml

        <div class="section-title">Orphaned adminCount=1</div>
        $orphanAdminTableHtml

        <div class="section-title">Built-in RID-500 Administrator</div>
        $rid500TableHtml

        <div class="section-title">Non-standard User Primary Groups</div>
        $badPrimaryTableHtml

        <div class="section-title">Key Credential Links (Shadow Credentials / WHfB)</div>
        $keyCredTableHtml

        <div class="section-title">Legacy Password Attributes (userPassword / unixUserPassword)</div>
        $legacyPwdTableHtml
    </div>

    <!-- TAB 5: Computer Information -->
    <div id="tab-computers" class="tab-content" data-title="Computers">
        <div class="section-title">Unsupported EOL Operating Systems</div>
        $eolCompTableHtml

        <div class="section-title">Stale Machine Passwords (>90 Days)</div>
        $staleMachineTableHtml

        <div class="section-title">Inactive Computers</div>
        $inactiveCompTableHtml
    </div>

    <!-- TAB 6: Admin Groups -->
    <div id="tab-groups" class="tab-content" data-title="Admin Groups">
        <div class="section-title">Disabled or Inactive Administrative Members</div>
        $staleAdminsTableHtml

        <div class="section-title">Privileged User Accounts with SPNs (Kerberoasting Targets)</div>
        $spnAdminsTableHtml

        <div class="section-title">Foreign Security Principals (FSP) in Tier 0 Groups</div>
        $fspAdminsTableHtml

        <div class="section-title">Remote Desktop Users Group Membership</div>
        $rdpUsersTableHtml

        <div class="section-title">Computer Objects Nested in Privileged Groups</div>
        $computerPrivTableHtml

        <div class="section-title">Tier 0 Objects Owned by Non-Tier 0 Principals</div>
        $tier0OwnersTableHtml

        <div class="section-title">Non-Tier 0 Control of Admin Groups or Accounts</div>
        $tier0ControlTableHtml

        <div class="section-title">Non-Tier 0 Control of Domain Controller Objects</div>
        $tier0DcTableHtml
    </div>

    <!-- TAB 7: Trusts -->
    <div id="tab-trusts" class="tab-content" data-title="Trusts">
        <div class="section-title">Domain and Forest Trust Relationships</div>
        $trustsTableHtml
    </div>

    <!-- TAB 8: Anomalies & ACLs -->
    <div id="tab-acls" class="tab-content" data-title="ACLs">
        <div class="section-title">DCSync Rights Principals (DS-Replication)</div>
        $dcsyncTableHtml

        <div class="section-title">Domain Root Dangerous ACEs (GenericAll / WriteDacl)</div>
        $dangerousAcesTableHtml

        <div class="section-title">AdminSDHolder Unexpected Control</div>
        $adminSdTableHtml

        <div class="section-title">Unprivileged Organizational Unit (OU) Delegations</div>
        $ouDelegationsTableHtml

        <div class="section-title">Granular User Object Control (ForceChangePassword / WriteDacl)</div>
        $userObjAcesTableHtml
    </div>

    <!-- TAB 9: Password Policies -->
    <div id="tab-passwords" class="tab-content" data-title="Passwords">
        <div class="section-title">Domain & Fine-Grained Password Policies</div>
        $pwdPolicyTableHtml
    </div>

    <!-- TAB 10: GPO & Infrastructure -->
    <div id="tab-gpo" class="tab-content" data-title="GPO and PKI">
        <div class="section-title">Group Policy Preferences cpassword Credentials in SYSVOL</div>
        $cpasswordTableHtml

        <div class="section-title">Unlinked or Empty Group Policy Objects</div>
        $unlinkedGpoTableHtml

        <div class="section-title">Vulnerable AD CS Certificate Templates (ESC1)</div>
        $esc1TableHtml

        <div class="section-title">Writable Certificate Templates (ESC4)</div>
        $esc4TableHtml

        <div class="section-title">HTTP Enrollment Endpoints (ESC8)</div>
        $esc8TableHtml

        <div class="section-title">Templates Missing the SID Security Extension (ESC9)</div>
        $esc9TableHtml

        <div class="section-title">Issuance Policy Linked to Groups (ESC13)</div>
        $esc13TableHtml

        <div class="section-title">Forest PKI Container Control (ESC5)</div>
        $esc5TableHtml

        <div class="section-title">GPO Modify / Write ACLs</div>
        $gpoAclTableHtml

        <div class="section-title">Group Policy Object Ownership</div>
        $gpoOwnerTableHtml

        <div class="section-title">Credential-like Content in SYSVOL</div>
        $gpoSecretTableHtml

        <div class="section-title">gMSA Password Retrieval</div>
        $gmsaTableHtml
    </div>

    <div id="tab-hybrid" class="tab-content" data-title="Hybrid">
        <div class="section-title">Hybrid identity, built-in groups, and site issues</div>
        $hybridTableHtml
    </div>

    <div id="tab-mitre" class="tab-content" data-title="ATT&amp;CK">
        <div class="section-title">Failed checks mapped to MITRE ATT&amp;CK</div>
        $mitreTableHtml
    </div>

    <!-- TAB 11: Attack Paths -->
    <div id="tab-paths" class="tab-content" data-title="Attack Paths">
        <div class="section-title">In-Memory Graph Attack Path Indicators (Tier 0 Targets)</div>
        <input type="text" id="inputPaths" onkeyup="filterTable('inputPaths', 'attackPathTable')" placeholder="Search attack path edges by Principal, Relationship, or Target..." class="search-box">
        $attackPathTableHtml
    </div>

    <div class="footer">
        <p>Active Directory Security Assessment Framework v$auditVersion · Read-only authorized audit · $providerHtml</p>
    </div>
</div>
    $js
</body>
</html>
"@

        Set-Content -Path $htmlPath -Value $htmlContent -Encoding UTF8
    }

    Write-Verbose "Audit reports generated successfully in $OutputPath"
}

Export-ModuleMember -Function @("Export-AuditReports", "Compare-AuditBaseline", "Import-AuditBaseline")
