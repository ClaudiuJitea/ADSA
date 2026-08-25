# Command-line launcher for AD Security Audit on Windows.
# Double-click run-audit.bat, or run: powershell -File .\run-audit.ps1 -Domain contoso.local

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

$exePath = Join-Path $scriptDir "Publish\win-x64\AD-Security-Audit.exe"
$orchestrator = Join-Path $scriptDir "Invoke-ADSecurityAudit.ps1"

function Find-PowerShell {
    $pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
    if ($pwsh) { return $pwsh.Source }
    $candidates = @(
        (Join-Path ${env:ProgramFiles} "PowerShell\7\pwsh.exe"),
        (Join-Path ${env:ProgramFiles} "PowerShell\7-preview\pwsh.exe")
    )
    foreach ($path in $candidates) {
        if ($path -and (Test-Path $path)) { return $path }
    }
    $windowsPowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    if (Test-Path $windowsPowerShell) { return $windowsPowerShell }
    return $null
}

if (Test-Path $exePath) {
    & $exePath @args
    exit $LASTEXITCODE
}

$shell = Find-PowerShell
if (-not $shell) {
    Write-Host "[ERROR] CLI binary not found at $exePath and PowerShell is not available." -ForegroundColor Red
    exit 1
}

& $shell -NoProfile -File $orchestrator @args
exit $LASTEXITCODE
