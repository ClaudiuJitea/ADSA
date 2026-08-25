# Windows launcher for the AD Security Audit GUI.
# Double-click run-gui.bat, or run: powershell -File .\run-gui.ps1

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

$exePath = Join-Path $scriptDir "Publish\win-x64-gui\AD-Security-Audit-GUI.exe"
$projectPath = Join-Path $scriptDir "GUI\ADSecurityAuditGUI.csproj"
$sourceMarkers = @(
    $projectPath,
    (Join-Path $scriptDir "Invoke-ADSecurityAudit.ps1"),
    (Join-Path $scriptDir "Modules"),
    (Join-Path $scriptDir "Config")
)

function Find-DotNet {
    $cmd = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($env:ProgramFiles) { [void]$candidates.Add((Join-Path $env:ProgramFiles "dotnet\dotnet.exe")) }
    $pf86 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
    if ($pf86) { [void]$candidates.Add((Join-Path $pf86 "dotnet\dotnet.exe")) }
    if ($env:LOCALAPPDATA) { [void]$candidates.Add((Join-Path $env:LOCALAPPDATA "Microsoft\dotnet\dotnet.exe")) }
    foreach ($path in $candidates) {
        if ($path -and (Test-Path $path)) { return $path }
    }
    return $null
}

function Test-NeedsPublish {
    if (-not (Test-Path $exePath)) { return $true }
    $exeTime = (Get-Item $exePath).LastWriteTimeUtc
    foreach ($path in $sourceMarkers) {
        if ((Test-Path $path) -and (Get-Item $path).LastWriteTimeUtc -gt $exeTime) { return $true }
    }
    return $false
}

if (Test-NeedsPublish) {
    $dotnet = Find-DotNet
    if (-not $dotnet) {
        Write-Host "[ERROR] Windows GUI is not published yet, and the .NET 8 SDK was not found." -ForegroundColor Red
        Write-Host "[INFO] Install the .NET 8 SDK from https://dotnet.microsoft.com/download/dotnet/8.0" -ForegroundColor Yellow
        Write-Host "       then run this script again. It publishes Publish\win-x64-gui\AD-Security-Audit-GUI.exe" -ForegroundColor Yellow
        exit 1
    }

    Write-Host "[*] Publishing the GUI for Windows..." -ForegroundColor Cyan
    & $dotnet publish $projectPath -c Release -r win-x64 --self-contained true -p:OutputType=WinExe -o (Join-Path $scriptDir "Publish\win-x64-gui")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

if (-not (Test-Path $exePath)) {
    Write-Host "[ERROR] GUI executable was not found at $exePath" -ForegroundColor Red
    exit 1
}

Start-Process -FilePath $exePath
