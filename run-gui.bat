@echo off
setlocal EnableExtensions
cd /d "%~dp0"

REM AD Security Audit GUI. Double-click this file on Windows.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-gui.ps1" %*
if errorlevel 1 (
    echo.
    echo Press any key to close...
    pause >nul
)
