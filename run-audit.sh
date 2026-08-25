#!/bin/sh
# Command-line launcher for AD Security Audit.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BINARY_PATH="$SCRIPT_DIR/Publish/linux-x64/AD-Security-Audit"

if [ -f "$BINARY_PATH" ]; then
    chmod +x "$BINARY_PATH"
    exec "$BINARY_PATH" "$@"
fi

if command -v pwsh >/dev/null 2>&1; then
    exec pwsh -NoProfile -File "$SCRIPT_DIR/Invoke-ADSecurityAudit.ps1" "$@"
fi

echo "[ERROR] CLI binary not found at $BINARY_PATH and pwsh is not installed."
echo "[INFO] Install PowerShell 7, or publish the CLI with:"
echo "       dotnet publish ./CLI/ADSecurityAuditCLI.csproj -c Release -r linux-x64 --self-contained true -o ./Publish/linux-x64"
exit 1
