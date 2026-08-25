#!/bin/sh
# Launch the AD Security Audit GUI (same app on Linux and Windows).
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BINARY_PATH="$SCRIPT_DIR/Publish/linux-x64-gui/AD-Security-Audit-GUI"
PROJECT_PATH="$SCRIPT_DIR/GUI/ADSecurityAuditGUI.csproj"

if ! command -v dotnet >/dev/null 2>&1; then
    if [ -x "$HOME/.dotnet/dotnet" ]; then
        DOTNET_ROOT="$HOME/.dotnet"
        export DOTNET_ROOT
        PATH="$HOME/.dotnet:$HOME/.dotnet/tools:$PATH"
        export PATH
    fi
fi

needs_publish=0
if [ ! -f "$BINARY_PATH" ]; then
    needs_publish=1
else
    for src in "$PROJECT_PATH" "$SCRIPT_DIR/Invoke-ADSecurityAudit.ps1" "$SCRIPT_DIR/Modules" "$SCRIPT_DIR/Config"; do
        if [ -e "$src" ] && [ "$src" -nt "$BINARY_PATH" ]; then
            needs_publish=1
            break
        fi
    done
fi

if [ "$needs_publish" -eq 1 ]; then
    if ! command -v dotnet >/dev/null 2>&1; then
        echo "[ERROR] Published GUI not found at $BINARY_PATH"
        echo "[INFO] Install the .NET 8 SDK, then re-run this script to publish it."
        exit 1
    fi

    echo "[*] Publishing GUI to $SCRIPT_DIR/Publish/linux-x64-gui ..."
    dotnet publish "$PROJECT_PATH" -c Release -r linux-x64 --self-contained true -o "$SCRIPT_DIR/Publish/linux-x64-gui"
fi

chmod +x "$BINARY_PATH"
exec "$BINARY_PATH" "$@"
