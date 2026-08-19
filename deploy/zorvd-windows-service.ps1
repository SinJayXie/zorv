# Install Zorv tunnel server as a Windows service (using NSSM).
#
# Prerequisites:
#   1) Build zorvd.exe (cargo build --release --bin zorvd)
#   2) Install NSSM (https://nssm.cc) and add nssm.exe to PATH
#   3) Prepare zorvd.toml (copy config/zorvd.example.toml)
#
# Usage: (as admin PowerShell)
#   powershell -ExecutionPolicy Bypass -File deploy\zorvd-windows-service.ps1
# Optional parameters:
#   -InstallDir  zorvd.exe directory (default ..\releases)
#   -ConfigPath  Config file path (default <InstallDir>\zorvd.toml)
#   -ServiceName  Service name (default zorvd)
param(
    [string]$InstallDir = (Split-Path $PSScriptRoot -Parent) + "\releases",
    [string]$ConfigPath = (Split-Path $PSScriptRoot -Parent) + "\releases\zorvd.toml",
    [string]$ServiceName = "zorvd"
)

$ErrorActionPreference = "Stop"
$exe = Join-Path $InstallDir "zorvd.exe"
if (-not (Test-Path $exe)) { throw "Not found $exe, please build or specify -InstallDir" }
if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) { throw "Not found nssm, please install and add NSSM to PATH" }

# Override default service parameters when hash password:  & $exe hash-password "your-password"

if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Service $ServiceName already exists, stop and remove it..."
    & nssm stop $ServiceName | Out-Null
    & nssm remove $ServiceName confirm | Out-Null
}

& nssm install $ServiceName $exe "--config" $ConfigPath
& nssm set $ServiceName DisplayName "Zorv tunnel server"
& nssm set $ServiceName Description "Zorv tunnel server daemon"
& nssm set $ServiceName AppStdout "$InstallDir\zorvd.log"
& nssm set $ServiceName AppStderr "$InstallDir\zorvd.err.log"
& nssm set $ServiceName AppRotateFiles 1
& nssm set $ServiceName AppRotateBytes 10485760
& nssm set $ServiceName Start SERVICE_AUTO_START
& nssm set $ServiceName AppExit Default Restart
& nssm set $ServiceName AppRestartDelay 3000
& nssm start $ServiceName

Write-Host "Service $ServiceName installed and started"
Write-Host "View log: $InstallDir\zorvd.log"
