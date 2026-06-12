$ErrorActionPreference = "Stop"

$launcher = Join-Path $PSScriptRoot "v2.0\start.ps1"
if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
    Write-Error "The SentinelOps v2.0 launcher was not found."
}

Write-Host "Opening the SentinelOps v2.0 Phase 6 project."
& $launcher
