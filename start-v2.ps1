$ErrorActionPreference = "Stop"

$project = Join-Path $PSScriptRoot "SentinelOps-v2-phase2"
$launcher = Join-Path $project "start.ps1"

if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
    Write-Error "The SentinelOps v2 launcher was not found at: $launcher"
}

Write-Host "Opening the SentinelOps v2.0 Phase 6 project."
& $launcher
