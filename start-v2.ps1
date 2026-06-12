$ErrorActionPreference = "Stop"

$projectNames = @("SentinelOps-v2-phase2", "v2.0")
$launcher = $projectNames |
    ForEach-Object { Join-Path $PSScriptRoot "$_\start.ps1" } |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
    Select-Object -First 1

if (-not $launcher) {
    Write-Error "The SentinelOps v2 launcher was not found in SentinelOps-v2-phase2 or v2.0."
}

Write-Host "Opening the SentinelOps v2.0 Phase 6 project."
& $launcher
