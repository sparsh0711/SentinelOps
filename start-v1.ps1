$ErrorActionPreference = "Stop"

$launcher = Join-Path $PSScriptRoot "v1.0\start.ps1"
if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
    Write-Error "The SentinelOps v1.0 launcher was not found."
}

Write-Host "Opening the SentinelOps v1.0 project."
& $launcher
