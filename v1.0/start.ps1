$ErrorActionPreference = "Stop"

$candidates = @(
    (Join-Path $env:LOCALAPPDATA "Programs\Python\Python313\python.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Python\Python311\python.exe"),
    (Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"),
    "py.exe",
    "python.exe"
)

$python = $null
foreach ($candidate in $candidates) {
    try {
        if ([System.IO.Path]::IsPathRooted($candidate) -and -not (Test-Path -LiteralPath $candidate)) {
            continue
        }

        $version = & $candidate --version 2>&1
        if ($LASTEXITCODE -eq 0 -and "$version" -match "^Python 3\.") {
            $python = $candidate
            break
        }
    }
    catch {
        continue
    }
}

if (-not $python) {
    Write-Error "A working Python 3 installation was not found. Install Python from https://www.python.org/downloads/ and enable 'Add Python to PATH'."
}

Set-Location -LiteralPath $PSScriptRoot
Write-Host "Starting SentinelOps with $python"
& $python ".\server.py"
