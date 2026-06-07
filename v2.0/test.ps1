$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$python = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
$node = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"

if (-not (Test-Path -LiteralPath $python)) { $python = "python.exe" }
if (-not (Test-Path -LiteralPath $node)) { $node = "node.exe" }

& $python -m unittest discover -s tests/backend -v
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $node --test tests/frontend/*.test.mjs
exit $LASTEXITCODE
