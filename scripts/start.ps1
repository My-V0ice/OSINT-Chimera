param([switch]$CoreOnly)
$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    if ($CoreOnly) { docker compose up -d --build app }
    else { docker compose --profile tools up -d --build }
    if ($LASTEXITCODE -ne 0) { throw 'Не удалось запустить приложение. Проверьте Docker Desktop и вывод сборки.' }
    Write-Host 'Химера: http://localhost:8000'
} finally { Pop-Location }
