param([int]$Port = 8000)

Set-Location -LiteralPath $PSScriptRoot

$env:WATCHFILES_FORCE_POLLING = "true"

Write-Host "Messenger Forensic Analyzer - http://127.0.0.1:$Port  (끝내려면 Ctrl+C)"
python -m uvicorn backend.main:app --host 127.0.0.1 --port $Port --reload --reload-dir backend
