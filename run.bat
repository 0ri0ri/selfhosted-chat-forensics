@echo off
cd /d "%~dp0"
set WATCHFILES_FORCE_POLLING=true
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload --reload-dir backend
