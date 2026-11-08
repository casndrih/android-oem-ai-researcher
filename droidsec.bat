@echo off
setlocal
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Python 3.10 or newer is required. Install Python, then retry.
  exit /b 1
)
python droidsec.py %*
endlocal
