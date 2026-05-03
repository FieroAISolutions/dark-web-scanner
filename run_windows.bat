@echo off
setlocal enabledelayedexpansion
set SCRIPT_DIR=%~dp0
set BACKEND=%SCRIPT_DIR%backend
set DATA=%SCRIPT_DIR%data

if not exist "%DATA%" mkdir "%DATA%"

REM ── upstream repo for the in-app updater ────────────────────────────────────
REM By default the updater fetches from the same GitHub repo this code came
REM from. If you've set up a public mirror (see .github/workflows/
REM mirror-to-public.yml), uncomment and adjust to make operator hosts pull
REM from the public channel - no GitHub token required on the host.
REM set DWS_UPSTREAM_OWNER=enfierno21
REM set DWS_UPSTREAM_REPO=DarkWebScanner-Public
REM set DWS_UPSTREAM_BRANCH=main

cd /d "%SCRIPT_DIR%"

where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.10+ and add it to PATH.
    pause
    exit /b 1
)

if not exist "%BACKEND%\.venv" (
    echo Creating virtual environment...
    python -m venv "%BACKEND%\.venv"
)

call "%BACKEND%\.venv\Scripts\activate.bat"
python -m pip install -q --upgrade pip
python -m pip install -q -r "%BACKEND%\requirements.txt"

set PORT=%1
if "%PORT%"=="" set PORT=7070

echo.
echo   DarkWebScanner starting at http://localhost:%PORT%
echo   On first run, watch for the admin token URL printed below.
echo   The token is also saved to: %DATA%\admin_token.txt
echo   Press Ctrl+C to stop.
echo.

python -m backend.main %PORT%
pause
