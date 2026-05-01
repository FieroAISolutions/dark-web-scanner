@echo off
setlocal enabledelayedexpansion
set SCRIPT_DIR=%~dp0
set BACKEND=%SCRIPT_DIR%backend
set DATA=%SCRIPT_DIR%data

if not exist "%DATA%" mkdir "%DATA%"

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
pip install -q --upgrade pip
pip install -q -r "%BACKEND%\requirements.txt"

set PORT=%1
if "%PORT%"=="" set PORT=7070

echo.
echo   DarkWebScanner starting at http://localhost:%PORT%
echo   Press Ctrl+C to stop.
echo.

python -m backend.main %PORT%
pause
