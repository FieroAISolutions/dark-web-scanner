@echo off
setlocal enabledelayedexpansion
set SCRIPT_DIR=%~dp0
set BACKEND=%SCRIPT_DIR%backend

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
python -m pip install -q -r "%BACKEND%\requirements-dev.txt"

python -m pytest %*
