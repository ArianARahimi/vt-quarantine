@echo off
rem One-click install for Windows: finds Python 3.11 or newer (installing it
rem for your account with winget if there is none), then sets up vt-quarantine.
setlocal
cd /d "%~dp0"
set "CHECK=import sys; sys.exit(sys.version_info < (3, 11) or 'WindowsApps' in sys.executable)"
set "PY="
py -3 -c "%CHECK%" >nul 2>&1 && set "PY=py -3"
if not defined PY python -c "%CHECK%" >nul 2>&1 && set "PY=python"
if defined PY goto install

echo Python 3.11 or newer is needed. Installing Python 3.13 for your account...
winget install --id Python.Python.3.13 --exact --scope user --silent --accept-package-agreements --accept-source-agreements
set "PYEXE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if not exist "%PYEXE%" (
    echo.
    echo Python could not be installed automatically. Install it from
    echo https://www.python.org/downloads/ and then run this file again.
    echo.
    pause
    exit /b 1
)
set PY="%PYEXE%"

:install
%PY% "%~dp0vt-quarantine" --install
echo.
pause
