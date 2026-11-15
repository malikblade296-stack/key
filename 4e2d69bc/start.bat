@echo off
setlocal
cd /d "%~dp0"
set "PYTHON="
where py >nul 2>nul && set "PYTHON=py -3"
if not defined PYTHON (
  python -c "import sys" >nul 2>nul && set "PYTHON=python"
)
if not defined PYTHON if exist "%LOCALAPPDATA%\Programs\Thonny\python.exe" set "PYTHON=%LOCALAPPDATA%\Programs\Thonny\python.exe"
if not defined PYTHON (
  echo Python 3 is required but was not found.
  echo Install Python from https://www.python.org/downloads/
  pause
  exit /b 1
)
%PYTHON% server.py
pause
