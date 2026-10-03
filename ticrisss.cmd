@echo off
setlocal
where py >nul 2>nul
if not errorlevel 1 (
    py -3 "%~dp0ticrisss.py" %*
    exit /b
)
where python >nul 2>nul
if not errorlevel 1 (
    python "%~dp0ticrisss.py" %*
    exit /b
)
echo Python 3 est requis. Installez Python 3 et rendez-le accessible dans le terminal.
exit /b 1
