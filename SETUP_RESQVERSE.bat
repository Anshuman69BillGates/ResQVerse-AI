@echo off
setlocal
cd /d "%~dp0"
echo =============================================
echo       ResQVerse AI - Final V1 Setup
echo =============================================
echo.
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js was not found. Trying to install Node.js LTS...
  where winget >nul 2>nul
  if errorlevel 1 (
    echo winget is not available. Please install Node.js LTS manually.
    pause
    exit /b 1
  )
  winget install OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements
  if errorlevel 1 (
    echo Node.js installation did not complete.
    pause
    exit /b 1
  )
  echo.
  echo Close this window and run SETUP_RESQVERSE.bat again so Windows refreshes PATH.
  pause
  exit /b 0
)
node -v
npm.cmd -v
echo.
echo Installing dependencies...
npm.cmd install
if errorlevel 1 (
  echo Dependency installation failed.
  pause
  exit /b 1
)
echo.
echo Setup complete. Starting ResQVerse AI...
npm.cmd start
pause
