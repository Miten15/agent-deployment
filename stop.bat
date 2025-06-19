@echo off
REM Endpoint Agent Service Stop Script
REM Run as Administrator

echo ============================================
echo Endpoint Agent Service Stopper
echo ============================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as Administrator!
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo [INFO] Running as Administrator - OK
echo.

REM Set working directory to script location
cd /d "%~dp0"

REM Check if service exists
sc query EndpointAgent >nul 2>&1
if %errorLevel% neq 0 (
    echo [INFO] Service is not installed
    pause
    exit /b 0
)

REM Stop the service
echo [INFO] Stopping Endpoint Agent service...
net stop EndpointAgent

if %errorLevel% neq 0 (
    echo WARNING: Service may not have been running
) else (
    echo [INFO] Service stopped successfully
)

echo.
echo ============================================
echo Service Stop Complete!
echo ============================================
echo.
pause
