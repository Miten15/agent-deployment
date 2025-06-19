@echo off
REM Endpoint Agent Service Uninstall Script
REM Run as Administrator

echo ============================================
echo Endpoint Agent Service Uninstaller
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
    goto :end
)

REM Stop the service first
echo [INFO] Stopping Endpoint Agent service...
net stop EndpointAgent >nul 2>&1

REM Wait a moment for the service to stop
timeout /t 3 /nobreak >nul

REM Remove the service
echo [INFO] Removing Windows service...
python agent_service.py remove

if %errorLevel% neq 0 (
    echo ERROR: Failed to remove service!
    echo You may need to remove it manually using: sc delete EndpointAgent
    pause
    exit /b 1
)

echo [INFO] Service removed successfully - OK

:end
echo.
echo ============================================
echo Uninstall Complete!
echo ============================================
echo.
echo The service has been removed from the system.
echo Log files remain in the 'logs' directory.
echo.
pause
