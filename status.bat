@echo off
REM Endpoint Agent Service Status Script

echo ============================================
echo Endpoint Agent Service Status
echo ============================================
echo.

REM Check if service exists
sc query EndpointAgent >nul 2>&1
if %errorLevel% neq 0 (
    echo [STATUS] Service is NOT installed
    echo.
    echo To install the service, run: install.bat
    goto :end
)

echo [INFO] Service is installed
echo.

REM Display detailed service information
echo Service Details:
sc query EndpointAgent
echo.

REM Show service configuration
echo Service Configuration:
sc qc EndpointAgent
echo.

REM Check if log directory exists and show recent logs
if exist "logs" (
    echo Recent Log Entries:
    echo --------------------
    if exist "logs\service.log" (
        powershell "Get-Content 'logs\service.log' | Select-Object -Last 10"
    ) else (
        echo No service log file found
    )
    echo.
)

:end
echo ============================================
echo.
echo Available commands:
echo   install.bat   - Install the service
echo   stop.bat      - Stop the service
echo   uninstall.bat - Remove the service
echo   update.bat    - Update service dependencies
echo   status.bat    - Show this status (current script)
echo.
echo Manual commands:
echo   net start EndpointAgent    - Start service
echo   net stop EndpointAgent     - Stop service
echo   sc query EndpointAgent     - Check status
echo.
pause
