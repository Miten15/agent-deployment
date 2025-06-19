@echo off
REM Endpoint Agent Service Update Script
REM Run as Administrator

echo ============================================
echo Endpoint Agent Service Updater
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
    echo ERROR: Service is not installed!
    echo Please run install.bat first.
    pause
    exit /b 1
)

REM Check service status
for /f "tokens=4" %%i in ('sc query EndpointAgent ^| find "STATE"') do set SERVICE_STATE=%%i
echo [INFO] Current service state: %SERVICE_STATE%

REM Stop the service if running
if "%SERVICE_STATE%"=="RUNNING" (
    echo [INFO] Stopping service for update...
    net stop EndpointAgent
    timeout /t 5 /nobreak >nul
)

REM Update Python requirements
echo [INFO] Updating Python requirements...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt --upgrade

if %errorLevel% neq 0 (
    echo ERROR: Failed to update Python requirements!
    pause
    exit /b 1
)

echo [INFO] Python packages updated - OK
echo.

REM Restart the service if it was running
if "%SERVICE_STATE%"=="RUNNING" (
    echo [INFO] Restarting service...
    net start EndpointAgent
    
    if %errorLevel% neq 0 (
        echo ERROR: Failed to restart service!
        echo Please check the service logs and start manually if needed.
        pause
        exit /b 1
    )
    
    echo [INFO] Service restarted successfully - OK
) else (
    echo [INFO] Service was not running, leaving stopped
)

echo.
echo ============================================
echo Update Complete!
echo ============================================
echo.
echo Service has been updated with latest dependencies.
echo.
pause
