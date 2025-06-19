@echo off
REM Comprehensive Endpoint Agent Service Manager
REM Run as Administrator

setlocal enabledelayedexpansion

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo ============================================
    echo ERROR: Administrator Rights Required
    echo ============================================
    echo This script must be run as Administrator!
    echo Right-click and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

REM Set working directory to script location
cd /d "%~dp0"

:main_menu
cls
echo ============================================
echo   Endpoint Agent Service Manager v2.0
echo ============================================
echo.
echo Current Status:
call :check_service_status
echo.
echo Available Actions:
echo   1. Install Service (Auto-start)
echo   2. Start Service
echo   3. Stop Service  
echo   4. Restart Service
echo   5. Uninstall Service
echo   6. Update Dependencies
echo   7. View Service Logs
echo   8. View Service Details
echo   9. Test Server Connection
echo   0. Exit
echo.
set /p choice="Select option (0-9): "

if "%choice%"=="1" goto install_service
if "%choice%"=="2" goto start_service
if "%choice%"=="3" goto stop_service
if "%choice%"=="4" goto restart_service
if "%choice%"=="5" goto uninstall_service
if "%choice%"=="6" goto update_service
if "%choice%"=="7" goto view_logs
if "%choice%"=="8" goto service_details
if "%choice%"=="9" goto test_connection
if "%choice%"=="0" goto exit_script
goto invalid_choice

:check_service_status
sc query EndpointAgent >nul 2>&1
if %errorLevel% neq 0 (
    echo   Service Status: NOT INSTALLED
    set SERVICE_EXISTS=false
) else (
    for /f "tokens=4" %%i in ('sc query EndpointAgent ^| find "STATE"') do set SERVICE_STATE=%%i
    echo   Service Status: !SERVICE_STATE!
    set SERVICE_EXISTS=true
)
goto :eof

:install_service
echo.
echo ============================================
echo Installing Endpoint Agent Service
echo ============================================
echo.

REM Check if service already exists
if "%SERVICE_EXISTS%"=="true" (
    echo [WARNING] Service is already installed!
    echo Use option 6 to update or option 5 to uninstall first.
    goto pause_and_return
)

echo [INFO] Checking Python installation...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python not found! Please install Python 3.8+
    goto pause_and_return
)

python --version
echo [INFO] Python found - OK

echo.
echo [INFO] Installing Python requirements...
python -m pip install --upgrade pip >nul 2>&1
python -m pip install -r requirements.txt >nul 2>&1
python -m pip install pywin32 >nul 2>&1

if %errorLevel% neq 0 (
    echo [ERROR] Failed to install Python requirements!
    goto pause_and_return
)

echo [INFO] Requirements installed - OK

echo.
echo [INFO] Installing Windows service...
python agent_service.py install

if %errorLevel% neq 0 (
    echo [ERROR] Failed to install service!
    goto pause_and_return
)

echo [INFO] Service installed with AUTO-START - OK

echo.
echo [INFO] Setting service to automatic startup...
sc config EndpointAgent start= auto

if %errorLevel% neq 0 (
    echo [WARNING] Failed to set automatic startup, but service is installed
) else (
    echo [INFO] Service configured for automatic startup - OK
)

echo.
echo [INFO] Starting service...
python agent_service.py start

if %errorLevel% neq 0 (
    echo [WARNING] Service installed but failed to start
    echo You can try starting it with option 2
) else (
    echo [INFO] Service started successfully - OK
)

echo.
echo [SUCCESS] Installation completed!
echo The service will now start automatically on system boot.
goto pause_and_return

:start_service
echo.
echo ============================================
echo Starting Endpoint Agent Service
echo ============================================
echo.

if "%SERVICE_EXISTS%"=="false" (
    echo [ERROR] Service is not installed! Use option 1 to install.
    goto pause_and_return
)

net start EndpointAgent
if %errorLevel% neq 0 (
    echo [ERROR] Failed to start service!
    echo Check the logs with option 7 for details.
) else (
    echo [SUCCESS] Service started successfully!
)
goto pause_and_return

:stop_service
echo.
echo ============================================
echo Stopping Endpoint Agent Service
echo ============================================
echo.

if "%SERVICE_EXISTS%"=="false" (
    echo [ERROR] Service is not installed!
    goto pause_and_return
)

net stop EndpointAgent
if %errorLevel% neq 0 (
    echo [WARNING] Service may not have been running
) else (
    echo [SUCCESS] Service stopped successfully!
)
goto pause_and_return

:restart_service
echo.
echo ============================================
echo Restarting Endpoint Agent Service
echo ============================================
echo.

if "%SERVICE_EXISTS%"=="false" (
    echo [ERROR] Service is not installed! Use option 1 to install.
    goto pause_and_return
)

echo [INFO] Stopping service...
net stop EndpointAgent >nul 2>&1
timeout /t 3 /nobreak >nul

echo [INFO] Starting service...
net start EndpointAgent
if %errorLevel% neq 0 (
    echo [ERROR] Failed to restart service!
) else (
    echo [SUCCESS] Service restarted successfully!
)
goto pause_and_return

:uninstall_service
echo.
echo ============================================
echo Uninstalling Endpoint Agent Service
echo ============================================
echo.

if "%SERVICE_EXISTS%"=="false" (
    echo [INFO] Service is not installed
    goto pause_and_return
)

echo [WARNING] This will completely remove the service!
set /p confirm="Are you sure? (y/N): "
if /i not "%confirm%"=="y" (
    echo [INFO] Uninstall cancelled
    goto pause_and_return
)

echo [INFO] Stopping service...
net stop EndpointAgent >nul 2>&1
timeout /t 3 /nobreak >nul

echo [INFO] Removing service...
python agent_service.py remove

if %errorLevel% neq 0 (
    echo [ERROR] Failed to remove service!
    echo You may need to remove manually: sc delete EndpointAgent
) else (
    echo [SUCCESS] Service removed successfully!
)
goto pause_and_return

:update_service
echo.
echo ============================================
echo Updating Endpoint Agent Service
echo ============================================
echo.

if "%SERVICE_EXISTS%"=="false" (
    echo [ERROR] Service is not installed! Use option 1 to install.
    goto pause_and_return
)

echo [INFO] Checking current service status...
for /f "tokens=4" %%i in ('sc query EndpointAgent ^| find "STATE"') do set CURRENT_STATE=%%i
echo Current state: %CURRENT_STATE%

if "%CURRENT_STATE%"=="RUNNING" (
    echo [INFO] Stopping service for update...
    net stop EndpointAgent
    timeout /t 5 /nobreak >nul
    set RESTART_NEEDED=true
) else (
    set RESTART_NEEDED=false
)

echo [INFO] Updating Python requirements...
python -m pip install --upgrade pip >nul 2>&1
python -m pip install -r requirements.txt --upgrade >nul 2>&1

if %errorLevel% neq 0 (
    echo [ERROR] Failed to update requirements!
    goto pause_and_return
)

echo [INFO] Requirements updated - OK

if "%RESTART_NEEDED%"=="true" (
    echo [INFO] Restarting service...
    net start EndpointAgent
    if %errorLevel% neq 0 (
        echo [ERROR] Failed to restart service!
    ) else (
        echo [SUCCESS] Service updated and restarted!
    )
) else (
    echo [SUCCESS] Service updated (was not running)!
)
goto pause_and_return

:view_logs
echo.
echo ============================================
echo Service Logs (Last 20 lines)
echo ============================================
echo.

if exist "logs\service.log" (
    powershell "Get-Content 'logs\service.log' | Select-Object -Last 20"
) else (
    echo [INFO] No log file found at logs\service.log
)

echo.
echo [INFO] Log files location: %~dp0logs\
goto pause_and_return

:service_details
echo.
echo ============================================
echo Service Details
echo ============================================
echo.

if "%SERVICE_EXISTS%"=="false" (
    echo [INFO] Service is not installed
    goto pause_and_return
)

echo Service Query:
sc query EndpointAgent
echo.
echo Service Configuration:
sc qc EndpointAgent
echo.
goto pause_and_return

:test_connection
echo.
echo ============================================
echo Testing Server Connection
echo ============================================
echo.

echo [INFO] Testing connection to localhost:8080...
powershell "try { $response = Invoke-WebRequest -Uri 'http://localhost:8080/' -TimeoutSec 5; Write-Host '[SUCCESS] Server is responding - Status:' $response.StatusCode } catch { Write-Host '[ERROR] Cannot connect to server:' $_.Exception.Message }"

echo.
echo [INFO] Testing API endpoint...
powershell "try { $response = Invoke-WebRequest -Uri 'http://localhost:8080/api/agent-data' -Method GET -TimeoutSec 5; Write-Host '[INFO] API endpoint responded - Status:' $response.StatusCode } catch { Write-Host '[INFO] API endpoint test:' $_.Exception.Message }"

goto pause_and_return

:invalid_choice
echo.
echo [ERROR] Invalid choice! Please enter a number between 0-9.
goto pause_and_return

:pause_and_return
echo.
pause
goto main_menu

:exit_script
echo.
echo [INFO] Goodbye!
echo.
exit /b 0
