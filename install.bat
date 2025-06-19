@echo off
REM Endpoint Agent Service Installation Script
REM Run as Administrator

echo ============================================
echo Endpoint Agent Service Installer
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

REM Check Python installation
echo [INFO] Checking Python installation...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH!
    echo Please install Python 3.8+ and add it to PATH
    pause
    exit /b 1
)

python --version
echo [INFO] Python found - OK
echo.

REM Install required Python packages
echo [INFO] Installing Python requirements...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pywin32

if %errorLevel% neq 0 (
    echo ERROR: Failed to install Python requirements!
    pause
    exit /b 1
)

echo [INFO] Python packages installed - OK
echo.

REM Install the Windows service
echo [INFO] Installing Windows service...
python agent_service.py install

if %errorLevel% neq 0 (
    echo ERROR: Failed to install service!
    pause
    exit /b 1
)

echo [INFO] Service installed successfully - OK
echo.

REM Start the service
echo [INFO] Starting Endpoint Agent service...
python agent_service.py start

if %errorLevel% neq 0 (
    echo WARNING: Service installed but failed to start automatically
    echo You can start it manually using: net start EndpointAgent
) else (
    echo [INFO] Service started successfully - OK
)

echo.
echo ============================================
echo Installation Complete!
echo ============================================
echo.
echo Service Name: EndpointAgent
echo Display Name: Endpoint Security Agent
echo.
echo Commands:
echo   Start:   net start EndpointAgent
echo   Stop:    net stop EndpointAgent
echo   Status:  sc query EndpointAgent
echo.
echo Log files are located in the 'logs' directory
echo.
pause
