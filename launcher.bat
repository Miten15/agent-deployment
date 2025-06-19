@echo off
REM Endpoint Agent Service Launcher
REM This script provides a simple menu to manage the service

:menu
cls
echo ============================================
echo    Endpoint Agent Service Manager
echo ============================================
echo.
echo Please select an option:
echo.
echo 1. Install Service
echo 2. Check Status
echo 3. Stop Service
echo 4. Update Service
echo 5. Uninstall Service
echo 6. View README
echo 7. Exit
echo.
set /p choice="Enter your choice (1-7): "

if "%choice%"=="1" goto install
if "%choice%"=="2" goto status
if "%choice%"=="3" goto stop
if "%choice%"=="4" goto update
if "%choice%"=="5" goto uninstall
if "%choice%"=="6" goto readme
if "%choice%"=="7" goto exit
goto invalid

:install
echo.
echo Running installation...
call install.bat
goto menu

:status
echo.
echo Checking service status...
call status.bat
goto menu

:stop
echo.
echo Stopping service...
call stop.bat
goto menu

:update
echo.
echo Updating service...
call update.bat
goto menu

:uninstall
echo.
echo Uninstalling service...
call uninstall.bat
goto menu

:readme
echo.
echo Opening README file...
type README.md | more
echo.
pause
goto menu

:invalid
echo.
echo Invalid choice! Please enter a number between 1-7.
echo.
pause
goto menu

:exit
echo.
echo Goodbye!
echo.
