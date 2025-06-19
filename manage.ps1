# Endpoint Agent Service PowerShell Installer
# Run as Administrator

param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Start,
    [switch]$Stop,
    [switch]$Status,
    [switch]$Update,
    [switch]$Help
)

$ServiceName = "EndpointAgent"
$ServiceDisplayName = "Endpoint Security Agent"

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-Header {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "Endpoint Agent Service Manager" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Help {
    Write-Host "Usage: .\manage.ps1 [OPTION]" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Green
    Write-Host "  -Install     Install the service" -ForegroundColor White
    Write-Host "  -Uninstall   Remove the service" -ForegroundColor White
    Write-Host "  -Start       Start the service" -ForegroundColor White
    Write-Host "  -Stop        Stop the service" -ForegroundColor White
    Write-Host "  -Status      Show service status" -ForegroundColor White
    Write-Host "  -Update      Update service dependencies" -ForegroundColor White
    Write-Host "  -Help        Show this help" -ForegroundColor White
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Green
    Write-Host "  .\manage.ps1 -Install" -ForegroundColor White
    Write-Host "  .\manage.ps1 -Status" -ForegroundColor White
    Write-Host "  .\manage.ps1 -Stop" -ForegroundColor White
}

function Test-ServiceExists {
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Install-AgentService {
    Write-Host "[INFO] Installing Endpoint Agent Service..." -ForegroundColor Green
    
    # Check Python
    try {
        $pythonVersion = python --version 2>&1
        Write-Host "[INFO] Python found: $pythonVersion" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Python not found! Please install Python 3.8+" -ForegroundColor Red
        return $false
    }
    
    # Install requirements
    Write-Host "[INFO] Installing Python requirements..." -ForegroundColor Yellow
    try {
        python -m pip install --upgrade pip | Out-Null
        python -m pip install -r requirements.txt | Out-Null
        python -m pip install pywin32 | Out-Null
        Write-Host "[INFO] Requirements installed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Failed to install requirements!" -ForegroundColor Red
        return $false
    }
    
    # Install service
    try {
        python agent_service.py install | Out-Null
        Write-Host "[INFO] Service installed successfully" -ForegroundColor Green
        
        # Try to start the service
        python agent_service.py start | Out-Null
        Write-Host "[INFO] Service started successfully" -ForegroundColor Green
        
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to install/start service!" -ForegroundColor Red
        return $false
    }
}

function Uninstall-AgentService {
    Write-Host "[INFO] Uninstalling Endpoint Agent Service..." -ForegroundColor Yellow
    
    if (-not (Test-ServiceExists)) {
        Write-Host "[INFO] Service is not installed" -ForegroundColor Yellow
        return $true
    }
    
    try {
        # Stop service first
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        
        # Remove service
        python agent_service.py remove | Out-Null
        Write-Host "[INFO] Service removed successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to remove service!" -ForegroundColor Red
        return $false
    }
}

function Start-AgentService {
    if (-not (Test-ServiceExists)) {
        Write-Host "[ERROR] Service is not installed!" -ForegroundColor Red
        return $false
    }
    
    try {
        Start-Service -Name $ServiceName
        Write-Host "[INFO] Service started successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to start service!" -ForegroundColor Red
        return $false
    }
}

function Stop-AgentService {
    if (-not (Test-ServiceExists)) {
        Write-Host "[ERROR] Service is not installed!" -ForegroundColor Red
        return $false
    }
    
    try {
        Stop-Service -Name $ServiceName -Force
        Write-Host "[INFO] Service stopped successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to stop service!" -ForegroundColor Red
        return $false
    }
}

function Show-ServiceStatus {
    if (-not (Test-ServiceExists)) {
        Write-Host "[STATUS] Service is NOT installed" -ForegroundColor Red
        Write-Host ""
        Write-Host "To install: .\manage.ps1 -Install" -ForegroundColor Yellow
        return
    }
    
    $service = Get-Service -Name $ServiceName
    
    Write-Host "Service Details:" -ForegroundColor Green
    Write-Host "  Name: $($service.Name)" -ForegroundColor White
    Write-Host "  Status: $($service.Status)" -ForegroundColor White
    Write-Host "  Start Type: $($service.StartType)" -ForegroundColor White
    Write-Host ""
    
    # Show recent logs if available
    $logFile = "logs\service.log"
    if (Test-Path $logFile) {
        Write-Host "Recent Log Entries:" -ForegroundColor Green
        Write-Host "-------------------" -ForegroundColor Gray
        Get-Content $logFile | Select-Object -Last 10 | ForEach-Object {
            Write-Host $_ -ForegroundColor Gray
        }
    }
    else {
        Write-Host "No log file found at: $logFile" -ForegroundColor Yellow
    }
}

function Update-AgentService {
    Write-Host "[INFO] Updating Endpoint Agent Service..." -ForegroundColor Yellow
    
    if (-not (Test-ServiceExists)) {
        Write-Host "[ERROR] Service is not installed!" -ForegroundColor Red
        return $false
    }
    
    $service = Get-Service -Name $ServiceName
    $wasRunning = $service.Status -eq "Running"
    
    if ($wasRunning) {
        Write-Host "[INFO] Stopping service for update..." -ForegroundColor Yellow
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 5
    }
    
    try {
        # Update requirements
        python -m pip install --upgrade pip | Out-Null
        python -m pip install -r requirements.txt --upgrade | Out-Null
        Write-Host "[INFO] Requirements updated successfully" -ForegroundColor Green
        
        if ($wasRunning) {
            Start-Service -Name $ServiceName
            Write-Host "[INFO] Service restarted successfully" -ForegroundColor Green
        }
        
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to update service!" -ForegroundColor Red
        return $false
    }
}

# Main execution
Show-Header

if (-not (Test-Administrator)) {
    Write-Host "[ERROR] This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as administrator'" -ForegroundColor Yellow
    exit 1
}

# Change to script directory
Set-Location $PSScriptRoot

# Process parameters
if ($Help -or (-not ($Install -or $Uninstall -or $Start -or $Stop -or $Status -or $Update))) {
    Show-Help
}
elseif ($Install) {
    Install-AgentService
}
elseif ($Uninstall) {
    Uninstall-AgentService
}
elseif ($Start) {
    Start-AgentService
}
elseif ($Stop) {
    Stop-AgentService
}
elseif ($Status) {
    Show-ServiceStatus
}
elseif ($Update) {
    Update-AgentService
}

Write-Host ""
Read-Host "Press Enter to exit"
