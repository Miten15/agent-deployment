# Endpoint Agent Service Installer

This directory contains a clean, isolated installation package for the Endpoint Agent Windows Service.

## Files Included

- `endpoint_agent_modular.py` - Main agent application
- `agent_service.py` - Windows service wrapper
- `modules/` - Agent modules directory
- `requirements.txt` - Python dependencies
- Installation and management scripts (see below)

## Installation Scripts

### Batch Files (Simple)
- `install.bat` - Install and start the service
- `stop.bat` - Stop the service
- `uninstall.bat` - Remove the service completely
- `update.bat` - Update dependencies and restart service
- `status.bat` - Show service status and logs

### PowerShell Script (Advanced)
- `manage.ps1` - Comprehensive management tool

## Quick Start

### 1. Install the Service
```batch
# Run as Administrator
install.bat
```

### 2. Check Status
```batch
status.bat
```

### 3. Manage the Service
```batch
# Stop the service
stop.bat

# Update dependencies
update.bat

# Remove the service
uninstall.bat
```

## PowerShell Management

For more advanced management, use the PowerShell script:

```powershell
# Run PowerShell as Administrator

# Install service
.\manage.ps1 -Install

# Check status
.\manage.ps1 -Status

# Stop service
.\manage.ps1 -Stop

# Start service
.\manage.ps1 -Start

# Update service
.\manage.ps1 -Update

# Remove service
.\manage.ps1 -Uninstall

# Show help
.\manage.ps1 -Help
```

## Manual Service Commands

Once installed, you can also use standard Windows service commands:

```batch
# Start service
net start EndpointAgent

# Stop service
net stop EndpointAgent

# Check status
sc query EndpointAgent

# View service configuration
sc qc EndpointAgent
```

## Requirements

- Python 3.8 or higher
- Administrator privileges
- Windows 10/11 or Windows Server 2016+

## Log Files

Service logs are stored in the `logs/` directory:
- `service.log` - Service startup/shutdown and error logs
- Agent logs - Additional logs from the agent modules

## Troubleshooting

### Service Won't Start
1. Check the service.log file for errors
2. Ensure all Python dependencies are installed
3. Verify Python is in the system PATH
4. Check Windows Event Viewer for service errors

### Permission Issues
- Always run installation scripts as Administrator
- Ensure the service account has necessary permissions

### Dependency Issues
- Run `update.bat` to refresh Python dependencies
- Check that `requirements.txt` is present and complete

## Service Details

- **Service Name**: EndpointAgent
- **Display Name**: Endpoint Security Agent
- **Description**: Endpoint security monitoring and management agent
- **Start Type**: Automatic
- **Log Level**: INFO (configurable in agent_service.py)

## Security Notes

This service runs with elevated privileges and should be:
- Installed only on trusted systems
- Monitored for proper operation
- Updated regularly for security patches
- Configured with appropriate access controls

## Support

Check the main project documentation and logs for troubleshooting information.
