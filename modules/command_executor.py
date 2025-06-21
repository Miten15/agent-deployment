# command_executor.py - Command Execution Module
import subprocess
import platform
import logging
import json
from datetime import datetime


class CommandExecutor:
    """Handles command execution with security controls"""
    
    def __init__(self, agent_id, config=None):
        self.agent_id = agent_id
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Default allowed commands
        self.default_allowed_commands = [
            "dir", "ls", "ps", "netstat", "whoami", "systeminfo", "ipconfig", "ifconfig",
            "ping", "tracert", "traceroute", "nslookup", "route", "arp", "tasklist",
            "wmic", "get-process", "get-service", "get-computerinfo","RUN_BEHAVIORAL_SCAN","GET_BEHAVIORAL_HISTORY",
        "STOP_BEHAVIORAL_SCAN"
        ]
    
    def execute_command(self, command, timeout=30):
        """Execute a system command safely with comprehensive output"""
        try:
            self.logger.info(f"Executing command: {command}")
            
            if not command or not command.strip():
                return {
                    "command": command,
                    "return_code": 1,
                    "error": "Empty command",
                    "timestamp": datetime.now().isoformat()
                }
            
            # Security check
            if not self._is_command_allowed(command):
                return {
                    "command": command,
                    "return_code": 1,
                    "error": f"Command not allowed by security policy",
                    "timestamp": datetime.now().isoformat()
                }
              # Execute the command
            start_time = datetime.now()
            if platform.system() == "Windows":
                # Use cmd /c for Windows commands - pass as list to avoid quoting issues
                result = subprocess.run(
                    ["cmd", "/c", command], 
                    shell=False, 
                    capture_output=True, 
                    text=True, 
                    timeout=timeout,
                    encoding='utf-8',
                    errors='replace'
                )
            else:
                # Use bash for Unix-like systems
                result = subprocess.run(
                    command, 
                    shell=True, 
                    capture_output=True, 
                    text=True, 
                    timeout=timeout,
                    encoding='utf-8',
                    errors='replace'
                )
            
            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()
            
            # Prepare comprehensive output
            command_result = {
                "command": command,
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "execution_time_seconds": execution_time,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "timestamp": datetime.now().isoformat(),
                "platform": platform.system(),
                "agent_id": self.agent_id
            }
            
            # Add combined output for easier reading
            if result.stdout and result.stderr:
                command_result["output"] = f"STDOUT:\\n{result.stdout}\\n\\nSTDERR:\\n{result.stderr}"
            elif result.stdout:
                command_result["output"] = result.stdout
            elif result.stderr:
                command_result["output"] = result.stderr
            else:
                command_result["output"] = "No output generated"
            
            # Add success indicator
            command_result["success"] = result.returncode == 0
            
            # Log execution details
            if result.returncode == 0:
                self.logger.info(f"Command executed successfully in {execution_time:.2f}s")
            else:
                self.logger.warning(f"Command failed with return code {result.returncode}")
            
            return command_result
            
        except subprocess.TimeoutExpired:
            return {
                "command": command,
                "return_code": 124,  # Standard timeout return code
                "error": f"Command timed out after {timeout} seconds",
                "timeout": timeout,
                "timestamp": datetime.now().isoformat(),
                "agent_id": self.agent_id
            }
        except Exception as e:
            self.logger.error(f"Error executing command '{command}': {e}")
            return {
                "command": command,
                "return_code": 1,
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
                "agent_id": self.agent_id
            }
    
    def _is_command_allowed(self, command):
        """Check if command is allowed by security policy"""
        command_parts = command.strip().split()
        if not command_parts:
            return False
        
        base_command = command_parts[0].lower()
        
        # Get allowed commands from config or use defaults
        allowed_commands = self.config.get("allowed_commands", self.default_allowed_commands)
        
        # Convert to lowercase for comparison
        allowed_commands_lower = [cmd.lower() for cmd in allowed_commands]
        
        # Special handling for PowerShell commands
        if base_command in ["powershell", "pwsh"]:
            # Allow PowerShell if it's in the allowed list
            return "powershell" in allowed_commands_lower or "pwsh" in allowed_commands_lower
        
        # Check if base command is allowed
        return base_command in allowed_commands_lower
    
    def get_command_suggestions(self):
        """Get list of allowed commands for help"""
        allowed_commands = self.config.get("allowed_commands", self.default_allowed_commands)
        
        suggestions = {
            "allowed_commands": allowed_commands,
            "examples": {
                "Windows": [
                    "dir C:\\",
                    "systeminfo",
                    "tasklist",
                    "ipconfig /all",
                    "netstat -an",
                    "wmic process list brief"
                ],
                "Linux": [
                    "ls -la /",
                    "ps aux",
                    "netstat -tuln",
                    "ifconfig",
                    "df -h",
                    "top -n 1"
                ]
            },
            "platform": platform.system(),
            "timestamp": datetime.now().isoformat()
        }
        
        return suggestions
