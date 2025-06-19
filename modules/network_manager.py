# network_manager.py - Network Communication Module
import json
import logging
import requests
from datetime import datetime
import time


class NetworkManager:
    """Handles network communication with the management server"""
    
    def __init__(self, server_url, api_key, agent_id):
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.agent_id = agent_id
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        
        # Set default headers
        self.session.headers.update({
            'X-API-Key': self.api_key,
            'Content-Type': 'application/json',
            'User-Agent': f'EndpointAgent/{self.agent_id}'
        })    
    def send_heartbeat(self, system_info, latest_command=None):
        """Send heartbeat to server"""
        try:
            heartbeat_data = {
                "agent_id": self.agent_id,
                "timestamp": datetime.now().isoformat(),
                "hostname": system_info.get("hostname", "Unknown"),
                "os": system_info.get("os", "Unknown"),
                "os_version": system_info.get("os_version", "Unknown"),
                "status": "active",
                "latest_command": latest_command
            }
            
            response = self.session.post(
                f"{self.server_url}/api/heartbeat",
                json=heartbeat_data,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.debug("Heartbeat sent successfully")
                return True
            else:
                self.logger.warning(f"Heartbeat failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending heartbeat: {e}")
            return False
    
    def send_data(self, data):
        """Send data to server"""
        try:
            response = self.session.post(
                f"{self.server_url}/api/agent-data",
                json=data,
                timeout=30
            )
            
            if response.status_code == 200:
                self.logger.info(f"Data sent successfully: {data.get('message_type', 'unknown')}")
                return True
            else:
                self.logger.warning(f"Data send failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending data: {e}")
            return False
    
    def get_commands(self):
        """Get pending commands from server"""
        try:
            response = self.session.get(
                f"{self.server_url}/api/commands/{self.agent_id}",
                timeout=10
            )
            
            if response.status_code == 200:
                commands = response.json()
                if commands:
                    self.logger.info(f"Received {len(commands)} pending commands")
                return commands
            else:
                self.logger.warning(f"Failed to get commands: {response.status_code}")
                return []
                
        except Exception as e:
            self.logger.error(f"Error getting commands: {e}")
            return []
    
    def send_command_result(self, command_id, result):
        """Send command execution result to server"""
        try:
            result_data = {
                "agent_id": self.agent_id,
                "message_type": "command_result",
                "command_id": command_id,
                "result": result,
                "timestamp": datetime.now().isoformat()
            }
            
            return self.send_data(result_data)
            
        except Exception as e:
            self.logger.error(f"Error sending command result: {e}")
            return False
    
    def test_connection(self):
        """Test connection to server"""
        try:
            response = self.session.get(
                f"{self.server_url}/",
                timeout=5
            )
            
            if response.status_code in [200, 401, 403]:  # Server is responding
                self.logger.info("Server connection test successful")
                return True
            else:
                self.logger.warning(f"Server connection test failed: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Server connection test failed: {e}")
            return False
