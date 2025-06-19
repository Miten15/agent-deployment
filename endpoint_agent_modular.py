# endpoint_agent_modular.py - Modular System Inventory & Command Execution Agent
import os
import sys
import json
import time
import threading
import queue
import hashlib
import socket
import platform
import logging
from datetime import datetime
from dotenv import load_dotenv

# Import our modules
from modules.system_info import SystemInfoCollector
from modules.sbom import SBOMCollector
from modules.command_executor import CommandExecutor
from modules.network_manager import NetworkManager
from modules.hardening_manager import HardeningManager

# Load environment variables
load_dotenv()


class ModularEndpointAgent:
    """Modular Endpoint Agent with separated responsibilities"""
    
    def __init__(self, server_url=None, config_file="agent_config.json", api_key=None):        # Configuration
        self.server_url = server_url or os.getenv('SERVER_URL', 'http://localhost:8080/')
        self.api_key = api_key or os.getenv('AGENT_API_KEY', 'your-secret-agent-key-here')
        self.config_file = config_file
        
        # Generate unique agent ID
        self.agent_id = self._generate_agent_id()
        
        # Setup logging
        self._setup_logging()
        
        # Load configuration
        self.config = self._load_config()
          # Initialize modules
        self.system_info = SystemInfoCollector(self.agent_id)
        self.sbom_collector = SBOMCollector(self.agent_id)
        self.command_executor = CommandExecutor(self.agent_id, self.config)
        self.network_manager = NetworkManager(self.server_url, self.api_key, self.agent_id)
        self.hardening_manager = HardeningManager(self.agent_id)
        
        # Agent state
        self.running = True
        self.command_queue = queue.Queue()
        self.latest_command = None
        
        # Intervals (from config)
        self.heartbeat_interval = self.config.get('heartbeat_interval', 60)
        self.inventory_interval = self.config.get('inventory_interval', 300)
        self.sbom_interval = self.config.get('sbom_interval', 1800)  # 30 minutes
        
        self.logger.info(f"Modular Endpoint Agent initialized - ID: {self.agent_id}")
    
    def _generate_agent_id(self):
        """Generate unique agent ID"""
        hostname = socket.gethostname()
        try:
            import uuid
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                           for elements in range(0,2*6,2)][::-1])
        except:
            mac = "unknown"
        
        agent_string = f"{hostname}-{mac}-{platform.system()}"
        return hashlib.md5(agent_string.encode()).hexdigest()[:16]
    
    def _setup_logging(self):
        """Setup logging configuration"""
        log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'agent_{self.agent_id}.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(f'EndpointAgent_{self.agent_id}')
    
    def _load_config(self):
        """Load agent configuration"""
        default_config = {
            "server_url": self.server_url,
            "heartbeat_interval": 60,
            "inventory_interval": 300,
            "sbom_interval": 1800,            "allowed_commands": [
                "dir", "ls", "ps", "netstat", "whoami", "systeminfo", "ipconfig", "ifconfig",
                "ping", "tracert", "traceroute", "nslookup", "route", "arp", "tasklist",
                "wmic", "get-process", "get-service", "get-computerinfo", "powershell",
                "RUN_HARDENING_AUDIT", "GET_HARDENING_STATUS", "COLLECT_INVENTORY", 
                "COLLECT_SBOM", "SHOW_INSTALLED_SOFTWARE", "GET_SYSTEM_INFO"
            ],
            "max_command_timeout": 60,
            "enable_full_sbom": True,
            "enable_system_monitoring": True        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    default_config.update(config)
                    self.logger.info(f"Configuration loaded from {self.config_file}")
        except Exception as e:
            self.logger.warning(f"Could not load config: {e}, using defaults")
        
        return default_config
    
    def collect_full_inventory(self):
        """Collect comprehensive system inventory"""
        try:
            self.logger.info("Collecting comprehensive system inventory...")
            
            # Collect all system information
            basic_info = self.system_info.collect_basic_info()
            hardware_info = self.system_info.collect_hardware_info()
            disk_info = self.system_info.collect_disk_info()
            network_info = self.system_info.collect_network_info()
            processes_info = self.system_info.collect_processes_info()
              # Format network data for dashboard compatibility
            formatted_network = {}
            if "interfaces" in network_info:
                for interface_name, interface_data in network_info["interfaces"].items():
                    ip_addr = "N/A"
                    subnet = "N/A"
                    mac = "N/A"
                    
                    # Extract IP, subnet, and MAC from addresses
                    for addr in interface_data.get("addresses", []):
                        family = addr.get("family", "")
                        address = addr.get("address", "")
                        
                        # IPv4 addresses (family = "2" or "AddressFamily.AF_INET")
                        if family == "2" or family == "AddressFamily.AF_INET":
                            ip_addr = address
                            subnet = addr.get("netmask", "N/A")
                        # MAC addresses (family = "-1" or contains colons and dashes)
                        elif family == "-1" or (("-" in address or ":" in address) and len(address.replace("-", "").replace(":", "")) == 12):
                            mac = address
                    
                    formatted_network[interface_name] = {
                        "ip": ip_addr,
                        "subnet": subnet,
                        "mac": mac
                    }
            
            # Format disk data with usage_percent field
            formatted_disks = []
            for disk in disk_info.get("disks", []):
                disk_copy = disk.copy()
                if "percent" in disk_copy:
                    disk_copy["usage_percent"] = disk_copy.pop("percent")
                formatted_disks.append(disk_copy)
            
            # Format hardware data with memory_usage_percent field
            formatted_hardware = hardware_info.copy()
            if "memory_percent" in formatted_hardware:
                formatted_hardware["memory_usage_percent"] = formatted_hardware.pop("memory_percent")
            
            # Add missing system fields
            formatted_system = basic_info.copy()
            if "hostname" not in formatted_system:
                formatted_system["hostname"] = formatted_system.get("node", "Unknown")
            
            # Add domain and username (Windows specific)
            try:
                import os
                formatted_system["domain"] = os.getenv("USERDOMAIN", "N/A")
                formatted_system["username"] = os.getenv("USERNAME", "N/A")
                
                # Get uptime
                import psutil
                boot_time = psutil.boot_time()
                uptime_seconds = time.time() - boot_time
                uptime_hours = int(uptime_seconds // 3600)
                uptime_minutes = int((uptime_seconds % 3600) // 60)
                formatted_system["uptime"] = f"{uptime_hours}h {uptime_minutes}m"
            except Exception as e:
                self.logger.warning(f"Error getting additional system info: {e}")
                formatted_system["domain"] = "N/A"
                formatted_system["username"] = "N/A"
                formatted_system["uptime"] = "N/A"
            
            # Combine all inventory data
            inventory_data = {
                "agent_id": self.agent_id,
                "message_type": "inventory",
                "timestamp": datetime.now().isoformat(),
                "data": {
                    "system": formatted_system,
                    "hardware": formatted_hardware,
                    "disks": formatted_disks,
                    "network": formatted_network,
                    "processes": processes_info.get("top_processes_by_memory", []),
                    "network_connections": network_info.get("connections", []),
                    "collection_summary": {
                        "total_processes": processes_info.get("total_processes", 0),
                        "total_disks": len(formatted_disks),
                        "total_network_interfaces": len(formatted_network),
                        "collection_time": datetime.now().isoformat()
                    }
                }
            }
            
            self.logger.info("System inventory collection completed")
            return inventory_data
            
        except Exception as e:
            self.logger.error(f"Error collecting full inventory: {e}")
            return {
                "agent_id": self.agent_id,
                "message_type": "inventory",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            }
    
    def collect_sbom(self):
        """Collect Software Bill of Materials"""
        try:
            self.logger.info("Collecting Software Bill of Materials...")
            sbom_data = self.sbom_collector.collect_full_sbom()
            
            # Format for server
            sbom_message = {
                "agent_id": self.agent_id,
                "message_type": "sbom",
                "timestamp": datetime.now().isoformat(),
                "data": sbom_data
            }
            
            self.logger.info(f"SBOM collection completed - {sbom_data.get('summary', {}).get('total_packages', 0)} packages found")
            return sbom_message
            
        except Exception as e:
            self.logger.error(f"Error collecting SBOM: {e}")
            return {
                "agent_id": self.agent_id,
                "message_type": "sbom",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            }
    
    def handle_special_commands(self, command):
        """Handle special agent commands"""
        command = command.strip().upper()
        
        if command == "COLLECT_INVENTORY":
            self.logger.info("Handling COLLECT_INVENTORY command")
            inventory = self.collect_full_inventory()
            
            # Send inventory to server
            if self.network_manager.send_data(inventory):
                return {
                    "command": "COLLECT_INVENTORY",
                    "return_code": 0,
                    "success": True,
                    "output": f"System inventory collected and sent successfully\\n\\nInventory Summary:\\n" +
                             f"- System: {inventory['data']['system'].get('hostname', 'Unknown')} ({inventory['data']['system'].get('os', 'Unknown')})\\n" +
                             f"- Hardware: {inventory['data']['hardware'].get('cpu_count_logical', 'Unknown')} CPUs, {inventory['data']['hardware'].get('memory_total_gb', 'Unknown')} GB RAM\\n" +
                             f"- Disks: {len(inventory['data']['disks'])} disk(s)\\n" +
                             f"- Network: {len(inventory['data']['network'])} interface(s)\\n" +
                             f"- Processes: {inventory['data']['collection_summary'].get('total_processes', 0)} running\\n" +
                             f"- Collection Time: {inventory['timestamp']}",
                    "timestamp": datetime.now().isoformat(),
                    "inventory_data": inventory  # Include full inventory in response
                }
            else:
                return {
                    "command": "COLLECT_INVENTORY",
                    "return_code": 1,
                    "success": False,
                    "error": "Failed to send inventory data to server",
                    "timestamp": datetime.now().isoformat()
                }
        
        elif command == "COLLECT_SBOM":
            self.logger.info("Handling COLLECT_SBOM command")
            sbom = self.collect_sbom()
            
            if self.network_manager.send_data(sbom):
                total_packages = sbom['data'].get('summary', {}).get('total_packages', 0)
                source_count = sbom['data'].get('summary', {}).get('source_count', 0)
                
                return {
                    "command": "COLLECT_SBOM",
                    "return_code": 0,
                    "success": True,
                    "output": f"Software Bill of Materials collected and sent successfully\\n\\nSBOM Summary:\\n" +
                             f"- Total Packages: {total_packages}\\n" +
                             f"- Package Sources: {source_count}\\n" +
                             f"- Platform: {platform.system()}\\n" +
                             f"- Collection Time: {sbom['timestamp']}",
                    "timestamp": datetime.now().isoformat(),
                    "sbom_data": sbom
                }
            else:
                return {
                    "command": "COLLECT_SBOM",
                    "return_code": 1,
                    "success": False,
                    "error": "Failed to send SBOM data to server",
                    "timestamp": datetime.now().isoformat()
                }
        
        elif command == "SHOW_INSTALLED_SOFTWARE":
            self.logger.info("Handling SHOW_INSTALLED_SOFTWARE command")
            sbom = self.collect_sbom()
            
            # Format the software list for display
            software_list = []
            total_count = 0
            
            for source in sbom['data'].get('software_sources', []):
                source_type = source.get('source_type', 'Unknown')
                packages = source.get('packages', [])
                total_count += len(packages)
                
                software_list.append(f"\n=== {source_type.upper()} ({len(packages)} packages) ===")
                
                for pkg in packages:
                    name = pkg.get('DisplayName') or pkg.get('name', 'Unknown')
                    version = pkg.get('DisplayVersion') or pkg.get('version', 'Unknown')
                    publisher = pkg.get('Publisher') or pkg.get('vendor') or pkg.get('maintainer', 'Unknown')
                    
                    software_list.append(f"• {name}")
                    if version != 'Unknown':
                        software_list.append(f"  Version: {version}")
                    if publisher != 'Unknown':
                        software_list.append(f"  Publisher: {publisher}")
                    software_list.append("")  # Empty line for spacing
            
            formatted_output = f"Complete Installed Software List\n{'='*50}\n"
            formatted_output += f"Total Software Packages: {total_count}\n"
            formatted_output += f"Collection Time: {datetime.now().isoformat()}\n"
            formatted_output += f"Platform: {platform.system()}\n"
            formatted_output += "\n".join(software_list)
            
            return {
                "command": "SHOW_INSTALLED_SOFTWARE",
                "return_code": 0,
                "success": True,
                "output": formatted_output,
                "timestamp": datetime.now().isoformat(),
                "sbom_data": sbom,
                "software_count": total_count
            }
        
        elif command == "GET_SYSTEM_INFO":
            basic_info = self.system_info.collect_basic_info()
            hardware_info = self.system_info.collect_hardware_info()
            
            return {
                "command": "GET_SYSTEM_INFO",
                "return_code": 0,
                "success": True,
                "output": f"System Information:\\n" +
                         f"Hostname: {basic_info.get('hostname', 'Unknown')}\\n" +
                         f"OS: {basic_info.get('os', 'Unknown')} {basic_info.get('os_version', '')}\\n" +
                         f"Architecture: {basic_info.get('architecture', 'Unknown')}\\n" +
                         f"CPU: {hardware_info.get('cpu_model', 'Unknown')} ({hardware_info.get('cpu_count_logical', 'Unknown')} cores)\\n" +
                         f"Memory: {hardware_info.get('memory_total_gb', 'Unknown')} GB total, {hardware_info.get('memory_used_gb', 'Unknown')} GB used ({hardware_info.get('memory_percent', 'Unknown')}%)\\n" +
                         f"Boot Time: {basic_info.get('boot_time', 'Unknown')}",
                "timestamp": datetime.now().isoformat(),
                "system_data": {"basic": basic_info, "hardware": hardware_info}            }
        
        elif command == "HELP":
            suggestions = self.command_executor.get_command_suggestions()
            return {
                "command": "HELP",
                "return_code": 0,
                "success": True,
                "output": f"Available Commands:\\n" +
                         f"Special Commands: COLLECT_INVENTORY, COLLECT_SBOM, SHOW_INSTALLED_SOFTWARE, GET_SYSTEM_INFO, RUN_HARDENING_AUDIT, GET_HARDENING_STATUS, HELP\\n\\n" +
                         f"System Commands: {', '.join(suggestions['allowed_commands'])}\\n\\n" +
                         f"Platform: {suggestions['platform']}\\n" +
                         f"Example Commands: {', '.join(suggestions['examples'].get(suggestions['platform'], []))}",
                "timestamp": datetime.now().isoformat(),
                "help_data": suggestions
            }
        
        elif command == "RUN_HARDENING_AUDIT":
            self.logger.info("Handling RUN_HARDENING_AUDIT command")
            try:
                audit_results = self.hardening_manager.run_hardening_audit()
                
                if audit_results.get('status') == 'success':
                    summary = audit_results.get('summary', {})
                    
                    return {
                        "command": "RUN_HARDENING_AUDIT",
                        "return_code": 0,
                        "success": True,
                        "output": f"Windows Hardening Audit Completed\\n{'='*50}\\n" +
                                 f"HardeningKitty Score: {summary.get('score', 0):.2f}/6.0\\n" +
                                 f"Total Checks: {summary.get('total_checks', 0)}\\n" +
                                 f"✅ Passed: {summary.get('passed', 0)}\\n" +
                                 f"🟡 Low Risk: {summary.get('low', 0)}\\n" +
                                 f"🟠 Medium Risk: {summary.get('medium', 0)}\\n" +
                                 f"🔴 High Risk: {summary.get('high', 0)}\\n" +
                                 f"\\n📊 Score Rating:\\n" +
                                 f"6.0 = 😹 Excellent\\n5.0 = 😺 Well done\\n4.0 = 😼 Sufficient\\n" +
                                 f"3.0 = 😿 You should do better\\n2.0 = 🙀 Weak\\n1.0 = 😾 Bogus\\n" +
                                 f"\\nScan completed at: {audit_results.get('timestamp')}",
                        "timestamp": datetime.now().isoformat(),
                        "hardening_data": audit_results
                    }
                else:
                    return {
                        "command": "RUN_HARDENING_AUDIT",
                        "return_code": 1,
                        "success": False,
                        "error": f"Hardening audit failed: {audit_results.get('error', 'Unknown error')}",
                        "timestamp": datetime.now().isoformat()
                    }
            except Exception as e:
                self.logger.error(f"Hardening audit error: {str(e)}")
                return {
                    "command": "RUN_HARDENING_AUDIT",
                    "return_code": 1,
                    "success": False,
                    "error": f"Hardening audit failed: {str(e)}",
                    "timestamp": datetime.now().isoformat()
                }
        
        elif command == "GET_HARDENING_STATUS":
            self.logger.info("Handling GET_HARDENING_STATUS command")
            try:
                status = self.hardening_manager.get_hardening_status()
                
                return {
                    "command": "GET_HARDENING_STATUS",
                    "return_code": 0,
                    "success": True,
                    "output": f"Windows Hardening Status\\n{'='*30}\\n" +
                             f"Agent ID: {status.get('agent_id')}\\n" +
                             f"Last Scan: {status.get('last_scan_time', 'Never')}\\n" +
                             f"Current Score: {status.get('hardening_score', 0):.2f}/6.0\\n" +
                             f"HardeningKitty Available: {'✅ Yes' if status.get('hardening_kitty_available') else '❌ No'}\\n" +
                             f"Available Finding Lists: {len(status.get('available_lists', []))}\\n" +
                             f"Temp Directory: {status.get('temp_directory')}",
                    "timestamp": datetime.now().isoformat(),
                    "status_data": status
                }
            except Exception as e:
                self.logger.error(f"Get hardening status error: {str(e)}")
                return {
                    "command": "GET_HARDENING_STATUS",
                    "return_code": 1,
                    "success": False,
                    "error": f"Failed to get hardening status: {str(e)}",
                    "timestamp": datetime.now().isoformat()
                }
        
        return None  # Not a special command
    
    def execute_command(self, command, timeout=None):
        """Execute a command (special or system)"""
        try:
            if not timeout:
                timeout = self.config.get('max_command_timeout', 60)
            
            # Check for special commands first
            special_result = self.handle_special_commands(command)
            if special_result:
                return special_result
            
            # Execute as regular system command
            result = self.command_executor.execute_command(command, timeout)
            return result
            
        except Exception as e:
            self.logger.error(f"Error executing command '{command}': {e}")
            return {
                "command": command,
                "return_code": 1,
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def command_worker(self):
        """Worker thread for processing commands"""
        self.logger.info("Command worker thread started")
        
        while self.running:
            try:
                # Get pending commands from server
                commands = self.network_manager.get_commands()
                
                for command_data in commands:
                    command_id = command_data.get('command_id')
                    command = command_data.get('command')
                    timeout = command_data.get('timeout', 30)
                    
                    self.logger.info(f"Processing command: {command}")
                    
                    # Execute command
                    result = self.execute_command(command, timeout)
                    
                    # Update latest command
                    self.latest_command = {
                        "command": command,
                        "timestamp": datetime.now().isoformat(),
                        "return_code": result.get('return_code', 1)
                    }
                    
                    # Send result back to server
                    self.network_manager.send_command_result(command_id, result)
                
                # Sleep before checking for more commands
                time.sleep(5)
                
            except Exception as e:
                self.logger.error(f"Error in command worker: {e}")
                time.sleep(10)
    
    def heartbeat_worker(self):
        """Worker thread for sending heartbeats"""
        self.logger.info("Heartbeat worker thread started")
        
        while self.running:
            try:
                # Get basic system info for heartbeat
                basic_info = self.system_info.collect_basic_info()
                
                # Send heartbeat
                self.network_manager.send_heartbeat(basic_info, self.latest_command)
                
                # Sleep until next heartbeat
                time.sleep(self.heartbeat_interval)
                
            except Exception as e:
                self.logger.error(f"Error in heartbeat worker: {e}")
                time.sleep(30)
    
    def inventory_worker(self):
        """Worker thread for periodic inventory collection"""
        self.logger.info("Inventory worker thread started")
        
        while self.running:
            try:
                # Collect and send full inventory
                inventory = self.collect_full_inventory()
                self.network_manager.send_data(inventory)
                
                # Sleep until next inventory collection
                time.sleep(self.inventory_interval)
                
            except Exception as e:
                self.logger.error(f"Error in inventory worker: {e}")
                time.sleep(60)
    
    def sbom_worker(self):
        """Worker thread for periodic SBOM collection"""
        if not self.config.get('enable_full_sbom', True):
            self.logger.info("SBOM collection disabled")
            return
        
        self.logger.info("SBOM worker thread started")
        
        while self.running:
            try:
                # Collect and send SBOM
                sbom = self.collect_sbom()
                self.network_manager.send_data(sbom)
                
                # Sleep until next SBOM collection
                time.sleep(self.sbom_interval)
                
            except Exception as e:
                self.logger.error(f"Error in SBOM worker: {e}")
                time.sleep(300)  # Wait 5 minutes on error
    
    def start(self):
        """Start the agent"""
        self.logger.info("Starting Modular Endpoint Agent...")
        
        # Test server connection
        if not self.network_manager.test_connection():
            self.logger.error("Cannot connect to server, starting anyway...")
        
        # Start worker threads
        threads = [
            threading.Thread(target=self.heartbeat_worker, daemon=True),
            threading.Thread(target=self.command_worker, daemon=True),
            threading.Thread(target=self.inventory_worker, daemon=True),
            threading.Thread(target=self.sbom_worker, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
        
        self.logger.info("All worker threads started")
        
        # Send initial inventory
        try:
            initial_inventory = self.collect_full_inventory()
            self.network_manager.send_data(initial_inventory)
            self.logger.info("Initial inventory sent")
        except Exception as e:
            self.logger.error(f"Failed to send initial inventory: {e}")
        
        # Main loop
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Shutdown requested by user")
            self.stop()
    
    def stop(self):
        """Stop the agent"""
        self.logger.info("Stopping Modular Endpoint Agent...")
        self.running = False
        time.sleep(2)  # Give threads time to finish
        self.logger.info("Modular Endpoint Agent stopped")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Modular Endpoint Agent')
    parser.add_argument('--server-url', help='Server URL', default=None)
    parser.add_argument('--api-key', help='API Key', default=None)
    parser.add_argument('--config', help='Configuration file', default='agent_config.json')
    
    args = parser.parse_args()
    
    # Create and start agent
    agent = ModularEndpointAgent(
        server_url=args.server_url,
        api_key=args.api_key,
        config_file=args.config
    )
    
    try:
        agent.start()
    except Exception as e:
        logging.error(f"Agent failed to start: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
