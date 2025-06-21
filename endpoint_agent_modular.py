# endpoint_agent_modular.py - Modular System Inventory & Command Execution Agent
import os
import sys
import json
import time
import uuid
import psutil
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
from modules.behavioral_anomaly_detector import BehavioralAnomalyDetector

# Load environment variables
load_dotenv()


class ModularEndpointAgent:
    """Modular Endpoint Agent with separated responsibilities"""
    
    def __init__(self, server_url=None, config_file="agent_config.json", api_key=None):
        # Configuration
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
        
        # Initialize Behavioral Anomaly Detector
        behavioral_config = self.config.get('behavioral_detection', {})
        self.behavioral_detector = BehavioralAnomalyDetector(self.agent_id, behavioral_config)
        
        # Agent state
        self.running = True
        self.command_queue = queue.Queue()
        self.latest_command = None
          # Intervals (from config) - Optimized for better detection
        self.heartbeat_interval = self.config.get('heartbeat_interval', 30)  # 30s standard
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
            ]        )
        self.logger = logging.getLogger(f'EndpointAgent_{self.agent_id}')
    
    def _load_config(self):
        """Load agent configuration"""
        default_config = {
            "server_url": self.server_url,
            "heartbeat_interval": 30,  # Reduced to 30s for faster detection
            "inventory_interval": 300,
            "sbom_interval": 1800,
            "allowed_commands": [
                "dir", "ls", "ps", "netstat", "whoami", "systeminfo", "ipconfig", "ifconfig",
                "ping", "tracert", "traceroute", "nslookup", "route", "arp", "tasklist",
                "wmic", "get-process", "get-service", "get-computerinfo", "powershell",
                "RUN_HARDENING_AUDIT", "GET_HARDENING_STATUS", "COLLECT_INVENTORY", 
                "COLLECT_SBOM", "SHOW_INSTALLED_SOFTWARE", "GET_SYSTEM_INFO",
                "RUN_BEHAVIORAL_SCAN", "GET_BEHAVIORAL_HISTORY", "STOP_BEHAVIORAL_SCAN"
            ],
            "max_command_timeout": 60,
            "enable_full_sbom": True,
            "enable_system_monitoring": True,
            "behavioral_detection": {
                "profile_duration": 120,
                "sampling_interval": 2,
                "suspicion_threshold": 4.0,  # Updated to 0-10 scale
                "high_privilege_users": [
                    "NT AUTHORITY\\SYSTEM", "root", "SYSTEM", "Administrator"
                ],
                # Research-based thresholds from NIST, MITRE ATT&CK, and security frameworks
                "high_disk_reads_mb": 350,  # 300-400MB range for enterprise
                "contextual_disk_reads_mb": 800,  # Higher for AV/backup tools
                "high_data_egress_mb": 5,  # Lowered based on APT research
                "sensitive_data_egress_mb": 1,  # Stricter for sensitive systems
                "persistent_connection_seconds": 60,  # Maintained
                "off_hours_connection_seconds": 30,  # Stricter outside business hours
                "high_cpu_percent": 60,  # Lowered from 70% based on research
                "sustained_cpu_duration_minutes": 3,  # 3-5 min requirement
                "sustained_cpu_samples": 30,  # Increased for 3-min duration
                "beaconing_min_intervals": 5,  # Minimum intervals
                "beaconing_variance_threshold": 0.15,  # Tightened to 15%
                "beaconing_min_interval_seconds": 5,  # 5s minimum
                "beaconing_max_interval_seconds": 600,  # 10min maximum
                "slow_beacon_max_interval_seconds": 3600,  # 1hr for "low and slow"
                "legitimate_processes": [
                    "windows defender", "defender", "antimalware", "msmpeng.exe",
                    "backup", "veeam", "acronis", "carbonite",
                    "chrome.exe", "firefox.exe", "edge.exe", "browser",
                    "system monitor", "perfmon", "procmon", "sysmon"
                ],
                "auto_scan_interval": 3600  # Run behavioral scan every hour
            }
        }
        
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
                "timestamp": datetime.now().isoformat(),                "error": str(e)
            }
    
    def handle_special_commands(self, command):
        """Handle special agent commands"""
        original_command = command
        command = command.strip().upper()
        self.logger.info(f"Handling special command: '{original_command}' -> '{command}'")
        
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
                "system_data": {"basic": basic_info, "hardware": hardware_info}
            }
        
        elif command == "RUN_BEHAVIORAL_SCAN":
            self.logger.info("Handling RUN_BEHAVIORAL_SCAN command")
            try:
                # Get optional duration parameter (default to config value)
                duration = self.config.get('behavioral_detection', {}).get('profile_duration', 120)
                
                # Run behavioral scan
                scan_result = self.behavioral_detector.run_full_detection(duration)
                
                # Send results to server
                behavioral_message = {
                    "agent_id": self.agent_id,
                    "message_type": "behavioral_scan",
                    "timestamp": datetime.now().isoformat(),
                    "data": scan_result
                }
                
                if self.network_manager.send_data(behavioral_message):
                    suspicious_count = len(scan_result.get('suspicious_processes', []))
                    total_analyzed = scan_result.get('summary', {}).get('total_processes_analyzed', 0)
                    
                    # Format summary output
                    output_lines = [
                        "Behavioral Anomaly Detection Scan Completed",
                        "=" * 50,
                        f"Scan Duration: {duration} seconds",
                        f"Total Processes Analyzed: {total_analyzed}",
                        f"Suspicious Processes Found: {suspicious_count}",
                        ""
                    ]
                    
                    if suspicious_count > 0:
                        output_lines.append("Suspicious Processes:")
                        for process in scan_result.get('suspicious_processes', []):
                            output_lines.append(f"• {process['process_name']} (PID: {process['pid']})")
                            output_lines.append(f"  Risk Level: {process['risk_level'].upper()}")
                            output_lines.append(f"  Suspicion Score: {process['suspicion_score']}")
                            output_lines.append(f"  User: {process['username']}")
                            
                            # Show top 3 suspicious behaviors
                            behaviors = process.get('suspicious_behaviors', [])[:3]
                            for behavior in behaviors:
                                output_lines.append(f"    - {behavior['description']}")
                            output_lines.append("")
                    else:
                        output_lines.append("No suspicious processes detected.")
                    
                    return {                        "command": "RUN_BEHAVIORAL_SCAN",
                        "return_code": 0,
                        "success": True,
                        "output": "\\n".join(output_lines),
                        "timestamp": datetime.now().isoformat(),
                        "behavioral_data": scan_result
                    }
                else:
                    # Even if server connection fails, return the scan results for testing/debugging
                    return {
                        "command": "RUN_BEHAVIORAL_SCAN",
                        "return_code": 1,
                        "success": False,
                        "error": "Failed to send behavioral scan results to server",
                        "timestamp": datetime.now().isoformat(),
                        "behavioral_data": scan_result  # Include scan results even on server failure
                    }
                    
            except Exception as e:
                self.logger.error(f"Error running behavioral scan: {e}")
                return {
                    "command": "RUN_BEHAVIORAL_SCAN",
                    "return_code": 1,
                    "success": False,
                    "error": f"Behavioral scan failed: {str(e)}",
                    "timestamp": datetime.now().isoformat()
                }
        
        elif command == "GET_BEHAVIORAL_HISTORY":
            self.logger.info("Handling GET_BEHAVIORAL_HISTORY command")
            try:
                history = self.behavioral_detector.get_detection_history()
                history_count = len(history)
                
                if history_count == 0:
                    return {
                        "command": "GET_BEHAVIORAL_HISTORY",
                        "return_code": 0,
                        "success": True,
                        "output": "No behavioral scan history available. Run RUN_BEHAVIORAL_SCAN first.",
                        "timestamp": datetime.now().isoformat(),
                        "behavioral_history": []
                    }
                
                # Format history summary
                output_lines = ["Behavioral Detection History", "=" * 30]
                
                for i, scan in enumerate(history[-5:], 1):  # Show last 5 scans
                    metadata = scan.get('detection_metadata', {})
                    summary = scan.get('summary', {})
                    
                    output_lines.append(f"\\nScan #{i}:")
                    output_lines.append(f"  Time: {metadata.get('detection_timestamp', 'Unknown')}")
                    output_lines.append(f"  Duration: {metadata.get('analysis_duration_seconds', 'Unknown')}s")
                    output_lines.append(f"  Processes Analyzed: {summary.get('total_processes_analyzed', 0)}")
                    output_lines.append(f"  Suspicious Processes: {summary.get('suspicious_processes_found', 0)}")
                    
                    risk_dist = summary.get('risk_distribution', {})
                    if any(risk_dist.values()):
                        output_lines.append(f"  Risk Distribution: Critical={risk_dist.get('critical', 0)}, High={risk_dist.get('high', 0)}, Medium={risk_dist.get('medium', 0)}")
                
                return {
                    "command": "GET_BEHAVIORAL_HISTORY",
                    "return_code": 0,
                    "success": True,
                    "output": "\\n".join(output_lines),
                    "timestamp": datetime.now().isoformat(),
                    "behavioral_history": history
                }
                
            except Exception as e:
                self.logger.error(f"Error getting behavioral history: {e}")
                return {
                    "command": "GET_BEHAVIORAL_HISTORY",
                    "return_code": 1,
                    "success": False,
                    "error": f"Failed to get behavioral history: {str(e)}",
                    "timestamp": datetime.now().isoformat()
                }
        
        elif command == "STOP_BEHAVIORAL_SCAN":
            self.logger.info("Handling STOP_BEHAVIORAL_SCAN command")
            try:
                self.behavioral_detector.stop_profiling()
                return {
                    "command": "STOP_BEHAVIORAL_SCAN",
                    "return_code": 0,
                    "success": True,
                    "output": "Behavioral profiling stopped successfully.",
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                self.logger.error(f"Error stopping behavioral scan: {e}")
                return {
                    "command": "STOP_BEHAVIORAL_SCAN",
                    "return_code": 1,
                    "success": False,
                    "error": f"Failed to stop behavioral scan: {str(e)}",
                    "timestamp": datetime.now().isoformat()
                }
        
        # Hardening commands
        elif command == "RUN_HARDENING_AUDIT":
            self.logger.info("Handling RUN_HARDENING_AUDIT command")
            try:
                result = self.hardening_manager.run_hardening_audit()
                
                if result["success"]:
                    # Send hardening results to server
                    hardening_message = {
                        "agent_id": self.agent_id,
                        "message_type": "hardening_audit",
                        "timestamp": datetime.now().isoformat(),
                        "data": result
                    }
                    
                    if self.network_manager.send_data(hardening_message):
                        return {
                            "command": "RUN_HARDENING_AUDIT",
                            "return_code": 0,
                            "success": True,
                            "output": f"Windows Hardening Audit Completed\\n{'='*40}\\n" +
                                      f"Agent ID: {result.get('agent_id')}\\n" +
                                      f"Timestamp: {result.get('timestamp')}\\n" +
                                      f"Overall Score: {result.get('hardening_score', 0):.2f}/6.0\\n" +
                                      f"Critical Findings: {len([f for f in result.get('findings', []) if f.get('severity') == 'Critical'])}\\n" +
                                      f"High Findings: {len([f for f in result.get('findings', []) if f.get('severity') == 'High'])}\\n" +
                                      f"Medium Findings: {len([f for f in result.get('findings', []) if f.get('severity') == 'Medium'])}\\n" +
                                      f"Total Findings: {len(result.get('findings', []))}\\n" +
                                      f"HardeningKitty Available: {'✅ Yes' if result.get('hardening_kitty_available') else '❌ No'}\\n" +
                                      f"Scan Duration: {result.get('scan_duration_seconds', 0):.1f} seconds",
                            "timestamp": datetime.now().isoformat(),
                            "hardening_data": result
                        }
                    else:
                        return {
                            "command": "RUN_HARDENING_AUDIT",
                            "return_code": 1,
                            "success": False,
                            "error": "Failed to send hardening audit results to server",
                            "timestamp": datetime.now().isoformat()
                        }
                else:
                    return {
                        "command": "RUN_HARDENING_AUDIT",
                        "return_code": 1,
                        "success": False,
                        "error": result.get("error", "Hardening audit failed"),
                        "timestamp": datetime.now().isoformat()
                    }
                    
            except Exception as e:
                self.logger.error(f"Error running hardening audit: {e}")
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
          # Return None if command not recognized
        return None
    
    def execute_command(self, command):
        """Execute a command using the command executor"""
        try:
            self.logger.info(f"Execute command called with: '{command}'")
            
            # Check if it's a special command first
            self.logger.info(f"Checking if '{command}' is a special command...")
            special_result = self.handle_special_commands(command)
            if special_result is not None:
                self.logger.info(f"Special command handled successfully: {command}")
                self.logger.info(f"Special command result: {special_result}")
                return special_result
            
            self.logger.info(f"Not a special command, executing normally: {command}")
            # If not a special command, execute normally
            return self.command_executor.execute_command(command)
            
        except Exception as e:
            self.logger.error(f"Error executing command '{command}': {e}")
            return {
                "command": command,
                "return_code": 1,
                "success": False,
                "error": str(e),                
                "timestamp": datetime.now().isoformat()
            }
    
    def send_heartbeat(self):
        """Send heartbeat to server"""
        try:
            # Get system info for heartbeat
            system_info = self.system_info.collect_basic_info()
            
            # Use the dedicated heartbeat endpoint via network manager
            success = self.network_manager.send_heartbeat(system_info, self.latest_command)
            
            if success:
                self.logger.info(f"Heartbeat sent successfully for agent {self.agent_id}")
            else:
                self.logger.warning(f"Heartbeat failed for agent {self.agent_id} - server may be offline")
                
            return success
        except Exception as e:
            self.logger.error(f"Error sending heartbeat: {e}")
            return False
    
    def check_for_commands(self):
        """Check server for pending commands"""
        try:
            self.logger.debug("Checking for commands from server...")
            commands = self.network_manager.get_commands()
            
            if commands:
                for command_data in commands:
                    command = command_data.get('command', '').strip()
                    command_id = command_data.get('command_id', 'unknown')
                    
                    if command:
                        self.logger.info(f"Received command: {command} (ID: {command_id})")
                        self.latest_command = command
                        self.command_queue.put((command, command_id))
                        
        except Exception as e:
            self.logger.error(f"Error checking for commands: {e}")
    
    def process_command_queue(self):
        """Process commands from the queue using threading for non-blocking execution"""
        while not self.command_queue.empty():
            try:
                command, command_id = self.command_queue.get(timeout=1)
                self.logger.info(f"Processing command: {command}")
                
                # Check if it's a long-running command that should be threaded
                long_running_commands = [
                    'RUN_BEHAVIORAL_SCAN', 'COLLECT_INVENTORY', 'COLLECT_SBOM', 
                    'SHOW_INSTALLED_SOFTWARE', 'RUN_HARDENING_AUDIT'
                ]
                
                is_long_running = any(cmd in command.upper() for cmd in long_running_commands)
                
                if is_long_running:
                    # Execute long-running commands in separate thread
                    self.logger.info(f"Executing long-running command in thread: {command}")
                    thread = threading.Thread(
                        target=self._execute_command_threaded,
                        args=(command, command_id),
                        daemon=True
                    )
                    thread.start()
                else:
                    # Execute short commands synchronously
                    result = self.execute_command(command)
                    self._send_command_result(command, command_id, result)
                
                self.command_queue.task_done()
                
            except queue.Empty:
                break
            except Exception as e:
                self.logger.error(f"Error processing command: {e}")
    
    def _execute_command_threaded(self, command, command_id):
        """Execute command in a separate thread"""
        try:
            self.logger.info(f"Thread executing: {command}")
            result = self.execute_command(command)
            self._send_command_result(command, command_id, result)
        except Exception as e:
            self.logger.error(f"Error in threaded command execution: {e}")
            error_result = {
                "command": command,
                "return_code": 1,
                "success": False,
                "error": f"Thread execution error: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
            self._send_command_result(command, command_id, error_result)
    
    def _send_command_result(self, command, command_id, result):
        """Send command result to server"""
        try:
            result_data = {
                "agent_id": self.agent_id,
                "message_type": "command_result",
                "command_id": command_id,
                "timestamp": datetime.now().isoformat(),
                "result": result
            }
            
            self.network_manager.send_data(result_data)
            self.logger.info(f"Command result sent: {command}")
        except Exception as e:
            self.logger.error(f"Error sending command result: {e}")
    
    def run_periodic_tasks(self):
        """Run periodic tasks like inventory collection"""
        try:
            current_time = time.time()
            
            # Check if it's time for full inventory
            if (current_time - getattr(self, 'last_inventory_time', 0)) >= self.inventory_interval:
                self.logger.info("Running periodic inventory collection...")
                inventory = self.collect_full_inventory()
                self.network_manager.send_data(inventory)
                self.last_inventory_time = current_time
                
            # Check if it's time for SBOM collection
            if (current_time - getattr(self, 'last_sbom_time', 0)) >= self.sbom_interval:
                self.logger.info("Running periodic SBOM collection...")
                sbom = self.collect_sbom()
                self.network_manager.send_data(sbom)
                self.last_sbom_time = current_time
                
            # Check if behavioral detection is enabled and if it's time for auto-scan
            behavioral_config = self.config.get('behavioral_detection', {})
            auto_scan_interval = behavioral_config.get('auto_scan_interval', 0)
            
            if auto_scan_interval > 0:
                if (current_time - getattr(self, 'last_behavioral_scan_time', 0)) >= auto_scan_interval:
                    self.logger.info("Running periodic behavioral scan...")
                    try:
                        scan_result = self.behavioral_detector.run_full_detection()
                        behavioral_message = {
                            "agent_id": self.agent_id,
                            "message_type": "behavioral_scan",
                            "timestamp": datetime.now().isoformat(),
                            "data": scan_result
                        }
                        self.network_manager.send_data(behavioral_message)
                        self.last_behavioral_scan_time = current_time
                    except Exception as e:
                        self.logger.error(f"Error in periodic behavioral scan: {e}")
                        
        except Exception as e:
            self.logger.error(f"Error in periodic tasks: {e}")
    
    def run(self):
        """Main agent execution loop"""
        self.logger.info("Starting Modular Endpoint Agent...")
        self.start_time = time.time()
        
        # Initialize timers
        last_heartbeat = 0
        last_command_check = 0
        last_periodic_tasks = 0
        
        try:
            while self.running:
                current_time = time.time()
                
                # Send heartbeat
                if (current_time - last_heartbeat) >= self.heartbeat_interval:
                    self.send_heartbeat()
                    last_heartbeat = current_time
                  # Check for commands (more frequent for responsiveness)
                if (current_time - last_command_check) >= 10:  # Check every 10 seconds
                    self.check_for_commands()
                    last_command_check = current_time
                
                # Process command queue
                self.process_command_queue()
                
                # Run periodic tasks
                if (current_time - last_periodic_tasks) >= 60:  # Check every minute
                    self.run_periodic_tasks()
                    last_periodic_tasks = current_time
                
                # Sleep to prevent excessive CPU usage
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal, shutting down...")
        except Exception as e:
            self.logger.error(f"Unexpected error in main loop: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the agent"""
        self.logger.info("Stopping Modular Endpoint Agent...")
        self.running = False
        
        # Stop behavioral profiling if running
        try:
            if hasattr(self, 'behavioral_detector'):
                self.behavioral_detector.stop_profiling()
        except Exception as e:
            self.logger.error(f"Error stopping behavioral detector: {e}")


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Modular Endpoint Agent')
    parser.add_argument('--server-url', default=None, help='Server URL')
    parser.add_argument('--config', default='agent_config.json', help='Configuration file')
    parser.add_argument('--api-key', default=None, help='API Key')
    parser.add_argument('--test-mode', action='store_true', help='Run in test mode')
    
    args = parser.parse_args()
    
    try:
        # Create and run agent
        agent = ModularEndpointAgent(
            server_url=args.server_url,
            config_file=args.config,
            api_key=args.api_key
        )
        
        if args.test_mode:
            print(f"Agent initialized successfully - ID: {agent.agent_id}")
            print("Test mode - collecting sample data...")
            
            # Test basic functionality
            inventory = agent.collect_full_inventory()
            print(f"Inventory collected: {len(inventory.get('data', {}))} sections")
            
            sbom = agent.collect_sbom()
            print(f"SBOM collected: {sbom.get('data', {}).get('summary', {}).get('total_packages', 0)} packages")
            
            print("Test completed successfully")
        else:
            # Run normally
            agent.run()
            
    except Exception as e:
        print(f"Error starting agent: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
