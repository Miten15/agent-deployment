# system_info.py - System Information Collection Module
import platform
import socket
import psutil
import logging
from datetime import datetime


class SystemInfoCollector:
    """Collects basic system information"""
    
    def __init__(self, agent_id):
        self.agent_id = agent_id
        self.logger = logging.getLogger(__name__)
    
    def collect_basic_info(self):
        """Collect basic system information"""
        try:
            return {
                "hostname": socket.gethostname(),
                "platform": platform.platform(),
                "os": platform.system(),
                "os_version": platform.version(),
                "architecture": platform.architecture()[0],
                "processor": platform.processor(),
                "machine": platform.machine(),
                "python_version": platform.python_version(),
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                "node": platform.node(),
                "release": platform.release(),
                "collected_at": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error collecting basic system info: {e}")
            return {"error": str(e)}
    
    def collect_hardware_info(self):
        """Collect hardware information"""
        try:
            memory = psutil.virtual_memory()
            disk_io = psutil.disk_io_counters()
            network_io = psutil.net_io_counters()            # Get CPU model name (Windows specific)
            cpu_model = "Unknown"
            try:
                if platform.system() == "Windows":
                    import subprocess
                    
                    # Try PowerShell first (wmic is deprecated in newer Windows)
                    try:
                        result = subprocess.run(['powershell', '-Command', 
                                               'Get-WmiObject -Class Win32_Processor | Select-Object -ExpandProperty Name'], 
                                              capture_output=True, text=True, timeout=10)
                        if result.returncode == 0:
                            name = result.stdout.strip()
                            if name:
                                cpu_model = name
                    except Exception:
                        pass
                    
                    # Try newer PowerShell CIM cmdlet if WMI fails
                    if cpu_model == "Unknown":
                        try:
                            result = subprocess.run(['powershell', '-Command', 
                                                   'Get-CimInstance -ClassName Win32_Processor | Select-Object -ExpandProperty Name'], 
                                                  capture_output=True, text=True, timeout=10)
                            if result.returncode == 0:
                                name = result.stdout.strip()
                                if name:
                                    cpu_model = name
                        except Exception:
                            pass
                    
                    # Try wmic as fallback (for older Windows systems)
                    if cpu_model == "Unknown":
                        try:
                            result = subprocess.run(['wmic', 'cpu', 'get', 'name'], 
                                                  capture_output=True, text=True, timeout=10)
                            if result.returncode == 0:
                                lines = result.stdout.strip().split('\n')
                                if len(lines) > 1:
                                    name = lines[1].strip()
                                    if name and name != "Name":  # Skip header
                                        cpu_model = name
                        except Exception:
                            pass
                            
                    # Final fallback to platform.processor()
                    if cpu_model == "Unknown":
                        fallback = platform.processor()
                        if fallback:
                            cpu_model = fallback
                            
            except Exception as e:
                # Final fallback
                try:
                    cpu_model = platform.processor()
                except Exception:
                    cpu_model = "Unknown"
            
            return {
                "cpu_count_physical": psutil.cpu_count(logical=False),
                "cpu_count_logical": psutil.cpu_count(logical=True),
                "cpu_freq": psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
                "cpu_model": cpu_model,
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_total_gb": round(memory.total / (1024**3), 2),
                "memory_available_gb": round(memory.available / (1024**3), 2),
                "memory_used_gb": round(memory.used / (1024**3), 2),
                "memory_percent": memory.percent,
                "disk_io": disk_io._asdict() if disk_io else None,
                "network_io": network_io._asdict() if network_io else None,
                "collected_at": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error collecting hardware info: {e}")
            return {"error": str(e)}
    
    def collect_disk_info(self):
        """Collect disk information"""
        try:
            disk_info = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_info.append({
                        "device": partition.device,
                        "mountpoint": partition.mountpoint,
                        "fstype": partition.fstype,
                        "total_gb": round(usage.total / (1024**3), 2),
                        "used_gb": round(usage.used / (1024**3), 2),
                        "free_gb": round(usage.free / (1024**3), 2),
                        "percent": round((usage.used / usage.total) * 100, 2)
                    })
                except PermissionError:
                    continue
                except Exception as e:
                    self.logger.warning(f"Error getting disk info for {partition.device}: {e}")
                    continue
            
            return {
                "disks": disk_info,
                "collected_at": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error collecting disk info: {e}")
            return {"error": str(e)}
    
    def collect_network_info(self):
        """Collect network information"""
        try:
            network_info = {}
            for interface, addrs in psutil.net_if_addrs().items():
                network_info[interface] = {
                    "addresses": [],
                    "stats": None
                }
                
                # Collect addresses
                for addr in addrs:
                    network_info[interface]["addresses"].append({
                        "family": str(addr.family),
                        "address": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast
                    })
                
                # Get interface statistics
                try:
                    stats = psutil.net_if_stats()[interface]
                    network_info[interface]["stats"] = {
                        "isup": stats.isup,
                        "duplex": str(stats.duplex),
                        "speed": stats.speed,
                        "mtu": stats.mtu
                    }
                except KeyError:
                    pass
            
            # Get active connections
            connections = []
            try:
                for conn in psutil.net_connections(kind='inet'):
                    connections.append({
                        "family": str(conn.family),
                        "type": str(conn.type),
                        "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        "status": conn.status,
                        "pid": conn.pid
                    })
            except Exception as e:
                self.logger.warning(f"Error getting network connections: {e}")
            
            return {
                "interfaces": network_info,
                "connections": connections[:50],  # Limit to first 50
                "collected_at": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error collecting network info: {e}")
            return {"error": str(e)}
    
    def collect_processes_info(self):
        """Collect running processes information"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent', 'status', 'create_time']):
                try:
                    proc_info = proc.info
                    proc_info['create_time'] = datetime.fromtimestamp(proc_info.get('create_time', 0)).isoformat()
                    processes.append(proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # Sort by memory usage (descending)
            top_processes = sorted(processes, key=lambda x: x.get('memory_percent', 0), reverse=True)
            
            return {
                "total_processes": len(processes),
                "top_processes_by_memory": top_processes[:20],
                "top_processes_by_cpu": sorted(processes, key=lambda x: x.get('cpu_percent', 0), reverse=True)[:20],
                "collected_at": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error collecting processes info: {e}")
            return {"error": str(e)}
