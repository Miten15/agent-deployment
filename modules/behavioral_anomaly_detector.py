# behavioral_anomaly_detector.py - Behavioral Anomaly Detection Module
import os
import json
import time
import psutil
import logging
import threading
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Any, Optional


class BehavioralAnomalyDetector:
    """
    Comprehensive Behavioral Anomaly Detector for identifying security tools and monitoring agents
    based on their behavioral patterns rather than signatures or known names.
    
    Architecture: Four-Phase Detection System
    1. Profiler: Collects raw behavioral data
    2. Analyzer: Applies heuristics and rules to identify suspicious patterns
    3. Scorer: Quantifies suspicion into numerical scores
    4. Reporter: Generates actionable, structured reports
    """
    
    def __init__(self, agent_id: str, config: Optional[Dict] = None):
        self.agent_id = agent_id
        self.logger = logging.getLogger(__name__)        # Configuration with sensible defaults - Updated for realistic baselines
        self.config = config or {}
        self.profile_duration = self.config.get('profile_duration', 120)  # seconds
        self.sampling_interval = self.config.get('sampling_interval', 2)  # seconds
        self.suspicion_threshold = self.config.get('suspicion_threshold', 4.0)  # 0-10 scale (raised slightly for precision)
        self.high_privilege_users = self.config.get('high_privilege_users', [
            'NT AUTHORITY\\SYSTEM', 'root', 'SYSTEM', 'Administrator'
        ])
          # Log collection/forwarding services - for contextual scoring
        self.log_collection_services = self.config.get('log_collection_services', [
            # SIEM and Log Management
            'wazuh', 'wazuh-agent', 'wazuh-manager', 'ossec', 'ossec-agent',
            'elasticsearch', 'logstash', 'kibana', 'filebeat', 'metricbeat', 'winlogbeat',
            'splunk', 'splunkd', 'splunk-forwarder', 'universalforwarder',
            'fluentd', 'fluent-bit', 'td-agent', 'vector', 'rsyslog', 'syslog-ng',
            # Security and Monitoring
            'datadog-agent', 'dd-agent', 'newrelic', 'nr-agent', 'collectd',
            'telegraf', 'prometheus', 'node_exporter', 'windows_exporter',
            'suricata', 'snort', 'zeek', 'bro', 'falco',
            # Microsoft native
            'winlogbeat', 'azure-monitor-agent', 'microsoft-monitoring-agent', 'mma',
            'system-center-monitoring-agent', 'scma', 'windows-event-log'
        ])
        
        # Legitimate Windows services and applications - should have minimal scoring
        self.legitimate_services = self.config.get('legitimate_services', [
            # Windows System Services
            'wudfhost', 'svchost', 'services', 'lsass', 'csrss', 'winlogon', 'dwm',
            'spoolsv', 'taskhost', 'audiodg', 'wininit', 'smss', 'conhost', 'explorer',
            'ipfsvc', 'dnscache', 'dhcp', 'winhttp', 'bits', 'cryptsvc', 'eventlog',
            
            # Windows Defender and Security
            'mpdefendercoreservice', 'msmpeng', 'antimalware', 'windefend', 'securityhealthservice',
            'wscsvc', 'wdnissvc', 'sense', 'mpssvc',
            
            # Hardware and Driver Services  
            'nvdisplay.container', 'nvcontainer', 'nvidia', 'amd', 'intel', 'atikmdag',
            'igfxpers', 'igfxtray', 'igfxhk', 'igfxem', 'audiodg', 'realtek',
            
            # Development Tools
            'code', 'devenv', 'msbuild', 'dotnet', 'java', 'javaw', 'python', 'pythonw',
            'node', 'npm', 'git', 'gitbash', 'powershell', 'pwsh', 'cmd',
            
            # Browsers and Communication
            'chrome', 'firefox', 'edge', 'opera', 'brave', 'arc', 'safari',
            'teams', 'skype', 'zoom', 'discord', 'slack', 'whatsapp', 'telegram',
            
            # Database and Server Software
            'mysqld', 'mysql', 'postgres', 'sqlservr', 'mongodb', 'redis-server',
            'elasticsearch', 'apache', 'nginx', 'iis', 'tomcat',
            
            # Gaming and Hardware Control Software
            'steam', 'origin', 'uplay', 'epicgameslauncher', 'battlenet', 'gog',
            'msiafterburner', 'evga', 'corsair', 'logitech', 'razer', 'steelseries',
            'armorycrate', 'asus', 'roggaming', 'roglivesservice', 'lightingservice',
            'aura', 'armouryservice', 'armourysocketserver', 'aacambientlighting',
            'asus_framework', 'acpowernotification',
            
            # Microsoft Services and Apps
            'microsoftedge', 'msedge', 'phoneexperiencehost', 'crossdeviceservice',
            'cortana', 'searchui', 'startmenuexperiencehost', 'shellexperiencehost',
            'runtimebroker', 'applicationframehost', 'systemsettings',
            
            # Cloud Storage and Sync
            'onedrive', 'dropbox', 'googledrivesync', 'box', 'icloud', 'mega',
            
            # Antivirus Software
            'avgui', 'avguix', 'avgidsagent', 'avgwdsvc', 'avast', 'avira',
            'kaspersky', 'bitdefender', 'norton', 'mcafee', 'eset', 'trend',
            
            # Media and Entertainment
            'spotify', 'vlc', 'mediaplayer', 'netflix', 'prime', 'youtube',
            'obs', 'streamlabs', 'xsplit', 'bandicam', 'fraps'
        ])
        
        # C2 signatures and suspicious patterns
        self.c2_signatures = self.config.get('c2_signatures', [
            # Common C2 frameworks
            'cobalt', 'beacon', 'meterpreter', 'empire', 'covenant', 'sliver',
            'mythic', 'havoc', 'brute-ratel', 'nighthawk', 'koadic',
            # Network indicators
            'heartbeat', 'checkin', 'staging', 'stager', 'payload',
            'backdoor', 'shell', 'implant', 'rat', 'trojan',
            # Communication patterns
            '/api/v1/', '/rest/', '/admin/', '/config/', '/data/',
            'base64', 'powershell', 'cmd.exe', 'rundll32'
        ])
        
        # Suspicious Windows service patterns
        self.suspicious_service_patterns = self.config.get('suspicious_service_patterns', [
            # Generic suspicious patterns
            'svc', 'service', 'daemon', 'agent', 'helper', 'updater',
            'manager', 'monitor', 'scanner', 'checker', 'runner',
            # Disguised as legitimate
            'microsoft', 'windows', 'system', 'security', 'update',
            'antivirus', 'defender', 'protection', 'firewall',
            # Random/encoded names
            r'[a-f0-9]{8,}',  # Hex strings
            r'[A-Z]{3,8}[0-9]{3,8}',  # Random caps + numbers
            r'svchost[0-9]+',  # Fake svchost variations
        ])
          # Behavioral thresholds - Research-based baselines from NIST, MITRE ATT&CK, and security frameworks
        self.thresholds = {
            # Disk I/O: Based on TPC-E benchmarks and NIST SP 800-94 recommendations
            'high_disk_reads_mb': self.config.get('high_disk_reads_mb', 350),  # 300-400MB range for enterprise
            'contextual_disk_reads_mb': self.config.get('contextual_disk_reads_mb', 800),  # Higher for AV/backup tools
            
            # Data egress: Based on APT traffic analysis and exfiltration patterns
            'high_data_egress_mb': self.config.get('high_data_egress_mb', 5),  # Lowered based on APT research
            'sensitive_data_egress_mb': self.config.get('sensitive_data_egress_mb', 1),  # Stricter for sensitive systems
              # Network connections: Based on C2 communication patterns research
            'persistent_connection_seconds': self.config.get('persistent_connection_seconds', 300),  # Increased to 5 minutes for better precision
            'off_hours_connection_seconds': self.config.get('off_hours_connection_seconds', 120),  # 2 minutes outside business hours
            
            # CPU usage: Based on cryptominer and malware resource consumption studies
            'high_cpu_percent': self.config.get('high_cpu_percent', 60),  # Lowered from 70% based on research
            'sustained_cpu_duration_minutes': self.config.get('sustained_cpu_duration_minutes', 3),  # 3-5 min requirement
            'sustained_cpu_samples': self.config.get('sustained_cpu_samples', 30),  # Increased for 3-min duration
            
            # Beaconing: Based on APT group communication patterns (APT29, Cobalt Strike research)
            'beaconing_min_intervals': self.config.get('beaconing_min_intervals', 5),  # Minimum intervals
            'beaconing_variance_threshold': self.config.get('beaconing_variance_threshold', 0.15),  # Tightened to 15%
            'beaconing_min_interval_seconds': self.config.get('beaconing_min_interval_seconds', 5),  # 5s minimum
            'beaconing_max_interval_seconds': self.config.get('beaconing_max_interval_seconds', 600),  # 10min maximum
            'slow_beacon_max_interval_seconds': self.config.get('slow_beacon_max_interval_seconds', 3600),  # 1hr for "low and slow"
              # Process-specific allowances for legitimate software
            'legitimate_processes': self.config.get('legitimate_processes', [
                # Security and system tools
                'windows defender', 'defender', 'antimalware', 'msmpeng.exe', 'windefend',
                'sysmon', 'perfmon', 'procmon', 'system monitor',
                
                # Backup software
                'backup', 'veeam', 'acronis', 'carbonite', 'bacula',
                
                # Browsers (will have separate contextual handling)
                'chrome.exe', 'firefox.exe', 'edge.exe', 'opera.exe', 'brave.exe', 'arc.exe',
                
                # Database servers
                'mysqld.exe', 'postgres.exe', 'sqlservr.exe', 'mongodb.exe', 'redis-server.exe',
                'oracle.exe', 'cassandra.exe', 'elasticsearch.exe',                # Development and sync tools
                'node.exe', 'python.exe', 'java.exe', 'code.exe', 'devenv.exe',
                'onedrive.exe', 'dropbox.exe', 'googledrivesync.exe',
                
                # Gaming and hardware services
                'armorycrate.service.exe', 'roglivservice.exe', 'lightingservice.exe',
                'armorysocketserver.exe', 'armorycrate.usersessionhelper.exe',
                'aacambientlighting.exe', 'asus_framework.exe',
                
                # Log collection and forwarding services
                'wazuh-agent.exe', 'wazuh-authd.exe', 'wazuh-execd.exe', 'wazuh-logcollector.exe',
                'logstash.exe', 'elasticsearch.exe', 'kibana.exe', 'beats.exe',
                'filebeat.exe', 'winlogbeat.exe', 'metricbeat.exe', 'packetbeat.exe',
                'splunk.exe', 'splunkd.exe', 'universalforwarder.exe',
                'fluentd.exe', 'fluent-bit.exe', 'nxlog.exe', 'rsyslog.exe',
                  # Windows services and system processes
                'svchost.exe', 'services.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe',
                'spoolsv.exe', 'taskhost.exe', 'dwm.exe', 'explorer.exe', 'conhost.exe',
                'audiodg.exe', 'wininit.exe', 'smss.exe', 'wuauclt.exe', 'msiexec.exe',
                'wudfhost.exe', 'nvdisplay.container.exe', 'ipfsvc.exe',
                'mpdefendercoreservice.exe', 'phoneexperiencehost.exe', 'crossdeviceservice.exe'
            ]),
            
            # Log collection and security service patterns
            'log_collection_services': self.config.get('log_collection_services', [
                'wazuh', 'elastic', 'logstash', 'kibana', 'beats', 'filebeat', 'winlogbeat',
                'splunk', 'fluentd', 'fluent-bit', 'nxlog', 'rsyslog', 'syslog-ng',
                'graylog', 'datadog', 'new relic', 'sumo logic', 'azure monitor'
            ]),
            
            # Command & Control signatures (process and network patterns)
            'c2_signatures': self.config.get('c2_signatures', [
                'cobalt strike', 'metasploit', 'empire', 'covenant', 'sliver',
                'powershell empire', 'mythic', 'merlin', 'koadic', 'pupy'
            ]),
            
            # Suspicious Windows service patterns
            'suspicious_service_patterns': self.config.get('suspicious_service_patterns', [
                'temp', 'update', 'service', 'host', 'manager', 'system32',
                'windows', 'microsoft', 'adobe', 'java', 'chrome', 'firefox'
            ])
        }        # Scoring weights - Research-based rebalancing with weighted indicators (Bayesian approach)
        self.scoring_weights = {
            'high_privilege': 1.5,    # Reduced - many legitimate services run as SYSTEM
            'persistent_connection': 2.5,  # Moderate - context-dependent
            'high_disk_reads': 2,     # Moderate - antivirus and backup tools read a lot
            'high_data_egress': 4,    # Higher - unusual data egress is very suspicious
            'sustained_cpu': 1,       # Low - many legitimate processes use CPU
            'beaconing_pattern': 6,   # Highest - regular beaconing is extremely suspicious (primary indicator)
            'slow_beaconing': 5,      # High - "low and slow" C2 patterns
            'multiple_connections': 1.5, # Lower - browsers and sync tools do this
            'system_scanning': 3,     # Moderate-high - port scanning is suspicious
            'off_hours_activity': 2,  # Higher weight for activity outside business hours
            'contextual_disk_activity': 1, # Lower weight for processes with disk-intensive allowances
            # New detection types
            'c2_signatures': 6,       # High - C2 signatures are very suspicious
            'suspicious_service_patterns': 4,  # Moderate-high - suspicious service patterns
            'log_forwarding_service': 0, # No score - informational only
        }
        
        # Data structures for profiling
        self.process_profiles = defaultdict(lambda: {
            'metadata': {},
            'cpu_samples': deque(maxlen=100),
            'memory_samples': deque(maxlen=100),
            'disk_io_samples': deque(maxlen=100),
            'network_connections': set(),
            'connection_history': defaultdict(list),
            'first_seen': None,
            'last_seen': None
        })
        
        self.detection_results = []
        self.profiling_active = False
        
        self.logger.info(f"Behavioral Anomaly Detector initialized for agent {agent_id}")
    
    # ========== PHASE 1: THE PROFILER (Data Collection Layer) ==========
    
    def start_profiling(self, duration: Optional[int] = None) -> None:
        """
        Start the behavioral profiling process.
        
        Args:
            duration: Override default profile duration in seconds
        """
        duration = duration or self.profile_duration
        self.logger.info(f"Starting behavioral profiling for {duration} seconds")
        
        self.profiling_active = True
        self.process_profiles.clear()
        
        # Start profiling in a separate thread
        profiling_thread = threading.Thread(
            target=self._profile_system_activity,
            args=(duration,),
            daemon=True
        )
        profiling_thread.start()
        return profiling_thread
    
    def _profile_system_activity(self, duration_seconds: int) -> None:
        """
        Core profiling loop that collects behavioral data from all processes.
        
        Args:
            duration_seconds: How long to collect data
        """
        end_time = time.time() + duration_seconds
        sample_count = 0
        
        while time.time() < end_time and self.profiling_active:
            try:
                current_time = datetime.now()
                
                # Get all current processes
                for process in psutil.process_iter(['pid', 'name', 'username', 'create_time']):
                    try:
                        pid = process.pid
                        process_info = process.info
                        
                        # Initialize process profile if first time seeing it
                        if self.process_profiles[pid]['first_seen'] is None:
                            self.process_profiles[pid]['first_seen'] = current_time
                            self.process_profiles[pid]['metadata'] = {
                                'name': process_info['name'],
                                'username': process_info.get('username', 'unknown'),
                                'create_time': process_info.get('create_time', 0),
                                'pid': pid
                            }
                        
                        self.process_profiles[pid]['last_seen'] = current_time
                        
                        # Collect resource metrics
                        self._collect_process_metrics(process, pid)
                        
                        # Collect network connections
                        self._collect_network_connections(process, pid)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        # Process might have disappeared or we don't have access
                        continue
                    except Exception as e:
                        self.logger.debug(f"Error profiling process {pid}: {e}")
                        continue
                
                sample_count += 1
                time.sleep(self.sampling_interval)
                
            except Exception as e:
                self.logger.error(f"Error in profiling loop: {e}")
                continue
        
        self.profiling_active = False
        self.logger.info(f"Profiling completed. Collected {sample_count} samples from {len(self.process_profiles)} processes")
    
    def _collect_process_metrics(self, process: psutil.Process, pid: int) -> None:
        """Collect CPU, memory, and disk I/O metrics for a process."""
        try:
            profile = self.process_profiles[pid]
            
            # CPU metrics
            cpu_percent = process.cpu_percent()
            profile['cpu_samples'].append(cpu_percent)
            
            # Memory metrics
            memory_info = process.memory_info()
            memory_percent = process.memory_percent()
            profile['memory_samples'].append({
                'rss': memory_info.rss,
                'vms': memory_info.vms,
                'percent': memory_percent
            })
            
            # Disk I/O metrics
            try:
                io_counters = process.io_counters()
                profile['disk_io_samples'].append({
                    'read_bytes': io_counters.read_bytes,
                    'write_bytes': io_counters.write_bytes,
                    'read_count': io_counters.read_count,
                    'write_count': io_counters.write_count,
                    'timestamp': time.time()
                })
            except (psutil.AccessDenied, AttributeError):
                # Some processes don't allow I/O access or platform doesn't support it
                pass
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    def _collect_network_connections(self, process: psutil.Process, pid: int) -> None:
        """Collect network connection information for a process."""
        try:
            connections = process.connections()
            profile = self.process_profiles[pid]
            
            for conn in connections:
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    connection_key = f"{conn.raddr.ip}:{conn.raddr.port}"
                    profile['network_connections'].add(connection_key)
                    
                    # Track connection history for beaconing detection
                    profile['connection_history'][connection_key].append({
                        'timestamp': time.time(),
                        'local_port': conn.laddr.port if conn.laddr else None,
                        'status': conn.status
                    })
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    def _collect_process_data(self) -> Dict[int, Dict[str, Any]]:
        """
        Collect current process data snapshot for testing.
        
        Returns:
            Dictionary mapping PID to process information
        """
        process_data = {}
        
        for process in psutil.process_iter(['pid', 'name', 'username', 'create_time', 'status']):
            try:
                pid = process.pid
                info = process.info
                
                # Get additional metrics
                try:
                    cpu_percent = process.cpu_percent()
                    memory_percent = process.memory_percent()
                    memory_info = process.memory_info()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cpu_percent = 0
                    memory_percent = 0
                    memory_info = None
                
                process_data[pid] = {
                    'name': info.get('name') or 'unknown',
                    'username': info.get('username') or 'unknown',
                    'create_time': info.get('create_time', 0),
                    'status': info.get('status') or 'unknown',
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory_percent,
                    'memory_info': memory_info
                }
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                self.logger.debug(f"Error collecting data for process {process.pid}: {e}")
                continue
        return process_data
    
    def profile_system_behavior(self, duration_seconds: int) -> Dict[int, List[Dict[str, Any]]]:
        """
        Profile system behavior for the specified duration and return collected samples.
        
        Args:
            duration_seconds: How long to collect data
            
        Returns:
            Dictionary mapping PID to list of behavioral samples
        """
        self.logger.info(f"Starting system behavior profiling for {duration_seconds} seconds")
        
        # Clear existing profiles
        self.process_profiles.clear()
        
        # Set profiling active and run profiling
        self.profiling_active = True
        self._profile_system_activity(duration_seconds)
        
        # Convert profiles to the format expected by tests
        result = {}
        for pid, profile in self.process_profiles.items():
            if profile['metadata']:  # Only include processes with data
                samples = []
                
                # Convert collected data to sample format
                for i in range(len(profile['cpu_samples'])):
                    sample = {
                        'timestamp': time.time(),
                        'cpu_percent': profile['cpu_samples'][i] if i < len(profile['cpu_samples']) else 0,
                        'memory_percent': 0,  # Default
                        'name': profile['metadata'].get('name', 'unknown'),
                        'username': profile['metadata'].get('username', 'unknown'),
                        'status': 'running'
                    }
                    
                    # Add memory data if available
                    if i < len(profile['memory_samples']):
                        memory_sample = profile['memory_samples'][i]
                        if isinstance(memory_sample, dict):
                            sample['memory_percent'] = memory_sample.get('percent', 0)
                    
                    samples.append(sample)
                
                if samples:  # Only add if we have samples
                    result[pid] = samples
        
        self.logger.info(f"Profiling completed. Collected data for {len(result)} processes")
        return result

    # ========== PHASE 2: THE ANALYZER (Heuristics and Rules) ==========
    def analyze_behavioral_patterns(self, profile_data: Optional[Dict[int, List[Dict[str, Any]]]] = None) -> Dict[int, Dict[str, Any]]:
        """
        Analyze collected behavioral data against heuristics to identify suspicious patterns.
        
        Args:
            profile_data: Optional profile data for testing. If None, uses internal process_profiles.
        
        Returns:
            Dictionary mapping PID to analysis results
        """
        # Use provided profile data for testing, or internal profiles for normal operation
        if profile_data is not None:
            # Convert test profile data to internal format
            self.process_profiles.clear()
            for pid, samples in profile_data.items():
                if samples:  # Only process if we have samples
                    first_sample = samples[0]
                    profile = self.process_profiles[pid]
                    profile['metadata'] = {
                        'name': first_sample.get('name', 'unknown'),
                        'username': first_sample.get('username', 'unknown'),
                        'create_time': first_sample.get('create_time', 0),
                        'pid': pid
                    }
                    # Add sample data
                    for sample in samples:
                        profile['cpu_samples'].append(sample.get('cpu_percent', 0))
                        profile['memory_samples'].append({
                            'percent': sample.get('memory_percent', 0)
                        })
        
        self.logger.info(f"Analyzing behavioral patterns for {len(self.process_profiles)} processes")
        analysis_results = {}
        
        for pid, profile in self.process_profiles.items():
            if not profile['metadata']:  # Skip empty profiles
                continue
                
            analysis = {
                'pid': pid,
                'metadata': profile['metadata'],
                'suspicious_behaviors': [],
                'behavioral_score': 0,
                'analysis_timestamp': datetime.now().isoformat()
            }
              # Apply all behavioral heuristics
            self._analyze_privilege_escalation(profile, analysis)
            self._analyze_persistent_connections(profile, analysis)
            self._analyze_disk_activity(profile, analysis)
            self._analyze_network_patterns(profile, analysis)
            self._analyze_cpu_patterns(profile, analysis)            
            self._analyze_beaconing_behavior(profile, analysis)
            
            # Apply new detection methods
            self._apply_log_forwarding_detection(profile, analysis)
            self._apply_c2_signature_detection(profile, analysis)
            self._apply_suspicious_service_detection(profile, analysis)
            
            analysis_results[pid] = analysis
        
        return analysis_results
    
    def _analyze_privilege_escalation(self, profile: Dict, analysis: Dict) -> None:
        """Detect processes running with high privileges."""
        username = profile['metadata'].get('username') or ''
        username = username.upper() if username else ''
        
        for priv_user in self.high_privilege_users or []:
            if priv_user and priv_user.upper() in username:
                analysis['suspicious_behaviors'].append({
                    'type': 'high_privilege',                    'description': f"Runs with high privileges ({username})",
                    'severity': 'high',
                    'score': self.scoring_weights['high_privilege']                })
                break
    
    def _analyze_persistent_connections(self, profile: Dict, analysis: Dict) -> None:
        """Detect processes maintaining persistent outbound connections with enhanced contextual awareness."""
        connections = profile['network_connections']
        connection_history = profile['connection_history']
        process_name = profile['metadata'].get('name', '').lower()
        
        if not connections:
            return
        
        # Check if this is a legitimate service (much more comprehensive now)
        is_legitimate_service = any(service in process_name for service in self.legitimate_services)
        is_log_service = any(service in process_name for service in self.log_collection_services)
        
        # If it's a well-known legitimate service, apply very minimal scoring
        if is_legitimate_service or is_log_service:
            suspicious_connections = []
            
            for connection in connections:
                if connection in connection_history:
                    timestamps = [entry['timestamp'] for entry in connection_history[connection]]
                    if timestamps:
                        connection_duration = max(timestamps) - min(timestamps)
                        if connection_duration >= self.thresholds['persistent_connection_seconds']:
                            
                            # Parse connection to check if it's local
                            is_local_connection = self._is_local_connection(connection)
                            
                            # For legitimate services, completely skip local connections
                            if is_local_connection:
                                continue  # Don't flag local connections for legitimate services at all
                              # For remote connections from legitimate services, only flag very suspicious ones
                            remote_parts = connection.split(':')
                            if len(remote_parts) >= 2:
                                try:
                                    remote_port = int(remote_parts[1]) if remote_parts[1].strip().isdigit() and remote_parts[1].strip() else 0
                                except (ValueError, IndexError):
                                    remote_port = 0
                                
                                # Only flag very suspicious ports/patterns for legitimate services
                                very_suspicious_ports = [4444, 6666, 1337, 31337, 8888, 9999]
                                suspicious_domains = ['darkweb', 'tor', 'onion', 'malware', 'c2']
                                
                                # Check if this is a clearly suspicious remote connection
                                is_very_suspicious = (
                                    remote_port in very_suspicious_ports or
                                    any(domain in connection.lower() for domain in suspicious_domains)
                                )
                                
                                if not is_very_suspicious:
                                    continue  # Don't flag normal remote connections for legitimate services
                            
                            # If we get here, it's a legitimate service with a very suspicious connection
                            suspicious_connections.append({
                                'type': 'persistent_connection',
                                'description': f"Legitimate service with potentially suspicious remote connection to {connection}",
                                'severity': 'low',  # Always low for legitimate services
                                'score': 0.5,  # Very low score
                                'details': {
                                    'remote_endpoint': connection,
                                    'duration_seconds': connection_duration,
                                    'connection_count': len(timestamps),
                                    'is_local': False,
                                    'is_legitimate_service': True,
                                    'process_context': 'Known legitimate service with unusual connection'
                                }
                            })
            
            analysis['suspicious_behaviors'].extend(suspicious_connections)
            return  # Exit early for legitimate services
        
        # For unknown/potentially suspicious processes, apply normal analysis
        suspicious_connections = []
        for connection in connections:
            if connection in connection_history:
                timestamps = [entry['timestamp'] for entry in connection_history[connection]]
                if timestamps:
                    connection_duration = max(timestamps) - min(timestamps)
                    if connection_duration >= self.thresholds['persistent_connection_seconds']:
                        
                        # Parse connection to check if it's local
                        is_local_connection = self._is_local_connection(connection)
                        
                        # For unknown processes, still be more lenient with local connections
                        if is_local_connection:
                            # Skip obvious development/database patterns even for unknown processes
                            if ('localhost' in connection or ':8080' in connection or ':3000' in connection or 
                                ':3306' in connection or ':5432' in connection or ':27017' in connection):
                                continue  # Skip common dev/database ports
                            
                            # Other local connections get reduced score
                            severity = 'low'
                            score = self.scoring_weights['persistent_connection'] * 0.2  # 80% reduction
                            description_suffix = ' (local connection - likely legitimate)'
                        else:
                            # Remote connections for unknown processes - moderate scoring
                            severity = 'medium'
                            score = self.scoring_weights['persistent_connection'] * 0.6  # 40% reduction
                            description_suffix = ' (unknown process - investigate)'
                        
                        suspicious_connections.append({
                            'type': 'persistent_connection',
                            'description': f"Maintains persistent {'local' if is_local_connection else 'remote'} connection to {connection}{description_suffix}",
                            'severity': severity,
                            'score': score,
                            'details': {
                                'remote_endpoint': connection,
                                'duration_seconds': connection_duration,
                                'connection_count': len(timestamps),
                                'is_local': is_local_connection,
                                'is_legitimate_service': False,
                                'process_context': 'Unknown process - requires investigation'
                            }                        })
        
        analysis['suspicious_behaviors'].extend(suspicious_connections)
        
        # Check for multiple connections (possible C2 infrastructure) with context
        if len(connections) > 3:
            # Be more lenient with browsers and known multi-connection processes
            browser_patterns = ['chrome', 'firefox', 'edge', 'opera', 'brave', 'arc']
            sync_patterns = ['onedrive', 'dropbox', 'googledrive', 'sync', 'backup']
            is_multi_connection_app = any(pattern in process_name for pattern in browser_patterns + sync_patterns)
            
            # Higher threshold for browsers and sync apps
            threshold = 10 if is_multi_connection_app else 5
            severity = 'low' if is_multi_connection_app else 'medium'
            
            if len(connections) > threshold:
                analysis['suspicious_behaviors'].append({
                    'type': 'multiple_connections',
                    'description': f"Maintains {len(connections)} simultaneous connections (threshold: {threshold})",
                    'severity': severity,
                    'score': self.scoring_weights['multiple_connections'] * (0.5 if is_multi_connection_app else 1.0),
                    'details': {
                        'connection_count': len(connections),
                        'threshold_used': threshold,
                        'process_context': 'Multi-connection app' if is_multi_connection_app else 'Unknown process'
                    }
                })
    
    def _analyze_disk_activity(self, profile: Dict, analysis: Dict) -> None:
        """Detect high disk I/O activity with contextual awareness for legitimate software."""
        io_samples = profile['disk_io_samples']
        
        if len(io_samples) < 2:
            return
        
        # Calculate total bytes read during profiling
        first_sample = io_samples[0]
        last_sample = io_samples[-1]
        
        if 'read_bytes' in first_sample and 'read_bytes' in last_sample:
            total_read_bytes = last_sample['read_bytes'] - first_sample['read_bytes']
            total_read_mb = total_read_bytes / (1024 * 1024)
            
            # Check if this is a known legitimate process with higher disk I/O allowance
            process_name = profile['metadata'].get('name', '').lower()
            is_legitimate_disk_intensive = any(
                legit_process.lower() in process_name 
                for legit_process in self.thresholds['legitimate_processes']
            )
            
            # Use contextual thresholds based on process type
            threshold = (self.thresholds['contextual_disk_reads_mb'] 
                        if is_legitimate_disk_intensive 
                        else self.thresholds['high_disk_reads_mb'])
            
            if total_read_mb >= threshold:
                # Reduce severity and score for legitimate disk-intensive processes
                severity = 'low' if is_legitimate_disk_intensive else 'medium'
                score_weight = ('contextual_disk_activity' 
                              if is_legitimate_disk_intensive 
                              else 'high_disk_reads')
                
                analysis['suspicious_behaviors'].append({
                    'type': 'high_disk_reads',
                    'description': f"High disk read activity ({total_read_mb:.1f} MB, threshold: {threshold} MB)",
                    'severity': severity,
                    'score': self.scoring_weights[score_weight],
                    'details': {
                        'total_read_mb': total_read_mb,
                        'threshold_used': threshold,
                        'is_legitimate_process': is_legitimate_disk_intensive,
                        'process_context': 'Known disk-intensive software' if is_legitimate_disk_intensive else 'Unknown process'
                    }
                })
    
    def _analyze_network_patterns(self, profile: Dict, analysis: Dict) -> None:
        """Analyze network patterns for data exfiltration or beaconing."""
        connection_history = profile['connection_history']
        
        for connection, history in connection_history.items():
            if len(history) < 2:
                continue
            
            # Estimate data volume (this is a simplified heuristic)
            # In a real implementation, you'd need to track actual bytes transferred
            estimated_data_mb = len(history) * 0.1  # Rough estimate based on connection frequency
            
            if estimated_data_mb >= self.thresholds['high_data_egress_mb']:
                analysis['suspicious_behaviors'].append({
                    'type': 'high_data_egress',
                    'description': f"High data egress to {connection} (~{estimated_data_mb:.1f} MB)",
                    'severity': 'medium',
                    'score': self.scoring_weights['high_data_egress'],
                    'details': {
                        'remote_endpoint': connection,
                        'estimated_data_mb': estimated_data_mb,
                        'connection_events': len(history)                    }
                })
    
    def _analyze_cpu_patterns(self, profile: Dict, analysis: Dict) -> None:
        """Detect sustained CPU usage patterns characteristic of monitoring tools."""
        cpu_samples = list(profile['cpu_samples'])
        
        if len(cpu_samples) < self.thresholds['sustained_cpu_samples']:
            return
        
        # Check for sustained low-level CPU usage (background monitoring)
        low_cpu_count = sum(1 for cpu in cpu_samples if 0.1 <= cpu <= 5.0)
        sustained_ratio = low_cpu_count / len(cpu_samples)
        
        if sustained_ratio >= 0.7:  # 70% of samples show sustained low CPU
            avg_cpu = sum(cpu_samples) / len(cpu_samples)
            analysis['suspicious_behaviors'].append({
                'type': 'sustained_cpu',
                'description': f"Sustained low-level CPU usage ({avg_cpu:.1f}% average)",
                'severity': 'low',
                'score': self.scoring_weights['sustained_cpu'],
                'details': {
                    'average_cpu_percent': avg_cpu,
                    'sustained_ratio': sustained_ratio,
                    'sample_count': len(cpu_samples)
                }
            })
    def _analyze_beaconing_behavior(self, profile: Dict, analysis: Dict) -> None:
        """
        Detect regular beaconing patterns with enhanced contextual awareness.
        Implements detection for both standard and "low and slow" C2 communication.
        """
        connection_history = profile['connection_history']
        process_name = profile['metadata'].get('name', '').lower()
        
        # Check if this is a legitimate service that might have regular communication patterns
        is_legitimate_service = any(service in process_name for service in self.legitimate_services)
        is_log_service = any(service in process_name for service in self.log_collection_services)
        
        for connection, history in connection_history.items():
            if len(history) < self.thresholds['beaconing_min_intervals']:
                continue
            
            timestamps = [entry['timestamp'] for entry in history]
            timestamps.sort()
            
            # Calculate intervals between connections
            intervals = []
            for i in range(1, len(timestamps)):
                intervals.append(timestamps[i] - timestamps[i-1])
            
            if len(intervals) < self.thresholds['beaconing_min_intervals']:
                continue
            
            # Calculate statistical measures for beaconing detection
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((interval - avg_interval) ** 2 for interval in intervals) / len(intervals)
            std_dev = variance ** 0.5
            variance_ratio = (std_dev / avg_interval) if avg_interval > 0 else 1
            
            # Check if this is a local connection (much less suspicious for beaconing)
            is_local_connection = self._is_local_connection(connection)
            
            # For legitimate services, be extremely lenient with beaconing detection
            if is_legitimate_service or is_log_service:
                # Skip ALL local beaconing for legitimate services (this is normal behavior)
                if is_local_connection:
                    continue
                
                # For remote connections from legitimate services, only flag EXTREMELY suspicious patterns
                # Require super tight beaconing (variance < 2%) AND suspicious characteristics
                super_tight_threshold = 0.02  # 2% variance - almost perfect timing
                
                # Check for additional suspicious indicators
                suspicious_characteristics = 0
                
                # Very suspicious ports
                if ':4444' in connection or ':6666' in connection or ':1337' in connection:
                    suspicious_characteristics += 2
                
                # Very suspicious domains/IPs (you'd expand this with threat intel)
                suspicious_domains = ['tor', 'onion', 'darkweb', 'temp', 'suspicious']
                if any(domain in connection.lower() for domain in suspicious_domains):
                    suspicious_characteristics += 2
                
                # Very short intervals (< 10 seconds) are more suspicious
                if avg_interval < 10:
                    suspicious_characteristics += 1
                
                # Only flag if BOTH conditions are met: super tight timing AND suspicious characteristics
                if variance_ratio < super_tight_threshold and suspicious_characteristics >= 2:
                    total_duration_minutes = (max(timestamps) - min(timestamps)) / 60
                    
                    analysis['suspicious_behaviors'].append({
                        'type': 'beaconing_pattern',
                        'description': f"Legitimate service with highly suspicious beaconing to {connection} (every {avg_interval:.1f}s, variance: {variance_ratio:.3f})",
                        'severity': 'medium',  # Still only medium for legitimate services
                        'score': self.scoring_weights['beaconing_pattern'] * 0.4,  # 60% reduction
                        'details': {
                            'remote_endpoint': connection,
                            'average_interval_seconds': round(avg_interval, 1),
                            'standard_deviation': round(std_dev, 2),
                            'variance_ratio': round(variance_ratio, 3),
                            'beacon_count': len(timestamps),
                            'total_duration_minutes': round(total_duration_minutes, 1),
                            'detection_confidence': 'medium',
                            'pattern_type': 'legitimate_service_suspicious_beaconing',
                            'is_legitimate_service': True,
                            'suspicious_characteristics': suspicious_characteristics
                        }
                    })
                continue  # Skip normal analysis for legitimate services
            
            # For unknown processes, apply normal beaconing detection but still be smarter about local connections
            # Local connections get much more lenient treatment
            if is_local_connection:
                # Skip obviously legitimate local patterns
                local_skip_patterns = [
                    ':3000', ':8080', ':3306', ':5432', ':27017',  # Dev/DB ports
                    ':9200', ':5044', ':9300',  # Elasticsearch/Logstash
                    ':6379', ':11211', ':5672'   # Redis, Memcached, RabbitMQ
                ]
                
                if any(pattern in connection for pattern in local_skip_patterns):
                    continue
                
                # For other local connections, require tighter variance and give reduced score
                local_variance_threshold = self.thresholds['beaconing_variance_threshold'] * 0.5  # Half the normal threshold
                
                # Standard beaconing detection for local unknown processes
                if (self.thresholds['beaconing_min_interval_seconds'] <= avg_interval <= 
                    self.thresholds['beaconing_max_interval_seconds']):
                    
                    if variance_ratio < local_variance_threshold:
                        total_duration_minutes = (max(timestamps) - min(timestamps)) / 60
                        
                        analysis['suspicious_behaviors'].append({
                            'type': 'beaconing_pattern',
                            'description': f"Local beaconing pattern to {connection} (every {avg_interval:.1f}s, {len(intervals)} intervals)",
                            'severity': 'low',  # Local is less severe
                            'score': self.scoring_weights['beaconing_pattern'] * 0.5,  # 50% reduction for local
                            'details': {
                                'remote_endpoint': connection,
                                'average_interval_seconds': round(avg_interval, 1),
                                'standard_deviation': round(std_dev, 2),
                                'variance_ratio': round(variance_ratio, 3),
                                'beacon_count': len(timestamps),
                                'total_duration_minutes': round(total_duration_minutes, 1),
                                'detection_confidence': 'medium',
                                'pattern_type': 'local_beaconing',
                                'is_local': True
                            }
                        })
            else:
                # Remote connections from unknown processes - full analysis
                # Standard beaconing detection (5s - 10min intervals)
                if (self.thresholds['beaconing_min_interval_seconds'] <= avg_interval <= 
                    self.thresholds['beaconing_max_interval_seconds']):
                    
                    if variance_ratio < self.thresholds['beaconing_variance_threshold']:
                        total_duration_minutes = (max(timestamps) - min(timestamps)) / 60
                        
                        analysis['suspicious_behaviors'].append({
                            'type': 'beaconing_pattern',
                            'description': f"Regular C2 beaconing to {connection} (every {avg_interval:.1f}s, {len(intervals)} intervals)",
                            'severity': 'critical',
                            'score': self.scoring_weights['beaconing_pattern'],
                            'details': {
                                'remote_endpoint': connection,
                                'average_interval_seconds': round(avg_interval, 1),
                                'standard_deviation': round(std_dev, 2),
                                'variance_ratio': round(variance_ratio, 3),
                                'beacon_count': len(timestamps),
                                'total_duration_minutes': round(total_duration_minutes, 1),
                                'detection_confidence': 'high',
                                'pattern_type': 'standard_beaconing'
                            }
                        })
                
                # "Low and slow" beaconing detection (10min - 1hr intervals)
                elif (self.thresholds['beaconing_max_interval_seconds'] < avg_interval <= 
                      self.thresholds['slow_beacon_max_interval_seconds']):
                    
                    # Slightly more lenient variance threshold for slow beaconing
                    if variance_ratio < (self.thresholds['beaconing_variance_threshold'] + 0.05):
                        total_duration_hours = (max(timestamps) - min(timestamps)) / 3600
                        
                        analysis['suspicious_behaviors'].append({
                            'type': 'slow_beaconing',
                            'description': f"Low-and-slow C2 beaconing to {connection} (every {avg_interval/60:.1f}min, {len(intervals)} intervals)",
                            'severity': 'high',
                            'score': self.scoring_weights['slow_beaconing'],
                            'details': {
                                'remote_endpoint': connection,
                                'average_interval_minutes': round(avg_interval/60, 1),
                                'standard_deviation': round(std_dev, 2),
                                'variance_ratio': round(variance_ratio, 3),
                                'beacon_count': len(timestamps),
                                'total_duration_hours': round(total_duration_hours, 1),
                                'detection_confidence': 'medium-high',
                                'pattern_type': 'slow_beaconing'
                            }
                        })
                    
                    # Adjust severity based on connection type
                    if is_local_connection:
                        severity = 'medium'  # Local beaconing is less critical
                        score_multiplier = 0.6  # 40% reduction for local
                        description_prefix = "Local regular communication"
                    else:
                        severity = 'critical'  # Remote beaconing is very suspicious
                        score_multiplier = 1.0  # Full score for remote
                        description_prefix = "Regular C2 beaconing"
                    
                    analysis['suspicious_behaviors'].append({
                        'type': 'beaconing_pattern',
                        'description': f"{description_prefix} to {connection} (every {avg_interval:.1f}s, {len(intervals)} intervals)",
                        'severity': severity,
                        'score': self.scoring_weights['beaconing_pattern'] * score_multiplier,
                        'details': {
                            'remote_endpoint': connection,
                            'average_interval_seconds': round(avg_interval, 1),
                            'standard_deviation': round(std_dev, 2),
                            'variance_ratio': round(variance_ratio, 3),
                            'beacon_count': len(timestamps),
                            'total_duration_minutes': round(total_duration_minutes, 1),
                            'detection_confidence': 'high' if not is_local_connection else 'medium',
                            'pattern_type': 'potential_c2_beaconing',
                            'is_local': is_local_connection
                        }                        })
                
                # "Low and slow" beaconing detection (10min - 1hr intervals)
                elif (self.thresholds['beaconing_max_interval_seconds'] < avg_interval <= 
                      self.thresholds['slow_beacon_max_interval_seconds']):
                    
                    # Slightly more lenient variance threshold for slow beaconing
                    if variance_ratio < (self.thresholds['beaconing_variance_threshold'] + 0.05):
                        total_duration_hours = (max(timestamps) - min(timestamps)) / 3600
                        
                        analysis['suspicious_behaviors'].append({
                            'type': 'slow_beaconing',
                            'description': f"Low-and-slow C2 beaconing to {connection} (every {avg_interval/60:.1f}min, {len(intervals)} intervals)",
                            'severity': 'high',
                            'score': self.scoring_weights['slow_beaconing'],
                            'details': {
                                'remote_endpoint': connection,
                                'average_interval_minutes': round(avg_interval/60, 1),
                                'standard_deviation': round(std_dev, 2),
                                'variance_ratio': round(variance_ratio, 3),
                                'beacon_count': len(timestamps),
                                'total_duration_hours': round(total_duration_hours, 1),
                                'detection_confidence': 'medium-high',
                                'pattern_type': 'slow_beaconing'
                            }
                        })
                        severity = 'high'  # Remote slow beaconing is suspicious
                        score_multiplier = 0.8  # 20% reduction (less certain than fast beaconing)
                        description_prefix = "Low-and-slow C2 beaconing"
                    
                    analysis['suspicious_behaviors'].append({
                        'type': 'slow_beaconing',
                        'description': f"{description_prefix} to {connection} (every {avg_interval/60:.1f}min, {len(intervals)} intervals)",
                        'severity': severity,
                        'score': self.scoring_weights['slow_beaconing'] * score_multiplier,
                        'details': {
                            'remote_endpoint': connection,
                            'average_interval_minutes': round(avg_interval/60, 1),
                            'standard_deviation': round(std_dev, 2),
                            'variance_ratio': round(variance_ratio, 3),
                            'beacon_count': len(timestamps),
                            'total_duration_hours': round(total_duration_hours, 1),
                            'detection_confidence': 'medium-high' if not is_local_connection else 'low',
                            'pattern_type': 'potential_slow_c2_beaconing',
                            'is_local': is_local_connection
                        }
                    })
    
    def _apply_log_forwarding_detection(self, profile: Dict, analysis: Dict) -> None:
        """Apply log forwarding behavior detection and adjust scoring."""
        process_name = profile['metadata'].get('name', '')
        connections = list(profile['network_connections'])
          # Get log forwarding behavior analysis
        log_behavior = self._detect_log_forwarding_behavior(process_name, [
            {'remote_address': conn.split(':')[0], 'remote_port': self._safe_parse_port(conn.split(':')[1]) if ':' in conn and len(conn.split(':')) > 1 else 0}
            for conn in connections if ':' in conn
        ])
        
        if log_behavior['likely_log_forwarding']:
            # This is likely a legitimate log forwarding service
            # Reduce scoring for persistent connections if they exist
            for behavior in analysis['suspicious_behaviors']:
                if behavior['type'] == 'persistent_connection':
                    if behavior['details'].get('is_local', False):
                        # Reduce local connection scores for log services by 75%
                        behavior['score'] *= 0.25
                        behavior['severity'] = 'minimal'
                        behavior['description'] += ' (Log collection service - low risk)'
                    else:
                        # Reduce remote connection scores for log services by 50%
                        behavior['score'] *= 0.5
                        behavior['severity'] = 'low' if behavior['severity'] == 'high' else 'minimal'
                        behavior['description'] += ' (Log forwarding service - reduced risk)'
            
            # Add informational entry about log forwarding detection
            analysis['suspicious_behaviors'].append({
                'type': 'log_forwarding_service',
                'description': f"Detected as log collection/forwarding service ({log_behavior['forwarding_indicators']} indicators)",
                'severity': 'info',
                'score': 0,  # No score - this is informational
                'details': {
                    'is_known_log_service': log_behavior['is_log_service'],
                    'forwarding_indicators': log_behavior['forwarding_indicators'],
                    'detection_type': 'log_forwarding'
                }
            })
    
    def _apply_c2_signature_detection(self, profile: Dict, analysis: Dict) -> None:
        """Apply C2 signature detection and scoring."""
        process_name = profile['metadata'].get('name', '')
        connections = list(profile['network_connections'])
        connection_history = profile['connection_history']
        
        # Convert connections to format expected by C2 detector
        connection_data = []        
        for conn in connections:
            parts = conn.split(':')
            if len(parts) >= 2:
                connection_data.append({
                    'remote_address': parts[0],
                    'remote_port': self._safe_parse_port(parts[1])
                })
        
        # Convert connection history to network data
        network_data = []
        for conn, history in connection_history.items():
            for entry in history:
                network_data.append({
                    'timestamp': entry['timestamp'],
                    'connection': conn
                })
        
        # Get C2 analysis
        c2_analysis = self._detect_c2_signatures(process_name, connection_data, network_data)
        
        if c2_analysis['c2_score'] > 0:
            # Determine severity based on C2 score
            if c2_analysis['c2_score'] >= 8:
                severity = 'critical'
            elif c2_analysis['c2_score'] >= 5:
                severity = 'high'
            elif c2_analysis['c2_score'] >= 3:
                severity = 'medium'
            else:
                severity = 'low'
            
            analysis['suspicious_behaviors'].append({
                'type': 'c2_signatures',
                'description': f"C2 signatures detected (score: {c2_analysis['c2_score']}/10)",
                'severity': severity,
                'score': c2_analysis['c2_score'],
                'details': {
                    'c2_score': c2_analysis['c2_score'],
                    'indicators': c2_analysis['indicators'],
                    'detection_type': 'c2_signatures'
                }
            })
    
    def _apply_suspicious_service_detection(self, profile: Dict, analysis: Dict) -> None:
        """Apply suspicious Windows service pattern detection."""
        process_name = profile['metadata'].get('name', '')
        process_info = profile['metadata']
        
        # Get suspicious service analysis
        service_analysis = self._detect_suspicious_service_patterns(process_name, process_info)
        
        if service_analysis['suspicious_score'] > 0:
            # Determine severity based on suspicious score
            if service_analysis['suspicious_score'] >= 8:
                severity = 'critical'
            elif service_analysis['suspicious_score'] >= 5:
                severity = 'high'
            elif service_analysis['suspicious_score'] >= 3:
                severity = 'medium'
            else:
                severity = 'low'
            
            analysis['suspicious_behaviors'].append({
                'type': 'suspicious_service_patterns',
                'description': f"Suspicious service patterns detected (score: {service_analysis['suspicious_score']}/10)",
                'severity': severity,
                'score': service_analysis['suspicious_score'],
                'details': {
                    'suspicious_score': service_analysis['suspicious_score'],
                    'indicators': service_analysis['indicators'],
                    'detection_type': 'suspicious_service'
                }
            })
    
    # ========== PHASE 3: THE SCORER (Risk Quantification) ==========
    
    def calculate_suspicion_scores(self, analysis_results: Dict[int, Dict]) -> Dict[int, Dict]:
        """
        Calculate final suspicion scores for all analyzed processes.
        Standardizes scores to 0-10 scale for consistent risk assessment.
        
        Args:
            analysis_results: Results from behavioral analysis
            
        Returns:
            Updated analysis results with calculated scores
        """
        for pid, analysis in analysis_results.items():
            # Calculate raw score from behavior weights
            raw_score = sum(behavior['score'] for behavior in analysis['suspicious_behaviors'])
            
            # Normalize to 0-10 scale based on realistic maximum scores
            # Maximum realistic score would be around 20 (multiple high-risk behaviors)
            max_possible_score = 20
            normalized_score = min(10.0, (raw_score / max_possible_score) * 10.0)
            
            # Round to 1 decimal place for consistency
            analysis['behavioral_score'] = round(normalized_score, 1)
            analysis['raw_behavioral_score'] = raw_score  # Keep original for debugging
              # Determine risk level based on 0-10 normalized score
            # Research-based thresholds for better discrimination
            if normalized_score >= 9.0:
                analysis['risk_level'] = 'critical'     # 9-10 = Critical
            elif normalized_score >= 7.0:
                analysis['risk_level'] = 'high'        # 7-8.9 = High  
            elif normalized_score >= 4.0:
                analysis['risk_level'] = 'medium'      # 4-6.9 = Medium
            elif normalized_score >= 1.0:
                analysis['risk_level'] = 'low'         # 1-3.9 = Low
            else:
                analysis['risk_level'] = 'minimal'     # 0-0.9 = Minimal
        
        return analysis_results
    
    # ========== PHASE 4: THE REPORTER (Actionable Output) ==========
    
    def generate_detection_report(self, analysis_results: Dict[int, Dict]) -> Dict[str, Any]:
        """
        Generate a comprehensive, structured detection report.
        
        Args:
            analysis_results: Results from behavioral analysis and scoring
            
        Returns:
            Structured JSON report with all findings
        """
        # Filter for suspicious processes
        suspicious_processes = []
        for pid, analysis in analysis_results.items():
            if analysis['behavioral_score'] >= self.suspicion_threshold:
                suspicious_processes.append(self._format_process_report(analysis))
        
        # Generate summary statistics
        total_processes = len(analysis_results)
        critical_count = sum(1 for a in analysis_results.values() if a.get('risk_level') == 'critical')
        high_count = sum(1 for a in analysis_results.values() if a.get('risk_level') == 'high')
        medium_count = sum(1 for a in analysis_results.values() if a.get('risk_level') == 'medium')
        
        report = {
            "detection_metadata": {
                "agent_id": self.agent_id,
                "detection_timestamp": datetime.now().isoformat(),
                "analysis_duration_seconds": self.profile_duration,
                "sampling_interval_seconds": self.sampling_interval,
                "suspicion_threshold": self.suspicion_threshold
            },
            "summary": {
                "total_processes_analyzed": total_processes,
                "suspicious_processes_found": len(suspicious_processes),
                "risk_distribution": {
                    "critical": critical_count,
                    "high": high_count,
                    "medium": medium_count,
                    "low": total_processes - critical_count - high_count - medium_count
                }
            },
            "suspicious_processes": suspicious_processes,
            "detection_rules_applied": list(self.scoring_weights.keys()),
            "thresholds_used": self.thresholds
        }
        
        return report
    
    def _format_process_report(self, analysis: Dict) -> Dict[str, Any]:
        """Format individual process analysis for the report."""
        metadata = analysis['metadata']
        
        return {
            "pid": analysis['pid'],
            "process_name": metadata.get('name', 'unknown'),
            "username": metadata.get('username', 'unknown'),
            "create_time": metadata.get('create_time', 0),
            "suspicion_score": analysis['behavioral_score'],
            "risk_level": analysis.get('risk_level', 'unknown'),
            "suspicious_behaviors": [
                {
                    "type": behavior['type'],
                    "description": behavior['description'],
                    "severity": behavior['severity'],
                    "score_contribution": behavior['score'],
                    "details": behavior.get('details', {})
                }
                for behavior in analysis['suspicious_behaviors']
            ],
            "analysis_timestamp": analysis['analysis_timestamp']
        }
    
    # ========== PUBLIC API METHODS ==========
    
    def run_full_detection(self, duration: Optional[int] = None) -> Dict[str, Any]:
        """
        Run a complete behavioral anomaly detection cycle.
        
        Args:
            duration: Override default profiling duration
            
        Returns:
            Complete detection report
        """
        self.logger.info("Starting full behavioral anomaly detection cycle")
        
        try:
            # Phase 1: Profile system activity
            profiling_thread = self.start_profiling(duration)
            profiling_thread.join()  # Wait for profiling to complete
            
            # Phase 2: Analyze behavioral patterns
            analysis_results = self.analyze_behavioral_patterns()
            
            # Phase 3: Calculate suspicion scores
            scored_results = self.calculate_suspicion_scores(analysis_results)
            
            # Phase 4: Generate final report
            report = self.generate_detection_report(scored_results)
            
            # Store results
            self.detection_results.append(report)
            
            self.logger.info(f"Detection completed. Found {len(report['suspicious_processes'])} suspicious processes")
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error during behavioral detection: {e}")
            return {
                "error": str(e),
                "detection_timestamp": datetime.now().isoformat(),
                "agent_id": self.agent_id
            }
    
    def get_detection_history(self) -> List[Dict[str, Any]]:
        """Get historical detection results."""
        return self.detection_results
    
    def stop_profiling(self) -> None:
        """Stop ongoing profiling process."""
        self.profiling_active = False
        self.logger.info("Behavioral profiling stopped")
    
    def update_configuration(self, new_config: Dict[str, Any]) -> None:
        """Update detector configuration."""
        self.config.update(new_config)
        
        # Update derived settings
        self.profile_duration = self.config.get('profile_duration', self.profile_duration)
        self.sampling_interval = self.config.get('sampling_interval', self.sampling_interval)
        self.suspicion_threshold = self.config.get('suspicion_threshold', self.suspicion_threshold)
        
        self.logger.info("Behavioral anomaly detector configuration updated")
    
    def _is_outside_business_hours(self) -> bool:
        """
        Check if current time is outside typical business hours.
        Business hours: Monday-Friday, 8 AM - 6 PM local time.
        """
        now = datetime.now()
        # Weekend check
        if now.weekday() >= 5:  # Saturday = 5, Sunday = 6
            return True        # Time check (outside 8 AM - 6 PM)
        if now.hour < 8 or now.hour >= 18:
            return True
        return False
    
    def _is_local_connection(self, connection_str: str) -> bool:
        """Check if a connection string represents a local/localhost connection."""
        if not connection_str:
            return False
        
        local_indicators = [
            '127.0.0.1',     # IPv4 localhost
            '::1',           # IPv6 localhost  
            'localhost',     # Hostname localhost
            '0.0.0.0',       # All interfaces (often local services)
        ]
        
        return any(indicator in connection_str for indicator in local_indicators)

    def _detect_log_forwarding_behavior(self, process_name: str, connections: List[Dict]) -> Dict:
        """Detect if process is exhibiting log forwarding/collection behavior."""
        process_lower = process_name.lower()
        
        # Check if it's a known log collection service
        is_log_service = any(service in process_lower for service in self.log_collection_services)
        
        # Check for log forwarding patterns in connections
        log_forwarding_indicators = 0
        
        for conn in connections:
            # Common log forwarding ports
            if conn.get('remote_port') in [514, 601, 6514, 9200, 9300, 5044, 8089, 24224]:
                log_forwarding_indicators += 1
            
            # Check for log forwarding URLs/patterns
            remote_addr = conn.get('remote_address', '')
            if any(pattern in remote_addr.lower() for pattern in [
                'elastic', 'kibana', 'logstash', 'splunk', 'wazuh', 'siem'
            ]):
                log_forwarding_indicators += 1
        
        return {
            'is_log_service': is_log_service,
            'forwarding_indicators': log_forwarding_indicators,
            'likely_log_forwarding': is_log_service and log_forwarding_indicators > 0        }
    
    def _detect_c2_signatures(self, process_name: str, connections: List[Dict], network_data: List[Dict]) -> Dict:
        """Detect C2 (Command and Control) signatures in process behavior with improved accuracy."""
        c2_score = 0
        c2_indicators = []
        
        process_lower = process_name.lower()
        
        # Check if this is a known legitimate process that might trigger false positives
        legitimate_processes = ['chrome', 'firefox', 'edge', 'teams', 'skype', 'zoom', 'discord', 'slack']
        is_legitimate_networking = any(proc in process_lower for proc in legitimate_processes)
        
        # Check if this is a log service (log services should not trigger C2 detection)
        is_log_service = any(service in process_lower for service in self.log_collection_services)
        
        if is_log_service:
            # Log services get minimal C2 scoring
            return {
                'c2_score': 0,
                'indicators': ['Process identified as log collection service - C2 detection skipped']
            }
        
        # Check process name for C2 signatures (but be more careful with legitimate processes)
        for signature in self.c2_signatures:
            if signature.lower() in process_lower:
                if is_legitimate_networking:
                    c2_score += 0.5  # Reduced score for legitimate processes
                    c2_indicators.append(f"Weak C2 signature in legitimate process: {signature}")
                else:
                    c2_score += 2
                    c2_indicators.append(f"C2 signature in process name: {signature}")
        
        # Check network connections for C2 patterns
        suspicious_ports = 0
        total_connections = len(connections)
        
        for conn in connections:
            remote_addr = conn.get('remote_address', '').lower()
            remote_port = conn.get('remote_port', 0)
            
            # Common C2 ports (but be more selective)
            if remote_port in [4444, 8080, 443, 80, 53, 8443, 9999]:
                # Port 80, 443 are very common for legitimate traffic
                if remote_port in [80, 443] and is_legitimate_networking:
                    continue  # Skip common web ports for browsers
                elif remote_port in [4444, 9999]:  # These are more suspicious
                    suspicious_ports += 1
                    c2_score += 1.5
                    c2_indicators.append(f"Highly suspicious port: {remote_port}")
                else:
                    suspicious_ports += 1
                    c2_score += 0.5  # Lower score for common ports
                    c2_indicators.append(f"Potentially suspicious port: {remote_port}")
            
            # Check for C2 URL patterns in remote addresses
            for signature in self.c2_signatures:
                if signature.lower() in remote_addr:
                    c2_score += 2
                    c2_indicators.append(f"C2 signature in connection: {signature}")
        
        # Enhanced beaconing detection (more precise)
        if network_data and len(network_data) > 7:  # Need more samples for reliable detection
            intervals = []
            timestamps = sorted([entry.get('timestamp', 0) for entry in network_data])
            for i in range(1, len(timestamps)):
                intervals.append(timestamps[i] - timestamps[i-1])
            
            if intervals and len(intervals) >= 5:  # Need at least 5 intervals
                avg_interval = sum(intervals) / len(intervals)
                
                # Very regular intervals (beaconing) - but be more precise
                if 10 <= avg_interval <= 3600:  # 10 seconds to 1 hour
                    variance = sum(abs(interval - avg_interval) for interval in intervals) / len(intervals)
                    regularity_ratio = variance / avg_interval if avg_interval > 0 else 1
                    
                    # Very regular pattern (less than 5% variance)
                    if regularity_ratio < 0.05:
                        if is_legitimate_networking:
                            c2_score += 1  # Reduced for legitimate processes
                            c2_indicators.append(f"Regular pattern in legitimate process (avg: {avg_interval:.1f}s)")
                        else:
                            c2_score += 4  # High score for unknown processes
                            c2_indicators.append(f"Highly regular beaconing pattern (avg: {avg_interval:.1f}s, variance: {regularity_ratio:.3f})")
                    # Somewhat regular pattern (5-15% variance)
                    elif regularity_ratio < 0.15:
                        if not is_legitimate_networking:
                            c2_score += 2
                            c2_indicators.append(f"Moderately regular beaconing pattern (avg: {avg_interval:.1f}s)")
        
        return {
            'c2_score': min(c2_score, 10),  # Cap at 10
            'indicators': c2_indicators
        }
    
    def _detect_suspicious_service_patterns(self, process_name: str, process_info: Dict) -> Dict:
        """Detect suspicious Windows service patterns."""
        import re
        
        suspicious_score = 0
        suspicious_indicators = []
        
        process_lower = process_name.lower()
        
        # Check for suspicious service patterns
        for pattern in self.suspicious_service_patterns:
            if pattern.startswith('r\'') and pattern.endswith('\''):
                # Regex pattern
                regex_pattern = pattern[2:-1]
                if re.search(regex_pattern, process_lower):
                    suspicious_score += 2
                    suspicious_indicators.append(f"Suspicious pattern: {pattern}")
            else:
                # Simple string match
                if pattern.lower() in process_lower:
                    suspicious_score += 1
                    suspicious_indicators.append(f"Suspicious pattern: {pattern}")
        
        # Check for masquerading as system processes
        system_processes = ['svchost.exe', 'lsass.exe', 'winlogon.exe', 'csrss.exe', 'smss.exe']
        for sys_proc in system_processes:
            if sys_proc.lower() in process_lower and process_lower != sys_proc.lower():
                suspicious_score += 3
                suspicious_indicators.append(f"Masquerading as system process: {sys_proc}")
        
        # Check for unusual service locations
        if process_info and 'path' in process_info:
            path = process_info['path'].lower()
            suspicious_paths = ['temp', 'appdata', 'downloads', 'documents', 'desktop']
            for sus_path in suspicious_paths:
                if sus_path in path:
                    suspicious_score += 2
                    suspicious_indicators.append(f"Unusual service location: {sus_path}")
        
        return {
            'suspicious_score': min(suspicious_score, 10),  # Cap at 10
            'indicators': suspicious_indicators
        }


# Utility functions for integration with existing agent

def create_behavioral_detector(agent_id: str, config: Optional[Dict] = None) -> BehavioralAnomalyDetector:
    """Factory function to create a configured behavioral anomaly detector."""
    return BehavioralAnomalyDetector(agent_id, config)


def run_behavioral_scan(agent_id: str, duration: int = 120, config: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Convenience function to run a one-off behavioral scan.
    
    Args:
        agent_id: Unique agent identifier
        duration: Profiling duration in seconds
        config: Optional configuration override
        
    Returns:
        Detection report
    """
    detector = BehavioralAnomalyDetector(agent_id, config)
    return detector.run_full_detection(duration)
