# sbom.py - Software Bill of Materials Collection Module
import json
import platform
import subprocess
import logging
from datetime import datetime


class SBOMCollector:
    """Software Bill of Materials (SBOM) Collector"""
    
    def __init__(self, agent_id):
        self.agent_id = agent_id
        self.logger = logging.getLogger(__name__)
    
    def collect_full_sbom(self):
        """Collect comprehensive Software Bill of Materials"""
        try:
            self.logger.info("Collecting comprehensive SBOM...")
            
            sbom_data = {
                "agent_id": self.agent_id,
                "collection_timestamp": datetime.now().isoformat(),
                "platform": platform.system(),
                "software_sources": []
            }
            
            if platform.system() == "Windows":
                sbom_data["software_sources"] = self._collect_windows_software()
            elif platform.system() == "Linux":
                sbom_data["software_sources"] = self._collect_linux_software()
            elif platform.system() == "Darwin":
                sbom_data["software_sources"] = self._collect_macos_software()
            
            # Add Python packages (universal)
            python_packages = self._collect_python_packages()
            if python_packages:
                sbom_data["software_sources"].append({
                    "source_type": "python_packages",
                    "packages": python_packages,
                    "count": len(python_packages)
                })
            
            # Calculate summary
            total_packages = sum(len(source.get("packages", [])) for source in sbom_data["software_sources"])
            sbom_data["summary"] = {
                "total_packages": total_packages,
                "source_count": len(sbom_data["software_sources"]),
                "collection_time": datetime.now().isoformat()
            }
            
            return sbom_data
            
        except Exception as e:
            self.logger.error(f"Error collecting SBOM: {e}")
            return {
                "agent_id": self.agent_id,
                "error": str(e),
                "collection_timestamp": datetime.now().isoformat()
            }
    
    def _collect_windows_software(self):
        """Collect Windows-specific software"""
        sources = []
        
        # 1. Registry-based installed programs (32-bit)
        try:
            self.logger.info("Collecting 32-bit registry programs...")
            cmd = [
                'powershell', '-Command',
                'Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, EstimatedSize, InstallLocation | Where-Object {$_.DisplayName} | ConvertTo-Json'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                packages = data if isinstance(data, list) else [data]
                sources.append({
                    "source_type": "windows_registry_32bit",
                    "packages": packages,
                    "count": len(packages)
                })
        except Exception as e:
            self.logger.warning(f"Failed to get 32-bit registry software: {e}")
        
        # 2. Registry-based installed programs (64-bit)
        try:
            self.logger.info("Collecting 64-bit registry programs...")
            cmd = [
                'powershell', '-Command',
                'Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, EstimatedSize, InstallLocation | Where-Object {$_.DisplayName} | ConvertTo-Json'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                packages = data if isinstance(data, list) else [data]
                sources.append({
                    "source_type": "windows_registry_64bit",
                    "packages": packages,
                    "count": len(packages)
                })
        except Exception as e:
            self.logger.warning(f"Failed to get 64-bit registry software: {e}")
        
        # 3. Windows Store apps
        try:
            self.logger.info("Collecting Windows Store apps...")
            cmd = [
                'powershell', '-Command',
                'Get-AppxPackage | Select-Object Name, Version, Publisher, Architecture, InstallLocation | ConvertTo-Json'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                packages = data if isinstance(data, list) else [data]
                sources.append({
                    "source_type": "windows_store_apps",
                    "packages": packages,
                    "count": len(packages)
                })
        except Exception as e:
            self.logger.warning(f"Failed to get Windows Store apps: {e}")
        
        # 4. Windows Features
        try:
            self.logger.info("Collecting Windows features...")
            cmd = [
                'powershell', '-Command',
                'Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Enabled"} | Select-Object FeatureName, State, Description | ConvertTo-Json'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                packages = data if isinstance(data, list) else [data]
                sources.append({
                    "source_type": "windows_features",
                    "packages": packages,
                    "count": len(packages)
                })
        except Exception as e:
            self.logger.warning(f"Failed to get Windows features: {e}")
        
        # 5. Windows Services
        try:
            self.logger.info("Collecting Windows services...")
            cmd = [
                'powershell', '-Command',
                'Get-Service | Select-Object Name, DisplayName, Status, StartType, ServiceType | ConvertTo-Json'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                packages = data if isinstance(data, list) else [data]
                # Filter to only running services to reduce size
                running_services = [svc for svc in packages if svc.get('Status') == 'Running']
                sources.append({
                    "source_type": "windows_services",
                    "packages": running_services,
                    "count": len(running_services)
                })
        except Exception as e:
            self.logger.warning(f"Failed to get Windows services: {e}")
        
        return sources
    
    def _collect_linux_software(self):
        """Collect Linux-specific software"""
        sources = []
        
        # Try different package managers
        # 1. dpkg (Debian/Ubuntu)
        try:
            result = subprocess.run(
                ['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${Maintainer}\t${Section}\t${Architecture}\t${Description}\n'], 
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                packages = []
                for line in result.stdout.strip().split('\n'):
                    if line and '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            packages.append({
                                "name": parts[0],
                                "version": parts[1],
                                "maintainer": parts[2] if len(parts) > 2 else "Unknown",
                                "section": parts[3] if len(parts) > 3 else "Unknown",
                                "architecture": parts[4] if len(parts) > 4 else "Unknown",
                                "description": parts[5] if len(parts) > 5 else "Unknown"
                            })
                sources.append({
                    "source_type": "dpkg_packages",
                    "packages": packages,
                    "count": len(packages)
                })
        except FileNotFoundError:
            # 2. rpm (Red Hat/CentOS)
            try:
                result = subprocess.run(
                    ['rpm', '-qa', '--queryformat', '%{NAME}\t%{VERSION}\t%{VENDOR}\t%{GROUP}\t%{ARCH}\t%{SUMMARY}\n'], 
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode == 0:
                    packages = []
                    for line in result.stdout.strip().split('\n'):
                        if line and '\t' in line:
                            parts = line.split('\t')
                            if len(parts) >= 2:
                                packages.append({
                                    "name": parts[0],
                                    "version": parts[1],
                                    "vendor": parts[2] if len(parts) > 2 else "Unknown",
                                    "group": parts[3] if len(parts) > 3 else "Unknown",
                                    "architecture": parts[4] if len(parts) > 4 else "Unknown",
                                    "summary": parts[5] if len(parts) > 5 else "Unknown"
                                })
                    sources.append({
                        "source_type": "rpm_packages",
                        "packages": packages,
                        "count": len(packages)
                    })
            except FileNotFoundError:
                pass
        
        # 3. Snap packages
        try:
            result = subprocess.run(['snap', 'list'], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                packages = []
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        packages.append({
                            "name": parts[0],
                            "version": parts[1],
                            "revision": parts[2] if len(parts) > 2 else "Unknown",
                            "tracking": parts[3] if len(parts) > 3 else "Unknown",
                            "publisher": parts[4] if len(parts) > 4 else "Unknown"
                        })
                sources.append({
                    "source_type": "snap_packages",
                    "packages": packages,
                    "count": len(packages)
                })
        except FileNotFoundError:
            pass
        
        # 4. Flatpak packages
        try:
            result = subprocess.run(['flatpak', 'list', '--app'], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                packages = []
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            packages.append({
                                "name": parts[0],
                                "application_id": parts[1],
                                "version": parts[2] if len(parts) > 2 else "Unknown",
                                "branch": parts[3] if len(parts) > 3 else "Unknown",
                                "origin": parts[4] if len(parts) > 4 else "Unknown"
                            })
                sources.append({
                    "source_type": "flatpak_packages",
                    "packages": packages,
                    "count": len(packages)
                })
        except FileNotFoundError:
            pass
        
        return sources
    
    def _collect_macos_software(self):
        """Collect macOS-specific software"""
        sources = []
        
        # 1. Homebrew packages
        try:
            result = subprocess.run(['brew', 'list', '--formula'], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                packages = []
                for package in result.stdout.strip().split('\n'):
                    if package:
                        packages.append({"name": package, "type": "formula"})
                sources.append({
                    "source_type": "homebrew_formula",
                    "packages": packages,
                    "count": len(packages)
                })
        except FileNotFoundError:
            pass
        
        # 2. Homebrew casks
        try:
            result = subprocess.run(['brew', 'list', '--cask'], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                packages = []
                for package in result.stdout.strip().split('\n'):
                    if package:
                        packages.append({"name": package, "type": "cask"})
                sources.append({
                    "source_type": "homebrew_cask",
                    "packages": packages,
                    "count": len(packages)
                })
        except FileNotFoundError:
            pass
        
        return sources
    
    def _collect_python_packages(self):
        """Collect Python packages"""
        packages = []
        
        # Try pip
        for pip_cmd in ['pip', 'pip3']:
            try:
                result = subprocess.run([pip_cmd, 'list', '--format=json'], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0 and result.stdout.strip():
                    pip_packages = json.loads(result.stdout)
                    for package in pip_packages:
                        packages.append({
                            "name": package.get('name', 'Unknown'),
                            "version": package.get('version', 'Unknown'),
                            "installer": pip_cmd
                        })
                    break  # Use first successful pip command
            except Exception as e:
                self.logger.debug(f"{pip_cmd} not available: {e}")
        
        return packages
