"""
Windows Service wrapper for the Endpoint Agent
"""
import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import sys
import os
import logging
import time
import threading
from pathlib import Path

# Add the current directory to the path so we can import the agent
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    env_file = Path(__file__).parent / ".env"
    if env_file.exists():
        load_dotenv(env_file)
except ImportError:
    # Fallback to manual loading if dotenv is not available
    def load_env_file():
        env_file = Path(__file__).parent / ".env"
        if env_file.exists():
            with open(env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key.strip()] = value.strip()
    load_env_file()

try:
    from endpoint_agent_modular import ModularEndpointAgent
except ImportError as e:
    print(f"Failed to import ModularEndpointAgent: {e}")
    sys.exit(1)

class EndpointAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "EndpointAgent"
    _svc_display_name_ = "Endpoint Security Agent"
    _svc_description_ = "Endpoint security monitoring and management agent"
    
    # Service starts automatically
    _svc_start_type_ = win32service.SERVICE_AUTO_START
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = True
        self.agent = None
        self.agent_thread = None
        
        # Set working directory to service directory
        self.service_dir = Path(__file__).parent
        os.chdir(self.service_dir)
        
        # Setup logging
        self.setup_logging()
        
    def setup_logging(self):
        """Setup service logging"""
        log_dir = Path(__file__).parent / "logs"
        log_dir.mkdir(exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / "service.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("EndpointAgentService")
        
    def SvcStop(self):
        """Stop the service"""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.logger.info("Service stop requested")
        
        self.is_running = False
        
        # Stop the agent gracefully
        if self.agent:
            try:
                self.agent.stop()
                self.logger.info("Agent stopped successfully")
            except Exception as e:
                self.logger.error(f"Error stopping agent: {e}")
        
        # Wait for agent thread to finish
        if self.agent_thread and self.agent_thread.is_alive():
            self.agent_thread.join(timeout=10)
            if self.agent_thread.is_alive():
                self.logger.warning("Agent thread did not stop gracefully")
        
        win32event.SetEvent(self.hWaitStop)
        
    def SvcDoRun(self):
        """Run the service"""
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        
        self.logger.info("Endpoint Agent Service starting...")
        
        try:
            self.run_agent()
        except Exception as e:
            self.logger.error(f"Service error: {e}")
            servicemanager.LogErrorMsg(f"Service error: {e}")
        
        self.logger.info("Endpoint Agent Service stopped")
    def run_agent(self):
        """Run the agent in a separate thread"""
        def agent_worker():
            try:
                self.logger.info("Initializing agent...")
                config_path = self.service_dir / "agent_config.json"
                self.logger.info(f"Using config file: {config_path}")
                
                self.agent = ModularEndpointAgent(config_file=str(config_path))
                
                self.logger.info("Starting agent...")
                self.agent.start()
                
                # Keep the agent running
                while self.is_running:
                    time.sleep(1)
                    
            except Exception as e:
                self.logger.error(f"Agent error: {e}")
                self.SvcStop()
        
        self.agent_thread = threading.Thread(target=agent_worker)
        self.agent_thread.daemon = True
        self.agent_thread.start()
        
        # Wait for stop signal
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(EndpointAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(EndpointAgentService)
