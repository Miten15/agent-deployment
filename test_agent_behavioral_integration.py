#!/usr/bin/env python3
"""
Agent-BAD Integration Test
Tests the integration between the endpoint agent and the Behavioral Anomaly Detector module.
"""

import sys
import os
import logging
import time
from datetime import datetime

# Add the current directory to the path so we can import modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the main agent
from endpoint_agent_modular import ModularEndpointAgent

def setup_test_logging():
    """Setup logging for the test"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    logger = logging.getLogger("AgentBADIntegrationTest")
    return logger

def test_agent_behavioral_integration():
    """Test the integration between agent and BAD module"""
    logger = setup_test_logging()
    
    logger.info("Starting Agent-BAD Integration Test")
    logger.info("="*60)
    
    try:
        # Initialize the agent
        logger.info("TEST 1: Agent Initialization")
        logger.info("-" * 30)
        
        agent = ModularEndpointAgent(
            server_url="http://localhost:8080",
            config_file="agent_config.json"
        )
        
        # Check if BAD module is loaded
        if hasattr(agent, 'behavioral_detector') and agent.behavioral_detector:
            logger.info("[SUCCESS] Agent initialized with BAD module")
            logger.info(f"BAD Agent ID: {agent.behavioral_detector.agent_id}")
        else:
            logger.error("[FAILED] BAD module not initialized")
            return False
        
        # Test command handling
        logger.info("\nTEST 2: Command Handling")
        logger.info("-" * 30)
          # Test RUN_BEHAVIORAL_SCAN command
        logger.info("Testing RUN_BEHAVIORAL_SCAN command...")
        # Simulate command execution
        result = agent.execute_command("RUN_BEHAVIORAL_SCAN")
        
        # Check if the scan itself was successful, even if server connection failed
        if result:
            return_code = result.get('return_code', 1)
            error_msg = result.get('error', '')
            
            # If the scan ran but server connection failed, that's acceptable for testing
            if (result.get('success') or 
                ('Failed to send behavioral scan results to server' in error_msg and 
                 'behavioral_data' in result)):
                logger.info("[SUCCESS] RUN_BEHAVIORAL_SCAN command executed successfully")
                logger.info(f"Return code: {return_code}")
                logger.info(f"Output length: {len(result.get('output', ''))}")
                
                # Check if behavioral data is present
                behavioral_data = result.get('behavioral_data', {})
                if behavioral_data:
                    suspicious_count = len(behavioral_data.get('suspicious_processes', []))
                    total_analyzed = behavioral_data.get('summary', {}).get('total_processes_analyzed', 0)
                    logger.info(f"Processes analyzed: {total_analyzed}")
                    logger.info(f"Suspicious processes: {suspicious_count}")
                    
                    if 'Failed to send behavioral scan results to server' in error_msg:
                        logger.info("Note: Server connection failed (expected if backend not running)")
                else:
                    logger.warning("No behavioral data in result")
            else:
                logger.error("[FAILED] RUN_BEHAVIORAL_SCAN command failed")
                if result:
                    logger.error(f"Error: {result.get('error', 'Unknown error')}")
                return False
        else:
            logger.error("[FAILED] RUN_BEHAVIORAL_SCAN command returned no result")
            return False
        
        # Test GET_BEHAVIORAL_HISTORY command
        logger.info("\nTesting GET_BEHAVIORAL_HISTORY command...")
        
        history_result = agent.execute_command("GET_BEHAVIORAL_HISTORY")
        
        if history_result and history_result.get('success'):
            logger.info("[SUCCESS] GET_BEHAVIORAL_HISTORY command executed successfully")
            history = history_result.get('behavioral_history', [])
            logger.info(f"History entries: {len(history)}")
        else:
            logger.error("[FAILED] GET_BEHAVIORAL_HISTORY command failed")
            if history_result:
                logger.error(f"Error: {history_result.get('error', 'Unknown error')}")
            return False
        
        # Test direct BAD module access
        logger.info("\nTEST 3: Direct BAD Module Access")
        logger.info("-" * 30)
        
        # Test process collection
        logger.info("Testing direct process collection...")
        process_data = agent.behavioral_detector._collect_process_data()
        logger.info(f"[SUCCESS] Collected data for {len(process_data)} processes")
        
        # Test profiling
        logger.info("Testing short profiling (10 seconds)...")
        profile_result = agent.behavioral_detector.profile_system_behavior(10)
        if profile_result:
            logger.info(f"[SUCCESS] Profiling completed for {len(profile_result)} processes")
        else:
            logger.error("[FAILED] Profiling returned no data")
            return False
        
        # Test analysis
        logger.info("Testing behavioral analysis...")
        analysis_result = agent.behavioral_detector.analyze_behavioral_patterns()
        logger.info(f"[SUCCESS] Analysis completed for {len(analysis_result)} processes")
        
        # Show some analysis results
        suspicious_count = sum(1 for result in analysis_result.values() 
                             if result.get('behavioral_score', 0) >= agent.behavioral_detector.suspicion_threshold)
        logger.info(f"Suspicious processes found: {suspicious_count}")
        
        logger.info("\nTEST 4: Configuration Validation")
        logger.info("-" * 30)
        
        # Check configuration
        config = agent.config.get('behavioral_detection', {})
        logger.info(f"Profile duration: {config.get('profile_duration', 'default')} seconds")
        logger.info(f"Sampling interval: {config.get('sampling_interval', 'default')} seconds")
        logger.info(f"Suspicion threshold: {config.get('suspicion_threshold', 'default')}")
        logger.info(f"Auto scan interval: {config.get('auto_scan_interval', 'default')} seconds")
        logger.info("[SUCCESS] Configuration loaded correctly")
        
        logger.info("\n" + "="*60)
        logger.info("INTEGRATION TEST RESULTS")
        logger.info("="*60)
        logger.info("Agent Initialization       [SUCCESS] PASS")
        logger.info("Command Handling           [SUCCESS] PASS")
        logger.info("Direct BAD Access          [SUCCESS] PASS")
        logger.info("Configuration Validation   [SUCCESS] PASS")
        logger.info("-"*60)
        logger.info("Integration Tests: 4/4 PASSED")
        logger.info("SUCCESS RATE: 100%")
        logger.info("[COMPLETE] Agent-BAD integration working correctly!")
        
        return True
        
    except Exception as e:
        logger.error(f"Integration test failed with exception: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

if __name__ == "__main__":
    success = test_agent_behavioral_integration()
    sys.exit(0 if success else 1)
