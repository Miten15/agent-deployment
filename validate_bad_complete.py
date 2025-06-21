#!/usr/bin/env python3
"""
Behavioral Anomaly Detector (BAD) - Complete Validation Suite
This script runs comprehensive tests to validate the entire BAD implementation including:
1. Standalone BAD module functionality
2. Agent-BAD integration
3. Configuration validation
4. Performance testing
"""

import sys
import os
import time
import logging
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def setup_logging():
    """Setup comprehensive logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('bad_validation.log')
        ]
    )
    return logging.getLogger("BADValidationSuite")

def run_standalone_test():
    """Run the standalone BAD test"""
    logger = logging.getLogger("BADValidationSuite")
    logger.info("Running Standalone BAD Test...")
    
    try:
        # Import and run standalone test
        from test_behavioral_detector import main as run_standalone_test
        result = run_standalone_test()
        # Standalone test returns 0 for success, 1 for failure (Unix exit codes)
        success = (result == 0)
        logger.info(f"Standalone test result: {'PASS' if success else 'FAIL'}")
        return success
    except Exception as e:
        logger.error(f"Standalone test failed: {e}")
        return False

def run_integration_test():
    """Run the agent-BAD integration test"""
    logger = logging.getLogger("BADValidationSuite")
    logger.info("Running Agent-BAD Integration Test...")
    
    try:
        # Import and run integration test
        from test_agent_behavioral_integration import test_agent_behavioral_integration
        result = test_agent_behavioral_integration()
        logger.info(f"Integration test result: {'PASS' if result else 'FAIL'}")
        return result
    except Exception as e:
        logger.error(f"Integration test failed: {e}")
        return False

def validate_configuration():
    """Validate configuration files"""
    logger = logging.getLogger("BADValidationSuite")
    logger.info("Validating Configuration...")
    
    try:
        import json
        
        # Check agent_config.json
        if os.path.exists('agent_config.json'):
            with open('agent_config.json', 'r') as f:
                config = json.load(f)
                
            behavioral_config = config.get('behavioral_detection', {})
            required_keys = ['profile_duration', 'sampling_interval', 'suspicion_threshold', 'auto_scan_interval']
            
            for key in required_keys:
                if key not in behavioral_config:
                    logger.warning(f"Missing configuration key: {key}")
                else:
                    logger.info(f"[PASS] {key}: {behavioral_config[key]}")
            
            # Check allowed commands
            allowed_commands = config.get('allowed_commands', [])
            behavioral_commands = ['RUN_BEHAVIORAL_SCAN', 'GET_BEHAVIORAL_HISTORY', 'STOP_BEHAVIORAL_SCAN']
            
            for cmd in behavioral_commands:
                if cmd not in allowed_commands:
                    logger.warning(f"Behavioral command not in allowed_commands: {cmd}")
                else:
                    logger.info(f"[PASS] Command allowed: {cmd}")
        else:
            logger.warning("agent_config.json not found")
            
        logger.info("Configuration validation completed")
        return True
        
    except Exception as e:
        logger.error(f"Configuration validation failed: {e}")
        return False

def validate_module_structure():
    """Validate module file structure"""
    logger = logging.getLogger("BADValidationSuite")
    logger.info("Validating Module Structure...")
    
    required_files = [
        'modules/behavioral_anomaly_detector.py',
        'endpoint_agent_modular.py',
        'dashboard/app/api/behavioral/start/route.ts',
        'dashboard/app/api/behavioral/report/route.ts',
        'dashboard/app/(dashboard)/dashboard/behavioral/page.tsx'
    ]
    
    missing_files = []
    for file_path in required_files:
        if os.path.exists(file_path):
            logger.info(f"[PASS] {file_path}")
        else:
            logger.warning(f"[FAIL] Missing: {file_path}")
            missing_files.append(file_path)
    
    if missing_files:
        logger.warning(f"Missing files: {missing_files}")
        return False
    
    logger.info("Module structure validation completed")
    return True

def performance_test():
    """Run basic performance tests"""
    logger = logging.getLogger("BADValidationSuite")
    logger.info("Running Performance Tests...")
    
    try:
        from modules.behavioral_anomaly_detector import BehavioralAnomalyDetector
        
        # Create detector instance
        detector = BehavioralAnomalyDetector("perf-test-agent")
        
        # Test 1: Process collection speed
        start_time = time.time()
        processes = detector._collect_process_data()
        collection_time = time.time() - start_time
        
        logger.info(f"Process collection: {len(processes)} processes in {collection_time:.2f}s")
        
        # Test 2: Short profiling performance
        start_time = time.time()
        profile = detector.profile_system_behavior(5)
        profiling_time = time.time() - start_time
        
        logger.info(f"Short profiling: {len(profile)} processes in {profiling_time:.2f}s")
        
        # Test 3: Analysis performance
        start_time = time.time()
        analysis = detector.analyze_behavioral_patterns()
        analysis_time = time.time() - start_time
        
        logger.info(f"Analysis: {len(analysis)} processes in {analysis_time:.2f}s")
        
        # Performance thresholds
        if collection_time > 10:
            logger.warning(f"Process collection took {collection_time:.2f}s (threshold: 10s)")
        if analysis_time > 5:
            logger.warning(f"Analysis took {analysis_time:.2f}s (threshold: 5s)")
        
        logger.info("Performance tests completed")
        return True
        
    except Exception as e:
        logger.error(f"Performance test failed: {e}")
        return False

def main():
    """Main validation function"""
    logger = setup_logging()
    
    logger.info("="*80)
    logger.info("BEHAVIORAL ANOMALY DETECTOR (BAD) - COMPLETE VALIDATION SUITE")
    logger.info("="*80)
    logger.info(f"Test started at: {datetime.now().isoformat()}")
    logger.info("")
    
    # Track test results
    tests = {
        "Module Structure": validate_module_structure(),
        "Configuration": validate_configuration(),
        "Standalone BAD": run_standalone_test(),
        "Agent Integration": run_integration_test(),
        "Performance": performance_test()
    }
    
    # Print results summary
    logger.info("="*80)
    logger.info("VALIDATION RESULTS SUMMARY")
    logger.info("="*80)
    
    passed = 0
    total = len(tests)
    
    for test_name, result in tests.items():
        status = "PASS" if result else "FAIL"
        logger.info(f"{test_name:<25} [{status}]")
        if result:
            passed += 1
    logger.info("-" * 80)
    logger.info(f"Tests passed: {passed}/{total}")
    logger.info(f"Success rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        logger.info("[SUCCESS] ALL TESTS PASSED! BAD module is fully functional and integrated.")
        logger.info("[SUCCESS] The Behavioral Anomaly Detector is ready for production use.")
    else:
        logger.warning(f"[WARNING] {total-passed} test(s) failed. Please review the issues above.")
    
    logger.info("="*80)
    logger.info(f"Validation completed at: {datetime.now().isoformat()}")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
