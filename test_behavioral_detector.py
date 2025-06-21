#!/usr/bin/env python3
"""
Standalone test script for the Behavioral Anomaly Detector module.
This script tests the behavioral detector in isolation to identify and fix bugs.
"""

import os
import sys
import json
import time
import logging
from datetime import datetime

# Add modules directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

# Import the behavioral detector
from behavioral_anomaly_detector import BehavioralAnomalyDetector

def setup_logging():
    """Setup logging for the test"""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('test_behavioral_detector.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger('BehavioralDetectorTest')

def test_basic_initialization():
    """Test basic initialization of the behavioral detector"""
    logger = logging.getLogger('BehavioralDetectorTest')
    logger.info("=" * 60)
    logger.info("TEST 1: Basic Initialization")
    logger.info("=" * 60)
    
    try:
        # Test configuration
        test_config = {
            "profile_duration": 30,  # Shorter for testing
            "sampling_interval": 2,
            "suspicion_threshold": 3,
            "high_privilege_users": [
                "NT AUTHORITY\\SYSTEM", "root", "SYSTEM", "Administrator"
            ],
            "high_disk_reads_mb": 50,
            "high_data_egress_mb": 1,
            "persistent_connection_seconds": 15
        }
          # Initialize detector
        detector = BehavioralAnomalyDetector("test-agent-001", test_config)
        logger.info("[SUCCESS] Behavioral detector initialized successfully")
        
        # Test configuration loading
        logger.info(f"Profile duration: {detector.profile_duration}s")
        logger.info(f"Sampling interval: {detector.sampling_interval}s")
        logger.info(f"Suspicion threshold: {detector.suspicion_threshold}")
        logger.info(f"High privilege users: {len(detector.high_privilege_users)}")
        
        return detector, True
        
    except Exception as e:        logger.error(f"[FAIL] Initialization failed: {e}")
    return None, False

def test_process_collection(detector):
    """Test process data collection"""
    logger = logging.getLogger('BehavioralDetectorTest')
    logger.info("\n" + "=" * 60)
    logger.info("TEST 2: Process Data Collection")
    logger.info("=" * 60)
    
    try:
        # Test process collection
        logger.info("Collecting process data...")
        process_data = detector._collect_process_data()
        
        if not process_data:
            logger.warning("[WARNING]  No process data collected")
            return False
            
        logger.info(f"[SUCCESS] Collected data for {len(process_data)} processes")
        
        # Examine a few processes
        for i, (pid, data) in enumerate(list(process_data.items())[:3]):
            logger.info(f"Process {i+1}: PID={pid}")
            logger.info(f"  Name: {data.get('name', 'Unknown')}")
            logger.info(f"  Username: {data.get('username', 'Unknown')}")
            logger.info(f"  CPU %: {data.get('cpu_percent', 'Unknown')}")
            logger.info(f"  Memory %: {data.get('memory_percent', 'Unknown')}")
            logger.info(f"  Status: {data.get('status', 'Unknown')}")
            
            # Check for None values that might cause the 'upper' error
            for key, value in data.items():
                if value is None:
                    logger.warning(f"  [WARNING]  Found None value for key '{key}'")
        
        return True
        
    except Exception as e:
        logger.error(f"[FAIL] Process collection failed: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False

def test_short_profiling(detector):
    """Test short duration profiling"""
    logger = logging.getLogger('BehavioralDetectorTest')
    logger.info("\n" + "=" * 60)
    logger.info("TEST 3: Short Duration Profiling")
    logger.info("=" * 60)
    
    try:
        # Run a short profiling session
        logger.info("Starting 10-second profiling session...")
        profile_result = detector.profile_system_behavior(10)
        
        if not profile_result:
            logger.error("[FAIL] Profiling returned no data")
            return False
            
        logger.info(f"[SUCCESS] Profiling completed successfully")
        logger.info(f"Total processes tracked: {len(profile_result)}")
        
        # Examine profile data
        sample_count = 0
        for pid, samples in profile_result.items():
            if samples:
                sample_count += len(samples)
                if len(samples) > 0:
                    logger.info(f"Process {pid}: {len(samples)} samples")
                    # Check first sample for None values
                    first_sample = samples[0]
                    for key, value in first_sample.items():
                        if value is None:
                            logger.warning(f"  [WARNING]  Found None value for key '{key}' in sample")
                
        logger.info(f"Total samples collected: {sample_count}")
        return True
        
    except Exception as e:
        logger.error(f"[FAIL] Profiling failed: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False

def test_analysis_phase(detector):
    """Test the analysis phase with sample data"""
    logger = logging.getLogger('BehavioralDetectorTest')
    logger.info("\n" + "=" * 60)
    logger.info("TEST 4: Analysis Phase")
    logger.info("=" * 60)
    
    try:
        # First, run a very short profile to get some data
        logger.info("Running 5-second profile for analysis testing...")
        profile_data = detector.profile_system_behavior(5)
        
        if not profile_data:
            logger.error("[FAIL] No profile data for analysis")
            return False
            
        logger.info(f"Profile data collected for {len(profile_data)} processes")
        
        # Now test the analysis
        logger.info("Running behavioral analysis...")
        analysis_result = detector.analyze_behavioral_patterns(profile_data)
        
        if analysis_result is None:
            logger.error("[FAIL] Analysis returned None")
            return False
            
        logger.info(f"[SUCCESS] Analysis completed successfully")
        logger.info(f"Total processes analyzed: {len(analysis_result)}")
        
        # Check for suspicious processes
        suspicious_count = 0
        for pid, analysis in analysis_result.items():
            if analysis.get('suspicion_score', 0) > 0:
                suspicious_count += 1
                logger.info(f"Suspicious process found: PID={pid}, Score={analysis.get('suspicion_score', 0)}")
                
                # Check for None values in analysis
                for key, value in analysis.items():
                    if value is None:
                        logger.warning(f"  [WARNING]  Found None value for key '{key}' in analysis")
        
        logger.info(f"Suspicious processes found: {suspicious_count}")
        return True
        
    except Exception as e:
        logger.error(f"[FAIL] Analysis failed: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False

def test_full_detection_cycle(detector):
    """Test the full detection cycle"""
    logger = logging.getLogger('BehavioralDetectorTest')
    logger.info("\n" + "=" * 60)
    logger.info("TEST 5: Full Detection Cycle")
    logger.info("=" * 60)
    
    try:
        # Run full detection with short duration
        logger.info("Running full detection cycle (15 seconds)...")
        detection_result = detector.run_full_detection(15)
        
        if not detection_result:
            logger.error("[FAIL] Full detection returned no data")
            return False
            
        logger.info(f"[SUCCESS] Full detection completed successfully")
        
        # Examine results
        summary = detection_result.get('summary', {})
        logger.info(f"Total processes analyzed: {summary.get('total_processes_analyzed', 0)}")
        logger.info(f"Suspicious processes found: {summary.get('suspicious_processes_found', 0)}")
        logger.info(f"Detection timestamp: {detection_result.get('detection_metadata', {}).get('detection_timestamp', 'Unknown')}")
        
        # Check suspicious processes
        suspicious_processes = detection_result.get('suspicious_processes', [])
        for process in suspicious_processes[:3]:  # Show first 3
            logger.info(f"Suspicious process: {process.get('process_name', 'Unknown')} (PID: {process.get('pid', 'Unknown')})")
            logger.info(f"  Risk level: {process.get('risk_level', 'Unknown')}")
            logger.info(f"  Suspicion score: {process.get('suspicion_score', 0)}")
            
            # Check for None values
            for key, value in process.items():
                if value is None:
                    logger.warning(f"  [WARNING]  Found None value for key '{key}' in suspicious process")
        
        return True
        
    except Exception as e:
        logger.error(f"[FAIL] Full detection failed: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False

def test_detection_history(detector):
    """Test detection history functionality"""
    logger = logging.getLogger('BehavioralDetectorTest')
    logger.info("\n" + "=" * 60)
    logger.info("TEST 6: Detection History")
    logger.info("=" * 60)
    
    try:
        # Get history
        history = detector.get_detection_history()
        logger.info(f"[SUCCESS] Retrieved detection history: {len(history)} entries")
        
        for i, entry in enumerate(history):
            metadata = entry.get('detection_metadata', {})
            summary = entry.get('summary', {})
            logger.info(f"History entry {i+1}:")
            logger.info(f"  Timestamp: {metadata.get('detection_timestamp', 'Unknown')}")
            logger.info(f"  Processes analyzed: {summary.get('total_processes_analyzed', 0)}")
            logger.info(f"  Suspicious found: {summary.get('suspicious_processes_found', 0)}")
        
        return True
        
    except Exception as e:
        logger.error(f"[FAIL] History retrieval failed: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False

def main():
    """Main test function"""
    logger = setup_logging()
    logger.info("Starting Behavioral Anomaly Detector Test Suite")
    logger.info(f"Test started at: {datetime.now().isoformat()}")
    
    test_results = []
    
    # Test 1: Basic initialization
    detector, init_success = test_basic_initialization()
    test_results.append(("Initialization", init_success))
    
    if not init_success:
        logger.error("[FAIL] Cannot continue tests - initialization failed")
        return 1
    
    # Test 2: Process collection
    collection_success = test_process_collection(detector)
    test_results.append(("Process Collection", collection_success))
    
    # Test 3: Short profiling
    profiling_success = test_short_profiling(detector)
    test_results.append(("Short Profiling", profiling_success))
    
    # Test 4: Analysis phase
    analysis_success = test_analysis_phase(detector)
    test_results.append(("Analysis Phase", analysis_success))
    
    # Test 5: Full detection cycle
    detection_success = test_full_detection_cycle(detector)
    test_results.append(("Full Detection", detection_success))
    
    # Test 6: Detection history
    history_success = test_detection_history(detector)
    test_results.append(("Detection History", history_success))
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("TEST RESULTS SUMMARY")
    logger.info("=" * 60)
    
    passed = 0
    total = len(test_results)
    
    for test_name, success in test_results:
        status = "[SUCCESS] PASS" if success else "[FAIL] FAIL"
        logger.info(f"{test_name:<20} {status}")
        if success:
            passed += 1
    
    logger.info("-" * 60)
    logger.info(f"Tests passed: {passed}/{total}")
    logger.info(f"Success rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        logger.info("[COMPLETE] All tests passed!")
        return 0
    else:
        logger.error("[FAIL] Some tests failed. Check the logs for details.")
        return 1

if __name__ == "__main__":
    exit(main())
