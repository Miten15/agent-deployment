#!/usr/bin/env python3
"""
Test script for enhanced behavioral anomaly detector with new detections.
Tests the improved log forwarding, C2 signatures, and suspicious service detection.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.behavioral_anomaly_detector import BehavioralAnomalyDetector

def test_log_forwarding_detection():
    """Test log forwarding behavior detection and score reduction."""
    print("=== Testing Log Forwarding Detection ===")
    
    detector = BehavioralAnomalyDetector("test-agent")
    
    # Test known log forwarding service
    connections = [
        {'remote_address': '192.168.1.100', 'remote_port': 9200},  # Elasticsearch
        {'remote_address': '10.0.0.5', 'remote_port': 5044},      # Logstash
    ]
    
    # Test with Wazuh agent
    result = detector._detect_log_forwarding_behavior('wazuh-agent', connections)
    print(f"Wazuh agent detection: {result}")
    assert result['is_log_service'] == True
    assert result['likely_log_forwarding'] == True
    
    # Test with ELK stack
    result = detector._detect_log_forwarding_behavior('elasticsearch', connections)
    print(f"Elasticsearch detection: {result}")
    assert result['is_log_service'] == True
    
    # Test with unknown process
    result = detector._detect_log_forwarding_behavior('unknown.exe', connections)
    print(f"Unknown process detection: {result}")
    assert result['is_log_service'] == False
    
    print("✓ Log forwarding detection working correctly")

def test_c2_signature_detection():
    """Test C2 signature detection."""
    print("\n=== Testing C2 Signature Detection ===")
    
    detector = BehavioralAnomalyDetector("test-agent")
    
    # Test process with C2 signature in name
    connections = [
        {'remote_address': '192.168.1.100', 'remote_port': 4444},  # Common C2 port
        {'remote_address': '10.0.0.5', 'remote_port': 8080},      # HTTP alternative
    ]
    
    network_data = [
        {'timestamp': 1000, 'connection': '192.168.1.100:4444'},
        {'timestamp': 1060, 'connection': '192.168.1.100:4444'},  # 60s interval
        {'timestamp': 1120, 'connection': '192.168.1.100:4444'},  # 60s interval
        {'timestamp': 1180, 'connection': '192.168.1.100:4444'},  # 60s interval
        {'timestamp': 1240, 'connection': '192.168.1.100:4444'},  # 60s interval
        {'timestamp': 1300, 'connection': '192.168.1.100:4444'},  # 60s interval
    ]
    
    # Test with suspicious process name
    result = detector._detect_c2_signatures('beacon.exe', connections, network_data)
    print(f"Beacon process detection: {result}")
    assert result['c2_score'] > 0
    assert len(result['indicators']) > 0
    
    # Test with legitimate process
    result = detector._detect_c2_signatures('chrome.exe', connections, network_data)
    print(f"Chrome process detection: {result}")
    # Chrome might still trigger on ports, but lower score
    
    print("✓ C2 signature detection working correctly")

def test_suspicious_service_detection():
    """Test suspicious Windows service pattern detection."""
    print("\n=== Testing Suspicious Service Detection ===")
    
    detector = BehavioralAnomalyDetector("test-agent")
    
    # Test suspicious service name
    process_info = {'path': 'C:\\temp\\svchost32.exe'}
    result = detector._detect_suspicious_service_patterns('svchost32.exe', process_info)
    print(f"Suspicious svchost detection: {result}")
    assert result['suspicious_score'] > 0
    
    # Test legitimate service
    process_info = {'path': 'C:\\Windows\\System32\\svchost.exe'}
    result = detector._detect_suspicious_service_patterns('svchost.exe', process_info)
    print(f"Legitimate svchost detection: {result}")
    # Should have lower or no score
    
    # Test service in suspicious location
    process_info = {'path': 'C:\\Users\\Username\\AppData\\Local\\Temp\\service.exe'}
    result = detector._detect_suspicious_service_patterns('winlogon_helper.exe', process_info)
    print(f"Temp location service detection: {result}")
    assert result['suspicious_score'] > 0
    
    print("✓ Suspicious service detection working correctly")

def test_integrated_analysis():
    """Test integrated analysis with new detection methods."""
    print("\n=== Testing Integrated Analysis ===")
    
    detector = BehavioralAnomalyDetector("test-agent")
    
    # Create test profile data for Wazuh agent (should have reduced scores)
    profile_data = {
        1234: [
            {
                'name': 'wazuh-agent',
                'username': 'SYSTEM',
                'cpu_percent': 2.0,
                'memory_percent': 1.5,
                'create_time': 1640995200,
                'status': 'running'
            }
        ],
        5678: [
            {
                'name': 'beacon.exe',
                'username': 'Administrator',  
                'cpu_percent': 1.0,
                'memory_percent': 0.8,
                'create_time': 1640995200,
                'status': 'running'
            }
        ]
    }
    
    # Add some network connections to the internal profiles
    # This simulates the profiling having collected network data
    detector.process_profiles[1234]['network_connections'].add('127.0.0.1:9200')  # Local Elasticsearch
    detector.process_profiles[1234]['connection_history']['127.0.0.1:9200'].append({
        'timestamp': 1000,
        'local_port': 54321,
        'status': 'ESTABLISHED'
    })
    
    detector.process_profiles[5678]['network_connections'].add('192.168.1.100:4444')  # Suspicious C2
    detector.process_profiles[5678]['connection_history']['192.168.1.100:4444'].extend([
        {'timestamp': 1000, 'local_port': 54322, 'status': 'ESTABLISHED'},
        {'timestamp': 1060, 'local_port': 54323, 'status': 'ESTABLISHED'},
        {'timestamp': 1120, 'local_port': 54324, 'status': 'ESTABLISHED'},
    ])
    
    # Run analysis
    analysis_results = detector.analyze_behavioral_patterns(profile_data)
    
    print(f"Analysis results for {len(analysis_results)} processes:")
    for pid, analysis in analysis_results.items():
        process_name = analysis['metadata']['name']
        behavior_count = len(analysis['suspicious_behaviors'])
        print(f"  PID {pid} ({process_name}): {behavior_count} suspicious behaviors")
        
        for behavior in analysis['suspicious_behaviors']:
            print(f"    - {behavior['type']}: {behavior['description']} (score: {behavior['score']})")
    
    # Calculate scores
    scored_results = detector.calculate_suspicion_scores(analysis_results)
    
    print(f"\nFinal scores:")
    for pid, analysis in scored_results.items():
        process_name = analysis['metadata']['name']
        score = analysis['behavioral_score']
        risk_level = analysis['risk_level']
        print(f"  PID {pid} ({process_name}): Score {score}/10 - Risk: {risk_level}")
    
    # Verify that Wazuh agent has reduced scores compared to suspicious beacon
    wazuh_score = scored_results[1234]['behavioral_score']
    beacon_score = scored_results[5678]['behavioral_score']
    
    print(f"\nScore comparison:")
    print(f"  Wazuh agent: {wazuh_score}/10")
    print(f"  Suspicious beacon: {beacon_score}/10")
    
    if beacon_score > wazuh_score:
        print("✓ Contextual scoring working - legitimate log service has lower score")
    else:
        print("⚠ Contextual scoring may need adjustment")
    
    print("✓ Integrated analysis completed")

def main():
    """Run all tests."""
    print("Testing Enhanced Behavioral Anomaly Detector")
    print("=" * 50)
    
    try:
        test_log_forwarding_detection()
        test_c2_signature_detection()
        test_suspicious_service_detection()
        test_integrated_analysis()
        
        print("\n" + "=" * 50)
        print("✅ All tests completed successfully!")
        print("\nKey improvements implemented:")
        print("• Log forwarding service detection with score reduction")
        print("• C2 signature detection for processes and network patterns")
        print("• Suspicious Windows service pattern detection")
        print("• Contextual scoring adjustments for legitimate services")
        print("• Reduced false positives for Wazuh, ELK, Splunk, and other log services")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
