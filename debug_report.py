#!/usr/bin/env python3
"""
Debug script to check the latest behavioral scan results
"""

import sys
import os
import requests
import json
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def check_agent_results():
    """Check the latest command results from the agent"""
    try:
        # Get agents first
        agents_response = requests.get('http://localhost:8080/api/agents')
        if agents_response.status_code != 200:
            print("❌ Backend server not responding")
            return
            
        agents = agents_response.json()
        print(f"✅ Found {len(agents)} agents")
        
        # Get the first agent
        if not agents:
            print("❌ No agents found")
            return
            
        agent_id = list(agents.keys())[0]
        print(f"📡 Checking agent: {agent_id}")
        
        # Get command results
        results_response = requests.get(f'http://localhost:8080/api/command-results/{agent_id}')
        if results_response.status_code != 200:
            print("❌ Failed to get command results")
            return
            
        results = results_response.json()
        print(f"📊 Found {len(results)} command results")
        
        # Filter for behavioral scan results
        behavioral_results = [
            result for result in results 
            if result.get('command') and 'RUN_BEHAVIORAL_SCAN' in result.get('command', '')
        ]
        
        print(f"🔍 Found {len(behavioral_results)} behavioral scan results")
        
        if behavioral_results:
            # Get the latest one
            latest = sorted(behavioral_results, key=lambda x: x.get('timestamp', ''), reverse=True)[0]
            
            print("\n" + "="*80)
            print("LATEST BEHAVIORAL SCAN RESULT")
            print("="*80)
            print(f"Command: {latest.get('command', 'Unknown')}")
            print(f"Return Code: {latest.get('return_code', 'Unknown')}")
            print(f"Timestamp: {latest.get('timestamp', 'Unknown')}")
            print(f"Success: {latest.get('success', 'Unknown')}")
            
            if latest.get('output'):
                print("\nOutput Preview:")
                print("-" * 40)
                output_lines = latest['output'].split('\n')[:20]  # First 20 lines
                for line in output_lines:
                    print(line)
                if len(latest['output'].split('\n')) > 20:
                    print("... (truncated)")
                    
            print("\n" + "="*80)
            
            # Try to parse the output
            if latest.get('output'):
                try:
                    from test_behavioral_detector import parse_behavioral_output
                    parsed = parse_behavioral_output(latest['output'])
                    if parsed:
                        print(f"✅ Parsing successful!")
                        print(f"   - Suspicious processes: {len(parsed.get('suspicious_processes', []))}")
                        print(f"   - Analysis duration: {parsed.get('analysis_duration_seconds', 'Unknown')}s")
                    else:
                        print("❌ Parsing failed")
                except Exception as e:
                    print(f"❌ Parsing error: {e}")
        else:
            print("❌ No behavioral scan results found")
            
    except Exception as e:
        print(f"❌ Error: {e}")

def parse_behavioral_output_simple(output):
    """Simple parser for behavioral scan output"""
    try:
        lines = output.split('\n')
        suspicious_count = 0
        
        for line in lines:
            if 'Suspicious Processes Found:' in line:
                parts = line.split(':')
                if len(parts) > 1:
                    try:
                        suspicious_count = int(parts[1].strip())
                    except:
                        pass
                        
        print(f"🔍 Simple parse result: {suspicious_count} suspicious processes")
        return suspicious_count > 0
        
    except Exception as e:
        print(f"❌ Simple parsing error: {e}")
        return False

if __name__ == "__main__":
    print("🔧 BAD Report Debug Script")
    print("=" * 50)
    check_agent_results()
