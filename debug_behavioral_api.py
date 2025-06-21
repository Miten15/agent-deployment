#!/usr/bin/env python3
"""
Test script to debug the behavioral report retrieval with proper authentication
"""

import requests
import json
import time

# Server configuration
SERVER_URL = "http://localhost:8080"
USERNAME = "admin"
PASSWORD = "RTAOGrzX9*ySx@P4V@rW"

def test_authentication():
    """Test authentication and get token"""
    print("Testing authentication...")
    
    login_url = f"{SERVER_URL}/api/auth/login"
    login_data = {
        "username": USERNAME,
        "password": PASSWORD
    }
    
    try:
        response = requests.post(login_url, json=login_data)
        print(f"Login response status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            token = data.get('access_token')
            print(f"✅ Authentication successful! Token received.")
            return token
        else:
            print(f"❌ Authentication failed: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ Authentication error: {e}")
        return None

def get_agents(token):
    """Get list of agents"""
    print("\nGetting agents...")
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(f"{SERVER_URL}/api/agents", headers=headers)
        print(f"Agents response status: {response.status_code}")
        
        if response.status_code == 200:
            agents = response.json()
            print(f"✅ Found {len(agents)} agents:")
            for agent_id, agent_data in agents.items():
                print(f"  - {agent_id}: {agent_data.get('status', 'unknown')}")
            return agents
        else:
            print(f"❌ Failed to get agents: {response.text}")
            return {}
            
    except Exception as e:
        print(f"❌ Error getting agents: {e}")
        return {}

def get_command_results(token, agent_id):
    """Get command results for agent"""
    print(f"\nGetting command results for agent {agent_id}...")
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    try:
        response = requests.get(f"{SERVER_URL}/api/command-results/{agent_id}", headers=headers)
        print(f"Command results response status: {response.status_code}")
        
        if response.status_code == 200:
            results = response.json()
            print(f"✅ Found {len(results)} command results")
            
            # LOG: Show all command types to debug
            print(f"\n🔍 DEBUG: All command results:")
            for i, result in enumerate(results[-10:]):  # Show last 10
                cmd = result.get('command', 'NO_COMMAND')
                timestamp = result.get('timestamp', 'NO_TIME')
                return_code = result.get('return_code', 'NO_CODE')
                output_len = len(result.get('output', ''))
                print(f"  {i}: '{cmd}' | RC:{return_code} | Time:{timestamp} | Output:{output_len} chars")
                
                # If it might be behavioral, show more details
                if 'BEHAVIORAL' in str(cmd).upper() or 'SCAN' in str(cmd).upper():
                    print(f"    🎯 POTENTIAL MATCH: {result}")
            
            # Look for behavioral scan results (more flexible search)
            behavioral_results = []
            for r in results:
                cmd_str = str(r.get('command', '')).upper()
                if any(keyword in cmd_str for keyword in ['RUN_BEHAVIORAL_SCAN', 'BEHAVIORAL', 'SCAN']):
                    behavioral_results.append(r)
                    
            print(f"📊 Found {len(behavioral_results)} behavioral scan results")
            
            if behavioral_results:
                latest = behavioral_results[-1]  # Get latest
                print(f"Latest behavioral scan:")
                print(f"  - Timestamp: {latest.get('timestamp')}")
                print(f"  - Command: {latest.get('command')}")
                print(f"  - Return Code: {latest.get('return_code')}")
                print(f"  - Output length: {len(latest.get('output', ''))}")
                
                # Show first few lines of output
                output = latest.get('output', '')
                if output:
                    lines = output.split('\\n')[:10]
                    print(f"  - Output preview:")
                    for line in lines:
                        print(f"    {line}")
                
                return latest
            else:
                print("❌ No behavioral scan results found")
                return None
                
        else:
            print(f"❌ Failed to get command results: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ Error getting command results: {e}")
        return None

def test_behavioral_api(token):
    """Test the behavioral API endpoint directly"""
    print(f"\nTesting behavioral API endpoint...")
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    try:
        # Test the Next.js API endpoint
        response = requests.get("http://localhost:3000/api/behavioral/report", headers=headers)
        print(f"Behavioral API response status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Behavioral API successful!")
            print(f"  - Success: {data.get('success')}")
            print(f"  - Message: {data.get('message')}")
            if data.get('report'):
                print(f"  - Report found: {len(str(data.get('report')))} chars")
            return data
        else:
            print(f"❌ Behavioral API failed: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ Error testing behavioral API: {e}")
        return None

def main():
    """Main test function"""
    print("🔧 Behavioral Report Debug Tool")
    print("=" * 50)
    
    # Step 1: Authenticate
    token = test_authentication()
    if not token:
        return
    
    # Step 2: Get agents
    agents = get_agents(token)
    if not agents:
        return
        
    # Step 3: Get command results from the first agent
    agent_id = list(agents.keys())[0]
    command_result = get_command_results(token, agent_id)
    
    # Step 4: Test the behavioral API
    api_result = test_behavioral_api(token)
    
    print("\n" + "=" * 50)
    print("🎯 Summary:")
    print(f"✅ Authentication: {'Success' if token else 'Failed'}")
    print(f"✅ Agents found: {len(agents)}")
    print(f"✅ Behavioral scan data: {'Found' if command_result else 'Not found'}")
    print(f"✅ API endpoint: {'Working' if api_result else 'Failed'}")

if __name__ == "__main__":
    main()
