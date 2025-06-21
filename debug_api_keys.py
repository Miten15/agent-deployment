#!/usr/bin/env python3
import os
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

print("=== API Key Debug ===")
print(f"Environment AGENT_API_KEY: {repr(os.getenv('AGENT_API_KEY'))}")

# Load config
try:
    with open('agent_config.json') as f:
        config = json.load(f)
    print(f"Config API key: {repr(config.get('api_key'))}")
except Exception as e:
    print(f"Error loading config: {e}")

# Check server environment
print("\n=== Server Environment ===")
server_env_path = "server/.env"
if os.path.exists(server_env_path):
    with open(server_env_path) as f:
        for line in f:
            if 'AGENT_API_KEY' in line:
                print(f"Server .env: {line.strip()}")
else:
    print("Server .env not found")

# Check main environment
main_env_path = ".env"
if os.path.exists(main_env_path):
    with open(main_env_path) as f:
        for line in f:
            if 'AGENT_API_KEY' in line:
                print(f"Main .env: {line.strip()}")
else:
    print("Main .env not found")
