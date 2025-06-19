# secure_server.py - Secure agent management server with JWT authentication
from flask import Flask, request, jsonify, render_template_string
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors import CORS
import json
import os
import bcrypt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import threading
import time
import secrets

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configure Flask for larger request sizes (for SBOM data)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max request size
app.config['JSON_AS_ASCII'] = False

# Enable CORS for Next.js frontend
CORS(app, origins=["http://localhost:3000"], supports_credentials=True)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
jwt = JWTManager(app)

# In-memory storage (use database in production)
agents = {}
agent_data = {}
commands = {}
command_results = {}

# Agent timeout settings (consider agents offline after this time)
AGENT_TIMEOUT_SECONDS = 60  # 1 minute without heartbeat = offline

# Default admin credentials (change these!)
ADMIN_USERS = {
    'admin': {
        'password_hash': bcrypt.hashpw(os.getenv('ADMIN_PASSWORD', 'admin123').encode('utf-8'), bcrypt.gensalt()),
        'role': 'admin'
    }
}

def verify_password(password, password_hash):
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash)

def cleanup_offline_agents():
    """Background task to mark agents as offline if they haven't sent heartbeat recently"""
    while True:
        try:
            current_time = datetime.now()
            agents_to_update = []
            
            for agent_id, agent_info in agents.items():
                if 'last_seen' in agent_info and agent_info['last_seen']:
                    try:
                        last_seen = datetime.fromisoformat(agent_info['last_seen'])
                        time_diff = (current_time - last_seen).total_seconds()
                        
                        if time_diff > AGENT_TIMEOUT_SECONDS:
                            if agent_info.get('status') != 'offline':
                                agents_to_update.append((agent_id, 'offline'))
                        else:
                            if agent_info.get('status') != 'online':
                                agents_to_update.append((agent_id, 'online'))
                    except ValueError:
                        # Invalid datetime format, mark as offline
                        agents_to_update.append((agent_id, 'offline'))
            
            # Update agent statuses
            for agent_id, new_status in agents_to_update:
                agents[agent_id]['status'] = new_status
                print(f"Agent {agent_id} status updated to {new_status}")
                
        except Exception as e:
            print(f"Error in cleanup_offline_agents: {e}")
        
        time.sleep(10)  # Check every 10 seconds

# Start background cleanup thread
cleanup_thread = threading.Thread(target=cleanup_offline_agents, daemon=True)
cleanup_thread.start()

@app.route('/')
def dashboard():
    """Simple web dashboard"""
    dashboard_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Agent Management Dashboard</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; }
            .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
            .card { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .login-form { max-width: 400px; margin: 100px auto; }
            .form-group { margin-bottom: 15px; }
            .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
            .form-group input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
            .btn { background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
            .btn:hover { background: #2980b9; }
            .status-online { color: #27ae60; font-weight: bold; }
            .status-offline { color: #e74c3c; font-weight: bold; }
            #agents-table { width: 100%; border-collapse: collapse; }
            #agents-table th, #agents-table td { border: 1px solid #ddd; padding: 12px; text-align: left; }
            #agents-table th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔐 Secure Agent Management Dashboard</h1>
                <p>Manage your endpoint agents securely</p>
            </div>
            
            <div id="login-section">
                <div class="card login-form">
                    <h2>Authentication Required</h2>
                    <form id="login-form">
                        <div class="form-group">
                            <label>Username:</label>
                            <input type="text" id="username" required>
                        </div>
                        <div class="form-group">
                            <label>Password:</label>
                            <input type="password" id="password" required>
                        </div>
                        <button type="submit" class="btn">Login</button>
                    </form>
                </div>
            </div>
            
            <div id="dashboard-section" style="display: none;">
                <div class="card">
                    <h2>📊 Agent Overview</h2>
                    <table id="agents-table">
                        <thead>
                            <tr>
                                <th>Agent ID</th>
                                <th>Hostname</th>
                                <th>OS</th>
                                <th>Status</th>
                                <th>Last Seen</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="agents-tbody">
                            <tr><td colspan="6">No agents connected</td></tr>
                        </tbody>
                    </table>
                </div>
                
                <div class="card">
                    <h2>💻 Send Command</h2>
                    <form id="command-form">
                        <div class="form-group">
                            <label>Agent ID:</label>
                            <select id="command-agent-id" required>
                                <option value="">Select Agent</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Command:</label>
                            <input type="text" id="command" placeholder="e.g., systeminfo" required>
                        </div>
                        <button type="submit" class="btn">Send Command</button>
                    </form>
                </div>
                
                <div class="card">
                    <button onclick="logout()" class="btn" style="background: #e74c3c;">Logout</button>
                </div>
            </div>
        </div>

        <script>
            let authToken = localStorage.getItem('authToken');
            
            if (authToken) {
                showDashboard();
            }
            
            document.getElementById('login-form').addEventListener('submit', async (e) => {
                e.preventDefault();
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                
                try {
                    const response = await fetch('/api/auth/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password })
                    });
                    
                    const data = await response.json();
                    if (data.access_token) {
                        localStorage.setItem('authToken', data.access_token);
                        showDashboard();
                    } else {
                        alert('Login failed: ' + data.message);
                    }
                } catch (error) {
                    alert('Login error: ' + error.message);
                }
            });
            
            function showDashboard() {
                document.getElementById('login-section').style.display = 'none';
                document.getElementById('dashboard-section').style.display = 'block';
                loadAgents();
                setInterval(loadAgents, 5000); // Refresh every 5 seconds
            }
            
            async function loadAgents() {
                try {
                    const response = await fetch('/api/agents', {
                        headers: { 'Authorization': `Bearer ${authToken}` }
                    });
                    
                    if (response.status === 401) {
                        logout();
                        return;
                    }
                    
                    const agents = await response.json();
                    updateAgentsTable(agents);
                    updateAgentSelect(agents);
                } catch (error) {
                    console.error('Error loading agents:', error);
                }
            }
            
            function updateAgentsTable(agents) {
                const tbody = document.getElementById('agents-tbody');
                if (Object.keys(agents).length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6">No agents connected</td></tr>';
                    return;
                }
                
                tbody.innerHTML = Object.entries(agents).map(([id, agent]) => `
                    <tr>
                        <td>${id.substring(0, 12)}...</td>
                        <td>${agent.hostname || 'Unknown'}</td>
                        <td>${agent.os || 'Unknown'}</td>
                        <td class="status-online">Online</td>
                        <td>${agent.last_seen || 'Never'}</td>
                        <td><button onclick="sendCommand('${id}')" class="btn">Send Command</button></td>
                    </tr>
                `).join('');
            }
            
            function updateAgentSelect(agents) {
                const select = document.getElementById('command-agent-id');
                select.innerHTML = '<option value="">Select Agent</option>' +
                    Object.entries(agents).map(([id, agent]) => 
                        `<option value="${id}">${agent.hostname || id.substring(0, 12)} (${agent.os || 'Unknown'})</option>`
                    ).join('');
            }
            
            document.getElementById('command-form').addEventListener('submit', async (e) => {
                e.preventDefault();
                const agentId = document.getElementById('command-agent-id').value;
                const command = document.getElementById('command').value;
                
                try {
                    const response = await fetch('/api/send-command', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${authToken}`
                        },
                        body: JSON.stringify({ agent_id: agentId, command })
                    });
                    
                    const data = await response.json();
                    if (data.status === 'success') {
                        alert('Command sent successfully!');
                        document.getElementById('command').value = '';
                    } else {
                        alert('Failed to send command: ' + data.message);
                    }
                } catch (error) {
                    alert('Error sending command: ' + error.message);
                }
            });
            
            function logout() {
                localStorage.removeItem('authToken');
                location.reload();
            }
        </script>
    </body>
    </html>
    """
    return dashboard_html

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login endpoint"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400
    
    if username in ADMIN_USERS and verify_password(password, ADMIN_USERS[username]['password_hash']):
        access_token = create_access_token(identity=username)
        return jsonify({'access_token': access_token}), 200
    
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/agents', methods=['GET'])
@jwt_required()
def get_agents():
    """Get all connected agents with proper status information (protected)"""
    # Ensure all agents have proper status
    current_time = datetime.now()
    for agent_id, agent_info in agents.items():
        if 'last_seen' in agent_info and agent_info['last_seen']:
            try:
                last_seen = datetime.fromisoformat(agent_info['last_seen'])
                time_diff = (current_time - last_seen).total_seconds()
                agent_info['status'] = 'online' if time_diff <= AGENT_TIMEOUT_SECONDS else 'offline'
            except ValueError:
                agent_info['status'] = 'offline'
        else:
            agent_info['status'] = 'offline'
    
    return jsonify(agents), 200

@app.route('/api/heartbeat', methods=['POST'])
def heartbeat():
    """Receive heartbeat from agent (with API key authentication)"""
    # Check for API key in headers
    api_key = request.headers.get('X-API-Key')
    expected_key = os.getenv('AGENT_API_KEY', 'your-secret-agent-key-here')
    
    if api_key != expected_key:
        return jsonify({'error': 'Invalid API key'}), 401
    
    data = request.get_json()
    agent_id = data.get('agent_id')
      # Update agent information with current timestamp and online status
    agents[agent_id] = {
        'last_seen': datetime.now().isoformat(),
        'hostname': data.get('hostname'),
        'os': data.get('os'),
        'os_version': data.get('os_version'),
        'status': 'online'  # Always online when sending heartbeat
    }
    
    print(f"Heartbeat from {agent_id} ({data.get('hostname')})")
    return jsonify({'status': 'success'}), 200

@app.route('/api/agent-data', methods=['POST'])
def receive_agent_data():
    """Receive data from agent (with API key authentication)"""
    try:
        # Check for API key in headers
        api_key = request.headers.get('X-API-Key')
        expected_key = os.getenv('AGENT_API_KEY', 'your-secret-agent-key-here')
        
        if api_key != expected_key:
            return jsonify({'error': 'Invalid API key'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data received'}), 400
            
        agent_id = data.get('agent_id')
        message_type = data.get('message_type')
        
        if not agent_id or not message_type:
            return jsonify({'error': 'Missing agent_id or message_type'}), 400
        
        if agent_id not in agent_data:
            agent_data[agent_id] = []
        
        agent_data[agent_id].append(data)
        
        print(f"Received {message_type} from {agent_id}")
        
        # Print inventory summary
        if message_type == 'inventory':
            inventory = data.get('data', {})
            system = inventory.get('system', {})
            hardware = inventory.get('hardware', {})
            print(f"  System: {system.get('hostname')} - {system.get('os')} {system.get('os_version')}")
            print(f"  Hardware: {hardware.get('cpu_count_logical')} CPUs, {hardware.get('memory_total_gb')} GB RAM")
            
            # Check for SBOM/software data
            if 'sbom' in inventory or 'software' in inventory or 'packages' in inventory:
                sbom_data = inventory.get('sbom', inventory.get('software', inventory.get('packages', [])))
                if isinstance(sbom_data, list):
                    print(f"  SBOM: {len(sbom_data)} packages/software items found")
                elif isinstance(sbom_data, dict) and 'packages' in sbom_data:
                    print(f"  SBOM: {len(sbom_data['packages'])} packages found")
        
        # Print command result summary
        if message_type == 'command_result':
            command_id = data.get('command_id')
            result = data.get('result', {})
            command = result.get('command', 'Unknown')
            return_code = result.get('return_code', 'N/A')
            print(f"  Command Result: {command} (Return Code: {return_code})")
            if 'error' in result:
                print(f"  Error: {result['error']}")
            
            # Store command result separately for easy access
            if agent_id not in command_results:
                command_results[agent_id] = []
            command_results[agent_id].append(data)
        
        return jsonify({'status': 'success'}), 200
        
    except Exception as e:
        print(f"Error in receive_agent_data: {e}")
        print(f"Request data: {request.get_data(as_text=True)[:500]}...")  # First 500 chars for debugging
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

@app.route('/api/commands/<agent_id>', methods=['GET'])
def get_commands(agent_id):
    """Get pending commands for agent (with API key authentication)"""
    # Check for API key in headers
    api_key = request.headers.get('X-API-Key')
    expected_key = os.getenv('AGENT_API_KEY', 'your-secret-agent-key-here')
    
    if api_key != expected_key:
        return jsonify({'error': 'Invalid API key'}), 401
    
    pending_commands = commands.get(agent_id, [])
    
    # Clear commands after sending
    if agent_id in commands:
        del commands[agent_id]
    
    return jsonify(pending_commands), 200

@app.route('/api/send-command', methods=['POST'])
@jwt_required()
def send_command():
    """Send command to agent (protected)"""
    data = request.get_json()
    agent_id = data.get('agent_id')
    command = data.get('command')
    command_id = f"cmd_{int(time.time())}"
    
    if agent_id not in commands:
        commands[agent_id] = []
    
    commands[agent_id].append({
        'command_id': command_id,
        'command': command,
        'timeout': data.get('timeout', 30)
    })
    
    print(f"Command queued for {agent_id}: {command}")
    return jsonify({'status': 'success', 'command_id': command_id}), 200

@app.route('/api/request-inventory', methods=['POST'])
@jwt_required()
def request_inventory():
    """Request system inventory from agent (protected)"""
    data = request.get_json()
    agent_id = data.get('agent_id')
    command_id = f"inv_{int(time.time())}"
    
    if agent_id not in commands:
        commands[agent_id] = []
      # Send a PowerShell command to get installed software (more reliable than wmic)
    inventory_command = 'powershell "Get-WmiObject -Class Win32_Product | Select-Object Name,Version,Vendor | ConvertTo-Csv -NoTypeInformation"'
    
    commands[agent_id].append({
        'command_id': command_id,
        'command': inventory_command,
        'timeout': 60  # Longer timeout for inventory
    })
    
    print(f"Inventory request queued for {agent_id}: {inventory_command}")
    return jsonify({'status': 'success', 'command_id': command_id}), 200

@app.route('/api/agent-data/<agent_id>', methods=['GET'])
@jwt_required()
def get_agent_data(agent_id):
    """Get data for specific agent (protected)"""
    return jsonify(agent_data.get(agent_id, [])), 200

@app.route('/api/command-results/<agent_id>', methods=['GET'])
@jwt_required()
def get_command_results(agent_id):
    """Get command results for specific agent (protected)"""
    return jsonify(command_results.get(agent_id, [])), 200

@app.route('/api/agents/stats', methods=['GET'])
@jwt_required()
def get_agent_stats():
    """Get agent statistics (protected)"""
    online_count = 0
    offline_count = 0
    
    current_time = datetime.now()
    for agent_id, agent_info in agents.items():
        if 'last_seen' in agent_info and agent_info['last_seen']:
            try:
                last_seen = datetime.fromisoformat(agent_info['last_seen'])
                time_diff = (current_time - last_seen).total_seconds()
                if time_diff <= AGENT_TIMEOUT_SECONDS:
                    online_count += 1
                else:
                    offline_count += 1
            except ValueError:
                offline_count += 1
        else:
            offline_count += 1
    
    return jsonify({
        'total': len(agents),
        'online': online_count,
        'offline': offline_count
    }), 200

@app.route('/api/agent-software/<agent_id>', methods=['GET'])
@jwt_required()
def get_agent_software(agent_id):
    """Get software/SBOM data for specific agent (protected)"""
    try:
        software_data = []
        
        # Look through agent_data for inventory with software/SBOM
        if agent_id in agent_data:
            for data_entry in agent_data[agent_id]:
                if (data_entry.get('message_type') == 'inventory' and 
                    data_entry.get('data')):
                    inventory = data_entry['data']
                    
                    # Check for various software data formats
                    software_items = (inventory.get('software') or 
                                    inventory.get('applications') or 
                                    inventory.get('installed_software') or
                                    inventory.get('sbom') or
                                    inventory.get('packages'))
                    
                    # Handle SBOM format with packages array
                    if software_items and isinstance(software_items, dict) and 'packages' in software_items:
                        software_items = software_items['packages']
                    
                    if software_items and isinstance(software_items, list):
                        software_data = [{
                            'name': item.get('name') or item.get('displayName') or item.get('package_name') or 'Unknown',
                            'version': item.get('version') or item.get('package_version') or 'Unknown',
                            'publisher': item.get('publisher') or item.get('vendor') or item.get('supplier') or 'Unknown',
                            'timestamp': data_entry.get('timestamp')
                        } for item in software_items]
                        break  # Use the most recent inventory data
        
        return jsonify({
            'agent_id': agent_id,
            'software_count': len(software_data),
            'software': software_data
        }), 200
        
    except Exception as e:
        print(f"Error getting software data for {agent_id}: {e}")
        return jsonify({'error': 'Failed to get software data', 'details': str(e)}), 500

@app.route('/api/request-hardening-audit', methods=['POST'])
@jwt_required()
def request_hardening_audit():
    """Request hardening audit from agent (protected)"""
    data = request.get_json()
    agent_id = data.get('agent_id')
    finding_list = data.get('finding_list', '')  # Optional custom finding list
    
    if not agent_id:
        return jsonify({'error': 'agent_id required'}), 400
    
    # Check if agent exists
    if agent_id not in agents:
        return jsonify({'error': 'Agent not found'}), 404
    
    # Generate unique command ID
    command_id = f"hardening_audit_{int(time.time())}"
    
    # Build hardening audit command
    if finding_list:
        audit_command = f"RUN_HARDENING_AUDIT:{finding_list}"
    else:
        audit_command = "RUN_HARDENING_AUDIT"
    
    # Add command to queue
    if agent_id not in commands:
        commands[agent_id] = []
    
    commands[agent_id].append({
        'command_id': command_id,
        'command': audit_command,
        'timeout': 300  # 5 minute timeout for hardening audit
    })
    
    print(f"Hardening audit request queued for {agent_id}: {audit_command}")
    return jsonify({'status': 'success', 'command_id': command_id}), 200

@app.route('/api/get-hardening-status', methods=['POST'])
@jwt_required()
def get_hardening_status():
    """Get hardening status from agent (protected)"""
    data = request.get_json()
    agent_id = data.get('agent_id')
    
    if not agent_id:
        return jsonify({'error': 'agent_id required'}), 400
    
    # Check if agent exists
    if agent_id not in agents:
        return jsonify({'error': 'Agent not found'}), 404
    
    # Generate unique command ID
    command_id = f"hardening_status_{int(time.time())}"
    
    # Add command to queue
    if agent_id not in commands:
        commands[agent_id] = []
    
    commands[agent_id].append({
        'command_id': command_id,
        'command': "GET_HARDENING_STATUS",
        'timeout': 60
    })
    
    print(f"Hardening status request queued for {agent_id}")
    return jsonify({'status': 'success', 'command_id': command_id}), 200

@app.route('/api/hardening-results/<agent_id>', methods=['GET'])
@jwt_required()
def get_hardening_results(agent_id):
    """Get hardening results for specific agent (protected)"""
    # Get command results and filter for hardening-related commands
    agent_results = command_results.get(agent_id, [])
    hardening_results = []
    
    for result in agent_results:
        command = result.get('command', '').upper()
        if any(hardening_cmd in command for hardening_cmd in ['RUN_HARDENING_AUDIT', 'GET_HARDENING_STATUS']):
            hardening_results.append(result)
    
    return jsonify(hardening_results), 200

if __name__ == '__main__':
    print("🔐 Starting Secure Agent Management Server...")
    print("📊 Dashboard available at: http://localhost:8080")
    print("🔑 Default login: admin / admin123")
    print("⚠️  Change default password in production!")
    print("🌍 Set AGENT_API_KEY environment variable for agent authentication")
    
    # Create .env file if it doesn't exist
    if not os.path.exists('.env'):
        with open('.env', 'w') as f:
            f.write(f"JWT_SECRET_KEY={secrets.token_hex(32)}\n")
            f.write("ADMIN_PASSWORD=admin123\n")
            f.write("AGENT_API_KEY=your-secret-agent-key-here\n")
        print("📝 Created .env file with default settings")
    
    app.run(host='0.0.0.0', port=8080, debug=False)
