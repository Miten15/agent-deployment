// API utility functions
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080'

class ApiClient {
  private getAuthHeaders() {
    const token = localStorage.getItem('authToken')
    return {
      'Content-Type': 'application/json',
      ...(token && { 'Authorization': `Bearer ${token}` }),
    }
  }
  private async handleResponse<T>(response: Response): Promise<T> {
    if (response.status === 401) {
      localStorage.removeItem('authToken')
      window.location.href = '/login'
      throw new Error('Authentication required')
    }

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      throw new Error(errorData.message || `HTTP error! status: ${response.status}`)
    }

    return response.json()
  }

  // Authentication
  async login(username: string, password: string) {
    const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
    return this.handleResponse<{ access_token: string }>(response)
  }

  // Agents
  async getAgents() {
    const response = await fetch(`${API_BASE_URL}/api/agents`, {
      headers: this.getAuthHeaders(),
    })
    return this.handleResponse<Record<string, any>>(response)
  }

  async getAgentStats() {
    const response = await fetch(`${API_BASE_URL}/api/agents/stats`, {
      headers: this.getAuthHeaders(),
    })
    return this.handleResponse<{ total: number; online: number; offline: number }>(response)
  }

  async getAgentData(agentId: string) {
    const response = await fetch(`${API_BASE_URL}/api/agent-data/${agentId}`, {
      headers: this.getAuthHeaders(),
    })
    return this.handleResponse<any[]>(response)
  }

  async getAgentSoftware(agentId: string) {
    const response = await fetch(`${API_BASE_URL}/api/agent-software/${agentId}`, {
      headers: this.getAuthHeaders(),
    })
    return this.handleResponse<{ agent_id: string; software_count: number; software: any[] }>(response)
  }

  // Commands
  async sendCommand(agentId: string, command: string, timeout?: number) {
    const response = await fetch(`${API_BASE_URL}/api/send-command`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify({ agent_id: agentId, command, timeout }),
    })
    return this.handleResponse<{ status: string; command_id: string }>(response)
  }

  async getCommandResults(agentId: string) {
    const response = await fetch(`${API_BASE_URL}/api/command-results/${agentId}`, {
      headers: this.getAuthHeaders(),
    })
    return this.handleResponse<any[]>(response)
  }

  async requestInventory(agentId: string) {
    const response = await fetch(`${API_BASE_URL}/api/request-inventory`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify({ agent_id: agentId }),
    })
    return this.handleResponse<{ status: string; command_id: string }>(response)
  }
}

export const apiClient = new ApiClient()


