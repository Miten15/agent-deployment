"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { AgentTable } from "@/components/agent-table"
import { Server } from "lucide-react"
import { apiClient } from "@/lib/api"
import { useToast } from "@/hooks/use-toast"
import type { Agent } from "@/types"

export default function AgentsPage() {
  const [agents, setAgents] = useState<Record<string, Agent>>({})
  const [isLoading, setIsLoading] = useState(true)
  const { toast } = useToast()

  useEffect(() => {
    loadAgents()
    
    // Set up auto-refresh every 5 seconds
    const interval = setInterval(loadAgents, 5000)
    return () => clearInterval(interval)
  }, [])

  const loadAgents = async () => {
    try {
      const agentsData = await apiClient.getAgents()
      
      // Transform the data to match our Agent interface
      const transformedAgents: Record<string, Agent> = {}
      
      Object.entries(agentsData).forEach(([id, agent]: [string, any]) => {
        transformedAgents[id] = {
          id,
          hostname: agent.hostname || 'Unknown',
          os: agent.os || 'Unknown',
          status: 'online', // Agents in the list are online
          lastSeen: agent.last_seen,
          latestCommand: agent.latest_command ? {
            command: agent.latest_command.command || 'N/A',
            timestamp: agent.latest_command.timestamp || agent.last_seen,
            status: agent.latest_command.status || 'success'
          } : undefined
        }
      })
      
      setAgents(transformedAgents)
    } catch (error: any) {
      console.error('Failed to load agents:', error)
      toast({
        title: "Connection Error",
        description: "Failed to connect to the server. Please ensure the Flask server is running on localhost:8080",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Agent Management</h1>
        <p className="text-muted-foreground">Monitor and manage all connected endpoint agents</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Server className="h-5 w-5" />
            Connected Agents
          </CardTitle>
          <CardDescription>Real-time status and information for all agents</CardDescription>
        </CardHeader>
        <CardContent>
          <AgentTable agents={agents} isLoading={isLoading} />
        </CardContent>
      </Card>
    </div>
  )
}
