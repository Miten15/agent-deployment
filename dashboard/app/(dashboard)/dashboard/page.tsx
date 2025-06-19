"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { AgentTable } from "@/components/agent-table"
import { CommandPanel } from "@/components/command-panel"
import { SystemStats } from "@/components/system-stats"
import { ActivityChart } from "@/components/activity-chart"
import { Server, Users, Activity, Shield } from "lucide-react"
import { apiClient } from "@/lib/api"
import { useToast } from "@/hooks/use-toast"
import type { Agent } from "@/types"

export default function DashboardPage() {
  const [agents, setAgents] = useState<Record<string, Agent>>({})
  const [agentStats, setAgentStats] = useState({ total: 0, online: 0, offline: 0 })
  const [isLoading, setIsLoading] = useState(true)
  const { toast } = useToast()

  useEffect(() => {
    // Load initial data
    loadData()

    // Set up auto-refresh every 5 seconds for more responsive updates
    const interval = setInterval(loadData, 5000)
    return () => clearInterval(interval)
  }, [])

  const loadData = async () => {
    try {
      // Load agents and stats in parallel
      const [agentsData, statsData] = await Promise.all([
        apiClient.getAgents(),
        apiClient.getAgentStats()
      ])
      
      setAgents(agentsData)
      setAgentStats(statsData)
    } catch (error) {
      console.error('Failed to load data:', error)
      toast({
        title: "Error",
        description: "Failed to load agent data",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  const agentCount = agentStats.total
  const onlineCount = agentStats.online
  const offlineCount = agentStats.offline

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground">Monitor and manage your endpoint agents</p>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Agents</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{agentCount}</div>
            <p className="text-xs text-muted-foreground">Connected endpoints</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Online</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{onlineCount}</div>
            <p className="text-xs text-muted-foreground">Active connections</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Offline</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{offlineCount}</div>
            <p className="text-xs text-muted-foreground">Disconnected agents</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Security Status</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">Secure</div>
            <p className="text-xs text-muted-foreground">All systems protected</p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Grid */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Agent Overview */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Server className="h-5 w-5" />
                Agent Overview
              </CardTitle>
              <CardDescription>Real-time status of all connected agents</CardDescription>
            </CardHeader>
            <CardContent>
              <AgentTable agents={agents} isLoading={isLoading} />
            </CardContent>
          </Card>
        </div>

        {/* Command Panel */}
        <div>
          <CommandPanel />
        </div>
      </div>

      {/* Additional Sections */}
      <div className="grid gap-6 lg:grid-cols-2">
        <SystemStats />
        <ActivityChart />
      </div>
    </div>
  )
}
