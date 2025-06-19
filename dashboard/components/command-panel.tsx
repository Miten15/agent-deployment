"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Terminal, Send, Package, RefreshCw } from "lucide-react"
import { apiClient } from "@/lib/api"
import { useToast } from "@/hooks/use-toast"
import { eventBus } from "@/lib/events"

interface Agent {
  last_seen: string
  hostname: string
  os: string
  status: string
  latest_command?: {
    command: string
    timestamp: string
  }
}

interface CommandPanelProps {
  preselectedAgent?: string
}

export function CommandPanel({ preselectedAgent }: CommandPanelProps = {}) {
  const [agents, setAgents] = useState<Record<string, Agent>>({})
  const [selectedAgent, setSelectedAgent] = useState<string>("")
  const [command, setCommand] = useState<string>("")
  const [isLoading, setIsLoading] = useState(false)
  const [isSendingCommand, setIsSendingCommand] = useState(false)
  const [isRequestingInventory, setIsRequestingInventory] = useState(false)
  const { toast } = useToast()
  useEffect(() => {
    loadAgents()
    // Auto-refresh agents every 5 seconds
    const interval = setInterval(loadAgents, 5000)
    return () => clearInterval(interval)
  }, [])

  // Effect to handle preselected agent
  useEffect(() => {
    if (preselectedAgent && agents[preselectedAgent]) {
      setSelectedAgent(preselectedAgent)
    }
  }, [preselectedAgent, agents])

  const loadAgents = async () => {
    try {
      setIsLoading(true)
      const agentsData = await apiClient.getAgents()
      setAgents(agentsData)
    } catch (error) {
      console.error('Failed to load agents:', error)
      // Don't show toast for auto-refresh failures to avoid spam
    } finally {
      setIsLoading(false)
    }
  }

  const sendCommand = async () => {
    if (!selectedAgent || !command.trim()) {
      toast({
        title: "Error",
        description: "Please select an agent and enter a command",
        variant: "destructive",
      })
      return
    }

    setIsSendingCommand(true)
    try {
      await apiClient.sendCommand(selectedAgent, command.trim())
      
      // Check if command might install/remove software
      const softwareCommands = [
        'winget install', 'winget uninstall', 'choco install', 'choco uninstall',
        'apt install', 'apt remove', 'yum install', 'yum remove',
        'pip install', 'pip uninstall', 'npm install', 'npm uninstall'
      ]
      
      const commandLower = command.trim().toLowerCase()
      const mightAffectSoftware = softwareCommands.some(cmd => commandLower.includes(cmd))
        if (mightAffectSoftware) {
        toast({
          title: "Success",
          description: "Command sent! Software inventory will be updated automatically in 10 seconds.",
        })
        
        // Emit event to notify software page
        eventBus.emit('software-command-sent', { agentId: selectedAgent, command: command.trim() })
        
        // Auto-request inventory update after software installation commands
        setTimeout(async () => {
          try {
            await apiClient.requestInventory(selectedAgent)
            eventBus.emit('software-inventory-requested', { agentId: selectedAgent })
            toast({
              title: "Info",
              description: "Software inventory updated automatically",
            })
          } catch (error) {
            console.error('Auto inventory update failed:', error)
          }
        }, 10000) // Wait 10 seconds for command to complete
      } else {
        toast({
          title: "Success",
          description: "Command sent successfully!",
        })
      }
      
      setCommand("")
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to send command",
        variant: "destructive",
      })
    } finally {
      setIsSendingCommand(false)
    }
  }
  const requestInventory = async () => {
    if (!selectedAgent) {
      toast({
        title: "Error",
        description: "Please select an agent first",
        variant: "destructive",
      })
      return
    }

    setIsRequestingInventory(true)
    try {
      await apiClient.requestInventory(selectedAgent)
      eventBus.emit('software-inventory-requested', { agentId: selectedAgent })
      toast({
        title: "Success",
        description: "Software inventory request sent! Check the Software section in a few seconds.",
      })
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to request software inventory",
        variant: "destructive",
      })
    } finally {
      setIsRequestingInventory(false)
    }
  }

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendCommand()
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Terminal className="h-5 w-5" />
          Command Execution
        </CardTitle>
        <CardDescription>
          Send commands to connected agents and request system information
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="agent-select">Select Agent</Label>
          <div className="flex items-center gap-2">
            <Select value={selectedAgent} onValueChange={setSelectedAgent}>
              <SelectTrigger id="agent-select">
                <SelectValue placeholder="Choose an agent to send commands" />
              </SelectTrigger>
              <SelectContent>
                {Object.keys(agents).length === 0 ? (
                  <SelectItem value="no-agents" disabled>
                    No agents connected
                  </SelectItem>
                ) : (                  Object.entries(agents).map(([id, agent]) => (
                    <SelectItem key={id} value={id} disabled={agent.status === 'offline'}>
                      <div className="flex items-center gap-2">
                        <Badge 
                          variant="outline" 
                          className={`${
                            agent.status === 'online' 
                              ? 'bg-green-500/10 text-green-600 border-green-500/20' 
                              : 'bg-red-500/10 text-red-600 border-red-500/20'
                          }`}
                        >
                          ●
                        </Badge>
                        {agent.hostname || id.substring(0, 12)} ({agent.os || 'Unknown'})
                        {agent.status === 'offline' && (
                          <Badge variant="secondary" className="text-xs">Offline</Badge>
                        )}
                      </div>
                    </SelectItem>
                  ))
                )}
              </SelectContent>
            </Select>
            <Button
              variant="outline"
              size="icon"
              onClick={loadAgents}
              disabled={isLoading}
            >
              <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
            </Button>
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="command-input">Command</Label>
          <div className="flex gap-2">
            <Input
              id="command-input"
              value={command}
              onChange={(e) => setCommand(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="e.g., dir, systeminfo, whoami, ps"
              disabled={!selectedAgent || isSendingCommand}
            />
            <Button
              onClick={sendCommand}
              disabled={!selectedAgent || !command.trim() || isSendingCommand}
            >
              {isSendingCommand ? (
                <RefreshCw className="h-4 w-4 animate-spin" />
              ) : (
                <Send className="h-4 w-4" />
              )}
            </Button>
          </div>
        </div>

        <div className="flex gap-2">
          <Button
            variant="secondary"
            onClick={requestInventory}
            disabled={!selectedAgent || isRequestingInventory}
            className="flex items-center gap-2"
          >
            {isRequestingInventory ? (
              <RefreshCw className="h-4 w-4 animate-spin" />
            ) : (
              <Package className="h-4 w-4" />
            )}
            Get Installed Software
          </Button>
        </div>

        {selectedAgent && agents[selectedAgent] && (
          <div className="mt-4 p-3 bg-muted rounded-lg">
            <div className="text-sm space-y-1">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Selected Agent:</span>
                <span className="font-mono text-xs">{selectedAgent.substring(0, 12)}...</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Hostname:</span>
                <span>{agents[selectedAgent].hostname}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">OS:</span>
                <span>{agents[selectedAgent].os}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Last Seen:</span>
                <span>{new Date(agents[selectedAgent].last_seen).toLocaleString()}</span>
              </div>
            </div>
          </div>
        )}

        <div className="text-xs text-muted-foreground">
          <p>• Commands are executed on the selected agent</p>
          <p>• Check Command History page to see command results</p>
          <p>• Use "Get Installed Software" for comprehensive software inventory</p>
        </div>
      </CardContent>
    </Card>
  )
}
