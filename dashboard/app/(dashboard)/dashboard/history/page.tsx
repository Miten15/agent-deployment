"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { RefreshCw, Search, Maximize2, Minimize2, Clock, CheckCircle, XCircle, Copy } from "lucide-react"
import { apiClient } from "@/lib/api"
import { useToast } from "@/hooks/use-toast"

interface CommandResult {
  command_id: string
  timestamp: string
  result: {
    command: string
    return_code: number
    success: boolean
    output?: string
    stdout?: string
    error?: string
    stderr?: string
  }
}

export default function CommandHistoryPage() {
  const [agents, setAgents] = useState<Record<string, any>>({})
  const [selectedAgent, setSelectedAgent] = useState<string>("")
  const [commandHistory, setCommandHistory] = useState<CommandResult[]>([])
  const [searchTerm, setSearchTerm] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const [isFullScreen, setIsFullScreen] = useState(false)
  const { toast } = useToast()

  useEffect(() => {
    loadAgents()
  }, [])

  useEffect(() => {
    if (selectedAgent) {
      loadCommandHistory()
    }
  }, [selectedAgent])

  const loadAgents = async () => {
    try {
      const agentsData = await apiClient.getAgents()
      setAgents(agentsData)
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to load agents",
        variant: "destructive",
      })
    }
  }

  const loadCommandHistory = async () => {
    if (!selectedAgent) return
    
    setIsLoading(true)
    try {
      const results = await apiClient.getCommandResults(selectedAgent)
      setCommandHistory(results.reverse()) // Show newest first
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to load command history",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text)
      toast({
        title: "Copied",
        description: "Content copied to clipboard",
      })
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to copy to clipboard",
        variant: "destructive",
      })
    }
  }
  const filteredHistory = commandHistory.filter(item =>
    (item.result?.command || "").toLowerCase().includes(searchTerm.toLowerCase()) ||
    (item.result?.output || item.result?.stdout || "").toLowerCase().includes(searchTerm.toLowerCase())
  )

  const getStatusIcon = (success: boolean, returnCode: number) => {
    if (success && returnCode === 0) {
      return <CheckCircle className="h-4 w-4 text-green-500" />
    }
    return <XCircle className="h-4 w-4 text-red-500" />
  }

  const getStatusBadge = (success: boolean, returnCode: number) => {
    if (success && returnCode === 0) {
      return <Badge variant="default" className="bg-green-500">Success</Badge>
    }
    return <Badge variant="destructive">Failed</Badge>
  }

  return (
    <div className={`space-y-6 ${isFullScreen ? 'fixed inset-4 z-50 bg-background p-6 rounded-lg shadow-2xl overflow-hidden' : ''}`}>
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Command History</h1>
          <p className="text-muted-foreground">View execution history and results for agent commands</p>
        </div>
        <Button
          variant="outline"
          size="icon"
          onClick={() => setIsFullScreen(!isFullScreen)}
        >
          {isFullScreen ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5" />
            Agent Selection & Filters
          </CardTitle>
          <CardDescription>
            Select an agent to view its command execution history
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4">            <div className="flex-1">
              <Select value={selectedAgent} onValueChange={setSelectedAgent}>
                <SelectTrigger>
                  <SelectValue placeholder="Select an online agent" />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(agents)
                    .filter(([id, agent]) => agent.status === 'online')
                    .map(([id, agent]) => (
                    <SelectItem key={id} value={id}>
                      {agent.hostname || id.substring(0, 12)} ({agent.os || 'Unknown'})
                      <Badge variant="default" className="ml-2 bg-green-500 text-white">Online</Badge>
                    </SelectItem>
                  ))}
                  {Object.entries(agents).filter(([id, agent]) => agent.status === 'online').length === 0 && (
                    <SelectItem value="none" disabled>
                      No online agents available
                    </SelectItem>
                  )}
                </SelectContent>
              </Select>
            </div>
            <Button onClick={loadCommandHistory} disabled={!selectedAgent || isLoading}>
              <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>

          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
            <Input
              placeholder="Search commands and output..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10"
            />
          </div>
        </CardContent>
      </Card>

      {selectedAgent && (
        <Card className="flex-1 min-h-0">
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>Command History ({filteredHistory.length} results)</span>
              {commandHistory.length > 0 && (
                <Badge variant="outline">
                  Agent: {agents[selectedAgent]?.hostname || selectedAgent.substring(0, 12)}
                </Badge>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <ScrollArea className={`${isFullScreen ? 'h-[calc(100vh-300px)]' : 'h-[600px]'} px-6 pb-6`}>
              {isLoading ? (
                <div className="flex items-center justify-center py-12">
                  <RefreshCw className="h-8 w-8 animate-spin" />
                </div>
              ) : filteredHistory.length === 0 ? (
                <div className="text-center py-12">
                  <p className="text-muted-foreground">
                    {searchTerm ? "No matching commands found" : "No command history available for this agent"}
                  </p>
                </div>
              ) : (
                <div className="space-y-4">
                  {filteredHistory.map((item, index) => (
                    <div key={`${item.command_id}-${index}`} className="border rounded-lg p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          {getStatusIcon(item.result.success, item.result.return_code)}
                          <code className="text-sm font-mono bg-muted px-2 py-1 rounded">
                            {item.result.command}
                          </code>
                        </div>
                        <div className="flex items-center gap-2">
                          {getStatusBadge(item.result.success, item.result.return_code)}
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => copyToClipboard(item.result.command)}
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>

                      <div className="text-sm text-muted-foreground flex items-center gap-4">
                        <span>Time: {new Date(item.timestamp).toLocaleString()}</span>
                        <span>Return Code: {item.result.return_code}</span>
                      </div>

                      {(item.result.output || item.result.stdout) && (
                        <div>
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-sm font-medium">Output:</span>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyToClipboard(item.result.output || item.result.stdout || '')}
                            >
                              <Copy className="h-3 w-3" />
                            </Button>
                          </div>
                          <pre className="text-xs bg-muted p-3 rounded border overflow-x-auto whitespace-pre-wrap max-h-64 overflow-y-auto">
                            {(item.result.output || item.result.stdout || '').trim()}
                          </pre>
                        </div>
                      )}

                      {(item.result.error || item.result.stderr) && (
                        <div>
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-sm font-medium text-red-500">Error:</span>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyToClipboard(item.result.error || item.result.stderr || '')}
                            >
                              <Copy className="h-3 w-3" />
                            </Button>
                          </div>
                          <pre className="text-xs bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300 p-3 rounded border overflow-x-auto whitespace-pre-wrap max-h-64 overflow-y-auto">
                            {(item.result.error || item.result.stderr || '').trim()}
                          </pre>
                        </div>
                      )}

                      {index < filteredHistory.length - 1 && <Separator className="mt-4" />}
                    </div>
                  ))}
                </div>
              )}
            </ScrollArea>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
