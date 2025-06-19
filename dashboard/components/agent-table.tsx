"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent } from "@/components/ui/card"
import { MoreHorizontal, Search, Terminal, Info, Monitor } from "lucide-react"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import type { Agent } from "@/types"
import { formatDistanceToNow } from "date-fns"

interface AgentTableProps {
  agents: Record<string, Agent>
  isLoading: boolean
}

export function AgentTable({ agents, isLoading }: AgentTableProps) {
  const [searchTerm, setSearchTerm] = useState("")
  const [isMobile, setIsMobile] = useState(false)
  const router = useRouter()

  const filteredAgents = Object.entries(agents).map(([id, agent]) => ({
    ...agent,
    id
  })).filter(
    (agent) =>
      (agent.hostname || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (agent.os || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (agent.id || '').toLowerCase().includes(searchTerm.toLowerCase()),
  )

  if (isLoading) {
    return (
      <div className="space-y-4">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="h-16 bg-muted animate-pulse rounded-lg" />
        ))}
      </div>
    )
  }

  // Helper function to safely format relative time
  const formatRelativeTime = (dateString: string | undefined): string => {
    if (!dateString) return 'Unknown'
    const date = new Date(dateString)
    return isNaN(date.getTime()) ? 'Unknown' : formatDistanceToNow(date) + ' ago'
  }

  const AgentCard = ({ agent }: { agent: Agent }) => (
    <Card className="mb-4">
      <CardContent className="p-4">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <Monitor className="h-4 w-4 text-muted-foreground" />
            <span className="font-medium">{agent.hostname}</span>
          </div>
          <Badge variant={agent.status === "online" ? "default" : "destructive"}>
            {agent.status === "online" ? "Online" : "Offline"}
          </Badge>
        </div>
        <div className="space-y-1 text-sm text-muted-foreground">
          <div>ID: {agent.id.substring(0, 12)}...</div>
          <div>OS: {agent.os}{agent.os_version ? ` ${agent.os_version}` : ''}</div>
          <div>Last seen: {formatRelativeTime(agent.lastSeen)}</div>
          {agent.latestCommand && <div>Latest: {agent.latestCommand.command}</div>}
        </div>
        <div className="flex gap-2 mt-3">
          <Button 
            size="sm" 
            variant="outline"
            onClick={() => router.push(`/dashboard/commands?agent=${agent.id}`)}
          >
            <Terminal className="h-3 w-3 mr-1" />
            Command
          </Button>
          <Button 
            size="sm" 
            variant="outline"
            onClick={() => router.push(`/dashboard/agents/${agent.id}`)}
          >
            <Info className="h-3 w-3 mr-1" />
            Info
          </Button>
        </div>
      </CardContent>
    </Card>
  )

  return (
    <div className="space-y-4">
      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search agents..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="pl-10"
        />
      </div>

      {/* Mobile View */}
      <div className="block md:hidden">
        {filteredAgents.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground">No agents found</div>
        ) : (
          filteredAgents.map((agent) => <AgentCard key={agent.id} agent={agent} />)
        )}
      </div>

      {/* Desktop View */}
      <div className="hidden md:block">
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Agent ID</TableHead>
                <TableHead>Hostname</TableHead>
                <TableHead>OS</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last Seen</TableHead>
                <TableHead>Latest Command</TableHead>
                <TableHead className="w-[100px]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredAgents.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                    No agents found
                  </TableCell>
                </TableRow>
              ) : (
                filteredAgents.map((agent) => (
                  <TableRow key={agent.id || 'unknown'}>
                    <TableCell className="font-mono text-sm">
                      {agent.id ? agent.id.substring(0, 12) + '...' : 'Unknown'}
                    </TableCell>
                    <TableCell className="font-medium">{agent.hostname || 'Unknown'}</TableCell>
                    <TableCell>{agent.os ? `${agent.os}${agent.os_version ? ` ${agent.os_version}` : ''}` : 'Unknown'}</TableCell>
                    <TableCell>
                      <Badge 
                        variant={agent.status === "online" ? "default" : "destructive"} 
                        className="gap-1"
                      >
                        <div className={`h-2 w-2 rounded-full ${
                          agent.status === "online" 
                            ? "bg-green-500 animate-pulse" 
                            : "bg-red-500"
                        }`} />
                        {agent.status === "online" ? "Online" : "Offline"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {formatRelativeTime(agent.lastSeen)}
                    </TableCell>
                    <TableCell className="text-sm">
                      {agent.latestCommand ? (
                        <div>
                          <div className="font-mono text-xs">{agent.latestCommand.command}</div>
                          <div className="text-xs text-muted-foreground">
                            {agent.latestCommand?.timestamp ? formatRelativeTime(agent.latestCommand.timestamp) : 'Unknown'}
                          </div>
                        </div>
                      ) : (
                        <span className="text-muted-foreground">No commands</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" className="h-8 w-8 p-0">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => router.push(`/dashboard/commands?agent=${agent.id}`)}>
                            <Terminal className="mr-2 h-4 w-4" />
                            Send Command
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => router.push(`/dashboard/agents/${agent.id}`)}>
                            <Info className="mr-2 h-4 w-4" />
                            View Details
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </div>
    </div>
  )
}
