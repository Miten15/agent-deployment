'use client'

import { useState, useEffect } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { useToast } from '@/hooks/use-toast'
import { apiClient } from '@/lib/api'
import { 
  ArrowLeft,
  Monitor,
  Cpu,
  HardDrive,
  Network,
  Shield,
  Clock,
  MapPin,
  User,
  Settings,
  Activity,
  Terminal,
  RefreshCw,
  AlertCircle,
  CheckCircle,
  Info,
  Plus,
  ChevronDown,
  ChevronUp
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import type { Agent } from '@/types'

export default function AgentDetailsPage() {
  const params = useParams()
  const router = useRouter()
  const { toast } = useToast()
  const [agent, setAgent] = useState<Agent | null>(null)
  const [agentData, setAgentData] = useState<any[]>([])
  const [commandResults, setCommandResults] = useState<any[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [showAllIPs, setShowAllIPs] = useState(false)

  const agentId = params.id as string

  useEffect(() => {
    if (agentId) {
      loadAgentDetails()
    }
  }, [agentId])

  const loadAgentDetails = async () => {
    try {
      setIsLoading(true)
      
      // Get all agents and find the specific one
      const agents = await apiClient.getAgents()
      const currentAgent = agents[agentId]
      
      if (!currentAgent) {
        toast({
          title: "Agent Not Found",
          description: "The requested agent could not be found.",
          variant: "destructive",
        })
        router.push('/dashboard/agents')
        return
      }

      setAgent({ 
        ...currentAgent, 
        id: agentId,
        lastSeen: currentAgent.last_seen // Map the server property to client property
      })
      
      // Get additional agent data
      const [agentDataResult, commandResultsData] = await Promise.all([
        apiClient.getAgentData(agentId),
        apiClient.getCommandResults(agentId)
      ])
      
      setAgentData(agentDataResult)
      setCommandResults(commandResultsData)
      
    } catch (error) {
      console.error('Error loading agent details:', error)
      toast({
        title: "Error",
        description: "Failed to load agent details.",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  const refreshData = async () => {
    setIsRefreshing(true)
    await loadAgentDetails()
    setIsRefreshing(false)
    
    toast({
      title: "Refreshed",
      description: "Agent details have been updated.",
    })
  }

  const handleSendCommand = () => {
    router.push(`/dashboard/commands?agent=${agentId}`)
  }
  
  const formatRelativeTime = (dateString: string | undefined): string => {
    if (!dateString) return 'Unknown'
    const date = new Date(dateString)
    return isNaN(date.getTime()) ? 'Unknown' : formatDistanceToNow(date) + ' ago'
  }

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div className="h-8 bg-muted animate-pulse rounded-lg w-1/3" />
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="h-32 bg-muted animate-pulse rounded-lg" />
          ))}
        </div>
      </div>
    )
  }

  if (!agent) {
    return (
      <div className="p-6">
        <Alert>
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Agent Not Found</AlertTitle>
          <AlertDescription>
            The requested agent could not be found. It may have been disconnected or removed.
          </AlertDescription>
        </Alert>
      </div>
    )
  }
  // Get the latest inventory data
  const latestInventory = agentData
    .filter(data => data.message_type === 'inventory')    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())[0]
  const systemInfo = latestInventory?.data?.system || {}  
  const hardwareInfo = latestInventory?.data?.hardware || {}
  const diskInfo = latestInventory?.data?.disk || {}  
  const networkData = latestInventory?.data?.network || {}
  // Fix: networkData is the interfaces object, not networkData.interfaces
  const networkInterfaces = networkData
  
  // Debug logging for network data
  console.log('Agent Details - latestInventory:', latestInventory)
  console.log('Agent Details - networkData:', networkData)
  console.log('Agent Details - networkInterfaces:', networkInterfaces)
    // Helper function to extract IP addresses from network interfaces
  const getIPAddresses = (interfaces: any) => {
    const allIPs: string[] = []
    
    // Debug logging
    console.log('getIPAddresses - interfaces:', interfaces)
    
    if (!interfaces || typeof interfaces !== 'object') {
      console.log('getIPAddresses - interfaces is null or not object')
      return { primary: 'Unknown', all: [] }
    }
    
    // Iterate through all network interfaces
    Object.entries(interfaces).forEach(([interfaceName, interfaceData]: [string, any]) => {
      console.log(`getIPAddresses - processing interface ${interfaceName}:`, interfaceData)
      
      if (interfaceData && typeof interfaceData === 'object') {
        // Handle different data formats
        
        // Format 1: Direct IP field {ip, subnet, mac}
        if ((interfaceData as any).ip) {
          const ip = (interfaceData as any).ip;
          console.log(`getIPAddresses - found direct IP ${ip} for ${interfaceName}`)
          if (ip && 
              ip !== '127.0.0.1' && 
              ip !== '::1' && 
              !ip.startsWith('169.254.')) { // Filter out loopback and link-local
            allIPs.push(ip);
          }
        }        // Format 2: Addresses array from psutil
        else if ((interfaceData as any).addresses && Array.isArray((interfaceData as any).addresses)) {
          const addresses = (interfaceData as any).addresses;
          console.log(`getIPAddresses - found addresses array for ${interfaceName}:`, addresses)
          addresses.forEach((addr: any) => {
            if (addr.address && addr.family) {
              const address = addr.address;
              const family = addr.family;
              
              // IPv4 addresses (family = "2" or "AddressFamily.AF_INET")
              if ((family === '2' || family === 'AddressFamily.AF_INET' || family.includes('AF_INET')) && 
                  address !== '127.0.0.1' && 
                  !address.startsWith('169.254.')) { // Filter out loopback and link-local
                console.log(`getIPAddresses - found IPv4 address ${address} for ${interfaceName}`)
                allIPs.push(address);
              }
            }
          });
        }
      }
    })
    
    console.log('getIPAddresses - final IPs:', allIPs)
    // Return primary (first valid IP) and all IPs
    return {
      primary: allIPs.length > 0 ? allIPs[0] : 'Unknown',
      all: allIPs
    }
  }
  
  const ipAddresses = getIPAddresses(networkInterfaces)

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => router.push('/dashboard/agents')}
            className="flex items-center gap-2"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Agents
          </Button>
          <Separator orientation="vertical" className="h-6" />
          <div>
            <h1 className="text-3xl font-bold flex items-center gap-2">
              <Monitor className="w-8 h-8 text-blue-600" />
              {agent.hostname || 'Unknown Agent'}
            </h1>
            <p className="text-muted-foreground">
              Agent ID: {agent.id}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            onClick={refreshData}
            disabled={isRefreshing}
            className="flex items-center gap-2"
          >
            <RefreshCw className={`h-4 w-4 ${isRefreshing ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button
            onClick={handleSendCommand}
            className="flex items-center gap-2"
          >
            <Terminal className="h-4 w-4" />
            Send Command
          </Button>
        </div>
      </div>

      {/* Status Banner */}
      <Alert className={agent.status === 'online' ? 'border-green-200 bg-green-50' : 'border-red-200 bg-red-50'}>
        {agent.status === 'online' ? (
          <CheckCircle className="h-4 w-4 text-green-600" />
        ) : (
          <AlertCircle className="h-4 w-4 text-red-600" />
        )}
        <AlertTitle className={agent.status === 'online' ? 'text-green-800' : 'text-red-800'}>
          Agent Status: {agent.status === 'online' ? 'Online' : 'Offline'}
        </AlertTitle>
        <AlertDescription className={agent.status === 'online' ? 'text-green-700' : 'text-red-700'}>
          Last seen: {formatRelativeTime(agent.lastSeen)}
          {agent.latestCommand && (
            <span className="ml-4">
              Latest command: {agent.latestCommand.command}
            </span>
          )}
        </AlertDescription>
      </Alert>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Basic Information */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Info className="h-5 w-5" />
              Basic Information
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 gap-3">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Hostname</label>
                <p className="text-sm font-mono">{agent.hostname || 'Unknown'}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Operating System</label>
                <p className="text-sm">{agent.os ? `${agent.os}${agent.os_version ? ` ${agent.os_version}` : ''}` : 'Unknown'}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Status</label>
                <Badge variant={agent.status === "online" ? "default" : "destructive"} className="gap-1">
                  <div className={`h-2 w-2 rounded-full ${
                    agent.status === "online" 
                      ? "bg-green-500 animate-pulse" 
                      : "bg-red-500"
                  }`} />
                  {agent.status === "online" ? "Online" : "Offline"}
                </Badge>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Last Seen</label>
                <p className="text-sm flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  {formatRelativeTime(agent.lastSeen)}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* System Information */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Settings className="h-5 w-5" />
              System Information
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 gap-3">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Platform</label>
                <p className="text-sm font-mono">{systemInfo.platform || 'Unknown'}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Architecture</label>
                <p className="text-sm">{systemInfo.architecture || 'Unknown'}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Machine Type</label>
                <p className="text-sm">{systemInfo.machine || 'Unknown'}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Python Version</label>
                <p className="text-sm">{systemInfo.python_version || 'Unknown'}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Boot Time</label>
                <p className="text-sm">{systemInfo.boot_time ? formatRelativeTime(systemInfo.boot_time) : 'Unknown'}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Hardware Information */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Cpu className="h-5 w-5" />
              Hardware Information
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 gap-3">
              <div>
                <label className="text-sm font-medium text-muted-foreground">CPU Model</label>
                <p className="text-sm">{hardwareInfo.cpu_model || 'Unknown'}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">CPU Cores</label>
                <p className="text-sm">
                  {hardwareInfo.cpu_count_physical || 'Unknown'} Physical, {hardwareInfo.cpu_count_logical || 'Unknown'} Logical
                </p>
              </div>              <div>
                <label className="text-sm font-medium text-muted-foreground">Memory</label>
                <p className="text-sm">
                  {hardwareInfo.memory_total_gb ? `${hardwareInfo.memory_total_gb} GB Total` : 'Unknown'}
                  {hardwareInfo.memory_available_gb && ` (${hardwareInfo.memory_available_gb} GB Available)`}
                </p>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">IP Address</label>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-mono">{ipAddresses.primary}</span>
                  {ipAddresses.all.length > 1 && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setShowAllIPs(!showAllIPs)}
                      className="h-6 w-6 p-0 rounded-full"
                    >
                      {showAllIPs ? (
                        <ChevronUp className="h-3 w-3" />
                      ) : (
                        <Plus className="h-3 w-3" />
                      )}
                    </Button>
                  )}
                </div>
                {showAllIPs && ipAddresses.all.length > 1 && (
                  <div className="mt-2 p-2 bg-muted rounded-md">
                    <p className="text-xs text-muted-foreground mb-1">All IP Addresses:</p>
                    <div className="space-y-1">
                      {ipAddresses.all.map((ip, index) => (
                        <div key={index} className="text-xs font-mono flex items-center gap-2">
                          <span className={ip === ipAddresses.primary ? 'text-blue-600 font-medium' : ''}>
                            {ip}
                          </span>
                          {ip === ipAddresses.primary && (
                            <Badge variant="outline" className="text-xs h-4 px-1">
                              Primary
                            </Badge>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Disk Information */}
      {diskInfo && diskInfo.disks && diskInfo.disks.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <HardDrive className="h-5 w-5" />
              Disk Space
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {diskInfo.disks.map((disk: any, index: number) => (
                <div key={index} className="p-4 border rounded-lg space-y-3">
                  <div className="flex items-center justify-between">
                    <h4 className="font-medium">{disk.device || `Disk ${index + 1}`}</h4>
                    <Badge variant="outline" className="text-xs">
                      {disk.fstype || 'Unknown'}
                    </Badge>
                  </div>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Mount:</span>
                      <span className="font-mono">{disk.mountpoint || 'Unknown'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Total:</span>
                      <span>{disk.total_gb ? `${disk.total_gb} GB` : 'Unknown'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Used:</span>
                      <span>{disk.used_gb ? `${disk.used_gb} GB` : 'Unknown'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Free:</span>
                      <span className="text-green-600">{disk.free_gb ? `${disk.free_gb} GB` : 'Unknown'}</span>
                    </div>
                    {disk.percent && (
                      <div className="space-y-1">
                        <div className="flex justify-between text-xs">
                          <span className="text-muted-foreground">Usage:</span>
                          <span className={disk.percent > 90 ? 'text-red-600' : disk.percent > 70 ? 'text-yellow-600' : 'text-green-600'}>
                            {disk.percent}%
                          </span>
                        </div>
                        <div className="w-full bg-gray-200 rounded-full h-2">
                          <div
                            className={`h-2 rounded-full transition-all ${
                              disk.percent > 90 ? 'bg-red-500' : disk.percent > 70 ? 'bg-yellow-500' : 'bg-green-500'
                            }`}
                            style={{ width: `${Math.min(disk.percent, 100)}%` }}
                          />
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>        </Card>
      )}

      {/* Recent Activity */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Recent Activity
          </CardTitle>
          <CardDescription>Latest commands and system events</CardDescription>
        </CardHeader>
        <CardContent>
          {commandResults.length > 0 ? (
            <div className="space-y-4">
              {commandResults.slice(0, 5).map((result, index) => (
                <div key={index} className="flex items-start gap-4 p-4 border rounded-lg">
                  <div className="flex-shrink-0">
                    {result.result?.return_code === 0 ? (
                      <CheckCircle className="h-5 w-5 text-green-500" />
                    ) : (
                      <AlertCircle className="h-5 w-5 text-red-500" />
                    )}
                  </div>
                  <div className="flex-1 space-y-1">
                    <div className="flex items-center justify-between">
                      <p className="font-medium text-sm">{result.result?.command || 'Unknown Command'}</p>
                      <p className="text-xs text-muted-foreground">
                        {formatRelativeTime(result.timestamp)}
                      </p>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Return Code: {result.result?.return_code || 'Unknown'}
                    </p>
                    {result.result?.output && (
                      <p className="text-xs bg-muted p-2 rounded font-mono">
                        {result.result.output.substring(0, 200)}
                        {result.result.output.length > 200 && '...'}
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              No recent activity found
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
