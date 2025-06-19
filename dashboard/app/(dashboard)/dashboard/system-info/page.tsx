"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { 
  RefreshCw, 
  Monitor, 
  Cpu, 
  HardDrive, 
  Network, 
  Server, 
  Wifi,
  Activity,
  Clock
} from "lucide-react"
import { apiClient } from "@/lib/api"
import { useToast } from "@/hooks/use-toast"

interface AgentInventory {
  message_type: string
  timestamp: string
  data: {
    system: {
      hostname: string
      os: string
      os_version: string
      architecture: string
      domain?: string
      username: string
      uptime: string
    }
    hardware: {
      cpu_model: string
      cpu_count_physical: number
      cpu_count_logical: number
      memory_total_gb: number
      memory_available_gb: number
      memory_usage_percent: number
    }
    network: Record<string, {
      ip: string
      subnet: string
      mac: string
    }>
    disks: Array<{
      device: string
      mountpoint: string
      fstype: string
      total_gb: number
      used_gb: number
      free_gb: number
      usage_percent: number
    }>
  }
}

export default function SystemInfoPage() {
  const [agents, setAgents] = useState<Record<string, any>>({})
  const [selectedAgent, setSelectedAgent] = useState<string>("")
  const [systemInfo, setSystemInfo] = useState<AgentInventory | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const { toast } = useToast()

  useEffect(() => {
    loadAgents()
  }, [])

  useEffect(() => {
    if (selectedAgent) {
      loadSystemInfo()
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
    const loadSystemInfo = async () => {
    if (!selectedAgent) return
    
    setIsLoading(true)
    try {
      const agentData = await apiClient.getAgentData(selectedAgent);
      console.log('Agent data received:', agentData) // Debug log
      const inventoryData = agentData.find(data => data.message_type === 'inventory')
      console.log('Inventory data found:', inventoryData) // Debug log
      if (inventoryData?.data) {
        console.log('Full inventory data structure:', JSON.stringify(inventoryData.data, null, 2)) // Deep debug log
        console.log('Hardware data:', inventoryData.data.hardware) // Debug log
        console.log('Network data:', inventoryData.data.network) // Debug log
        
        // Log specific CPU model access attempts
        console.log('CPU model attempts:')
        console.log('- cpu_model:', inventoryData.data.hardware?.cpu_model)
        console.log('- processor (hardware):', (inventoryData.data.hardware as any)?.processor)
        console.log('- processor (system):', (inventoryData.data.system as any)?.processor)
        
        // Log network data structure
        if (inventoryData.data.network) {
          console.log('Network interfaces:')
          Object.entries(inventoryData.data.network).forEach(([name, details]) => {
            console.log(`- ${name}:`, details)
          })
        }
      }
      setSystemInfo(inventoryData || null)
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to load system information",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  const requestSystemInventory = async () => {
    if (!selectedAgent) return
    
    try {
      await apiClient.sendCommand(selectedAgent, 'COLLECT_INVENTORY', 60)
      toast({
        title: "Request Sent",
        description: "System inventory request sent. Data will be updated in a few seconds.",
      })
      
      // Auto-refresh after 10 seconds
      setTimeout(() => {
        loadSystemInfo()
      }, 10000)
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to request system inventory",
        variant: "destructive",
      })
    }
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 GB'
    const k = 1024
    const sizes = ['GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">System Information</h1>
          <p className="text-muted-foreground">View detailed hardware and system information for agents</p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Server className="h-5 w-5" />
            Agent Selection
          </CardTitle>
          <CardDescription>
            Select an agent to view its system information
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4">
            <div className="flex-1">
              <Select value={selectedAgent} onValueChange={setSelectedAgent}>
                <SelectTrigger>
                  <SelectValue placeholder="Select an agent" />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(agents).map(([id, agent]) => (
                    <SelectItem key={id} value={id}>
                      {agent.hostname || id.substring(0, 12)} ({agent.os || 'Unknown'})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button onClick={loadSystemInfo} disabled={!selectedAgent || isLoading}>
              <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button onClick={requestSystemInventory} disabled={!selectedAgent} variant="outline">
              <Activity className="h-4 w-4 mr-2" />
              Request Inventory
            </Button>
          </div>
        </CardContent>
      </Card>

      {selectedAgent && (
        <div className="space-y-6">
          {/* Connection Status */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Wifi className="h-5 w-5" />
                Connection Status
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <div className="space-y-2">
                  <span className="text-sm font-medium text-muted-foreground">Agent ID</span>
                  <p className="font-mono text-sm">{selectedAgent}</p>
                </div>
                <div className="space-y-2">
                  <span className="text-sm font-medium text-muted-foreground">Hostname</span>
                  <p>{agents[selectedAgent]?.hostname || 'Unknown'}</p>
                </div>
                <div className="space-y-2">
                  <span className="text-sm font-medium text-muted-foreground">Operating System</span>
                  <p>{agents[selectedAgent]?.os || 'Unknown'}</p>
                </div>
                <div className="space-y-2">
                  <span className="text-sm font-medium text-muted-foreground">Status</span>
                  <Badge variant="default" className="bg-green-500">
                    ● Online
                  </Badge>
                </div>
                <div className="space-y-2">
                  <span className="text-sm font-medium text-muted-foreground">Last Seen</span>
                  <p className="text-sm">{new Date(agents[selectedAgent]?.last_seen).toLocaleString()}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          {isLoading ? (
            <Card>
              <CardContent className="flex items-center justify-center py-12">
                <RefreshCw className="h-8 w-8 animate-spin" />
              </CardContent>
            </Card>
          ) : !systemInfo ? (
            <Card>
              <CardContent className="text-center py-12">
                <h3 className="text-lg font-semibold mb-2">📊 No Detailed System Data Available</h3>
                <p className="text-muted-foreground mb-4">
                  Click "Request Inventory" to gather detailed hardware and system information.
                </p>
                <Button onClick={requestSystemInventory}>
                  <Activity className="h-4 w-4 mr-2" />
                  Request System Inventory
                </Button>
              </CardContent>
            </Card>
          ) : (
            <Tabs defaultValue="system" className="space-y-4">
              <TabsList className="grid w-full grid-cols-4">
                <TabsTrigger value="system">System</TabsTrigger>
                <TabsTrigger value="hardware">Hardware</TabsTrigger>
                <TabsTrigger value="network">Network</TabsTrigger>
                <TabsTrigger value="storage">Storage</TabsTrigger>
              </TabsList>              <TabsContent value="system" className="space-y-4">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Monitor className="h-5 w-5" />
                      System Details
                    </CardTitle>
                  </CardHeader>                  <CardContent>
                    {systemInfo?.data?.system ? (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div className="space-y-4">
                          <div className="space-y-2">
                            <span className="text-sm font-medium text-muted-foreground">Computer Name</span>
                            <p className="font-semibold">{systemInfo.data.system?.hostname || 'N/A'}</p>
                          </div>
                          <div className="space-y-2">
                            <span className="text-sm font-medium text-muted-foreground">Operating System</span>
                            <p>{systemInfo.data.system?.os || 'N/A'} {systemInfo.data.system?.os_version || ''}</p>
                          </div>
                          <div className="space-y-2">
                            <span className="text-sm font-medium text-muted-foreground">Architecture</span>
                            <p>{systemInfo.data.system?.architecture || 'N/A'}</p>
                          </div>
                        </div>
                        <div className="space-y-4">
                          <div className="space-y-2">
                            <span className="text-sm font-medium text-muted-foreground">Domain</span>
                            <p>{systemInfo.data.system?.domain || 'N/A'}</p>
                          </div>
                          <div className="space-y-2">
                            <span className="text-sm font-medium text-muted-foreground">Username</span>
                            <p>{systemInfo.data.system?.username || 'N/A'}</p>
                          </div>
                          <div className="space-y-2">
                            <span className="text-sm font-medium text-muted-foreground">Uptime</span>
                            <p>{systemInfo.data.system?.uptime || 'N/A'}</p>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        <p className="text-muted-foreground mb-4">Detailed system information not available. Showing basic agent info:</p>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                          <div className="space-y-4">
                            <div className="space-y-2">
                              <span className="text-sm font-medium text-muted-foreground">Hostname</span>
                              <p className="font-semibold">{agents[selectedAgent]?.hostname || 'Unknown'}</p>
                            </div>
                            <div className="space-y-2">
                              <span className="text-sm font-medium text-muted-foreground">Operating System</span>
                              <p>{agents[selectedAgent]?.os || 'Unknown'}</p>
                            </div>
                          </div>
                          <div className="space-y-4">
                            <div className="space-y-2">
                              <span className="text-sm font-medium text-muted-foreground">Status</span>
                              <p className="text-green-600 font-semibold">Online</p>
                            </div>
                            <div className="space-y-2">
                              <span className="text-sm font-medium text-muted-foreground">Last Seen</span>
                              <p>{agents[selectedAgent]?.last_seen ? new Date(agents[selectedAgent].last_seen).toLocaleString() : 'N/A'}</p>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="hardware" className="space-y-4">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Cpu className="h-5 w-5" />
                      Hardware Information
                    </CardTitle>
                  </CardHeader>                  <CardContent className="space-y-6">
                    {systemInfo?.data?.hardware ? (
                      <>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                          <div className="space-y-4">
                            <div className="space-y-2">                              <span className="text-sm font-medium text-muted-foreground">Processor</span>
                              <p className="font-semibold">{
                                systemInfo.data.hardware?.cpu_model || 
                                (systemInfo.data.hardware as any)?.processor || 
                                (systemInfo.data.system as any)?.processor || 
                                'N/A'
                              }</p>
                            </div>
                            <div className="space-y-2">
                              <span className="text-sm font-medium text-muted-foreground">CPU Cores</span>
                              <p>{systemInfo.data.hardware?.cpu_count_physical || 'N/A'} physical, {systemInfo.data.hardware?.cpu_count_logical || 'N/A'} logical</p>
                            </div>
                          </div>
                          <div className="space-y-4">
                            <div className="space-y-2">
                              <span className="text-sm font-medium text-muted-foreground">Total Memory</span>
                              <p className="font-semibold">{systemInfo.data.hardware?.memory_total_gb || 'N/A'} GB</p>
                            </div>
                            <div className="space-y-2">
                              <span className="text-sm font-medium text-muted-foreground">Available Memory</span>
                              <p>{systemInfo.data.hardware?.memory_available_gb || 'N/A'} GB</p>
                            </div>
                          </div>
                        </div>
                        
                        <div className="space-y-2">
                          <div className="flex justify-between text-sm">
                            <span className="font-medium">Memory Usage</span>
                            <span>{systemInfo.data.hardware?.memory_usage_percent || 0}%</span>
                          </div>
                          <Progress value={systemInfo.data.hardware?.memory_usage_percent || 0} className="h-2" />
                        </div>
                      </>
                    ) : (
                      <p className="text-muted-foreground">No hardware information available. Click "Request Inventory" to collect detailed hardware data.</p>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="network" className="space-y-4">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Network className="h-5 w-5" />
                      Network Interfaces
                    </CardTitle>
                  </CardHeader>                  <CardContent>
                    <div className="space-y-4">                      {systemInfo?.data?.network && Object.entries(systemInfo.data.network).map(([interfaceName, details]) => {
                        // Handle different data formats
                        let ip = 'N/A', subnet = 'N/A', mac = 'N/A';
                        
                        if (details && typeof details === 'object') {
                          // Format 1: Direct fields {ip, subnet, mac}
                          if ((details as any).ip) {
                            ip = (details as any).ip;
                            subnet = (details as any).subnet || (details as any).netmask || 'N/A';
                            mac = (details as any).mac || 'N/A';
                          }
                          // Format 2: Addresses array from psutil
                          else if ((details as any).addresses) {
                            const addresses = (details as any).addresses;
                            for (const addr of addresses) {
                              const family = addr.family;
                              const address = addr.address;
                              
                              // IPv4 addresses (family = "2" or "AddressFamily.AF_INET")
                              if (family === '2' || family === 'AddressFamily.AF_INET') {
                                ip = address;
                                subnet = addr.netmask || 'N/A';
                              } 
                              // MAC addresses (family = "-1" or MAC format)
                              else if (family === '-1' || 
                                      ((address.includes(':') || address.includes('-')) && 
                                       address.replace(/[:-]/g, '').length === 12)) {
                                mac = address;
                              }
                            }
                          }
                        }
                        
                        return (
                          <div key={interfaceName} className="p-4 border rounded-lg border-l-4 border-l-blue-500">
                            <h4 className="font-semibold mb-3">{interfaceName}</h4>
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                              <div>
                                <span className="text-muted-foreground">IP Address:</span>
                                <p className="font-mono">{ip}</p>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Subnet:</span>
                                <p className="font-mono">{subnet}</p>
                              </div>
                              <div>
                                <span className="text-muted-foreground">MAC Address:</span>
                                <p className="font-mono">{mac}</p>
                              </div>
                            </div>
                          </div>
                        )
                      })}
                      {(!systemInfo?.data?.network || Object.keys(systemInfo.data.network).length === 0) && (
                        <p className="text-muted-foreground">No network interface data available. Click "Request Inventory" to collect network information.</p>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="storage" className="space-y-4">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <HardDrive className="h-5 w-5" />
                      Storage Devices
                    </CardTitle>
                  </CardHeader>                  <CardContent>
                    <div className="space-y-4">
                      {systemInfo?.data?.disks && systemInfo.data.disks.length > 0 ? (
                        systemInfo.data.disks.map((disk, index) => {
                          const usagePercent = disk?.usage_percent || 0
                          const usageColor = usagePercent > 90 ? 'border-l-red-500' : 
                                            usagePercent > 70 ? 'border-l-yellow-500' : 'border-l-green-500'
                          return (
                            <div key={index} className={`p-4 border rounded-lg border-l-4 ${usageColor}`}>
                              <div className="flex justify-between items-start mb-3">
                                <div>
                                  <h4 className="font-semibold">{disk?.device || 'Unknown'}</h4>
                                  <p className="text-sm text-muted-foreground">{disk?.mountpoint || 'N/A'} • {disk?.fstype || 'N/A'}</p>
                                </div>
                                <Badge variant={usagePercent > 90 ? "destructive" : usagePercent > 70 ? "secondary" : "default"}>
                                  {usagePercent}% Used
                                </Badge>
                              </div>
                              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm mb-3">
                                <div>
                                  <span className="text-muted-foreground">Total Size:</span>
                                  <p className="font-semibold">{disk?.total_gb?.toFixed(2) || 'N/A'} GB</p>
                                </div>
                                <div>
                                  <span className="text-muted-foreground">Used:</span>
                                  <p className="font-semibold">{disk?.used_gb?.toFixed(2) || 'N/A'} GB</p>
                                </div>
                                <div>
                                  <span className="text-muted-foreground">Free:</span>
                                  <p className="font-semibold">{disk?.free_gb?.toFixed(2) || 'N/A'} GB</p>
                                </div>
                              </div>
                              <Progress value={usagePercent} className="h-2" />
                            </div>
                          )
                        })
                      ) : (
                        <p className="text-muted-foreground">No disk information available. Click "Request Inventory" to collect storage data.</p>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          )}

          {systemInfo && (
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between text-sm text-muted-foreground">
                  <div className="flex items-center gap-2">
                    <Clock className="h-4 w-4" />
                    <span>Data Collection Time: {new Date(systemInfo.timestamp).toLocaleString()}</span>
                  </div>
                  <Badge variant="outline">Agent: {selectedAgent.substring(0, 12)}</Badge>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  )
}
