"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { ScrollArea } from "@/components/ui/scroll-area"
import { 
  RefreshCw, 
  Search, 
  Package, 
  Download,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  Maximize2,
  Minimize2
} from "lucide-react"
import { apiClient } from "@/lib/api"
import { useToast } from "@/hooks/use-toast"
import { eventBus } from "@/lib/events"

interface SoftwareItem {
  name: string
  version: string
  publisher: string
}

interface CommandResult {
  command_id: string
  timestamp: string
  result: {
    command: string
    return_code: number
    success: boolean
    output?: string
  }
}

type SortDirection = 'asc' | 'desc' | null
type SortColumn = 'name' | 'version' | 'publisher'

export default function SoftwarePage() {
  const [agents, setAgents] = useState<Record<string, any>>({})
  const [selectedAgent, setSelectedAgent] = useState<string>("")
  const [software, setSoftware] = useState<SoftwareItem[]>([])
  const [searchTerm, setSearchTerm] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const [isFullScreen, setIsFullScreen] = useState(false)
  const [sortColumn, setSortColumn] = useState<SortColumn>('name')
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc')
  const [lastUpdated, setLastUpdated] = useState<string>("")
  const { toast } = useToast()

  useEffect(() => {
    loadAgents()

    // Listen for software-related events
    const handleSoftwareCommandSent = (data: { agentId: string; command: string }) => {
      if (data.agentId === selectedAgent) {
        toast({
          title: "Software Command Detected",
          description: "Software inventory will be refreshed automatically",
        })
        // Refresh after 15 seconds to allow command to complete
        setTimeout(() => {
          loadSoftwareInventory()
        }, 15000)
      }
    }

    const handleInventoryRequested = (data: { agentId: string }) => {
      if (data.agentId === selectedAgent) {
        // Refresh after 20 seconds to allow inventory to complete
        setTimeout(() => {
          loadSoftwareInventory()
          toast({
            title: "Auto-refresh",
            description: "Software inventory has been updated",
          })
        }, 20000)
      }
    }

    eventBus.on('software-command-sent', handleSoftwareCommandSent)
    eventBus.on('software-inventory-requested', handleInventoryRequested)

    return () => {
      eventBus.off('software-command-sent', handleSoftwareCommandSent)
      eventBus.off('software-inventory-requested', handleInventoryRequested)
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

  const loadSoftwareInventory = async () => {
    if (!selectedAgent) return
    
    setIsLoading(true)
    try {
      // Get both command results and agent data (inventory data)
      const [results, agentData] = await Promise.all([
        apiClient.getCommandResults(selectedAgent),
        apiClient.getAgentData(selectedAgent)
      ])
      
      console.log('All command results:', results)
      console.log('Agent inventory data:', agentData)
      
      // First, try to find software data in agent inventory data
      let softwareData: SoftwareItem[] = []
      let inventoryTimestamp = ""
      
      // Look for inventory data that contains software/applications
      const inventoryWithSoftware = agentData.find((data: any) => 
        data.message_type === 'inventory' && 
        data.data && 
        (data.data.software || data.data.applications || data.data.installed_software)
      )
      
      if (inventoryWithSoftware) {
        console.log('Found inventory with software:', inventoryWithSoftware)
        const inventoryData = inventoryWithSoftware.data
        let softwareItems = inventoryData.software || inventoryData.applications || inventoryData.installed_software
        
        if (Array.isArray(softwareItems)) {
          softwareData = softwareItems.map((item: any) => ({
            name: item.name || item.displayName || item.DisplayName || 'Unknown',
            version: item.version || item.Version || 'Unknown',
            publisher: item.publisher || item.vendor || item.Publisher || item.Vendor || 'Unknown'
          }))
          inventoryTimestamp = inventoryWithSoftware.timestamp || new Date().toISOString()
        }
      }
      
      // If no software found in inventory, look in command results
      if (softwareData.length === 0) {
        // Look for software data in multiple ways:
        // 1. Standard PowerShell software commands
        let softwareResult = results.find((result: CommandResult) => 
          result.result && result.result.command && (
            result.result.command.includes('Win32_Product') ||
            result.result.command.includes('Get-WmiObject') ||
            result.result.command.toLowerCase().includes('software') ||
            (result.result.command.includes('powershell') && 
             (result.result.command.includes('Name') || result.result.command.includes('Version')))
          )
        )
        
        // 2. Look for COLLECT_INVENTORY command that might contain software data
        if (!softwareResult) {
          softwareResult = results.find((result: CommandResult) => 
            result.result && result.result.command && 
            result.result.command.includes('COLLECT_INVENTORY') &&
            result.result.output && 
            (result.result.output.includes('software') || result.result.output.includes('applications'))
          )
        }
        
        // 3. Look for any command result that contains CSV-like software data
        if (!softwareResult) {
          softwareResult = results.find((result: CommandResult) => 
            result.result && result.result.output && (
              (result.result.output.includes('Name,Version') || 
               result.result.output.includes('"Name","Version"') ||
               result.result.output.includes('Name\t') ||
               result.result.output.match(/\w+,\d+\.\d+/)) // Pattern for name,version
            )
          )
        }
        
        console.log('Found software result:', softwareResult)
        
        if (softwareResult && softwareResult.result.output) {
          console.log('Raw software output:', softwareResult.result.output)
          softwareData = parseSoftwareOutput(softwareResult.result.output)
          inventoryTimestamp = softwareResult.timestamp
        }
      }
      
      console.log('Final parsed software:', softwareData)
      setSoftware(softwareData)
      setLastUpdated(inventoryTimestamp)
      
      if (softwareData.length === 0) {
        toast({
          title: "No Software Data",
          description: "No software inventory data found. Try requesting a software inventory first.",
          variant: "default",
        })
      }
      
    } catch (error) {
      console.error('Error loading software inventory:', error)
      toast({
        title: "Error",
        description: "Failed to load software inventory",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  const parseSoftwareOutput = (output: string): SoftwareItem[] => {
    const lines = output.split('\n').filter(line => line.trim())
    const softwareList: SoftwareItem[] = []
    
    console.log(`Processing ${lines.length} lines of output`)
    
    // Check if this is JSON data from COLLECT_INVENTORY
    if (output.trim().startsWith('{') || output.includes('"software"') || output.includes('"applications"')) {
      try {
        const jsonData = JSON.parse(output)
        // Handle different JSON structures
        if (jsonData.software && Array.isArray(jsonData.software)) {
          return jsonData.software.map((item: any) => ({
            name: item.name || item.displayName || 'Unknown',
            version: item.version || 'Unknown',
            publisher: item.publisher || item.vendor || 'Unknown'
          }))
        }
        if (jsonData.applications && Array.isArray(jsonData.applications)) {
          return jsonData.applications.map((item: any) => ({
            name: item.name || item.displayName || 'Unknown',
            version: item.version || 'Unknown',
            publisher: item.publisher || item.vendor || 'Unknown'
          }))
        }
      } catch (error) {
        console.log('Not valid JSON, trying CSV parsing')
      }
    }
    
    // Handle CSV format (skip header if present)
    let startIndex = 0
    if (lines.length > 0 && 
        (lines[0].toLowerCase().includes('name') || 
         lines[0].includes('"Name"') || 
         lines[0].includes('Name,Version'))) {
      startIndex = 1
    }
    
    // Process each line
    for (let i = startIndex; i < lines.length; i++) {
      const line = lines[i].trim()
      if (!line) continue
      
      try {
        let name = '', version = '', vendor = ''
        
        // Method 1: Handle quoted CSV (most common PowerShell output)
        const quotedCsvMatch = line.match(/"([^"]*)","([^"]*)","([^"]*)"/);
        if (quotedCsvMatch) {
          [, name, version, vendor] = quotedCsvMatch
        } 
        // Method 2: Handle tab-separated values
        else if (line.includes('\t')) {
          const parts = line.split('\t').map(part => part.trim())
          if (parts.length >= 3) {
            [name, version, vendor] = parts
          } else if (parts.length === 2) {
            [name, version] = parts
            vendor = 'Unknown'
          }
        }
        // Method 3: Handle comma-separated without quotes
        else if (line.includes(',')) {
          const parts = line.split(',').map(part => part.trim().replace(/^"|"$/g, ''))
          if (parts.length >= 3) {
            [name, version, vendor] = parts
          } else if (parts.length === 2) {
            [name, version] = parts
            vendor = 'Unknown'
          } else if (parts.length === 1) {
            name = parts[0]
            version = 'Unknown'
            vendor = 'Unknown'
          }
        }
        // Method 4: Handle single line with just software name
        else if (line.length > 0 && !line.toLowerCase().includes('name')) {
          name = line
          version = 'Unknown'
          vendor = 'Unknown'
        }
        
        // Clean up the data and validate
        name = name.trim().replace(/^"|"$/g, '')
        version = version.trim().replace(/^"|"$/g, '')
        vendor = vendor.trim().replace(/^"|"$/g, '')
        
        // Only add if we have a valid name and it's not a header
        if (name && 
            name !== 'Name' && 
            name !== 'DisplayName' &&
            name.length > 0 && 
            !name.toLowerCase().includes('name,version')) {
          softwareList.push({
            name: name,
            version: version || 'Unknown',
            publisher: vendor || 'Unknown'
          })
        }
      } catch (error) {
        console.warn(`Error parsing software line: ${line}`, error)
        continue
      }
    }
    
    console.log(`Parsed ${softwareList.length} software items from ${lines.length} lines`)
    return softwareList
  }

  const requestSoftwareInventory = async () => {
    if (!selectedAgent) return
    
    try {
      await apiClient.sendCommand(selectedAgent, 'powershell "Get-WmiObject -Class Win32_Product | Select-Object Name,Version,Vendor | ConvertTo-Csv -NoTypeInformation"', 120)
      toast({
        title: "Software Request Sent",
        description: "PowerShell software inventory request sent. Check back in a few seconds for updated data.",
      })
      
      // Emit event for other components
      eventBus.emit('software-command-sent', { 
        agentId: selectedAgent, 
        command: 'powershell software inventory' 
      })
      
      // Auto-refresh after 15 seconds (software inventory takes longer)
      setTimeout(() => {
        loadSoftwareInventory()
      }, 15000)
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to request software inventory",
        variant: "destructive",
      })
    }
  }

  const requestSystemInventory = async () => {
    if (!selectedAgent) return
    
    try {
      await apiClient.requestInventory(selectedAgent)
      toast({
        title: "System Inventory Request Sent",
        description: "COLLECT_INVENTORY command sent. This includes system information and may include software data.",
      })
      
      // Emit event for other components
      eventBus.emit('software-inventory-requested', { agentId: selectedAgent })
      
      // Auto-refresh after 20 seconds (system inventory takes longer)
      setTimeout(() => {
        loadSoftwareInventory()
      }, 20000)
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to request system inventory",
        variant: "destructive",
      })
    }
  }

  const handleSort = (column: SortColumn) => {
    if (sortColumn === column) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : sortDirection === 'desc' ? null : 'asc')
    } else {
      setSortColumn(column)
      setSortDirection('asc')
    }
  }

  const getSortIcon = (column: SortColumn) => {
    if (sortColumn !== column) return <ArrowUpDown className="h-4 w-4" />
    if (sortDirection === 'asc') return <ArrowUp className="h-4 w-4" />
    if (sortDirection === 'desc') return <ArrowDown className="h-4 w-4" />
    return <ArrowUpDown className="h-4 w-4" />
  }

  const filteredAndSortedSoftware = () => {
    let filtered = software.filter(item =>
      item.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.version.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.publisher.toLowerCase().includes(searchTerm.toLowerCase())
    )

    if (sortColumn && sortDirection) {
      filtered.sort((a, b) => {
        const aValue = a[sortColumn].toLowerCase()
        const bValue = b[sortColumn].toLowerCase()
        const comparison = aValue.localeCompare(bValue)
        return sortDirection === 'asc' ? comparison : -comparison
      })
    }

    return filtered
  }

  const exportToCSV = () => {
    const csvContent = [
      ['Software Name', 'Version', 'Publisher'],
      ...filteredAndSortedSoftware().map(item => [item.name, item.version, item.publisher])
    ].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n')

    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `software-inventory-${agents[selectedAgent]?.hostname || selectedAgent}.csv`
    a.click()
    window.URL.revokeObjectURL(url)
  }

  const displayedSoftware = filteredAndSortedSoftware()

  return (
    <div className={`space-y-6 ${isFullScreen ? 'fixed inset-4 z-50 bg-background p-6 rounded-lg shadow-2xl overflow-hidden' : ''}`}>
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Installed Software</h1>
          <p className="text-muted-foreground">View and manage installed applications on agents</p>
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
            <Package className="h-5 w-5" />
            Agent Selection & Filters
          </CardTitle>
          <CardDescription>
            Select an online agent to view its installed software inventory
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4">
            <div className="flex-1">
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
            <Button onClick={loadSoftwareInventory} disabled={!selectedAgent || isLoading}>
              <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button onClick={requestSoftwareInventory} disabled={!selectedAgent} variant="outline">
              <Package className="h-4 w-4 mr-2" />
              Get Software List
            </Button>
            <Button onClick={requestSystemInventory} disabled={!selectedAgent} variant="secondary">
              <Download className="h-4 w-4 mr-2" />
              System Inventory
            </Button>
          </div>

          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
            <Input
              placeholder="Search software by name, version, or publisher..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10"
            />
          </div>

          {displayedSoftware.length > 0 && (
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4 text-sm text-muted-foreground">
                <span>Showing {displayedSoftware.length} of {software.length} applications</span>
                {lastUpdated && (
                  <span>Last updated: {new Date(lastUpdated).toLocaleString()}</span>
                )}
              </div>
              <Button onClick={exportToCSV} variant="outline" size="sm">
                <Download className="h-4 w-4 mr-2" />
                Export CSV
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {selectedAgent && (
        <Card className="flex-1 min-h-0">
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>📦 Installed Software</span>
              {software.length > 0 && (
                <Badge variant="outline">
                  Agent: {agents[selectedAgent]?.hostname || selectedAgent.substring(0, 12)}
                </Badge>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {isLoading ? (
              <div className="flex items-center justify-center py-12">
                <RefreshCw className="h-8 w-8 animate-spin" />
              </div>
            ) : software.length === 0 ? (
              <div className="text-center py-12">
                <h3 className="text-lg font-semibold mb-2">📦 No Software Data Available</h3>
                <p className="text-muted-foreground mb-4">
                  Click "Get Software List" for PowerShell-based software inventory or "System Inventory" for comprehensive system data including installed applications.
                </p>
                <div className="flex justify-center gap-2">
                  <Button onClick={requestSoftwareInventory} variant="outline">
                    <Package className="h-4 w-4 mr-2" />
                    Get Software List
                  </Button>
                  <Button onClick={requestSystemInventory} variant="secondary">
                    <Download className="h-4 w-4 mr-2" />
                    System Inventory
                  </Button>
                </div>
              </div>
            ) : displayedSoftware.length === 0 ? (
              <div className="text-center py-12">
                <p className="text-muted-foreground">No software matches your search criteria</p>
              </div>
            ) : (
              <ScrollArea className={`${isFullScreen ? 'h-[calc(100vh-400px)]' : 'h-[600px]'}`}>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead 
                        className="cursor-pointer select-none"
                        onClick={() => handleSort('name')}
                      >
                        <div className="flex items-center gap-2">
                          Software Name
                          {getSortIcon('name')}
                        </div>
                      </TableHead>
                      <TableHead 
                        className="cursor-pointer select-none"
                        onClick={() => handleSort('version')}
                      >
                        <div className="flex items-center gap-2">
                          Version
                          {getSortIcon('version')}
                        </div>
                      </TableHead>
                      <TableHead 
                        className="cursor-pointer select-none"
                        onClick={() => handleSort('publisher')}
                      >
                        <div className="flex items-center gap-2">
                          Publisher
                          {getSortIcon('publisher')}
                        </div>
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {displayedSoftware.map((item, index) => (
                      <TableRow key={`${item.name}-${index}`}>
                        <TableCell className="font-medium">{item.name}</TableCell>
                        <TableCell>{item.version}</TableCell>
                        <TableCell>{item.publisher}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </ScrollArea>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
