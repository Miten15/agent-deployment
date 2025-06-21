'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Separator } from '@/components/ui/separator'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Progress } from '@/components/ui/progress'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { useToast } from '@/hooks/use-toast'
import { apiClient } from '@/lib/api'
import { 
  Shield, 
  Play, 
  Square, 
  FileSearch, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  Activity,
  Network,
  HardDrive,
  Cpu,
  Clock,
  Eye,
  History,
  Calendar,
  TrendingUp
} from 'lucide-react'

interface SuspiciousProcess {
  pid: number
  process_name: string
  username: string
  suspicion_score: number
  risk_level?: string
  reasons: string[]
}

interface BehavioralReport {
  detection_timestamp: string
  analysis_duration_seconds: number
  suspicious_processes: SuspiciousProcess[]
}

interface HistoricalScan {
  timestamp: string
  agent_id: string
  duration: number
  suspicious_count: number
  risk_distribution: {
    critical: number
    high: number
    medium: number
    low: number
  }
  summary: string
}

interface ScanStatus {
  scanning: boolean
  progress: number
  duration: number
  message: string
}

export default function BehavioralPage() {
  const [agents, setAgents] = useState<Record<string, any>>({})
  const [selectedAgent, setSelectedAgent] = useState<string>('')
  const [scanStatus, setScanStatus] = useState<ScanStatus>({
    scanning: false,
    progress: 0,
    duration: 0,
    message: 'Ready to scan'
  })
  const [report, setReport] = useState<BehavioralReport | null>(null)
  const [historicalScans, setHistoricalScans] = useState<HistoricalScan[]>([])
  const [showHistory, setShowHistory] = useState(false)
  const [loading, setLoading] = useState(false)
  const { toast } = useToast()

  // Fetch agents on component mount
  useEffect(() => {
    fetchAgents()
    const interval = setInterval(fetchAgents, 10000)
    return () => clearInterval(interval)
  }, [])

  const fetchAgents = async () => {
    try {
      const agentsData = await apiClient.getAgents()
      setAgents(agentsData)
      
      // Auto-select first online agent if none selected
      if (!selectedAgent) {
        const onlineAgents = Object.entries(agentsData).filter(([_, agent]: [string, any]) => 
          agent.status === 'online'
        )
        if (onlineAgents.length > 0) {
          setSelectedAgent(onlineAgents[0][0])
        }
      }
    } catch (err) {
      console.error('Failed to fetch agents:', err)
      toast({
        title: "Connection Error",
        description: "Failed to connect to the server. Please ensure the Flask server is running.",
        variant: "destructive",
      })
    }
  }

  const startScan = async () => {
    if (!selectedAgent) {
      toast({
        title: "Error",
        description: "Please select an agent first",
        variant: "destructive",
      })
      return
    }

    try {
      setLoading(true)
      
      const result = await apiClient.sendCommand(selectedAgent, 'RUN_BEHAVIORAL_SCAN', 30)
      
      if (result.status === 'success') {
        setScanStatus({
          scanning: true,
          progress: 0,
          duration: 0,
          message: 'Behavioral scan started... analyzing system behavior'
        })
        setReport(null) // Clear previous report
          toast({
          title: "Scan Started",
          description: "Behavioral anomaly detection has been initiated.",
        })
        
        // Start monitoring for results
        monitorScanProgress()
      } else {
        throw new Error('Failed to start scan')
      }
    } catch (err) {
      console.error('Failed to start behavioral scan:', err)
      toast({
        title: "Error",
        description: err instanceof Error ? err.message : 'Failed to start behavioral scan',
        variant: "destructive",
      })
    } finally {
      setLoading(false)
    }
  }

  const stopScan = async () => {
    if (!selectedAgent) {
      return
    }

    try {
      setLoading(true)
      
      const result = await apiClient.sendCommand(selectedAgent, 'STOP_BEHAVIORAL_SCAN', 30)
      
      if (result.status === 'success') {
        setScanStatus({
          scanning: false,
          progress: 0,
          duration: 0,
          message: 'Scan stopped by user'
        })
        
        toast({
          title: "Scan Stopped",
          description: "Behavioral anomaly detection has been stopped.",
        })
      }
    } catch (err) {
      console.error('Failed to stop behavioral scan:', err)
      toast({
        title: "Error",
        description: err instanceof Error ? err.message : 'Failed to stop behavioral scan',
        variant: "destructive",
      })
    } finally {
      setLoading(false)
    }
  }
  const fetchReport = async () => {
    if (!selectedAgent) {
      toast({
        title: "Error",
        description: "Please select an agent first",
        variant: "destructive",
      })
      return
    }    try {
      setLoading(true)
      
      console.log('🔍 DEBUG: Fetching report for agent:', selectedAgent)
      
      // Get command results directly (no need to send command)
      const results = await apiClient.getCommandResults(selectedAgent)
      
      console.log('🔍 DEBUG: Total command results:', results.length)
      console.log('🔍 DEBUG: All results:', results)
      
      // Show each result for debugging
      results.forEach((result: any, index: number) => {
        console.log(`🔍 DEBUG: Result ${index}:`, {
          command: result.command,
          timestamp: result.timestamp,
          return_code: result.return_code,
          output_preview: result.output ? result.output.substring(0, 100) + '...' : 'NO OUTPUT',
          output_length: result.output ? result.output.length : 0
        })
      })
        // Find the most recent successful behavioral scan result
      const behavioralResults = results.filter((result: any) => {
        const command = result.command || result.result?.command || ''
        return command.toUpperCase().includes('RUN_BEHAVIORAL_SCAN')
      })
      
      console.log('🔍 DEBUG: Behavioral scan results found:', behavioralResults.length)
      behavioralResults.forEach((result: any, index: number) => {
        console.log(`🔍 DEBUG: Behavioral result ${index}:`, {
          command: result.command || result.result?.command,
          return_code: result.return_code || result.result?.return_code,
          timestamp: result.timestamp,
          has_output: !!(result.output || result.result?.output),
          output_length: (result.output || result.result?.output)?.length || 0
        })
      })
        
      const behavioralResult = behavioralResults
        .filter((result: any) => {
          const returnCode = result.return_code || result.result?.return_code
          const output = result.output || result.result?.output
          return returnCode === 0 && output
        })
        .sort((a: any, b: any) => new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime())[0]
      
      console.log('🔍 DEBUG: Selected behavioral result:', behavioralResult)
        if (behavioralResult) {
        const output = behavioralResult.output || behavioralResult.result?.output
        console.log('🔍 DEBUG: Processing output:', output?.substring(0, 200))
        
        // Parse the scan output to extract structured data
        const reportData = parseBehavioralScanOutput(output)
        
        console.log('🔍 DEBUG: Parsed report data:', reportData)
        
        if (reportData) {
          setReport(reportData)
          toast({
            title: "Report Retrieved",
            description: `Latest behavioral scan report loaded with ${reportData.suspicious_processes.length} suspicious processes.`,
          })
        } else {
          console.log('🔍 DEBUG: Failed to parse output')
          toast({
            title: "Parse Error",
            description: "Could not parse the scan output. Please try running a new scan.",
            variant: "destructive",
          })
        }
      } else {
        console.log('🔍 DEBUG: No valid behavioral result found')
        toast({
          title: "No Report Available",
          description: "No successful behavioral scan found. Please run a scan first.",
          variant: "destructive",
        })
      }
    } catch (err) {
      console.error('Failed to fetch behavioral report:', err)
      toast({
        title: "Error",
        description: err instanceof Error ? err.message : 'Failed to fetch behavioral report',
        variant: "destructive",
      })
    } finally {
      setLoading(false)
    }
  }

  const monitorScanProgress = () => {
    let progress = 0
    let duration = 0
    
    const interval = setInterval(() => {
      duration += 1
      progress = Math.min((duration / 120) * 100, 100) // 120 seconds scan time
      
      setScanStatus(prev => ({
        ...prev,
        progress,
        duration,
        message: `Analyzing system behavior... ${Math.round(progress)}% complete`
      }))
      
      if (progress >= 100) {
        clearInterval(interval)
        setScanStatus(prev => ({
          ...prev,
          scanning: false,
          message: 'Scan completed. Click "Get Latest Report" to view results.'
        }))
        
        toast({
          title: "Scan Complete",
          description: "Behavioral analysis has finished. You can now view the report.",
        })
      }
    }, 1000)
    
    // Auto-clear after 2 minutes max
    setTimeout(() => {
      clearInterval(interval)    }, 125000)
  }
  
  const getSeverityColor = (score: number) => {
    if (score >= 9.0) return 'destructive'    // Critical: 9-10
    if (score >= 7.0) return 'secondary'      // High: 7-8.9  
    if (score >= 4.0) return 'outline'        // Medium: 4-6.9
    return 'default'                          // Low/Minimal: 0-3.9
  }

  const getSeverityIcon = (score: number) => {
    if (score >= 9.0) return <XCircle className="h-4 w-4 text-red-500" />
    if (score >= 7.0) return <AlertTriangle className="h-4 w-4 text-orange-500" />
    if (score >= 4.0) return <AlertTriangle className="h-4 w-4 text-yellow-500" />
    return <CheckCircle className="h-4 w-4 text-green-500" />
  }

  const getSeverityLabel = (score: number) => {
    if (score >= 9.0) return 'Critical'
    if (score >= 7.0) return 'High'
    if (score >= 4.0) return 'Medium'
    if (score >= 1.0) return 'Low'
    return 'Minimal'
  }
  // Parse the behavioral scan text output into structured data
  const parseBehavioralScanOutput = (output: string): BehavioralReport | null => {
    try {
      console.log('🔍 PARSING: Starting to parse output:', output.substring(0, 500))
      const lines = output.split('\\n') // Handle escaped newlines
      
      // Extract metadata
      let detectionTimestamp = new Date().toISOString()
      let analysisDuration = 120
      let suspiciousProcesses: SuspiciousProcess[] = []
      
      // Find duration line
      const durationLine = lines.find(line => line.includes('Scan Duration:'))
      if (durationLine) {
        const match = durationLine.match(/(\d+)\s+seconds/)
        if (match) {
          analysisDuration = parseInt(match[1])
        }
      }
      
      console.log('🔍 PARSING: Found duration:', analysisDuration)
      
      // Parse suspicious processes
      let inProcessList = false
      let currentProcess: Partial<SuspiciousProcess> | null = null
      
      for (const line of lines) {
        const trimmedLine = line.trim()
        
        // Start of suspicious processes list
        if (trimmedLine === 'Suspicious Processes:') {
          inProcessList = true
          console.log('🔍 PARSING: Found suspicious processes section')
          continue
        }
        
        if (!inProcessList) continue
        
        // Process header line (starts with •)
        if (trimmedLine.startsWith('•')) {
          // Save previous process if exists
          if (currentProcess && currentProcess.pid && currentProcess.process_name) {
            console.log('🔍 PARSING: Adding process:', currentProcess.process_name, 'with', currentProcess.reasons?.length, 'reasons')
            suspiciousProcesses.push({
              pid: currentProcess.pid,
              process_name: currentProcess.process_name,
              username: currentProcess.username || 'Unknown',
              suspicion_score: currentProcess.suspicion_score || 0,
              reasons: currentProcess.reasons || []
            })
          }
          
          // Parse new process: • ProcessName.exe (PID: 1234)
          const processMatch = trimmedLine.match(/•\s+(.+?)\s+\(PID:\s+(\d+)\)/)
          if (processMatch) {
            currentProcess = {
              process_name: processMatch[1],
              pid: parseInt(processMatch[2]),
              reasons: []
            }
            console.log('🔍 PARSING: Started new process:', currentProcess.process_name, 'PID:', currentProcess.pid)
          }
        }
        // Risk Level line
        else if (trimmedLine.startsWith('Risk Level:') && currentProcess) {
          const riskMatch = trimmedLine.match(/Risk Level:\s+(.+)/)
          if (riskMatch) {
            currentProcess.risk_level = riskMatch[1]
            console.log('🔍 PARSING: Risk level:', riskMatch[1])
          }
        }
        // Suspicion Score line
        else if (trimmedLine.startsWith('Suspicion Score:') && currentProcess) {
          const scoreMatch = trimmedLine.match(/Suspicion Score:\s+(\d+)/)
          if (scoreMatch) {
            currentProcess.suspicion_score = parseInt(scoreMatch[1])
            console.log('🔍 PARSING: Suspicion score:', scoreMatch[1])
          }
        }
        // User line
        else if (trimmedLine.startsWith('User:') && currentProcess) {
          const userMatch = trimmedLine.match(/User:\s+(.+)/)
          if (userMatch) {
            currentProcess.username = userMatch[1] === 'None' ? 'Unknown' : userMatch[1]
            console.log('🔍 PARSING: User:', currentProcess.username)
          }
        }
        // Reason lines (start with - and handle spaces before dash)
        else if ((trimmedLine.startsWith('-') || line.match(/^\s*-/)) && currentProcess) {
          const reason = trimmedLine.replace(/^-\s*/, '').trim()
          if (reason && currentProcess.reasons) {
            currentProcess.reasons.push(reason)
            console.log('🔍 PARSING: Added reason:', reason)
          }
        }
      }
      
      // Add the last process
      if (currentProcess && currentProcess.pid && currentProcess.process_name) {
        suspiciousProcesses.push({
          pid: currentProcess.pid,
          process_name: currentProcess.process_name,
          username: currentProcess.username || 'Unknown',
          suspicion_score: currentProcess.suspicion_score || 0,
          reasons: currentProcess.reasons || []
        })
      }
      
      return {
        detection_timestamp: detectionTimestamp,
        analysis_duration_seconds: analysisDuration,
        suspicious_processes: suspiciousProcesses
      }
    } catch (err) {
      console.error('Failed to parse behavioral scan output:', err)
      return null
    }
  }
  const fetchBehavioralHistory = async () => {
    if (!selectedAgent) {
      toast({
        title: "Error",
        description: "Please select an agent first",
        variant: "destructive",
      })
      return
    }

    try {
      setLoading(true)
      
      // Send GET_BEHAVIORAL_HISTORY command
      const result = await apiClient.sendCommand(selectedAgent, 'GET_BEHAVIORAL_HISTORY', 30)
      
      if (result.status === 'success') {
        toast({
          title: "History Request Sent",
          description: "Behavioral history request sent. Fetching results...",
        })
        
        // Wait a moment then fetch the results
        setTimeout(async () => {
          try {
            const results = await apiClient.getCommandResults(selectedAgent)
              
            // Find the most recent GET_BEHAVIORAL_HISTORY result
            const historyResults = results.filter((result: any) => {
              const command = result.command || result.result?.command || ''
              return command.toUpperCase().includes('GET_BEHAVIORAL_HISTORY')
            })
            
            console.log('📊 DEBUG: History results found:', historyResults.length)
            
            const historyResult = historyResults
              .filter((result: any) => {
                const returnCode = result.return_code || result.result?.return_code
                const output = result.output || result.result?.output
                return returnCode === 0 && output
              })
              .sort((a: any, b: any) => new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime())[0]
            
            if (historyResult) {
              const output = historyResult.output || historyResult.result?.output
              
              // Parse the history data and populate the history state
              const parsedHistory = parseHistoryOutput(output)
              setHistoricalScans(parsedHistory)
              setShowHistory(true)
              
              toast({
                title: "History Retrieved",
                description: `Found ${parsedHistory.length} historical scan(s). View in History section below.`,
              })
            } else {
              toast({
                title: "No History Available",
                description: "No behavioral scan history found.",
                variant: "destructive",
              })
            }
          } catch (err) {
            console.error('Failed to fetch history results:', err)
            toast({
              title: "Error",
              description: "Failed to retrieve history data.",
              variant: "destructive",
            })
          }
        }, 3000)
      }
    } catch (err) {
      console.error('Failed to request behavioral history:', err)
      toast({
        title: "Error",
        description: err instanceof Error ? err.message : 'Failed to request behavioral history',
        variant: "destructive",
      })
    } finally {
      setLoading(false)
    }
  }

  const parseHistoryOutput = (output: string): HistoricalScan[] => {
    // Parse the history output into structured data
    // This is a simplified parser - in production you'd want more robust parsing
    try {
      const lines = output.split('\\n')
      const scans: HistoricalScan[] = []
      
      // Look for scan entries in the output
      for (const line of lines) {
        if (line.includes('Detection completed') || line.includes('suspicious processes')) {
          // Extract scan information (this is a simplified example)
          const scan: HistoricalScan = {
            timestamp: new Date().toISOString(),
            agent_id: selectedAgent,
            duration: 120,
            suspicious_count: 0,
            risk_distribution: {
              critical: 0,
              high: 0,
              medium: 0,
              low: 0
            },
            summary: line.trim()
          }
          scans.push(scan)
        }
      }
      
      return scans
    } catch (err) {
      console.error('Failed to parse history output:', err)
      return []
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Behavioral Anomaly Detection</h1>
          <p className="text-muted-foreground">
            Detect security tools and monitoring agents by analyzing system behavior patterns
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Shield className="h-8 w-8 text-primary" />
        </div>
      </div>

      {/* Agent Selection */}
      <Card>
        <CardHeader>
          <CardTitle>Agent Selection</CardTitle>
        </CardHeader>        <CardContent>
          <div className="flex items-center space-x-4">
            <Select value={selectedAgent} onValueChange={setSelectedAgent}>
              <SelectTrigger className="min-w-[200px]">
                <SelectValue placeholder="Select an agent..." />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(agents).map(([agentId, agent]: [string, any]) => (
                  <SelectItem key={agentId} value={agentId}>
                    {agentId} ({agent.status})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Badge variant={selectedAgent && agents[selectedAgent]?.status === 'online' ? 'default' : 'secondary'}>
              {selectedAgent ? (agents[selectedAgent]?.status || 'unknown') : 'No agent selected'}
            </Badge>
          </div>
        </CardContent>
      </Card>

      {/* Control Panel */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Activity className="h-5 w-5" />
            <span>Scan Control</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Scan Status */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Status: {scanStatus.message}</span>
              <Badge variant={scanStatus.scanning ? 'default' : 'secondary'}>
                {scanStatus.scanning ? 'Scanning' : 'Idle'}
              </Badge>
            </div>
            {scanStatus.scanning && (
              <div className="space-y-1">
                <Progress value={scanStatus.progress} />
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>Duration: {scanStatus.duration}s</span>
                  <span>{Math.round(scanStatus.progress)}% Complete</span>
                </div>
              </div>
            )}
          </div>

          <Separator />

          {/* Control Buttons */}
          <div className="flex space-x-2">
            <Button
              onClick={startScan}
              disabled={loading || scanStatus.scanning || !selectedAgent}
              className="flex items-center space-x-2"
            >
              <Play className="h-4 w-4" />
              <span>Start Behavioral Scan</span>
            </Button>
            
            <Button
              variant="outline"
              onClick={stopScan}
              disabled={loading || !scanStatus.scanning}
              className="flex items-center space-x-2"
            >
              <Square className="h-4 w-4" />
              <span>Stop Scan</span>
            </Button>
              <Button
              variant="secondary"
              onClick={fetchReport}
              disabled={loading || !selectedAgent}
              className="flex items-center space-x-2"
            >
              <FileSearch className="h-4 w-4" />
              <span>Get Latest Report</span>
            </Button>
              <Button
              variant="outline"
              onClick={fetchBehavioralHistory}
              disabled={loading || !selectedAgent}
              className="flex items-center space-x-2"
            >
              <Clock className="h-4 w-4" />
              <span>Get History</span>
            </Button>
            
            <Button
              variant="ghost"
              onClick={() => setShowHistory(!showHistory)}
              disabled={historicalScans.length === 0}
              className="flex items-center space-x-2"
            >
              <History className="h-4 w-4" />
              <span>{showHistory ? 'Hide' : 'Show'} History ({historicalScans.length})</span>
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Behavioral Analysis Report */}
      {report && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Eye className="h-5 w-5" />
              <span>Behavioral Analysis Report</span>
            </CardTitle>
            <div className="flex items-center space-x-4 text-sm text-muted-foreground">
              <div className="flex items-center space-x-1">
                <Clock className="h-4 w-4" />
                <span>Analyzed: {new Date(report.detection_timestamp).toLocaleString()}</span>
              </div>
              <div className="flex items-center space-x-1">
                <Activity className="h-4 w-4" />
                <span>Duration: {report.analysis_duration_seconds}s</span>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {report.suspicious_processes.length === 0 ? (
              <Alert>
                <CheckCircle className="h-4 w-4" />
                <AlertDescription>
                  ✅ No suspicious behavioral patterns detected. System appears clean.
                </AlertDescription>
              </Alert>
            ) : (
              <div className="space-y-4">
                <Alert variant="destructive">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    ⚠️ {report.suspicious_processes.length} process(es) showing suspicious behavioral patterns detected!
                  </AlertDescription>
                </Alert>

                <ScrollArea className="h-96">
                  <div className="space-y-4">
                    {report.suspicious_processes.map((process, index) => (
                      <Card key={index} className="border-l-4 border-l-orange-500">
                        <CardHeader className="pb-3">
                          <div className="flex items-center justify-between">
                            <CardTitle className="text-lg flex items-center space-x-2">
                              {getSeverityIcon(process.suspicion_score)}
                              <span>{process.process_name}</span>
                              <Badge variant="outline">PID: {process.pid}</Badge>
                            </CardTitle>                            <Badge variant={getSeverityColor(process.suspicion_score)}>
                              {getSeverityLabel(process.suspicion_score)}: {process.suspicion_score}/10
                            </Badge>
                          </div>
                          <div className="text-sm text-muted-foreground">
                            Running as: <code>{process.username}</code>
                          </div>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            <h4 className="text-sm font-medium flex items-center space-x-2">
                              <AlertTriangle className="h-4 w-4" />
                              <span>Suspicious Behaviors Detected:</span>
                            </h4>
                            <ul className="space-y-1">
                              {process.reasons.map((reason, reasonIndex) => (
                                <li key={reasonIndex} className="flex items-start space-x-2 text-sm">
                                  <div className="flex items-center space-x-1 min-w-0">
                                    {reason.includes('persistent') && <Network className="h-3 w-3 text-blue-500 flex-shrink-0" />}
                                    {reason.includes('disk') && <HardDrive className="h-3 w-3 text-green-500 flex-shrink-0" />}
                                    {reason.includes('CPU') && <Cpu className="h-3 w-3 text-purple-500 flex-shrink-0" />}
                                    {reason.includes('privileges') && <Shield className="h-3 w-3 text-red-500 flex-shrink-0" />}
                                    <span className="break-words">{reason}</span>
                                  </div>
                                </li>
                              ))}
                            </ul>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </ScrollArea>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Behavioral History Section */}
      {showHistory && historicalScans.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <History className="h-5 w-5" />
                <span>Behavioral Scan History</span>
              </div>
              <Button 
                variant="outline" 
                size="sm"
                onClick={() => setShowHistory(!showHistory)}
              >
                {showHistory ? 'Hide' : 'Show'} History
              </Button>
            </CardTitle>
            <div className="text-sm text-muted-foreground">
              Historical behavioral scan results for agent: {selectedAgent}
            </div>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-96">
              <div className="space-y-4">
                {historicalScans.map((scan, index) => (
                  <Card key={index} className="border-l-4 border-l-blue-500">
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <Calendar className="h-4 w-4 text-blue-500" />
                          <span className="font-medium">
                            {new Date(scan.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge variant="outline">
                            Duration: {scan.duration}s
                          </Badge>
                          <Badge variant={scan.suspicious_count > 0 ? 'destructive' : 'default'}>
                            {scan.suspicious_count} Suspicious
                          </Badge>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        {/* Risk Distribution Chart */}
                        <div className="space-y-2">
                          <h4 className="text-sm font-medium flex items-center space-x-2">
                            <TrendingUp className="h-4 w-4" />
                            <span>Risk Distribution</span>
                          </h4>
                          <div className="grid grid-cols-4 gap-2 text-xs">
                            <div className="flex items-center space-x-1">
                              <div className="w-3 h-3 bg-red-500 rounded"></div>
                              <span>Critical: {scan.risk_distribution.critical}</span>
                            </div>
                            <div className="flex items-center space-x-1">
                              <div className="w-3 h-3 bg-orange-500 rounded"></div>
                              <span>High: {scan.risk_distribution.high}</span>
                            </div>
                            <div className="flex items-center space-x-1">
                              <div className="w-3 h-3 bg-yellow-500 rounded"></div>
                              <span>Medium: {scan.risk_distribution.medium}</span>
                            </div>
                            <div className="flex items-center space-x-1">
                              <div className="w-3 h-3 bg-green-500 rounded"></div>
                              <span>Low: {scan.risk_distribution.low}</span>
                            </div>
                          </div>
                        </div>
                        
                        {/* Summary */}
                        <div className="space-y-1">
                          <h4 className="text-sm font-medium">Summary</h4>
                          <p className="text-sm text-muted-foreground">
                            {scan.summary || 'No additional details available'}
                          </p>
                        </div>
                        
                        {/* Progress indicator for scan completeness */}
                        <div className="space-y-1">
                          <div className="flex justify-between text-xs text-muted-foreground">
                            <span>Scan Completeness</span>
                            <span>100%</span>
                          </div>
                          <Progress value={100} className="h-2" />
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </ScrollArea>
            
            {historicalScans.length === 0 && (
              <Alert>
                <History className="h-4 w-4" />
                <AlertDescription>
                  No historical scan data available. Run some behavioral scans to build history.
                </AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>
      )}

      {/* Info Panel */}
      <Card>
        <CardHeader>
          <CardTitle>How It Works</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <h4 className="font-medium">System-Level Indicators</h4>
              <ul className="text-sm text-muted-foreground space-y-1">
                <li>• High-frequency process enumeration</li>
                <li>• Registry access patterns (Windows)</li>
                <li>• WMI query rate monitoring</li>
                <li>• High-privilege execution detection</li>
                <li>• Anomalous resource consumption</li>
                <li>• Kernel driver/system hook loading</li>
              </ul>
            </div>
            <div className="space-y-2">
              <h4 className="font-medium">Network-Level Indicators</h4>
              <ul className="text-sm text-muted-foreground space-y-1">
                <li>• Persistent outbound connections</li>
                <li>• Beaconing traffic patterns</li>
                <li>• High volume data egress</li>
                <li>• Single destination communication</li>
                <li>• Command & control signatures</li>
                <li>• Log forwarding behavior</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
