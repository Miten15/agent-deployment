'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Label } from '@/components/ui/label'
import { useToast } from '@/hooks/use-toast'
import { apiClient } from '@/lib/api'
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  Clock,
  Activity,
  TrendingUp,
  Download,
  Play,
  RefreshCw
} from 'lucide-react'

interface HardeningFinding {
  id: string
  category: string
  name: string
  result: string
  recommended: string
  severity: 'Passed' | 'Low' | 'Medium' | 'High'
  method: string
  operator: string
}

interface HardeningSummary {
  total_checks: number
  passed: number
  low: number
  medium: number
  high: number
  score: number
}

interface HardeningData {
  status: string
  timestamp: string
  agent_id: string
  findings: HardeningFinding[]
  summary: HardeningSummary
  output: string
  errors: string
}

interface Agent {
  id: string
  hostname: string
  os: string
  status: 'online' | 'offline'
  last_seen: string
}

export default function HardeningPage() {
  const [agents, setAgents] = useState<Record<string, any>>({})
  const [selectedAgent, setSelectedAgent] = useState<string>('')
  const [hardeningData, setHardeningData] = useState<HardeningData | null>(null)
  const [isRunningAudit, setIsRunningAudit] = useState(false)
  const [lastAuditTime, setLastAuditTime] = useState<string>('')
  const [loading, setLoading] = useState(false)
  const { toast } = useToast()

  // Fetch agents on component mount
  useEffect(() => {
    fetchAgents()
    // Auto-refresh agents every 10 seconds
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

  const runHardeningAudit = async () => {
    if (!selectedAgent) {
      toast({
        title: "Error",
        description: "Please select an agent first",
        variant: "destructive",
      })
      return
    }

    console.log('🚀 Starting hardening audit for agent:', selectedAgent)
    setIsRunningAudit(true)
    setLoading(true)

    try {
      // Send hardening audit command
      console.log('📤 Sending RUN_HARDENING_AUDIT command to agent:', selectedAgent)
      const commandResult = await apiClient.sendCommand(selectedAgent, 'RUN_HARDENING_AUDIT')
      console.log('✅ Command sent successfully, result:', commandResult)
      
      toast({
        title: "Audit Started",
        description: "Hardening audit is running. Checking for results...",
      })
      
      // Start immediate result checking
      console.log('🔍 Starting result polling...')
      await pollForResults()
    } catch (err) {
      console.error('❌ Failed to run hardening audit:', err)
      toast({
        title: "Error",
        description: "Failed to start hardening audit",
        variant: "destructive",
      })
      setIsRunningAudit(false)
      setLoading(false)
    }
  }
  const pollForResults = async () => {
    let attempts = 0
    const maxAttempts = 60 // 5 minutes max (60 attempts * 5 seconds)
    
    const checkResults = async (): Promise<boolean> => {
      attempts++
      console.log(`🔍 Checking for hardening results (attempt ${attempts}/${maxAttempts}) for agent:`, selectedAgent)
      
      try {
        const results = await apiClient.getCommandResults(selectedAgent)
        console.log('📋 All command results received:', results)
          // Look for hardening audit results
        const hardeningResults = results.filter((result: any) => {
          console.log('🔎 Checking result:', {
            command: result.result?.command || result.command,
            success: result.result?.success || result.success,
            hasHardeningData: !!(result.result?.hardening_data || result.hardening_data),
            hasOutput: !!(result.result?.output || result.output),
            timestamp: result.timestamp
          })
          return (result.result?.command || result.command) === 'RUN_HARDENING_AUDIT'
        })

        console.log('🎯 Filtered hardening results:', hardeningResults.length, 'found')

        if (hardeningResults.length > 0) {
          const latestResult = hardeningResults
            .sort((a: any, b: any) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())[0]

          console.log('📊 Latest hardening result:', latestResult)

          // Check for hardening data in the nested structure
          const hardeningData = latestResult.result?.hardening_data || latestResult.hardening_data
          const resultData = latestResult.result || latestResult

          if (hardeningData) {
            console.log('✅ Found hardening_data, setting results:', hardeningData)
            setHardeningData(hardeningData)
            setLastAuditTime(latestResult.timestamp)
            setIsRunningAudit(false)
            setLoading(false)
            
            toast({
              title: "Audit Complete",
              description: `Security audit completed with score: ${hardeningData.summary.score.toFixed(2)}/6.0`,
            })
            return true
          } else if (resultData.success && resultData.output?.includes('HardeningKitty')) {            console.log('📝 No hardening_data but found HardeningKitty output, parsing...')
            
            // Parse from output
            const output = resultData.output
            const scoreMatch = output.match(/HardeningKitty Score: ([\d.]+)\/6\.0/)
            const totalMatch = output.match(/Total Checks: (\d+)/)
            const passedMatch = output.match(/✅ Passed: (\d+)/)
            const lowMatch = output.match(/🟡 Low Risk: (\d+)/)
            const mediumMatch = output.match(/🟠 Medium Risk: (\d+)/)
            const highMatch = output.match(/🔴 High Risk: (\d+)/)
            
            if (scoreMatch) {
              const mockHardeningData = {
                status: 'success',
                timestamp: latestResult.timestamp,
                agent_id: selectedAgent,
                findings: [],
                summary: {
                  total_checks: totalMatch ? parseInt(totalMatch[1]) : 0,
                  passed: passedMatch ? parseInt(passedMatch[1]) : 0,
                  low: lowMatch ? parseInt(lowMatch[1]) : 0,
                  medium: mediumMatch ? parseInt(mediumMatch[1]) : 0,
                  high: highMatch ? parseInt(highMatch[1]) : 0,
                  score: parseFloat(scoreMatch[1])
                },
                output: output,
                errors: ''
              }
              
              console.log('🔧 Created hardening data from output:', mockHardeningData)
              setHardeningData(mockHardeningData)
              setLastAuditTime(latestResult.timestamp)
              setIsRunningAudit(false)
              setLoading(false)
              
              toast({
                title: "Audit Complete",
                description: `Security audit completed with score: ${mockHardeningData.summary.score}/6.0`,
              })
              return true
            } else {
              console.log('❌ Could not parse score from output:', output.substring(0, 200))
            }
          } else {
            console.log('⚠️ Found result but no usable data:', {
              success: resultData.success,
              hasOutput: !!resultData.output,
              outputPreview: resultData.output?.substring(0, 100)
            })
          }
        }
        
        // Continue polling if no results found
        if (attempts < maxAttempts) {
          console.log(`⏳ No usable results found, waiting 5 seconds before next attempt...`)
          await new Promise(resolve => setTimeout(resolve, 5000)) // Wait 5 seconds
          return await checkResults()
        } else {
          // Max attempts reached
          console.log('❌ Max polling attempts reached')
          setIsRunningAudit(false)
          setLoading(false)
          toast({
            title: "Timeout",
            description: "Hardening audit is taking longer than expected. Please check manually.",
            variant: "destructive",
          })
          return false
        }
      } catch (error) {
        console.error('❌ Error checking results:', error)
        if (attempts < maxAttempts) {
          await new Promise(resolve => setTimeout(resolve, 5000))
          return await checkResults()
        } else {
          setIsRunningAudit(false)
          setLoading(false)
          toast({
            title: "Error",
            description: "Failed to check audit results",
            variant: "destructive",
          })          
          return false
        }
      }
    }

    await checkResults()
  }

  const refreshResults = async () => {
    if (!selectedAgent) {
      toast({
        title: "Error",
        description: "Please select an agent first",
        variant: "destructive",
      })
      return
    }

    console.log('🔄 Refreshing hardening results for agent:', selectedAgent)

    toast({
      title: "Refreshing",
      description: "Checking for latest hardening results...",
    })

    // Check for results immediately
    try {
      const results = await apiClient.getCommandResults(selectedAgent)
      console.log('📋 Refresh - All command results:', results)
      
      const hardeningResults = results.filter((result: any) => {
        const command = result.result?.command || result.command
        const hasHardeningData = !!(result.result?.hardening_data || result.hardening_data)
        const hasOutput = !!(result.result?.output || result.output)
        
        console.log('🔎 Refresh - Checking result:', {
          command,
          hasHardeningData,
          hasOutput,
          timestamp: result.timestamp
        })
        
        return command === 'RUN_HARDENING_AUDIT'
      })

      console.log('🎯 Refresh - Found hardening results:', hardeningResults.length)

      if (hardeningResults.length > 0) {
        const latestResult = hardeningResults
          .sort((a: any, b: any) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())[0]

        console.log('📊 Refresh - Latest result:', latestResult)

        // Check for hardening data in the nested structure
        const hardeningData = latestResult.result?.hardening_data || latestResult.hardening_data
        const resultData = latestResult.result || latestResult

        if (hardeningData) {
          console.log('✅ Refresh - Found hardening data:', hardeningData)
          setHardeningData(hardeningData)
          setLastAuditTime(latestResult.timestamp)
          
          toast({
            title: "Results Found",
            description: `Latest audit found with score: ${hardeningData.summary.score.toFixed(2)}/6.0`,
          })
        } else if (resultData.success && resultData.output?.includes('HardeningKitty')) {
          console.log('📝 Refresh - Parsing from output')
          
          // Parse from output
          const output = resultData.output
          const scoreMatch = output.match(/HardeningKitty Score: ([\d.]+)\/6\.0/)
          
          if (scoreMatch) {
            const totalMatch = output.match(/Total Checks: (\d+)/)
            const passedMatch = output.match(/✅ Passed: (\d+)/)
            const lowMatch = output.match(/🟡 Low Risk: (\d+)/)
            const mediumMatch = output.match(/🟠 Medium Risk: (\d+)/)
            const highMatch = output.match(/🔴 High Risk: (\d+)/)
            
            const mockHardeningData = {
              status: 'success',
              timestamp: latestResult.timestamp,
              agent_id: selectedAgent,
              findings: [],
              summary: {
                total_checks: totalMatch ? parseInt(totalMatch[1]) : 0,
                passed: passedMatch ? parseInt(passedMatch[1]) : 0,
                low: lowMatch ? parseInt(lowMatch[1]) : 0,
                medium: mediumMatch ? parseInt(mediumMatch[1]) : 0,
                high: highMatch ? parseInt(highMatch[1]) : 0,
                score: parseFloat(scoreMatch[1])
              },
              output: output,
              errors: ''
            }
            
            console.log('🔧 Refresh - Created hardening data from output')
            setHardeningData(mockHardeningData)
            setLastAuditTime(latestResult.timestamp)
            
            toast({
              title: "Results Found",
              description: `Latest audit found with score: ${mockHardeningData.summary.score}/6.0`,
            })
          } else {
            toast({
              title: "Results Found",
              description: "Found audit results but could not parse score",
              variant: "destructive",
            })
          }
        } else {
          console.log('❌ Refresh - No usable data found')
          toast({
            title: "No Results",
            description: "No completed hardening audits found for this agent",
            variant: "destructive",
          })
        }
      } else {
        console.log('❌ Refresh - No hardening results found')
        toast({
          title: "No Results",
          description: "No hardening audit results found for this agent",
          variant: "destructive",
        })
      }
    } catch (error) {
      console.error('❌ Refresh error:', error)
      toast({
        title: "Error",
        description: "Failed to refresh results",
        variant: "destructive",
      })
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 5.5) return 'text-green-600'
    if (score >= 4.5) return 'text-blue-600'
    if (score >= 3.5) return 'text-yellow-600'
    if (score >= 2.5) return 'text-orange-600'
    return 'text-red-600'
  }

  const getScoreEmoji = (score: number) => {
    if (score >= 5.5) return '😹'
    if (score >= 4.5) return '😺'
    if (score >= 3.5) return '😼'
    if (score >= 2.5) return '😿'
    if (score >= 1.5) return '🙀'
    return '😾'
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'Passed': return <CheckCircle className="w-4 h-4 text-green-600" />
      case 'Low': return <AlertTriangle className="w-4 h-4 text-yellow-600" />
      case 'Medium': return <AlertTriangle className="w-4 h-4 text-orange-600" />
      case 'High': return <XCircle className="w-4 h-4 text-red-600" />
      default: return <AlertTriangle className="w-4 h-4 text-gray-600" />
    }
  }

  const getSeverityBadgeColor = (severity: string) => {
    switch (severity) {
      case 'Passed': return 'bg-green-100 text-green-800 border-green-200'
      case 'Low': return 'bg-yellow-100 text-yellow-800 border-yellow-200'
      case 'Medium': return 'bg-orange-100 text-orange-800 border-orange-200'
      case 'High': return 'bg-red-100 text-red-800 border-red-200'
      default: return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Shield className="w-8 h-8 text-blue-600" />
            Windows Hardening
          </h1>
          <p className="text-muted-foreground mt-1">
            System security assessment and hardening with HardeningKitty
          </p>
        </div>
          <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="agent-select">Select Agent</Label>
            <div className="flex items-center gap-4">
              <Select value={selectedAgent} onValueChange={setSelectedAgent}>
                <SelectTrigger id="agent-select" className="w-64">
                  <SelectValue placeholder="Choose an agent for hardening audit" />
                </SelectTrigger>
                <SelectContent>
                  {Object.keys(agents).length === 0 ? (
                    <SelectItem value="no-agents" disabled>
                      No agents connected
                    </SelectItem>
                  ) : (
                    Object.entries(agents)
                      .filter(([_, agent]: [string, any]) => agent.status === 'online')
                      .map(([id, agent]: [string, any]) => (
                        <SelectItem key={id} value={id}>
                          <div className="flex items-center gap-2">
                            <Badge 
                              variant="outline" 
                              className="bg-green-500/10 text-green-600 border-green-500/20"
                            >
                              ●
                            </Badge>
                            {agent.hostname || id.substring(0, 12)} ({agent.os || 'Unknown'})
                          </div>
                        </SelectItem>
                      ))
                  )}
                </SelectContent>
              </Select>
                <Button 
                onClick={runHardeningAudit} 
                disabled={!selectedAgent || isRunningAudit}
                className="flex items-center gap-2"
              >
                {isRunningAudit ? (
                  <>
                    <Clock className="w-4 h-4 animate-spin" />
                    Running Audit...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4" />
                    Run Hardening Audit
                  </>
                )}
              </Button>
                <Button 
                variant="outline" 
                onClick={refreshResults}
                disabled={!selectedAgent}
                className="flex items-center gap-2"
              >
                <RefreshCw className="w-4 h-4" />
                Check Results
              </Button>
            </div>
          </div>
        </div>
      </div>{loading && (
        <Alert>
          <Activity className="h-4 w-4" />
          <AlertTitle>Running Hardening Audit</AlertTitle>
          <AlertDescription>
            Please wait while the system security assessment is being performed...
          </AlertDescription>
        </Alert>
      )}

      {hardeningData && (
        <div className="space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">HardeningKitty Score</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <div className={`text-2xl font-bold ${getScoreColor(hardeningData.summary.score)}`}>
                    {hardeningData.summary.score.toFixed(2)}/6.0
                  </div>
                  <div className="text-2xl">
                    {getScoreEmoji(hardeningData.summary.score)}
                  </div>
                </div>
                <Progress 
                  value={(hardeningData.summary.score / 6) * 100} 
                  className="mt-2"
                />
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-600" />
                  Passed
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-green-600">
                  {hardeningData.summary.passed}
                </div>
                <p className="text-xs text-muted-foreground">
                  {((hardeningData.summary.passed / hardeningData.summary.total_checks) * 100).toFixed(1)}% of total
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-orange-600" />
                  Medium/High Risk
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-orange-600">
                  {hardeningData.summary.medium + hardeningData.summary.high}
                </div>
                <p className="text-xs text-muted-foreground">
                  Requires attention
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <TrendingUp className="w-4 h-4 text-blue-600" />
                  Total Checks
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {hardeningData.summary.total_checks}
                </div>
                <p className="text-xs text-muted-foreground">
                  Security controls assessed
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Detailed Results */}
          <Card>
            <CardHeader>
              <CardTitle>Hardening Assessment Results</CardTitle>
              <CardDescription>
                Last scan: {new Date(hardeningData.timestamp).toLocaleString()}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="findings" className="w-full">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="findings">Security Findings</TabsTrigger>
                  <TabsTrigger value="categories">By Category</TabsTrigger>
                  <TabsTrigger value="output">Raw Output</TabsTrigger>
                </TabsList>
                
                <TabsContent value="findings" className="space-y-4">
                  <div className="max-h-96 overflow-y-auto space-y-2">
                    {hardeningData.findings
                      .sort((a, b) => {
                        const severityOrder = { 'High': 0, 'Medium': 1, 'Low': 2, 'Passed': 3 }
                        return severityOrder[a.severity as keyof typeof severityOrder] - severityOrder[b.severity as keyof typeof severityOrder]
                      })
                      .map((finding, index) => (
                        <div key={index} className="border rounded-lg p-3 space-y-2">
                          <div className="flex items-start justify-between">
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-1">
                                {getSeverityIcon(finding.severity)}
                                <span className="font-medium">ID {finding.id}</span>
                                <Badge className={getSeverityBadgeColor(finding.severity)}>
                                  {finding.severity}
                                </Badge>
                              </div>
                              <h4 className="font-semibold">{finding.name}</h4>
                              <p className="text-sm text-muted-foreground">{finding.category}</p>
                            </div>
                          </div>
                          
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
                            <div>
                              <span className="font-medium">Current: </span>
                              <span className="text-muted-foreground">{finding.result || 'N/A'}</span>
                            </div>
                            <div>
                              <span className="font-medium">Recommended: </span>
                              <span className="text-muted-foreground">{finding.recommended || 'N/A'}</span>
                            </div>
                          </div>
                        </div>
                      ))}
                  </div>
                </TabsContent>
                
                <TabsContent value="categories" className="space-y-4">
                  <div className="space-y-3">
                    {Array.from(new Set(hardeningData.findings.map(f => f.category)))
                      .map(category => {
                        const categoryFindings = hardeningData.findings.filter(f => f.category === category)
                        const passed = categoryFindings.filter(f => f.severity === 'Passed').length
                        const total = categoryFindings.length
                        
                        return (
                          <div key={category} className="border rounded-lg p-4">
                            <div className="flex items-center justify-between mb-2">
                              <h4 className="font-semibold">{category}</h4>
                              <Badge variant="outline">
                                {passed}/{total} passed
                              </Badge>
                            </div>
                            <Progress value={(passed / total) * 100} className="mb-2" />
                            <div className="flex gap-4 text-sm">
                              <span className="text-green-600">
                                ✓ {categoryFindings.filter(f => f.severity === 'Passed').length}
                              </span>
                              <span className="text-yellow-600">
                                ⚠ {categoryFindings.filter(f => f.severity === 'Low').length}
                              </span>
                              <span className="text-orange-600">
                                ⚠ {categoryFindings.filter(f => f.severity === 'Medium').length}
                              </span>
                              <span className="text-red-600">
                                ✗ {categoryFindings.filter(f => f.severity === 'High').length}
                              </span>
                            </div>
                          </div>
                        )
                      })}
                  </div>
                </TabsContent>
                  <TabsContent value="output" className="space-y-4">
                  <div className="bg-gray-100 dark:bg-gray-800 border dark:border-gray-700 p-4 rounded-lg">
                    <pre className="text-sm text-gray-900 dark:text-gray-100 whitespace-pre-wrap max-h-96 overflow-y-auto font-mono">
                      {hardeningData.output}
                    </pre>
                  </div>
                  
                  {hardeningData.errors && (
                    <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-4 rounded-lg">
                      <h4 className="font-semibold text-red-800 dark:text-red-200 mb-2">Errors/Warnings:</h4>
                      <pre className="text-sm text-red-700 dark:text-red-300 whitespace-pre-wrap font-mono">
                        {hardeningData.errors}
                      </pre>
                    </div>
                  )}
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>
      )}

      {!hardeningData && !loading && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="w-6 h-6 text-blue-600" />
              Get Started with System Hardening
            </CardTitle>
            <CardDescription>
              Run a comprehensive security assessment of your Windows system using HardeningKitty
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
              <div className="flex items-start gap-3">
                <ShieldCheck className="w-5 h-5 text-green-600 mt-0.5" />
                <div>
                  <h4 className="font-semibold">Security Assessment</h4>
                  <p className="text-muted-foreground">
                    Comprehensive evaluation of Windows security settings against industry standards
                  </p>
                </div>
              </div>
              
              <div className="flex items-start gap-3">
                <Activity className="w-5 h-5 text-blue-600 mt-0.5" />
                <div>
                  <h4 className="font-semibold">Real-time Scoring</h4>
                  <p className="text-muted-foreground">
                    Get a security score from 1-6 based on your system's compliance with best practices
                  </p>
                </div>
              </div>
              
              <div className="flex items-start gap-3">
                <Download className="w-5 h-5 text-purple-600 mt-0.5" />
                <div>
                  <h4 className="font-semibold">Detailed Reports</h4>
                  <p className="text-muted-foreground">
                    Actionable insights and recommendations to improve your system security
                  </p>
                </div>
              </div>
            </div>
            
            <Alert>
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>Before You Start</AlertTitle>
              <AlertDescription>
                Select an agent from the dropdown above and click "Run Hardening Audit" to begin the security assessment.
                The process may take several minutes to complete.
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
