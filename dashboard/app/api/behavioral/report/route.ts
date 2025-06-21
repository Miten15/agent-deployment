import { NextRequest, NextResponse } from 'next/server'

export async function GET(request: NextRequest) {
  try {
    // Get the auth token from the request
    const authToken = request.headers.get('authorization') || 
                     request.cookies.get('authToken')?.value

    if (!authToken) {
      throw new Error('Authentication required')
    }

    // For now, we'll use a default agent_id - you may want to get this from the request or session
    const agent_id = 'default_agent' // You should get this from your agent management system

    // First, send GET_BEHAVIORAL_REPORT command to the agent
    const commandResponse = await fetch('http://localhost:8080/api/send-command', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`,
      },      body: JSON.stringify({
        agent_id: agent_id,
        command: 'GET_BEHAVIORAL_HISTORY',
        timeout: 30
      })
    })

    if (!commandResponse.ok) {
      throw new Error('Failed to request behavioral report from agent')
    }

    const commandResult = await commandResponse.json()
    
    // Wait a moment for the command to be processed
    await new Promise(resolve => setTimeout(resolve, 2000))
    
    // Now get the command results
    const resultsResponse = await fetch(`http://localhost:8080/api/command-results/${agent_id}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${authToken}`,
      }
    })

    if (!resultsResponse.ok) {
      throw new Error('Failed to get command results from server')
    }

    const results = await resultsResponse.json()      // Find the most recent behavioral report result
    const behavioralResult = results
      .filter((result: any) => result.command && result.command.includes('GET_BEHAVIORAL_HISTORY'))
      .sort((a: any, b: any) => new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime())[0]
    
    console.log('Behavioral result from API:', behavioralResult) // Debug log
    
    // Check for behavioral_history in the command result
    if (behavioralResult && (behavioralResult.behavioral_history || behavioralResult.report_data)) {
      const reportData = behavioralResult.behavioral_history || behavioralResult.report_data
      
      if (reportData && reportData.length > 0) {
        // Use the latest scan report
        return NextResponse.json({
          success: true,
          message: 'Behavioral report retrieved successfully',
          report: reportData[reportData.length - 1], // Latest scan
          allReports: reportData, // All scan history
          data: behavioralResult
        })
      } else {
        return NextResponse.json({
          success: false,
          error: 'Behavioral history is empty. Please run a scan first.',
          message: 'No behavioral scan data found'
        })
      }
    } else {
      return NextResponse.json({
        success: false,
        error: 'No behavioral report available. Please run a scan first.',
        message: 'No behavioral report data found'
      })
    }
  } catch (error) {
    console.error('Error getting behavioral report:', error)
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to get behavioral report'
      },
      { status: 500 }
    )
  }
}
