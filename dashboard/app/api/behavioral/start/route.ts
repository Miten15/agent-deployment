import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  try {
    // Get the auth token from the request (you may need to adjust this based on your auth setup)
    const authToken = request.headers.get('authorization') || 
                     request.cookies.get('authToken')?.value

    if (!authToken) {
      throw new Error('Authentication required')
    }

    // For now, we'll use a default agent_id - you may want to get this from the request or session
    const agent_id = 'default_agent' // You should get this from your agent management system

    // Send START_BEHAVIORAL_SCAN command to the server
    const response = await fetch('http://localhost:8080/api/send-command', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`,
      },      body: JSON.stringify({
        agent_id: agent_id,
        command: 'RUN_BEHAVIORAL_SCAN',
        timeout: 30
      })
    })

    if (!response.ok) {
      throw new Error('Failed to communicate with server')
    }

    const result = await response.json()
    
    return NextResponse.json({
      success: result.status === 'success',
      message: 'Behavioral scan command sent to agent',
      command_id: result.command_id,
      data: result
    })
  } catch (error) {
    console.error('Error starting behavioral scan:', error)
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to start behavioral scan'
      },
      { status: 500 }
    )
  }
}
