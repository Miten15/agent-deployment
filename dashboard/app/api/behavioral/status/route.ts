import { NextRequest, NextResponse } from 'next/server'

export async function GET(request: NextRequest) {
  try {
    // This could be enhanced to get real-time status from the agent
    // For now, we'll return a mock status that the frontend can use
    
    // In a real implementation, you might:
    // 1. Check if the behavioral detector is running
    // 2. Get progress information
    // 3. Get current scan duration
    
    const response = await fetch('http://localhost:8080/api/status', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      }
    })

    if (!response.ok) {
      throw new Error('Failed to communicate with agent')
    }

    const agentStatus = await response.json()
    
    // Mock behavioral scan status for now
    // In a real implementation, this would come from the agent
    const mockStatus = {
      scanning: false,
      progress: 0,
      duration: 0,
      message: 'Ready to scan'
    }
    
    return NextResponse.json(mockStatus)
  } catch (error) {
    console.error('Error getting behavioral status:', error)
    return NextResponse.json(
      {
        scanning: false,
        progress: 0,
        duration: 0,
        message: 'Error connecting to agent',
        error: error instanceof Error ? error.message : 'Failed to get status'
      },
      { status: 500 }
    )
  }
}
