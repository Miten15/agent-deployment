"use client"

import { useSearchParams } from "next/navigation"
import { CommandPanel } from "@/components/command-panel"

export default function CommandsPage() {
  const searchParams = useSearchParams()
  const preselectedAgent = searchParams.get('agent')

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Command Execution</h1>
        <p className="text-muted-foreground">Send commands to remote agents and view results</p>
      </div>

      <CommandPanel preselectedAgent={preselectedAgent || undefined} />
    </div>
  )
}
