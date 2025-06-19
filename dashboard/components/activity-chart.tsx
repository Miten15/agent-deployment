"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { TrendingUp } from "lucide-react"
import { useEffect, useRef } from "react"

export function ActivityChart() {
  const chartRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    // Simple D3.js chart implementation
    if (typeof window !== "undefined" && chartRef.current) {
      // Generate sample data
      const data = Array.from({ length: 24 }, (_, i) => ({
        hour: i,
        agents: Math.floor(Math.random() * 10) + 5,
        commands: Math.floor(Math.random() * 50) + 10,
      }))

      // Create simple SVG chart
      const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg")
      svg.setAttribute("width", "100%")
      svg.setAttribute("height", "200")
      svg.setAttribute("viewBox", "0 0 400 200")

      // Create bars for agent activity
      data.forEach((d, i) => {
        const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect")
        rect.setAttribute("x", (i * 16 + 10).toString())
        rect.setAttribute("y", (200 - d.agents * 10).toString())
        rect.setAttribute("width", "12")
        rect.setAttribute("height", (d.agents * 10).toString())
        rect.setAttribute("fill", "hsl(var(--primary))")
        rect.setAttribute("opacity", "0.7")
        svg.appendChild(rect)
      })

      chartRef.current.innerHTML = ""
      chartRef.current.appendChild(svg)
    }
  }, [])

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <TrendingUp className="h-5 w-5" />
          Activity Overview
        </CardTitle>
        <CardDescription>Agent activity over the last 24 hours</CardDescription>
      </CardHeader>
      <CardContent>
        <div ref={chartRef} className="w-full h-[200px] flex items-center justify-center">
          <div className="text-muted-foreground">Loading chart...</div>
        </div>
        <div className="flex items-center justify-between mt-4 text-sm">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-primary rounded-sm opacity-70"></div>
            <span className="text-muted-foreground">Agent Connections</span>
          </div>
          <span className="text-muted-foreground">Last 24 hours</span>
        </div>
      </CardContent>
    </Card>
  )
}
