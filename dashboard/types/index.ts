export interface Agent {
  id: string
  hostname: string
  os: string
  os_version?: string
  status: "online" | "offline"
  lastSeen: string
  latestCommand?: {
    command: string
    timestamp: string
    status: "success" | "failed" | "pending"
  }
}

export interface CommandResult {
  id: string
  agentId: string
  command: string
  timestamp: string
  status: "pending" | "success" | "error"
  output?: string
  error?: string
  returnCode?: number
}

export interface SystemInfo {
  hostname: string
  os: string
  osVersion: string
  architecture: string
  domain?: string
  username: string
  uptime: string
}

export interface HardwareInfo {
  cpuModel: string
  cpuCores: number
  memoryTotal: number
  memoryAvailable: number
  memoryUsage: number
}

export interface NetworkInterface {
  name: string
  ip: string
  subnet: string
  mac: string
}

export interface DiskInfo {
  device: string
  mountpoint: string
  fstype: string
  total: number
  used: number
  free: number
  usagePercent: number
}

export interface SoftwareItem {
  name: string
  version: string
  publisher: string
}

export interface AgentInventory {
  system: SystemInfo
  hardware: HardwareInfo
  network: Record<string, NetworkInterface>
  disks: DiskInfo[]
  software: SoftwareItem[]
}
