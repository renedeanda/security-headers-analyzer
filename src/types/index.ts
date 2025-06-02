export interface SecurityHeader {
  name: string
  value?: string
  status: 'secure' | 'weak' | 'missing'
  score: number
  explanation: string
  recommendation?: string
}

export interface HeaderAnalysis {
  url: string
  headers: SecurityHeader[]
  rawHeaders?: RawHeaders
  overallScore: number
  timestamp: string
  ipAddress?: string
  // Advanced analysis results
  bypassVulnerabilities?: import('../lib/advanced-security-analysis').SecurityVulnerability[]
  headerInteractions?: import('../lib/advanced-security-analysis').HeaderInteraction[]
  securityMaturity?: import('../lib/advanced-security-analysis').SecurityMaturityReport
  threatMapping?: import('../lib/advanced-security-analysis').ThreatMapping
}

export interface RawHeaders {
  [key: string]: string
}