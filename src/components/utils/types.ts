export interface SecurityHeader {
  name: string;
  value?: string;
  status: 'secure' | 'weak' | 'missing';
  score: number;
  explanation: string;
  recommendation?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
}

export interface HeaderAnalysis {
  url: string;
  headers: SecurityHeader[];
  rawHeaders?: Record<string, string>;
  overallScore: number;
  timestamp: string;
  ipAddress?: string;
  method: string;
  cached?: boolean;
  cacheAge?: number;
  responseInfo?: {
    status: number;
    statusText: string;
    redirected: boolean;
    finalUrl?: string;
    ipAddress?: string;
    headers?: {
      server?: string;
      poweredBy?: string;
      contentType?: string;
    };
  };
  metadata?: {
    timestamp: string;
    processingTime: number;
    method: string;
    ipAddress?: string;
  };
}

export interface GradeTheme {
  grade: string;
  bgGradient: string;
  borderColor: string;
  circleColor: string;
  accentColor: string;
  badgeColor: string;
  description: string;
  icon: string;
}