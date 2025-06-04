'use client'
import React, { useState, useEffect } from 'react';
import { Search, Globe, Shield, AlertTriangle, CheckCircle, XCircle, Clock, Info, ExternalLink, Zap, ArrowRight, TrendingUp, Award, Bug, Server, MapPin, Timer, Wifi } from 'lucide-react';

// Types
interface SecurityHeader {
  name: string;
  value?: string;
  status: 'secure' | 'weak' | 'missing';
  score: number;
  explanation: string;
  recommendation?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
}

interface HeaderAnalysis {
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

// Security header configuration
const SECURITY_HEADERS = [
  'content-security-policy',
  'content-security-policy-report-only',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'x-xss-protection'
];

// Improved scoring model with better weights
const HEADER_WEIGHTS = {
  'content-security-policy': 40,              // Most critical - XSS protection
  'strict-transport-security': 25,            // Critical - HTTPS security
  'x-frame-options': 15,                      // Important - clickjacking
  'content-security-policy-report-only': 8,  // Monitoring only
  'x-content-type-options': 6,               // MIME protection
  'referrer-policy': 4,                      // Privacy
  'permissions-policy': 2,                   // Modern features
  'x-xss-protection': 0                      // Legacy, mostly ignored
};

// Individual analysis functions with proper scoring
const analyzeCspHeader = (name: string, value?: string, isEnforcing: boolean = true): SecurityHeader => {
  if (!value) {
    return {
      name,
      value,
      status: 'missing',
      score: 0,
      severity: 'critical',
      explanation: 'Content Security Policy prevents XSS attacks by controlling resource loading.',
      recommendation: 'Add CSP header: "default-src \'self\'; script-src \'self\' \'nonce-{random}\'"'
    };
  }
  
  let score = 100;
  let status: 'secure' | 'weak' | 'missing' = 'secure';
  let severity: 'critical' | 'high' | 'medium' | 'low' = 'low';
  
  // Major security issues
  if (value.includes("'unsafe-inline'")) {
    score -= 35;
    status = 'weak';
    severity = 'high';
  }
  if (value.includes("'unsafe-eval'")) {
    score -= 35;
    status = 'weak';
    severity = 'high';
  }
  if (value.includes('*') && !value.includes("'nonce-") && !value.includes("'sha256-")) {
    score -= 25;
    status = 'weak';
    severity = 'medium';
  }
  
  // Bonus for good practices
  if (value.includes("'strict-dynamic'")) score += 10;
  if (value.includes("'nonce-") || value.includes("'sha256-")) score += 10;
  
  // Report-only gets reduced score
  if (!isEnforcing) {
    score = Math.round(score * 0.6);
    severity = score < 50 ? 'medium' : 'low';
  }
  
  return {
    name,
    value,
    status,
    score: Math.max(0, Math.min(100, score)),
    severity,
    explanation: isEnforcing ? 'Enforces resource loading restrictions to prevent XSS attacks.' : 'Monitors CSP violations without blocking content.',
    recommendation: status === 'weak' ? 'Remove unsafe directives and use nonces or hashes' : undefined
  };
};

const analyzeHstsHeader = (value?: string): SecurityHeader => {
  if (!value) {
    return {
      name: 'Strict-Transport-Security',
      value,
      status: 'missing',
      score: 0,
      severity: 'high',
      explanation: 'HSTS forces HTTPS connections and prevents protocol downgrade attacks.',
      recommendation: 'Add HSTS: "max-age=31536000; includeSubDomains; preload"'
    };
  }
  
  let score = 70; // Base score
  let status: 'secure' | 'weak' | 'missing' = 'secure';
  
  // Parse max-age
  const maxAgeMatch = value.match(/max-age=(\d+)/);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;
  
  if (maxAge < 86400) { // Less than 1 day
    score = 30;
    status = 'weak';
  } else if (maxAge >= 31536000) { // 1 year+
    score = 85;
  }
  
  if (value.includes('includeSubDomains')) score += 10;
  if (value.includes('preload')) score += 5;
  
  return {
    name: 'Strict-Transport-Security',
    value,
    status,
    score: Math.min(100, score),
    severity: status === 'weak' ? 'medium' : 'low',
    explanation: 'Enforces HTTPS and prevents man-in-the-middle attacks.',
    recommendation: status === 'weak' ? 'Increase max-age and add includeSubDomains' : undefined
  };
};

const analyzeFrameOptions = (value?: string): SecurityHeader => {
  if (!value) {
    return {
      name: 'X-Frame-Options',
      value,
      status: 'missing',
      score: 0,
      severity: 'medium',
      explanation: 'Prevents clickjacking by controlling iframe embedding.',
      recommendation: 'Add X-Frame-Options: DENY or SAMEORIGIN'
    };
  }
  
  const lowerValue = value.toLowerCase();
  const isSecure = lowerValue === 'deny' || lowerValue === 'sameorigin';
  
  return {
    name: 'X-Frame-Options',
    value,
    status: isSecure ? 'secure' : 'weak',
    score: isSecure ? 100 : 40,
    severity: isSecure ? 'low' : 'medium',
    explanation: 'Controls whether your site can be framed by other sites.',
    recommendation: !isSecure ? 'Use DENY or SAMEORIGIN instead of permissive values' : undefined
  };
};

const analyzeContentTypeOptions = (value?: string): SecurityHeader => {
  const isSecure = value?.toLowerCase() === 'nosniff';
  
  return {
    name: 'X-Content-Type-Options',
    value,
    status: isSecure ? 'secure' : 'missing',
    score: isSecure ? 100 : 0,
    severity: isSecure ? 'low' : 'medium',
    explanation: 'Prevents MIME-sniffing attacks by enforcing declared content types.',
    recommendation: !isSecure ? 'Set X-Content-Type-Options: nosniff' : undefined
  };
};

const analyzeReferrerPolicy = (value?: string): SecurityHeader => {
  if (!value) {
    return {
      name: 'Referrer-Policy',
      value,
      status: 'missing',
      score: 0,
      severity: 'low',
      explanation: 'Controls referrer information sent with requests.',
      recommendation: 'Set Referrer-Policy: strict-origin-when-cross-origin'
    };
  }
  
  // Score based on privacy level
  let score = 100;
  let status: 'secure' | 'weak' | 'missing' = 'secure';
  
  const lowerValue = value.toLowerCase();
  if (lowerValue.includes('unsafe-url') || lowerValue === 'origin-when-cross-origin') {
    score = 60;
    status = 'weak';
  }
  
  return {
    name: 'Referrer-Policy',
    value,
    status,
    score,
    severity: status === 'weak' ? 'medium' : 'low',
    explanation: 'Controls how much referrer information is shared.',
    recommendation: status === 'weak' ? 'Use more restrictive policy like strict-origin-when-cross-origin' : undefined
  };
};

const analyzePermissionsPolicy = (value?: string): SecurityHeader => {
  if (!value) {
    return {
      name: 'Permissions-Policy',
      value,
      status: 'missing',
      score: 0,
      severity: 'low',
      explanation: 'Controls browser feature access to reduce attack surface.',
      recommendation: 'Add Permissions-Policy to restrict unused features'
    };
  }
  
  // Count restricted features
  const restrictedFeatures = ['camera', 'microphone', 'geolocation', 'payment'];
  const disabledCount = restrictedFeatures.filter(feature => 
    value.includes(`${feature}=()`)
  ).length;
  
  const score = 70 + (disabledCount / restrictedFeatures.length) * 30;
  
  return {
    name: 'Permissions-Policy',
    value,
    status: 'secure',
    score: Math.round(score),
    severity: 'low',
    explanation: 'Controls which browser features can be used.',
    recommendation: disabledCount < 2 ? 'Consider restricting more features' : undefined
  };
};

const analyzeXSSProtection = (value?: string, allHeaders?: Record<string, string>): SecurityHeader => {
  const hasCsp = allHeaders?.['content-security-policy'];
  
  if (!value) {
    return {
      name: 'X-XSS-Protection',
      value,
      status: hasCsp ? 'secure' : 'missing',
      score: hasCsp ? 90 : 0,
      severity: hasCsp ? 'low' : 'medium',
      explanation: 'Legacy XSS protection. CSP provides better security.',
      recommendation: hasCsp ? 'Not needed with CSP' : 'Add X-XSS-Protection: 1; mode=block or implement CSP'
    };
  }
  
  // X-XS-Protection: 0 is actually good if CSP is present
  if (value === '0' && hasCsp) {
    return {
      name: 'X-XSS-Protection',
      value,
      status: 'secure',
      score: 95,
      severity: 'low',
      explanation: 'Correctly disabled when CSP is present.',
      recommendation: undefined
    };
  }
  
  const isGoodConfig = value === '1; mode=block';
  
  return {
    name: 'X-XSS-Protection',
    value,
    status: isGoodConfig ? 'secure' : 'weak',
    score: isGoodConfig ? 85 : 50,
    severity: 'low',
    explanation: 'Legacy browser XSS filtering.',
    recommendation: !isGoodConfig ? 'Set to "1; mode=block" or implement CSP' : undefined
  };
};

const createMissingHeader = (name: string, severity: 'critical' | 'high' | 'medium' | 'low'): SecurityHeader => {
  return {
    name,
    value: undefined,
    status: 'missing',
    score: 0,
    severity,
    explanation: `${name} header is missing`,
    recommendation: `Implement ${name} for enhanced security`
  };
};

// Enhanced header analysis with better detection
const analyzeHeader = (name: string, value?: string, allHeaders?: Record<string, string>): SecurityHeader => {
  const lowerName = name.toLowerCase();
  
  switch (lowerName) {
    case 'content-security-policy':
      return analyzeCspHeader('Content-Security-Policy', value, true);
    case 'content-security-policy-report-only':
      return analyzeCspHeader('Content-Security-Policy-Report-Only', value, false);
    case 'strict-transport-security':
      return analyzeHstsHeader(value);
    case 'x-frame-options':
      return analyzeFrameOptions(value);
    case 'x-content-type-options':
      return analyzeContentTypeOptions(value);
    case 'referrer-policy':
      return analyzeReferrerPolicy(value);
    case 'permissions-policy':
      return analyzePermissionsPolicy(value);
    case 'x-xss-protection':
      return analyzeXSSProtection(value, allHeaders);
    default:
      return createMissingHeader(name, 'medium');
  }
};

// Get dynamic colors based on grade
const getGradeTheme = (score: number) => {
  if (score >= 90) {
    return {
      grade: 'A',
      bgGradient: 'from-emerald-50 via-green-50 to-teal-50',
      borderColor: 'border-emerald-200',
      circleColor: 'bg-gradient-to-br from-emerald-500 to-green-600',
      accentColor: 'text-emerald-700',
      badgeColor: 'bg-emerald-100 text-emerald-800',
      description: 'Excellent Security',
      icon: '🛡️'
    };
  } else if (score >= 80) {
    return {
      grade: 'B',
      bgGradient: 'from-blue-50 via-indigo-50 to-purple-50',
      borderColor: 'border-blue-200',
      circleColor: 'bg-gradient-to-br from-blue-500 to-indigo-600',
      accentColor: 'text-blue-700',
      badgeColor: 'bg-blue-100 text-blue-800',
      description: 'Good Security',
      icon: '🔒'
    };
  } else if (score >= 70) {
    return {
      grade: 'C',
      bgGradient: 'from-yellow-50 via-amber-50 to-orange-50',
      borderColor: 'border-yellow-200',
      circleColor: 'bg-gradient-to-br from-yellow-500 to-amber-600',
      accentColor: 'text-yellow-700',
      badgeColor: 'bg-yellow-100 text-yellow-800',
      description: 'Fair Security',
      icon: '⚠️'
    };
  } else if (score >= 60) {
    return {
      grade: 'D',
      bgGradient: 'from-orange-50 via-red-50 to-pink-50',
      borderColor: 'border-orange-200',
      circleColor: 'bg-gradient-to-br from-orange-500 to-red-500',
      accentColor: 'text-orange-700',
      badgeColor: 'bg-orange-100 text-orange-800',
      description: 'Poor Security',
      icon: '🔴'
    };
  } else {
    return {
      grade: 'F',
      bgGradient: 'from-red-50 via-rose-50 to-pink-50',
      borderColor: 'border-red-200',
      circleColor: 'bg-gradient-to-br from-red-500 to-rose-600',
      accentColor: 'text-red-700',
      badgeColor: 'bg-red-100 text-red-800',
      description: 'Critical Issues',
      icon: '🚨'
    };
  }
};

// ENHANCED HEADER ANALYSIS using our improved API route
const analyzeHeadersReal = async (url: string): Promise<HeaderAnalysis> => {
  const response = await fetch(`/api/analyze-headers?url=${encodeURIComponent(url)}`);
  
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(errorData.error || `HTTP ${response.status}: ${response.statusText}`);
  }
  
  const data = await response.json();
  
  if (!data.success) {
    throw new Error(data.error || 'Analysis failed');
  }
  
  // Process the raw headers into our security analysis
  const headers = SECURITY_HEADERS.map(headerName => {
    const value = data.headers[headerName];
    return analyzeHeader(headerName, value, data.headers);
  });

  // Calculate weighted score
  const totalPossibleScore = Object.values(HEADER_WEIGHTS).reduce((sum, weight) => sum + weight, 0);
  const actualScore = headers.reduce((sum, header) => {
    const headerName = header.name.toLowerCase().replace(/[^a-z-]/g, '');
    const weight = HEADER_WEIGHTS[headerName as keyof typeof HEADER_WEIGHTS] || 0;
    const weightedScore = (header.score / 100) * weight;
    return sum + weightedScore;
  }, 0);
  
  const overallScore = Math.round((actualScore / totalPossibleScore) * 100);

  return {
    url: data.url,
    headers,
    rawHeaders: data.headers,
    overallScore,
    timestamp: data.metadata.timestamp,
    method: 'enhanced-analysis',
    cached: data.cached || false,
    cacheAge: data.cacheAge || 0,
    responseInfo: data.responseInfo,
    metadata: data.metadata
  };
};

// Helper function to safely extract hostname from URL
const getHostnameFromUrl = (url: string): string => {
  try {
    return new URL(url).hostname;
  } catch {
    const match = url.match(/^(?:https?:\/\/)?([^\/]+)/);
    return match ? match[1] : url;
  }
};

// Format IP address with location info
const formatIPAddress = (ip: string) => {
  if (!ip || ip === 'Unknown') return 'Unknown';
  
  // Check if it's IPv6
  if (ip.includes(':')) {
    return `${ip} (IPv6)`;
  }
  
  return ip;
};

// UI Components
const GradeCircle = ({ score, theme }: { score: number; theme: any }) => {
  return (
    <div className={`w-24 h-24 rounded-2xl ${theme.circleColor} flex items-center justify-center shadow-xl border-4 border-white`}>
      <span className="text-4xl font-bold text-white">{theme.grade}</span>
    </div>
  );
};

const HeaderBadge = ({ header, onClick }: { header: SecurityHeader; onClick?: () => void }) => {
  const getBadgeStyles = () => {
    switch (header.status) {
      case 'secure':
        return 'bg-emerald-100 text-emerald-800 border-emerald-200 hover:bg-emerald-200';
      case 'weak':
        return 'bg-amber-100 text-amber-800 border-amber-200 hover:bg-amber-200';
      case 'missing':
        return 'bg-red-100 text-red-800 border-red-200 hover:bg-red-200';
    }
  };

  const getIcon = () => {
    switch (header.status) {
      case 'secure':
        return <CheckCircle className="w-3 h-3 mr-1" />;
      case 'weak':
        return <AlertTriangle className="w-3 h-3 mr-1" />;
      case 'missing':
        return <XCircle className="w-3 h-3 mr-1" />;
    }
  };

  return (
    <button 
      onClick={onClick}
      className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium border transition-colors cursor-pointer ${getBadgeStyles()}`}
    >
      {getIcon()}
      {header.name.replace('X-', '').replace('-', ' ')}
      <Info className="w-3 h-3 ml-1 opacity-60" />
    </button>
  );
};

const SecurityCard = ({ header, theme }: { header: SecurityHeader; theme: any }) => {
  const getSeverityColor = (severity?: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-50';
      case 'high': return 'text-orange-600 bg-orange-50';
      case 'medium': return 'text-yellow-600 bg-yellow-50';
      case 'low': return 'text-green-600 bg-green-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  return (
    <div className={`border-l-4 pl-6 py-4 ${
      header.status === 'secure' ? 'border-emerald-400 bg-emerald-50/30' : 
      header.status === 'weak' ? 'border-amber-400 bg-amber-50/30' : 
      'border-red-400 bg-red-50/30'
    } rounded-r-lg`}>
      <div className="flex items-center justify-between mb-3">
        <h4 className="font-semibold text-gray-900">{header.name}</h4>
        <div className="flex items-center gap-2">
          {header.severity && (
            <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(header.severity)}`}>
              {header.severity.toUpperCase()}
            </span>
          )}
          <span className="text-sm font-medium text-gray-500">
            {header.score}/100
          </span>
        </div>
      </div>
      
      {header.value && (
        <div className="bg-gray-900 rounded-lg p-3 mb-3 overflow-x-auto">
          <code className="text-sm text-emerald-400 font-mono break-all">
            {header.value}
          </code>
        </div>
      )}
      
      <p className="text-sm text-gray-700 mb-2 leading-relaxed">
        {header.explanation}
      </p>
      
      {header.recommendation && (
        <div className="mt-3 p-3 bg-blue-50 border border-blue-200 rounded-lg">
          <p className="text-sm text-blue-800">
            <strong className="text-blue-900">💡 Recommendation:</strong> {header.recommendation}
          </p>
        </div>
      )}
    </div>
  );
};

// Enhanced Server Info Component
const ServerInfoCard = ({ analysisResult }: { analysisResult: HeaderAnalysis }) => {
  const { responseInfo, metadata } = analysisResult;
  
  return (
    <div className="bg-white/70 backdrop-blur-sm rounded-2xl border border-gray-200 p-6 shadow-lg">
      <h3 className="text-lg font-bold text-gray-900 mb-4 flex items-center gap-2">
        <Server className="w-5 h-5 text-gray-600" />
        Server Information
      </h3>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* IP Address with enhanced display */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm text-gray-600">
            <MapPin className="w-4 h-4" />
            <span className="font-medium">IP Address</span>
          </div>
          <div className="bg-gray-50 rounded-lg p-3">
            <div className="font-mono text-sm text-gray-900">
              {formatIPAddress(responseInfo?.ipAddress || metadata?.ipAddress || 'Unknown')}
            </div>
          </div>
        </div>

        {/* Server Software */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm text-gray-600">
            <Server className="w-4 h-4" />
            <span className="font-medium">Server</span>
          </div>
          <div className="bg-gray-50 rounded-lg p-3">
            <div className="text-sm text-gray-900">
              {responseInfo?.headers?.server || 'Unknown'}
            </div>
          </div>
        </div>

        {/* Powered By */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm text-gray-600">
            <Zap className="w-4 h-4" />
            <span className="font-medium">Powered By</span>
          </div>
          <div className="bg-gray-50 rounded-lg p-3">
            <div className="text-sm text-gray-900">
              {responseInfo?.headers?.poweredBy || 'Not disclosed'}
            </div>
          </div>
        </div>

        {/* Response Time */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm text-gray-600">
            <Timer className="w-4 h-4" />
            <span className="font-medium">Response Time</span>
          </div>
          <div className="bg-gray-50 rounded-lg p-3">
            <div className="text-sm text-gray-900">
              {metadata?.processingTime ? `${metadata.processingTime}ms` : 'Unknown'}
              {analysisResult.cached && (
                <span className="ml-2 text-xs text-blue-600">(cached {analysisResult.cacheAge}s ago)</span>
              )}
            </div>
          </div>
        </div>

        {/* Content Type */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm text-gray-600">
            <Info className="w-4 h-4" />
            <span className="font-medium">Content Type</span>
          </div>
          <div className="bg-gray-50 rounded-lg p-3">
            <div className="text-sm text-gray-900">
              {responseInfo?.headers?.contentType || 'Unknown'}
            </div>
          </div>
        </div>

        {/* Connection Status */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm text-gray-600">
            <Wifi className="w-4 h-4" />
            <span className="font-medium">Status</span>
          </div>
          <div className="bg-gray-50 rounded-lg p-3">
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${
                responseInfo?.status === 200 ? 'bg-green-500' : 
                responseInfo?.status && responseInfo.status < 400 ? 'bg-yellow-500' : 
                'bg-red-500'
              }`}></div>
              <span className="text-sm text-gray-900">
                {responseInfo?.status || 'Unknown'} {responseInfo?.statusText || ''}
              </span>
            </div>
          </div>
        </div>
      </div>
      
      {/* Cache Status */}
      {analysisResult.cached && (
        <div className="mt-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
          <div className="flex items-center gap-2 text-sm text-blue-800">
            <Clock className="w-4 h-4" />
            <span>Results served from cache ({analysisResult.cacheAge} seconds old)</span>
          </div>
        </div>
      )}
    </div>
  );
};

// Modal Component for Header Details
const SecurityHeaderModal = ({ 
  header, 
  isOpen, 
  onClose 
}: { 
  header: SecurityHeader | null; 
  isOpen: boolean; 
  onClose: () => void; 
}) => {
  if (!isOpen || !header) return null;

  const getDetailedExplanation = (headerName: string) => {
    const name = headerName.toLowerCase();
    
    switch (name) {
      case 'content-security-policy':
        return {
          purpose: "Content Security Policy (CSP) is a security layer that helps detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks.",
          howItWorks: "CSP works by specifying which resources (scripts, styles, images, etc.) are allowed to load and execute on your website. It uses directives like 'script-src', 'style-src', and 'img-src' to control resource origins.",
          bestPractices: [
            "Use 'strict-dynamic' for modern browsers",
            "Avoid 'unsafe-inline' and 'unsafe-eval'",
            "Use nonces or hashes for inline scripts/styles",
            "Start with a restrictive policy and gradually allow necessary sources",
            "Use 'Content-Security-Policy-Report-Only' for testing"
          ],
          commonIssues: [
            "Too permissive policies with wildcard (*) sources",
            "Using 'unsafe-inline' which defeats CSP's purpose",
            "Not including necessary domains for third-party resources"
          ]
        };
      
      case 'content-security-policy-report-only':
        return {
          purpose: "CSP Report-Only header allows you to test Content Security Policy without actually blocking resources. It only reports violations to a specified endpoint.",
          howItWorks: "This header works exactly like CSP but doesn't enforce the policy. Instead, it sends violation reports to help you understand what would be blocked if the policy were enforced.",
          bestPractices: [
            "Use this to test new CSP policies before enforcement",
            "Set up a reporting endpoint to collect violation data",
            "Gradually move from Report-Only to enforcing CSP",
            "Monitor reports to identify false positives"
          ],
          commonIssues: [
            "Forgetting to transition from Report-Only to enforcing",
            "Not setting up proper violation reporting",
            "Ignoring violation reports"
          ]
        };
      
      case 'strict-transport-security':
        return {
          purpose: "HTTP Strict Transport Security (HSTS) forces browsers to use secure HTTPS connections instead of HTTP, protecting against man-in-the-middle attacks and protocol downgrade attacks.",
          howItWorks: "Once a browser receives an HSTS header, it will automatically convert all HTTP requests to HTTPS for the specified domain and duration, even if the user types 'http://' in the address bar.",
          bestPractices: [
            "Use a max-age of at least 1 year (31536000 seconds)",
            "Include 'includeSubDomains' to protect subdomains",
            "Consider 'preload' directive for maximum security",
            "Ensure HTTPS is properly configured before enabling"
          ],
          commonIssues: [
            "Too short max-age values provide minimal protection",
            "Not including subdomains leaves them vulnerable",
            "Deploying HSTS without proper HTTPS setup"
          ]
        };
      
      case 'x-frame-options':
        return {
          purpose: "X-Frame-Options prevents your website from being embedded in frames or iframes, protecting against clickjacking attacks where malicious sites trick users into clicking on hidden elements.",
          howItWorks: "This header tells browsers whether to allow your page to be displayed in frames. 'DENY' blocks all framing, 'SAMEORIGIN' allows framing only by the same origin.",
          bestPractices: [
            "Use 'DENY' if your site should never be framed",
            "Use 'SAMEORIGIN' if you need to frame your own content",
            "Avoid 'ALLOW-FROM' as it's deprecated and poorly supported",
            "Consider migrating to CSP's frame-ancestors directive"
          ],
          commonIssues: [
            "Using permissive settings when strict ones would work",
            "Not testing legitimate embedding use cases",
            "Mixing X-Frame-Options with CSP frame-ancestors"
          ]
        };
      
      case 'x-content-type-options':
        return {
          purpose: "X-Content-Type-Options prevents MIME-sniffing attacks by stopping browsers from guessing content types different from what the server declares.",
          howItWorks: "When set to 'nosniff', browsers will strictly follow the Content-Type header and won't try to guess the file type, preventing execution of malicious content disguised as innocent files.",
          bestPractices: [
            "Always set to 'nosniff'",
            "Ensure your server sets correct Content-Type headers",
            "Test file uploads and downloads work correctly",
            "Particularly important for user-generated content"
          ],
          commonIssues: [
            "Server not setting proper Content-Type headers",
            "Forgetting to implement this simple but effective header",
            "Issues with legacy browsers, though modern support is excellent"
          ]
        };
      
      case 'referrer-policy':
        return {
          purpose: "Referrer Policy controls how much referrer information is shared when users navigate from your site to external sites, protecting user privacy and preventing information leakage.",
          howItWorks: "This header determines what referrer information (origin, path, query string) is sent in the Referer header when users click links or when resources are requested.",
          bestPractices: [
            "Use 'strict-origin-when-cross-origin' for balanced privacy and functionality",
            "Consider 'strict-origin' for maximum privacy",
            "Avoid 'no-referrer' unless absolutely necessary",
            "Test that analytics and affiliate tracking still work"
          ],
          commonIssues: [
            "Using 'unsafe-url' which leaks sensitive URL parameters",
            "Breaking analytics or affiliate tracking with overly strict policies",
            "Not considering the impact on third-party integrations"
          ]
        };
      
      case 'permissions-policy':
        return {
          purpose: "Permissions Policy (formerly Feature Policy) controls which browser features and APIs can be used on your website, reducing attack surface and protecting user privacy.",
          howItWorks: "This header specifies which features like camera, microphone, geolocation, payment APIs, etc., are allowed to be used by your site and any embedded content.",
          bestPractices: [
            "Deny unnecessary features like camera and microphone if not needed",
            "Be restrictive by default, only allow what you actually use",
            "Consider embedded content and third-party widgets",
            "Regularly review and update based on new features"
          ],
          commonIssues: [
            "Not restricting unused powerful features",
            "Breaking embedded content by being too restrictive",
            "Not updating policies when browser APIs change"
          ]
        };
      
      case 'x-xss-protection':
        return {
          purpose: "X-XSS-Protection is a legacy header that enables built-in XSS filtering in older browsers. Modern browsers have deprecated this in favor of Content Security Policy.",
          howItWorks: "This header enabled the browser's built-in XSS filter, which attempted to detect and block reflected XSS attacks. However, it had bypass vulnerabilities and is now largely obsolete.",
          bestPractices: [
            "Set to '0' (disabled) if you have a strong CSP",
            "Use '1; mode=block' only if CSP is not available",
            "Focus on implementing proper CSP instead",
            "Modern browsers ignore this header"
          ],
          commonIssues: [
            "Relying on this instead of proper CSP",
            "Not understanding it's largely obsolete",
            "Potential bypass vulnerabilities in the filter itself"
          ]
        };
      
      default:
        return {
          purpose: "This security header helps protect your website from various attacks.",
          howItWorks: "Refer to the documentation for specific implementation details.",
          bestPractices: ["Follow security best practices", "Test thoroughly before deployment"],
          commonIssues: ["Misconfiguration", "Incomplete implementation"]
        };
    }
  };

  const details = getDetailedExplanation(header.name);
  
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'secure': return 'text-emerald-700 bg-emerald-50';
      case 'weak': return 'text-amber-700 bg-amber-50';
      case 'missing': return 'text-red-700 bg-red-50';
      default: return 'text-gray-700 bg-gray-50';
    }
  };

  const getStatusText = (status: string) => {
    switch (status) {
      case 'secure': return 'Properly Configured';
      case 'weak': return 'Needs Improvement';
      case 'missing': return 'Not Implemented';
      default: return 'Unknown';
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto shadow-2xl">
        {/* Header */}
        <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4 rounded-t-2xl">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-gray-900">{header.name}</h2>
                <div className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(header.status)}`}>
                  {getStatusText(header.status)}
                </div>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
            >
              <XCircle className="w-5 h-5 text-gray-400" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Current Status */}
          <div className="bg-gray-50 rounded-xl p-4">
            <h3 className="font-semibold text-gray-900 mb-2">Current Status</h3>
            <div className="flex items-center gap-4 mb-3">
              <span className="text-sm font-medium text-gray-600">Score:</span>
              <span className="text-lg font-bold text-gray-900">{header.score}/100</span>
            </div>
            {header.value ? (
              <div className="bg-gray-900 rounded-lg p-3 overflow-x-auto">
                <code className="text-sm text-emerald-400 font-mono break-all">
                  {header.value}
                </code>
              </div>
            ) : (
              <div className="bg-gray-200 rounded-lg p-3 text-center">
                <span className="text-sm text-gray-600 italic">Header not present</span>
              </div>
            )}
          </div>

          {/* Purpose */}
          <div>
            <h3 className="font-semibold text-gray-900 mb-2 flex items-center gap-2">
              <Info className="w-4 h-4" />
              What is this header?
            </h3>
            <p className="text-gray-700 leading-relaxed">{details.purpose}</p>
          </div>

          {/* How it works */}
          <div>
            <h3 className="font-semibold text-gray-900 mb-2 flex items-center gap-2">
              <Zap className="w-4 h-4" />
              How it works
            </h3>
            <p className="text-gray-700 leading-relaxed">{details.howItWorks}</p>
          </div>

          {/* Best Practices */}
          <div>
            <h3 className="font-semibold text-gray-900 mb-2 flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-emerald-500" />
              Best Practices
            </h3>
            <ul className="space-y-2">
              {details.bestPractices.map((practice, index) => (
                <li key={index} className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full mt-2 flex-shrink-0"></div>
                  <span className="text-gray-700 text-sm">{practice}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Common Issues */}
          <div>
            <h3 className="font-semibold text-gray-900 mb-2 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-500" />
              Common Issues
            </h3>
            <ul className="space-y-2">
              {details.commonIssues.map((issue, index) => (
                <li key={index} className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-amber-500 rounded-full mt-2 flex-shrink-0"></div>
                  <span className="text-gray-700 text-sm">{issue}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Current Recommendation */}
          {header.recommendation && (
            <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
              <h3 className="font-semibold text-blue-900 mb-2 flex items-center gap-2">
                <ArrowRight className="w-4 h-4" />
                Recommendation for your site
              </h3>
              <p className="text-blue-800 text-sm leading-relaxed">{header.recommendation}</p>
            </div>
          )}

          {/* Implementation Guide */}
          <div className="bg-gray-50 rounded-xl p-4">
            <h3 className="font-semibold text-gray-900 mb-3">Quick Implementation</h3>
            <div className="space-y-3 text-sm">
              <div className="bg-white p-3 rounded-lg border">
                <div className="font-medium text-gray-700 mb-1">Nginx:</div>
                <code className="text-xs bg-gray-100 px-2 py-1 rounded">
                  add_header {header.name} "your-policy-here";
                </code>
              </div>
              <div className="bg-white p-3 rounded-lg border">
                <div className="font-medium text-gray-700 mb-1">Apache:</div>
                <code className="text-xs bg-gray-100 px-2 py-1 rounded">
                  Header always set {header.name} "your-policy-here"
                </code>
              </div>
              <div className="bg-white p-3 rounded-lg border">
                <div className="font-medium text-gray-700 mb-1">Node.js/Express:</div>
                <code className="text-xs bg-gray-100 px-2 py-1 rounded">
                  res.setHeader('{header.name}', 'your-policy-here');
                </code>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="border-t border-gray-200 px-6 py-4 bg-gray-50 rounded-b-2xl">
          <div className="flex items-center justify-between">
            <div className="text-xs text-gray-500">
              Learn more about security headers at OWASP.org
            </div>
            <button
              onClick={onClose}
              className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors text-sm font-medium"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// Main Component
export default function SecurityHeadersAnalyzer() {
  const [url, setUrl] = useState('');
  const [analysisResult, setAnalysisResult] = useState<HeaderAnalysis | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [theme, setTheme] = useState(getGradeTheme(50));
  const [selectedHeader, setSelectedHeader] = useState<SecurityHeader | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  const exampleSites = [
    'github.com',
    'google.com',
    'stackoverflow.com',
    'microsoft.com',
    'cloudflare.com'
  ];

  // Update theme when analysis result changes
  useEffect(() => {
    if (analysisResult) {
      setTheme(getGradeTheme(analysisResult.overallScore));
    }
  }, [analysisResult]);

  const handleAnalyze = async () => {
    if (!url.trim()) {
      setError('Please enter a valid URL');
      return;
    }

    setLoading(true);
    setError('');
    setAnalysisResult(null);
    
    try {
      const result = await analyzeHeadersReal(url);
      setAnalysisResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to analyze headers. Please check the URL and try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleAnalyze();
    }
  };

  const openModal = (header: SecurityHeader) => {
    setSelectedHeader(header);
    setModalOpen(true);
  };

  const closeModal = () => {
    setSelectedHeader(null);
    setModalOpen(false);
  };

  const criticalIssues = analysisResult?.headers.filter(h => h.severity === 'critical' || (h.status === 'missing' && h.severity === 'high')).length || 0;
  const secureHeaders = analysisResult?.headers.filter(h => h.status === 'secure').length || 0;

  return (
    <div className={`min-h-screen bg-gradient-to-br ${theme.bgGradient} transition-all duration-1000`}>
      {/* Navigation */}
      <nav className="bg-white/80 backdrop-blur-sm border-b border-gray-200/50 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">Security Headers</h1>
                <p className="text-sm text-gray-600">by MAKR</p>
              </div>
            </div>
            
            {analysisResult && (
              <div className={`${theme.badgeColor} px-4 py-2 rounded-full flex items-center gap-2`}>
                <span className="text-xl">{theme.icon}</span>
                <span className="font-semibold">Grade {theme.grade}</span>
              </div>
            )}
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Hero Section */}
        {!analysisResult && (
          <div className="text-center mb-16">
            <div className="max-w-3xl mx-auto">
              <h1 className="text-5xl font-bold text-gray-900 mb-6 leading-tight">
                Analyze Your Website's
                <span className="bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent"> Security Headers</span>
              </h1>
              <p className="text-xl text-gray-600 mb-8 leading-relaxed">
                Get instant security analysis and actionable recommendations to protect your website from XSS, clickjacking, and other attacks.
              </p>

              {/* URL Input */}
              <div className="max-w-2xl mx-auto">
                <div className="flex gap-3 mb-6">
                  <div className="flex-1 relative">
                    <Globe className="absolute left-4 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
                    <input
                      type="text"
                      placeholder="Enter website URL (e.g., example.com)"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      onKeyPress={handleKeyPress}
                      className="w-full pl-12 pr-4 h-14 text-lg border-2 border-gray-200 rounded-xl focus:border-indigo-500 focus:ring-4 focus:ring-indigo-200 outline-none transition-all bg-white/50 backdrop-blur-sm"
                    />
                  </div>
                  <button 
                    onClick={handleAnalyze} 
                    disabled={loading || !url.trim()}
                    className="h-14 px-8 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-all flex items-center shadow-lg hover:shadow-xl"
                  >
                    {loading ? (
                      <>
                        <Search className="w-5 h-5 mr-2 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Search className="w-5 h-5 mr-2" />
                        Analyze
                      </>
                    )}
                  </button>
                </div>
                
                {/* Example URLs */}
                <div className="mb-8">
                  <p className="text-sm text-gray-600 mb-3">Popular examples:</p>
                  <div className="flex flex-wrap justify-center gap-2">
                    {exampleSites.map((site) => (
                      <button
                        key={site}
                        onClick={() => setUrl(site)}
                        className="px-4 py-2 text-sm text-indigo-600 hover:text-indigo-800 hover:bg-indigo-50 rounded-lg transition-colors border border-indigo-200"
                      >
                        {site}
                      </button>
                    ))}
                  </div>
                </div>

                {error && (
                  <div className="p-4 bg-red-50 border border-red-200 rounded-xl">
                    <p className="text-red-700 text-sm">{error}</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Results */}
        {analysisResult && (
          <div className="space-y-8">
            {/* Compact URL Input for New Analysis */}
            <div className="mb-8">
              <div className="max-w-2xl mx-auto">
                <div className="flex gap-3">
                  <div className="flex-1 relative">
                    <Globe className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                    <input
                      type="text"
                      placeholder="Analyze another website..."
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      onKeyPress={handleKeyPress}
                      className="w-full pl-10 pr-4 h-12 border border-gray-300 rounded-xl focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200 outline-none transition-all bg-white/80 backdrop-blur-sm"
                    />
                  </div>
                  <button 
                    onClick={handleAnalyze} 
                    disabled={loading || !url.trim()}
                    className="h-12 px-6 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-xl transition-all flex items-center"
                  >
                    {loading ? (
                      <Search className="w-4 h-4 animate-spin" />
                    ) : (
                      <Search className="w-4 h-4" />
                    )}
                  </button>
                </div>
              </div>
            </div>

            {/* Security Score Card */}
            <div className={`bg-white/70 backdrop-blur-sm rounded-2xl border ${theme.borderColor} p-8 shadow-xl`}>
              <div className="mb-8">
                <h2 className="text-2xl font-bold text-gray-900 mb-2">Security Analysis</h2>
                <p className="text-gray-600">
                  <strong>{analysisResult.url}</strong>
                  {analysisResult.responseInfo?.redirected && analysisResult.responseInfo.finalUrl && (
                    <span className="text-sm text-gray-500 ml-2">
                      → redirected to {getHostnameFromUrl(analysisResult.responseInfo.finalUrl)}
                    </span>
                  )}
                </p>
                {analysisResult.responseInfo?.redirected && (
                  <p className="text-xs text-blue-600 mt-1">
                    Final URL: {analysisResult.responseInfo.finalUrl}
                  </p>
                )}
              </div>
              
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-center">
                {/* Grade Circle */}
                <div className="text-center">
                  <GradeCircle score={analysisResult.overallScore} theme={theme} />
                  <div className="mt-4">
                    <div className={`text-3xl font-bold ${theme.accentColor} mb-1`}>
                      {analysisResult.overallScore}/100
                    </div>
                    <div className="text-gray-600 font-medium">{theme.description}</div>
                  </div>
                </div>

                {/* Quick Stats */}
                <div className="lg:col-span-2 grid grid-cols-2 gap-6">
                  <div className="text-center p-4 bg-emerald-50 rounded-xl border border-emerald-200">
                    <div className="flex items-center justify-center w-12 h-12 bg-emerald-100 rounded-xl mx-auto mb-3">
                      <CheckCircle className="w-6 h-6 text-emerald-600" />
                    </div>
                    <div className="text-2xl font-bold text-emerald-700 mb-1">{secureHeaders}</div>
                    <div className="text-sm text-emerald-600">Secure Headers</div>
                  </div>
                  
                  <div className="text-center p-4 bg-red-50 rounded-xl border border-red-200">
                    <div className="flex items-center justify-center w-12 h-12 bg-red-100 rounded-xl mx-auto mb-3">
                      <Bug className="w-6 h-6 text-red-600" />
                    </div>
                    <div className="text-2xl font-bold text-red-700 mb-1">{criticalIssues}</div>
                    <div className="text-sm text-red-600">Critical Issues</div>
                  </div>
                  
                  <div className="text-center p-4 bg-blue-50 rounded-xl border border-blue-200">
                    <div className="flex items-center justify-center w-12 h-12 bg-blue-100 rounded-xl mx-auto mb-3">
                      <TrendingUp className="w-6 h-6 text-blue-600" />
                    </div>
                    <div className="text-2xl font-bold text-blue-700 mb-1">{analysisResult.responseInfo?.status || 200}</div>
                    <div className="text-sm text-blue-600">HTTP Status</div>
                  </div>
                  
                  <div className="text-center p-4 bg-purple-50 rounded-xl border border-purple-200">
                    <div className="flex items-center justify-center w-12 h-12 bg-purple-100 rounded-xl mx-auto mb-3">
                      <Award className="w-6 h-6 text-purple-600" />
                    </div>
                    <div className="text-2xl font-bold text-purple-700 mb-1">{analysisResult.headers.length}</div>
                    <div className="text-sm text-purple-600">Headers Checked</div>
                  </div>
                </div>
              </div>

              {/* Header Status Pills */}
              <div className="mt-8 pt-6 border-t border-gray-200">
                <div className="flex flex-wrap gap-2">
                  {analysisResult.headers.map((header) => (
                    <HeaderBadge key={header.name} header={header} onClick={() => openModal(header)} />
                  ))}
                </div>
              </div>
            </div>

            {/* Server Information Card */}
            <ServerInfoCard analysisResult={analysisResult} />

            {/* Critical Issues Alert */}
            {criticalIssues > 0 && (
              <div className="bg-red-50 border-l-4 border-red-400 p-6 rounded-r-xl">
                <div className="flex items-start">
                  <div className="flex-shrink-0">
                    <XCircle className="h-5 w-5 text-red-400" />
                  </div>
                  <div className="ml-3">
                    <h3 className="text-sm font-medium text-red-800">
                      {criticalIssues} Critical Security {criticalIssues === 1 ? 'Issue' : 'Issues'} Found
                    </h3>
                    <div className="mt-2 text-sm text-red-700">
                      <p>Your website has critical security vulnerabilities that should be addressed immediately to protect against attacks.</p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Missing Headers */}
            {analysisResult.headers.filter(h => h.status === 'missing').length > 0 && (
              <div className="bg-white/70 backdrop-blur-sm rounded-2xl border border-gray-200 p-8 shadow-lg">
                <h3 className="text-xl font-bold text-gray-900 mb-6 flex items-center gap-2">
                  <XCircle className="w-5 h-5 text-red-500" />
                  Missing Security Headers
                </h3>
                <div className="space-y-6">
                  {analysisResult.headers
                    .filter(header => header.status === 'missing')
                    .map((header) => (
                      <SecurityCard key={header.name} header={header} theme={theme} />
                    ))}
                </div>
              </div>
            )}

            {/* Weak Headers */}
            {analysisResult.headers.filter(h => h.status === 'weak').length > 0 && (
              <div className="bg-white/70 backdrop-blur-sm rounded-2xl border border-gray-200 p-8 shadow-lg">
                <h3 className="text-xl font-bold text-gray-900 mb-6 flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-amber-500" />
                  Weak Security Headers
                </h3>
                <div className="space-y-6">
                  {analysisResult.headers
                    .filter(header => header.status === 'weak')
                    .map((header) => (
                      <SecurityCard key={header.name} header={header} theme={theme} />
                    ))}
                </div>
              </div>
            )}

            {/* Secure Headers */}
            {analysisResult.headers.filter(h => h.status === 'secure').length > 0 && (
              <div className="bg-white/70 backdrop-blur-sm rounded-2xl border border-gray-200 p-8 shadow-lg">
                <h3 className="text-xl font-bold text-gray-900 mb-6 flex items-center gap-2">
                  <CheckCircle className="w-5 h-5 text-emerald-500" />
                  Secure Headers
                </h3>
                <div className="space-y-6">
                  {analysisResult.headers
                    .filter(header => header.status === 'secure')
                    .map((header) => (
                      <SecurityCard key={header.name} header={header} theme={theme} />
                    ))}
                </div>
              </div>
            )}

            {/* Raw Headers */}
            {analysisResult.rawHeaders && Object.keys(analysisResult.rawHeaders).length > 0 && (
              <div className="bg-white/70 backdrop-blur-sm rounded-2xl border border-gray-200 p-8 shadow-lg">
                <h3 className="text-xl font-bold text-gray-900 mb-6">All HTTP Headers</h3>
                <div className="bg-gray-900 rounded-xl p-6 overflow-x-auto">
                  <div className="space-y-2">
                    {Object.entries(analysisResult.rawHeaders)
                      .sort(([a], [b]) => a.localeCompare(b))
                      .map(([key, value]) => (
                        <div key={key} className="flex">
                          <span className="text-blue-400 font-mono text-sm min-w-0 flex-shrink-0 mr-4">
                            {key}:
                          </span>
                          <span className="text-gray-300 font-mono text-sm break-all">
                            {value}
                          </span>
                        </div>
                      ))}
                  </div>
                </div>
              </div>
            )}

            {/* Security Resources */}
            <div className="bg-white/70 backdrop-blur-sm rounded-2xl border border-gray-200 p-8 shadow-lg">
              <h3 className="text-xl font-bold text-gray-900 mb-6">Security Resources</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <h4 className="font-semibold text-gray-800">Learn More</h4>
                  <div className="space-y-3">
                    <a 
                      href="https://owasp.org/www-project-secure-headers/" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="flex items-center justify-between p-3 bg-blue-50 hover:bg-blue-100 rounded-lg transition-colors group"
                    >
                      <span className="text-blue-800 font-medium">OWASP Secure Headers</span>
                      <ExternalLink className="w-4 h-4 text-blue-600 group-hover:text-blue-800" />
                    </a>
                    <a 
                      href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="flex items-center justify-between p-3 bg-purple-50 hover:bg-purple-100 rounded-lg transition-colors group"
                    >
                      <span className="text-purple-800 font-medium">MDN HTTP Headers</span>
                      <ExternalLink className="w-4 h-4 text-purple-600 group-hover:text-purple-800" />
                    </a>
                    <a 
                      href="https://csp-evaluator.withgoogle.com/" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="flex items-center justify-between p-3 bg-green-50 hover:bg-green-100 rounded-lg transition-colors group"
                    >
                      <span className="text-green-800 font-medium">CSP Evaluator</span>
                      <ExternalLink className="w-4 h-4 text-green-600 group-hover:text-green-800" />
                    </a>
                  </div>
                </div>
                
                <div className="space-y-4">
                  <h4 className="font-semibold text-gray-800">Common Fixes</h4>
                  <div className="space-y-3 text-sm text-gray-700">
                    <div className="p-3 bg-gray-50 rounded-lg">
                      <strong>Nginx:</strong> Add headers to your server block
                    </div>
                    <div className="p-3 bg-gray-50 rounded-lg">
                      <strong>Apache:</strong> Use .htaccess or virtual host config
                    </div>
                    <div className="p-3 bg-gray-50 rounded-lg">
                      <strong>Cloudflare:</strong> Transform Rules or Workers
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded">
                <div className="text-sm text-yellow-800">
                  <strong>💡 Pro Tip:</strong> Start with the highest severity issues first. Implementing Content Security Policy (CSP) provides the biggest security improvement.
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Footer */}
        <footer className="mt-16 pt-8 border-t border-gray-200/50 text-center">
          <div className="text-sm text-gray-600">
            <p className="mb-2">Built by MAKR • Protecting websites with security best practices</p>
            <div className="flex justify-center gap-6">
              <a href="https://owasp.org" className="hover:text-gray-800 transition-colors">OWASP</a>
              <a href="https://mozilla.org/security" className="hover:text-gray-800 transition-colors">Mozilla Security</a>
              <a href="https://web.dev/secure" className="hover:text-gray-800 transition-colors">Web.dev Security</a>
            </div>
          </div>
        </footer>

        {/* Header Details Modal */}
        <SecurityHeaderModal 
          header={selectedHeader} 
          isOpen={modalOpen} 
          onClose={closeModal} 
        />
      </div>
    </div>
  );
}